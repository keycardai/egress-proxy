// Command egress-proxy intercepts and applies Keycard policy to all of a sandbox's outbound
// HTTP/HTTPS communication.
//
// Settings come from the config file, then the environment, then flags, applied
// and overridden in that order. Some settings, such as the per-endpoint and
// policy configuration, are only defined in the config file.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/admin"
	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/dns"
	"github.com/keycardai/egress-proxy/internal/exchange"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// shutdownGrace bounds how long a stop waits for in-flight requests.
const shutdownGrace = 10 * time.Second

// envPrefix is the prefix of every environment variable this command reads.
// `egress-proxy settings` publishes the names, so a chart lint outside this
// repository can refuse any other variable with this prefix on the proxy
// container.
const envPrefix = config.EnvPrefix

func main() {
	action := func(ctx context.Context, opts flags) error {
		return run(ctx, opts, os.Stdout, os.Stderr)
	}
	if err := command(os.Stdout, os.Stderr, action).Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "egress-proxy: %v\n", err)
		os.Exit(1)
	}
}

// flags are the settings the command line and the environment supply.
type flags struct {
	configPath            string
	sandboxID             string
	zoneURL               string
	clientID              string
	workloadTokenFile     string
	impersonateUser       string
	connect               string
	transparentPort       int
	transparentPortSet    bool
	dnsPort               int
	dnsPortSet            bool
	dnsForwardTo          []string
	admin                 string
	connectAuthFile       string
	netsetupReceipt       string
	caOutDir              string
	caStateDir            string
	clientSecretFile      string
	credentialStaticFile  string
	leafTTL               time.Duration
	cacheSize             int
	upstreamCAFiles       []string
	maxConnections        int
	maxDNSConnections     int
	idleTimeout           time.Duration
	responseHeaderTimeout time.Duration
	exchangeTimeout       time.Duration
}

// overrides is the flags as the document parser applies them.
func (f flags) overrides() config.Overrides {
	return config.Overrides{
		SandboxID:             f.sandboxID,
		ZoneURL:               f.zoneURL,
		ClientID:              f.clientID,
		WorkloadTokenFile:     f.workloadTokenFile,
		ImpersonateUser:       f.impersonateUser,
		Connect:               f.connect,
		TransparentPort:       f.transparentPort,
		TransparentPortSet:    f.transparentPortSet,
		DNSPort:               f.dnsPort,
		DNSPortSet:            f.dnsPortSet,
		DNSForwardTo:          f.dnsForwardTo,
		Admin:                 f.admin,
		ConnectAuthFile:       f.connectAuthFile,
		NetsetupReceipt:       f.netsetupReceipt,
		CAOutDir:              f.caOutDir,
		CAStateDir:            f.caStateDir,
		ClientSecretFile:      f.clientSecretFile,
		CredentialStaticFile:  f.credentialStaticFile,
		LeafTTL:               f.leafTTL,
		CacheSize:             f.cacheSize,
		UpstreamCAFiles:       f.upstreamCAFiles,
		MaxConnections:        f.maxConnections,
		MaxDNSConnections:     f.maxDNSConnections,
		IdleTimeout:           f.idleTimeout,
		ResponseHeaderTimeout: f.responseHeaderTimeout,
		ExchangeTimeout:       f.exchangeTimeout,
	}
}

// flagSet defines the configurable command line options and environment
// variables.
func flagSet(opts *flags) []cli.Flag {
	return slices.Concat([]cli.Flag{
		stringFlag("config", "CONFIG", &opts.configPath, "path to the configuration document"),
		stringFlag("sandbox-id", "SANDBOX_ID", &opts.sandboxID, "the sandbox on every audit record (sandbox.id)"),
		stringFlag("zone-url", "ZONE_URL", &opts.zoneURL, "the Keycard zone (identity.zone_url)"),
		stringFlag("client-id", "CLIENT_ID", &opts.clientID, "the application credential id (identity.client_id)"),
		stringFlag("workload-token-file", "WORKLOAD_TOKEN_FILE", &opts.workloadTokenFile,
			"path of the projected ServiceAccount token (identity.workload_token_file)"),
		stringFlag("impersonate-user", "IMPERSONATE_USER", &opts.impersonateUser,
			"the user every exchange acts for (identity.impersonate.user)"),
	}, listenFlags(opts), []cli.Flag{
		stringFlag("ca-out-dir", "CA_OUT_DIR", &opts.caOutDir,
			"directory the CA certificate is written to (ca.out_dir)"),
		stringFlag("ca-state-dir", "CA_STATE_DIR", &opts.caStateDir,
			"memory-backed directory holding the CA across restarts (ca.state_dir)"),
		stringFlag("client-secret-file", "CLIENT_SECRET_FILE", &opts.clientSecretFile,
			"path of the file holding the application credential secret (identity.client_secret_file)"),
		stringFlag("credential-static-file", "CREDENTIAL_STATIC_FILE", &opts.credentialStaticFile,
			"file of credentials by resource, for tests and development (credentials.static_file)"),
		stringFlag("connect-auth-file", "CONNECT_AUTH_FILE", &opts.connectAuthFile,
			"file holding the user:password every CONNECT must present (listen.connect_auth_file)"),
		&cli.DurationFlag{
			Name: "leaf-ttl", Destination: &opts.leafTTL, Sources: env("LEAF_TTL"),
			Usage: "lifetime of a minted leaf (ca.leaf_ttl)",
		},
		&cli.IntFlag{
			Name: "cache-size", Destination: &opts.cacheSize, Sources: env("CACHE_SIZE"),
			Usage: "how many minted leaves are held (ca.cache_size)",
		},
		&cli.StringSliceFlag{
			Name: "upstream-ca-file", Destination: &opts.upstreamCAFiles, Sources: env("UPSTREAM_CA_FILES"),
			Usage: "PEM file joined to the system roots; repeatable, comma-separated in the variable " +
				"(tls.upstream_ca_files)",
		},
		&cli.IntFlag{
			Name: "max-connections", Destination: &opts.maxConnections, Sources: env("MAX_CONNECTIONS"),
			Usage: "simultaneous connections on the listener (limits.max_connections)",
		},
		&cli.IntFlag{
			Name: "max-dns-connections", Destination: &opts.maxDNSConnections,
			Sources: env("MAX_DNS_CONNECTIONS"),
			Usage:   "simultaneous TCP connections on each resolver listener (limits.max_dns_connections)",
		},
		&cli.DurationFlag{
			Name: "idle-timeout", Destination: &opts.idleTimeout, Sources: env("IDLE_TIMEOUT"),
			Usage: "close a connection idle for this long (limits.idle_timeout)",
		},
		&cli.DurationFlag{
			Name: "response-header-timeout", Destination: &opts.responseHeaderTimeout,
			Sources: env("RESPONSE_HEADER_TIMEOUT"),
			Usage:   "how long an upstream has to send a response head (limits.response_header_timeout)",
		},
		&cli.DurationFlag{
			Name: "exchange-timeout", Destination: &opts.exchangeTimeout, Sources: env("EXCHANGE_TIMEOUT"),
			Usage: "budget for one token exchange, discovery included (limits.exchange_timeout)",
		},
	})
}

// listenFlags defines the addresses where the process accepts connections and
// the settings it checks for containment.
func listenFlags(opts *flags) []cli.Flag {
	return []cli.Flag{
		stringFlag("connect", "CONNECT", &opts.connect,
			"address of the CONNECT frontend, host:port (listen.connect)"),
		&cli.IntFlag{
			Name: "transparent-port", Destination: &opts.transparentPort, Sources: env("TRANSPARENT_PORT"),
			Usage: "port the netsetup rules redirect to, bound on 127.0.0.1 and ::1 " +
				"(listen.transparent_port); 0 runs no transparent frontend",
		},
		&cli.IntFlag{
			Name: "dns-port", Destination: &opts.dnsPort, Sources: env("DNS_PORT"),
			Usage: "port of the allowlist resolver, bound on 127.0.0.1 and ::1 (listen.dns_port); " +
				"0 runs no resolver",
		},
		&cli.StringSliceFlag{
			Name: "dns-forward-to", Destination: &opts.dnsForwardTo, Sources: env("DNS_FORWARD_TO"),
			Usage: "cluster resolver an allowed name is forwarded to; repeatable, comma-separated in the " +
				"variable (dns.forward_to); empty reads the netsetup receipt",
		},
		stringFlag("admin", "ADMIN", &opts.admin, "path of the admin Unix socket (listen.admin)"),
		stringFlag("netsetup-receipt", "NETSETUP_RECEIPT", &opts.netsetupReceipt,
			"file the init container recorded what it programmed in (netsetup.receipt)"),
	}
}

func stringFlag(name, envName string, dest *string, usage string) *cli.StringFlag {
	return &cli.StringFlag{Name: name, Destination: dest, Sources: env(envName), Usage: usage}
}

// env is the variable a flag reads when the command line omits it.
func env(name string) cli.ValueSourceChain {
	return cli.EnvVars(envPrefix + name)
}

// command builds the command line. Running it with no subcommand serves
// the proxy. A subcommand serves nothing: probe reads this process's admin
// socket, and settings prints what the binary accepts.
func command(stdout, stderr io.Writer, action func(context.Context, flags) error) *cli.Command {
	var opts flags
	return &cli.Command{
		Name:  "egress-proxy",
		Usage: "the sandbox egress proxy sidecar",
		Description: "Reads one configuration document and serves a CONNECT proxy in front of\n" +
			"its endpoints. Each flag below also reads the environment variable named with\n" +
			"it; a flag wins over the variable, and both win over the document. Audit\n" +
			"records go to stdout, one JSON object per line; logs go to stderr.",
		Version:         version(),
		Writer:          stderr,
		ErrWriter:       stderr,
		HideHelpCommand: true,
		Flags:           flagSet(&opts),
		Commands:        []*cli.Command{probeCommand(&opts, stdout), settingsCommand(stdout)},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if opts.configPath == "" {
				return errNoConfig
			}
			opts.transparentPortSet = cmd.Count("transparent-port") > 0
			opts.dnsPortSet = cmd.Count("dns-port") > 0
			return action(ctx, opts)
		},
	}
}

// errNoConfig is returned when the proxy is started without a config path.
// --config is not marked Required, because probe and settings run without it.
var errNoConfig = errors.New("--config or EGRESS_PROXY_CONFIG names the configuration document, and neither is set")

// process represents the configured components which make up the proxy process.
type process struct {
	cfg         *config.Config
	logger      *slog.Logger
	matcher     *policy.Matcher
	authority   *ca.Authority
	credentials credential.Source
	// selector holds the per-sandbox sources when the proxy identifies
	// sandboxes. credentials is nil then.
	selector    *credential.Selector
	server      *proxy.Server
	admin       *admin.Server
	transparent *transparent.Frontend
	// listenCapture binds the capture sockets. Nil binds them with
	// transparent.Listen.
	listenCapture func(ctx context.Context, port int) ([]net.Listener, error)
	// resolver answers the sandbox's name lookups. It is nil when
	// listen.dns_port is unset.
	resolver *dns.Resolver
	// listenResolver binds the resolver sockets. Nil binds them with
	// dns.Listen.
	listenResolver func(ctx context.Context, port int) (dns.Sockets, error)
	// receiptFamilies are the address families the netsetup receipt says
	// the rules redirect. The capture and the resolver each need a bound
	// socket in every one of them, or the redirect sends that family to a
	// closed port.
	receiptFamilies []string
	// certPath is the CA certificate the workload trusts. Readiness checks
	// that it is on disk.
	certPath string
	// listening turns true once every frontend this process runs is bound:
	// the CONNECT listener, and the capture sockets when listen.transparent_port
	// is set. The shutdown path clears it when the drain starts.
	listening atomic.Bool
}

func run(ctx context.Context, opts flags, stdout, stderr io.Writer) error {
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := config.Load(opts.configPath, opts.overrides())
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	proc, err := build(ctx, cfg, logger, stdout)
	if err != nil {
		return err
	}
	return proc.serve(ctx)
}

func build(ctx context.Context, cfg *config.Config, logger *slog.Logger, stdout io.Writer) (*process, error) {
	deny, err := policy.NewDenyList(cfg.ClusterCIDRs, cfg.DenyListExceptions)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	matcher, err := policy.Compile(cfg.PolicyEndpoints(), deny)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	roots, err := cfg.UpstreamRoots()
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	authority, store, certPath, err := certificates(cfg, logger)
	if err != nil {
		return nil, err
	}
	identities, err := identitySources(cfg, deny, roots)
	if err != nil {
		return nil, err
	}
	// One sink for every decision this process makes. The JSON writer
	// serializes its writes, so a connection, a request and a name lookup
	// never interleave on stdout.
	sink := audit.NewStamped(audit.NewJSONSink(stdout), audit.Stamp{
		SandboxID:      cfg.Sandbox.ID,
		DocumentDigest: cfg.Digest,
		ConfigDigest:   cfg.ConfigDigest,
	}, nil)
	server, err := proxy.New(proxy.Options{
		Matcher:               matcher,
		Certificates:          store,
		ConnectAuth:           identities.connectAuth,
		Sandboxes:             identities.sandboxes,
		Audit:                 sink,
		UpstreamRoots:         roots,
		Credentials:           identities.credentials,
		Logger:                logger,
		MaxConnections:        cfg.Limits.MaxConnections,
		IdleTimeout:           cfg.Limits.IdleTimeout.Duration(),
		ResponseHeaderTimeout: cfg.Limits.ResponseHeaderTimeout.Duration(),
		ShutdownGrace:         shutdownGrace,
	})
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	proc := &process{
		cfg: cfg, logger: logger, matcher: matcher, authority: authority,
		credentials: identities.credentials, selector: identities.selector, server: server, certPath: certPath,
	}
	if err := proc.buildFrontends(ctx, sink); err != nil {
		return nil, err
	}
	proc.announce()
	return proc, nil
}

// buildFrontends adds the frontends the netsetup receipt governs and the
// admin socket. The receipt is read once: the capture and the resolver
// both check themselves against it.
func (p *process) buildFrontends(ctx context.Context, sink audit.Sink) error {
	receipt, err := containment(p.cfg, netsetup.ContainmentRequest{})
	if err != nil {
		return err
	}
	p.receiptFamilies = redirectedFamilies(receipt)
	if p.transparent, err = capture(p.cfg, receipt, p.server, p.logger); err != nil {
		return err
	}
	if p.resolver, err = nameResolver(p.cfg, receipt, sink, p.logger); err != nil {
		return err
	}
	p.admin, err = admin.New(ctx, admin.Options{
		Path: p.cfg.Listen.Admin, Info: p.info, Ready: p.ready, Logger: p.logger,
	})
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	return nil
}

// certificates prepares the authority the proxy terminates tunnels with and
// writes its certificate where the workload reads it.
func certificates(cfg *config.Config, logger *slog.Logger) (*ca.Authority, *ca.Store, string, error) {
	// A state directory inside the output directory would expose the key to the
	// workload.
	if err := ca.PrepareDirectories(cfg.CA.StateDir, cfg.CA.OutDir); err != nil {
		return nil, nil, "", fmt.Errorf("certificate authority: %w", err)
	}
	authority, loaded, err := ca.LoadOrNew(cfg.CA.StateDir, ca.Options{LeafTTL: cfg.CA.LeafTTL.Duration()})
	if err != nil {
		return nil, nil, "", fmt.Errorf("certificate authority: %w", err)
	}
	certPath, err := authority.WriteCertificate(cfg.CA.OutDir)
	if err != nil {
		return nil, nil, "", fmt.Errorf("certificate authority: %w", err)
	}
	store, err := ca.NewStore(authority, cfg.CA.CacheSize)
	if err != nil {
		return nil, nil, "", fmt.Errorf("certificate authority: %w", err)
	}
	logger.Info("certificate authority ready",
		slog.String("certificate", certPath),
		slog.Bool("loaded_from_state_dir", loaded),
		slog.Time("not_after", authority.NotAfter()))
	return authority, store, certPath, nil
}

// announce says what the process enforces and where each setting came from,
// on every start.
func (p *process) announce() {
	deny := p.matcher.DenyList()
	p.logger.Info("egress policy",
		slog.String("document_digest", p.cfg.Digest),
		slog.String("config_digest", p.cfg.ConfigDigest),
		slog.String("sandbox_id", p.cfg.Sandbox.ID),
		slog.Any("overridden", p.cfg.Overridden),
		slog.Any("endpoint_hosts", p.matcher.Hosts()),
		slog.Int("listen_dns_port", p.cfg.Listen.DNSPort),
		slog.Any("cluster_cidrs", deny.ClusterCIDRs()))
	for _, exception := range deny.Exceptions() {
		p.logger.Warn("deny list exception: the platform deny list does not cover this range",
			slog.String("range", exception.String()))
	}
	if p.credentials == nil && p.selector == nil {
		p.logger.Warn("no credential source; every endpoint that names a credential denies " +
			"with credential_unavailable")
		return
	}
	p.logger.Warn("credential source", slog.String("source", p.describeSource()))
}

// describeSource names the credential source in force: the process source,
// or the per-sandbox selector.
func (p *process) describeSource() string {
	switch {
	case p.selector != nil:
		return p.selector.Describe()
	case p.credentials != nil:
		return p.credentials.Describe()
	default:
		return "none"
	}
}

// errCredentials names a credential source that this build cannot construct.
var errCredentials = errors.New("credentials")

// connectAuthFor loads listen.connect_auth_file. Nil means every client may
// CONNECT.
func connectAuthFor(cfg *config.Config) (*proxy.ConnectAuth, error) {
	if cfg.Listen.ConnectAuthFile == "" {
		return nil, nil //nolint:nilnil // no file means no credential, which Options reads as nil
	}
	auth, err := proxy.LoadConnectAuth(cfg.Listen.ConnectAuthFile)
	if err != nil {
		return nil, fmt.Errorf("connect auth: %w", err)
	}
	return auth, nil
}

// identities is what the document says about who the proxy acts as and who
// may reach it: one process source, or a selector of one source per sandbox
// with the assertion check that selects from it, and the connect credential.
// A field is nil where the document names nothing for it.
type identities struct {
	credentials credential.Source
	selector    *credential.Selector
	sandboxes   *proxy.SandboxIdentification
	connectAuth *proxy.ConnectAuth
}

// identitySources builds the identities from the document.
func identitySources(cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool) (identities, error) {
	var (
		ids identities
		err error
	)
	switch kind := cfg.CredentialSource(); kind {
	case config.SourceNone:
	case config.SourceStaticFile:
		ids.credentials, ids.selector, err = staticSources(cfg)
	case config.SourceExchange:
		ids.credentials, ids.selector, err = exchangeSources(cfg, deny, roots)
	default:
		err = fmt.Errorf("%w: %q is not a source this build reads", errCredentials, kind)
	}
	if err != nil {
		return identities{}, err
	}
	if ids.sandboxes, err = sandboxIdentification(cfg, ids.selector); err != nil {
		return identities{}, err
	}
	if ids.connectAuth, err = connectAuthFor(cfg); err != nil {
		return identities{}, err
	}
	return ids, nil
}

// staticSources reads credentials.static_file: the file itself for one
// sandbox, or one view per sandbox and application entry. The process
// source reads the shared entries alone, so a scoped entry in a document
// that maps nothing is refused rather than ignored.
//
//nolint:ireturn // the process source is the interface the proxy consumes
func staticSources(cfg *config.Config) (credential.Source, *credential.Selector, error) {
	file, err := credential.LoadStaticFile(cfg.Credentials.StaticFile)
	if err != nil {
		return nil, nil, fmt.Errorf("credentials: %w", err)
	}
	if len(cfg.Sandboxes) == 0 && len(cfg.Applications) == 0 {
		if scoped := file.Scoped(); scoped > 0 {
			return nil, nil, fmt.Errorf("%w: credentials.static_file: %d entries are scoped to a sandbox or application, "+
				"which needs sandbox_assertion and sandboxes or applications in the document", errCredentials, scoped)
		}
		return file, nil, nil
	}
	selector := credential.NewSelector()
	if err := addStaticSandboxes(selector, file, cfg); err != nil {
		return nil, nil, err
	}
	if err := addStaticApplications(selector, file, cfg); err != nil {
		return nil, nil, err
	}
	return nil, selector, nil
}

// addStaticSandboxes maps each sandbox entry to its view of the file.
func addStaticSandboxes(selector *credential.Selector, file *credential.StaticFile, cfg *config.Config) error {
	// A static entry selects by sandbox name alone, so a name that repeats
	// across workspaces could not be told apart. Zone mode has no such
	// limit, because each entry names its own identity.
	byName := make(map[string]struct{}, len(cfg.Sandboxes))
	for _, entry := range cfg.Sandboxes {
		if _, repeated := byName[entry.Name]; repeated {
			return fmt.Errorf("%w: sandbox name %q repeats across workspaces; "+
				"a static credential file selects by name alone", errCredentials, entry.Name)
		}
		byName[entry.Name] = struct{}{}
		key := credential.SandboxKey{Name: entry.Name, Workspace: entry.Workspace}
		if err := selector.Add(key, credential.Selected{Source: file.ForSandbox(entry.Name)}); err != nil {
			return fmt.Errorf("credentials: %w", err)
		}
	}
	return refuseUnmapped(cfg, "sandbox", "sandboxes", file.Sandboxes(), byName)
}

// addStaticApplications maps each application entry to its view of the
// file.
func addStaticApplications(selector *credential.Selector, file *credential.StaticFile, cfg *config.Config) error {
	byName := make(map[string]struct{}, len(cfg.Applications))
	for _, entry := range cfg.Applications {
		byName[entry.Name] = struct{}{}
		selected := credential.Selected{Source: file.ForApplication(entry.Name)}
		if err := selector.AddApplication(entry.Name, selected); err != nil {
			return fmt.Errorf("credentials: %w", err)
		}
	}
	return refuseUnmapped(cfg, "application", "applications", file.Applications(), byName)
}

// refuseUnmapped refuses a file entry scoped to a name the document does not
// map. Such an entry would never answer, and the name would read the shared
// credential instead.
func refuseUnmapped(cfg *config.Config, what, list string, named []string, mapped map[string]struct{}) error {
	for _, name := range named {
		if _, ok := mapped[name]; !ok {
			return fmt.Errorf("%w: %s holds entries for %s %q, which %s does not name",
				errCredentials, cfg.Credentials.StaticFile, what, name, list)
		}
	}
	return nil
}

// exchangeSources builds the exchange for the top-level identity, or one
// exchange per sandbox and application entry.
//
//nolint:ireturn // the process source is the interface the proxy consumes
func exchangeSources(
	cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool,
) (credential.Source, *credential.Selector, error) {
	if cfg.Identity != nil {
		source, err := tokenExchange(cfg.Identity, cfg, deny, roots)
		return source, nil, err
	}
	selector := credential.NewSelector()
	for _, entry := range cfg.Sandboxes {
		selected, err := entrySource(entry.Identity, cfg, deny, roots)
		if err != nil {
			return nil, nil, fmt.Errorf("sandbox %q: %w", entry.Name, err)
		}
		key := credential.SandboxKey{Name: entry.Name, Workspace: entry.Workspace}
		if err := selector.Add(key, selected); err != nil {
			return nil, nil, fmt.Errorf("credentials: %w", err)
		}
	}
	for _, entry := range cfg.Applications {
		selected, err := entrySource(entry.Identity, cfg, deny, roots)
		if err != nil {
			return nil, nil, fmt.Errorf("application %q: %w", entry.Name, err)
		}
		if err := selector.AddApplication(entry.Name, selected); err != nil {
			return nil, nil, fmt.Errorf("credentials: %w", err)
		}
	}
	return nil, selector, nil
}

// entrySource builds the source one entry's identity names: the exchange as
// the asserted sandbox when the identity names the assertion as its client,
// or else the exchange as the identity's own application credential.
func entrySource(
	identity *config.Identity, cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool,
) (credential.Selected, error) {
	if identity.ClientAssertion == config.ClientAssertionSandbox {
		source, err := exchange.NewAssertionSource(exchange.AssertionOptions{
			ZoneURL:  identity.ZoneURL,
			Timeout:  cfg.Limits.ExchangeTimeout.Duration(),
			Roots:    roots,
			DenyAddr: deny.DeniesAddr,
		})
		if err != nil {
			return credential.Selected{}, fmt.Errorf("credentials: %w", err)
		}
		return credential.Selected{Source: source, SubjectIsClient: true}, nil
	}
	source, err := tokenExchange(identity, cfg, deny, roots)
	if err != nil {
		return credential.Selected{}, err
	}
	return credential.Selected{Source: source, ClientID: identity.ClientID}, nil
}

// sandboxIdentification builds the per-request sandbox check from
// sandbox_assertion. Nil when the document has none.
func sandboxIdentification(cfg *config.Config, selector *credential.Selector) (*proxy.SandboxIdentification, error) {
	if cfg.SandboxAssertion == nil {
		return nil, nil //nolint:nilnil // one sandbox per process is the default posture
	}
	settings := cfg.SandboxAssertion
	pemBytes, err := os.ReadFile(settings.IssuerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("sandbox assertion: %w", err)
	}
	var opts []assertion.Option
	if settings.Issuer != "" {
		opts = append(opts, assertion.WithIssuer(settings.Issuer))
	}
	verifier, err := assertion.NewVerifier(pemBytes, settings.Audience, settings.MaxAge.Duration(), opts...)
	if err != nil {
		return nil, fmt.Errorf("sandbox assertion: %w", err)
	}
	return &proxy.SandboxIdentification{Header: settings.Header, Verifier: verifier, Selector: selector}, nil
}

// tokenExchange builds a source that mints a credential for each request
// against the zone. It reads the client secret once, so a rotated secret
// takes effect after restart.
func tokenExchange(
	identity *config.Identity, cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool,
) (*exchange.Source, error) {
	var secret string
	if identity.ClientSecretFile != "" {
		read, err := credential.ReadSecretFile(identity.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}
		secret = read
	}
	source, err := exchange.New(exchange.Options{
		ZoneURL:           identity.ZoneURL,
		ClientID:          identity.ClientID,
		ImpersonateUser:   identity.Impersonate.User,
		WorkloadTokenFile: identity.WorkloadTokenFile,
		ClientSecret:      secret,
		Timeout:           cfg.Limits.ExchangeTimeout.Duration(),
		Roots:             roots,
		DenyAddr:          deny.DeniesAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	return source, nil
}

// info is what the admin socket reports at /info.
func (p *process) info() any {
	deny := p.matcher.DenyList()
	source := p.describeSource()
	return map[string]any{
		"version":              version(),
		"sandbox_id":           p.cfg.Sandbox.ID,
		"document_digest":      p.cfg.Digest,
		"config_digest":        p.cfg.ConfigDigest,
		"overridden":           p.cfg.Overridden,
		listenKey:              p.cfg.Listen,
		"ca":                   map[string]any{"out_dir": p.cfg.CA.OutDir, "not_after": p.authority.NotAfter()},
		"limits":               p.cfg.Limits,
		"credential_source":    source,
		"netsetup_receipt":     p.cfg.Netsetup.Receipt,
		"dns":                  p.dnsInfo(),
		"endpoint_hosts":       p.matcher.Hosts(),
		"cluster_cidrs":        deny.ClusterCIDRs(),
		"deny_list_exceptions": deny.Exceptions(),
	}
}

// dnsInfo is what /info reports about name resolution: whether a resolver
// runs, the names it answers for and where it forwards.
func (p *process) dnsInfo() map[string]any {
	if p.resolver == nil {
		return map[string]any{portKey: 0}
	}
	return map[string]any{
		portKey:      p.cfg.Listen.DNSPort,
		"resolves":   p.resolver.Hosts(),
		"forward_to": p.resolver.Forward(),
	}
}

// listenKey is the field /info reports the listen settings under.
const listenKey = "listen"

// portKey is the field /info reports the resolver's port under.
const portKey = "port"

// errNotReady is what the admin socket reports at /readyz while the
// process is not serving, which is before the bind and again from the
// moment the drain starts.
var errNotReady = errors.New("egress-proxy is not serving")

// ready decides /readyz. It answers once every frontend is bound and
// ca.crt is on ca.out_dir, which are the two things the workload needs
// before it makes its first request. The sidecar's startup probe reads it,
// so the agent container does not start before the certificate it must
// trust exists, and never while the port the capture redirects to is
// unbound.
func (p *process) ready() error {
	if !p.listening.Load() {
		return fmt.Errorf("%w: the frontend listeners are not bound", errNotReady)
	}
	if _, err := os.Stat(p.certPath); err != nil {
		return fmt.Errorf("%w: %s is not readable: %w", errNotReady, p.certPath, err)
	}
	return nil
}

// containment reads the netsetup receipt and refuses to serve behind a
// ruleset that disagrees with what this process is about to do. It returns
// nil without reading the receipt when the process runs neither a
// transparent frontend nor a resolver.
//
// A process that runs only the resolver still reads the receipt. Without
// the DNS redirect, no lookup reaches the resolver.
//
// The check runs before any listener is bound, so a sidecar that fails the
// check never services any request. The probes supply capability, sysctl,
// network namespace, and owner reads. A zero-value request reads this process
// and its filesystem.
func containment(cfg *config.Config, probes netsetup.ContainmentRequest) (*netsetup.Receipt, error) {
	if cfg.Listen.TransparentPort == 0 && cfg.Listen.DNSPort == 0 {
		return nil, nil //nolint:nilnil // no capture and no resolver is a posture, not a failure
	}
	if cfg.Listen.TransparentPort != 0 && !transparent.Supported {
		return nil, fmt.Errorf("%w: listen.transparent_port is set and this platform has no SO_ORIGINAL_DST",
			transparent.ErrNotSupported)
	}
	request := probes
	request.Path = cfg.Netsetup.Receipt
	request.TransparentPort = cfg.Listen.TransparentPort
	request.DNSPort = cfg.Listen.DNSPort
	request.UID = os.Getuid()
	receipt, err := netsetup.Containment(request)
	if err != nil {
		return nil, fmt.Errorf("network capture: %w", err)
	}
	return &receipt, nil
}

// redirectedFamilies is the address families the receipt records, nil
// without a receipt. The bind compares the capture and resolver sockets
// against them.
func redirectedFamilies(receipt *netsetup.Receipt) []string {
	if receipt == nil {
		return nil
	}
	return receipt.Families
}

// capture builds the transparent frontend behind a receipt that checked
// out.
func capture(cfg *config.Config, receipt *netsetup.Receipt, server *proxy.Server, logger *slog.Logger) (
	*transparent.Frontend, error,
) {
	if receipt == nil || cfg.Listen.TransparentPort == 0 {
		return nil, nil //nolint:nilnil // no transparent frontend is a posture, not a failure
	}
	logger.Info("transparent network capture enabled",
		slog.String("receipt", cfg.Netsetup.Receipt),
		slog.String("ruleset_digest", receipt.RulesetDigest),
		slog.Int("proxy_uid", receipt.ProxyUID),
		slog.Int("redirect_port", receipt.RedirectPort),
		slog.Any("capture_ports", receipt.CapturePorts),
		slog.Int("dns_port", receipt.DNSPort),
		slog.Any("families", receipt.Families),
		slog.Any("cleartext_ports", cfg.Listen.CleartextPorts))
	for _, port := range uncaptured(receipt.CapturePorts, cfg.Listen.CleartextPorts) {
		logger.Warn("listen.cleartext_ports names a port outside of the network capture and transparent redirect, "+
			"so nothing reaches this frontend on it",
			slog.Int("port", port))
	}
	frontend, err := transparent.New(transparent.Options{
		Handler:        server.ServeRedirected,
		Logger:         logger,
		CleartextPorts: cfg.Listen.CleartextPorts,
		MaxConnections: cfg.Limits.MaxConnections,
		IdleTimeout:    cfg.Limits.IdleTimeout.Duration(),
	})
	if err != nil {
		return nil, fmt.Errorf("transparent frontend: %w", err)
	}
	return frontend, nil
}

// errResolver is an allowlist resolver this process refuses to serve.
var errResolver = errors.New("dns resolver")

// nameResolver builds the allowlist resolver. It returns nil when
// listen.dns_port is unset.
//
// The names that resolve come from the document alone. The resolvers an
// allowed name is forwarded to come from dns.forward_to, or from the
// netsetup receipt when dns.forward_to is empty.
func nameResolver(cfg *config.Config, receipt *netsetup.Receipt, sink audit.Sink, logger *slog.Logger) (
	*dns.Resolver, error,
) {
	if cfg.Listen.DNSPort == 0 {
		return nil, nil //nolint:nilnil // no resolver is a posture, not a failure
	}
	forward := cfg.DNS.ForwardTo
	if len(forward) == 0 && receipt != nil {
		forward = receipt.DNSServers
	}
	if len(forward) == 0 {
		return nil, fmt.Errorf("%w: listen.dns_port is set and no resolver is named. Set dns.forward_to, or run "+
			"the init container so the receipt names the cluster resolvers", errResolver)
	}
	resolver, err := dns.New(dns.Options{
		Hosts:          cfg.DNSHosts(),
		Forward:        forward,
		Port:           cfg.Listen.DNSPort,
		Audit:          sink,
		Logger:         logger,
		MaxConnections: cfg.Limits.MaxDNSConnections,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errResolver, err)
	}
	logger.Info("name resolution in force",
		slog.Int("port", cfg.Listen.DNSPort),
		slog.Any("resolves", resolver.Hosts()),
		slog.Any("forward_to", resolver.Forward()))
	return resolver, nil
}

// uncaptured returns cleartext ports outside the capture and redirect. The
// settings come from different containers. The receipt lets the proxy compare
// them.
func uncaptured(captured, cleartext []int) []int {
	covered := make(map[int]bool, len(captured))
	for _, port := range captured {
		covered[port] = true
	}
	var out []int
	for _, port := range cleartext {
		if !covered[port] {
			out = append(out, port)
		}
	}
	return out
}

// serve runs the proxy service until a signal arrives or a component
// fails on a fatal error. On shutdown, each server drains within its grace period.
//
// Returns once every server has stopped.
func (p *process) serve(ctx context.Context) error {
	listener, captured, resolver, err := p.bind(ctx)
	if err != nil {
		return err
	}
	group, ctx := errgroup.WithContext(ctx)
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	for _, captured := range captured {
		group.Go(func() error { return p.transparent.Serve(ctx, captured) })
	}
	if p.resolver != nil {
		group.Go(func() error { return p.resolver.Serve(ctx, resolver) })
	}
	group.Go(func() error { return p.server.Run(ctx, listener) })
	group.Go(func() error { return p.admin.Run(ctx) })
	group.Go(func() error {
		<-ctx.Done()
		// The admin socket stops accepting as the drain starts. Clearing
		// the flag covers a /readyz request that is already in flight.
		p.listening.Store(false)
		p.logger.Info("stopping", slog.String("cause", context.Cause(ctx).Error()))
		return nil
	})
	if err := group.Wait(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// version is the module version recorded in the binary, or "devel" for a
// build outside a tagged module.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "devel"
	}
	return info.Main.Version
}

// bind opens every socket the process serves on and then reports
// readiness. The order is the contract: /readyz answers 200 only after the
// transparent sockets are bound, so the kubelet never releases the workload
// while the port the capture redirects to refuses connections.
func (p *process) bind(ctx context.Context) (net.Listener, []net.Listener, dns.Sockets, error) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", p.cfg.Listen.Connect)
	if err != nil {
		return nil, nil, dns.Sockets{}, fmt.Errorf("listen on %s: %w", p.cfg.Listen.Connect, err)
	}
	captured, err := p.captureListeners(ctx)
	if err != nil {
		return nil, nil, dns.Sockets{}, errors.Join(err, listener.Close())
	}
	resolver, err := p.resolverSockets(ctx)
	if err != nil {
		return nil, nil, dns.Sockets{}, errors.Join(err, listener.Close(), closeAll(captured))
	}
	p.listening.Store(true)
	p.logger.Info("serving",
		slog.String("connect", listener.Addr().String()),
		slog.String("admin", p.admin.Path()))
	return listener, captured, resolver, nil
}

// resolverSockets binds the allowlist resolver, one UDP and one TCP socket
// per address family. It returns nothing when the process runs no
// resolver.
//
// If a family the receipt names has no bound socket, the proxy refuses to
// start. Otherwise the redirect would send that family's queries to a
// closed port.
func (p *process) resolverSockets(ctx context.Context) (dns.Sockets, error) {
	if p.resolver == nil {
		return dns.Sockets{}, nil
	}
	listen := p.listenResolver
	if listen == nil {
		listen = dns.Listen
	}
	sockets, err := listen(ctx, p.cfg.Listen.DNSPort)
	if errors.Is(err, syscall.EACCES) {
		return dns.Sockets{}, privilegedPortError(errResolver, err, p.cfg.Listen.DNSPort)
	}
	if err != nil {
		return dns.Sockets{}, fmt.Errorf("%w: %w", errResolver, err)
	}
	bound := boundFamilies(sockets.Stream)
	if missing := missingFamilies(p.receiptFamilies, bound); len(missing) > 0 {
		return dns.Sockets{}, errors.Join(
			fmt.Errorf("%w: the netsetup receipt names %s and the resolver bound %s, so the redirect sends %s "+
				"queries nowhere", errResolver, strings.Join(p.receiptFamilies, ","),
				strings.Join(bound, ","), strings.Join(missing, ",")),
			sockets.Close(),
		)
	}
	p.logger.Info("answering name lookups", slog.String("sockets", sockets.Addresses()))
	return sockets, nil
}

// errCapture is a transparent frontend this process refuses to serve
// behind.
var errCapture = errors.New("transparent frontend")

// captureListeners binds one transparent frontend socket per address family,
// on loopback. It returns nil when no transparent frontend is configured.
//
// The receipt names the families the init container redirects. If one of
// them has no bound socket, the proxy refuses to start. Otherwise the
// redirect would send that family's connections to a closed port.
func (p *process) captureListeners(ctx context.Context) ([]net.Listener, error) {
	if p.transparent == nil {
		return nil, nil
	}
	listen := p.listenCapture
	if listen == nil {
		listen = transparent.Listen
	}
	listeners, err := listen(ctx, p.cfg.Listen.TransparentPort)
	if errors.Is(err, syscall.EACCES) {
		return nil, privilegedPortError(errCapture, err, p.cfg.Listen.TransparentPort)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCapture, err)
	}
	bound := boundFamilies(listeners)
	if missing := missingFamilies(p.receiptFamilies, bound); len(missing) > 0 {
		return nil, errors.Join(
			fmt.Errorf("%w: the netsetup receipt names %s and the capture bound %s, so the redirect sends %s nowhere",
				errCapture, strings.Join(p.receiptFamilies, ","),
				strings.Join(bound, ","), strings.Join(missing, ",")),
			closeAll(listeners),
		)
	}
	p.logger.Info("capturing redirected connections",
		slog.String("transparent", transparent.Addresses(listeners)),
		slog.Any("families", bound))
	return listeners, nil
}

// privilegedPortError explains an EACCES from binding a port below
// net.ipv4.ip_unprivileged_port_start.
func privilegedPortError(surface, err error, port int) error {
	return fmt.Errorf("%w: %w. Port %d is below net.ipv4.ip_unprivileged_port_start, "+
		"so binding it needs CAP_NET_BIND_SERVICE. This binary holds it as a file capability, which the kernel "+
		"grants only from the bounding set and, under no_new_privs, only when the process that ran this binary "+
		"held it. Give the sidecar capabilities.add NET_BIND_SERVICE and make this binary the container "+
		"entrypoint", surface, err, port)
}

// boundFamilies names the address families a set of listeners covers, in
// the words the netsetup receipt uses.
func boundFamilies(listeners []net.Listener) []string {
	var families []string
	for _, listener := range listeners {
		family := netsetup.FamilyIPv6.String()
		if addr, ok := listener.Addr().(*net.TCPAddr); ok && addr.IP.To4() != nil {
			family = netsetup.FamilyIPv4.String()
		}
		if !slices.Contains(families, family) {
			families = append(families, family)
		}
	}
	return families
}

// missingFamilies names the families the receipt records that no listener
// covers.
func missingFamilies(programmed, bound []string) []string {
	var missing []string
	for _, family := range programmed {
		if !slices.Contains(bound, family) {
			missing = append(missing, family)
		}
	}
	return missing
}

// closeAll closes every listener and joins what the closes reported.
func closeAll(listeners []net.Listener) error {
	errs := make([]error, 0, len(listeners))
	for _, listener := range listeners {
		errs = append(errs, listener.Close())
	}
	return errors.Join(errs...)
}
