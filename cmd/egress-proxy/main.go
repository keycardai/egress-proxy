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
	"syscall"
	"time"

	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"

	"github.com/keycardai/egress-proxy/internal/admin"
	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/exchange"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/proxy"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// shutdownGrace bounds how long a stop waits for in-flight requests.
const shutdownGrace = 10 * time.Second

// envPrefix is the prefix of every environment variable this command reads.
// A manifest lint can refuse any other variable with this prefix on the proxy
// container.
const envPrefix = "EGRESS_PROXY_"

func main() {
	action := func(ctx context.Context, opts flags) error {
		return run(ctx, opts, os.Stdout, os.Stderr)
	}
	if err := command(os.Stderr, action).Run(context.Background(), os.Args); err != nil {
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
	transparent           string
	admin                 string
	netsetupReceipt       string
	caOutDir              string
	caStateDir            string
	clientSecretFile      string
	credentialStaticFile  string
	leafTTL               time.Duration
	cacheSize             int
	upstreamCAFiles       []string
	maxConnections        int
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
		Transparent:           f.transparent,
		Admin:                 f.admin,
		NetsetupReceipt:       f.netsetupReceipt,
		CAOutDir:              f.caOutDir,
		CAStateDir:            f.caStateDir,
		ClientSecretFile:      f.clientSecretFile,
		CredentialStaticFile:  f.credentialStaticFile,
		LeafTTL:               f.leafTTL,
		CacheSize:             f.cacheSize,
		UpstreamCAFiles:       f.upstreamCAFiles,
		MaxConnections:        f.maxConnections,
		IdleTimeout:           f.idleTimeout,
		ResponseHeaderTimeout: f.responseHeaderTimeout,
		ExchangeTimeout:       f.exchangeTimeout,
	}
}

// flagSet defines the configurable command line options and environment
// variables.
func flagSet(opts *flags) []cli.Flag {
	return slices.Concat([]cli.Flag{
		stringFlag("config", "CONFIG", &opts.configPath, "path to the configuration document", true),
		stringFlag("sandbox-id", "SANDBOX_ID", &opts.sandboxID, "the sandbox on every audit record (sandbox.id)", false),
		stringFlag("zone-url", "ZONE_URL", &opts.zoneURL, "the Keycard zone (identity.zone_url)", false),
		stringFlag("client-id", "CLIENT_ID", &opts.clientID, "the application credential id (identity.client_id)", false),
		stringFlag("workload-token-file", "WORKLOAD_TOKEN_FILE", &opts.workloadTokenFile,
			"path of the projected ServiceAccount token (identity.workload_token_file)", false),
		stringFlag("impersonate-user", "IMPERSONATE_USER", &opts.impersonateUser,
			"the user every exchange acts for (identity.impersonate.user)", false),
	}, listenFlags(opts), []cli.Flag{
		stringFlag("ca-out-dir", "CA_OUT_DIR", &opts.caOutDir,
			"directory the CA certificate is written to (ca.out_dir)", false),
		stringFlag("ca-state-dir", "CA_STATE_DIR", &opts.caStateDir,
			"memory-backed directory holding the CA across restarts (ca.state_dir)", false),
		stringFlag("client-secret-file", "CLIENT_SECRET_FILE", &opts.clientSecretFile,
			"path of the file holding the application credential secret (identity.client_secret_file)", false),
		stringFlag("credential-static-file", "CREDENTIAL_STATIC_FILE", &opts.credentialStaticFile,
			"file of credentials by resource, for tests and development (credentials.static_file)", false),
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

// listenFlags are where the process accepts connections and what it checks
// its own containment against.
func listenFlags(opts *flags) []cli.Flag {
	return []cli.Flag{
		stringFlag(
			"connect",
			"CONNECT",
			&opts.connect,
			"address of the CONNECT frontend, host:port (listen.connect)",
			false,
		),
		stringFlag("transparent", "TRANSPARENT", &opts.transparent,
			"address of the transparent frontend the netsetup rules redirect to, host:port "+
				"(listen.transparent); empty runs none", false),
		stringFlag("admin", "ADMIN", &opts.admin, "path of the admin Unix socket (listen.admin)", false),
		stringFlag("netsetup-receipt", "NETSETUP_RECEIPT", &opts.netsetupReceipt,
			"file the init container recorded what it programmed in (netsetup.receipt)", false),
	}
}

func stringFlag(name, envName string, dest *string, usage string, required bool) *cli.StringFlag {
	return &cli.StringFlag{Name: name, Destination: dest, Sources: env(envName), Usage: usage, Required: required}
}

// env is the variable a flag reads when the command line omits it.
func env(name string) cli.ValueSourceChain {
	return cli.EnvVars(envPrefix + name)
}

// command builds the command line.
func command(stderr io.Writer, action func(context.Context, flags) error) *cli.Command {
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
		Action: func(ctx context.Context, _ *cli.Command) error {
			return action(ctx, opts)
		},
	}
}

// process represents the configured components which make up the proxy process.
type process struct {
	cfg         *config.Config
	logger      *slog.Logger
	matcher     *policy.Matcher
	authority   *ca.Authority
	credentials credential.Source
	server      *proxy.Server
	admin       *admin.Server
	transparent *transparent.Frontend
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
	authority, store, err := certificates(cfg, logger)
	if err != nil {
		return nil, err
	}
	credentials, err := credentialSource(cfg, deny, roots)
	if err != nil {
		return nil, err
	}
	server, err := proxy.New(proxy.Options{
		Matcher:      matcher,
		Certificates: store,
		Audit: audit.NewStamped(audit.NewJSONSink(stdout), audit.Stamp{
			SandboxID:      cfg.Sandbox.ID,
			DocumentDigest: cfg.Digest,
			ConfigDigest:   cfg.ConfigDigest,
		}, nil),
		UpstreamRoots:         roots,
		Credentials:           credentials,
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
		credentials: credentials, server: server,
	}
	if proc.transparent, err = capture(cfg, server, logger, netsetup.ContainmentRequest{}); err != nil {
		return nil, err
	}
	proc.admin, err = admin.New(ctx, cfg.Listen.Admin, proc.info, logger)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	proc.announce()
	return proc, nil
}

// certificates prepares the authority the proxy terminates tunnels with and
// writes its certificate where the workload reads it.
func certificates(cfg *config.Config, logger *slog.Logger) (*ca.Authority, *ca.Store, error) {
	// A state directory inside the output directory would expose the key to the
	// workload.
	if err := ca.PrepareDirectories(cfg.CA.StateDir, cfg.CA.OutDir); err != nil {
		return nil, nil, fmt.Errorf("certificate authority: %w", err)
	}
	authority, loaded, err := ca.LoadOrNew(cfg.CA.StateDir, ca.Options{LeafTTL: cfg.CA.LeafTTL.Duration()})
	if err != nil {
		return nil, nil, fmt.Errorf("certificate authority: %w", err)
	}
	certPath, err := authority.WriteCertificate(cfg.CA.OutDir)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate authority: %w", err)
	}
	store, err := ca.NewStore(authority, cfg.CA.CacheSize)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate authority: %w", err)
	}
	logger.Info("certificate authority ready",
		slog.String("certificate", certPath),
		slog.Bool("loaded_from_state_dir", loaded),
		slog.Time("not_after", authority.NotAfter()))
	return authority, store, nil
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
		slog.Any("cluster_cidrs", deny.ClusterCIDRs()))
	for _, exception := range deny.Exceptions() {
		p.logger.Warn("deny list exception: the platform deny list does not cover this range",
			slog.String("range", exception.String()))
	}
	if p.credentials == nil {
		p.logger.Warn("no credential source; every endpoint that names a credential denies " +
			"with credential_unavailable")
		return
	}
	p.logger.Warn("credential source", slog.String("source", p.credentials.Describe()))
}

// errCredentials names a credential source that this build cannot construct.
var errCredentials = errors.New("credentials")

// credentialSource builds the configured source. It returns nil when none is set.
//
//nolint:ireturn // delegating the constructor to the configured source is intentional
func credentialSource(cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool) (credential.Source, error) {
	switch kind := cfg.CredentialSource(); kind {
	case config.SourceNone:
		return nil, nil //nolint:nilnil // no source is a posture, not a failure
	case config.SourceStaticFile:
		source, err := credential.LoadStaticFile(cfg.Credentials.StaticFile)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}
		return source, nil
	case config.SourceExchange:
		return tokenExchange(cfg, deny, roots)
	default:
		return nil, fmt.Errorf("%w: %q is not a source this build reads", errCredentials, kind)
	}
}

// tokenExchange builds a source that mints a credential for each request
// against the zone. It reads the client secret once, so a rotated secret
// takes effect after restart.
func tokenExchange(cfg *config.Config, deny *policy.DenyList, roots *x509.CertPool) (*exchange.Source, error) {
	var secret string
	if cfg.Identity.ClientSecretFile != "" {
		read, err := credential.ReadSecretFile(cfg.Identity.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("credentials: %w", err)
		}
		secret = read
	}
	source, err := exchange.New(exchange.Options{
		ZoneURL:           cfg.Identity.ZoneURL,
		ClientID:          cfg.Identity.ClientID,
		ImpersonateUser:   cfg.Identity.Impersonate.User,
		WorkloadTokenFile: cfg.Identity.WorkloadTokenFile,
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
	source := "none"
	if p.credentials != nil {
		source = p.credentials.Describe()
	}
	return map[string]any{
		"version":              version(),
		"sandbox_id":           p.cfg.Sandbox.ID,
		"document_digest":      p.cfg.Digest,
		"config_digest":        p.cfg.ConfigDigest,
		"overridden":           p.cfg.Overridden,
		"listen":               p.cfg.Listen,
		"ca":                   map[string]any{"out_dir": p.cfg.CA.OutDir, "not_after": p.authority.NotAfter()},
		"limits":               p.cfg.Limits,
		"credential_source":    source,
		"netsetup_receipt":     p.cfg.Netsetup.Receipt,
		"endpoint_hosts":       p.matcher.Hosts(),
		"cluster_cidrs":        deny.ClusterCIDRs(),
		"deny_list_exceptions": deny.Exceptions(),
	}
}

// capture builds the transparent frontend, after the netsetup receipt shows
// that the rules redirect to it and that this process cannot change them. A
// configuration with no listen.transparent runs no frontend and checks no
// receipt.
//
// The check runs before any listener is bound, so a sidecar whose
// containment does not hold never serves. probes supplies the capability,
// sysctl and owner reads. Its zero value reads this process and its
// filesystem.
func capture(
	cfg *config.Config, server *proxy.Server, logger *slog.Logger, probes netsetup.ContainmentRequest,
) (*transparent.Frontend, error) {
	if cfg.Listen.Transparent == "" {
		return nil, nil //nolint:nilnil // no transparent frontend is a posture, not a failure
	}
	if !transparent.Supported {
		return nil, fmt.Errorf("%w: listen.transparent is set and this platform has no SO_ORIGINAL_DST",
			transparent.ErrNotSupported)
	}
	request := probes
	request.Path = cfg.Netsetup.Receipt
	request.TransparentPort = cfg.TransparentPort()
	request.UID = os.Getuid()
	receipt, err := netsetup.Containment(request)
	if err != nil {
		return nil, fmt.Errorf("network capture: %w", err)
	}
	logger.Info("network capture in force",
		slog.String("receipt", cfg.Netsetup.Receipt),
		slog.String("ruleset_digest", receipt.RulesetDigest),
		slog.Int("proxy_uid", receipt.ProxyUID),
		slog.Int("redirect_port", receipt.RedirectPort),
		slog.Any("capture_ports", receipt.CapturePorts),
		slog.Any("families", receipt.Families),
		slog.Any("cleartext_ports", cfg.Listen.CleartextPorts))
	for _, port := range uncaptured(receipt.CapturePorts, cfg.Listen.CleartextPorts) {
		logger.Warn("listen.cleartext_ports names a port the redirect does not cover, "+
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

// uncaptured names the cleartext ports the redirect does not cover. The two
// settings live in different containers' arguments, and the receipt is what
// reconciles them.
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
// Returns once both servers have stopped.
func (p *process) serve(ctx context.Context) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", p.cfg.Listen.Connect)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.cfg.Listen.Connect, err)
	}
	p.logger.Info("serving",
		slog.String("connect", listener.Addr().String()),
		slog.String("admin", p.admin.Path()))

	captured, err := p.captureListeners(ctx)
	if err != nil {
		_ = listener.Close()
		return err
	}
	group, ctx := errgroup.WithContext(ctx)
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	for _, captured := range captured {
		group.Go(func() error { return p.transparent.Serve(ctx, captured) })
	}
	group.Go(func() error { return p.server.Run(ctx, listener) })
	group.Go(func() error { return p.admin.Run(ctx) })
	group.Go(func() error {
		<-ctx.Done()
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

// captureListeners binds the transparent frontend, one socket per address
// family. It returns nothing when no transparent frontend is configured.
func (p *process) captureListeners(ctx context.Context) ([]net.Listener, error) {
	if p.transparent == nil {
		return nil, nil
	}
	listeners, err := transparent.Listen(ctx, p.cfg.Listen.Transparent)
	if errors.Is(err, syscall.EACCES) {
		return nil, fmt.Errorf("transparent frontend: %w. Port %d is below net.ipv4.ip_unprivileged_port_start, "+
			"so binding it needs CAP_NET_BIND_SERVICE. Grant it as a file capability on this binary, and leave "+
			"allowPrivilegeEscalation unset or true on the sidecar: it sets no_new_privs, under which the kernel "+
			"ignores file capabilities", err, p.cfg.TransparentPort())
	}
	if err != nil {
		return nil, fmt.Errorf("transparent frontend: %w", err)
	}
	p.logger.Info("capturing redirected connections",
		slog.String("transparent", transparent.Addresses(listeners)))
	return listeners, nil
}
