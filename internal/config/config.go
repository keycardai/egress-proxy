// Package config reads the proxy's configuration document: the sandbox it
// serves, the identity it exchanges with, the endpoints it can reach, and
// the process settings.
package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"sigs.k8s.io/yaml"

	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/internal/policy"
	"github.com/keycardai/egress-proxy/internal/strictdoc"
)

// Defaults for the process settings.
//
// Every default path names a directory inside a mount rather than the mount
// point. A mount point belongs to root at mode 0777, and the proxy runs as a
// uid of its own: it sets the mode on the admin socket directory and on
// ca.out_dir at every start, which only the owner may do. NEVER default one
// of these to a mount point. The admin socket directory and the receipt
// directory are also separate, because the proxy takes the first to 0700 and
// the init container writes the second as root.
const (
	DefaultConnect = "127.0.0.1:3128"
	DefaultAdmin   = "/run/egress/admin/admin.sock"
	// DefaultCleartextPort is the captured port read as cleartext HTTP when
	// listen.cleartext_ports is empty.
	DefaultCleartextPort  = 80
	DefaultCAOutDir       = "/shared-ca/out"
	DefaultLeafTTL        = 24 * time.Hour
	DefaultCacheSize      = 1024
	DefaultMaxConnections = 1024
	// DefaultMaxDNSConnections caps the TCP connections the allowlist
	// resolver holds. It is well below DefaultMaxConnections: a lookup is
	// one short exchange, and the resolver shares the process's file
	// descriptors with the frontends and the audit writer.
	DefaultMaxDNSConnections = 128
	DefaultIdleTimeout       = 5 * time.Minute
	// DefaultEndpointPort is the port an https endpoint covers when it
	// names none.
	DefaultEndpointPort = 443
	// cleartextEndpointPort is the port an http endpoint covers when it
	// names none.
	cleartextEndpointPort = 80
	// DefaultResponseHeaderTimeout bounds the wait for an upstream response
	// head. It does not bound a body, so a streamed response is unaffected.
	DefaultResponseHeaderTimeout = 30 * time.Second
	// DefaultExchangeTimeout limits one token exchange, including discovery.
	DefaultExchangeTimeout = 10 * time.Second

	// DefaultAssertionHeader carries the sandbox assertion on a request.
	DefaultAssertionHeader = "X-Keycard-Sandbox-Assertion"
	// DefaultAssertionAudience is the audience an assertion names.
	DefaultAssertionAudience = "keycard-egress-proxy"
	// DefaultAssertionMaxAge bounds an assertion's lifetime. MaxAssertionMaxAge
	// is the longest a document may ask for.
	DefaultAssertionMaxAge = 30 * time.Second
	MaxAssertionMaxAge     = 5 * time.Minute
	// DefaultWorkspace is the OpenShell workspace a sandbox entry names when
	// it names none.
	DefaultWorkspace = "default"

	// Version is the only document version this build reads.
	Version = 1

	// EnvPrefix is the prefix of every environment variable the proxy
	// reads. It gives a manifest lint one namespace to inspect: a variable
	// with this prefix that the flag set does not name is refused.
	EnvPrefix = "EGRESS_PROXY_"
)

// PlacementKind defines where the proxy writes a credential into a request.
type PlacementKind = credential.Kind

// The placement kinds.
const (
	PlacementHeader = credential.KindHeader
	PlacementQuery  = credential.KindQuery
	PlacementBasic  = credential.KindBasic
)

var (
	errInvalid = errors.New("invalid configuration")
	errRoots   = errors.New("upstream roots")

	// hostLabelRE is one DNS label. A document's host is normalized to
	// lowercase before it is validated.
	hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

	// headerNameRE is an RFC 9110 field name: one or more token characters.
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// The limits RFC 1035 section 2.3.4 sets on a name and on one label.
const (
	maxDNSNameLength  = 253
	maxDNSLabelLength = 63
)

// maxPort is the highest TCP port an endpoint can name.
const maxPort = 65535

// Document is the configuration document as written.
type Document struct {
	Version  int       `json:"version"`
	Sandbox  Sandbox   `json:"sandbox"`
	Identity *Identity `json:"identity,omitempty"`
	Listen   Listen    `json:"listen"`
	CA       CA        `json:"ca"`
	TLS      TLS       `json:"tls"`
	Limits   Limits    `json:"limits"`
	// Credentials names the source from which the proxy reads credentials.
	Credentials Credentials `json:"credentials"`
	// Netsetup describes what the init container programmed into network
	// firewall rules. The proxy reads it before serving a transparent frontend.
	Netsetup Netsetup `json:"netsetup"`
	// DNS is where the allowlist resolver forwards a name it answers.
	DNS       DNS        `json:"dns"`
	Policy    Policy     `json:"policy"`
	Endpoints []Endpoint `json:"endpoints"`
	// SandboxAssertion turns on per-request sandbox identification. With it
	// set, every request must carry a verifiable assertion naming a sandbox
	// in Sandboxes, and the proxy brokers credentials as that sandbox.
	SandboxAssertion *SandboxAssertion `json:"sandbox_assertion,omitempty"`
	// Sandboxes maps each OpenShell sandbox to the Keycard identity it acts
	// as. Like the endpoints, the list comes from the document alone.
	Sandboxes []SandboxEntry `json:"sandboxes"`
	// Applications maps each kind of sandbox to the Keycard identity it
	// acts as. An assertion whose app claim names one selects it ahead of
	// the sandbox map. The list comes from the document alone.
	Applications []ApplicationEntry `json:"applications"`
}

// SandboxAssertion says how a request proves which sandbox sent it. A
// middleware in the sandbox runtime signs an assertion with the private half
// of the key at IssuerKeyFile and places it in Header.
type SandboxAssertion struct {
	Header string `json:"header"`
	// IssuerKeyFile is a PEM file holding the issuer's P-256 public key.
	IssuerKeyFile string `json:"issuer_key_file"`
	// Issuer, when set, is the iss claim every assertion must carry. The
	// zone verifies the same token by discovery on that URL.
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience"`
	// MaxAge bounds an assertion's lifetime. An assertion whose expiry lies
	// farther from its issue time is refused, whatever its signature.
	MaxAge Duration `json:"max_age"`
}

// SandboxEntry is one sandbox the proxy serves and the identity it acts as.
// Identity is absent when credentials.static_file supplies per-sandbox
// credentials.
type SandboxEntry struct {
	Name      string    `json:"name"`
	Workspace string    `json:"workspace"`
	Identity  *Identity `json:"identity,omitempty"`
}

// ApplicationEntry is one application the proxy serves and the identity it
// acts as. An application is the kind of sandbox: a sandbox id is new on
// every create, so the identity follows the application the assertion's app
// claim names. Identity is absent when credentials.static_file supplies
// per-application credentials.
type ApplicationEntry struct {
	Name     string    `json:"name"`
	Identity *Identity `json:"identity,omitempty"`
	// Creators are the principal subjects allowed to create a sandbox of
	// this application. The sandbox runtime's extension reads the list from
	// the shared document. The proxy validates its shape and never consults
	// it: no proxy decision depends on who created the sandbox.
	Creators []string `json:"creators,omitempty"`
}

// Credentials names the source for endpoint credentials. A document without a
// source denies every endpoint that names a credential.
type Credentials struct {
	// StaticFile maps resources to credentials stored as plain text. It serves
	// tests and development and cannot appear with an identity.
	StaticFile string `json:"static_file"`
}

// CredentialSourceKind names the credential source that a process reads.
// A record names the source that answered.
type CredentialSourceKind string

// The credential source kinds.
const (
	// SourceNone means that the configuration names no source. An endpoint
	// that names a credential returns credential_unavailable.
	SourceNone CredentialSourceKind = "none"
	// SourceStaticFile reads credentials from credentials.static_file.
	SourceStaticFile CredentialSourceKind = "static_file"
	// SourceExchange mints a credential for each request with a token exchange
	// against identity.zone_url.
	SourceExchange CredentialSourceKind = "exchange"
)

// CredentialSource names the effective source. Validation requires that only
// one is configured.
func (c *Config) CredentialSource() CredentialSourceKind {
	switch {
	case c.Credentials.StaticFile != "":
		return SourceStaticFile
	case c.Identity != nil || c.entryIdentities():
		return SourceExchange
	default:
		return SourceNone
	}
}

// Sandbox identifies the sandbox being proxied on every audit record.
type Sandbox struct {
	ID string `json:"id"`
}

// ClientAssertionSandbox is the one ClientAssertion value: the proxy
// presents the request's sandbox assertion as the client assertion of a
// client_credentials grant, so the zone authenticates the sandbox itself.
const ClientAssertionSandbox = "sandbox"

// Identity is the principal that identifies this proxy workload. It is the
// authority with which the egress proxy authenticates with a Keycard zone and
// performs a token exchange on the impersonated user's behalf.
// Exactly one of WorkloadTokenFile and ClientSecretFile authenticates the
// exchange. A workload token lets the zone read a ServiceAccount subject. A
// client secret gives the zone no ServiceAccount subject.
//
// With ClientAssertion set, the proxy holds no credential of its own: the
// sandbox assertion on each request authenticates the client, and the zone's
// policy decides which application the sandbox is. ZoneURL and
// Impersonate.SandboxOwner are then the only other fields allowed.
type Identity struct {
	ZoneURL           string `json:"zone_url"`
	ClientID          string `json:"client_id"`
	WorkloadTokenFile string `json:"workload_token_file"`
	// ClientSecretFile holds the application credential secret. The proxy
	// never writes the secret to the document, a flag, or a variable.
	ClientSecretFile string      `json:"client_secret_file"`
	Impersonate      Impersonate `json:"impersonate"`
	// ClientAssertion names what authenticates the client in place of a
	// credential the proxy holds. The one value is ClientAssertionSandbox.
	ClientAssertion string `json:"client_assertion,omitempty"`
}

// Impersonate identifies the user subject this proxy impersonates in every
// Keycard token exchange. User names one user for the process. SandboxOwner
// names the owner of the asserted sandbox, so it needs ClientAssertion and
// cannot be set with User.
type Impersonate struct {
	User         string `json:"user"`
	SandboxOwner bool   `json:"sandbox_owner,omitempty"`
}

// Listen is where the egress proxy process accepts connections.
type Listen struct {
	// Connect is the CONNECT frontend, host:port.
	Connect string `json:"connect"`
	// TransparentPort is the redirect target for captured TCP. The frontend
	// binds it on 127.0.0.1 and ::1 and no other address. Zero disables the
	// transparent frontend.
	//
	// The port is below 1024, so an unprivileged workload cannot bind it during
	// a sidecar restart and stand in for the proxy. The proxy holds
	// NET_BIND_SERVICE and no other capability.
	TransparentPort int `json:"transparent_port"`
	// DNSPort is the port the allowlist resolver binds on 127.0.0.1 and ::1,
	// which is where the nat REDIRECT sends a query. Zero runs no resolver.
	//
	// The port is below 1024, so an unprivileged workload cannot bind it
	// during a sidecar restart and answer its own lookups.
	DNSPort int `json:"dns_port"`
	// CleartextPorts lists captured destination ports to read as cleartext
	// HTTP. The destination comes from the Host header. Empty means port 80.
	// Every other captured port is read as TLS.
	CleartextPorts []int `json:"cleartext_ports"`
	// Admin is the path of the admin Unix socket.
	Admin string `json:"admin"`
	// ConnectAuthFile holds the "user:password" a client must present in
	// Proxy-Authorization on every CONNECT. Empty accepts every client.
	ConnectAuthFile string `json:"connect_auth_file"`
}

// Netsetup contains the init container's receipt. The proxy reads it before
// serving a transparent frontend and refuses a mismatched uid or port.
type Netsetup struct {
	Receipt string `json:"receipt"`
}

// DNS is where the allowlist resolver forwards a name it answers.
//
// There is no setting for which names resolve. The resolver answers only
// the endpoint hosts and the zone host, which are the hosts the proxy
// connects to. A setting that added names would be a policy rule with no
// endpoint behind it.
//
// NEVER add a setting that changes which names resolve. It would have to go
// in the decision inputs that config.digest covers.
type DNS struct {
	// ForwardTo are the cluster resolvers, each an address with an
	// optional port. When it is empty, the proxy reads them from the
	// netsetup receipt.
	ForwardTo []string `json:"forward_to"`
}

// CA configures the certificate authority that the proxy terminates the
// workload's outbound TLS with. The workload must trust the root
// certificate.
type CA struct {
	// OutDir is the directory the proxy writes the root CA certificate to.
	OutDir string `json:"out_dir"`
	// StateDir holds the CA key and certificate across a restart. It must be
	// a memory-backed volume. An empty value keeps the authority in process
	// memory alone.
	StateDir string `json:"state_dir"`
	// LeafTTL is a minted leaf's lifetime.
	LeafTTL Duration `json:"leaf_ttl"`
	// CacheSize is how many minted leaves the store holds.
	CacheSize int `json:"cache_size"`
}

// TLS is what the upstream leg verifies against.
type TLS struct {
	// UpstreamCAFiles are PEM files whose certificates join the system roots.
	UpstreamCAFiles []string `json:"upstream_ca_files"`
}

// Limits bound every listener and the upstream leg.
type Limits struct {
	MaxConnections int `json:"max_connections"`
	// MaxDNSConnections caps the TCP connections the allowlist resolver
	// accepts on each of its listeners. It is separate from
	// MaxConnections: a lookup is one short exchange, and a workload that
	// filled the frontend's budget with lookups would starve the frontends
	// and the audit writer of the file descriptors they share.
	MaxDNSConnections int      `json:"max_dns_connections"`
	IdleTimeout       Duration `json:"idle_timeout"`
	// ResponseHeaderTimeout is how long an upstream has to send a response
	// head once the request is written. It does not bound the body, so a
	// streamed response runs as long as it stays active.
	ResponseHeaderTimeout Duration `json:"response_header_timeout"`
	// ExchangeTimeout limits one token exchange, including discovery. A
	// request that exceeds it returns exchange_failed.
	ExchangeTimeout Duration `json:"exchange_timeout"`
}

// validate reports every limit that would leave a listener or the upstream
// leg unbounded.
func (l *Limits) validate(found *problems) {
	if l.MaxConnections < 1 {
		found.addf("limits.max_connections must be at least 1")
	}
	if l.MaxDNSConnections < 1 {
		found.addf("limits.max_dns_connections must be at least 1")
	}
	if l.IdleTimeout <= 0 {
		found.addf("limits.idle_timeout must be positive")
	}
	if l.ResponseHeaderTimeout <= 0 {
		found.addf("limits.response_header_timeout must be positive")
	}
	if l.ExchangeTimeout <= 0 {
		found.addf("limits.exchange_timeout must be positive")
	}
}

// Policy is what joins and what leaves the platform deny list.
type Policy struct {
	ClusterCIDRs       []string `json:"cluster_cidrs"`
	DenyListExceptions []string `json:"deny_list_exceptions"`
}

// Endpoint is one destination the sandbox can reach.
type Endpoint struct {
	// URL names the endpoint as scheme://host[:port][/path], with scheme
	// https or http. The host, the port and the path prefix are read from
	// it, and its canonical form is the resource the exchange asks the zone
	// for. One string decides both where a request goes and which credential
	// it gets.
	URL        string      `json:"url"`
	Credential *Credential `json:"credential,omitempty"`

	// Host, Port, PathPrefix and Resource are read from URL. They are not
	// document keys.
	Host string `json:"-"`
	// Port is the port this endpoint covers on that host. When the URL names
	// none, it is the scheme's port: 443 for https and 80 for http. A host
	// reachable on two ports is two endpoints.
	Port       int    `json:"-"`
	PathPrefix string `json:"-"`
	// Resource is the canonical URL: lowercase scheme and host, no trailing
	// dot, no port when it is the scheme's own, no root path, and any other
	// path as written.
	Resource string `json:"-"`
}

// endpointURL is what an endpoint URL names.
type endpointURL struct {
	scheme string
	host   string
	port   int
	path   string
}

// The reasons an endpoint URL is refused before its parts are checked.
var (
	errEndpointNotHTTPS = errors.New("must be an absolute http or https URL")
	errEndpointExtras   = errors.New("must not hold userinfo, a query or a fragment")
	errEndpointPort     = errors.New("must name a port between 1 and 65535")
)

// parseEndpointURL reads the host, port and path of an endpoint URL. The
// path is returned exactly as written, so normalizedPrefix judges the bytes
// the matcher compares. The host is normalized.
func parseEndpointURL(raw string) (endpointURL, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return endpointURL{}, fmt.Errorf("is not a URL: %w", err)
	}
	if err = endpointURLShape(parsed); err != nil {
		return endpointURL{}, err
	}
	port, err := endpointPort(parsed.Scheme, parsed.Port())
	if err != nil {
		return endpointURL{}, err
	}
	// The authority follows "scheme://", so the path is whatever comes after
	// the first "/" past both.
	rest := raw[len(parsed.Scheme)+len("://"):]
	path := "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path = rest[i:]
	}
	return endpointURL{
		scheme: parsed.Scheme, host: policy.NormalizeHost(parsed.Hostname()), port: port, path: path,
	}, nil
}

// endpointURLShape refuses a URL that is not absolute http or https, or that
// holds userinfo, a query or a fragment.
func endpointURLShape(parsed *url.URL) error {
	switch {
	case schemePort(parsed.Scheme) == 0 || parsed.Host == "" || parsed.Opaque != "":
		return errEndpointNotHTTPS
	case parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "":
		return errEndpointExtras
	default:
		return nil
	}
}

// schemePort is the port a scheme implies, zero for a scheme an endpoint
// cannot name.
func schemePort(scheme string) int {
	switch scheme {
	case "https":
		return DefaultEndpointPort
	case "http":
		return cleartextEndpointPort
	default:
		return 0
	}
}

// endpointPort reads the port a URL names, the scheme's port when it names
// none.
func endpointPort(scheme, text string) (int, error) {
	if text == "" {
		return schemePort(scheme), nil
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > maxPort {
		return 0, fmt.Errorf("%w, not %q", errEndpointPort, text)
	}
	return port, nil
}

// canonicalResource is the resource an endpoint sends to the zone. The root
// path is left out, so https://api.github.com/ sends https://api.github.com,
// the resource URL registered in the zone. Any other path is kept as written,
// because /api and /api/ cover different paths.
func canonicalResource(parsed endpointURL) string {
	authority := parsed.host
	if parsed.port != schemePort(parsed.scheme) {
		authority = net.JoinHostPort(parsed.host, strconv.Itoa(parsed.port))
	}
	path := parsed.path
	if path == "/" {
		path = ""
	}
	return parsed.scheme + "://" + authority + path
}

// Credential says where in a request a credential goes.
type Credential struct {
	Placement Placement `json:"placement"`
}

// Placement is where the proxy writes a credential into a request.
type Placement = credential.Placement

// Duration is a time.Duration written as Go writes one, such as 24h or 5m.
type Duration time.Duration

// UnmarshalJSON parses a duration string.
func (d *Duration) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return fmt.Errorf("a duration is written as a string such as 24h or 5m: %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("%q is not a duration such as 24h or 5m: %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON writes the duration in the form UnmarshalJSON reads.
func (d Duration) MarshalJSON() ([]byte, error) {
	out, err := json.Marshal(time.Duration(d).String())
	if err != nil {
		return nil, fmt.Errorf("encode duration: %w", err)
	}
	return out, nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config is a validated document with its overrides and defaults applied,
// and its digest.
type Config struct {
	Document

	// Digest is "sha256:<hex>" over the JCS-canonical (RFC 8785) JSON of the
	// document as written, before overrides and defaults. It identifies the
	// mounted document, so two sidecars reading one ConfigMap share it.
	Digest string
	// ConfigDigest is a digest of the same shape over the settings this
	// process enforces, after overrides and defaults. Two sidecars that
	// answer every request alike share it, whatever document, flag or
	// variable each one was given. decisionInputs says what goes in.
	ConfigDigest string
	// Overridden names the settings an override replaced, as document keys,
	// sorted. The process announces them on every start.
	Overridden []string
	// ClusterCIDRs and DenyListExceptions are policy.cluster_cidrs and
	// policy.deny_list_exceptions, parsed.
	ClusterCIDRs       []netip.Prefix
	DenyListExceptions []netip.Prefix
}

// Overrides are the settings a flag or an environment variable can replace:
// what identifies this instance, and how the process runs. A zero value is
// not an override.
//
// The endpoints and the policy section are not here. They come from the
// document alone, because an audit record has to name every allow and deny
// rule that was in force.
//
// Digest covers the document before these apply, so it alone does not
// identify what an override supplied. ConfigDigest covers the effective
// settings and does, and Overridden names the keys an override replaced.
type Overrides struct {
	SandboxID             string
	ZoneURL               string
	ClientID              string
	WorkloadTokenFile     string
	ImpersonateUser       string
	Connect               string
	TransparentPort       int
	TransparentPortSet    bool
	DNSPort               int
	DNSPortSet            bool
	DNSForwardTo          []string
	Admin                 string
	ConnectAuthFile       string
	NetsetupReceipt       string
	CAOutDir              string
	CAStateDir            string
	ClientSecretFile      string
	CredentialStaticFile  string
	LeafTTL               time.Duration
	CacheSize             int
	UpstreamCAFiles       []string
	MaxConnections        int
	MaxDNSConnections     int
	IdleTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	ExchangeTimeout       time.Duration
}

// Load reads and parses the document at path with the overrides applied.
func Load(path string, overrides Overrides) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the --config flag
	if err != nil {
		return nil, fmt.Errorf("read the configuration: %w", err)
	}
	cfg, err := Parse(data, overrides)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses a document, applies the overrides over it and the defaults
// under both, and validates the result.
func Parse(data []byte, overrides Overrides) (*Config, error) {
	if err := strictdoc.RefuseSecondYAMLDocument(data); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	jsonText, err := yaml.YAMLToJSONStrict(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	if err = strictdoc.RefuseCaseFoldedJSONKeys(jsonText); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, err)
	}
	canonical, err := jcs.Transform(jsonText)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize: %w", errInvalid, err)
	}
	sum := sha256.Sum256(canonical)

	decoder := json.NewDecoder(strings.NewReader(string(jsonText)))
	decoder.DisallowUnknownFields()
	var doc Document
	if decErr := decoder.Decode(&doc); decErr != nil {
		return nil, fmt.Errorf("%w: %w", errInvalid, decErr)
	}
	cfg := &Config{Document: doc, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	cfg.applyOverrides(overrides)
	cfg.applyDefaults()
	if valErr := cfg.validate(); valErr != nil {
		return nil, valErr
	}
	if cfg.ConfigDigest, err = cfg.digestDecisionInputs(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decisionInputs are the settings that decide what the proxy answers, in the
// effective form the process enforces. A setting belongs here when its value
// can make two sidecars answer the same request differently.
//
// sandbox.id stays out: it annotates a record but decides nothing, and it
// It already has its own field on every record. The same holds for ca, limits,
// and listen addresses, which bound the process without changing any answer.
//
// The compiled deny list goes in because it is platform policy that a build
// holds rather than a document. Two binaries that deny different
// destinations must not share a digest.
type decisionInputs struct {
	Endpoints          []digestEndpoint `json:"endpoints"`
	ClusterCIDRs       []string         `json:"cluster_cidrs"`
	DenyListExceptions []string         `json:"deny_list_exceptions"`
	Identity           *Identity        `json:"identity,omitempty"`
	UpstreamCAFiles    []string         `json:"upstream_ca_files"`
	CredentialSource   credentialSource `json:"credential_source"`
	DenyList           string           `json:"deny_list"`
	// CleartextPorts decides how the frontend reads a captured port. It refuses
	// a port read as cleartext where the same port read as TLS uses its server
	// name. It is empty with no transparent frontend, where nothing is captured.
	CleartextPorts []int `json:"cleartext_ports,omitempty"`
	// SandboxAssertion, Sandboxes and Applications decide which identity
	// answers a request and whether a request without an assertion is
	// served at all. applications[].creators stays out: the sandbox runtime
	// enforces it, and the proxy answers alike with or without it.
	SandboxAssertion *SandboxAssertion  `json:"sandbox_assertion,omitempty"`
	Sandboxes        []SandboxEntry     `json:"sandboxes,omitempty"`
	Applications     []ApplicationEntry `json:"applications,omitempty"`
	// ConnectAuthFile decides whether an unauthenticated CONNECT is refused.
	ConnectAuthFile string `json:"connect_auth_file,omitempty"`
}

// canonicalSandboxes orders entries by name and workspace. Validation rejects
// a repeated pair, so document order changes neither the answer nor the
// digest.
func canonicalSandboxes(entries []SandboxEntry) []SandboxEntry {
	out := append([]SandboxEntry(nil), entries...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Workspace < out[j].Workspace
	})
	return out
}

// canonicalApplications orders entries by name and drops creators.
// Validation rejects a repeated name, so document order changes neither the
// answer nor the digest. Creators decides nothing in the proxy, so two
// documents that differ only in that list digest the same.
func canonicalApplications(entries []ApplicationEntry) []ApplicationEntry {
	out := append([]ApplicationEntry(nil), entries...)
	for i := range out {
		out[i].Creators = nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// digestEndpoint is what an endpoint contributes to the digest: the values
// read from its URL, not the URL as written. Two spellings of one endpoint
// digest the same.
type digestEndpoint struct {
	Host       string      `json:"host"`
	Port       int         `json:"port"`
	PathPrefix string      `json:"path_prefix"`
	Resource   string      `json:"resource"`
	Credential *Credential `json:"credential,omitempty"`
}

// credentialSource names the configured source.
type credentialSource struct {
	Kind CredentialSourceKind `json:"kind"`
	// StaticFile is the file that the static source reads. Different files can
	// hold different credentials.
	StaticFile string `json:"static_file,omitempty"`
}

// canonicalPrefixes renders a range list the way the deny list reads it:
// masked, sorted and deduplicated. Two spellings of one set of ranges deny
// the same destinations, so they digest the same.
func canonicalPrefixes(prefixes []netip.Prefix) []string {
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		text := prefix.Masked().String()
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

// canonicalEndpoints orders endpoints by host, port, and path prefix. The
// matcher sorts prefixes by length, and validation rejects duplicates, so
// document order changes neither the answer nor the digest.
func canonicalEndpoints(endpoints []Endpoint) []digestEndpoint {
	out := make([]digestEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, digestEndpoint{
			Host: endpoint.Host, Port: endpoint.Port, PathPrefix: endpoint.PathPrefix,
			Resource: endpoint.Resource, Credential: endpoint.Credential,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].PathPrefix < out[j].PathPrefix
	})
	return out
}

// canonicalFiles sorts and deduplicates a file list. The same file named
// twice, or in another order, contributes the same material.
func canonicalFiles(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// PolicyEndpoints returns the endpoints in the matcher's shape.
func (c *Config) PolicyEndpoints() []policy.Endpoint {
	out := make([]policy.Endpoint, 0, len(c.Endpoints))
	for _, endpoint := range c.Endpoints {
		var placement *credential.Placement
		if endpoint.Credential != nil {
			value := endpoint.Credential.Placement
			placement = &value
		}
		out = append(out, policy.Endpoint{
			Host:       endpoint.Host,
			Port:       endpoint.Port,
			PathPrefix: endpoint.PathPrefix,
			Resource:   endpoint.Resource,
			Credential: placement,
		})
	}
	return out
}

// UpstreamRoots returns the system roots joined with every certificate in
// tls.upstream_ca_files. A file that cannot be read, or that holds no
// certificate, stops the process.
func (c *Config) UpstreamRoots() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("%w: read the system roots: %w", errRoots, err)
	}
	for _, file := range c.TLS.UpstreamCAFiles {
		pemBytes, err := os.ReadFile(file) //nolint:gosec // G304: the file is tls.upstream_ca_files
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errRoots, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%w: %s holds no certificate", errRoots, file)
		}
	}
	return pool, nil
}

// DNSHosts are the names the allowlist resolver answers for: every
// endpoint host and the zone host. It is derived from the document and
// nothing configures it.
func (c *Config) DNSHosts() []string {
	hosts := make([]string, 0, len(c.Endpoints)+1)
	for _, endpoint := range c.Endpoints {
		hosts = append(hosts, endpoint.Host)
	}
	if c.Identity != nil {
		if zone, err := url.Parse(c.Identity.ZoneURL); err == nil && zone.Hostname() != "" {
			hosts = append(hosts, zone.Hostname())
		}
	}
	sort.Strings(hosts)
	return hosts
}

// entryIdentities reports whether any sandbox or application entry names an
// identity.
func (c *Config) entryIdentities() bool {
	for _, entry := range c.Sandboxes {
		if entry.Identity != nil {
			return true
		}
	}
	for _, entry := range c.Applications {
		if entry.Identity != nil {
			return true
		}
	}
	return false
}

// digestDecisionInputs canonicalizes the decision inputs and hashes them.
//
// The digest is one way and this package exposes no reader for the input, so
// nothing it covers reaches an audit record or the admin socket in the
// clear.
func (c *Config) digestDecisionInputs() (string, error) {
	inputs := decisionInputs{
		Endpoints:          canonicalEndpoints(c.Endpoints),
		ClusterCIDRs:       canonicalPrefixes(c.ClusterCIDRs),
		DenyListExceptions: canonicalPrefixes(c.DenyListExceptions),
		Identity:           c.Identity,
		UpstreamCAFiles:    canonicalFiles(c.TLS.UpstreamCAFiles),
		CredentialSource:   credentialSource{Kind: c.CredentialSource(), StaticFile: c.Credentials.StaticFile},
		DenyList:           policy.CompiledDigest(),
		SandboxAssertion:   c.SandboxAssertion,
		Sandboxes:          canonicalSandboxes(c.Sandboxes),
		Applications:       canonicalApplications(c.Applications),
		ConnectAuthFile:    c.Listen.ConnectAuthFile,
	}
	if c.Listen.TransparentPort != 0 {
		inputs.CleartextPorts = sortedPorts(c.Listen.CleartextPorts)
	}
	encoded, err := json.Marshal(inputs)
	if err != nil {
		return "", fmt.Errorf("%w: encode the decision inputs: %w", errInvalid, err)
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize the decision inputs: %w", errInvalid, err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (c *Config) applyDefaults() {
	defaultString(&c.Listen.Connect, DefaultConnect)
	defaultString(&c.Listen.Admin, DefaultAdmin)
	defaultString(&c.Netsetup.Receipt, netsetup.DefaultReceiptPath)
	if len(c.Listen.CleartextPorts) == 0 {
		c.Listen.CleartextPorts = []int{DefaultCleartextPort}
	}
	defaultString(&c.CA.OutDir, DefaultCAOutDir)
	if c.CA.LeafTTL == 0 {
		c.CA.LeafTTL = Duration(DefaultLeafTTL)
	}
	if c.CA.CacheSize == 0 {
		c.CA.CacheSize = DefaultCacheSize
	}
	if c.Limits.MaxConnections == 0 {
		c.Limits.MaxConnections = DefaultMaxConnections
	}
	if c.Limits.MaxDNSConnections == 0 {
		c.Limits.MaxDNSConnections = DefaultMaxDNSConnections
	}
	if c.Limits.IdleTimeout == 0 {
		c.Limits.IdleTimeout = Duration(DefaultIdleTimeout)
	}
	if c.Limits.ResponseHeaderTimeout == 0 {
		c.Limits.ResponseHeaderTimeout = Duration(DefaultResponseHeaderTimeout)
	}
	if c.Limits.ExchangeTimeout == 0 {
		c.Limits.ExchangeTimeout = Duration(DefaultExchangeTimeout)
	}
	for i := range c.Endpoints {
		applyEndpointDefaults(&c.Endpoints[i])
	}
	c.applySandboxDefaults()
}

// applySandboxDefaults fills the assertion settings and the workspace each
// sandbox entry leaves out.
func (c *Config) applySandboxDefaults() {
	if c.SandboxAssertion != nil {
		defaultString(&c.SandboxAssertion.Header, DefaultAssertionHeader)
		defaultString(&c.SandboxAssertion.Audience, DefaultAssertionAudience)
		if c.SandboxAssertion.MaxAge == 0 {
			c.SandboxAssertion.MaxAge = Duration(DefaultAssertionMaxAge)
		}
	}
	for i := range c.Sandboxes {
		defaultString(&c.Sandboxes[i].Workspace, DefaultWorkspace)
	}
}

// applyEndpointDefaults reads the host, port, path prefix and resource out
// of the endpoint URL. A URL that does not parse leaves them empty, and
// validate reports why.
func applyEndpointDefaults(endpoint *Endpoint) {
	parsed, err := parseEndpointURL(endpoint.URL)
	if err != nil {
		return
	}
	endpoint.Host, endpoint.Port, endpoint.PathPrefix = parsed.host, parsed.port, parsed.path
	endpoint.Resource = canonicalResource(parsed)
}

func defaultString(field *string, value string) {
	if *field == "" {
		*field = value
	}
}

// applyOverrides replaces the settings the overrides name and records which.
func (c *Config) applyOverrides(overrides Overrides) {
	override := func(key string, set bool, assign func()) {
		if set {
			assign()
			c.Overridden = append(c.Overridden, key)
		}
	}
	identity := overrides.ZoneURL != "" || overrides.ClientID != "" || overrides.WorkloadTokenFile != "" ||
		overrides.ClientSecretFile != "" || overrides.ImpersonateUser != ""
	if identity && c.Identity == nil {
		c.Identity = &Identity{}
	}
	override("sandbox.id", overrides.SandboxID != "", func() { c.Sandbox.ID = overrides.SandboxID })
	override("identity.zone_url", overrides.ZoneURL != "", func() { c.Identity.ZoneURL = overrides.ZoneURL })
	override("identity.client_id", overrides.ClientID != "", func() { c.Identity.ClientID = overrides.ClientID })
	override("identity.workload_token_file", overrides.WorkloadTokenFile != "",
		func() { c.Identity.WorkloadTokenFile = overrides.WorkloadTokenFile })
	override("identity.client_secret_file", overrides.ClientSecretFile != "",
		func() { c.Identity.ClientSecretFile = overrides.ClientSecretFile })
	override("identity.impersonate.user", overrides.ImpersonateUser != "",
		func() { c.Identity.Impersonate.User = overrides.ImpersonateUser })
	override("listen.connect", overrides.Connect != "", func() { c.Listen.Connect = overrides.Connect })
	override("listen.transparent_port", overrides.TransparentPortSet || overrides.TransparentPort != 0,
		func() { c.Listen.TransparentPort = overrides.TransparentPort })
	override("listen.dns_port", overrides.DNSPortSet || overrides.DNSPort != 0,
		func() { c.Listen.DNSPort = overrides.DNSPort })
	override("dns.forward_to", len(overrides.DNSForwardTo) > 0,
		func() { c.DNS.ForwardTo = append([]string(nil), overrides.DNSForwardTo...) })
	override("listen.admin", overrides.Admin != "", func() { c.Listen.Admin = overrides.Admin })
	override("listen.connect_auth_file", overrides.ConnectAuthFile != "",
		func() { c.Listen.ConnectAuthFile = overrides.ConnectAuthFile })
	override("netsetup.receipt", overrides.NetsetupReceipt != "",
		func() { c.Netsetup.Receipt = overrides.NetsetupReceipt })
	override("ca.out_dir", overrides.CAOutDir != "", func() { c.CA.OutDir = overrides.CAOutDir })
	override("ca.state_dir", overrides.CAStateDir != "", func() { c.CA.StateDir = overrides.CAStateDir })
	override("ca.leaf_ttl", overrides.LeafTTL != 0, func() { c.CA.LeafTTL = Duration(overrides.LeafTTL) })
	override("ca.cache_size", overrides.CacheSize != 0, func() { c.CA.CacheSize = overrides.CacheSize })
	override("tls.upstream_ca_files", len(overrides.UpstreamCAFiles) > 0,
		func() { c.TLS.UpstreamCAFiles = append([]string(nil), overrides.UpstreamCAFiles...) })
	override("credentials.static_file", overrides.CredentialStaticFile != "",
		func() { c.Credentials.StaticFile = overrides.CredentialStaticFile })
	c.Limits.applyOverrides(overrides, override)
	sort.Strings(c.Overridden)
}

// applyOverrides replaces each limit an override names. record is what
// applyOverrides passes down, so an overridden limit reaches
// Config.Overridden the way every other setting does.
func (l *Limits) applyOverrides(overrides Overrides, record func(key string, set bool, assign func())) {
	record("limits.max_connections", overrides.MaxConnections != 0,
		func() { l.MaxConnections = overrides.MaxConnections })
	record("limits.max_dns_connections", overrides.MaxDNSConnections != 0,
		func() { l.MaxDNSConnections = overrides.MaxDNSConnections })
	record("limits.idle_timeout", overrides.IdleTimeout != 0,
		func() { l.IdleTimeout = Duration(overrides.IdleTimeout) })
	record("limits.response_header_timeout", overrides.ResponseHeaderTimeout != 0,
		func() { l.ResponseHeaderTimeout = Duration(overrides.ResponseHeaderTimeout) })
	record("limits.exchange_timeout", overrides.ExchangeTimeout != 0,
		func() { l.ExchangeTimeout = Duration(overrides.ExchangeTimeout) })
}

// problems collects validation findings so one run reports all of them.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

func (c *Config) validate() error {
	var found problems
	if c.Version != Version {
		found.addf("version is %d, this build reads version %d", c.Version, Version)
	}
	if strings.TrimSpace(c.Sandbox.ID) == "" || strings.ContainsAny(c.Sandbox.ID, " \t\r\n") {
		found.addf("sandbox.id %q must be a non-empty string without whitespace", c.Sandbox.ID)
	}
	if c.Identity != nil {
		if c.Identity.ClientAssertion != "" {
			found.addf("identity.client_assertion needs a per-request sandbox assertion; use it under applications")
		}
		c.Identity.validate("identity", &found)
	}
	c.validateProcess(&found)
	c.validateCredentials(&found)
	c.validateSandboxes(&found)
	c.validatePolicy(&found)
	seen := make(map[string]int, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		endpoint.validate(i, &found)
		// An endpoint identifies a service by host, port, and prefix. Compile
		// uses the same identity, so both checks reject the same duplicate.
		key := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)) + endpoint.PathPrefix
		if previous, ok := seen[key]; ok && endpoint.Host != "" {
			found.addf("endpoints[%d]: url %q names the same endpoint as endpoints[%d]",
				i, endpoint.URL, previous)
		}
		seen[key] = i
	}
	if len(found) > 0 {
		return fmt.Errorf("%w:\n  %s", errInvalid, strings.Join(found, "\n  "))
	}
	return nil
}

func (c *Config) validateProcess(found *problems) {
	c.validateListen(found)
	c.validateDNS(found)
	c.CA.validate(found)
	for i, file := range c.TLS.UpstreamCAFiles {
		if strings.TrimSpace(file) == "" {
			found.addf("tls.upstream_ca_files[%d] is empty", i)
			continue
		}
		if !filepath.IsAbs(file) {
			found.addf("tls.upstream_ca_files[%d] %q must be an absolute path", i, file)
		}
	}
	c.Limits.validate(found)
}

// validateListen checks the frontend addresses, the admin socket path, the
// connect credential path and the transparent frontend.
func (c *Config) validateListen(found *problems) {
	if _, _, err := net.SplitHostPort(c.Listen.Connect); err != nil {
		found.addf("listen.connect %q is not host:port: %v", c.Listen.Connect, err)
	}
	if !filepath.IsAbs(c.Listen.Admin) {
		found.addf("listen.admin %q must be an absolute path; the admin surface is a Unix socket", c.Listen.Admin)
	}
	if c.Listen.ConnectAuthFile != "" && !filepath.IsAbs(c.Listen.ConnectAuthFile) {
		found.addf("listen.connect_auth_file %q must be an absolute path", c.Listen.ConnectAuthFile)
	}
	// A redirected connection carries no Proxy-Authorization, so the
	// credential would guard the CONNECT frontend and not the transparent
	// one. Refuse the pair rather than promise a boundary with a hole in it.
	if c.Listen.ConnectAuthFile != "" && c.Listen.TransparentPort != 0 {
		found.addf("listen.connect_auth_file cannot be set with listen.transparent_port; " +
			"a redirected connection presents no credential")
	}
	c.validateTransparent(found)
}

func (c CA) validate(found *problems) {
	if !filepath.IsAbs(c.OutDir) {
		found.addf("ca.out_dir %q must be an absolute path", c.OutDir)
	}
	if c.StateDir != "" && !filepath.IsAbs(c.StateDir) {
		found.addf("ca.state_dir %q must be an absolute path", c.StateDir)
	}
	if c.StateDir != "" && ca.Overlaps(c.StateDir, c.OutDir) {
		found.addf("ca.state_dir %q overlaps ca.out_dir %q; the key must never be under the shared mount",
			c.StateDir, c.OutDir)
	}
	if c.LeafTTL <= 0 {
		found.addf("ca.leaf_ttl must be positive")
	}
	if c.CacheSize < 1 {
		found.addf("ca.cache_size must be at least 1")
	}
}

// validateCredentials requires an absolute static-file path and one source.
func (c *Config) validateCredentials(found *problems) {
	if c.Credentials.StaticFile == "" {
		return
	}
	if !filepath.IsAbs(c.Credentials.StaticFile) {
		found.addf("credentials.static_file %q must be an absolute path", c.Credentials.StaticFile)
	}
	if c.Identity != nil {
		found.addf("credentials.static_file and identity both name a credential source; configure one")
	}
}

func (c *Config) validatePolicy(found *problems) {
	c.ClusterCIDRs = c.ClusterCIDRs[:0]
	for i, raw := range c.Policy.ClusterCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			found.addf("policy.cluster_cidrs[%d] %q is not a CIDR: %v", i, raw, err)
			continue
		}
		c.ClusterCIDRs = append(c.ClusterCIDRs, prefix)
	}
	c.DenyListExceptions = c.DenyListExceptions[:0]
	for i, raw := range c.Policy.DenyListExceptions {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			found.addf("policy.deny_list_exceptions[%d] %q is not a CIDR: %v", i, raw, err)
			continue
		}
		c.DenyListExceptions = append(c.DenyListExceptions, prefix)
	}
}

// validate checks an identity. where names its place in the document, such
// as "identity" or "sandboxes[2].identity", so a finding points at the entry.
func (id *Identity) validate(where string, found *problems) {
	zone, err := url.Parse(id.ZoneURL)
	switch {
	case err != nil:
		found.addf("%s.zone_url %q is not a URL: %v", where, id.ZoneURL, err)
	case zone.Scheme != "https" || zone.Host == "":
		found.addf("%s.zone_url %q must be an absolute https URL", where, id.ZoneURL)
	case zone.User != nil:
		found.addf("%s.zone_url holds userinfo. It is an issuer and never a credential", where)
	}
	if id.ClientAssertion != "" {
		id.validateClientAssertion(where, found)
		return
	}
	if strings.TrimSpace(id.ClientID) == "" {
		found.addf("%s.client_id is empty", where)
	}
	id.validateClientAuth(where, found)
	if strings.TrimSpace(id.Impersonate.User) == "" {
		found.addf("%s.impersonate.user is empty", where)
	}
	if id.Impersonate.SandboxOwner {
		found.addf("%s.impersonate.sandbox_owner needs client_assertion: %s", where, ClientAssertionSandbox)
	}
}

// validateClientAssertion refuses any credential the proxy would hold
// beside the assertion. The assertion is the whole client authentication,
// and the zone names the client by its subject. impersonate.user is refused
// with it: the one user such an identity can act for is the sandbox owner
// the assertion names.
func (id *Identity) validateClientAssertion(where string, found *problems) {
	if id.ClientAssertion != ClientAssertionSandbox {
		found.addf("%s.client_assertion %q is not %q", where, id.ClientAssertion, ClientAssertionSandbox)
	}
	conflicts := []struct{ key, value string }{
		{"client_id", id.ClientID},
		{"client_secret_file", id.ClientSecretFile},
		{"workload_token_file", id.WorkloadTokenFile},
		{"impersonate.user", id.Impersonate.User},
	}
	for _, conflict := range conflicts {
		if conflict.value != "" {
			found.addf("%s.%s cannot be set with client_assertion", where, conflict.key)
		}
	}
}

// validateClientAuth requires exactly one client authentication mechanism.
// The two mechanisms give the zone different authority, so a record must
// identify which one the zone used.
func (id *Identity) validateClientAuth(where string, found *problems) {
	switch {
	case id.WorkloadTokenFile == "" && id.ClientSecretFile == "":
		found.addf("%s names no client authentication; set workload_token_file or client_secret_file", where)
	case id.WorkloadTokenFile != "" && id.ClientSecretFile != "":
		found.addf("%s.workload_token_file and %s.client_secret_file both authenticate the "+
			"exchange; configure one", where, where)
	}
	if id.WorkloadTokenFile != "" && !filepath.IsAbs(id.WorkloadTokenFile) {
		found.addf("%s.workload_token_file %q must be an absolute path", where, id.WorkloadTokenFile)
	}
	if id.ClientSecretFile != "" && !filepath.IsAbs(id.ClientSecretFile) {
		found.addf("%s.client_secret_file %q must be an absolute path", where, id.ClientSecretFile)
	}
}

// validateSandboxes checks the assertion settings and the two maps it
// selects from. They come together: an assertion that maps to nothing serves
// nothing, and a map that no assertion selects from is never consulted.
func (c *Config) validateSandboxes(found *problems) {
	if c.SandboxAssertion == nil {
		if len(c.Sandboxes) > 0 {
			found.addf("sandboxes requires sandbox_assertion; nothing else selects an entry")
		}
		if len(c.Applications) > 0 {
			found.addf("applications requires sandbox_assertion; nothing else selects an entry")
		}
		return
	}
	if len(c.Sandboxes) == 0 && len(c.Applications) == 0 {
		found.addf("sandbox_assertion requires at least one entry in sandboxes or applications")
	}
	c.SandboxAssertion.validate(found)
	c.validateSandboxEntries(found)
	c.validateApplicationEntries(found)
}

// validateSandboxEntries refuses a repeated name and workspace pair and
// checks each entry.
func (c *Config) validateSandboxEntries(found *problems) {
	if c.Identity != nil && len(c.Sandboxes) > 0 {
		found.addf("identity and sandboxes both name a credential source; configure one")
	}
	seen := make(map[[2]string]int, len(c.Sandboxes))
	for i, entry := range c.Sandboxes {
		key := [2]string{entry.Name, entry.Workspace}
		if previous, ok := seen[key]; ok {
			found.addf("sandboxes[%d]: name %q in workspace %q repeats sandboxes[%d]",
				i, entry.Name, entry.Workspace, previous)
		}
		seen[key] = i
		where := fmt.Sprintf("sandboxes[%d]", i)
		validateEntryName(where, entry.Name, found)
		c.validateEntrySource(where, "the sandbox", entry.Identity, found)
	}
}

// validateApplicationEntries refuses a repeated name and checks each entry.
// An application has no workspace: the name is the whole key.
func (c *Config) validateApplicationEntries(found *problems) {
	if c.Identity != nil && len(c.Applications) > 0 {
		found.addf("identity and applications both name a credential source; configure one")
	}
	seen := make(map[string]int, len(c.Applications))
	for i, entry := range c.Applications {
		if previous, ok := seen[entry.Name]; ok {
			found.addf("applications[%d]: name %q repeats applications[%d]", i, entry.Name, previous)
		}
		seen[entry.Name] = i
		where := fmt.Sprintf("applications[%d]", i)
		validateEntryName(where, entry.Name, found)
		c.validateEntrySource(where, "the application", entry.Identity, found)
		validateCreators(where, entry.Creators, found)
	}
}

// validateCreators refuses an empty or repeated creator. The proxy never
// reads the list, so the check only keeps a typo from reaching the sandbox
// runtime unnoticed.
func validateCreators(where string, creators []string, found *problems) {
	seen := make(map[string]int, len(creators))
	for i, creator := range creators {
		if strings.TrimSpace(creator) == "" {
			found.addf("%s.creators[%d]: a creator must be a non-empty string", where, i)
			continue
		}
		if previous, ok := seen[creator]; ok {
			found.addf("%s.creators[%d]: %q repeats creators[%d]", where, i, creator, previous)
		}
		seen[creator] = i
	}
}

// validateEntryName requires a name an assertion claim can carry.
func validateEntryName(where, name string, found *problems) {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t\r\n") {
		found.addf("%s: name must be a non-empty string without whitespace", where)
	}
}

// validateEntrySource checks that an entry has exactly one credential
// source: its own identity, or the shared static file. what names the kind
// of entry in the finding.
func (c *Config) validateEntrySource(where, what string, identity *Identity, found *problems) {
	switch {
	case identity != nil && c.Credentials.StaticFile != "":
		found.addf("%s.identity and credentials.static_file both name a credential source; configure one", where)
	case identity != nil:
		identity.validate(where+".identity", found)
	case c.Credentials.StaticFile == "":
		found.addf("%s names no identity and credentials.static_file is unset; "+
			"%s has no credential source", where, what)
	}
}

func (a *SandboxAssertion) validate(found *problems) {
	if !headerNameRE.MatchString(a.Header) {
		found.addf("sandbox_assertion.header %q is not a header name", a.Header)
	}
	switch {
	case strings.TrimSpace(a.IssuerKeyFile) == "":
		found.addf("sandbox_assertion.issuer_key_file is empty")
	case !filepath.IsAbs(a.IssuerKeyFile):
		found.addf("sandbox_assertion.issuer_key_file %q must be an absolute path", a.IssuerKeyFile)
	}
	if strings.TrimSpace(a.Audience) == "" {
		found.addf("sandbox_assertion.audience is empty")
	}
	a.validateIssuer(found)
	if age := a.MaxAge.Duration(); age < time.Second || age > MaxAssertionMaxAge {
		found.addf("sandbox_assertion.max_age %s must be between 1s and %s", age, MaxAssertionMaxAge)
	}
}

// validateIssuer requires an absolute URL when the issuer is pinned. The
// zone discovers the signer's keys at that URL.
func (a *SandboxAssertion) validateIssuer(found *problems) {
	if a.Issuer == "" {
		return
	}
	if issuer, err := url.Parse(a.Issuer); err != nil || !issuer.IsAbs() || issuer.Host == "" {
		found.addf("sandbox_assertion.issuer %q must be an absolute URL", a.Issuer)
	}
}

func (e Endpoint) validate(i int, found *problems) {
	parsed, err := parseEndpointURL(e.URL)
	if err != nil {
		found.addf("endpoints[%d]: url %q %v", i, e.URL, err)
		return
	}
	// The proxy forwards nothing cleartext, so a credential on an http
	// endpoint would never be sent.
	if parsed.scheme == "http" && e.Credential != nil {
		found.addf("endpoints[%d]: url %q is http, and the proxy forwards nothing cleartext, "+
			"so it cannot hold a credential", i, e.URL)
	}
	switch {
	case e.Host == "":
		found.addf("endpoints[%d]: url %q names no host", i, e.URL)
	case isIPLiteral(e.Host):
		found.addf("endpoints[%d]: host %q is an IP literal; a TLS client sends no SNI for one", i, e.Host)
	case !validDNSName(e.Host):
		found.addf("endpoints[%d]: host %q must be a DNS name of ASCII labels, "+
			"with no wildcard", i, e.Host)
	}
	switch {
	case !policy.CanonicalEscapes(e.PathPrefix):
		found.addf("endpoints[%d]: url path %q %s", i, e.PathPrefix, policy.NonCanonicalEscape)
	case !normalizedPrefix(e.PathPrefix):
		found.addf("endpoints[%d]: url path %q must be an absolute path in its shortest form", i, e.PathPrefix)
	}
	if e.Credential != nil {
		e.Credential.validate(i, found)
	}
}

// isIPLiteral reports whether host is an address rather than a name, in a
// spelling netip accepts.
func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// validDNSName reports whether host is a name a TLS client can send as an
// SNI. Labels hold ASCII letters, digits and hyphens, and a hyphen never
// starts or ends one.
//
// The final label must not be all digits. That rule refuses an address
// written so that netip does not read it as one, such as 0177.0.0.1, which
// glibc resolves as 127.0.0.1, or 2852039166, which it resolves as
// 169.254.169.254.
//
// RFC 6066 section 3 requires the SNI to be ASCII, so an internationalized
// name belongs here as its A-label. A host holding non-ASCII characters
// never matches what arrives, and a lookalike character would otherwise
// stand in for the ASCII one it resembles.
func validDNSName(host string) bool {
	if len(host) > maxDNSNameLength {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) > maxDNSLabelLength || !hostLabelRE.MatchString(label) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return strings.TrimLeft(last, "0123456789") != ""
}

// normalizedPrefix reports whether prefix is absolute, has no query or
// fragment, holds only characters a path can hold unescaped, and is in its
// shortest form with at most a trailing slash.
//
// The matcher compares a prefix against the escaped path a client sent. A
// prefix that is not already in that form could never match, so the document
// is refused rather than accepted and silently useless.
func normalizedPrefix(prefix string) bool {
	if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#") {
		return false
	}
	// A prefix is already in wire form when parsing it and escaping it
	// again returns the same bytes. That refuses a character a client
	// always escapes, such as a space, and a malformed escape such as "%zz"
	// or a trailing "%", which nothing unescapes and which would prefix
	// match by accident.
	parsed, err := url.Parse(prefix)
	if err != nil || parsed.EscapedPath() != prefix {
		return false
	}
	cleaned := path.Clean(prefix)
	return cleaned == prefix || cleaned+"/" == prefix
}

func (c Credential) validate(i int, found *problems) {
	validatePlacement(c.Placement, i, found)
}

func validatePlacement(placement Placement, i int, found *problems) {
	switch placement.Kind {
	case PlacementHeader:
		validateHeaderPlacement(placement, i, found)
	case PlacementQuery:
		requireOnly(i, found, "query", placement.Name != "", "needs a name",
			placement.Template == "" && placement.User == "", "takes no template or user")
	case PlacementBasic:
		requireOnly(i, found, "basic", placement.User != "", "needs a user",
			placement.Name == "" && placement.Template == "", "takes no name or template")
		if placement.User != "" && !credential.ValidBasicUser(placement.User) {
			found.addf("endpoints[%d]: a basic placement user must not contain a colon or a control character", i)
		}
	default:
		found.addf("endpoints[%d]: placement.kind %q must be %s, %s or %s",
			i, placement.Kind, PlacementHeader, PlacementQuery, PlacementBasic)
	}
}

func validateHeaderPlacement(placement Placement, i int, found *problems) {
	requireOnly(i, found, "header", placement.Name != "", "needs a name", placement.User == "", "takes no user")
	if !strings.Contains(placement.Template, credential.Token) {
		found.addf("endpoints[%d]: a header placement template must contain %s", i, credential.Token)
	}
	if credential.BannedHeaderName(placement.Name) {
		found.addf("endpoints[%d]: a header placement cannot name %s, "+
			"a header the connection, the proxy or the upstream's trust depends on", i, placement.Name)
	}
}

// requireOnly reports a missing required field and a field the kind does not
// take.
func requireOnly(
	i int, found *problems, kind string, hasRequired bool, missing string, onlyAllowed bool, extra string,
) {
	if !hasRequired {
		found.addf("endpoints[%d]: a %s placement %s", i, kind, missing)
	}
	if !onlyAllowed {
		found.addf("endpoints[%d]: a %s placement %s", i, kind, extra)
	}
}

// validateTransparent checks the transparent frontend and its receipt. A
// transparent frontend without a receipt cannot show that the rules send it
// traffic, so it requires a receipt path.
func (c *Config) validateTransparent(found *problems) {
	for i, port := range c.Listen.CleartextPorts {
		if port < 1 || port > maxPort {
			found.addf("listen.cleartext_ports[%d] is %d, outside 1-%d", i, port, maxPort)
		}
	}
	if c.Listen.TransparentPort == 0 {
		return
	}
	if c.Listen.TransparentPort < 0 || c.Listen.TransparentPort > maxPort {
		found.addf("listen.transparent_port is %d, outside 1-%d", c.Listen.TransparentPort, maxPort)
	}
	if !filepath.IsAbs(c.Netsetup.Receipt) {
		found.addf("netsetup.receipt %q must be an absolute path. The transparent frontend starts only after "+
			"the receipt shows the rules redirect to it", c.Netsetup.Receipt)
	}
}

// validateDNS checks the resolver's port and its forward targets. A
// resolver is optional. It refuses forward targets without
// listen.dns_port, because nothing would read them.
func (c *Config) validateDNS(found *problems) {
	for i, target := range c.DNS.ForwardTo {
		if _, err := netip.ParseAddr(strings.TrimSpace(target)); err == nil {
			continue
		}
		if _, err := netip.ParseAddrPort(strings.TrimSpace(target)); err != nil {
			found.addf("dns.forward_to[%d] %q must be an IP address or address:port. A hostname would need "+
				"a resolver to look it up", i, target)
		}
	}
	if c.Listen.DNSPort == 0 {
		if len(c.DNS.ForwardTo) > 0 {
			found.addf("dns.forward_to names resolvers and listen.dns_port is unset, so nothing reads them")
		}
		return
	}
	if c.Listen.DNSPort < 0 || c.Listen.DNSPort > maxPort {
		found.addf("listen.dns_port is %d, outside 1-%d", c.Listen.DNSPort, maxPort)
	}
}

// sortedPorts sorts and removes duplicate ports to canonicalize for the digest.
func sortedPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}
