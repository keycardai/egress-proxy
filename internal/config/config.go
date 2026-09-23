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
const (
	DefaultConnect = "127.0.0.1:3128"
	DefaultAdmin   = "/run/egress/admin/admin.sock"
	// DefaultCleartextPort is the captured port read as cleartext HTTP when
	// listen.cleartext_ports is empty.
	DefaultCleartextPort  = 80
	DefaultCAOutDir       = "/shared-ca"
	DefaultLeafTTL        = 24 * time.Hour
	DefaultCacheSize      = 1024
	DefaultMaxConnections = 1024
	DefaultIdleTimeout    = 5 * time.Minute
	// DefaultEndpointPort is the port an endpoint covers when it names none.
	// Endpoints name HTTPS destinations.
	DefaultEndpointPort = 443
	// DefaultResponseHeaderTimeout bounds the wait for an upstream response
	// head. It does not bound a body, so a streamed response is unaffected.
	DefaultResponseHeaderTimeout = 30 * time.Second
	// DefaultExchangeTimeout limits one token exchange, including discovery.
	DefaultExchangeTimeout = 10 * time.Second

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

	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// hostLabelRE is one DNS label. A document's host is normalized to
	// lowercase before it is validated.
	hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
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
	Netsetup  Netsetup   `json:"netsetup"`
	Policy    Policy     `json:"policy"`
	Endpoints []Endpoint `json:"endpoints"`
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
	case c.Identity != nil:
		return SourceExchange
	default:
		return SourceNone
	}
}

// Sandbox identifies the sandbox being proxied on every audit record.
type Sandbox struct {
	ID string `json:"id"`
}

// Identity is the principal that identifies this proxy workload. It is the
// authority with which the egress proxy authenticates with a Keycard zone and
// performs a token exchange on the impersonated user's behalf.
// Exactly one of WorkloadTokenFile and ClientSecretFile authenticates the
// exchange. A workload token lets the zone read a ServiceAccount subject. A
// client secret gives the zone no ServiceAccount subject.
type Identity struct {
	ZoneURL           string `json:"zone_url"`
	ClientID          string `json:"client_id"`
	WorkloadTokenFile string `json:"workload_token_file"`
	// ClientSecretFile holds the application credential secret. The proxy
	// never writes the secret to the document, a flag, or a variable.
	ClientSecretFile string      `json:"client_secret_file"`
	Impersonate      Impersonate `json:"impersonate"`
}

// Impersonate identifies the user subject this proxy impersonates in every
// Keycard token exchange.
type Impersonate struct {
	User string `json:"user"`
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
	// CleartextPorts lists captured destination ports to read as cleartext
	// HTTP. The destination comes from the Host header. Empty means port 80.
	// Every other captured port is read as TLS.
	CleartextPorts []int `json:"cleartext_ports"`
	// Admin is the path of the admin Unix socket.
	Admin string `json:"admin"`
}

// Netsetup contains the init container's receipt. The proxy reads it before
// serving a transparent frontend and refuses a mismatched uid or port.
type Netsetup struct {
	Receipt string `json:"receipt"`
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
	MaxConnections int      `json:"max_connections"`
	IdleTimeout    Duration `json:"idle_timeout"`
	// ResponseHeaderTimeout is how long an upstream has to send a response
	// head once the request is written. It does not bound the body, so a
	// streamed response runs as long as it stays active.
	ResponseHeaderTimeout Duration `json:"response_header_timeout"`
	// ExchangeTimeout limits one token exchange, including discovery. A
	// request that exceeds it returns exchange_failed.
	ExchangeTimeout Duration `json:"exchange_timeout"`
}

// Policy is what joins and what leaves the platform deny list.
type Policy struct {
	ClusterCIDRs       []string `json:"cluster_cidrs"`
	DenyListExceptions []string `json:"deny_list_exceptions"`
}

// Endpoint is one destination the sandbox can reach.
type Endpoint struct {
	Host string `json:"host"`
	// Port is the port this endpoint covers on that host. It defaults to
	// 443. A host reachable on two ports is two endpoints.
	Port       int         `json:"port"`
	PathPrefix string      `json:"path_prefix"`
	Resource   string      `json:"resource"`
	Credential *Credential `json:"credential,omitempty"`
}

// Credential says where a credential goes and which placeholder the
// workload holds for it.
type Credential struct {
	Placement Placement `json:"placement"`
	Env       string    `json:"env"`
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
	Admin                 string
	NetsetupReceipt       string
	CAOutDir              string
	CAStateDir            string
	ClientSecretFile      string
	CredentialStaticFile  string
	LeafTTL               time.Duration
	CacheSize             int
	UpstreamCAFiles       []string
	MaxConnections        int
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
	Endpoints          []Endpoint       `json:"endpoints"`
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
func canonicalEndpoints(endpoints []Endpoint) []Endpoint {
	out := append([]Endpoint(nil), endpoints...)
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
}

// applyEndpointDefaults normalizes the host and fills the settings the entry
// leaves out. Zero means the document named no port, as it does for the
// limits and the cache size, so a document cannot ask for port 0.
func applyEndpointDefaults(endpoint *Endpoint) {
	endpoint.Host = policy.NormalizeHost(endpoint.Host)
	if endpoint.Port == 0 {
		endpoint.Port = DefaultEndpointPort
	}
	if endpoint.PathPrefix == "" {
		endpoint.PathPrefix = "/"
	}
	if endpoint.Resource == "" && endpoint.Host != "" {
		endpoint.Resource = "https://" + endpoint.Host + "/"
	}
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
	override("listen.admin", overrides.Admin != "", func() { c.Listen.Admin = overrides.Admin })
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
	override(
		"limits.max_connections",
		overrides.MaxConnections != 0,
		func() { c.Limits.MaxConnections = overrides.MaxConnections },
	)
	override(
		"limits.idle_timeout",
		overrides.IdleTimeout != 0,
		func() { c.Limits.IdleTimeout = Duration(overrides.IdleTimeout) },
	)
	override(
		"limits.response_header_timeout",
		overrides.ResponseHeaderTimeout != 0,
		func() { c.Limits.ResponseHeaderTimeout = Duration(overrides.ResponseHeaderTimeout) },
	)
	override(
		"limits.exchange_timeout",
		overrides.ExchangeTimeout != 0,
		func() { c.Limits.ExchangeTimeout = Duration(overrides.ExchangeTimeout) },
	)
	sort.Strings(c.Overridden)
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
		c.Identity.validate(&found)
	}
	c.validateProcess(&found)
	c.validateCredentials(&found)
	c.validatePolicy(&found)
	seen := make(map[string]int, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		endpoint.validate(i, &found)
		// An endpoint identifies a service by host, port, and prefix. Compile
		// uses the same identity, so both checks reject the same duplicate.
		key := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)) + endpoint.PathPrefix
		if previous, ok := seen[key]; ok {
			found.addf("endpoints[%d]: host %q with path_prefix %q repeats endpoints[%d]",
				i, endpoint.Host, endpoint.PathPrefix, previous)
		}
		seen[key] = i
	}
	if len(found) > 0 {
		return fmt.Errorf("%w:\n  %s", errInvalid, strings.Join(found, "\n  "))
	}
	return nil
}

func (c *Config) validateProcess(found *problems) {
	if _, _, err := net.SplitHostPort(c.Listen.Connect); err != nil {
		found.addf("listen.connect %q is not host:port: %v", c.Listen.Connect, err)
	}
	if !filepath.IsAbs(c.Listen.Admin) {
		found.addf("listen.admin %q must be an absolute path; the admin surface is a Unix socket", c.Listen.Admin)
	}
	c.validateTransparent(found)
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
	if c.Limits.MaxConnections < 1 {
		found.addf("limits.max_connections must be at least 1")
	}
	if c.Limits.IdleTimeout <= 0 {
		found.addf("limits.idle_timeout must be positive")
	}
	if c.Limits.ResponseHeaderTimeout <= 0 {
		found.addf("limits.response_header_timeout must be positive")
	}
	if c.Limits.ExchangeTimeout <= 0 {
		found.addf("limits.exchange_timeout must be positive")
	}
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

func (id *Identity) validate(found *problems) {
	zone, err := url.Parse(id.ZoneURL)
	switch {
	case err != nil:
		found.addf("identity.zone_url %q is not a URL: %v", id.ZoneURL, err)
	case zone.Scheme != "https" || zone.Host == "":
		found.addf("identity.zone_url %q must be an absolute https URL", id.ZoneURL)
	case zone.User != nil:
		found.addf("identity.zone_url holds userinfo. It is an issuer and never a credential")
	}
	if strings.TrimSpace(id.ClientID) == "" {
		found.addf("identity.client_id is empty")
	}
	id.validateClientAuth(found)
	if strings.TrimSpace(id.Impersonate.User) == "" {
		found.addf("identity.impersonate.user is empty")
	}
}

// validateClientAuth requires exactly one client authentication mechanism.
// The two mechanisms give the zone different authority, so a record must
// identify which one the zone used.
func (id *Identity) validateClientAuth(found *problems) {
	switch {
	case id.WorkloadTokenFile == "" && id.ClientSecretFile == "":
		found.addf("identity names no client authentication; set workload_token_file or client_secret_file")
	case id.WorkloadTokenFile != "" && id.ClientSecretFile != "":
		found.addf("identity.workload_token_file and identity.client_secret_file both authenticate the " +
			"exchange; configure one")
	}
	if id.WorkloadTokenFile != "" && !filepath.IsAbs(id.WorkloadTokenFile) {
		found.addf("identity.workload_token_file %q must be an absolute path", id.WorkloadTokenFile)
	}
	if id.ClientSecretFile != "" && !filepath.IsAbs(id.ClientSecretFile) {
		found.addf("identity.client_secret_file %q must be an absolute path", id.ClientSecretFile)
	}
}

func (e Endpoint) validate(i int, found *problems) {
	switch {
	case e.Host == "":
		found.addf("endpoints[%d]: host is empty", i)
	case isIPLiteral(e.Host):
		found.addf("endpoints[%d]: host %q is an IP literal; a TLS client sends no SNI for one", i, e.Host)
	case !validDNSName(e.Host):
		found.addf("endpoints[%d]: host %q must be a DNS name of ASCII labels, "+
			"with no scheme, port, path or wildcard", i, e.Host)
	}
	if e.Port < 1 || e.Port > maxPort {
		found.addf("endpoints[%d]: port %d must be between 1 and %d", i, e.Port, maxPort)
	}
	if !normalizedPrefix(e.PathPrefix) {
		found.addf("endpoints[%d]: path_prefix %q must be an absolute path in its shortest form", i, e.PathPrefix)
	}
	e.validateResource(i, found)
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

func (e Endpoint) validateResource(i int, found *problems) {
	resource, err := url.Parse(e.Resource)
	switch {
	case err != nil:
		found.addf("endpoints[%d]: resource %q is not a URL: %v", i, e.Resource, err)
	case resource.Scheme != "https" || resource.Host == "":
		found.addf("endpoints[%d]: resource %q must be an absolute https URL", i, e.Resource)
	case resource.User != nil || resource.RawQuery != "" || resource.Fragment != "":
		found.addf("endpoints[%d]: resource %q must hold no userinfo, query or fragment", i, e.Resource)
	}
}

func (c Credential) validate(i int, found *problems) {
	if !envNameRE.MatchString(c.Env) {
		found.addf("endpoints[%d]: credential.env %q is not an environment variable name", i, c.Env)
	}
	validatePlacement(c.Placement, i, found)
}

func validatePlacement(placement Placement, i int, found *problems) {
	switch placement.Kind {
	case PlacementHeader:
		requireOnly(i, found, "header", placement.Name != "", "needs a name", placement.User == "", "takes no user")
		if !strings.Contains(placement.Template, credential.Token) {
			found.addf("endpoints[%d]: a header placement template must contain %s", i, credential.Token)
		}
		if credential.BannedHeaderName(placement.Name) {
			found.addf("endpoints[%d]: a header placement cannot name %s, "+
				"a header the connection, the proxy or the upstream's trust depends on", i, placement.Name)
		}
	case PlacementQuery:
		requireOnly(i, found, "query", placement.Name != "", "needs a name",
			placement.Template == "" && placement.User == "", "takes no template or user")
	case PlacementBasic:
		requireOnly(i, found, "basic", placement.User != "", "needs a user",
			placement.Name == "" && placement.Template == "", "takes no name or template")
	default:
		found.addf("endpoints[%d]: placement.kind %q must be %s, %s or %s",
			i, placement.Kind, PlacementHeader, PlacementQuery, PlacementBasic)
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
