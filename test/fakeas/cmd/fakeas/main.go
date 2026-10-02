// Command fakeas serves the fake authorization server of test/fakeas over TLS,
// so the cluster tests can deploy it as a pod beside the sandbox it tests. Unit
// and acceptance tests mount the same package on a listener in their own
// process.
//
// It verifies each client assertion against the service account keys of the
// cluster it runs in, so it must run in a pod. It does not verify the
// substitute-user token, which is unsigned. NEVER deploy it outside a test
// cluster.
//
// It writes one line per token request to standard output. The cluster tests
// read that stream back as the zone's request log.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"k8s.io/client-go/rest"

	"github.com/keycardai/egress-proxy/test/fakeas"
)

// readHeaderTimeout bounds how long a client has to send a request head.
const readHeaderTimeout = 10 * time.Second

// discoveryTimeout bounds the read of the API server's issuer at start-up.
const discoveryTimeout = 30 * time.Second

// The API server's service account issuer discovery paths. The default RBAC
// lets every ServiceAccount read both.
const (
	discoveryPath = "/.well-known/openid-configuration"
	jwksPath      = "/openid/v1/jwks"
)

// errUsage is returned for a command line the server cannot run with.
var errUsage = errors.New("fakeas")

// errDiscovery is returned when the API server's discovery document does not
// name an issuer.
var errDiscovery = errors.New("service account issuer discovery")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// grants collects the repeatable -grant flag.
type grants map[string]string

func (g grants) String() string { return fmt.Sprint(map[string]string(g)) }

func (g grants) Set(value string) error {
	resource, credential, ok := strings.Cut(value, "=")
	if !ok {
		return fmt.Errorf("%w: -grant takes RESOURCE=CREDENTIAL, got %q", errUsage, value)
	}
	g[resource] = credential
	return nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("fakeas", flag.ContinueOnError)
	addr := flags.String("addr", ":8443", "the address to serve TLS on")
	certFile := flags.String("cert", "", "the server certificate in PEM form")
	keyFile := flags.String("key", "", "the server private key in PEM form")
	namespace := flags.String("namespace", "agents",
		"the ServiceAccount namespace the impersonation rule expects")
	clientID := flags.String("client-id", "",
		"the client id this server knows, by -client-secret or by a client assertion")
	clientSecret := flags.String("client-secret", "", "the secret for -client-id, empty to accept assertions alone")
	audience := flags.String("assertion-audience", "",
		"the audience a client assertion must name, required with -client-id")
	granted := grants{}
	flags.Var(granted, "grant", "RESOURCE=CREDENTIAL to issue, repeatable")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse the command line: %w", err)
	}
	if *certFile == "" || *keyFile == "" {
		return fmt.Errorf("%w: -cert and -key are required", errUsage)
	}

	secrets := map[string]string{}
	if *clientID != "" && *clientSecret != "" {
		secrets[*clientID] = *clientSecret
	}
	var assertionClients []string
	var verifier *oidc.IDTokenVerifier
	if *clientID != "" {
		if *audience == "" {
			return fmt.Errorf("%w: -assertion-audience is required with -client-id", errUsage)
		}
		assertionClients = []string{*clientID}
		var err error
		if verifier, err = clusterVerifier(*audience); err != nil {
			return err
		}
	}
	zone := fakeas.New(fakeas.Options{
		Credentials:      granted,
		Namespace:        *namespace,
		ClientSecrets:    secrets,
		AssertionClients: assertionClients,
		Assertions:       verifier,
	})
	server := &http.Server{
		Addr:              *addr,
		Handler:           fakeas.LogExchanges(zone, os.Stdout),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	fmt.Fprintf(os.Stderr, "fakeas: serving %s for namespace %s\n", *addr, *namespace)
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		return fmt.Errorf("serve %s: %w", *addr, err)
	}
	return nil
}

// clusterVerifier checks client assertions against the API server of the
// cluster the pod runs in. The issuer comes from the API server's discovery
// document and the keys from its JWKS endpoint. Both requests use the pod's
// own ServiceAccount token.
func clusterVerifier(audience string) (*oidc.IDTokenVerifier, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("read the in-cluster config: %w", err)
	}
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, fmt.Errorf("build the API server client: %w", err)
	}
	issuer, err := discoverIssuer(client, config.Host)
	if err != nil {
		return nil, err
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), config.Host+jwksPath)
	fmt.Fprintf(os.Stderr, "fakeas: verifying client assertions from %s for audience %s\n", issuer, audience)
	// Audience claim must contain the Client ID per OpenID Connect Core 1.0
	// §3.1.3.7, step 3. Using the same string for both.
	return oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: audience}), nil
}

// discoverIssuer reads the service account issuer from the API server.
func discoverIssuer(client *http.Client, host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+discoveryPath, nil)
	if err != nil {
		return "", fmt.Errorf("build the discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", discoveryPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: read %s: %s", errDiscovery, discoveryPath, resp.Status)
	}
	var document struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return "", fmt.Errorf("decode %s: %w", discoveryPath, err)
	}
	if document.Issuer == "" {
		return "", fmt.Errorf("%w: %s names no issuer", errDiscovery, discoveryPath)
	}
	return document.Issuer, nil
}
