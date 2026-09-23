// Command fakeas serves the fake authorization server of test/fakeas over TLS,
// so the cluster tests can deploy it as a pod beside the sandbox it tests. Unit
// and acceptance tests mount the same package on a listener in their own
// process.
//
// It verifies no signature on anything; it is a mock fixture. NEVER deploy it
// outside a test cluster.
//
// It writes one line per token request to standard output. The cluster tests
// read that stream back as the zone's request log.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/keycardai/egress-proxy/test/fakeas"
)

// readHeaderTimeout bounds how long a client has to send a request head.
const readHeaderTimeout = 10 * time.Second

// errUsage is returned for a command line the server cannot run with.
var errUsage = errors.New("fakeas")

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
	if *clientID != "" {
		assertionClients = []string{*clientID}
	}
	zone := fakeas.New(fakeas.Options{
		Credentials:      granted,
		Namespace:        *namespace,
		ClientSecrets:    secrets,
		AssertionClients: assertionClients,
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
