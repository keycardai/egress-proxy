// Command egress-proxy is the sidecar that mediates a sandbox's outbound
// HTTPS: it decides each request against the configured endpoints, injects
// the credential the zone mints for the impersonated user, and writes one
// audit record per decision.
//
// The proxy data path is not implemented. This entry point exists so the
// module builds, the image builds, and the gates have a package to check.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

// exitNotImplemented is the exit status while the proxy data path does not
// exist: the binary starts, says so, and refuses to serve.
const exitNotImplemented = 2

func main() {
	fmt.Fprintf(os.Stderr, "egress-proxy %s: the proxy is not implemented yet\n", version())
	os.Exit(exitNotImplemented)
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
