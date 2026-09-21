// Negative fixture for the license gate: imports a GPL-3.0 module.
package main

import "github.com/AdguardTeam/gomitmproxy"

var _ = gomitmproxy.NewProxy

func main() {}
