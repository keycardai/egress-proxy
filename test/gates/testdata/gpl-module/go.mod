// Negative fixture for the license gate: this module depends on a GPL-3.0
// module. scripts/check-licenses.sh pointed here must fail. It is a separate
// module so the root build list never includes it.
module github.com/keycardai/egress-proxy/test/gates/testdata/gpl-module

go 1.27.1

require github.com/AdguardTeam/gomitmproxy v0.2.2

require (
	github.com/AdguardTeam/golibs v0.13.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/text v0.8.0 // indirect
)
