// Negative fixture for the NOTICE gate. The binary under cmd/ imports
// golang.org/x/text, and NOTICE leaves it out, so scripts/notice.sh pointed
// here with --check must fail and name it. The package under test/ imports
// github.com/pkg/errors, which does not ship in a binary and must not
// appear. It is a separate module so the root build list never includes it.
module github.com/keycardai/egress-proxy/test/gates/testdata/stale-notice

go 1.27.1

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/text v0.3.7
)
