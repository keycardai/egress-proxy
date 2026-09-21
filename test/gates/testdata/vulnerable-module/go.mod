// Negative fixture for the vulnerability gate: this module calls
// golang.org/x/text/language.ParseAcceptLanguage at a version with the
// published vulnerability GO-2022-1059. scripts/vuln.sh pointed here must
// fail. It is a separate module so the root build list never includes it.
module github.com/keycardai/egress-proxy/test/gates/testdata/vulnerable-module

go 1.27.1

require golang.org/x/text v0.3.7
