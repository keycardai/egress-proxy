// Negative fixture for the import gate. Three files build only under the
// gate_negative tag. banned.go imports a module under
// github.com/keycardlabs/. shipped.go imports a test fixture under
// github.com/keycardai/egress-proxy/test/ from a non-test file that is not
// under test/, which the gate refuses. test/harness/allowed.go makes the
// same import from a file that is under test/, which the gate allows. Each
// import resolves to a stub in this directory so the package compiles and
// depguard, not the type checker, is what rejects it. scripts/lint.sh
// pointed here with --build-tags gate_negative must fail on the first two
// and say nothing about the third, and must pass without the tag.
//
// test/gates copies this module out of the repository's own test tree
// before it lints it. The import gate exempts every file under test/ by
// absolute path, and this module lives under one.
module github.com/keycardai/egress-proxy/test/gates/testdata/banned-import

go 1.27.1

require (
	github.com/keycardai/egress-proxy/test/fakeas v0.0.0
	github.com/keycardlabs/gatefixture v0.0.0
)

replace github.com/keycardlabs/gatefixture => ./keycardlabs-fixture

replace github.com/keycardai/egress-proxy/test/fakeas => ./fakeas-fixture
