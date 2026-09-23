// Negative fixture for the import gate. Two files build only under the
// gate_negative tag: banned.go imports a module under github.com/keycardlabs/,
// and shipped.go imports a test fixture under
// github.com/keycardai/egress-proxy/test/ from a non-test file. Each import
// resolves to a stub in this directory so the package compiles and depguard,
// not the type checker, is what rejects it. scripts/lint.sh pointed here with
// --build-tags gate_negative must fail on both, and must pass without the tag.
module github.com/keycardai/egress-proxy/test/gates/testdata/banned-import

go 1.27.1

require (
	github.com/keycardai/egress-proxy/test/fakeas v0.0.0
	github.com/keycardlabs/gatefixture v0.0.0
)

replace github.com/keycardlabs/gatefixture => ./keycardlabs-fixture

replace github.com/keycardai/egress-proxy/test/fakeas => ./fakeas-fixture
