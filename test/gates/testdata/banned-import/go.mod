// Negative fixture for the import gate: banned.go, built only under the
// gate_negative tag, imports a module under github.com/keycardlabs/. The
// import resolves to the stub in ./keycardlabs-fixture so the package
// compiles and depguard, not the type checker, is what rejects it.
// scripts/lint.sh pointed here with --build-tags gate_negative must fail, and
// must pass without the tag.
module github.com/keycardai/egress-proxy/test/gates/testdata/banned-import

go 1.27.1

require github.com/keycardlabs/gatefixture v0.0.0

replace github.com/keycardlabs/gatefixture => ./keycardlabs-fixture
