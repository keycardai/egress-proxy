// Negative fixture for the tags the lint gate builds with. images.go and
// acceptance.go each build only under one of the tags scripts/lint.sh passes
// itself, and each imports a module under github.com/keycardlabs/. The import
// resolves to the stub in ../banned-import, so depguard, not the type
// checker, is what rejects it. scripts/lint.sh pointed here with no argument
// must fail on both files.
module github.com/keycardai/egress-proxy/test/gates/testdata/tagged-import

go 1.27.1

require github.com/keycardlabs/gatefixture v0.0.0

replace github.com/keycardlabs/gatefixture => ../banned-import/keycardlabs-fixture
