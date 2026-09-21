# Working in this repository

This file is how work gets into the repository, written for the agents doing it.
Read it before changing anything. `docs/` holds the user-facing documentation.

## Repository facts

- Module path `github.com/keycardai/egress-proxy`, licensed Apache-2.0
  (`LICENSE`). Go 1.27.1 is the floor in `go.mod`; it is a choice, not a
  constraint from a dependency. Dependabot does not update the `go`
  directive, so a toolchain bump is a manual change.
- The tree builds on macOS and Linux. Linux-only syscalls go behind
  `//go:build linux` with a stub for every other platform.
- Layout:
  `cmd/` for binaries, `internal/` for everything else,
  `test/acceptance/<purpose>/run.sh` for the runnable acceptance scripts,
  `test/e2e/` for the cluster lanes,
  `test/gates/` for the gate self-tests, `scripts/` for the gate scripts,
  `images/` for image definitions.
- Build-time tools are `tool` directives in `go.mod`, run as
  `go tool <name>`: golangci-lint, go-licenses, govulncheck and ko. **Every
  tool a gate runs is declared there and pinned by its `require` line;
  never install a tool from `$PATH` in a script or workflow.** Their modules
  are requirements of the module, so they appear in `go.mod` and `go.sum`
  and in scanners that read those files, but no package imports them: they
  are in no binary, and the license gate, which walks imported packages,
  does not apply to them.

## Working agreements

These apply to every task in this repository.

1. One task is one PR, under 2,000 non-generated lines including tests. The
   subject starts with the task id: `A2: proxy core with CONNECT frontend`.
2. Every task lands with table-driven tests that pin expected values and
   denial reason codes, never merely "no error".
3. A task that changes the request path adds or extends an acceptance script
   under `test/acceptance/`. A script's directory is named for what it
   proves (`connect-allow-deny`, `credential-injection`), never for a task
   or milestone id, because the tree outlives the plan that produced it. CI
   runs every acceptance script on every commit.
4. Configuration is additive. The config schema grows fields and never
   renames or repurposes one. `internal/config/testdata/compat/` holds every
   earlier example document and a test parses all of them.
5. Fail closed. Any error in decision, exchange or substitution denies, and
   the test asserts which reason.
6. **NEVER import `github.com/keycardlabs/`.** This repository ships to
   customers and may depend only on public modules. The `depguard` rule in
   `.golangci.yml` fails the lint gate on such an import.
7. Verify a third-party API against the module cache before building on it.
   Read the source under `$(go env GOMODCACHE)` or run `go doc`. Where a
   design document is wrong about an API, implement against the real API and
   record the discrepancy in the PR.
8. Use the library. The iteration plan names a maintained, permissively
   licensed library for each problem the earlier proof of concept hand-rolled.
   A PR that writes what a listed library does says why the library does not
   fit. A new dependency goes through the license gate, not through a
   reviewer's memory.
9. Drive the artifact that ships. An acceptance test exercises the built
   image and the rendered manifest, not a hand-built stand-in.
10. Security lands with the surface, never after it. A task that adds an
    enforcement surface (a listener, a rule set, a mount, a credential path)
    adds the threats against it and the mitigation to `docs/security-model.md`
    in the same PR, with a test that exercises the mitigation. There is no
    hardening task. Nothing is tagged for a public release until the security
    model is complete for every shipped surface and reviewed against the code.
11. Never rewrite history.

## Gates

A change is not done until all of these pass. Each `make` target is also a CI
job, so the local gate and the CI gate are one gate.

    make build       go build ./...
    make test        go vet, go test -race ./..., including the gate self-tests
    make lint        golangci-lint at the pinned version, with the depguard import gate
    make checks      license allow-list, NOTICE freshness, govulncheck
    make acceptance  every acceptance script under test/acceptance
    make e2e         the cluster lanes (skips when there are none)

`make all` runs build, test, lint, checks and acceptance in that order.

The gates and what each enforces:

- **Lint** (`scripts/lint.sh`): `.golangci.yml`. The `depguard` rule is the
  import gate for working agreement 6. `gci` requires imports in three
  groups: standard library, third-party, this module. `gocyclo` caps a
  function's cyclomatic complexity at 12.
- **Licenses** (`scripts/check-licenses.sh`): every module in the build list
  carries a license on the SPDX allow-list in that script: Apache-2.0, MIT,
  BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0. GPL, LGPL and AGPL are off it.
  MPL-2.0 is allowed because its obligations attach to the MPL-licensed
  files, which a Go module dependency leaves unmodified and unvendored.
- **NOTICE** (`scripts/notice.sh`): `NOTICE` is generated from the build list
  with `go-licenses report`. Run `make notice` after changing dependencies
  and commit the result; CI fails when it is stale.
- **Vulnerabilities** (`scripts/vuln.sh`): `govulncheck` over the module. It
  also runs daily on a schedule, because a vulnerability can be published
  against a dependency that has not changed.

Each gate has a negative fixture under `test/gates/testdata/` that makes it
fail, and `test/gates` runs the gate scripts against those fixtures as part
of `make test`. A change to a gate changes its fixture or its test. The
fixture modules pin old or copyleft versions on purpose; Dependabot scans
only the directories `.github/dependabot.yml` lists, and that is not one of
them, and `socket.yml` excludes the path from Socket's scan.

## Dependencies

A dependency goes in `go.mod` when a task imports it, and a dependency no task
imports does not go in at all. Before adding one:

1. Confirm its license is on the allow-list; `make check-licenses` tells you.
2. Run `make notice` and commit `NOTICE`.
3. Run `make vuln`.

A build-time tool is not a dependency of the product. It goes in `go.mod` as
a `tool` directive (`go get -tool <package>@<version>`), and its license is
not constrained by the product allow-list because nothing imports it.

Dependabot opens PRs for module, tool and action updates
(`.github/dependabot.yml`). Those PRs run the same gates as any other change.
