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
  `test/acceptance/` for the acceptance tests, Go behind the `acceptance`
  build tag with one testscript per scenario under `testdata/`,
  `test/acceptance/netfixture/` for the probes, listeners, HTTPS upstream,
  and Go client used by the Docker scenarios,
  `test/e2e/` for the cluster lanes,
  `test/fakeas/` a fake authorization server the unit tests and the
  acceptance lane drive the exchange against,
  `test/gates/` for the gate self-tests,
  `test/images/` the image lane, Go behind the `images` build tag, which
  builds the three images locally and drives what each one has to do,
  `scripts/` for the gate scripts,
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
   subject summarizes the purpose: `proxy core with CONNECT frontend`.
2. Every task lands with table-driven tests that pin expected values and
   denial reason codes, never merely "no error". Assertions use
   `stretchr/testify`: `require` where a failure makes the rest of the test
   meaningless, `assert` otherwise. See "Tests" below.
3. A task that changes the request path adds or extends an acceptance
   scenario under `test/acceptance/testdata/`. A scenario is a testscript
   (`github.com/rogpeppe/go-internal/testscript`) that drives the built
   binary through its flags, environment and an external client, with the
   custom commands `test/acceptance/acceptance_test.go` registers. Its file
   is named for what it proves (`connect_allow_deny.txtar`,
   `credential_injection.txtar`), never for a task or milestone id, because
   the tree outlives the plan that produced it. CI runs every scenario on
   every commit. Acceptance and gate code is Go; there are no shell scripts
   to maintain beyond the gate wrappers under `scripts/`.
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
8. Use the library. Prefer a maintained, permissively licensed module over a
   hand-rolled version of the same thing, and say in the PR why the obvious
   library does not fit when you write one anyway. A new dependency goes
   through the license gate, not through a reviewer's memory.
9. Drive the artifact that ships. An acceptance test exercises the built
   image and the rendered manifest, not a hand-built stand-in.
10. Security lands with the surface, never after it. A task that adds an
    enforcement surface (a listener, a rule set, a mount, a credential path)
    adds the threats against it and the mitigation to `docs/security-model.md`
    in the same PR, with a test that exercises the mitigation. There is no
    hardening task. Nothing is tagged for a public release until the security
    model is complete for every shipped surface and reviewed against the code.
11. Never rewrite history.

## Design decisions that constrain later tasks

These are settled and load-bearing. Changing one is a design change rather
than a refactor, and it changes `docs/security-model.md` with it.

- **goproxy handles the CONNECT line and nothing else.** It cannot serve the
  loop inside a tunnel: v1.9.1 dereferences a nil URL when a request has
  an asterisk-form target and a `Host` with a port, inside a goroutine it
  starts itself, so no recover outside goproxy reaches it. An allowed tunnel
  is hijacked, TLS is terminated on a goroutine of ours that recovers, and
  the decrypted connection goes into `intake`, a channel-backed listener that
  a second `http.Server` serves. A transparent frontend should push into that
  same intake rather than synthesizing a CONNECT, which needs a small
  exported entry point on `proxy.Server`.
- **A connection decision names no endpoint, but shares the reason codes.**
  The connection-scoped answer knows only a host, so it leaves
  `decision.endpoint` empty: a path prefix on a record that no path took part
  in is misleading. The reasons stay `endpoint_allowed` and
  `no_matching_endpoint` in both scopes, because the endpoint is the unit a
  document declares, and that holds even where a later protocol matches on
  something other than a path. Read `scope` to tell the two apart.
- **Reason codes are a stable contract.** An audit query and an agent's error
  handling both key on them, so add a code rather than reword one. They are a
  named type, and the `exhaustive` linter makes a new code fail the build
  until every switch that maps one decides what to do with it. The same holds
  for `policy.Verdict`, `audit.Scope` and `config.PlacementKind`.
- **Two digests identify every decision.** `document.digest` covers the
  mounted document before overrides and defaults. `config.digest` covers the
  settings in force after them, so two sidecars that answer every request
  alike share it whatever each was given. A setting belongs in
  `decisionInputs` when its value can make two sidecars answer the same
  request differently, which keeps `sandbox.id`, the listen addresses, the CA
  directories and the limits out. The digest input is never exposed, so
  hashing a file path leaks nothing.
- **Settings come from the document, then the environment, then flags.** Only
  the per-instance and process settings have a flag and an `EGRESS_PROXY_*`
  variable. The endpoints and the `policy` section come from the document
  alone and must never gain one, because a record has to name every rule that
  was in force. A variable is named for the setting it fills rather than the
  source that feeds it, so the mapping from pod metadata lives in the
  manifest. `Config.Overridden` lists the keys an override replaced, and the
  process announces them on every start.
- **Both servers take a context and stop together.** `Run` composes the proxy
  and the admin socket under one `errgroup`, so a failure in either cancels
  the other, each drains within its grace period, and `Run` returns once both
  have stopped. An error discarded during shutdown is logged unless it is the
  expected already-closed case.
- **The CA key goes only to `ca.state_dir`.** The binary proves that
  directory is memory-backed with a filesystem-type check rather than
  trusting the manifest, and refuses a path that overlaps the output
  directory. The output directory holds the certificate and nothing else.
- **The binary publishes what it accepts and judges no manifest.**
  `egress-proxy settings` prints the `EGRESS_PROXY_` names, the flag each
  one fills and the defaults in force, all read from `flagSet` and the
  document parser at run time. The pod composition and the lint that
  enforces it live with the charts, so NEVER judge a manifest here. A
  setting added to the flag set is published on the next build, and the
  chart lint reads it out of the image.
- **Readiness covers every listener.** `/readyz` answers 200 only after the
  CONNECT listener and the transparent sockets are bound and `ca.crt` is
  written. The kubelet releases the workload on that answer when the proxy
  is a sidecar, an init container with `restartPolicy: Always`, so a frontend
  bound later would leave the workload's first captured connection refused.
  The netsetup receipt says which address families the redirect covers, and
  a family it names with no bound socket stops the start. The admin socket
  stops accepting when the drain starts, so the probe fails from then on. The
  probe is the binary itself, because the admin surface is a socket and the
  proxy image has no shell.

## Tests

- `require` halts, `assert` continues. Port the old failure message into the
  assertion's message argument rather than dropping it, and split a compound
  condition so a failure names the field that actually differs.
- Wait on a signal, not on a clock. A test that needs something another
  goroutine produces subscribes to it; polling with a sleep is the fallback
  for a side effect of another process, such as a file appearing or a port
  binding.
- Prove a new negative assertion fails before trusting it. Break the thing it
  guards, watch the test go red, then restore. Restore from a copy you made,
  never with `git checkout`, which discards unstaged work in the file.
- Verify third-party behaviour rather than asserting it from memory. A short
  throwaway program under a scratch directory settles what a library actually
  does, and the answer belongs in the PR.
- The acceptance scenarios drive the built binary through its flags,
  environment and an external client. Beyond testscript's own commands,
  `acceptance_test.go` registers `upstream`, `fakeas`, `satoken`, `expand`,
  `freeport`, `shortdir`, `waitfile`, `waitgrep`, `waitport`, `sigterm`, and
  `audit`. The audit command matches dotted fields in the JSON stream, and
  `-all` requires every record to match. `dockerlab`, `linuxbin`, and `tlscert`
  build the Docker network, cross-compiled binaries, and an upstream
  certificate. `[docker]` skips a scenario when no Docker daemon answers.

## Comments

Comments describe the current state of the code in the present tense.
Anything historical belongs in the commit message.

- Give the rule, not the derivation. Drop the worked example and the
  reasoning chain that produced it.
- No postmortems and no rejected alternatives. State the invariant that holds
  now, not the bug that motivated it or what the code is not.
- Operational rules are imperative and findable: "NEVER write the key outside
  the state directory" beats three paragraphs circling the same point.
- Nothing that rots. No line or query counts, no "mirrors otherFunction"
  cross-references, no "for now" or "currently".
- Plain language. Active voice, simple tenses, one claim per sentence. Modals
  limited to can, will and must. No em-dashes and no semicolons joining two
  claims: write two sentences or name the relation.
- Say it once. Shared rationale lives at the thing it belongs to, not
  restated in every caller.
- The same standard applies in tests. Say why the test is shaped the way it
  is, not what you saw while writing it.

## Gates

A change is not done until all of these pass. Each `make` target is also a CI
job, so the local gate and the CI gate are one gate.

    make build       go build ./...
    make test        go vet, go test -race ./..., including the gate self-tests
    make lint        golangci-lint at the pinned version, with the depguard import gate
    make checks      license allow-list, NOTICE freshness, govulncheck
    make acceptance  the acceptance tests under test/acceptance, against the built binary
    make e2e         the cluster lanes (skips when there are none)
    make images      the three images, built locally, and what each one does

`make all` runs build, test, lint, checks and acceptance in that order.

The gates and what each enforces:

- **Lint** (`scripts/lint.sh`): `.golangci.yml`. The `depguard` rule is the
  import gate for working agreement 6. `gci` requires imports in three
  groups: standard library, third-party, this module. `cyclop` caps a
  function's cyclomatic complexity at 10, and does not run on tests. The
  script runs the linter once per GOOS, linux and then darwin, because a
  file its build constraints exclude is never loaded. A `//go:build linux`
  file linted on the host alone goes unlinted on a macOS workstation and
  fails in CI instead.
- **Licenses** (`scripts/check-licenses.sh`): every module in the build list
  has a license on the SPDX allow-list in that script: Apache-2.0, MIT,
  BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0. GPL, LGPL and AGPL are off it.
  MPL-2.0 is allowed because its obligations attach to the MPL-licensed
  files, which a Go module dependency leaves unmodified and unvendored.
- **NOTICE** (`scripts/notice.sh`): `NOTICE` is generated from the build list
  with `go-licenses report`. Run `make notice` after changing dependencies
  and commit the result; CI fails when it is stale.
- **Vulnerabilities** (`scripts/vuln.sh`): `govulncheck` over the module. It
  also runs daily on a schedule, because a vulnerability can be published
  against a dependency that has not changed.
- **Images** (`make images`): the three images under `images/`, built
  locally with `ko build --local` and `docker build`. The lane skips when no
  Docker daemon answers. Nothing in this repository pushes an image.

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

Dependabot opens PRs for module, tool, action and base image updates
(`.github/dependabot.yml`). It does not read `images/proxy/.ko.yaml`, so the
proxy's distroless base digest is bumped by hand. Those PRs run the same gates as any other change.
