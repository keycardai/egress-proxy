# Changelog

## [0.2.1](https://github.com/keycardai/egress-proxy/compare/v0.2.0...v0.2.1) (2026-10-13)


### Bug Fixes

* refuse path escapes that change endpoint selection ([#52](https://github.com/keycardai/egress-proxy/issues/52)) ([e455c02](https://github.com/keycardai/egress-proxy/commit/e455c0205f7fa1eb21b708f6baf00e85b2d0099c))

## [0.2.0](https://github.com/keycardai/egress-proxy/compare/v0.1.0...v0.2.0) (2026-10-13)


### ⚠ BREAKING CHANGES

* replace listen.dns with listen.dns_port ([#46](https://github.com/keycardai/egress-proxy/issues/46))

### Bug Fixes

* refuse a path escape that is not canonical ([#45](https://github.com/keycardai/egress-proxy/issues/45)) ([a1a9391](https://github.com/keycardai/egress-proxy/commit/a1a9391a2401873e2502a3d8ac788c1744da75c1))
* replace listen.dns with listen.dns_port ([#46](https://github.com/keycardai/egress-proxy/issues/46)) ([4e20b06](https://github.com/keycardai/egress-proxy/commit/4e20b069c2d0769fcf4e514ea2797f957d0d127d))

## 0.1.0 (2026-10-09)


### Features

* allowlist DNS resolver inside the proxy ([#15](https://github.com/keycardai/egress-proxy/issues/15)) ([4b2310b](https://github.com/keycardai/egress-proxy/commit/4b2310b689ffe37d4cab99395d9741e291b76108))
* authenticate the token exchange with workload identity ([#7](https://github.com/keycardai/egress-proxy/issues/7)) ([cad46c5](https://github.com/keycardai/egress-proxy/commit/cad46c5d1aa9c79625c1e670e44d96c6fa3996c8))
* basic authentication placement for git over HTTPS ([#16](https://github.com/keycardai/egress-proxy/issues/16)) ([915134e](https://github.com/keycardai/egress-proxy/commit/915134e476c34b9001df6f42089f46da578c619a))
* complete the sandbox base image ([#17](https://github.com/keycardai/egress-proxy/issues/17)) ([492ff7f](https://github.com/keycardai/egress-proxy/commit/492ff7fd5915b5ab8863d93e6ab4870010564846))
* container images and the settings surface ([#22](https://github.com/keycardai/egress-proxy/issues/22)) ([061e490](https://github.com/keycardai/egress-proxy/commit/061e490fba08e080de8f19b977bc094bd2fc3f6b))
* impersonating token exchange with a client secret ([#6](https://github.com/keycardai/egress-proxy/issues/6)) ([28ddc2c](https://github.com/keycardai/egress-proxy/commit/28ddc2c5c8fe3c3f4f11f065257ceb5b0457bbdf))
* netsetup init container programs the capture rules ([#10](https://github.com/keycardai/egress-proxy/issues/10)) ([2a49aa5](https://github.com/keycardai/egress-proxy/commit/2a49aa529691a7722e2e47f320cb67b7869fb5f6))
* proxy core with ca, configuration, host deny policy ([#3](https://github.com/keycardai/egress-proxy/issues/3)) ([01b5d11](https://github.com/keycardai/egress-proxy/commit/01b5d1193578183e199ef4cd676889eb47b4845a))
* readiness on the admin socket and a probe subcommand ([#21](https://github.com/keycardai/egress-proxy/issues/21)) ([ec4399e](https://github.com/keycardai/egress-proxy/commit/ec4399ec0541b896df7063e69589fba3b1077601))
* support credential injection from a static source ([#4](https://github.com/keycardai/egress-proxy/issues/4)) ([3426820](https://github.com/keycardai/egress-proxy/commit/3426820232a61a733b4888ce97a0e337db142da7))
* transparent frontend for redirected connections ([#9](https://github.com/keycardai/egress-proxy/issues/9)) ([b776044](https://github.com/keycardai/egress-proxy/commit/b776044de1acb2e8a786009409ba10027557cecf))
* wire the capture into the process, with a Docker acceptance matrix ([#11](https://github.com/keycardai/egress-proxy/issues/11)) ([51d7d67](https://github.com/keycardai/egress-proxy/commit/51d7d6748ff4b89f95ef07427cb8733676bb9158))
