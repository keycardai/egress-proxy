# Contributing to egress-proxy

Thank you for your interest in the Keycard egress proxy!

## Contribution Policy

`egress-proxy` is open source under the [Apache License 2.0](LICENSE).

**We do not accept public contributions at this time.**

The Keycard team maintains this project and handles all development
internally to keep it consistent with our platform and roadmap.

## Reporting Issues

If you encounter a bug or have a feature request, please open an issue on our
[GitHub Issues](https://github.com/keycardai/egress-proxy/issues) page. When
reporting a bug, please include:

- The release version, or the image digest you run
- The config document, with every secret removed
- The audit records for the failing request, the JSON lines the proxy writes
  to stdout
- Expected behavior vs. actual behavior
- Steps to reproduce

**Do not report security vulnerabilities in a GitHub issue.** Follow
[SECURITY.md](SECURITY.md) instead.

## Getting Support

For questions, support, or general inquiries:

- Read the documentation under [`docs/`](docs/)
- Check existing [GitHub Issues](https://github.com/keycardai/egress-proxy/issues)
- Email **support@keycard.ai**, or use [keycard.ai/contact](https://keycard.ai/contact/)

## Development

[README.md](README.md#build) describes how to build and run the proxy.
Agents working in this repository read [AGENTS.md](AGENTS.md) first. It
holds the working agreements, the tests and the gates every change passes.

## License

This project is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for third-party attributions.
