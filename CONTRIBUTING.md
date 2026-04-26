# Contributing to sipvault-agent

Thanks for your interest. This is a small project — the contribution flow stays light.

## Getting started

```bash
git clone https://github.com/sippulse/sipvault.git
cd sipvault
make build
make test
```

To work on the libpcap backend you'll also need `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/CentOS):

```bash
make build-pcap
```

## Before opening a PR

```bash
make test    # go test -race ./...
make lint    # golangci-lint run ./...
go mod tidy  # should produce no diff
```

CI runs the same checks on every push.

## Pull requests

- Keep PRs focused. One change per PR.
- Match the existing style — `gofmt`, no comment-block walls, prefer composition over abstraction layers.
- New behavior needs a test. Bug fixes need a regression test.
- If you change the wire protocol, update [`docs/wire-protocol.md`](docs/wire-protocol.md) in the same PR.
- If you add a new config key, document it in [`docs/configuration.md`](docs/configuration.md).

## Issues

- Bug reports: include kernel version, distro, capture mode, and a minimal reproduction.
- Feature requests: describe the use case before the implementation.

## Code of conduct

Be civil. Disagreements happen — keep them about the code.
