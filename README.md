# sipvault-agent

> [!WARNING]
> **Project status: alpha / experimental.** This code is published for the OpenSIPS Summit and is under active development. APIs, the wire protocol, the configuration schema, and the on-disk buffer format may change without notice. There are no stability or backwards-compatibility guarantees, no published security advisories, and no production support. Use at your own risk, do not run on critical infrastructure, and pin to a specific commit if you do try it. Bug reports and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

A lightweight Go agent that runs on a SIP proxy host (OpenSIPS, Kamailio, Asterisk, FreeSWITCH) and ships per-call SIP signaling, RTCP quality reports, RTP-derived metrics, and application logs to a remote collector over a custom binary wire protocol.

The agent is the open-source side of the SIP VAULT product line. It captures only INVITE dialogs — REGISTER/OPTIONS/SUBSCRIBE/NOTIFY are filtered out. Two capture backends are supported: **eBPF** (XDP/tc + kprobe, kernel ≥ 4.18) and **libpcap** (any Linux back to CentOS 6 / Ubuntu 14.04). The mode is auto-selected at startup based on kernel version, or forced via config.

## Features

- INVITE-dialog-scoped capture: SIP, RTCP, RTP-derived stats (jitter / loss per SSRC), and a Call-ID-filtered log tail
- Single static Go binary; eBPF mode has zero runtime dependencies (no libpcap, no CGO)
- 100 MB on-disk ring buffer survives upstream outages and replays on reconnect
- Frame-batched TCP wire protocol (64 frames or 5 ms flush) with HEARTBEAT keepalive and exponential-backoff reconnect
- Optional HEP v3 emission for split-server topologies where the media host is separate from signaling
- INI-format config; auto-detects network interface from the default route

## Quick Start

```bash
# Build the eBPF binary (no system dependencies)
make build

# Or build the libpcap variant (needs libpcap-dev)
make build-pcap

# Drop a config in place
sudo install -d /etc/sipvault /var/lib/sipvault
sudo cp install/agent.conf.example /etc/sipvault/agent.conf
sudo $EDITOR /etc/sipvault/agent.conf   # set [server] address, customer_id, token

# Run
sudo bin/sipvault-agent --config /etc/sipvault/agent.conf
```

For automated installation with systemd / SysV-init wiring, see [`install/install.sh`](install/install.sh).

## Capture Modes

| Mode | Kernel | Log capture | SIP/RTCP capture | Build |
|------|--------|-------------|------------------|-------|
| **eBPF** | ≥ 4.18 | kprobe on `sendmsg` | XDP/tc BPF programs | `make build` (no CGO) |
| **pcap** | Any | File tailing (`log_file` config) | libpcap on SIP/RTP ports | `make build-pcap` (needs `libpcap-dev`) |
| **auto** | — | Auto-selects based on kernel version | — | — |

## Build Matrix

| Target | Output | Notes |
|--------|--------|-------|
| `make build` | `bin/sipvault-agent` | Native, eBPF-capable, CGO disabled |
| `make build-pcap` | `bin/sipvault-agent-pcap` | Requires `libpcap-dev`, CGO enabled |
| `make build-release` | `bin/sipvault-agent-linux-{amd64,arm64}` | Cross-compiled, stripped |
| `make build-pcap-release` | `bin/sipvault-agent-pcap-linux-amd64` | Cross-compiled, CGO + libpcap |
| `make test` | — | `go test -race ./...` |
| `make lint` | — | `golangci-lint run ./...` |

## Documentation

- [Architecture](docs/architecture.md) — package map, data flow, batching, disk buffer, reconnect logic
- [Configuration](docs/configuration.md) — every key in `agent.conf`, plus OpenSIPS-side requirements
- [Wire protocol](docs/wire-protocol.md) — frame header, payload layouts, connection lifecycle, ring buffer format

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
