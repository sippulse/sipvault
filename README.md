# sipvault-agent

> [!WARNING]
> **Project status: alpha / experimental.** This code is published for the OpenSIPS Summit and is under active development. APIs, the wire protocol, the configuration schema, and the on-disk buffer format may change without notice. There are no stability or backwards-compatibility guarantees, no published security advisories, and no production support. Use at your own risk, do not run on critical infrastructure, and pin to a specific commit if you do try it. Bug reports and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

A lightweight Go agent that runs on a SIP proxy host (OpenSIPS, Kamailio, Asterisk, FreeSWITCH) and ships per-call evidence — SIP signaling, raw RTCP, an RTP-derived quality report, and Call-ID-sliced application logs — to a remote collector over a custom binary wire protocol.

The agent is the open-source side of the SIP VAULT product line. It captures only INVITE dialogs — REGISTER/OPTIONS/SUBSCRIBE/NOTIFY are filtered out. Two capture backends are available:

- **`pcap`** (default) — libpcap-based, works on any Linux back to CentOS 6 / Ubuntu 14.04.
- **`ebpf`** (opt-in) — kernel BPF socket filter on AF_PACKET, no libpcap, no CGO. v1 uses cBPF; XDP / kprobe-based log capture / ringbuf metadata are on the [roadmap](#roadmap).

## What the agent ships per call

| Artifact | Wire frame | Source | When |
|---|---|---|---|
| **SIP messages** | `DATA_SIP` | libpcap / eBPF on `sip_ports` | Live, frame-batched |
| **RTCP packets** | `DATA_RTCP` | libpcap / eBPF on RTP port range | Live, forwarded raw |
| **Log lines (Call-ID-sliced)** | `DATA_LOG` | Log file tail (pcap mode) or `sendmsg` kprobe (eBPF mode) | Live, only lines matching an active Call-ID |
| **RTP-derived quality report** | `DATA_QUALITY` | Per-SSRC analyzer (sequence gaps + RFC 3550 jitter) → MOS/jitter/loss per direction (`uac` / `uas`) as JSON | On BYE/CANCEL, once per call |

The quality report is generated locally from RTP headers, so you get a MOS estimate even when RTCP is missing or one-sided. When RTCP is present it is forwarded raw alongside the agent-computed report; the collector decides which to use.

## Features

- INVITE-dialog-scoped capture, with strict Call-ID-based slicing for logs (no log lines are shipped that don't belong to a tracked call)
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

| Mode | Status | Kernel | Log capture | SIP/RTCP capture | Build |
|------|--------|--------|-------------|------------------|-------|
| **pcap** | ✅ Implemented | Any | File tailing (`log_file` config) | libpcap on SIP/RTP ports | `make build-pcap` (needs `libpcap-dev` + CGO) |
| **ebpf** | ✅ Implemented (v1: cBPF socket filter) | Linux 3.x+ (any modern) | File tailing (same as pcap) | AF_PACKET raw socket + in-kernel BPF filter, no libpcap | `make build-ebpf` (pure Go, no CGO, no clang) |
| **auto** | ✅ Implemented | — | — | Resolves to `pcap`. Operators must set `mode = ebpf` explicitly to opt in. | — |

> v1 of the eBPF backend uses a classic-BPF (cBPF) socket filter — the same instruction set libpcap generates internally — attached via `SO_ATTACH_FILTER` to an `AF_PACKET` raw socket. This removes libpcap from the runtime dependency chain and produces a smaller, fully-static, CGO-free binary. True eBPF features (XDP, kprobes for kernel-side log capture, ringbuf-based metadata) are on the [Roadmap](#roadmap).
>
> Permissions: the eBPF backend needs `CAP_NET_RAW` (or root). Running under systemd, set `AmbientCapabilities=CAP_NET_RAW` in the unit file.

## Build Matrix

| Target | Output | Notes |
|--------|--------|-------|
| `make build-pcap` | `bin/sipvault-agent-pcap` | libpcap-based capture, requires `libpcap-dev`, CGO enabled |
| `make build-pcap-release` | `bin/sipvault-agent-pcap-linux-amd64` | Cross-compiled, CGO + libpcap |
| `make build-ebpf` | `bin/sipvault-agent-ebpf` | eBPF (cBPF socket filter) backend. Pure Go, no CGO, no clang |
| `make build-ebpf-release` | `bin/sipvault-agent-ebpf-linux-{amd64,arm64}` | Cross-compiled eBPF binaries, stripped |
| `make build` | `bin/sipvault-agent` | Default: neither backend compiled in. `mode = pcap` and `mode = ebpf` both fail with a clear error. Useful for compile-only smoke tests |
| `make build-release` | `bin/sipvault-agent-linux-{amd64,arm64}` | Same caveat as `make build` |
| `make test` | — | `go test -race ./...` |
| `make test-ebpf` | — | `go test -tags ebpf ./...` |
| `make lint` | — | `golangci-lint run ./...` |

## Roadmap

- **True-eBPF feature expansion.** v1 ships a cBPF socket filter; future revisions will move to eBPF programs (XDP for fast-path ingress, TC clsact for symmetric ingress/egress, kprobes for kernel-side log capture, ringbuf maps for richer metadata). The userspace Source interface is independent of the in-kernel filter strategy, so this can land iteratively.
- **Live timeseries in the RTP-fallback quality report.** Today only a per-call summary is emitted; the goal is 5-second buckets matching the RTCP-derived report shape.
- **Codec-aware MOS in the agent.** Currently fixed at G.711 impairment; the collector re-derives codec-specific MOS from raw jitter/loss.

## Documentation

- [Architecture](docs/architecture.md) — package map, data flow, batching, disk buffer, reconnect logic
- [Configuration](docs/configuration.md) — every key in `agent.conf`, plus OpenSIPS-side requirements
- [Wire protocol](docs/wire-protocol.md) — frame header, payload layouts, connection lifecycle, ring buffer format

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
