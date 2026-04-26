# sipvault-agent Configuration

The agent reads its configuration from an INI-format file. The default location is `/etc/sipvault/agent.conf`. Override with `--config /path/to/agent.conf`.

## Full Configuration Reference

```ini
[server]
# Server address in HOST:PORT format (required)
address = 10.0.0.1:9060

# Customer identifier, must match the server's customer registry (required)
customer_id = acme

# Authentication token, must match the server's customer registry (required)
token = securetoken123

[capture]
# Capture mode: auto, ebpf, or pcap (default: auto)
# auto resolves to "pcap" — operators must set mode = ebpf explicitly to
# opt in. The ebpf backend requires a binary built with `-tags ebpf` and
# CAP_NET_RAW (or root) at runtime.
mode = auto

# Comma-separated SIP ports to monitor (default: 5060)
sip_ports = 5060

# Network interface for packet capture (default: auto-detected from default route)
interface = eth0

# OpenSIPS log file path for pcap mode log tailing (default: empty = disabled)
# In eBPF mode, logs are captured via kprobe on sendmsg instead
log_file = /var/log/opensips.log

# RTP port range for RTCP capture (default: 10000-30000)
# Should match your RTPProxy/RTPEngine port range
rtp_port_min = 10000
rtp_port_max = 30000

[buffer]
# Path to the disk buffer file (default: /var/lib/sipvault/buffer.dat)
path = /var/lib/sipvault/buffer.dat

# Maximum disk buffer size in bytes (default: 104857600 = 100 MB)
# When the TCP connection to the server is lost, data is buffered locally
max_size = 104857600

[logging]
# Log level: debug, info, warn, error (default: info)
level = info
```

## Section: `[server]`

| Key | Required | Default | Description |
|---|---|---|---|
| `address` | **Yes** | — | Receiving server address as `host:port` |
| `customer_id` | **Yes** | — | Customer identifier |
| `token` | **Yes** | — | Authentication token |

## Section: `[capture]`

| Key | Required | Default | Description |
|---|---|---|---|
| `mode` | No | `auto` | Capture mode: `auto`, `ebpf`, or `pcap` |
| `sip_ports` | No | `5060` | Comma-separated list of SIP ports |
| `interface` | No | Auto-detected | Network interface name |
| `log_file` | No | (empty) | OpenSIPS log file for pcap mode |
| `rtp_port_min` | No | `10000` | Minimum RTP port |
| `rtp_port_max` | No | `30000` | Maximum RTP port |

## Section: `[buffer]`

| Key | Required | Default | Description |
|---|---|---|---|
| `path` | No | `/var/lib/sipvault/buffer.dat` | Disk buffer file path |
| `max_size` | No | `104857600` (100 MB) | Maximum buffer size in bytes |

## Section: `[logging]`

| Key | Required | Default | Description |
|---|---|---|---|
| `level` | No | `info` | Log level |

## Capture Mode Comparison

Both backends are implemented and emit the same wire-protocol output. The `auto` selector resolves to `pcap` for upgrade safety; `mode = ebpf` is opt-in.

| Feature | pcap Mode | ebpf Mode (v1 = cBPF socket filter) |
|---|---|---|
| Kernel requirement | Any | Linux 3.x+ (any modern kernel; `SO_ATTACH_FILTER` since 3.0) |
| SIP/RTCP capture | libpcap on SIP/RTP ports | AF_PACKET raw socket + in-kernel cBPF filter |
| Log capture | File tailing (`log_file` config) | File tailing (same as pcap; kprobe path on roadmap) |
| Runtime dependencies | `libpcap0.8` package | None (pure Go static binary) |
| Build | `make build-pcap` (needs `libpcap-dev` + CGO) | `make build-ebpf` (no CGO, no clang) |
| Capabilities | root or `CAP_NET_RAW` | root or `CAP_NET_RAW` |
| Supported OS | CentOS 6+, Debian 7+, Ubuntu 14.04+ | Any modern Linux |

The ebpf backend installs a minimal kernel filter that accepts IPv4 UDP traffic (and IPv4 fragments for reassembly), and performs port-based SIP/RTP/RTCP classification in userspace. This removes libpcap from the runtime dependency chain and produces a smaller, fully-static, CGO-free binary. Future revisions will move classification into the kernel via true eBPF programs (XDP, TC clsact, ringbuf maps) — see the project roadmap.

## Example: pcap Mode on CentOS 6/7

```ini
[server]
address = 10.0.0.1:9060
customer_id = acme
token = securetoken123

[capture]
mode = pcap
sip_ports = 5060
interface = eth0
log_file = /var/log/opensips.log
rtp_port_min = 10000
rtp_port_max = 30000

[buffer]
path = /var/lib/sipvault/buffer.dat
max_size = 104857600

[logging]
level = info
```

## OpenSIPS-Side Requirements

For the agent to capture data correctly, the upstream OpenSIPS / Kamailio / Asterisk / FreeSWITCH installation should:

### Log to a file

OpenSIPS must log to a file (not just syslog) for the agent to capture log data in pcap mode:

```ini
# opensips.cfg
log_facility=LOG_LOCAL0
log_level=3
```

In `/etc/rsyslog.d/opensips.conf`:

```
local0.*    /var/log/opensips.log
```

The `log_file` parameter in the agent config must point to this file.

### Listen on the configured SIP ports

Ensure the SIP proxy listens on the ports declared in `sip_ports`:

```ini
listen=udp:0.0.0.0:5060
listen=tcp:0.0.0.0:5060
```

### RTPProxy / RTPEngine port range

The agent's `rtp_port_min` and `rtp_port_max` must match the RTPProxy or RTPEngine port range:

```
rtpproxy -l 0.0.0.0 -m 10000 -M 30000
```

### Authentication

No changes to OpenSIPS authentication are needed. The agent passively captures packets; it does not inject or modify SIP traffic.

### Split-server RTCP (RTPProxy on a separate machine)

When RTPProxy runs on a machine separate from OpenSIPS, the agent on the SIP server only sees signaling. To get RTCP from the media plane, point RTPProxy's HEP output at the receiving server (no agent needed on the media host):

```
modparam("rtpproxy", "rtpp_flags", "HEP=sipvault-server:9060")
```
