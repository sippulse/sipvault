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
# auto currently resolves to "pcap" on every kernel (eBPF is on the roadmap
# but not implemented; setting mode = ebpf will hard-fail at startup).
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

> **Status:** only `pcap` is implemented today. `eBPF` is on the roadmap. The `auto` selector currently resolves to `pcap` on every kernel; setting `mode = ebpf` explicitly will hard-fail at startup with an error directing you to `pcap`.

| Feature | pcap Mode (✅ implemented) | eBPF Mode (🚧 planned) |
|---|---|---|
| Kernel requirement | Any | >= 4.18 (BTF/CO-RE) |
| SIP/RTCP capture | libpcap on SIP/RTP ports | XDP/tc BPF programs |
| Log capture | File tailing (`log_file` config) | kprobe on `sendmsg` |
| Build | `make build-pcap` (needs `libpcap-dev`) | TBD (no CGO) |
| Capabilities | root or `CAP_NET_RAW` | `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_PTRACE` |
| Supported OS | CentOS 6+, Debian 7+, Ubuntu 14.04+ | Ubuntu 18.04+, Debian 10+, CentOS 8+ |

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
