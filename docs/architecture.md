# SIP VAULT Agent Architecture

## Overview

The sipvault-agent is a single Go binary that runs on customer SIP proxy servers (OpenSIPS, Kamailio, Asterisk, FreeSWITCH). It captures SIP signaling, RTCP quality reports, RTP headers (when RTCP is unavailable), and application logs — then sends them to the sipvault-server via a custom binary wire protocol over TCP.

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Customer SIP Server                       │
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                │
│  │  libpcap │   │  libpcap │   │ Log File │                │
│  │ SIP pkts │   │ RTP/RTCP │   │  Tailer  │                │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                │
│       │              │              │                        │
│       ▼              ▼              ▼                        │
│  ┌─────────────────────────────────────┐                    │
│  │          MultiSource                 │                    │
│  │    (merges all event channels)       │                    │
│  └──────────────┬──────────────────────┘                    │
│                 │                                            │
│                 ▼                                            │
│  ┌─────────────────────────────────────┐                    │
│  │            Reader                    │                    │
│  │  ┌──────┬───────┬───────┬────────┐  │                    │
│  │  │ SIP  │ RTCP  │  Log  │  RTP   │  │                    │
│  │  │handle│handle │handle │handle  │  │                    │
│  │  └──┬───┴───┬───┴───┬───┴───┬────┘  │                    │
│  │     │       │       │       │        │                    │
│  │     ▼       ▼       ▼       ▼        │                    │
│  │  Tracker  Tracker  Filter  Analyzer  │                    │
│  └──────────────┬──────────────────────┘                    │
│                 │                                            │
│                 ▼                                            │
│  ┌─────────────────────────────────────┐                    │
│  │          BatchSender                 │                    │
│  │   (64 frames or 5ms flush)          │                    │
│  └──────────────┬──────────────────────┘                    │
│                 │                                            │
│                 ▼                                            │
│  ┌─────────────────────────────────────┐                    │
│  │            Sender                    │                    │
│  │  ┌──────────┐  ┌────────────────┐   │                    │
│  │  │TCP:9060  │  │  DiskBuffer    │   │                    │
│  │  │(online)  │  │  (offline)     │   │                    │
│  │  └──────────┘  │  100MB ring    │   │                    │
│  │                └────────────────┘   │                    │
│  └──────────────┬──────────────────────┘                    │
│                 │                                            │
└─────────────────┼────────────────────────────────────────────┘
                  │ TCP :9060
                  ▼
          sipvault-server
```

## Capture Modes

### pcap mode (production)

Uses libpcap via gopacket. Requires `libpcap` installed and root or `CAP_NET_RAW`.

```
Build: go build -tags pcap ./cmd/sipvault-agent
```

| Feature | Details |
|---------|---------|
| Snap length | 65535 bytes |
| Promiscuous | Yes |
| Read timeout | 100ms (non-blocking) |
| IP defragmentation | Yes (gopacket `ip4defrag`) |
| BPF filter | Dynamic based on SIP ports + RTP port range |

**BPF filter example:**
```
udp and (port 5060 or portrange 35000-65000)
```

**Packet classification:**

```
Is src or dst port in sipPorts?
  → Yes: EventSIP
  → No: Does NeedsRTPCapture(port) return true?
      → Yes: EventRTP  (stream without RTCP)
      → No:  EventRTCP
```

### eBPF mode (planned)

Not yet implemented. Will use XDP/tc BPF programs for kernel-space capture with perf event arrays. Requires kernel ≥ 4.18.

### Log file tailing

Runs alongside pcap. Polls the OpenSIPS/Kamailio log file every 200ms.

- Starts from end of file (no historical replay)
- Detects log rotation via inode change or file truncation
- Emits `EventLog` for each new line

## Core Components

### Tracker

Central registry mapping Call-IDs to media streams. Thread-safe with `sync.RWMutex`.

```
calls    map[string]time.Time      Call-ID → last seen
removed  map[string]time.Time      Call-ID → grace expiry
ssrcMap  map[uint32]string         SSRC → Call-ID
mediaMap map[int]*MediaInfo        RTP port → MediaInfo
```

**MediaInfo** holds per-stream metadata:

```go
type MediaInfo struct {
    CallID      string
    SSRC        uint32
    Port        int        // RTP port from SDP m= line
    ClockRate   int        // Hz (8000 for G.711/G.729)
    Codec       string     // "PCMU", "G729", etc.
    RTCPEnabled bool       // false → activate RTP analysis
}
```

**Key operations:**

| Method | Trigger | Effect |
|--------|---------|--------|
| `Add(callID)` | INVITE captured | Register active call |
| `Remove(callID)` | BYE/CANCEL captured | Start 30s grace period |
| `MapSSRC(ssrc, callID)` | SDP with `a=ssrc:` | Link SSRC for RTCP correlation |
| `MapMediaPort(port, info)` | SDP with `a=rtcp:0` | Enable RTP capture on this port |
| `NeedsRTPCapture(port)` | pcap classifier | Returns true if port needs RTP analysis |
| `LookupSSRC(ssrc)` | RTCP packet arrives | Find Call-ID for this SSRC |
| `LookupMediaPort(port)` | RTP packet arrives | Find Call-ID + codec for analysis |
| `Cleanup()` | Every 30s | Remove expired calls + SSRCs + ports |

### Reader

Dispatches captured events through four handlers:

#### handleSIP

```
Parse SIP message (method, Call-ID, From, To, CSeq)
  ↓
INVITE? → tracker.Add(callID)
BYE/CANCEL? → sendRTPQuality(callID), tracker.Remove(callID)
  ↓
Has SDP body?
  → Parse SDP: port, codecs, SSRC, RTCPEnabled
  → SSRC found? → tracker.MapSSRC(ssrc, callID)
  → RTCP disabled? → tracker.MapMediaPort(port, mediaInfo)
  ↓
Build DATA_SIP frame with src/dst IP:port
Send via BatchSender
```

#### handleRTCP

```
Parse RTCP packet → extract sender SSRC
  ↓
tracker.LookupSSRC(ssrc) → callID
  ↓
Build DATA_RTCP frame
Send via BatchSender
```

#### handleLog

```
logfilter.Match(line) → scan for any active Call-ID
  ↓
Match found? → Build DATA_LOG frame, send
No match? → Drop silently
```

#### handleRTP

Activated only for streams where SDP indicates no RTCP (`a=rtcp:0`).

```
tracker.LookupMediaPort(srcPort or dstPort) → MediaInfo
  ↓
Parse RTP header: SSRC, sequence number, timestamp, PT
  ↓
Get/create Analyzer for this SSRC
  ↓
analyzer.Process(header, receiveTime)
  → Track sequence gaps (packet loss)
  → Calculate interarrival jitter (RFC 3550)
  → Count packets received
```

On BYE/CANCEL, `sendRTPQuality()` collects all analyzers for the call, builds a quality report with MOS/jitter/loss per direction, and sends it as a `DATA_QUALITY` frame.

### RTP Analyzer

Per-SSRC quality estimator using only RTP headers (no RTCP needed).

**Jitter calculation (RFC 3550):**

```
D(i,j) = (Rj - Ri) - (Sj - Si)
  R = wall-clock arrival time (converted to RTP timestamp units)
  S = RTP timestamp from packet

J(i) = J(i-1) + (|D| - J(i-1)) / 16
```

**Loss calculation:**

```
expected = highest_seq - first_seq + 1
lost = expected - packets_received
loss_percent = lost / expected * 100
```

**Quality report output:**

```json
{
  "call_id": "...",
  "verdict": "good",
  "audio_status": "normal",
  "summary": { "codec": "PCMU", "sample_count": 2 },
  "directions": {
    "uac": { "mos": {...}, "jitter": {...}, "loss": {...} },
    "uas": { "mos": {...}, "jitter": {...}, "loss": {...} }
  }
}
```

### SDP Parser

Extracts media information from SIP message bodies.

**Parsing strategy:**

1. Two-pass: first collect `a=rtpmap:` mappings, then process `m=` and `a=` lines
2. Codec from first PT in `m=audio` line (static PT map for 0/3/4/8/9/18)
3. RTCP detection:
   - Default: `RTCPEnabled = true`
   - `a=rtcp:0` → `RTCPEnabled = false` (triggers RTP analysis)
   - `a=rtcp-mux` → `RTCPEnabled = true`
   - `a=rtcp:<port>` → explicit RTCP port

**Static payload type map:**

| PT | Codec |
|----|-------|
| 0 | PCMU |
| 3 | GSM |
| 4 | G723 |
| 8 | PCMA |
| 9 | G722 |
| 18 | G729 |

## Wire Protocol

12-byte frame header, big-endian:

```
┌──────┬─────────┬───────────┬────────────────┬─────────────────┐
│Magic │ Version │ Frame Type│ Payload Length │ Sequence Number │
│0x5356│  0x01   │  1 byte   │   4 bytes      │    4 bytes      │
│ 2B   │  1B     │           │                │                 │
└──────┴─────────┴───────────┴────────────────┴─────────────────┘
```

**Frame types:**

| Type | Code | Direction | Purpose |
|------|------|-----------|---------|
| HANDSHAKE | 0x01 | Agent → Server | Auth with customer_id + token |
| HANDSHAKE_ACK | 0x02 | Server → Agent | Auth response (0x00=OK) |
| DATA_SIP | 0x03 | Agent → Server | SIP message with src/dst IP:port |
| DATA_RTCP | 0x04 | Agent → Server | Raw RTCP packet |
| DATA_LOG | 0x05 | Agent → Server | Log line with Call-ID |
| HEARTBEAT | 0x06 | Agent → Server | Keep-alive (every 30s) |
| HEARTBEAT_ACK | 0x07 | Server → Agent | Keep-alive response |
| DATA_QUALITY | 0x08 | Agent → Server | RTP-derived quality report (JSON) |

**DATA_SIP payload:**

```
timestamp (8B) + callID_len (2B) + callID + direction (1B)
+ srcIP (4B) + srcPort (2B) + dstIP (4B) + dstPort (2B) + rawSIP
```

## Batch Sender

Reduces TCP syscalls by coalescing frames before writing.

```
Frame → channel (256 buffer, non-blocking)
           ↓
     Background goroutine
           ↓
     Accumulate in bytes.Buffer
           ↓
     ┌─────┴──────┐
     ↓            ↓
  64 frames    5ms timer
     ↓            ↓
     └─── Flush ──┘
           ↓
      Sender.Write()
```

At 250 CPS with ~10 frames per call, this reduces ~2500 writes/sec to ~400 batched writes/sec.

## Disk Buffer

Append-only file at `/var/lib/sipvault/buffer.dat` for offline resilience.

```
┌────────┬────────┬────────┬────────┐
│len(4B) │ frame  │len(4B) │ frame  │ ...
│        │ bytes  │        │ bytes  │
└────────┴────────┴────────┴────────┘
```

- Max size: 100 MB (configurable)
- When full: truncate and start fresh (oldest data lost)
- On reconnect: replay all buffered frames, re-sequence, then clear

## Reconnection

Exponential backoff: 1s → 2s → 4s → 8s → 16s → max 30s

```
Connect() → HANDSHAKE → wait HANDSHAKE_ACK
  ↓
Auth OK? → replayBuffer() → clear buffer → resume live capture
Auth fail? → backoff → retry
```

## Configuration

INI format at `/etc/sipvault/agent.conf`:

```ini
[server]
address = collector.example.com:9060
customer_id = acme
token = secret123

[capture]
mode = pcap              # auto | ebpf | pcap
sip_ports = 5060
interface = eth0
log_file = /var/log/opensips.log
rtp_port_min = 35000
rtp_port_max = 65000

[buffer]
path = /var/lib/sipvault/buffer.dat
max_size = 104857600     # 100 MB

[logging]
level = info
```

## Package Map

```
agent/
├── cmd/sipvault-agent/main.go    Entry point, wiring
├── internal/
│   ├── capture/
│   │   ├── reader.go             Event dispatcher (SIP/RTCP/RTP/Log handlers)
│   │   ├── multi.go              MultiSource fan-in
│   │   └── detect.go             Auto-detect eBPF vs pcap
│   ├── pcap/
│   │   ├── capture.go            libpcap source (build tag: pcap)
│   │   ├── capture_stub.go       Stub when pcap not available
│   │   └── classify.go           Packet classification + BPF filter
│   ├── sip/
│   │   ├── parser.go             SIP message parser
│   │   └── sdp.go                SDP parser (ports, codecs, SSRC, RTCP flag)
│   ├── rtcp/
│   │   ├── parser.go             RTCP SR/RR binary decoder
│   │   └── types.go              RTCP packet structures
│   ├── rtp/
│   │   ├── parser.go             RTP header parser
│   │   ├── analyzer.go           Per-SSRC jitter/loss calculator
│   │   └── quality.go            Quality report builder from RTP stats
│   ├── tracker/
│   │   └── tracker.go            Call-ID ↔ SSRC ↔ port registry
│   ├── logfilter/
│   │   └── filter.go             Call-ID substring matcher for logs
│   ├── logtail/
│   │   └── tailer.go             Log file poller (200ms, rotation aware)
│   ├── mux/
│   │   ├── protocol.go           Wire protocol encoder/decoder
│   │   ├── sender.go             TCP sender with reconnect
│   │   └── batch.go              Frame batching (64 frames / 5ms)
│   ├── buffer/
│   │   └── disk.go               100MB disk ring buffer
│   └── config/
│       └── config.go             INI config parser
└── testdata/                     Sample SIP messages for tests
```
