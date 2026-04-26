# SIP VAULT Agent Architecture

## Overview

The sipvault-agent is a single Go binary that runs on customer SIP proxy servers (OpenSIPS, Kamailio, Asterisk, FreeSWITCH). It captures SIP signaling, RTCP quality reports, RTP headers (when RTCP is unavailable), and application logs — then sends them to the sipvault-server via a custom binary wire protocol over TCP.

> **Capture backends.** Two implementations of the `Source` interface ship in this repo: the libpcap-based path (`internal/pcap`) and a kernel BPF socket-filter path (`internal/ebpf`). Both produce the same `CaptureEvent` shape, so everything downstream — Reader, tracker, log filter, RTP/RTCP analysis, wire protocol — is identical. v1 of the eBPF backend uses a cBPF socket filter attached via `SO_ATTACH_FILTER` to an `AF_PACKET` raw socket; subsequent revisions will move toward true eBPF features (XDP fast path, kprobes for log capture, ringbuf maps). The `auto` selector resolves to `pcap` for upgrade-safety reasons; operators must set `capture.mode = ebpf` explicitly to opt in.

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

## Log Slicing by Call-ID

Logs reach the wire only as `DATA_LOG` frames keyed by an active Call-ID. Every line that doesn't belong to a tracked call is dropped at the agent. The slicer is built from three pieces in `internal/`:

| Component | File | Role |
|---|---|---|
| `tracker` | `tracker/tracker.go` | Source of truth for "what calls are active right now." Populated by the SIP path: `Add(callID)` on INVITE, `Remove(callID)` on BYE/CANCEL (with grace period). |
| `logtail` (pcap mode) | `logtail/tailer.go` | Polls the log file every 200 ms, tracks file offset, detects rotation via inode change or truncation, emits each new line as an `EventLog`. |
| `logfilter` | `logfilter/filter.go` | `Match(line)` snapshots `tracker.AllActive()`, runs `bytes.Contains(line, callID)` against the snapshot, returns the first hit. |

### Mechanism

1. Tailer (pcap mode) or the `sendmsg` kprobe (eBPF mode) emits every log line on the `EventLog` channel — no filtering happens at the source.
2. The Reader pulls each event and calls `Filter.Match(ev.Data)`.
3. `Match` takes a Call-ID snapshot (`AllActive()` returns the slice under `RLock`, then iterates lock-free) and runs a substring scan. **First match wins**, early exit. No regex, no SIP-header parsing.
4. Matched lines become `DATA_LOG` frames stamped with `(timestamp, Call-ID, line)`. Unmatched lines drop silently.

### Why substring is enough

OpenSIPS embeds the Call-ID inline in many forms (`Call-ID: abc@host`, `[B2B::abc@host]`, `dlg:abc@host`). A literal `bytes.Contains` catches all of them at O(N) per line where N is the active-call count — small in practice (tens to a few hundred).

### Grace period

`tracker.Remove` doesn't delete immediately; it marks the Call-ID for expiry at `now + grace` (default 30 s). Trailing log lines emitted after BYE — rtpproxy teardown, B2B leg destruction, "freeing dialog" — still match and reach the wire. After the grace window `Cleanup()` drops the Call-ID and any further references stop matching.

### Rotation handling

The Tailer's loop checks both signals on each tick:
- `info.Size() < offset` → file truncated (logrotate `copytruncate`)
- `currentInode != lastInode` → file replaced (logrotate `create`)

On either, the offset resets to 0 and the new inode is recorded. No lines are lost across a rotation as long as the agent sees both old-file remainder and new-file head within one polling cycle.

### Backpressure

The Tailer's emit channel has capacity 256. Under a log burst, a stall in filter+sender pushes back into file I/O (`t.events <- ev` blocks) rather than ballooning memory.

### Edge cases

- **Pre-INVITE noise** — log lines emitted before the INVITE is parsed don't match any active Call-ID and are dropped silently.
- **Multi-Call-ID lines** (B2B / relay) — first match in snapshot order wins, no duplication.
- **Multi-line entries** (stack traces, SDP dumps) — matched per line; second and subsequent lines drop unless they also contain the Call-ID. OpenSIPS log lines are normally single-line, so this is rarely felt.

## RTP Fallback (no-RTCP streams)

When SDP advertises that no RTCP will be sent, the agent estimates voice quality locally from RTP headers. This produces a `DATA_QUALITY` JSON frame on BYE/CANCEL with `source: "rtp"`.

### Activation: only on `a=rtcp:0`

Per RFC 3605 the default is "RTCP exists, on RTP-port + 1." The agent assumes that and only flips on the fallback when SDP explicitly disables RTCP:

| SDP attribute | Effect |
|---|---|
| (none) | `RTCPEnabled = true` (RFC 3605 default) — no fallback |
| `a=rtcp:0` | `RTCPEnabled = false` — **fallback armed** |
| `a=rtcp:<port>` (port > 0) | `RTCPEnabled = true` — no fallback, RTCP captured on declared port |
| `a=rtcp-mux` | `RTCPEnabled = true` — no fallback, RTCP rides the RTP port |

When `RTCPEnabled == false` and `MediaPort > 0`, `handleSIP` calls `tracker.MapMediaPort(port, MediaInfo{...})`. Side effects:

1. The capture filter widens — `tracker.NeedsRTPCapture(port)` now returns true. The pcap source consults that callback per packet, so RTP packets to that port stop being silently dropped and start flowing in as `EventRTP`. Without this gate, RTP is ignored entirely (the agent does **not** capture RTP indiscriminately — only opted-in streams).
2. Direction is anchored by media port. Each call leg has its own port; port-based lookup is enough to attribute the stream to a Call-ID.

### Per-packet processing

`handleRTP` is on the hot path:

```
LookupMediaPort(dstPort) || LookupMediaPort(srcPort) → MediaInfo (Call-ID, codec)
  ↓
Parse first 12 bytes (RTP fixed header) — payload never touched, never copied
  ↓
analyzers[hdr.SSRC] — get-or-create Analyzer with PT-aware clock rate
  ↓
analyzer.Process(hdr, arrivalTime)
```

Properties worth calling out:

- **Header-only.** Only the 12-byte RTP header is parsed. Payload is never read; no audio leaves the host.
- **Lazy analyzer creation.** First packet for a new SSRC creates the Analyzer; subsequent packets just call `Process`. Handles SSRCs that aren't pre-announced in SDP and SSRC changes mid-call (treated as new streams).
- **PT-aware clock rate.** `rtp.ClockRate(PT)` returns 8000 for narrowband audio (PT 0/3/4/7/8/9/15/18), 44100 for L16, 90000 for H.263. Used for jitter unit conversion.
- **Wrap-safe arithmetic.** RTP timestamp deltas use signed `int32` subtraction; sequence-number expected-count uses `uint16`. Both wrap correctly.

### Emission: one frame per call, on BYE/CANCEL

`handleSIP` calls `sendRTPQuality(callID)` **before** `tracker.Remove` so analyzers are still indexed. The flow:

1. Walk `streamMeta` for every SSRC tagged with this Call-ID.
2. Skip analyzers with `PacketsReceived == 0` (no media flowed).
3. Label streams `"uac"` then `"uas"` in iteration order. Streams beyond two are not labeled (rare in audio calls).
4. `BuildMultiStreamReport` aggregates jitter/loss/MOS per direction and the **worst** MOS picks the verdict.
5. JSON-encode, ship as `FrameDataQuality`, then delete the analyzers and stream metadata.

If `BuildMultiStreamReport` returns nil (no streams produced packets), no frame is emitted — the collector won't see a phantom report.

### MOS in fallback mode

`mosFromStats` uses ITU-T G.107 with two intentional simplifications:

- **Delay ≈ 2 × jitter_ms.** RTT is unmeasurable from one-way RTP, so a plausible buffer-induced delay is substituted from observed jitter.
- **Codec impairment fixed at G.711** (Ie = 0, Bpl = 25.1). The observed codec name *is* shipped in `summary.codec`, so the collector can re-derive a codec-accurate MOS from raw jitter and loss using its own codec table. The agent's MOS is a fast estimate; the authoritative MOS calculation lives server-side.

Verdict thresholds (agent-local): `good ≥ 3.6`, `fair 3.1–3.6`, `poor 2.5–3.1`, `bad < 2.5`.

### Distinguishing fallback reports

The `source` field in the JSON is `"rtp"` for agent-derived reports vs. `"rtcp"` for collector-derived reports. RTT is always `0` in fallback mode (present-but-zero keeps the schema stable; collector should treat it as "unknown," not "0 ms"). No 5-second timeseries — just the per-direction summary.

### What fallback does *not* do

- No RTT (one-way RTP can't measure it).
- No codec-specific MOS (delegated to the collector).
- No live timeseries (only the per-call summary on BYE).
- No audio-path inference (OWA / NOA) — that decision lives in the collector with both directions of evidence in hand.

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
