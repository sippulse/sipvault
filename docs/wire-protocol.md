# SIP VAULT Wire Protocol Specification v1

## Overview

Binary protocol for communication between sipvault-agent and sipvault-server over TCP (port 9060).
All multi-byte integers are big-endian (network byte order).

## Frame Header (12 bytes)

```
Offset  Size  Field            Description
------  ----  -----            -----------
0       2B    Magic            0x5356 ("SV")
2       1B    Version          0x01
3       1B    Frame Type       See Frame Types below
4       4B    Payload Length   Bytes following the header (max 1MB = 1048576)
8       4B    Sequence Number  Monotonically increasing per connection
```

## Frame Types

| Code | Name           | Direction        | Description |
|------|----------------|------------------|-------------|
| 0x01 | HANDSHAKE      | Agent → Server   | Initial auth with customer_id + token |
| 0x02 | HANDSHAKE_ACK  | Server → Agent   | Auth response (success/failure) |
| 0x03 | DATA_SIP       | Agent → Server   | SIP message capture |
| 0x04 | DATA_RTCP      | Agent → Server   | RTCP packet capture |
| 0x05 | DATA_LOG       | Agent → Server   | OpenSIPS log line |
| 0x06 | HEARTBEAT      | Agent → Server   | Keepalive |
| 0x07 | HEARTBEAT_ACK  | Server → Agent   | Keepalive response |

## Payload Formats

### HANDSHAKE (0x01)

```
Offset  Size   Field
------  ----   -----
0       2B     Customer ID length
2       var    Customer ID (UTF-8)
+0      2B     Token length
+2      var    Token (UTF-8)
+0      2B     Agent Version length
+2      var    Agent Version (UTF-8)
```

### HANDSHAKE_ACK (0x02)

```
Offset  Size   Field
------  ----   -----
0       1B     Status (0x00 = success, 0x01 = auth_failed, 0x02 = version_mismatch)
1       2B     Message length
3       var    Message (UTF-8)
```

### DATA_SIP (0x03)

```
Offset  Size   Field
------  ----   -----
0       8B     Timestamp (nanoseconds since Unix epoch)
8       2B     Call-ID length
10      var    Call-ID (UTF-8, redundant with SIP body for fast routing)
+0      1B     Direction (0x00 = inbound, 0x01 = outbound)
+1      4B     Source IP (IPv4) or 16B (IPv6, indicated by high bit of direction)
+5/17   2B     Source Port
+7/19   4/16B  Destination IP
+11/35  2B     Destination Port
+13/37  var    Raw SIP message (remainder of payload)
```

### DATA_RTCP (0x04)

```
Offset  Size   Field
------  ----   -----
0       8B     Timestamp (nanoseconds since Unix epoch)
8       2B     Call-ID length
10      var    Call-ID (UTF-8)
+0      4B     SSRC
+4      var    Raw RTCP packet (remainder of payload)
```

### DATA_LOG (0x05)

```
Offset  Size   Field
------  ----   -----
0       8B     Timestamp (nanoseconds since Unix epoch)
8       2B     Call-ID length
10      var    Call-ID (UTF-8)
+0      var    Raw log line (UTF-8, remainder of payload)
```

### HEARTBEAT (0x06)

```
Offset  Size   Field
------  ----   -----
0       8B     Timestamp (nanoseconds since Unix epoch)
```

### HEARTBEAT_ACK (0x07)

```
Offset  Size   Field
------  ----   -----
0       8B     Timestamp (echo of received HEARTBEAT timestamp)
```

## Connection Lifecycle

1. Agent connects via TCP (optionally TLS) to server port 9060
2. Agent sends HANDSHAKE frame
3. Server validates credentials, responds with HANDSHAKE_ACK
4. On success, agent begins sending DATA_* frames and periodic HEARTBEAT (every 30s)
5. Server responds to each HEARTBEAT with HEARTBEAT_ACK
6. If no HEARTBEAT_ACK received within 90s, agent reconnects with exponential backoff

## Disk Buffer

When TCP connection is unavailable, agent appends frames to `/var/lib/sipvault/buffer.dat`.
Format: frames written sequentially with same 12-byte header + payload format.
Max size: 100MB. Oldest frames discarded when limit exceeded (ring buffer).
On reconnect, buffered frames are replayed in order before live capture resumes.

## Constants

```
MaxPayloadSize  = 1048576  // 1MB
MaxCallIDLength = 512
HeaderSize      = 12
MagicBytes      = 0x5356
ProtocolVersion = 0x01
```
