package mux

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

func TestEncodeFrame_Header(t *testing.T) {
	f := &Frame{
		Type:    FrameHandshake,
		Seq:     1,
		Payload: []byte("hello"),
	}

	data, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != HeaderSize+5 {
		t.Fatalf("expected %d bytes, got %d", HeaderSize+5, len(data))
	}

	// Check magic
	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != Magic {
		t.Fatalf("expected magic 0x%04X, got 0x%04X", Magic, magic)
	}

	// Check version
	if data[2] != Version {
		t.Fatalf("expected version 0x%02X, got 0x%02X", Version, data[2])
	}

	// Check type
	if data[3] != FrameHandshake {
		t.Fatalf("expected type 0x%02X, got 0x%02X", FrameHandshake, data[3])
	}

	// Check payload length
	payLen := binary.BigEndian.Uint32(data[4:8])
	if payLen != 5 {
		t.Fatalf("expected payload length 5, got %d", payLen)
	}

	// Check sequence number
	seq := binary.BigEndian.Uint32(data[8:12])
	if seq != 1 {
		t.Fatalf("expected seq 1, got %d", seq)
	}

	// Check payload
	if !bytes.Equal(data[HeaderSize:], []byte("hello")) {
		t.Fatalf("payload mismatch")
	}
}

func TestGoldenBytes_Heartbeat(t *testing.T) {
	ts := int64(1700000000000000000)
	payload := BuildHeartbeat(ts)

	f := &Frame{
		Type:    FrameHeartbeat,
		Seq:     42,
		Payload: payload,
	}

	data, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}

	// Build expected bytes manually
	expected := make([]byte, HeaderSize+8)
	binary.BigEndian.PutUint16(expected[0:2], Magic)
	expected[2] = Version
	expected[3] = FrameHeartbeat
	binary.BigEndian.PutUint32(expected[4:8], 8)  // payload len
	binary.BigEndian.PutUint32(expected[8:12], 42) // seq
	binary.BigEndian.PutUint64(expected[12:20], uint64(ts))

	if !bytes.Equal(data, expected) {
		t.Fatalf("golden bytes mismatch:\n  got:    %x\n  expect: %x", data, expected)
	}
}

func TestGoldenBytes_Handshake(t *testing.T) {
	payload := BuildHandshake("cust1", "tok123", "v0.1.0")

	// Manually construct expected payload
	var expected bytes.Buffer
	// Customer ID
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, 5) // len("cust1")
	expected.Write(b)
	expected.WriteString("cust1")
	// Token
	binary.BigEndian.PutUint16(b, 6) // len("tok123")
	expected.Write(b)
	expected.WriteString("tok123")
	// Version
	binary.BigEndian.PutUint16(b, 6) // len("v0.1.0")
	expected.Write(b)
	expected.WriteString("v0.1.0")

	if !bytes.Equal(payload, expected.Bytes()) {
		t.Fatalf("handshake payload mismatch:\n  got:    %x\n  expect: %x", payload, expected.Bytes())
	}
}

func TestRoundtrip_AllFrameTypes(t *testing.T) {
	frames := []*Frame{
		{Type: FrameHandshake, Seq: 1, Payload: BuildHandshake("cust", "tok", "v1")},
		{Type: FrameDataSIP, Seq: 2, Payload: BuildDataSIP(
			1000, "call-1", 0x00,
			net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2),
			5060, 5060, []byte("INVITE sip:user@host SIP/2.0\r\n"),
		)},
		{Type: FrameDataRTCP, Seq: 3, Payload: BuildDataRTCP(2000, "call-1", 12345, []byte{0x80, 0xc8})},
		{Type: FrameDataLog, Seq: 4, Payload: BuildDataLog(3000, "call-1", []byte("log line"))},
		{Type: FrameHeartbeat, Seq: 5, Payload: BuildHeartbeat(4000)},
		{Type: FrameHeartbeatACK, Seq: 6, Payload: BuildHeartbeat(4000)},
	}

	var buf bytes.Buffer
	for _, f := range frames {
		data, err := EncodeFrame(f)
		if err != nil {
			t.Fatalf("encode frame type 0x%02x: %v", f.Type, err)
		}
		buf.Write(data)
	}

	r := bytes.NewReader(buf.Bytes())
	for i, orig := range frames {
		decoded, err := DecodeFrame(r)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}

		if decoded.Type != orig.Type {
			t.Errorf("frame %d: type mismatch: got 0x%02x, want 0x%02x", i, decoded.Type, orig.Type)
		}
		if decoded.Seq != orig.Seq {
			t.Errorf("frame %d: seq mismatch: got %d, want %d", i, decoded.Seq, orig.Seq)
		}
		if !bytes.Equal(decoded.Payload, orig.Payload) {
			t.Errorf("frame %d: payload mismatch", i)
		}
	}
}

func TestEncodeFrame_EmptyPayload(t *testing.T) {
	f := &Frame{
		Type:    FrameHeartbeatACK,
		Seq:     0,
		Payload: nil,
	}

	data, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != HeaderSize {
		t.Fatalf("expected %d bytes for empty payload frame, got %d", HeaderSize, len(data))
	}

	// Decode it back
	decoded, err := DecodeFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(decoded.Payload))
	}
}

func TestEncodeFrame_MaxPayload(t *testing.T) {
	f := &Frame{
		Type:    FrameDataSIP,
		Seq:     1,
		Payload: make([]byte, MaxPayloadSize),
	}

	_, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("max payload should succeed: %v", err)
	}

	// One byte over the limit
	f.Payload = make([]byte, MaxPayloadSize+1)
	_, err = EncodeFrame(f)
	if err != ErrPayloadTooBig {
		t.Fatalf("expected ErrPayloadTooBig, got %v", err)
	}
}

func TestDecodeFrame_TruncatedHeader(t *testing.T) {
	_, err := DecodeFrame(bytes.NewReader([]byte{0x53, 0x56, 0x01}))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestDecodeFrame_TruncatedPayload(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], Magic)
	hdr[2] = Version
	hdr[3] = FrameHeartbeat
	binary.BigEndian.PutUint32(hdr[4:8], 100) // claim 100 bytes
	binary.BigEndian.PutUint32(hdr[8:12], 1)

	// Only provide 5 bytes of payload instead of 100
	data := append(hdr, []byte("short")...)
	_, err := DecodeFrame(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestDecodeFrame_BadMagic(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 0xFFFF)
	hdr[2] = Version
	hdr[3] = FrameHeartbeat
	binary.BigEndian.PutUint32(hdr[4:8], 0)
	binary.BigEndian.PutUint32(hdr[8:12], 0)

	_, err := DecodeFrame(bytes.NewReader(hdr))
	if err != ErrBadMagic {
		t.Fatalf("expected ErrBadMagic, got %v", err)
	}
}

func TestDecodeFrame_BadVersion(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], Magic)
	hdr[2] = 0xFF // bad version
	hdr[3] = FrameHeartbeat
	binary.BigEndian.PutUint32(hdr[4:8], 0)
	binary.BigEndian.PutUint32(hdr[8:12], 0)

	_, err := DecodeFrame(bytes.NewReader(hdr))
	if err != ErrBadVersion {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestDecodeFrame_PayloadTooBig(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], Magic)
	hdr[2] = Version
	hdr[3] = FrameDataSIP
	binary.BigEndian.PutUint32(hdr[4:8], MaxPayloadSize+1)
	binary.BigEndian.PutUint32(hdr[8:12], 0)

	_, err := DecodeFrame(bytes.NewReader(hdr))
	if err != ErrPayloadTooBig {
		t.Fatalf("expected ErrPayloadTooBig, got %v", err)
	}
}

func TestDecodeFrame_EOF(t *testing.T) {
	_, err := DecodeFrame(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected error for empty reader")
	}
}

func TestBuildDataSIP_Layout(t *testing.T) {
	ts := int64(1234567890)
	callID := "abc@host"
	dir := byte(0x01)
	srcIP := net.IPv4(192, 168, 1, 1)
	dstIP := net.IPv4(10, 0, 0, 1)
	srcPort := uint16(5060)
	dstPort := uint16(5080)
	rawSIP := []byte("INVITE sip:u@h SIP/2.0\r\n")

	payload := BuildDataSIP(ts, callID, dir, srcIP, dstIP, srcPort, dstPort, rawSIP)

	off := 0
	gotTS := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8
	if gotTS != ts {
		t.Fatalf("ts: got %d, want %d", gotTS, ts)
	}

	cidLen := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	gotCID := string(payload[off : off+int(cidLen)])
	off += int(cidLen)
	if gotCID != callID {
		t.Fatalf("callID: got %q, want %q", gotCID, callID)
	}

	if payload[off] != dir {
		t.Fatalf("dir: got 0x%02x, want 0x%02x", payload[off], dir)
	}
	off++

	gotSrcIP := net.IP(payload[off : off+4])
	off += 4
	if !gotSrcIP.Equal(srcIP.To4()) {
		t.Fatalf("srcIP: got %s, want %s", gotSrcIP, srcIP)
	}

	gotSrcPort := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	if gotSrcPort != srcPort {
		t.Fatalf("srcPort: got %d, want %d", gotSrcPort, srcPort)
	}

	gotDstIP := net.IP(payload[off : off+4])
	off += 4
	if !gotDstIP.Equal(dstIP.To4()) {
		t.Fatalf("dstIP: got %s, want %s", gotDstIP, dstIP)
	}

	gotDstPort := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	if gotDstPort != dstPort {
		t.Fatalf("dstPort: got %d, want %d", gotDstPort, dstPort)
	}

	gotRaw := payload[off:]
	if !bytes.Equal(gotRaw, rawSIP) {
		t.Fatalf("rawSIP mismatch")
	}
}

func TestBuildDataRTCP_Layout(t *testing.T) {
	ts := int64(99999)
	callID := "rtcp-call"
	ssrc := uint32(0xDEADBEEF)
	raw := []byte{0x80, 0xC8, 0x00, 0x01}

	payload := BuildDataRTCP(ts, callID, ssrc, raw)

	off := 0
	gotTS := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8
	if gotTS != ts {
		t.Fatalf("ts mismatch")
	}

	cidLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	gotCID := string(payload[off : off+cidLen])
	off += cidLen
	if gotCID != callID {
		t.Fatalf("callID mismatch")
	}

	gotSSRC := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4
	if gotSSRC != ssrc {
		t.Fatalf("ssrc mismatch: got 0x%08x, want 0x%08x", gotSSRC, ssrc)
	}

	if !bytes.Equal(payload[off:], raw) {
		t.Fatal("raw RTCP mismatch")
	}
}

func TestBuildDataLog_Layout(t *testing.T) {
	ts := int64(55555)
	callID := "log-call"
	line := []byte("Mar 13 12:00:00 opensips[1234]: some log line")

	payload := BuildDataLog(ts, callID, line)

	off := 0
	gotTS := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8
	if gotTS != ts {
		t.Fatalf("ts mismatch")
	}

	cidLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	gotCID := string(payload[off : off+cidLen])
	off += cidLen
	if gotCID != callID {
		t.Fatalf("callID mismatch")
	}

	if !bytes.Equal(payload[off:], line) {
		t.Fatal("log line mismatch")
	}
}

func TestBuildDataQuality(t *testing.T) {
	ts := int64(1700000000000000000)
	callID := "quality-call@host"
	qualityJSON := []byte(`{"mos":4.2,"jitter":5.1}`)

	payload := BuildDataQuality(ts, callID, qualityJSON)

	f := &Frame{
		Type:    FrameDataQuality,
		Seq:     10,
		Payload: payload,
	}

	data, err := EncodeFrame(f)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}

	// Verify frame type byte in header.
	if data[3] != FrameDataQuality {
		t.Fatalf("frame type: got 0x%02x, want 0x%02x", data[3], FrameDataQuality)
	}

	// Decode and verify payload layout.
	off := 0
	gotTS := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8
	if gotTS != ts {
		t.Fatalf("ts: got %d, want %d", gotTS, ts)
	}

	cidLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	gotCID := string(payload[off : off+cidLen])
	off += cidLen
	if gotCID != callID {
		t.Fatalf("callID: got %q, want %q", gotCID, callID)
	}

	if !bytes.Equal(payload[off:], qualityJSON) {
		t.Fatalf("qualityJSON mismatch: got %s, want %s", payload[off:], qualityJSON)
	}
}

func TestDecodeFrame_MultipleFromStream(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 100; i++ {
		f := &Frame{
			Type:    FrameHeartbeat,
			Seq:     uint32(i),
			Payload: BuildHeartbeat(int64(i * 1000)),
		}
		data, err := EncodeFrame(f)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(data)
	}

	r := &buf
	for i := 0; i < 100; i++ {
		f, err := DecodeFrame(r)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		if f.Seq != uint32(i) {
			t.Fatalf("frame %d: seq %d", i, f.Seq)
		}
	}

	// Should get EOF now
	_, err := DecodeFrame(r)
	if err == nil {
		t.Fatal("expected EOF")
	}
	if !strings.Contains(err.Error(), io.EOF.Error()) {
		t.Fatalf("expected EOF in error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkEncodeDecodeFrame(b *testing.B) {
	// Build a typical SIP frame (~800 bytes payload)
	rawSIP := []byte("INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bKnashds8\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@pc33.atlanta.example.com>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 142\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=alice 53655765 2353687637 IN IP4 pc33.atlanta.example.com\r\n" +
		"s=Session SDP\r\n" +
		"t=0 0\r\n" +
		"c=IN IP4 pc33.atlanta.example.com\r\n" +
		"m=audio 3456 RTP/AVP 0 111 8\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=ptime:20\r\n" +
		"a=sendrecv\r\n")

	payload := BuildDataSIP(
		1700000000000000000,
		"a84b4c76e66710@pc33.atlanta.example.com",
		0x00,
		net.IPv4(192, 168, 1, 100),
		net.IPv4(10, 0, 0, 50),
		5060, 5060,
		rawSIP,
	)

	f := &Frame{
		Type:    FrameDataSIP,
		Seq:     42,
		Payload: payload,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		encoded, err := EncodeFrame(f)
		if err != nil {
			b.Fatal(err)
		}

		_, err = DecodeFrame(bytes.NewReader(encoded))
		if err != nil {
			b.Fatal(err)
		}
	}
}
