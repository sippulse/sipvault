package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sippulse/sipvault/internal/buffer"
	"github.com/sippulse/sipvault/internal/logfilter"
	"github.com/sippulse/sipvault/internal/mux"
	"github.com/sippulse/sipvault/internal/tracker"
)

func TestIsSIPKeepAlive(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"single CRLF", []byte("\r\n"), true},
		{"double CRLF (RFC 5626)", []byte("\r\n\r\n"), true},
		{"single LF", []byte("\n"), true},
		{"empty", []byte{}, true},
		{"whitespace only", []byte(" \t"), true},
		{"INVITE", []byte("INVITE sip:bob@ex SIP/2.0\r\n"), false},
		{"OPTIONS short", []byte("OPTI"), false}, // 4 bytes, non-whitespace
		{"larger than threshold", []byte("\r\n\r\n\r\n"), false},
		{"single 'a'", []byte("a"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSIPKeepAlive(c.data); got != c.want {
				t.Fatalf("isSIPKeepAlive(%q) = %v, want %v", c.data, got, c.want)
			}
		})
	}
}

// MockSource implements Source using a channel.
type MockSource struct {
	ch chan CaptureEvent
}

func NewMockSource() *MockSource {
	return &MockSource{ch: make(chan CaptureEvent, 100)}
}

func (m *MockSource) Events() <-chan CaptureEvent {
	return m.ch
}

func (m *MockSource) Close() error {
	close(m.ch)
	return nil
}

func (m *MockSource) Send(ev CaptureEvent) {
	m.ch <- ev
}

// buildInvite builds a minimal SIP INVITE message with the given Call-ID.
func buildInvite(callID string) []byte {
	return []byte("INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"From: <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"To: <sip:bob@biloxi.example.com>\r\n" +
		"\r\n")
}

// buildInviteWithSDP builds a SIP INVITE with SDP containing an SSRC line.
func buildInviteWithSDP(callID string, ssrc uint32) []byte {
	sdp := "v=0\r\n" +
		"o=- 123 456 IN IP4 10.0.0.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 10000 RTP/AVP 0 8\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=ssrc:" + itoa(ssrc) + " cname:test\r\n"

	return []byte("INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"From: <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"To: <sip:bob@biloxi.example.com>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		sdp)
}

// itoa converts uint32 to decimal string.
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// Reverse.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// buildBye builds a minimal SIP BYE message.
func buildBye(callID string) []byte {
	return []byte("BYE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 2 BYE\r\n" +
		"From: <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"To: <sip:bob@biloxi.example.com>;tag=31415\r\n" +
		"\r\n")
}

// buildRTCPSenderReport builds a minimal RTCP Sender Report with the given SSRC.
func buildRTCPSenderReport(ssrc uint32) []byte {
	// SR: V=2, P=0, RC=0, PT=200, length=6 (7 32-bit words = 28 bytes)
	buf := make([]byte, 28)
	buf[0] = 0x80 // V=2, P=0, RC=0
	buf[1] = 200  // PT = SR
	binary.BigEndian.PutUint16(buf[2:4], 6) // length = 6 (28 bytes total)
	binary.BigEndian.PutUint32(buf[4:8], ssrc)
	// Rest is sender info (NTP, RTP TS, pkt count, oct count) — zeroes are fine.
	return buf
}

// setupTestReader creates a Reader with a mock source and buffer-backed sender.
// It returns the mock source, sender, buffer, tracker, and filter for inspection.
func setupTestReader(t *testing.T) (*MockSource, *mux.Sender, *buffer.DiskBuffer, *tracker.Tracker, *logfilter.Filter) {
	t.Helper()

	dir := t.TempDir()
	buf, err := buffer.NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	trk := tracker.New(5 * time.Second)
	fltr := logfilter.New(trk)
	src := NewMockSource()
	sender := mux.NewSender("127.0.0.1:1", "cust1", "tok", "v1", buf)

	return src, sender, buf, trk, fltr
}

// readBufferedFrames reads all frames from the buffer and decodes them.
func readBufferedFrames(t *testing.T, buf *buffer.DiskBuffer) []*mux.Frame {
	t.Helper()
	raw, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var frames []*mux.Frame
	for _, r := range raw {
		f, err := mux.DecodeFrame(bytes.NewReader(r))
		if err != nil {
			t.Fatalf("decode buffered frame: %v", err)
		}
		frames = append(frames, f)
	}
	return frames
}

func TestINVITETrackedAndFrameSent(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "invite-test-call@host"
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInvite(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	// Give time for processing.
	time.Sleep(50 * time.Millisecond)

	cancel()
	wg.Wait()

	// Verify tracker has the call.
	if !trk.IsActive(callID) {
		t.Fatal("expected call to be tracked after INVITE")
	}

	// Verify frame was sent (buffered since sender is not connected).
	frames := readBufferedFrames(t, buf)
	if len(frames) != 1 {
		t.Fatalf("expected 1 buffered frame, got %d", len(frames))
	}
	if frames[0].Type != mux.FrameDataSIP {
		t.Fatalf("expected DATA_SIP frame, got 0x%02x", frames[0].Type)
	}
}

func TestBYERemovesFromTracker(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "bye-test-call@host"

	// Send INVITE first, then BYE.
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInvite(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 2000,
		Data:      buildBye(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	// Verify 2 SIP frames were sent.
	frames := readBufferedFrames(t, buf)
	if len(frames) != 2 {
		t.Fatalf("expected 2 buffered frames, got %d", len(frames))
	}
	for _, f := range frames {
		if f.Type != mux.FrameDataSIP {
			t.Fatalf("expected DATA_SIP, got 0x%02x", f.Type)
		}
	}
}

func TestRTCPWithMappedSSRC(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "rtcp-test-call@host"
	ssrc := uint32(12345678)

	// Send INVITE with SDP containing SSRC.
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInviteWithSDP(callID, ssrc),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(20 * time.Millisecond)

	// Send RTCP SR with the mapped SSRC.
	src.Send(CaptureEvent{
		Type:      EventRTCP,
		Timestamp: 2000,
		Data:      buildRTCPSenderReport(ssrc),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   10001,
		DstPort:   10001,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)
	// Should have 1 SIP frame + 1 RTCP frame.
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	rtcpFrame := frames[1]
	if rtcpFrame.Type != mux.FrameDataRTCP {
		t.Fatalf("expected DATA_RTCP, got 0x%02x", rtcpFrame.Type)
	}

	// Verify the Call-ID in the RTCP frame payload.
	off := 8 // skip timestamp
	cidLen := binary.BigEndian.Uint16(rtcpFrame.Payload[off : off+2])
	off += 2
	gotCallID := string(rtcpFrame.Payload[off : off+int(cidLen)])
	if gotCallID != callID {
		t.Fatalf("RTCP frame callID: got %q, want %q", gotCallID, callID)
	}
}

func TestLogWithTrackedCallID(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "log-test-call@host"

	// First register the call via INVITE.
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInvite(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(20 * time.Millisecond)

	// Send a log line containing the call ID.
	logLine := []byte("Mar 13 12:00:00 opensips[1234]: call " + callID + " some log info")
	src.Send(CaptureEvent{
		Type:      EventLog,
		Timestamp: 2000,
		Data:      logLine,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)
	// 1 SIP + 1 LOG
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[1].Type != mux.FrameDataLog {
		t.Fatalf("expected DATA_LOG, got 0x%02x", frames[1].Type)
	}
}

func TestLogWithoutCallIDIsDropped(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	// Send a log line that does not contain any tracked call ID.
	logLine := []byte("Mar 13 12:00:00 opensips[1234]: some unrelated log")
	src.Send(CaptureEvent{
		Type:      EventLog,
		Timestamp: 1000,
		Data:      logLine,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)
	if len(frames) != 0 {
		t.Fatalf("expected 0 frames for unmatched log, got %d", len(frames))
	}
}

func TestContextCancellationStopsReader(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- reader.Run(ctx)
	}()

	// Cancel immediately.
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reader to stop")
	}
}

// buildInviteWithSDPRtcpDisabled builds a SIP INVITE with SDP that has a=rtcp:0
// to disable RTCP, triggering RTP-based quality analysis.
func buildInviteWithSDPRtcpDisabled(callID string, mediaPort int) []byte {
	sdp := "v=0\r\n" +
		"o=- 123 456 IN IP4 10.0.0.1\r\n" +
		"s=-\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio " + itoa(uint32(mediaPort)) + " RTP/AVP 0 8\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtcp:0\r\n"

	return []byte("INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"From: <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"To: <sip:bob@biloxi.example.com>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		sdp)
}

// buildRTPPacketRaw constructs a minimal 12-byte RTP packet (version=2, PT=0).
func buildRTPPacketRaw(seq uint16, ts uint32, ssrc uint32) []byte {
	pkt := make([]byte, 12)
	pkt[0] = 0x80 // version=2
	pkt[1] = 0x00 // PT=0 (PCMU)
	binary.BigEndian.PutUint16(pkt[2:4], seq)
	binary.BigEndian.PutUint32(pkt[4:8], ts)
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	return pkt
}

func TestReader_RTPQualitySentOnBYE(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "rtp-quality-test@host"
	mediaPort := uint16(20000)

	// Send INVITE with SDP containing a=rtcp:0 (RTCP disabled).
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInviteWithSDPRtcpDisabled(callID, int(mediaPort)),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(30 * time.Millisecond)

	// Send 50 RTP packets on the mapped media port with sequential headers.
	ssrc := uint32(0xABCD1234)
	baseTS := time.Now()
	ptime := 20 * time.Millisecond
	for i := 0; i < 50; i++ {
		rtpPkt := buildRTPPacketRaw(uint16(i), uint32(i)*160, ssrc)
		src.Send(CaptureEvent{
			Type:      EventRTP,
			Timestamp: baseTS.Add(time.Duration(i) * ptime).UnixNano(),
			Data:      rtpPkt,
			SrcIP:     net.IPv4(10, 0, 0, 1),
			DstIP:     net.IPv4(10, 0, 0, 2),
			SrcPort:   30000,
			DstPort:   mediaPort,
		})
	}

	time.Sleep(30 * time.Millisecond)

	// Send BYE to trigger sendRTPQuality.
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 5000,
		Data:      buildBye(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)

	// Should have: 1 INVITE (SIP) + 1 BYE (SIP) + 1 Quality frame.
	var qualityFrames []*mux.Frame
	for _, f := range frames {
		if f.Type == mux.FrameDataQuality {
			qualityFrames = append(qualityFrames, f)
		}
	}

	if len(qualityFrames) != 1 {
		// List all frame types for debugging.
		types := make([]byte, len(frames))
		for i, f := range frames {
			types[i] = f.Type
		}
		t.Fatalf("expected 1 FrameDataQuality, got %d (frame types: %v)", len(qualityFrames), types)
	}

	// Decode the quality JSON from the payload.
	// Payload format: ts(8) + callIDLen(2) + callID + qualityJSON
	payload := qualityFrames[0].Payload
	off := 8 // skip timestamp
	cidLen := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	gotCallID := string(payload[off : off+int(cidLen)])
	off += int(cidLen)

	if gotCallID != callID {
		t.Fatalf("quality frame callID: got %q, want %q", gotCallID, callID)
	}

	qualityJSON := payload[off:]
	var report map[string]interface{}
	if err := json.Unmarshal(qualityJSON, &report); err != nil {
		t.Fatalf("failed to unmarshal quality JSON: %v", err)
	}

	// Assert verdict is present.
	v, ok := report["verdict"]
	if !ok || v == "" {
		t.Fatal("quality report missing verdict")
	}

	// Assert source is "rtp".
	src2, ok := report["source"]
	if !ok || src2 != "rtp" {
		t.Fatalf("quality report source: got %v, want 'rtp'", src2)
	}

	// Check that directions exist and contain MOS > 0.
	dirs, ok := report["directions"].(map[string]interface{})
	if !ok || len(dirs) == 0 {
		t.Fatal("quality report has no directions")
	}
	for dirName, dirVal := range dirs {
		dirMap, ok := dirVal.(map[string]interface{})
		if !ok {
			t.Fatalf("direction %q is not a map", dirName)
		}
		mosMap, ok := dirMap["mos"].(map[string]interface{})
		if !ok {
			t.Fatalf("direction %q missing mos", dirName)
		}
		avg, ok := mosMap["avg"].(float64)
		if !ok || avg <= 0 {
			t.Fatalf("direction %q MOS avg: got %v, want > 0", dirName, mosMap["avg"])
		}
	}
}

func TestReader_NoRTPQualityWhenRTCPPresent(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	callID := "rtcp-present-test@host"
	ssrc := uint32(99887766)

	// Send INVITE with normal SDP (RTCP enabled by default, no a=rtcp:0).
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      buildInviteWithSDP(callID, ssrc),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(30 * time.Millisecond)

	// Send some RTP packets. Since RTCP is enabled in the SDP, the port
	// should NOT be registered for RTP capture, so these should be ignored.
	baseTS := time.Now()
	ptime := 20 * time.Millisecond
	for i := 0; i < 20; i++ {
		rtpPkt := buildRTPPacketRaw(uint16(i), uint32(i)*160, ssrc)
		src.Send(CaptureEvent{
			Type:      EventRTP,
			Timestamp: baseTS.Add(time.Duration(i) * ptime).UnixNano(),
			Data:      rtpPkt,
			SrcIP:     net.IPv4(10, 0, 0, 1),
			DstIP:     net.IPv4(10, 0, 0, 2),
			SrcPort:   30000,
			DstPort:   10000, // SDP media port from buildInviteWithSDP
		})
	}

	time.Sleep(30 * time.Millisecond)

	// Send BYE.
	src.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 5000,
		Data:      buildBye(callID),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)

	// Should only have SIP frames (INVITE + BYE), NO FrameDataQuality.
	for _, f := range frames {
		if f.Type == mux.FrameDataQuality {
			t.Fatal("unexpected FrameDataQuality frame when RTCP is present")
		}
	}

	// Verify we have exactly the SIP frames.
	sipCount := 0
	for _, f := range frames {
		if f.Type == mux.FrameDataSIP {
			sipCount++
		}
	}
	if sipCount != 2 {
		t.Fatalf("expected 2 SIP frames (INVITE + BYE), got %d", sipCount)
	}
}

func TestRTCPWithUnmappedSSRCIsDropped(t *testing.T) {
	src, sender, buf, trk, fltr := setupTestReader(t)
	defer buf.Close()
	reader := NewReader(src, trk, fltr, sender)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader.Run(ctx)
	}()

	// Send RTCP with an SSRC that is not mapped to any call.
	src.Send(CaptureEvent{
		Type:      EventRTCP,
		Timestamp: 1000,
		Data:      buildRTCPSenderReport(99999),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   10001,
		DstPort:   10001,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	frames := readBufferedFrames(t, buf)
	if len(frames) != 0 {
		t.Fatalf("expected 0 frames for unmapped SSRC, got %d", len(frames))
	}
}
