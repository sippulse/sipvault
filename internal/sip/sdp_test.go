package sip

import (
	"testing"
)

func TestParseSDP_Full(t *testing.T) {
	raw := readTestFile(t, "invite.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	sdp, err := ParseSDP(msg.Body)
	if err != nil {
		t.Fatal(err)
	}

	if sdp.MediaPort != 49170 {
		t.Fatalf("MediaPort: got %d, want 49170", sdp.MediaPort)
	}

	expectedCodecs := []string{"PCMU/8000", "PCMA/8000", "iLBC/8000"}
	if len(sdp.Codecs) != len(expectedCodecs) {
		t.Fatalf("Codecs: got %v, want %v", sdp.Codecs, expectedCodecs)
	}
	for i, c := range sdp.Codecs {
		if c != expectedCodecs[i] {
			t.Fatalf("Codec[%d]: got %q, want %q", i, c, expectedCodecs[i])
		}
	}

	if sdp.SSRC != 12345678 {
		t.Fatalf("SSRC: got %d, want 12345678", sdp.SSRC)
	}
}

func TestParseSDP_200OK(t *testing.T) {
	raw := readTestFile(t, "response_200.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	sdp, err := ParseSDP(msg.Body)
	if err != nil {
		t.Fatal(err)
	}

	if sdp.MediaPort != 3456 {
		t.Fatalf("MediaPort: got %d, want 3456", sdp.MediaPort)
	}

	if len(sdp.Codecs) != 2 {
		t.Fatalf("Codecs: got %v", sdp.Codecs)
	}

	if sdp.SSRC != 87654321 {
		t.Fatalf("SSRC: got %d, want 87654321", sdp.SSRC)
	}
}

func TestParseSDP_MinimalSDP(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if sdp.MediaPort != 8000 {
		t.Fatalf("MediaPort: got %d, want 8000", sdp.MediaPort)
	}

	// No rtpmap → empty codec list
	if len(sdp.Codecs) != 0 {
		t.Fatalf("expected no codecs without rtpmap, got %v", sdp.Codecs)
	}

	if sdp.SSRC != 0 {
		t.Fatalf("SSRC: got %d, want 0", sdp.SSRC)
	}
}

func TestParseSDP_NoMediaLine(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n")

	_, err := ParseSDP(body)
	if err != ErrNoMediaLine {
		t.Fatalf("expected ErrNoMediaLine, got %v", err)
	}
}

func TestParseSDP_NoSSRC(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if sdp.SSRC != 0 {
		t.Fatalf("SSRC: got %d, want 0", sdp.SSRC)
	}

	if sdp.MediaPort != 5004 {
		t.Fatalf("MediaPort: got %d, want 5004", sdp.MediaPort)
	}

	if len(sdp.Codecs) != 2 {
		t.Fatalf("Codecs count: got %d, want 2", len(sdp.Codecs))
	}
}

func TestParseSDP_Empty(t *testing.T) {
	_, err := ParseSDP(nil)
	if err != ErrNoMediaLine {
		t.Fatalf("expected ErrNoMediaLine for nil, got %v", err)
	}

	_, err = ParseSDP([]byte{})
	if err != ErrNoMediaLine {
		t.Fatalf("expected ErrNoMediaLine for empty, got %v", err)
	}
}

func TestParseSDP_DetectsRTCPDisabled(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=rtcp:0\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if sdp.RTCPEnabled {
		t.Fatal("RTCPEnabled: got true, want false for a=rtcp:0")
	}
}

func TestParseSDP_DetectsRTCPEnabled(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=rtcp:8001\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if !sdp.RTCPEnabled {
		t.Fatal("RTCPEnabled: got false, want true for a=rtcp:8001")
	}
	if sdp.RTCPPort != 8001 {
		t.Fatalf("RTCPPort: got %d, want 8001", sdp.RTCPPort)
	}
}

func TestParseSDP_DefaultRTCPEnabled(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if !sdp.RTCPEnabled {
		t.Fatal("RTCPEnabled: got false, want true (RFC 3605 default)")
	}
	if sdp.RTCPPort != 0 {
		t.Fatalf("RTCPPort: got %d, want 0 (default RTP+1)", sdp.RTCPPort)
	}
}

func TestParseSDP_DetectsRTCPMux(t *testing.T) {
	body := []byte("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=rtcp-mux\r\n")

	sdp, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}

	if !sdp.RTCPEnabled {
		t.Fatal("RTCPEnabled: got false, want true for a=rtcp-mux")
	}
}
