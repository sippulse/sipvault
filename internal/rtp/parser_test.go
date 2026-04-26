package rtp

import (
	"testing"
)

// buildRTPPacket constructs a minimal 12-byte RTP packet with the given fields.
func buildRTPPacket(version, pt uint8, marker bool, seq uint16, ts uint32, ssrc uint32) []byte {
	pkt := make([]byte, 12)
	pkt[0] = (version << 6)
	pkt[1] = pt & 0x7F
	if marker {
		pkt[1] |= 0x80
	}
	pkt[2] = byte(seq >> 8)
	pkt[3] = byte(seq)
	pkt[4] = byte(ts >> 24)
	pkt[5] = byte(ts >> 16)
	pkt[6] = byte(ts >> 8)
	pkt[7] = byte(ts)
	pkt[8] = byte(ssrc >> 24)
	pkt[9] = byte(ssrc >> 16)
	pkt[10] = byte(ssrc >> 8)
	pkt[11] = byte(ssrc)
	return pkt
}

func TestParseHeader(t *testing.T) {
	pkt := buildRTPPacket(2, 0, true, 1234, 56789, 0xDEADBEEF)
	// Append fake payload to make sure we only read 12 bytes.
	pkt = append(pkt, 0xAA, 0xBB)

	hdr, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hdr.SequenceNumber != 1234 {
		t.Errorf("SequenceNumber: got %d, want 1234", hdr.SequenceNumber)
	}
	if hdr.Timestamp != 56789 {
		t.Errorf("Timestamp: got %d, want 56789", hdr.Timestamp)
	}
	if hdr.SSRC != 0xDEADBEEF {
		t.Errorf("SSRC: got 0x%X, want 0xDEADBEEF", hdr.SSRC)
	}
	if hdr.PayloadType != 0 {
		t.Errorf("PayloadType: got %d, want 0", hdr.PayloadType)
	}
	if !hdr.Marker {
		t.Error("Marker: got false, want true")
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x80, 0x00, 0x00})
	if err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestParseHeader_BadVersion(t *testing.T) {
	pkt := buildRTPPacket(0, 0, false, 0, 0, 0)
	_, err := ParseHeader(pkt)
	if err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}
