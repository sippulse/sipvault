package rtcp

import (
	"encoding/binary"
	"testing"
)

// buildSenderReport constructs a binary RTCP Sender Report with the given
// SSRC, sender info, and report blocks.
func buildSenderReport(ssrc uint32, si SenderInfo, blocks []ReportBlock) []byte {
	count := len(blocks)
	// Length in 32-bit words minus 1: (header excluded from count)
	// SR = 4(header) + 4(ssrc) + 20(senderinfo) + 24*count = 28 + 24*count bytes
	// Length = (28 + 24*count)/4 - 1 = 6 + 6*count
	totalLen := 28 + 24*count
	wordsMinusOne := totalLen/4 - 1

	buf := make([]byte, totalLen)
	// V=2, P=0, RC=count
	buf[0] = (2 << 6) | byte(count)
	buf[1] = byte(TypeSenderReport)
	binary.BigEndian.PutUint16(buf[2:4], uint16(wordsMinusOne))
	binary.BigEndian.PutUint32(buf[4:8], ssrc)

	off := 8
	binary.BigEndian.PutUint64(buf[off:off+8], si.NTPTimestamp)
	binary.BigEndian.PutUint32(buf[off+8:off+12], si.RTPTimestamp)
	binary.BigEndian.PutUint32(buf[off+12:off+16], si.PacketCount)
	binary.BigEndian.PutUint32(buf[off+16:off+20], si.OctetCount)
	off += 20

	for _, rb := range blocks {
		writeReportBlock(buf[off:], rb)
		off += 24
	}

	return buf
}

// buildReceiverReport constructs a binary RTCP Receiver Report.
func buildReceiverReport(ssrc uint32, blocks []ReportBlock) []byte {
	count := len(blocks)
	totalLen := 8 + 24*count
	wordsMinusOne := totalLen/4 - 1

	buf := make([]byte, totalLen)
	buf[0] = (2 << 6) | byte(count)
	buf[1] = byte(TypeReceiverReport)
	binary.BigEndian.PutUint16(buf[2:4], uint16(wordsMinusOne))
	binary.BigEndian.PutUint32(buf[4:8], ssrc)

	off := 8
	for _, rb := range blocks {
		writeReportBlock(buf[off:], rb)
		off += 24
	}

	return buf
}

func writeReportBlock(buf []byte, rb ReportBlock) {
	binary.BigEndian.PutUint32(buf[0:4], rb.SSRC)
	lostWord := uint32(rb.FractionLost)<<24 | (rb.CumulativeLost & 0x00FFFFFF)
	binary.BigEndian.PutUint32(buf[4:8], lostWord)
	binary.BigEndian.PutUint32(buf[8:12], rb.HighestSeq)
	binary.BigEndian.PutUint32(buf[12:16], rb.Jitter)
	binary.BigEndian.PutUint32(buf[16:20], rb.LastSR)
	binary.BigEndian.PutUint32(buf[20:24], rb.DelaySinceLastSR)
}

func TestParseSenderReport_NoBlocks(t *testing.T) {
	si := SenderInfo{
		NTPTimestamp: 0xDEADBEEFCAFEBABE,
		RTPTimestamp: 160000,
		PacketCount:  1000,
		OctetCount:   160000,
	}
	data := buildSenderReport(0x12345678, si, nil)

	pkt, err := ParsePacket(data)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.SenderReport == nil {
		t.Fatal("expected SenderReport")
	}
	sr := pkt.SenderReport

	if sr.SSRC != 0x12345678 {
		t.Fatalf("SSRC: got 0x%08x", sr.SSRC)
	}
	if sr.SenderInfo.NTPTimestamp != si.NTPTimestamp {
		t.Fatalf("NTP: got 0x%016x", sr.SenderInfo.NTPTimestamp)
	}
	if sr.SenderInfo.PacketCount != 1000 {
		t.Fatalf("PacketCount: got %d", sr.SenderInfo.PacketCount)
	}
	if len(sr.Reports) != 0 {
		t.Fatalf("expected 0 reports, got %d", len(sr.Reports))
	}
}

func TestParseSenderReport_WithBlocks(t *testing.T) {
	si := SenderInfo{
		NTPTimestamp: 1000,
		RTPTimestamp: 2000,
		PacketCount:  500,
		OctetCount:   80000,
	}
	blocks := []ReportBlock{
		{
			SSRC:             0xAABBCCDD,
			FractionLost:     25,
			CumulativeLost:   100,
			HighestSeq:       65536,
			Jitter:           150,
			LastSR:           0x11223344,
			DelaySinceLastSR: 5000,
		},
	}
	data := buildSenderReport(0x11111111, si, blocks)

	pkt, err := ParsePacket(data)
	if err != nil {
		t.Fatal(err)
	}

	sr := pkt.SenderReport
	if len(sr.Reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(sr.Reports))
	}

	rb := sr.Reports[0]
	if rb.SSRC != 0xAABBCCDD {
		t.Fatalf("report SSRC: got 0x%08x", rb.SSRC)
	}
	if rb.FractionLost != 25 {
		t.Fatalf("FractionLost: got %d", rb.FractionLost)
	}
	if rb.CumulativeLost != 100 {
		t.Fatalf("CumulativeLost: got %d", rb.CumulativeLost)
	}
	if rb.Jitter != 150 {
		t.Fatalf("Jitter: got %d", rb.Jitter)
	}
}

func TestParseReceiverReport(t *testing.T) {
	blocks := []ReportBlock{
		{
			SSRC:             0x12345678,
			FractionLost:     10,
			CumulativeLost:   50,
			HighestSeq:       32768,
			Jitter:           75,
			LastSR:           0x55667788,
			DelaySinceLastSR: 2500,
		},
		{
			SSRC:             0x87654321,
			FractionLost:     0,
			CumulativeLost:   0,
			HighestSeq:       100000,
			Jitter:           5,
			LastSR:           0,
			DelaySinceLastSR: 0,
		},
	}
	data := buildReceiverReport(0xAAAAAAAA, blocks)

	pkt, err := ParsePacket(data)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.ReceiverReport == nil {
		t.Fatal("expected ReceiverReport")
	}
	rr := pkt.ReceiverReport

	if rr.SSRC != 0xAAAAAAAA {
		t.Fatalf("SSRC: got 0x%08x", rr.SSRC)
	}
	if len(rr.Reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(rr.Reports))
	}

	if rr.Reports[0].SSRC != 0x12345678 {
		t.Fatalf("first report SSRC mismatch")
	}
	if rr.Reports[1].FractionLost != 0 {
		t.Fatalf("second report FractionLost: got %d", rr.Reports[1].FractionLost)
	}
}

func TestParseCompound_SR_RR(t *testing.T) {
	sr := buildSenderReport(0x11111111, SenderInfo{NTPTimestamp: 999}, nil)
	rr := buildReceiverReport(0x22222222, []ReportBlock{
		{SSRC: 0x33333333, FractionLost: 5, CumulativeLost: 10, HighestSeq: 500, Jitter: 20},
	})

	compound := append(sr, rr...)

	packets, err := ParseCompound(compound)
	if err != nil {
		t.Fatal(err)
	}

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}

	if packets[0].SenderReport == nil {
		t.Fatal("first packet should be SR")
	}
	if packets[1].ReceiverReport == nil {
		t.Fatal("second packet should be RR")
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := ParsePacket([]byte{0x80})
	if err != ErrTooShort {
		t.Fatalf("expected ErrTooShort, got %v", err)
	}
}

func TestParse_WrongVersion(t *testing.T) {
	// Version 3 (invalid)
	data := []byte{0xC0, byte(TypeSenderReport), 0x00, 0x06}
	_, err := ParsePacket(data)
	if err != ErrBadVersion {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestParse_Truncated(t *testing.T) {
	// Build a valid SR header but truncate the data.
	data := make([]byte, 8)
	data[0] = (2 << 6) | 1 // V=2, RC=1 (claims 1 report block)
	data[1] = byte(TypeSenderReport)
	binary.BigEndian.PutUint16(data[2:4], 12) // says 52 bytes total, but we only have 8

	_, err := ParsePacket(data)
	if err != ErrTruncated {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}

func TestParse_TruncatedReportBlock(t *testing.T) {
	// Build SR with RC=1 but without the report block data.
	si := SenderInfo{NTPTimestamp: 1}
	data := buildSenderReport(0x11, si, nil)
	// Manually set RC=1 so parser expects a report block.
	data[0] = (2 << 6) | 1
	// But length still only covers header+ssrc+senderinfo (no room for report block).

	_, err := ParsePacket(data)
	if err != ErrTruncated {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}

func TestParseCompound_Empty(t *testing.T) {
	packets, err := ParseCompound(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 0 {
		t.Fatalf("expected 0 packets, got %d", len(packets))
	}
}
