package rtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors returned by the RTCP parser.
var (
	ErrTooShort      = errors.New("rtcp: packet too short")
	ErrBadVersion    = errors.New("rtcp: invalid version (must be 2)")
	ErrTruncated     = errors.New("rtcp: packet truncated")
	ErrUnknownType   = errors.New("rtcp: unknown packet type")
)

const (
	headerSize      = 4  // Common RTCP header
	ssrcSize        = 4
	senderInfoSize  = 20 // NTP(8) + RTP_TS(4) + PKT_CNT(4) + OCT_CNT(4)
	reportBlockSize = 24 // SSRC(4) + lost(4) + highseq(4) + jitter(4) + lsr(4) + dlsr(4)
)

// ParsePacket parses a single RTCP packet from data.
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < headerSize {
		return nil, ErrTooShort
	}

	hdr := parseHeader(data)
	if hdr.Version != 2 {
		return nil, ErrBadVersion
	}

	// Total packet length in bytes: (Length + 1) * 4
	totalLen := int(hdr.Length+1) * 4
	if len(data) < totalLen {
		return nil, ErrTruncated
	}

	pkt := &Packet{Header: hdr}

	switch hdr.PacketType {
	case TypeSenderReport:
		sr, err := parseSenderReport(data, hdr)
		if err != nil {
			return nil, err
		}
		pkt.SenderReport = sr

	case TypeReceiverReport:
		rr, err := parseReceiverReport(data, hdr)
		if err != nil {
			return nil, err
		}
		pkt.ReceiverReport = rr

	default:
		// For unknown types we still return the header.
		// Caller can inspect Header.PacketType.
	}

	return pkt, nil
}

// ParseCompound parses a compound RTCP packet (multiple RTCP packets
// concatenated).
func ParseCompound(data []byte) ([]*Packet, error) {
	var packets []*Packet

	for len(data) > 0 {
		if len(data) < headerSize {
			return nil, ErrTooShort
		}

		hdr := parseHeader(data)
		if hdr.Version != 2 {
			return nil, ErrBadVersion
		}

		totalLen := int(hdr.Length+1) * 4
		if len(data) < totalLen {
			return nil, ErrTruncated
		}

		pkt, err := ParsePacket(data[:totalLen])
		if err != nil {
			return nil, fmt.Errorf("rtcp: compound packet at offset %d: %w", len(data), err)
		}
		packets = append(packets, pkt)
		data = data[totalLen:]
	}

	return packets, nil
}

func parseHeader(data []byte) Header {
	first := data[0]
	return Header{
		Version:    (first >> 6) & 0x03,
		Padding:    (first>>5)&0x01 == 1,
		Count:      first & 0x1F,
		PacketType: PacketType(data[1]),
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}
}

func parseSenderReport(data []byte, hdr Header) (*SenderReport, error) {
	// Minimum SR size: header(4) + SSRC(4) + SenderInfo(20) = 28
	minSize := headerSize + ssrcSize + senderInfoSize
	if len(data) < minSize {
		return nil, ErrTruncated
	}

	sr := &SenderReport{
		SSRC: binary.BigEndian.Uint32(data[4:8]),
	}

	off := 8
	sr.SenderInfo = SenderInfo{
		NTPTimestamp: binary.BigEndian.Uint64(data[off : off+8]),
		RTPTimestamp: binary.BigEndian.Uint32(data[off+8 : off+12]),
		PacketCount:  binary.BigEndian.Uint32(data[off+12 : off+16]),
		OctetCount:   binary.BigEndian.Uint32(data[off+16 : off+20]),
	}
	off += senderInfoSize

	// Parse report blocks.
	for i := 0; i < int(hdr.Count); i++ {
		if off+reportBlockSize > len(data) {
			return nil, ErrTruncated
		}
		rb := parseReportBlock(data[off:])
		sr.Reports = append(sr.Reports, rb)
		off += reportBlockSize
	}

	return sr, nil
}

func parseReceiverReport(data []byte, hdr Header) (*ReceiverReport, error) {
	// Minimum RR size: header(4) + SSRC(4) = 8
	minSize := headerSize + ssrcSize
	if len(data) < minSize {
		return nil, ErrTruncated
	}

	rr := &ReceiverReport{
		SSRC: binary.BigEndian.Uint32(data[4:8]),
	}

	off := 8
	for i := 0; i < int(hdr.Count); i++ {
		if off+reportBlockSize > len(data) {
			return nil, ErrTruncated
		}
		rb := parseReportBlock(data[off:])
		rr.Reports = append(rr.Reports, rb)
		off += reportBlockSize
	}

	return rr, nil
}

func parseReportBlock(data []byte) ReportBlock {
	lostWord := binary.BigEndian.Uint32(data[4:8])
	return ReportBlock{
		SSRC:             binary.BigEndian.Uint32(data[0:4]),
		FractionLost:     uint8(lostWord >> 24),
		CumulativeLost:   lostWord & 0x00FFFFFF,
		HighestSeq:       binary.BigEndian.Uint32(data[8:12]),
		Jitter:           binary.BigEndian.Uint32(data[12:16]),
		LastSR:           binary.BigEndian.Uint32(data[16:20]),
		DelaySinceLastSR: binary.BigEndian.Uint32(data[20:24]),
	}
}
