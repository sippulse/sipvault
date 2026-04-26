package rtp

import (
	"encoding/binary"
	"errors"
)

var (
	ErrTooShort   = errors.New("rtp: packet too short for header")
	ErrBadVersion = errors.New("rtp: version must be 2")
)

const HeaderSize = 12

// Header contains the fixed fields from an RTP header.
type Header struct {
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	PayloadType    uint8
	Marker         bool
}

// ParseHeader extracts the RTP header from raw packet data.
// Only reads the first 12 bytes; payload is ignored.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, ErrTooShort
	}

	version := (data[0] >> 6) & 0x03
	if version != 2 {
		return nil, ErrBadVersion
	}

	return &Header{
		Marker:         (data[1] & 0x80) != 0,
		PayloadType:    data[1] & 0x7F,
		SequenceNumber: binary.BigEndian.Uint16(data[2:4]),
		Timestamp:      binary.BigEndian.Uint32(data[4:8]),
		SSRC:           binary.BigEndian.Uint32(data[8:12]),
	}, nil
}

// ClockRate returns the clock rate for common audio payload types.
// Returns 8000 as a default for unknown types.
func ClockRate(pt uint8) int {
	switch pt {
	case 0: // PCMU (G.711 μ-law)
		return 8000
	case 3: // GSM
		return 8000
	case 4: // G.723
		return 8000
	case 7: // LPC
		return 8000
	case 8: // PCMA (G.711 A-law)
		return 8000
	case 9: // G.722
		return 8000
	case 10, 11: // L16 stereo / mono
		return 44100
	case 15: // G.728
		return 8000
	case 18: // G.729
		return 8000
	case 34: // H.263
		return 90000
	default:
		return 8000
	}
}
