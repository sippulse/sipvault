package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Wire protocol constants.
const (
	Magic          = 0x5356
	Version        = 0x01
	HeaderSize     = 12
	MaxPayloadSize = 1048576 // 1 MB
	MaxCallIDLen   = 512
)

// Frame types.
const (
	FrameHandshake    = 0x01
	FrameHandshakeACK = 0x02
	FrameDataSIP      = 0x03
	FrameDataRTCP     = 0x04
	FrameDataLog      = 0x05
	FrameHeartbeat    = 0x06
	FrameHeartbeatACK = 0x07
	FrameDataQuality  = 0x08
	FrameMediaWatch   = 0x09
)

// Errors returned by the protocol encoder/decoder.
var (
	ErrBadMagic      = errors.New("mux: invalid magic bytes")
	ErrBadVersion    = errors.New("mux: unsupported protocol version")
	ErrPayloadTooBig = errors.New("mux: payload exceeds maximum size")
	ErrCallIDTooLong = errors.New("mux: call-id exceeds maximum length")
	ErrShortPayload  = errors.New("mux: payload too short for frame type")
)

// Frame represents a single wire protocol frame.
type Frame struct {
	Type    byte
	Seq     uint32
	Payload []byte
}

// EncodeFrame serialises a Frame into its wire representation.
func EncodeFrame(f *Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}

	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], Magic)
	buf[2] = Version
	buf[3] = f.Type
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(f.Payload)))
	binary.BigEndian.PutUint32(buf[8:12], f.Seq)
	copy(buf[HeaderSize:], f.Payload)
	return buf, nil
}

// DecodeFrame reads a single frame from r.
func DecodeFrame(r io.Reader) (*Frame, error) {
	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("mux: reading header: %w", err)
	}

	magic := binary.BigEndian.Uint16(hdr[0:2])
	if magic != Magic {
		return nil, ErrBadMagic
	}

	ver := hdr[2]
	if ver != Version {
		return nil, ErrBadVersion
	}

	f := &Frame{
		Type: hdr[3],
	}

	payloadLen := binary.BigEndian.Uint32(hdr[4:8])
	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}

	f.Seq = binary.BigEndian.Uint32(hdr[8:12])

	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("mux: reading payload: %w", err)
		}
	}

	return f, nil
}

// BuildHandshake constructs a HANDSHAKE payload.
func BuildHandshake(customerID, token, version string) []byte {
	cidBytes := []byte(customerID)
	tokBytes := []byte(token)
	verBytes := []byte(version)

	size := 2 + len(cidBytes) + 2 + len(tokBytes) + 2 + len(verBytes)
	buf := make([]byte, size)

	off := 0
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cidBytes)))
	off += 2
	copy(buf[off:], cidBytes)
	off += len(cidBytes)

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(tokBytes)))
	off += 2
	copy(buf[off:], tokBytes)
	off += len(tokBytes)

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(verBytes)))
	off += 2
	copy(buf[off:], verBytes)

	return buf
}

// BuildDataSIP constructs a DATA_SIP payload. Only IPv4 is supported.
func BuildDataSIP(ts int64, callID string, dir byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, rawSIP []byte) []byte {
	cidBytes := []byte(callID)

	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	// ts(8) + callIDLen(2) + callID + dir(1) + srcIP(4) + srcPort(2) + dstIP(4) + dstPort(2) + rawSIP
	size := 8 + 2 + len(cidBytes) + 1 + 4 + 2 + 4 + 2 + len(rawSIP)
	buf := make([]byte, size)

	off := 0
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(ts))
	off += 8

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cidBytes)))
	off += 2
	copy(buf[off:], cidBytes)
	off += len(cidBytes)

	buf[off] = dir
	off++

	copy(buf[off:off+4], src4)
	off += 4
	binary.BigEndian.PutUint16(buf[off:off+2], srcPort)
	off += 2

	copy(buf[off:off+4], dst4)
	off += 4
	binary.BigEndian.PutUint16(buf[off:off+2], dstPort)
	off += 2

	copy(buf[off:], rawSIP)
	return buf
}

// BuildDataRTCP constructs a DATA_RTCP payload.
func BuildDataRTCP(ts int64, callID string, ssrc uint32, rawRTCP []byte) []byte {
	cidBytes := []byte(callID)

	// ts(8) + callIDLen(2) + callID + ssrc(4) + rawRTCP
	size := 8 + 2 + len(cidBytes) + 4 + len(rawRTCP)
	buf := make([]byte, size)

	off := 0
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(ts))
	off += 8

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cidBytes)))
	off += 2
	copy(buf[off:], cidBytes)
	off += len(cidBytes)

	binary.BigEndian.PutUint32(buf[off:off+4], ssrc)
	off += 4

	copy(buf[off:], rawRTCP)
	return buf
}

// BuildDataLog constructs a DATA_LOG payload.
func BuildDataLog(ts int64, callID string, line []byte) []byte {
	cidBytes := []byte(callID)

	// ts(8) + callIDLen(2) + callID + line
	size := 8 + 2 + len(cidBytes) + len(line)
	buf := make([]byte, size)

	off := 0
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(ts))
	off += 8

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cidBytes)))
	off += 2
	copy(buf[off:], cidBytes)
	off += len(cidBytes)

	copy(buf[off:], line)
	return buf
}

// BuildDataQuality constructs a DATA_QUALITY payload.
// Format: ts(8) + callIDLen(2) + callID + qualityJSON
func BuildDataQuality(ts int64, callID string, qualityJSON []byte) []byte {
	cidBytes := []byte(callID)

	// ts(8) + callIDLen(2) + callID + qualityJSON
	size := 8 + 2 + len(cidBytes) + len(qualityJSON)
	buf := make([]byte, size)

	off := 0
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(ts))
	off += 8

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cidBytes)))
	off += 2
	copy(buf[off:], cidBytes)
	off += len(cidBytes)

	copy(buf[off:], qualityJSON)
	return buf
}

// ParseMediaWatch extracts call and media info from a MEDIA_WATCH payload
// sent by the server to this agent.
// Format: callIDLen(2) + callID + mediaIPLen(2) + mediaIP + port(2) + codecLen(2) + codec
func ParseMediaWatch(payload []byte) (callID, mediaIP string, mediaPort uint16, codec string, err error) {
	off := 0

	callID, off, err = readLenPrefixed16(payload, off)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("mux: media_watch call_id: %w", err)
	}

	mediaIP, off, err = readLenPrefixed16(payload, off)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("mux: media_watch media_ip: %w", err)
	}

	if off+2 > len(payload) {
		return "", "", 0, "", fmt.Errorf("mux: media_watch port: %w", ErrShortPayload)
	}
	mediaPort = binary.BigEndian.Uint16(payload[off : off+2])
	off += 2

	codec, _, err = readLenPrefixed16(payload, off)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("mux: media_watch codec: %w", err)
	}

	return callID, mediaIP, mediaPort, codec, nil
}

// BuildHeartbeat constructs a HEARTBEAT payload.
func BuildHeartbeat(ts int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf[0:8], uint64(ts))
	return buf
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// readLenPrefixed16 reads a 2-byte big-endian length prefix followed by that
// many bytes of UTF-8 data starting at offset off within p. It returns the
// string value, the new offset, and any error.
func readLenPrefixed16(p []byte, off int) (string, int, error) {
	if off+2 > len(p) {
		return "", off, ErrShortPayload
	}
	n := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+n > len(p) {
		return "", off, ErrShortPayload
	}
	s := string(p[off : off+n])
	off += n
	return s, off, nil
}
