package mux

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sippulse/sipvault/internal/buffer"
)

// HEP v3 chunk identifiers.
const (
	hepVendorZero uint16 = 0x0000
	hepVendorSV   uint16 = 0x5350 // "SP" = SipPulse vendor namespace

	hepChunkIPFamily    uint16 = 0x0001
	hepChunkIPProto     uint16 = 0x0002
	hepChunkSrcIPv4     uint16 = 0x0003
	hepChunkDstIPv4     uint16 = 0x0004
	hepChunkSrcPort     uint16 = 0x0007
	hepChunkDstPort     uint16 = 0x0008
	hepChunkTsSec       uint16 = 0x0009
	hepChunkTsUSec      uint16 = 0x000a
	hepChunkProtoType   uint16 = 0x000b
	hepChunkCorrelation uint16 = 0x0011
	hepChunkPayload     uint16 = 0x000f

	hepChunkSVCustomer uint16 = 0x0001 // vendor SipPulse: customer_id
	hepChunkSVToken    uint16 = 0x0002 // vendor SipPulse: auth token

	hepProtoSIP     byte = 0x01
	hepProtoRTCP    byte = 0x05
	hepProtoLog     byte = 0x64
	hepProtoQuality byte = 0x65
)

// HEPSender connects to sipvault-server over TLS/TCP and sends data
// encoded as HEP v3 packets. It implements io.Writer so it can serve
// as the underlying writer for BatchSender.
//
// Authentication is embedded in every HEP packet via SipVault vendor
// chunks (vendor_id 0x5350) carrying the customer_id and token.
type HEPSender struct {
	addr       string
	customerID string
	token      string
	tlsCfg     *tls.Config

	mu        sync.Mutex
	conn      net.Conn
	connected bool
	buf       *buffer.DiskBuffer
}

// NewHEPSenderTLS creates a HEPSender.
//
// serverName is used for TLS SNI; if empty, the host portion of addr is used.
// caCertFile is a path to a PEM CA certificate for validating self-signed
// server certs; if empty, the system root pool is used.
func NewHEPSenderTLS(
	addr, customerID, token string,
	serverName, caCertFile string,
	buf *buffer.DiskBuffer,
) (*HEPSender, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if tlsCfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			tlsCfg.ServerName = host
		}
	}
	if caCertFile != "" {
		pem, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("hep_sender: read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hep_sender: no valid certs in %s", caCertFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &HEPSender{
		addr:       addr,
		customerID: customerID,
		token:      token,
		tlsCfg:     tlsCfg,
		buf:        buf,
	}, nil
}

// Connect dials the server and establishes a TLS session.
func (s *HEPSender) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := tls.Dialer{Config: s.tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("hep_sender: dial: %w", err)
	}
	s.conn = conn
	s.connected = true
	return nil
}

// Write implements io.Writer. It expects the concatenated encoded wire-protocol
// frames that BatchSender produces. Each frame is decoded, converted to a
// HEP v3 packet, and written to the TLS connection. If the connection is down,
// the raw bytes are spooled to the disk buffer.
func (s *HEPSender) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected || s.conn == nil {
		if s.buf != nil {
			_ = s.buf.Write(p)
		}
		return len(p), nil
	}

	r := bytes.NewReader(p)
	for r.Len() > 0 {
		f, err := DecodeFrame(r)
		if err != nil {
			break
		}
		pkt, err := s.frameToHEP(f)
		if err != nil || len(pkt) == 0 {
			continue
		}
		if _, err := s.conn.Write(pkt); err != nil {
			s.connected = false
			s.conn.Close()
			s.conn = nil
			if s.buf != nil {
				_ = s.buf.Write(p)
			}
			return len(p), nil
		}
	}
	return len(p), nil
}

// Close closes the TLS connection.
func (s *HEPSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// Reconnect retries Connect with exponential backoff (same contract as Sender).
func (s *HEPSender) Reconnect(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if err := s.Connect(ctx); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// frameToHEP converts a wire-protocol Frame to a HEP v3 packet.
// Returns nil for frame types that have no HEP equivalent (handshake, heartbeat).
func (s *HEPSender) frameToHEP(f *Frame) ([]byte, error) {
	switch f.Type {
	case FrameDataSIP:
		return s.buildHEPSIP(f.Payload)
	case FrameDataRTCP:
		return s.buildHEPSimple(f.Payload, hepProtoRTCP, true)
	case FrameDataLog:
		return s.buildHEPSimple(f.Payload, hepProtoLog, false)
	case FrameDataQuality:
		return s.buildHEPSimple(f.Payload, hepProtoQuality, false)
	default:
		return nil, nil
	}
}

// buildHEPSIP parses a DATA_SIP payload and returns a HEP v3 SIP packet.
// Payload layout: ts(8) + callIDLen(2) + callID + dir(1) + srcIP(4) + srcPort(2) + dstIP(4) + dstPort(2) + rawSIP
func (s *HEPSender) buildHEPSIP(payload []byte) ([]byte, error) {
	off := 0
	if off+8 > len(payload) {
		return nil, fmt.Errorf("DATA_SIP too short for timestamp")
	}
	ts := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8

	callID, off, err := readLen16(payload, off)
	if err != nil {
		return nil, fmt.Errorf("DATA_SIP callID: %w", err)
	}

	if off+1+4+2+4+2 > len(payload) {
		return nil, fmt.Errorf("DATA_SIP header fields truncated")
	}
	off++ // skip dir byte
	srcIP := net.IP(make([]byte, 4))
	copy(srcIP, payload[off:off+4])
	off += 4
	srcPort := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	dstIP := net.IP(make([]byte, 4))
	copy(dstIP, payload[off:off+4])
	off += 4
	dstPort := binary.BigEndian.Uint16(payload[off : off+2])
	off += 2
	rawSIP := payload[off:]

	tsSec := uint32(ts / 1e9)
	tsUSec := uint32((ts % 1e9) / 1000)

	var c hepBuilder
	c.uint8(hepVendorZero, hepChunkIPFamily, 0x02)   // AF_INET
	c.uint8(hepVendorZero, hepChunkIPProto, 0x11)    // UDP (typical for SIP)
	c.ip4(hepVendorZero, hepChunkSrcIPv4, srcIP)
	c.ip4(hepVendorZero, hepChunkDstIPv4, dstIP)
	c.uint16(hepVendorZero, hepChunkSrcPort, srcPort)
	c.uint16(hepVendorZero, hepChunkDstPort, dstPort)
	c.uint32(hepVendorZero, hepChunkTsSec, tsSec)
	c.uint32(hepVendorZero, hepChunkTsUSec, tsUSec)
	c.uint8(hepVendorZero, hepChunkProtoType, hepProtoSIP)
	c.bytes(hepVendorZero, hepChunkCorrelation, []byte(callID))
	c.bytes(hepVendorZero, hepChunkPayload, rawSIP)
	c.bytes(hepVendorSV, hepChunkSVCustomer, []byte(s.customerID))
	c.bytes(hepVendorSV, hepChunkSVToken, []byte(s.token))
	return c.build(), nil
}

// buildHEPSimple parses DATA_RTCP / DATA_LOG / DATA_QUALITY payloads.
// Common layout: ts(8) + callIDLen(2) + callID [+ ssrc(4) for RTCP] + data
func (s *HEPSender) buildHEPSimple(payload []byte, protoType byte, hasSSRC bool) ([]byte, error) {
	off := 0
	if off+8 > len(payload) {
		return nil, fmt.Errorf("payload too short for timestamp")
	}
	ts := int64(binary.BigEndian.Uint64(payload[off : off+8]))
	off += 8

	callID, off, err := readLen16(payload, off)
	if err != nil {
		return nil, fmt.Errorf("payload callID: %w", err)
	}

	if hasSSRC {
		if off+4 > len(payload) {
			return nil, fmt.Errorf("RTCP payload too short for SSRC")
		}
		off += 4
	}
	data := payload[off:]

	tsSec := uint32(ts / 1e9)
	tsUSec := uint32((ts % 1e9) / 1000)

	var c hepBuilder
	c.uint32(hepVendorZero, hepChunkTsSec, tsSec)
	c.uint32(hepVendorZero, hepChunkTsUSec, tsUSec)
	c.uint8(hepVendorZero, hepChunkProtoType, protoType)
	c.bytes(hepVendorZero, hepChunkCorrelation, []byte(callID))
	c.bytes(hepVendorZero, hepChunkPayload, data)
	c.bytes(hepVendorSV, hepChunkSVCustomer, []byte(s.customerID))
	c.bytes(hepVendorSV, hepChunkSVToken, []byte(s.token))
	return c.build(), nil
}

// hepBuilder accumulates HEP v3 chunks and builds a complete HEP3 packet.
type hepBuilder struct {
	buf bytes.Buffer
}

func (b *hepBuilder) chunk(vendorID, chunkType uint16, data []byte) {
	hdr := [6]byte{}
	binary.BigEndian.PutUint16(hdr[0:2], vendorID)
	binary.BigEndian.PutUint16(hdr[2:4], chunkType)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(6+len(data)))
	b.buf.Write(hdr[:])
	b.buf.Write(data)
}

func (b *hepBuilder) bytes(v, t uint16, d []byte)  { b.chunk(v, t, d) }
func (b *hepBuilder) uint8(v, t uint16, n byte)    { b.chunk(v, t, []byte{n}) }
func (b *hepBuilder) uint16(v, t uint16, n uint16) {
	d := [2]byte{}
	binary.BigEndian.PutUint16(d[:], n)
	b.chunk(v, t, d[:])
}
func (b *hepBuilder) uint32(v, t uint16, n uint32) {
	d := [4]byte{}
	binary.BigEndian.PutUint32(d[:], n)
	b.chunk(v, t, d[:])
}
func (b *hepBuilder) ip4(v, t uint16, ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = make([]byte, 4)
	}
	b.chunk(v, t, ip4)
}

func (b *hepBuilder) build() []byte {
	chunks := b.buf.Bytes()
	total := 6 + len(chunks)
	pkt := make([]byte, total)
	copy(pkt[0:4], "HEP3")
	binary.BigEndian.PutUint16(pkt[4:6], uint16(total))
	copy(pkt[6:], chunks)
	return pkt
}

// readLen16 reads a 2-byte big-endian length followed by that many bytes,
// returning the string and the new offset.
func readLen16(p []byte, off int) (string, int, error) {
	if off+2 > len(p) {
		return "", off, ErrShortPayload
	}
	n := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+n > len(p) {
		return "", off, ErrShortPayload
	}
	s := string(p[off : off+n])
	return s, off + n, nil
}
