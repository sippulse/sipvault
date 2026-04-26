package mux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sippulse/sipvault/internal/buffer"
)

// Handshake ACK status codes.
const (
	HandshakeOK   = 0x00
	HandshakeFail = 0x01
)

// Errors returned by the Sender.
var (
	ErrAuthFailed  = errors.New("mux: authentication failed")
	ErrNotConnected = errors.New("mux: not connected")
)

// Sender is a TCP client that connects to sipvault-server,
// performs handshake, and sends wire protocol frames.
type Sender struct {
	addr       string
	customerID string
	token      string
	version    string

	mu        sync.Mutex
	conn      net.Conn
	seq       uint32
	connected bool

	buffer *buffer.DiskBuffer // fallback when disconnected
}

// NewSender creates a new Sender.
func NewSender(addr, customerID, token, version string, buf *buffer.DiskBuffer) *Sender {
	return &Sender{
		addr:       addr,
		customerID: customerID,
		token:      token,
		version:    version,
		buffer:     buf,
	}
}

// Connect dials the server, sends a HANDSHAKE frame, and reads
// the HANDSHAKE_ACK response. Returns an error if the connection
// fails or authentication is rejected.
func (s *Sender) Connect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("mux: dial: %w", err)
	}

	// Build and send HANDSHAKE frame.
	payload := BuildHandshake(s.customerID, s.token, s.version)
	f := &Frame{
		Type:    FrameHandshake,
		Seq:     0,
		Payload: payload,
	}

	encoded, err := EncodeFrame(f)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mux: encode handshake: %w", err)
	}

	if _, err := conn.Write(encoded); err != nil {
		conn.Close()
		return fmt.Errorf("mux: write handshake: %w", err)
	}

	// Read HANDSHAKE_ACK.
	ackFrame, err := DecodeFrame(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mux: read handshake ack: %w", err)
	}

	if ackFrame.Type != FrameHandshakeACK {
		conn.Close()
		return fmt.Errorf("mux: expected HANDSHAKE_ACK (0x%02x), got 0x%02x", FrameHandshakeACK, ackFrame.Type)
	}

	if len(ackFrame.Payload) < 1 {
		conn.Close()
		return fmt.Errorf("mux: empty HANDSHAKE_ACK payload")
	}

	status := ackFrame.Payload[0]
	if status != HandshakeOK {
		conn.Close()
		return ErrAuthFailed
	}

	s.conn = conn
	s.connected = true
	s.seq = 1 // start sequence after handshake
	return nil
}

// Send encodes and sends a frame over the TCP connection. If the
// sender is not connected or the write fails, the frame is written
// to the disk buffer instead. The frame's Seq field is auto-set.
func (s *Sender) Send(f *Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f.Seq = s.seq
	s.seq++

	encoded, err := EncodeFrame(f)
	if err != nil {
		return fmt.Errorf("mux: encode: %w", err)
	}

	if !s.connected || s.conn == nil {
		return s.writeToBuffer(encoded)
	}

	if _, err := s.conn.Write(encoded); err != nil {
		// Connection failed; buffer the frame.
		s.connected = false
		s.conn.Close()
		s.conn = nil
		return s.writeToBuffer(encoded)
	}

	return nil
}

// writeToBuffer stores an encoded frame in the disk buffer.
func (s *Sender) writeToBuffer(encoded []byte) error {
	if s.buffer == nil {
		return ErrNotConnected
	}
	return s.buffer.Write(encoded)
}

// Write implements io.Writer by sending raw (already-encoded) bytes to the
// server connection. If the sender is not connected, the bytes are stored in
// the disk buffer so they can be replayed after reconnection. This allows
// BatchSender to use *Sender as its underlying writer.
func (s *Sender) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected || s.conn == nil {
		if err := s.writeToBuffer(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	n, err := s.conn.Write(p)
	if err != nil {
		s.connected = false
		s.conn.Close()
		s.conn = nil
		if bufErr := s.writeToBuffer(p); bufErr != nil {
			return n, bufErr
		}
		return len(p), nil
	}
	return n, nil
}

// Close closes the TCP connection.
func (s *Sender) Close() error {
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

// Reconnect attempts to re-establish the TCP connection with
// exponential backoff (1s, 2s, 4s, 8s, 16s, max 30s). After
// a successful reconnection, buffered frames are replayed.
func (s *Sender) Reconnect(ctx context.Context) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		err := s.Connect(ctx)
		if err == nil {
			// Connected — replay buffered data.
			return s.replayBuffer()
		}

		// If context is already cancelled, don't wait.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Wait with backoff.
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

// replayBuffer reads all frames from the disk buffer and sends them
// over the current connection.
func (s *Sender) replayBuffer() error {
	if s.buffer == nil {
		return nil
	}

	frames, err := s.buffer.ReadAll()
	if err != nil {
		return fmt.Errorf("mux: replay read: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, raw := range frames {
		if s.conn == nil || !s.connected {
			return ErrNotConnected
		}
		// Re-decode and re-encode to update the sequence number.
		f, err := DecodeFrame(bytes.NewReader(raw))
		if err != nil {
			// Skip malformed buffered frames.
			continue
		}
		f.Seq = s.seq
		s.seq++

		encoded, err := EncodeFrame(f)
		if err != nil {
			continue
		}
		if _, err := s.conn.Write(encoded); err != nil {
			s.connected = false
			s.conn.Close()
			s.conn = nil
			return fmt.Errorf("mux: replay write: %w", err)
		}
	}

	// Clear the buffer after successful replay.
	if err := s.buffer.Clear(); err != nil {
		return fmt.Errorf("mux: replay clear: %w", err)
	}

	return nil
}

// buildHandshakeACK constructs a HANDSHAKE_ACK frame with the given status.
// This is used in tests to simulate server responses.
func buildHandshakeACK(status byte) ([]byte, error) {
	f := &Frame{
		Type:    FrameHandshakeACK,
		Seq:     0,
		Payload: []byte{status},
	}
	return EncodeFrame(f)
}

// BuildHandshakeACK constructs a HANDSHAKE_ACK payload with timestamp
// and status. Exported for server-side use.
func BuildHandshakeACK(status byte) []byte {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))
	buf[8] = status
	return buf
}
