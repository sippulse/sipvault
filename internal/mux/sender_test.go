package mux

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sippulse/sipvault/internal/buffer"
)

// mockServer accepts a connection, reads the handshake, and sends back
// a HANDSHAKE_ACK with the given status byte.
func mockServer(t *testing.T, ln net.Listener, status byte, wg *sync.WaitGroup) {
	t.Helper()
	defer wg.Done()

	conn, err := ln.Accept()
	if err != nil {
		return // listener closed
	}
	defer conn.Close()

	// Read handshake frame.
	_, err = DecodeFrame(conn)
	if err != nil {
		t.Errorf("mock server: decode handshake: %v", err)
		return
	}

	// Send HANDSHAKE_ACK.
	ack, err := buildHandshakeACK(status)
	if err != nil {
		t.Errorf("mock server: build ack: %v", err)
		return
	}
	conn.Write(ack)
}

// mockServerReadFrames accepts a connection, handles handshake, then reads
// n frames and writes them to the frames channel.
func mockServerReadFrames(t *testing.T, ln net.Listener, status byte, n int, frames chan<- *Frame, wg *sync.WaitGroup) {
	t.Helper()
	defer wg.Done()

	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read handshake.
	_, err = DecodeFrame(conn)
	if err != nil {
		t.Errorf("mock server: decode handshake: %v", err)
		return
	}

	// Send ACK.
	ack, err := buildHandshakeACK(status)
	if err != nil {
		t.Errorf("mock server: build ack: %v", err)
		return
	}
	conn.Write(ack)

	// Read data frames.
	for i := 0; i < n; i++ {
		f, err := DecodeFrame(conn)
		if err != nil {
			if err != io.EOF {
				t.Errorf("mock server: decode frame %d: %v", i, err)
			}
			return
		}
		frames <- f
	}
}

func TestSuccessfulHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockServer(t, ln, HandshakeOK, &wg)

	sender := NewSender(ln.Addr().String(), "cust1", "tok123", "v0.1.0", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sender.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sender.Close()

	wg.Wait()
}

func TestAuthFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go mockServer(t, ln, HandshakeFail, &wg)

	sender := NewSender(ln.Addr().String(), "cust1", "bad-token", "v0.1.0", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = sender.Connect(ctx)
	if err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}

	wg.Wait()
}

func TestSendFramesAfterHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	frames := make(chan *Frame, 3)
	var wg sync.WaitGroup
	wg.Add(1)
	go mockServerReadFrames(t, ln, HandshakeOK, 3, frames, &wg)

	sender := NewSender(ln.Addr().String(), "cust1", "tok123", "v0.1.0", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sender.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sender.Close()

	// Send 3 data frames.
	for i := 0; i < 3; i++ {
		f := &Frame{
			Type:    FrameDataSIP,
			Payload: BuildDataSIP(int64(i*1000), "call-1", 0x00, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("SIP data")),
		}
		if err := sender.Send(f); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	// Verify frames were received on the server side.
	for i := 0; i < 3; i++ {
		select {
		case f := <-frames:
			if f.Type != FrameDataSIP {
				t.Fatalf("frame %d: expected type DATA_SIP, got 0x%02x", i, f.Type)
			}
			// Sequence numbers should be 1, 2, 3 (0 used by handshake setup, seq starts at 1).
			if f.Seq != uint32(i+1) {
				t.Fatalf("frame %d: expected seq %d, got %d", i, i+1, f.Seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for frame %d", i)
		}
	}

	wg.Wait()
}

func TestFallbackToBufferWhenDisconnected(t *testing.T) {
	dir := t.TempDir()
	buf, err := buffer.NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	// Create sender with no server (never connect).
	sender := NewSender("127.0.0.1:1", "cust1", "tok123", "v0.1.0", buf)

	f := &Frame{
		Type:    FrameDataLog,
		Payload: BuildDataLog(1000, "call-1", []byte("log line")),
	}

	if err := sender.Send(f); err != nil {
		t.Fatalf("Send should not error when buffering: %v", err)
	}

	// Verify the frame was buffered.
	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 buffered frame, got %d", len(frames))
	}

	// Decode the buffered frame.
	decoded, err := DecodeFrame(bytes.NewReader(frames[0]))
	if err != nil {
		t.Fatalf("decode buffered frame: %v", err)
	}
	if decoded.Type != FrameDataLog {
		t.Fatalf("expected type DATA_LOG, got 0x%02x", decoded.Type)
	}
}

func TestReconnectAndReplay(t *testing.T) {
	dir := t.TempDir()
	buf, err := buffer.NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	// Create sender with buffer, send frames while disconnected.
	sender := NewSender("127.0.0.1:1", "cust1", "tok123", "v0.1.0", buf)

	for i := 0; i < 3; i++ {
		f := &Frame{
			Type:    FrameDataSIP,
			Payload: BuildDataSIP(int64(i*1000), "call-1", 0x00, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("SIP data")),
		}
		sender.Send(f)
	}

	// Verify buffered.
	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 buffered frames, got %d", len(frames))
	}

	// Start a server now.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The server should receive 3 replayed frames.
	receivedFrames := make(chan *Frame, 3)
	var wg sync.WaitGroup
	wg.Add(1)
	go mockServerReadFrames(t, ln, HandshakeOK, 3, receivedFrames, &wg)

	// Update sender address to the new server.
	sender.mu.Lock()
	sender.addr = ln.Addr().String()
	sender.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sender.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	defer sender.Close()

	// Verify the replayed frames arrived.
	for i := 0; i < 3; i++ {
		select {
		case f := <-receivedFrames:
			if f.Type != FrameDataSIP {
				t.Fatalf("replayed frame %d: expected DATA_SIP, got 0x%02x", i, f.Type)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for replayed frame %d", i)
		}
	}

	// Buffer should be cleared after successful replay.
	if buf.Size() != 0 {
		t.Fatalf("expected buffer cleared after replay, size=%d", buf.Size())
	}

	wg.Wait()
}

func TestSender_ReconnectAndReplayUnderLoad(t *testing.T) {
	dir := t.TempDir()
	buf, err := buffer.NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	// Phase 1: Start server, connect, send 10 frames successfully.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	phase1Frames := make(chan *Frame, 10)
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go mockServerReadFrames(t, ln1, HandshakeOK, 10, phase1Frames, &wg1)

	sender := NewSender(ln1.Addr().String(), "cust1", "tok123", "v0.1.0", buf)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := sender.Connect(ctx); err != nil {
		t.Fatalf("Connect phase 1: %v", err)
	}

	for i := 0; i < 10; i++ {
		f := &Frame{
			Type:    FrameDataSIP,
			Payload: BuildDataSIP(int64(i*1000), "call-load", 0x00, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("SIP data")),
		}
		if err := sender.Send(f); err != nil {
			t.Fatalf("Send phase 1 frame %d: %v", i, err)
		}
	}

	// Collect phase 1 frames
	for i := 0; i < 10; i++ {
		select {
		case f := <-phase1Frames:
			if f.Type != FrameDataSIP {
				t.Fatalf("phase 1 frame %d: wrong type 0x%02x", i, f.Type)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for phase 1 frame %d", i)
		}
	}

	wg1.Wait()

	// Phase 2: Close server, send 10 frames (should buffer).
	ln1.Close()
	sender.Close()

	// Create sender with buffer pointing to closed address; frames will go to disk.
	sender2 := NewSender("127.0.0.1:1", "cust1", "tok123", "v0.1.0", buf)

	for i := 0; i < 10; i++ {
		f := &Frame{
			Type:    FrameDataSIP,
			Payload: BuildDataSIP(int64((10+i)*1000), "call-load", 0x00, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 5060, 5060, []byte("SIP buffered")),
		}
		if err := sender2.Send(f); err != nil {
			t.Fatalf("Send phase 2 frame %d: %v", i, err)
		}
	}

	// Verify frames were buffered
	buffered, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(buffered) != 10 {
		t.Fatalf("expected 10 buffered frames, got %d", len(buffered))
	}

	// Phase 3: Start new server, reconnect, verify replay.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	phase3Frames := make(chan *Frame, 10)
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go mockServerReadFrames(t, ln2, HandshakeOK, 10, phase3Frames, &wg2)

	// Point sender to new server
	sender2.mu.Lock()
	sender2.addr = ln2.Addr().String()
	sender2.mu.Unlock()

	if err := sender2.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	defer sender2.Close()

	// Verify all 10 buffered frames were replayed with sequential sequence numbers.
	var seqs []uint32
	for i := 0; i < 10; i++ {
		select {
		case f := <-phase3Frames:
			if f.Type != FrameDataSIP {
				t.Fatalf("replayed frame %d: wrong type 0x%02x", i, f.Type)
			}
			seqs = append(seqs, f.Seq)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for replayed frame %d", i)
		}
	}

	// Verify sequence numbers are sequential
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Errorf("sequence numbers not sequential: seqs[%d]=%d, seqs[%d]=%d",
				i-1, seqs[i-1], i, seqs[i])
		}
	}

	// Buffer should be cleared
	if buf.Size() != 0 {
		t.Fatalf("expected buffer cleared after replay, size=%d", buf.Size())
	}

	wg2.Wait()
}

func TestSendWithNoBufferReturnsError(t *testing.T) {
	sender := NewSender("127.0.0.1:1", "cust1", "tok123", "v0.1.0", nil)

	f := &Frame{
		Type:    FrameDataSIP,
		Payload: []byte("test"),
	}

	err := sender.Send(f)
	if err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}
