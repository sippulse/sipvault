package mux

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// countingWriter wraps a bytes.Buffer and tracks the number of Write calls.
type countingWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.writes++
	return cw.buf.Write(p)
}

func (cw *countingWriter) Bytes() []byte {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	b := make([]byte, cw.buf.Len())
	copy(b, cw.buf.Bytes())
	return b
}

func (cw *countingWriter) WriteCount() int {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.writes
}

// TestBatchSender_FlushesOnMaxFrames verifies that sending maxFrames frames
// triggers a flush and that all bytes arrive in ≤2 write calls (batched).
func TestBatchSender_FlushesOnMaxFrames(t *testing.T) {
	const maxFrames = 5
	cw := &countingWriter{}
	bs := NewBatchSender(cw, maxFrames, 500*time.Millisecond)
	bs.Start()

	for i := 0; i < maxFrames; i++ {
		if err := bs.Send(&Frame{
			Type:    FrameHeartbeat,
			Seq:     uint32(i),
			Payload: BuildHeartbeat(int64(i)),
		}); err != nil {
			t.Fatalf("Send failed: %v", err)
		}
	}

	// Stop drains the channel and flushes any remaining data.
	bs.Stop()

	writes := cw.WriteCount()
	if writes > 2 {
		t.Errorf("expected ≤2 write calls for %d frames, got %d", maxFrames, writes)
	}

	// Verify all frames were written by decoding them back.
	r := bytes.NewReader(cw.Bytes())
	decoded := 0
	for {
		f, err := DecodeFrame(r)
		if err != nil {
			break
		}
		if f.Type != FrameHeartbeat {
			t.Errorf("unexpected frame type 0x%02x", f.Type)
		}
		decoded++
	}
	if decoded != maxFrames {
		t.Errorf("expected %d decoded frames, got %d", maxFrames, decoded)
	}
}

// TestBatchSender_FlushesOnTimeout verifies that a single frame is flushed
// after the timeout even when the batch is not full.
func TestBatchSender_FlushesOnTimeout(t *testing.T) {
	const flushDelay = 50 * time.Millisecond
	cw := &countingWriter{}
	bs := NewBatchSender(cw, 100, flushDelay)
	bs.Start()

	if err := bs.Send(&Frame{
		Type:    FrameHeartbeat,
		Seq:     1,
		Payload: BuildHeartbeat(time.Now().UnixNano()),
	}); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Wait slightly longer than the flush delay.
	time.Sleep(flushDelay * 3)

	bs.Stop()

	if cw.WriteCount() == 0 {
		t.Fatal("expected at least one write after flush timeout, got 0")
	}

	r := bytes.NewReader(cw.Bytes())
	f, err := DecodeFrame(r)
	if err != nil {
		t.Fatalf("failed to decode flushed frame: %v", err)
	}
	if f.Type != FrameHeartbeat {
		t.Errorf("expected FrameHeartbeat, got 0x%02x", f.Type)
	}
}
