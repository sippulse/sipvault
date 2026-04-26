package mux

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// FrameSender is the interface used by capture.Reader to send wire-protocol
// frames. Both *Sender and *BatchSender satisfy this interface.
type FrameSender interface {
	Send(f *Frame) error
}

// BatchSender buffers frames and writes them in batches to reduce TCP syscalls
// at high call-per-second rates.
type BatchSender struct {
	w          io.Writer
	maxFrames  int
	flushDelay time.Duration
	ch chan *Frame
	wg sync.WaitGroup
}

// NewBatchSender creates a BatchSender that writes to w.
// It flushes when either maxFrames frames have accumulated or flushDelay elapses.
func NewBatchSender(w io.Writer, maxFrames int, flushDelay time.Duration) *BatchSender {
	return &BatchSender{
		w:          w,
		maxFrames:  maxFrames,
		flushDelay: flushDelay,
		ch: make(chan *Frame, maxFrames*2),
	}
}

// Start launches the background goroutine that batches and flushes frames.
func (bs *BatchSender) Start() {
	bs.wg.Add(1)
	go bs.run()
}

// Send enqueues a frame for batched delivery. It always returns nil; errors
// are logged internally and the frame is silently dropped if un-encodable.
func (bs *BatchSender) Send(f *Frame) error {
	bs.ch <- f
	return nil
}

// Stop signals the sender to stop and waits for the goroutine to drain and finish.
func (bs *BatchSender) Stop() {
	close(bs.ch)
	bs.wg.Wait()
}

// run is the background goroutine. It accumulates encoded frames into a buffer
// and flushes to the underlying writer when either maxFrames is reached or
// flushDelay elapses.
func (bs *BatchSender) run() {
	defer bs.wg.Done()

	var buf bytes.Buffer
	count := 0
	timer := time.NewTimer(bs.flushDelay)
	defer timer.Stop()

	flush := func() {
		if buf.Len() == 0 {
			return
		}
		// Best-effort write; errors are not propagated (caller is fire-and-forget).
		_, _ = bs.w.Write(buf.Bytes())
		buf.Reset()
		count = 0
	}

	for {
		select {
		case f, ok := <-bs.ch:
			if !ok {
				// Channel closed — drain and finish.
				flush()
				return
			}
			encoded, err := EncodeFrame(f)
			if err != nil {
				// Skip un-encodable frames.
				continue
			}
			buf.Write(encoded)
			count++
			if count >= bs.maxFrames {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(bs.flushDelay)
			}
		case <-timer.C:
			flush()
			timer.Reset(bs.flushDelay)
		}
	}
}
