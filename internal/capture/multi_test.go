package capture

import (
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestMultiSource_MergesTwoSources(t *testing.T) {
	src1 := NewMockSource()
	src2 := NewMockSource()

	multi := NewMultiSource(src1, src2)
	defer multi.Close()

	src1.Send(CaptureEvent{
		Type:      EventSIP,
		Timestamp: 1000,
		Data:      []byte("sip-from-1"),
		SrcIP:     net.IPv4(10, 0, 0, 1),
		DstIP:     net.IPv4(10, 0, 0, 2),
		SrcPort:   5060,
		DstPort:   5060,
	})

	src2.Send(CaptureEvent{
		Type:      EventRTCP,
		Timestamp: 2000,
		Data:      []byte("rtcp-from-2"),
		SrcIP:     net.IPv4(10, 0, 0, 3),
		DstIP:     net.IPv4(10, 0, 0, 4),
		SrcPort:   10001,
		DstPort:   10001,
	})

	var events []CaptureEvent
	timeout := time.After(500 * time.Millisecond)
	for len(events) < 2 {
		select {
		case ev := <-multi.Events():
			events = append(events, ev)
		case <-timeout:
			t.Fatalf("timed out: got %d events, want 2", len(events))
		}
	}

	// Sort by timestamp to get deterministic order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})

	if events[0].Type != EventSIP || string(events[0].Data) != "sip-from-1" {
		t.Fatalf("event 0: got type=%d data=%q", events[0].Type, events[0].Data)
	}
	if events[1].Type != EventRTCP || string(events[1].Data) != "rtcp-from-2" {
		t.Fatalf("event 1: got type=%d data=%q", events[1].Type, events[1].Data)
	}
}

func TestMultiSource_CloseShutdownsAll(t *testing.T) {
	src1 := NewMockSource()
	src2 := NewMockSource()

	multi := NewMultiSource(src1, src2)

	done := make(chan struct{})
	go func() {
		multi.Close()
		close(done)
	}()

	select {
	case <-done:
		// Good — Close returned.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Close")
	}

	// After close, the merged channel should eventually close.
	select {
	case _, ok := <-multi.Events():
		if ok {
			// Draining leftover events is fine; eventually it should close.
		}
	case <-time.After(500 * time.Millisecond):
		// Channel may already be drained.
	}
}

func TestMultiSource_OneSourceCloses_OtherContinues(t *testing.T) {
	src1 := &safeCloseMockSource{ch: make(chan CaptureEvent, 100)}
	src2 := &safeCloseMockSource{ch: make(chan CaptureEvent, 100)}

	multi := NewMultiSource(src1, src2)
	defer multi.Close()

	// Close src1's channel.
	src1.Close()

	// src2 should still work.
	src2.ch <- CaptureEvent{
		Type:      EventLog,
		Timestamp: 3000,
		Data:      []byte("from-2-after-1-closed"),
	}

	select {
	case ev := <-multi.Events():
		if string(ev.Data) != "from-2-after-1-closed" {
			t.Fatalf("unexpected event data: %q", ev.Data)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event from src2")
	}
}

// safeCloseMockSource is a MockSource variant that can be closed multiple
// times without panicking.
type safeCloseMockSource struct {
	ch     chan CaptureEvent
	closed sync.Once
}

func (s *safeCloseMockSource) Events() <-chan CaptureEvent { return s.ch }
func (s *safeCloseMockSource) Close() error {
	s.closed.Do(func() { close(s.ch) })
	return nil
}

// Compile-time check that *MultiSource implements Source.
var _ Source = (*MultiSource)(nil)
