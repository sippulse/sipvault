package tracker

import (
	"sync"
	"testing"
	"time"
)

func TestAddAndIsActive(t *testing.T) {
	tr := New(5 * time.Second)

	tr.Add("call-1")
	if !tr.IsActive("call-1") {
		t.Fatal("call-1 should be active")
	}

	if tr.IsActive("call-2") {
		t.Fatal("call-2 should not be active")
	}
}

func TestRemoveWithGrace(t *testing.T) {
	tr := New(100 * time.Millisecond)

	tr.Add("call-1")
	tr.Remove("call-1")

	// Should still be active during grace.
	if !tr.IsActive("call-1") {
		t.Fatal("call-1 should be active during grace period")
	}

	// Wait for grace to expire.
	time.Sleep(150 * time.Millisecond)

	if tr.IsActive("call-1") {
		t.Fatal("call-1 should be inactive after grace period")
	}
}

func TestRemoveAndReAdd(t *testing.T) {
	tr := New(100 * time.Millisecond)

	tr.Add("call-1")
	tr.Remove("call-1")

	// Re-add before grace expires.
	tr.Add("call-1")

	time.Sleep(150 * time.Millisecond)

	// Should still be active because it was re-added.
	if !tr.IsActive("call-1") {
		t.Fatal("call-1 should be active after re-add")
	}
}

func TestSSRCMapping(t *testing.T) {
	tr := New(5 * time.Second)

	tr.Add("call-1")
	tr.MapSSRC(12345, "call-1")

	callID, ok := tr.LookupSSRC(12345)
	if !ok || callID != "call-1" {
		t.Fatalf("LookupSSRC: got %q, %v", callID, ok)
	}

	_, ok = tr.LookupSSRC(99999)
	if ok {
		t.Fatal("unexpected SSRC found")
	}
}

func TestCleanup(t *testing.T) {
	tr := New(50 * time.Millisecond)

	tr.Add("call-1")
	tr.Add("call-2")
	tr.MapSSRC(111, "call-1")
	tr.MapSSRC(222, "call-2")

	tr.Remove("call-1")

	time.Sleep(100 * time.Millisecond)

	tr.Cleanup()

	if tr.IsActive("call-1") {
		t.Fatal("call-1 should be cleaned up")
	}
	if !tr.IsActive("call-2") {
		t.Fatal("call-2 should still be active")
	}

	_, ok := tr.LookupSSRC(111)
	if ok {
		t.Fatal("SSRC 111 should be cleaned up")
	}

	callID, ok := tr.LookupSSRC(222)
	if !ok || callID != "call-2" {
		t.Fatal("SSRC 222 should still map to call-2")
	}
}

func TestActiveCount(t *testing.T) {
	tr := New(50 * time.Millisecond)

	if tr.ActiveCount() != 0 {
		t.Fatalf("expected 0, got %d", tr.ActiveCount())
	}

	tr.Add("call-1")
	tr.Add("call-2")
	tr.Add("call-3")

	if tr.ActiveCount() != 3 {
		t.Fatalf("expected 3, got %d", tr.ActiveCount())
	}

	tr.Remove("call-2")
	// Still active during grace.
	if tr.ActiveCount() != 3 {
		t.Fatalf("expected 3 during grace, got %d", tr.ActiveCount())
	}

	time.Sleep(100 * time.Millisecond)

	if tr.ActiveCount() != 2 {
		t.Fatalf("expected 2 after grace, got %d", tr.ActiveCount())
	}
}

func TestConcurrentAccess(t *testing.T) {
	tr := New(100 * time.Millisecond)
	var wg sync.WaitGroup

	// Concurrent adds.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			callID := "call-" + string(rune('A'+n%26))
			tr.Add(callID)
			tr.IsActive(callID)
			tr.MapSSRC(uint32(n), callID)
			tr.LookupSSRC(uint32(n))
			tr.ActiveCount()
		}(i)
	}

	// Concurrent removes.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			callID := "call-" + string(rune('A'+n%26))
			tr.Remove(callID)
			tr.IsActive(callID)
		}(i)
	}

	// Concurrent cleanup.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Cleanup()
		}()
	}

	wg.Wait()
}

func TestTracker_MediaPortTracking(t *testing.T) {
	tr := New(30 * time.Second)

	info := &MediaInfo{
		CallID:      "call-1",
		SSRC:        0xABCD,
		Port:        8000,
		ClockRate:   8000,
		Codec:       "PCMU/8000",
		RTCPEnabled: false,
	}
	tr.MapMediaPort(8000, info)

	got, ok := tr.LookupMediaPort(8000)
	if !ok {
		t.Fatal("expected port 8000 to be tracked")
	}
	if got.CallID != "call-1" {
		t.Fatalf("expected CallID %q, got %q", "call-1", got.CallID)
	}
	if !tr.NeedsRTPCapture(8000) {
		t.Fatal("expected NeedsRTPCapture(8000) to be true")
	}

	// Port with RTCP enabled should not need capture.
	tr.MapMediaPort(9000, &MediaInfo{RTCPEnabled: true})
	if tr.NeedsRTPCapture(9000) {
		t.Fatal("expected NeedsRTPCapture(9000) to be false when RTCPEnabled=true")
	}

	// Unknown port should not need capture.
	if tr.NeedsRTPCapture(7000) {
		t.Fatal("expected NeedsRTPCapture(7000) to be false for untracked port")
	}
}

func TestAllActive(t *testing.T) {
	tr := New(50 * time.Millisecond)

	tr.Add("call-1")
	tr.Add("call-2")
	tr.Add("call-3")

	active := tr.AllActive()
	if len(active) != 3 {
		t.Fatalf("expected 3 active, got %d", len(active))
	}

	tr.Remove("call-2")
	time.Sleep(100 * time.Millisecond)

	active = tr.AllActive()
	if len(active) != 2 {
		t.Fatalf("expected 2 active after removal, got %d", len(active))
	}
}
