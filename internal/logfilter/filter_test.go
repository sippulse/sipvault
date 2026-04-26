package logfilter

import (
	"testing"
	"time"

	"github.com/sippulse/sipvault/internal/tracker"
)

func TestMatch_TrackedCallID(t *testing.T) {
	tr := tracker.New(5 * time.Second)
	tr.Add("abc123@host.example.com")

	f := New(tr)

	line := []byte("Mar 13 12:00:00 opensips[1234]: ACC: call abc123@host.example.com ended")
	callID, ok := f.Match(line)
	if !ok {
		t.Fatal("expected match")
	}
	if callID != "abc123@host.example.com" {
		t.Fatalf("callID: got %q", callID)
	}
}

func TestMatch_UntrackedCallID(t *testing.T) {
	tr := tracker.New(5 * time.Second)
	tr.Add("tracked-call@host")

	f := New(tr)

	line := []byte("Mar 13 12:00:00 opensips[1234]: ACC: call different-call@other ended")
	_, ok := f.Match(line)
	if ok {
		t.Fatal("should not match untracked call")
	}
}

func TestMatch_NoCallIDInLine(t *testing.T) {
	tr := tracker.New(5 * time.Second)
	tr.Add("some-call@host")

	f := New(tr)

	line := []byte("Mar 13 12:00:00 opensips[1234]: started successfully")
	_, ok := f.Match(line)
	if ok {
		t.Fatal("should not match line without any call-id")
	}
}

func TestMatch_MultipleTracked(t *testing.T) {
	tr := tracker.New(5 * time.Second)
	tr.Add("call-A@host")
	tr.Add("call-B@host")
	tr.Add("call-C@host")

	f := New(tr)

	line := []byte("Mar 13 12:00:00 opensips[1234]: processing call-B@host route")
	callID, ok := f.Match(line)
	if !ok {
		t.Fatal("expected match")
	}
	if callID != "call-B@host" {
		t.Fatalf("callID: got %q, want call-B@host", callID)
	}
}

func TestMatch_ExpiredCallID(t *testing.T) {
	tr := tracker.New(50 * time.Millisecond)
	tr.Add("expired-call@host")
	tr.Remove("expired-call@host")

	f := New(tr)

	// During grace period it should still match.
	line := []byte("log line with expired-call@host")
	callID, ok := f.Match(line)
	if !ok {
		t.Fatal("expected match during grace period")
	}
	if callID != "expired-call@host" {
		t.Fatalf("callID: got %q", callID)
	}

	// After grace period.
	time.Sleep(100 * time.Millisecond)
	_, ok = f.Match(line)
	if ok {
		t.Fatal("should not match after grace period")
	}
}

func TestMatch_EmptyLine(t *testing.T) {
	tr := tracker.New(5 * time.Second)
	tr.Add("call@host")

	f := New(tr)

	_, ok := f.Match(nil)
	if ok {
		t.Fatal("nil line should not match")
	}

	_, ok = f.Match([]byte{})
	if ok {
		t.Fatal("empty line should not match")
	}
}
