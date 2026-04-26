package logtail

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sippulse/sipvault/internal/capture"
)

// collectEvents reads events from a tailer for up to the given duration.
func collectEvents(t *testing.T, tailer *Tailer, timeout time.Duration) []capture.CaptureEvent {
	t.Helper()
	var events []capture.CaptureEvent
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-tailer.Events():
			if !ok {
				return events
			}
			events = append(events, ev)
		case <-deadline:
			return events
		}
	}
}

func TestTailer_NewLinesEmitted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Create file with some initial content that should NOT be emitted.
	if err := os.WriteFile(path, []byte("old line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tailer, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tailer.Close()

	// Wait for the tailer to start.
	time.Sleep(50 * time.Millisecond)

	// Append new lines.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("line1\n")
	f.WriteString("line2\n")
	f.Close()

	events := collectEvents(t, tailer, 600*time.Millisecond)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if string(events[0].Data) != "line1" {
		t.Fatalf("event 0: got %q, want %q", events[0].Data, "line1")
	}
	if string(events[1].Data) != "line2" {
		t.Fatalf("event 1: got %q, want %q", events[1].Data, "line2")
	}
	for _, ev := range events {
		if ev.Type != capture.EventLog {
			t.Fatalf("expected EventLog, got %d", ev.Type)
		}
		if ev.Timestamp == 0 {
			t.Fatal("expected non-zero timestamp")
		}
	}
}

func TestTailer_StartsFromEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Write content before starting the tailer.
	if err := os.WriteFile(path, []byte("pre-existing line 1\npre-existing line 2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tailer, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tailer.Close()

	// Wait and verify no events from pre-existing content.
	events := collectEvents(t, tailer, 500*time.Millisecond)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for pre-existing content, got %d", len(events))
	}
}

func TestTailer_LogRotation_Truncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	if err := os.WriteFile(path, []byte("initial\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tailer, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tailer.Close()

	// Wait for tailer to start.
	time.Sleep(50 * time.Millisecond)

	// Append a line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("before-rotate\n")
	f.Close()

	// Wait for it to be picked up.
	events := collectEvents(t, tailer, 500*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event before rotation, got %d", len(events))
	}

	// Truncate the file (simulate logrotate copytruncate).
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait a poll cycle.
	time.Sleep(300 * time.Millisecond)

	// Write new content after truncation.
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("after-rotate\n")
	f.Close()

	events = collectEvents(t, tailer, 600*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event after rotation, got %d", len(events))
	}
	if string(events[0].Data) != "after-rotate" {
		t.Fatalf("got %q, want %q", events[0].Data, "after-rotate")
	}
}

func TestTailer_CloseStops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	if err := os.WriteFile(path, []byte("init\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tailer, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}

	// Close should return promptly.
	done := make(chan struct{})
	go func() {
		tailer.Close()
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Close")
	}

	// Channel should be closed.
	_, ok := <-tailer.Events()
	if ok {
		t.Fatal("expected events channel to be closed after Close()")
	}
}

func TestTailer_EmptyFileNoEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	tailer, err := NewTailer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tailer.Close()

	events := collectEvents(t, tailer, 500*time.Millisecond)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty file, got %d", len(events))
	}
}

func TestTailer_NonexistentFileReturnsError(t *testing.T) {
	_, err := NewTailer("/nonexistent/path/test.log")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// Compile-time check that *Tailer implements capture.Source.
var _ capture.Source = (*Tailer)(nil)
