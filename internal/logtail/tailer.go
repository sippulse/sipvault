package logtail

import (
	"bufio"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sippulse/sipvault/internal/capture"
)

const pollInterval = 200 * time.Millisecond

// Tailer watches a log file and emits new lines as CaptureEvents.
// It handles log rotation by detecting file truncation or inode changes.
type Tailer struct {
	path   string
	events chan capture.CaptureEvent
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewTailer creates a Tailer that tails the given log file path.
// Only new lines appended after the tailer starts are emitted.
func NewTailer(path string) (*Tailer, error) {
	// Verify the file exists and is readable.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	t := &Tailer{
		path:   path,
		events: make(chan capture.CaptureEvent, 256),
		done:   make(chan struct{}),
	}

	t.wg.Add(1)
	go t.run(info.Size())
	return t, nil
}

// Events returns a read-only channel of CaptureEvents (EventLog).
func (t *Tailer) Events() <-chan capture.CaptureEvent {
	return t.events
}

// Close stops the tailer and waits for the goroutine to exit.
func (t *Tailer) Close() error {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	t.wg.Wait()
	return nil
}

func (t *Tailer) run(startOffset int64) {
	defer t.wg.Done()
	defer close(t.events)

	offset := startOffset
	var lastInode uint64
	if ino, err := fileInode(t.path); err == nil {
		lastInode = ino
	}

	for {
		select {
		case <-t.done:
			return
		default:
		}

		info, err := os.Stat(t.path)
		if err != nil {
			// File may be temporarily gone during rotation.
			t.sleep()
			continue
		}

		currentInode, _ := fileInode(t.path)

		// Detect rotation: file truncated or inode changed.
		if info.Size() < offset || (lastInode != 0 && currentInode != lastInode) {
			offset = 0
			lastInode = currentInode
		}

		if info.Size() > offset {
			newOffset := t.readLines(offset)
			if newOffset > offset {
				offset = newOffset
			}
		}

		t.sleep()
	}
}

func (t *Tailer) readLines(offset int64) int64 {
	f, err := os.Open(t.path)
	if err != nil {
		return offset
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}

	scanner := bufio.NewScanner(f)
	pos := offset
	for scanner.Scan() {
		line := scanner.Bytes()
		pos += int64(len(line)) + 1 // +1 for newline

		if len(line) == 0 {
			continue
		}

		// Copy the line since scanner reuses the buffer.
		data := make([]byte, len(line))
		copy(data, line)

		ev := capture.CaptureEvent{
			Type:      capture.EventLog,
			Timestamp: time.Now().UnixNano(),
			Data:      data,
		}

		select {
		case t.events <- ev:
		case <-t.done:
			return pos
		}
	}

	// If scan ended without error, we consumed up to here.
	// If there was no final newline, the scanner may have stopped
	// before the actual EOF. Use the file position to be precise.
	currentPos, err := f.Seek(0, io.SeekCurrent)
	if err == nil && currentPos > pos {
		// There may be a partial line without a trailing newline;
		// leave it for the next read by not advancing past pos.
	}

	return pos
}

func (t *Tailer) sleep() {
	select {
	case <-t.done:
	case <-time.After(pollInterval):
	}
}
