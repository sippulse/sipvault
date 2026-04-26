package buffer

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	frame := []byte("hello world frame")
	if err := buf.Write(frame); err != nil {
		t.Fatal(err)
	}

	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if !bytes.Equal(frames[0], frame) {
		t.Fatalf("frame mismatch: got %q, want %q", frames[0], frame)
	}
}

func TestMultipleFramesOrder(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	data := [][]byte{
		[]byte("frame-0"),
		[]byte("frame-1"),
		[]byte("frame-2"),
		[]byte("frame-3"),
		[]byte("frame-4"),
	}

	for _, d := range data {
		if err := buf.Write(d); err != nil {
			t.Fatal(err)
		}
	}

	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != len(data) {
		t.Fatalf("expected %d frames, got %d", len(data), len(frames))
	}
	for i, f := range frames {
		if !bytes.Equal(f, data[i]) {
			t.Fatalf("frame %d: got %q, want %q", i, f, data[i])
		}
	}
}

func TestSizeLimitEnforcement(t *testing.T) {
	dir := t.TempDir()
	// Small max size: 1024 bytes
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	// Each frame is 100 bytes + 4 bytes length prefix = 104 bytes.
	// 1024 / 104 = 9 frames max before hitting limit.
	frame := make([]byte, 100)
	for i := range frame {
		frame[i] = byte(i)
	}

	// Write 9 frames (9 * 104 = 936, under limit).
	for i := 0; i < 9; i++ {
		if err := buf.Write(frame); err != nil {
			t.Fatal(err)
		}
	}

	if buf.Size() != 936 {
		t.Fatalf("expected size 936, got %d", buf.Size())
	}

	// Writing a 10th frame would push to 1040 > 1024 so buffer truncates first.
	if err := buf.Write(frame); err != nil {
		t.Fatal(err)
	}

	// Buffer should now contain only the last frame.
	if buf.Size() != 104 {
		t.Fatalf("after overflow, expected size 104, got %d", buf.Size())
	}

	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame after overflow, got %d", len(frames))
	}
}

func TestClearResetsToZero(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	if err := buf.Write([]byte("some data")); err != nil {
		t.Fatal(err)
	}
	if buf.Size() == 0 {
		t.Fatal("expected non-zero size after write")
	}

	if err := buf.Clear(); err != nil {
		t.Fatal(err)
	}
	if buf.Size() != 0 {
		t.Fatalf("expected size 0 after clear, got %d", buf.Size())
	}

	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 0 {
		t.Fatalf("expected 0 frames after clear, got %d", len(frames))
	}
}

func TestEmptyBufferReadsEmptySlice(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	frames, err := buf.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if frames != nil {
		t.Fatalf("expected nil for empty buffer, got %d frames", len(frames))
	}
}

func TestSize(t *testing.T) {
	dir := t.TempDir()
	buf, err := NewDiskBuffer(filepath.Join(dir, "buffer.dat"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()

	if buf.Size() != 0 {
		t.Fatalf("expected initial size 0, got %d", buf.Size())
	}

	// 10 bytes data + 4 bytes prefix = 14
	if err := buf.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if buf.Size() != 14 {
		t.Fatalf("expected size 14, got %d", buf.Size())
	}
}
