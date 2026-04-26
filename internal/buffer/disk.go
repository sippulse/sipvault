package buffer

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
)

// DiskBuffer is an append-only disk-backed buffer for wire protocol frames.
// When the buffer exceeds maxSize, it is truncated (oldest data discarded).
type DiskBuffer struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	file    *os.File
	size    int64
}

// NewDiskBuffer opens or creates a buffer file at path with the given max size.
func NewDiskBuffer(path string, maxSize int64) (*DiskBuffer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	return &DiskBuffer{
		path:    path,
		maxSize: maxSize,
		file:    f,
		size:    info.Size(),
	}, nil
}

// Write appends a length-prefixed frame to the buffer.
// Each entry is stored as: [4-byte big-endian length][frame bytes].
// If the buffer would exceed maxSize, it is truncated first.
func (b *DiskBuffer) Write(frame []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	entrySize := int64(4 + len(frame))

	// If adding this frame would exceed max, truncate the file.
	if b.size+entrySize > b.maxSize {
		if err := b.file.Truncate(0); err != nil {
			return err
		}
		if _, err := b.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		b.size = 0
	}

	// Write length prefix.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if _, err := b.file.Write(lenBuf[:]); err != nil {
		return err
	}

	// Write frame data.
	if _, err := b.file.Write(frame); err != nil {
		return err
	}

	b.size += entrySize
	return nil
}

// ReadAll reads all buffered frames and returns them in order.
func (b *DiskBuffer) ReadAll() ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size == 0 {
		return nil, nil
	}

	if _, err := b.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var frames [][]byte
	for {
		var lenBuf [4]byte
		_, err := io.ReadFull(b.file, lenBuf[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}

		frameLen := binary.BigEndian.Uint32(lenBuf[:])
		frame := make([]byte, frameLen)
		_, err = io.ReadFull(b.file, frame)
		if err != nil {
			return nil, err
		}

		frames = append(frames, frame)
	}

	return frames, nil
}

// Clear truncates the buffer file to zero bytes.
func (b *DiskBuffer) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.file.Truncate(0); err != nil {
		return err
	}
	if _, err := b.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	b.size = 0
	return nil
}

// Close closes the underlying file.
func (b *DiskBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.file.Close()
}

// Size returns the current buffer size in bytes.
func (b *DiskBuffer) Size() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}
