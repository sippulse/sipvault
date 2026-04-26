//go:build !ebpf || !linux

package ebpf

import (
	"errors"

	"github.com/sippulse/sipvault/internal/capture"
)

// Available reports that the eBPF backend is NOT compiled in. The default
// build (no `-tags ebpf`) and any non-Linux build emit this stub.
const Available = false

// Source is a non-functional placeholder used when the binary is built
// without the `ebpf` tag or for a non-Linux target.
type Source struct {
	events chan capture.CaptureEvent
}

// NewSource always returns an error explaining how to enable eBPF support.
func NewSource(iface string, sipPorts []int, rtpMin, rtpMax int, rtpChecker func(int) bool) (*Source, error) {
	return nil, errors.New("ebpf: backend not compiled in. Rebuild with `-tags ebpf` on a Linux host (or use mode = pcap)")
}

// Events returns nil on the stub.
func (s *Source) Events() <-chan capture.CaptureEvent {
	if s == nil {
		return nil
	}
	return s.events
}

// Close is a no-op on the stub.
func (s *Source) Close() error { return nil }
