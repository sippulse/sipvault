//go:build !pcap

package pcap

import (
	"fmt"

	"github.com/sippulse/sipvault/internal/capture"
)

// Source is a stub when built without the pcap tag.
type Source struct {
	events chan capture.CaptureEvent
}

// NewSource returns an error indicating that pcap support was not compiled in.
func NewSource(iface string, sipPorts []int, rtpPortMin, rtpPortMax int, rtpChecker func(int) bool) (*Source, error) {
	return nil, fmt.Errorf("pcap not available: build with -tags pcap")
}

// Events returns a read-only channel. On the stub it returns nil.
func (s *Source) Events() <-chan capture.CaptureEvent {
	if s == nil {
		return nil
	}
	return s.events
}

// Close is a no-op on the stub.
func (s *Source) Close() error {
	return nil
}
