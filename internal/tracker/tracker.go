package tracker

import (
	"sync"
	"time"
)

// MediaInfo holds metadata about an RTP media stream associated with a call.
type MediaInfo struct {
	CallID      string
	SSRC        uint32
	Port        int
	ClockRate   int
	Codec       string
	RTCPEnabled bool
}

// Tracker maintains a thread-safe registry of active Call-IDs and
// an SSRC-to-Call-ID mapping for correlating RTCP packets.
type Tracker struct {
	mu       sync.RWMutex
	calls    map[string]time.Time // Call-ID → last seen (or removal deadline)
	removed  map[string]time.Time // Call-ID → expiry time (grace period)
	ssrcMap  map[uint32]string    // SSRC → Call-ID
	mediaMap map[int]*MediaInfo   // media port → MediaInfo
	grace    time.Duration
}

// New creates a Tracker with the given grace period after Remove().
func New(grace time.Duration) *Tracker {
	return &Tracker{
		calls:    make(map[string]time.Time),
		removed:  make(map[string]time.Time),
		ssrcMap:  make(map[uint32]string),
		mediaMap: make(map[int]*MediaInfo),
		grace:    grace,
	}
}

// Add registers or refreshes a Call-ID as active. If the Call-ID was
// previously marked for removal, it is restored.
func (t *Tracker) Add(callID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls[callID] = time.Now()
	delete(t.removed, callID)
}

// Remove marks a Call-ID for removal after the grace period expires.
// The Call-ID remains active (IsActive returns true) during the grace period.
func (t *Tracker) Remove(callID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.calls[callID]; ok {
		t.removed[callID] = time.Now().Add(t.grace)
	}
}

// IsActive returns true if the Call-ID is tracked and has not expired
// past its grace period.
func (t *Tracker) IsActive(callID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if _, ok := t.calls[callID]; !ok {
		return false
	}
	// If in removed set, check if grace period has elapsed.
	if deadline, ok := t.removed[callID]; ok {
		return time.Now().Before(deadline)
	}
	return true
}

// MapSSRC associates an SSRC with a Call-ID.
func (t *Tracker) MapSSRC(ssrc uint32, callID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ssrcMap[ssrc] = callID
}

// LookupSSRC returns the Call-ID associated with an SSRC.
func (t *Tracker) LookupSSRC(ssrc uint32) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	cid, ok := t.ssrcMap[ssrc]
	return cid, ok
}

// MapMediaPort registers an RTP media port and its associated MediaInfo.
func (t *Tracker) MapMediaPort(port int, info *MediaInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mediaMap[port] = info
}

// LookupMediaPort returns the MediaInfo associated with the given port.
func (t *Tracker) LookupMediaPort(port int) (*MediaInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.mediaMap[port]
	return info, ok
}

// NeedsRTPCapture returns true if the port is tracked and RTCPEnabled is false,
// meaning we should capture raw RTP headers for quality analysis.
func (t *Tracker) NeedsRTPCapture(port int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.mediaMap[port]
	return ok && !info.RTCPEnabled
}

// Cleanup removes entries whose grace period has expired. This should be
// called periodically.
func (t *Tracker) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for callID, deadline := range t.removed {
		if now.After(deadline) {
			// Collect SSRCs pointing to this call.
			for ssrc, cid := range t.ssrcMap {
				if cid == callID {
					delete(t.ssrcMap, ssrc)
				}
			}
			// Collect media ports belonging to this call.
			for port, info := range t.mediaMap {
				if info.CallID == callID {
					delete(t.mediaMap, port)
				}
			}
			delete(t.calls, callID)
			delete(t.removed, callID)
		}
	}
}

// ActiveCount returns the number of currently active Call-IDs
// (including those within the grace period).
func (t *Tracker) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	count := 0
	for callID := range t.calls {
		if deadline, ok := t.removed[callID]; ok {
			if now.Before(deadline) {
				count++
			}
		} else {
			count++
		}
	}
	return count
}

// AllActive returns a snapshot of all active Call-IDs. Intended for use
// by the log filter to scan log lines.
func (t *Tracker) AllActive() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	result := make([]string, 0, len(t.calls))
	for callID := range t.calls {
		if deadline, ok := t.removed[callID]; ok {
			if now.After(deadline) {
				continue
			}
		}
		result = append(result, callID)
	}
	return result
}
