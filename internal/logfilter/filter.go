package logfilter

import (
	"bytes"

	"github.com/sippulse/sipvault/internal/tracker"
)

// Filter scans log lines for active Call-IDs using a Tracker.
type Filter struct {
	tracker *tracker.Tracker
}

// New creates a Filter backed by the given Tracker.
func New(t *tracker.Tracker) *Filter {
	return &Filter{tracker: t}
}

// Match scans a log line for any tracked Call-ID. If found, it returns
// the matching Call-ID and true. If no active Call-ID is found in the
// line, it returns ("", false).
func (f *Filter) Match(line []byte) (callID string, ok bool) {
	active := f.tracker.AllActive()
	for _, cid := range active {
		if bytes.Contains(line, []byte(cid)) {
			return cid, true
		}
	}
	return "", false
}
