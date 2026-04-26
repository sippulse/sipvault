package capture

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/sippulse/sipvault/internal/logfilter"
	"github.com/sippulse/sipvault/internal/mux"
	"github.com/sippulse/sipvault/internal/rtcp"
	"github.com/sippulse/sipvault/internal/rtp"
	"github.com/sippulse/sipvault/internal/sip"
	"github.com/sippulse/sipvault/internal/tracker"
)

// EventType identifies the kind of captured data.
type EventType int

const (
	EventSIP  EventType = iota
	EventRTCP
	EventLog
	EventRTP
)

// CaptureEvent represents a raw captured packet or log line.
type CaptureEvent struct {
	Type      EventType
	Timestamp int64 // nanoseconds
	Data      []byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
}

// Source abstracts an eBPF ring buffer or any other event source.
type Source interface {
	Events() <-chan CaptureEvent
	Close() error
}

// rtpStreamMeta tracks metadata for an RTP stream being analyzed.
type rtpStreamMeta struct {
	callID string
	codec  string
}

// Reader dispatches captured events through parsers, tracker, and filter
// to the sender.
type Reader struct {
	source      Source
	tracker     *tracker.Tracker
	filter      *logfilter.Filter
	sender      mux.FrameSender
	analyzers   map[uint32]*rtp.Analyzer   // SSRC → Analyzer
	streamMeta  map[uint32]*rtpStreamMeta  // SSRC → call/codec metadata
}

// NewReader creates a new capture event reader/dispatcher.
func NewReader(source Source, tracker *tracker.Tracker, filter *logfilter.Filter, sender mux.FrameSender) *Reader {
	return &Reader{
		source:     source,
		tracker:    tracker,
		filter:     filter,
		sender:     sender,
		analyzers:  make(map[uint32]*rtp.Analyzer),
		streamMeta: make(map[uint32]*rtpStreamMeta),
	}
}

// Run reads events from the source and dispatches them until the context
// is cancelled or the event channel is closed.
func (r *Reader) Run(ctx context.Context) error {
	events := r.source.Events()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			switch ev.Type {
			case EventSIP:
				r.handleSIP(ev)
			case EventRTCP:
				r.handleRTCP(ev)
			case EventLog:
				r.handleLog(ev)
			case EventRTP:
				r.handleRTP(ev)
			}
		}
	}
}

// handleSIP parses a SIP message, updates the tracker, extracts SDP
// SSRC mappings, and sends a DATA_SIP frame.
func (r *Reader) handleSIP(ev CaptureEvent) {
	msg, err := sip.ParseMessage(ev.Data)
	if err != nil {
		n := len(ev.Data); if n > 60 { n = 60 }
		log.Printf("SIP parse error (%d bytes, first 60: %q): %v", len(ev.Data), ev.Data[:n], err)
		return
	}
	if !msg.IsResponse && msg.Method == "INVITE" {
		log.Printf("INVITE captured: Call-ID=%s", msg.CallID)
	}

	callID := msg.CallID

	// Track call based on method.
	if !msg.IsResponse {
		switch msg.Method {
		case "INVITE":
			r.tracker.Add(callID)
		case "BYE", "CANCEL":
			// Send RTP-derived quality report before removing the call.
			r.sendRTPQuality(callID)
			r.tracker.Remove(callID)
		}
	}

	// Extract SSRC from SDP body if present.
	if len(msg.Body) > 0 {
		sdpInfo, err := sip.ParseSDP(msg.Body)
		if err == nil {
			if sdpInfo.SSRC != 0 {
				r.tracker.MapSSRC(sdpInfo.SSRC, callID)
			}
			log.Printf("SDP parsed: Call-ID=%s port=%d rtcp=%v rtcpPort=%d codecs=%v ssrc=%d",
				callID, sdpInfo.MediaPort, sdpInfo.RTCPEnabled, sdpInfo.RTCPPort, sdpInfo.Codecs, sdpInfo.SSRC)
			// When no RTCP is expected, register the media port for RTP capture.
			if !sdpInfo.RTCPEnabled && sdpInfo.MediaPort > 0 {
				log.Printf("RTP capture activated for Call-ID=%s port=%d (no RTCP)", callID, sdpInfo.MediaPort)
				r.tracker.MapMediaPort(sdpInfo.MediaPort, &tracker.MediaInfo{
					CallID:      callID,
					SSRC:        sdpInfo.SSRC,
					Port:        sdpInfo.MediaPort,
					ClockRate:   rtp.ClockRate(0), // default 8000 Hz
					Codec:       firstCodec(sdpInfo.Codecs),
					RTCPEnabled: false,
				})
			}
		}
	}

	// Determine direction: 0x00 = outbound (from our perspective, just use 0).
	dir := byte(0x00)

	payload := mux.BuildDataSIP(ev.Timestamp, callID, dir, ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.Data)
	f := &mux.Frame{
		Type:    mux.FrameDataSIP,
		Payload: payload,
	}
	r.sender.Send(f)
}

// handleRTCP parses RTCP to get the SSRC, looks up the corresponding
// Call-ID, and sends a DATA_RTCP frame.
func (r *Reader) handleRTCP(ev CaptureEvent) {
	// Parse to extract SSRC.
	pkt, err := rtcp.ParsePacket(ev.Data)
	if err != nil {
		return
	}

	var ssrc uint32
	if pkt.SenderReport != nil {
		ssrc = pkt.SenderReport.SSRC
	} else if pkt.ReceiverReport != nil {
		ssrc = pkt.ReceiverReport.SSRC
	} else {
		return
	}

	callID, ok := r.tracker.LookupSSRC(ssrc)
	if !ok {
		return
	}

	payload := mux.BuildDataRTCP(ev.Timestamp, callID, ssrc, ev.Data)
	f := &mux.Frame{
		Type:    mux.FrameDataRTCP,
		Payload: payload,
	}
	r.sender.Send(f)
}

// handleLog filters a log line for tracked Call-IDs and sends
// matching lines as DATA_LOG frames.
func (r *Reader) handleLog(ev CaptureEvent) {
	callID, ok := r.filter.Match(ev.Data)
	if !ok {
		return
	}

	ts := ev.Timestamp
	if ts == 0 {
		ts = time.Now().UnixNano()
	}

	payload := mux.BuildDataLog(ts, callID, ev.Data)
	f := &mux.Frame{
		Type:    mux.FrameDataLog,
		Payload: payload,
	}
	r.sender.Send(f)
}

// handleRTP parses an RTP header and feeds it to the per-SSRC Analyzer
// for streams where RTCP is not available.
func (r *Reader) handleRTP(ev CaptureEvent) {
	info, ok := r.tracker.LookupMediaPort(int(ev.DstPort))
	if !ok {
		info, ok = r.tracker.LookupMediaPort(int(ev.SrcPort))
	}
	if !ok {
		return
	}

	hdr, err := rtp.ParseHeader(ev.Data)
	if err != nil {
		return
	}

	// Get or create an Analyzer for this SSRC.
	analyzer, exists := r.analyzers[hdr.SSRC]
	if !exists {
		clockRate := rtp.ClockRate(hdr.PayloadType)
		analyzer = rtp.NewAnalyzer(hdr.SSRC, clockRate)
		r.analyzers[hdr.SSRC] = analyzer
		r.streamMeta[hdr.SSRC] = &rtpStreamMeta{
			callID: info.CallID,
			codec:  info.Codec,
		}
	}

	receiveTime := time.Unix(0, ev.Timestamp)
	analyzer.Process(hdr, receiveTime)
}

// sendRTPQuality collects RTP analyzers for a call, builds a quality report,
// and sends it to the server as a FrameDataQuality frame.
func (r *Reader) sendRTPQuality(callID string) {
	// Collect all streams belonging to this call.
	var streams []rtp.StreamInfo
	var ssrcsToClean []uint32

	dirIndex := 0
	directions := []string{"uac", "uas"}

	for ssrc, meta := range r.streamMeta {
		if meta.callID != callID {
			continue
		}
		analyzer, ok := r.analyzers[ssrc]
		if !ok {
			continue
		}
		stats := analyzer.Stats()
		if stats.PacketsReceived == 0 {
			continue
		}

		dir := "uac"
		if dirIndex < len(directions) {
			dir = directions[dirIndex]
			dirIndex++
		}

		streams = append(streams, rtp.StreamInfo{
			Analyzer:  analyzer,
			Direction: dir,
			Codec:     meta.codec,
		})
		ssrcsToClean = append(ssrcsToClean, ssrc)
	}

	// Clean up analyzers and metadata for this call.
	for _, ssrc := range ssrcsToClean {
		delete(r.analyzers, ssrc)
		delete(r.streamMeta, ssrc)
	}

	if len(streams) == 0 {
		return
	}

	report := rtp.BuildMultiStreamReport(callID, streams)
	if report == nil {
		return
	}

	qualityJSON, err := json.Marshal(report)
	if err != nil {
		log.Printf("RTP quality marshal error for %s: %v", callID, err)
		return
	}

	payload := mux.BuildDataQuality(time.Now().UnixNano(), callID, qualityJSON)
	f := &mux.Frame{
		Type:    mux.FrameDataQuality,
		Payload: payload,
	}
	r.sender.Send(f)
	log.Printf("RTP quality sent for %s: %d streams, verdict=%s", callID, len(streams), report.Verdict)
}

// firstCodec returns the first codec name from a list, or "unknown".
func firstCodec(codecs []string) string {
	if len(codecs) > 0 {
		return codecs[0]
	}
	return "unknown"
}
