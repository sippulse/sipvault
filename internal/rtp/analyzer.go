package rtp

import (
	"math"
	"time"
)

// StreamStats holds computed statistics for a single RTP stream.
type StreamStats struct {
	SSRC            uint32
	PacketsReceived int
	PacketsLost     int
	LossPercent     float64
	JitterMs        float64
	FirstSeq        uint16
	LastSeq         uint16
	Duration        time.Duration
}

// Analyzer tracks state for a single RTP stream and computes RFC 3550 jitter.
type Analyzer struct {
	ssrc      uint32
	clockRate int

	count    int
	firstSeq uint16
	lastSeq  uint16

	firstReceive time.Time
	lastReceive  time.Time

	// RFC 3550 jitter state (in RTP timestamp units)
	prevRecvTime time.Time
	prevRTPTS    uint32
	jitter       float64 // running estimate in RTP timestamp units
}

// NewAnalyzer creates an Analyzer for the given SSRC and clock rate (Hz).
func NewAnalyzer(ssrc uint32, clockRate int) *Analyzer {
	return &Analyzer{
		ssrc:      ssrc,
		clockRate: clockRate,
	}
}

// Process records an arriving RTP packet.
func (a *Analyzer) Process(hdr *Header, receiveTime time.Time) {
	if a.count == 0 {
		a.firstSeq = hdr.SequenceNumber
		a.firstReceive = receiveTime
		a.prevRecvTime = receiveTime
		a.prevRTPTS = hdr.Timestamp
	} else {
		// RFC 3550 §A.8 jitter calculation.
		// D(i,j) = (Rj - Ri) - (Sj - Si)
		// where R is wall-clock in RTP timestamp units, S is RTP timestamp.
		recvDiff := receiveTime.Sub(a.prevRecvTime).Seconds() * float64(a.clockRate)
		rtpDiff := float64(int32(hdr.Timestamp - a.prevRTPTS)) // signed 32-bit wrap-safe subtraction
		d := math.Abs(recvDiff - rtpDiff)
		// J(i) = J(i-1) + (|D| - J(i-1)) / 16
		a.jitter += (d - a.jitter) / 16.0

		a.prevRecvTime = receiveTime
		a.prevRTPTS = hdr.Timestamp
	}

	a.lastSeq = hdr.SequenceNumber
	a.lastReceive = receiveTime
	a.count++
}

// Stats returns the computed statistics for the stream so far.
func (a *Analyzer) Stats() StreamStats {
	if a.count == 0 {
		return StreamStats{SSRC: a.ssrc}
	}

	// Expected packets accounts for uint16 wraparound.
	expected := int(uint16(a.lastSeq-a.firstSeq)) + 1
	lost := expected - a.count
	if lost < 0 {
		lost = 0
	}
	var lossPct float64
	if expected > 0 {
		lossPct = float64(lost) / float64(expected) * 100.0
	}

	// Convert jitter from RTP timestamp units to milliseconds.
	jitterMs := (a.jitter / float64(a.clockRate)) * 1000.0

	return StreamStats{
		SSRC:            a.ssrc,
		PacketsReceived: a.count,
		PacketsLost:     lost,
		LossPercent:     lossPct,
		JitterMs:        jitterMs,
		FirstSeq:        a.firstSeq,
		LastSeq:         a.lastSeq,
		Duration:        a.lastReceive.Sub(a.firstReceive),
	}
}

// Reset clears all accumulated state.
func (a *Analyzer) Reset() {
	a.count = 0
	a.firstSeq = 0
	a.lastSeq = 0
	a.firstReceive = time.Time{}
	a.lastReceive = time.Time{}
	a.prevRecvTime = time.Time{}
	a.prevRTPTS = 0
	a.jitter = 0
}
