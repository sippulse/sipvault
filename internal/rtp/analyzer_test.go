package rtp

import (
	"testing"
	"time"
)

// makePerfectStream generates count headers with sequential sequence numbers
// and perfectly spaced RTP timestamps (20ms ptime @ 8kHz = 160 samples/packet).
func makePerfectStream(count int, startSeq uint16, startTS uint32, clockRate int) []*Header {
	samplesPerPacket := uint32(clockRate / 50) // 20ms ptime
	hdrs := make([]*Header, count)
	for i := 0; i < count; i++ {
		hdrs[i] = &Header{
			SequenceNumber: startSeq + uint16(i),
			Timestamp:      startTS + uint32(i)*samplesPerPacket,
			SSRC:           0x1234,
			PayloadType:    0,
		}
	}
	return hdrs
}

func TestAnalyzer_NoLoss(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond
	hdrs := makePerfectStream(100, 1, 0, 8000)

	for i, hdr := range hdrs {
		a.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	s := a.Stats()
	if s.PacketsReceived != 100 {
		t.Errorf("PacketsReceived: got %d, want 100", s.PacketsReceived)
	}
	if s.PacketsLost != 0 {
		t.Errorf("PacketsLost: got %d, want 0", s.PacketsLost)
	}
	if s.LossPercent != 0 {
		t.Errorf("LossPercent: got %.2f, want 0", s.LossPercent)
	}
}

func TestAnalyzer_WithLoss(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond
	hdrs := makePerfectStream(100, 1, 0, 8000)

	// Skip every 10th packet (indices 9, 19, 29, ...) → ~10% loss.
	sent := 0
	wall := now
	for i, hdr := range hdrs {
		if (i+1)%10 == 0 {
			// Simulate loss: advance wall clock but don't Process.
			wall = wall.Add(ptime)
			continue
		}
		a.Process(hdr, wall)
		wall = wall.Add(ptime)
		sent++
	}

	s := a.Stats()
	if s.PacketsReceived != sent {
		t.Errorf("PacketsReceived: got %d, want %d", s.PacketsReceived, sent)
	}
	if s.PacketsLost == 0 {
		t.Error("expected non-zero PacketsLost")
	}
	// Loss should be around 10%.
	if s.LossPercent < 5 || s.LossPercent > 15 {
		t.Errorf("LossPercent: got %.2f, expected ~10%%", s.LossPercent)
	}
}

func TestAnalyzer_JitterComputation(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond
	hdrs := makePerfectStream(200, 1, 0, 8000)

	// Perfect timing: receive exactly at 20ms intervals.
	for i, hdr := range hdrs {
		a.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	s := a.Stats()
	// With perfect timing the jitter should converge very close to 0.
	if s.JitterMs > 0.5 {
		t.Errorf("JitterMs with perfect timing: got %.4f ms, want < 0.5 ms", s.JitterMs)
	}
}

func TestAnalyzer_JitterWithVariation(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond

	// ±5ms variation on each packet arrival.
	variation := []time.Duration{
		+5 * time.Millisecond,
		-5 * time.Millisecond,
		+5 * time.Millisecond,
		-5 * time.Millisecond,
	}

	samplesPerPacket := uint32(8000 / 50) // 160
	for i := 0; i < 200; i++ {
		hdr := &Header{
			SequenceNumber: uint16(i + 1),
			Timestamp:      uint32(i) * samplesPerPacket,
			SSRC:           0x1234,
		}
		offset := variation[i%len(variation)]
		a.Process(hdr, now.Add(time.Duration(i)*ptime+offset))
	}

	s := a.Stats()
	// With ±5ms variation we expect measurable jitter (> 0.5 ms).
	if s.JitterMs < 0.5 {
		t.Errorf("JitterMs with ±5ms variation: got %.4f ms, want > 0.5 ms", s.JitterMs)
	}
	// Sanity upper bound.
	if s.JitterMs > 20 {
		t.Errorf("JitterMs unexpectedly large: %.4f ms", s.JitterMs)
	}
}

func TestAnalyzer_TimestampWraparound(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond

	// Start near uint32 max so timestamps wrap around during the stream.
	startTS := uint32(0xFFFFFF00)
	hdrs := makePerfectStream(200, 1, startTS, 8000)

	for i, hdr := range hdrs {
		a.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	s := a.Stats()
	if s.JitterMs > 0.5 {
		t.Errorf("JitterMs with timestamp wraparound: got %.4f ms, want < 0.5 ms", s.JitterMs)
	}
	if s.PacketsLost != 0 {
		t.Errorf("PacketsLost: got %d, want 0", s.PacketsLost)
	}
	if s.PacketsReceived != 200 {
		t.Errorf("PacketsReceived: got %d, want 200", s.PacketsReceived)
	}
}

func TestAnalyzer_SeqNumberWraparound(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond

	// Start at seq 65530 so it wraps to 0 at 65536.
	hdrs := makePerfectStream(20, 65530, 0, 8000)

	for i, hdr := range hdrs {
		a.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	s := a.Stats()
	if s.PacketsLost != 0 {
		t.Errorf("PacketsLost: got %d, want 0", s.PacketsLost)
	}
	if s.PacketsReceived != 20 {
		t.Errorf("PacketsReceived: got %d, want 20", s.PacketsReceived)
	}
}

func TestAnalyzer_PacketReordering(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond

	hdrs := makePerfectStream(10, 0, 0, 8000)

	// Send in reordered sequence: [0,2,1,3,5,4,6,7,8,9]
	order := []int{0, 2, 1, 3, 5, 4, 6, 7, 8, 9}
	for i, idx := range order {
		a.Process(hdrs[idx], now.Add(time.Duration(i)*ptime))
	}

	s := a.Stats()
	if s.PacketsLost != 0 {
		t.Errorf("PacketsLost: got %d, want 0", s.PacketsLost)
	}
	// Reordered packets cause elevated jitter because RTP timestamps
	// arrive out of order relative to wall-clock.
	if s.JitterMs <= 0 {
		t.Errorf("JitterMs: got %.4f, want > 0 due to reordering", s.JitterMs)
	}
}

func TestAnalyzer_BurstLoss(t *testing.T) {
	a := NewAnalyzer(0x1234, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond

	hdrs := makePerfectStream(100, 0, 0, 8000)

	// Send all packets except indices 50-59 (10 consecutive lost).
	wall := now
	for i, hdr := range hdrs {
		if i >= 50 && i <= 59 {
			wall = wall.Add(ptime) // advance time but skip packet
			continue
		}
		a.Process(hdr, wall)
		wall = wall.Add(ptime)
	}

	s := a.Stats()
	if s.PacketsReceived != 90 {
		t.Errorf("PacketsReceived: got %d, want 90", s.PacketsReceived)
	}
	// Loss should be approximately 10%.
	if s.LossPercent < 8 || s.LossPercent > 12 {
		t.Errorf("LossPercent: got %.2f, want ~10%%", s.LossPercent)
	}
}

func BenchmarkAnalyzer_Process(b *testing.B) {
	hdrs := makePerfectStream(1000, 0, 0, 8000)
	ptime := 20 * time.Millisecond
	now := time.Now()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		a := NewAnalyzer(0x1234, 8000)
		for i, hdr := range hdrs {
			a.Process(hdr, now.Add(time.Duration(i)*ptime))
		}
	}
}
