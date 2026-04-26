package rtp

import (
	"math"
	"sort"
)

// StatSummary holds aggregate statistics matching the server's quality.json format.
type StatSummary struct {
	Avg float64 `json:"avg"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
	P5  float64 `json:"p5"`
	P95 float64 `json:"p95"`
}

// DirectionStats holds per-direction quality metrics.
type DirectionStats struct {
	MOS    StatSummary `json:"mos"`
	Jitter StatSummary `json:"jitter"`
	Loss   StatSummary `json:"loss"`
	RTT    StatSummary `json:"rtt"`
}

// QualityReport is the top-level quality report written to quality.json.
type QualityReport struct {
	CallID     string                    `json:"call_id"`
	Verdict    string                    `json:"verdict"`
	Summary    QualitySummary            `json:"summary"`
	Directions map[string]DirectionStats `json:"directions"`
	Source     string                    `json:"source"` // "rtp"
}

// QualitySummary holds high-level call summary fields.
type QualitySummary struct {
	DurationSecs int    `json:"duration_seconds"`
	Codec        string `json:"codec"`
	SampleCount  int    `json:"sample_count"`
}

// mosFromStats computes MOS using the ITU-T G.107 E-model from jitter and loss.
//
// Id   = delay impairment derived from jitter (approximated as 2× one-way delay)
// Ie_eff = equipment impairment factor for given packet loss
// R    = 93.2 - Id - Ie_eff
// MOS  = 1 + 0.035*R + R*(R-60)*(100-R)*7e-6
func mosFromStats(jitterMs float64, lossPct float64) float64 {
	// Estimate one-way jitter-induced delay (buffer ~2× jitter).
	delayMs := jitterMs * 2.0

	// Id: delay impairment (ITU-T G.107 §B.3 simplified)
	var Id float64
	if delayMs < 177.3 {
		Id = 0.024*delayMs + 0.11*(delayMs-177.3)*heaviside(delayMs-177.3)
	} else {
		Id = 0.024*delayMs + 0.11*(delayMs-177.3)
	}

	// Ie_eff for G.711 (Ie=0, Bpl=25.1)
	const (
		Ie  = 0.0
		Bpl = 25.1
	)
	IeEff := Ie + (95-Ie)*lossPct/(lossPct+Bpl)

	R := 93.2 - Id - IeEff
	if R < 0 {
		R = 0
	}
	if R > 100 {
		R = 100
	}

	mos := 1 + 0.035*R + R*(R-60)*(100-R)*7e-6
	if mos < 1 {
		mos = 1
	}
	if mos > 4.5 {
		mos = 4.5
	}
	return mos
}

func heaviside(x float64) float64 {
	if x > 0 {
		return 1.0
	}
	return 0.0
}

// verdict derives the quality verdict from MOS score.
// Thresholds: good >= 3.6, fair 3.1–3.6, poor 2.5–3.1, bad < 2.5.
func verdict(mos float64) string {
	switch {
	case mos >= 3.6:
		return "good"
	case mos >= 3.1:
		return "fair"
	case mos >= 2.5:
		return "poor"
	default:
		return "bad"
	}
}

// singleValueSummary creates a StatSummary where all fields equal the given value.
func singleValueSummary(v float64) StatSummary {
	return StatSummary{Avg: v, Min: v, Max: v, P5: v, P95: v}
}

// percentile returns the p-th percentile (0–100) of a sorted slice.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := p / 100.0 * float64(len(sorted)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// summaryFromSlice computes a StatSummary from a slice of values.
func summaryFromSlice(vals []float64) StatSummary {
	if len(vals) == 0 {
		return StatSummary{}
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)

	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	return StatSummary{
		Avg: sum / float64(len(sorted)),
		Min: sorted[0],
		Max: sorted[len(sorted)-1],
		P5:  percentile(sorted, 5),
		P95: percentile(sorted, 95),
	}
}

// BuildQualityReport constructs a QualityReport from a completed Analyzer.
// direction should be "inbound" or "outbound".
func BuildQualityReport(callID string, analyzer *Analyzer, direction string, codec string) *QualityReport {
	stats := analyzer.Stats()

	mos := mosFromStats(stats.JitterMs, stats.LossPercent)
	v := verdict(mos)

	durationSecs := int(stats.Duration.Seconds())

	dirStats := DirectionStats{
		MOS:    singleValueSummary(mos),
		Jitter: singleValueSummary(stats.JitterMs),
		Loss:   singleValueSummary(stats.LossPercent),
		RTT:    singleValueSummary(0), // RTT not available from one-way RTP analysis
	}

	return &QualityReport{
		CallID:  callID,
		Verdict: v,
		Summary: QualitySummary{
			DurationSecs: durationSecs,
			Codec:        codec,
			SampleCount:  stats.PacketsReceived,
		},
		Directions: map[string]DirectionStats{
			direction: dirStats,
		},
		Source: "rtp",
	}
}

// StreamInfo pairs an Analyzer with its direction and codec for multi-stream reports.
type StreamInfo struct {
	Analyzer  *Analyzer
	Direction string // "uac" or "uas"
	Codec     string
}

// BuildMultiStreamReport builds a quality report from multiple RTP streams
// belonging to the same call. Each stream gets its own direction entry.
func BuildMultiStreamReport(callID string, streams []StreamInfo) *QualityReport {
	if len(streams) == 0 {
		return nil
	}

	report := &QualityReport{
		CallID:     callID,
		Directions: make(map[string]DirectionStats),
		Source:     "rtp",
	}

	var worstMOS float64 = 5.0
	var totalPackets int
	var maxDuration int
	var codec string

	for _, s := range streams {
		stats := s.Analyzer.Stats()
		if stats.PacketsReceived == 0 {
			continue
		}

		mos := mosFromStats(stats.JitterMs, stats.LossPercent)
		if mos < worstMOS {
			worstMOS = mos
		}

		report.Directions[s.Direction] = DirectionStats{
			MOS:    singleValueSummary(mos),
			Jitter: singleValueSummary(stats.JitterMs),
			Loss:   singleValueSummary(stats.LossPercent),
			RTT:    singleValueSummary(0),
		}

		totalPackets += stats.PacketsReceived
		dur := int(stats.Duration.Seconds())
		if dur > maxDuration {
			maxDuration = dur
		}
		if codec == "" {
			codec = s.Codec
		}
	}

	if totalPackets == 0 {
		return nil
	}

	report.Verdict = verdict(worstMOS)
	report.Summary = QualitySummary{
		DurationSecs: maxDuration,
		Codec:        codec,
		SampleCount:  totalPackets,
	}

	return report
}
