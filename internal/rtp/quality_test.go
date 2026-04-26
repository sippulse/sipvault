package rtp

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildQualityReport_NormalCall(t *testing.T) {
	a := NewAnalyzer(0xABCD, 8000)
	now := time.Now()
	ptime := 20 * time.Millisecond
	hdrs := makePerfectStream(500, 1, 0, 8000)

	for i, hdr := range hdrs {
		a.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	report := BuildQualityReport("test-call-id", a, "inbound", "PCMU")

	if report == nil {
		t.Fatal("BuildQualityReport returned nil")
	}
	if report.CallID != "test-call-id" {
		t.Errorf("CallID: got %q, want %q", report.CallID, "test-call-id")
	}
	if report.Source != "rtp" {
		t.Errorf("Source: got %q, want %q", report.Source, "rtp")
	}
	if report.Verdict != "good" {
		t.Errorf("Verdict: got %q, want %q", report.Verdict, "good")
	}

	dir, ok := report.Directions["inbound"]
	if !ok {
		t.Fatal("missing 'inbound' direction in Directions map")
	}

	if dir.MOS.Avg <= 4.0 {
		t.Errorf("MOS avg: got %.4f, want > 4.0 for zero-loss perfect stream", dir.MOS.Avg)
	}

	if report.Summary.Codec != "PCMU" {
		t.Errorf("Codec: got %q, want %q", report.Summary.Codec, "PCMU")
	}
	if report.Summary.SampleCount != 500 {
		t.Errorf("SampleCount: got %d, want 500", report.Summary.SampleCount)
	}

	// Verify it serializes to valid JSON.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("json.Marshal returned empty bytes")
	}

	// Round-trip: unmarshal and check key fields survive.
	var decoded QualityReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.CallID != "test-call-id" {
		t.Errorf("after round-trip CallID: got %q", decoded.CallID)
	}
	if decoded.Verdict != "good" {
		t.Errorf("after round-trip Verdict: got %q", decoded.Verdict)
	}
}

func TestBuildMultiStreamReport_TwoDirections(t *testing.T) {
	now := time.Now()
	ptime := 20 * time.Millisecond

	// Good stream: no loss, perfect timing.
	goodAnalyzer := NewAnalyzer(0xAAAA, 8000)
	goodHdrs := makePerfectStream(500, 1, 0, 8000)
	for i, hdr := range goodHdrs {
		goodAnalyzer.Process(hdr, now.Add(time.Duration(i)*ptime))
	}

	// Degraded stream: ~20% loss to push MOS down.
	degradedAnalyzer := NewAnalyzer(0xBBBB, 8000)
	degradedHdrs := makePerfectStream(500, 1, 0, 8000)
	wall := now
	for i, hdr := range degradedHdrs {
		if i%5 == 0 {
			wall = wall.Add(ptime)
			continue // skip every 5th packet → ~20% loss
		}
		degradedAnalyzer.Process(hdr, wall)
		wall = wall.Add(ptime)
	}

	streams := []StreamInfo{
		{Analyzer: goodAnalyzer, Direction: "uac", Codec: "PCMU"},
		{Analyzer: degradedAnalyzer, Direction: "uas", Codec: "PCMU"},
	}

	report := BuildMultiStreamReport("two-dir-call", streams)
	if report == nil {
		t.Fatal("BuildMultiStreamReport returned nil")
	}

	// Should have both directions.
	if len(report.Directions) != 2 {
		t.Fatalf("expected 2 directions, got %d", len(report.Directions))
	}
	if _, ok := report.Directions["uac"]; !ok {
		t.Error("missing 'uac' direction")
	}
	if _, ok := report.Directions["uas"]; !ok {
		t.Error("missing 'uas' direction")
	}

	// The overall verdict should reflect the worse stream (degraded).
	uacMOS := report.Directions["uac"].MOS.Avg
	uasMOS := report.Directions["uas"].MOS.Avg
	if uacMOS <= uasMOS {
		t.Errorf("expected uac MOS (%.4f) > uas MOS (%.4f)", uacMOS, uasMOS)
	}

	// Verdict should not be "good" since the degraded stream pulls it down.
	worseMOS := uasMOS
	expectedVerdict := verdict(worseMOS)
	if report.Verdict != expectedVerdict {
		t.Errorf("Verdict: got %q, want %q (based on worse MOS %.4f)", report.Verdict, expectedVerdict, worseMOS)
	}
}

func TestVerdict_Boundaries(t *testing.T) {
	tests := []struct {
		mos  float64
		want string
	}{
		{3.60, "good"},
		{3.59, "fair"},
		{3.10, "fair"},
		{3.09, "poor"},
		{2.50, "poor"},
		{2.49, "bad"},
	}

	for _, tc := range tests {
		got := verdict(tc.mos)
		if got != tc.want {
			t.Errorf("verdict(%.2f): got %q, want %q", tc.mos, got, tc.want)
		}
	}
}
