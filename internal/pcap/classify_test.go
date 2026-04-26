package pcap

import (
	"testing"

	"github.com/sippulse/sipvault/internal/capture"
)

func TestClassifyPacket_SIPSrcPort(t *testing.T) {
	sipPorts := []int{5060, 5080}
	got := ClassifyPacket(5060, 12345, sipPorts, nil)
	if got != capture.EventSIP {
		t.Fatalf("expected EventSIP for src port 5060, got %d", got)
	}
}

func TestClassifyPacket_SIPDstPort(t *testing.T) {
	sipPorts := []int{5060, 5080}
	got := ClassifyPacket(12345, 5080, sipPorts, nil)
	if got != capture.EventSIP {
		t.Fatalf("expected EventSIP for dst port 5080, got %d", got)
	}
}

func TestClassifyPacket_RTCP(t *testing.T) {
	sipPorts := []int{5060, 5080}
	got := ClassifyPacket(10001, 10002, sipPorts, nil)
	if got != capture.EventRTCP {
		t.Fatalf("expected EventRTCP for non-SIP ports, got %d", got)
	}
}

func TestClassifyPacket_EmptySIPPorts(t *testing.T) {
	got := ClassifyPacket(5060, 5060, nil, nil)
	if got != capture.EventRTCP {
		t.Fatalf("expected EventRTCP when no SIP ports configured, got %d", got)
	}
}

func TestClassifyPacket_RTPWithChecker(t *testing.T) {
	sipPorts := []int{5060}
	rtpChecker := func(port int) bool { return port == 10100 }
	got := ClassifyPacket(10100, 10101, sipPorts, rtpChecker)
	if got != capture.EventRTP {
		t.Fatalf("expected EventRTP for tracked RTP src port, got %d", got)
	}
}

func TestClassifyPacket_RTPWithChecker_DstPort(t *testing.T) {
	sipPorts := []int{5060}
	rtpChecker := func(port int) bool { return port == 10200 }
	got := ClassifyPacket(10100, 10200, sipPorts, rtpChecker)
	if got != capture.EventRTP {
		t.Fatalf("expected EventRTP for tracked RTP dst port, got %d", got)
	}
}

func TestClassifyPacket_RTCPWhenCheckerReturnsFalse(t *testing.T) {
	sipPorts := []int{5060}
	rtpChecker := func(port int) bool { return false }
	got := ClassifyPacket(10001, 10002, sipPorts, rtpChecker)
	if got != capture.EventRTCP {
		t.Fatalf("expected EventRTCP when checker returns false, got %d", got)
	}
}

func TestBuildBPFFilter_SinglePort(t *testing.T) {
	filter := BuildBPFFilter([]int{5060}, 10000, 30000)
	expected := "udp and (port 5060 or portrange 10000-30000)"
	if filter != expected {
		t.Fatalf("filter:\n got: %q\nwant: %q", filter, expected)
	}
}

func TestBuildBPFFilter_MultiplePorts(t *testing.T) {
	filter := BuildBPFFilter([]int{5060, 5080, 5090}, 10000, 20000)
	expected := "udp and (port 5060 or port 5080 or port 5090 or portrange 10000-20000)"
	if filter != expected {
		t.Fatalf("filter:\n got: %q\nwant: %q", filter, expected)
	}
}

func TestBuildBPFFilter_NoPorts(t *testing.T) {
	filter := BuildBPFFilter(nil, 10000, 30000)
	expected := "udp and (portrange 10000-30000)"
	if filter != expected {
		t.Fatalf("filter:\n got: %q\nwant: %q", filter, expected)
	}
}

// Compile-time check that *Source implements capture.Source.
var _ capture.Source = (*Source)(nil)
