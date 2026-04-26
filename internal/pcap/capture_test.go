//go:build pcap

package pcap

import (
	"testing"

	"github.com/sippulse/sipvault/internal/capture"
)

// These tests require the pcap build tag and libpcap-dev installed.
// Run with: go test -tags pcap ./agent/internal/pcap/...

func TestNewSource_InvalidInterface(t *testing.T) {
	_, err := NewSource("nonexistent0", []int{5060}, 10000, 30000, nil)
	if err == nil {
		t.Fatal("expected error for invalid interface")
	}
}

func TestClassifyPacketInternal_SIP(t *testing.T) {
	got := classifyPacket(5060, 12345, []int{5060}, nil)
	if got != capture.EventSIP {
		t.Fatalf("expected EventSIP, got %d", got)
	}
}

func TestClassifyPacketInternal_RTCP(t *testing.T) {
	got := classifyPacket(10001, 10002, []int{5060}, nil)
	if got != capture.EventRTCP {
		t.Fatalf("expected EventRTCP, got %d", got)
	}
}

func TestBuildBPFFilterInternal(t *testing.T) {
	filter := buildBPFFilter([]int{5060, 5080}, 10000, 30000)
	expected := "udp and (port 5060 or port 5080 or portrange 10000-30000)"
	if filter != expected {
		t.Fatalf("got %q, want %q", filter, expected)
	}
}
