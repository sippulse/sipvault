package pcap

import (
	"fmt"
	"strings"

	"github.com/sippulse/sipvault/internal/capture"
)

// ClassifyPacket decides whether a packet is SIP, RTP, or RTCP based on the port.
// rtpChecker, if non-nil, returns true when a port needs raw RTP capture (i.e.
// no RTCP is available for that media stream). Exported for testing without the
// pcap build tag.
func ClassifyPacket(srcPort, dstPort uint16, sipPorts []int, rtpChecker func(int) bool) capture.EventType {
	for _, sp := range sipPorts {
		if srcPort == uint16(sp) || dstPort == uint16(sp) {
			return capture.EventSIP
		}
	}
	if rtpChecker != nil {
		if rtpChecker(int(srcPort)) || rtpChecker(int(dstPort)) {
			return capture.EventRTP
		}
	}
	return capture.EventRTCP
}

// BuildBPFFilter constructs a BPF filter string that captures UDP traffic on
// the given SIP ports and the RTP/RTCP port range. Exported for testing.
func BuildBPFFilter(sipPorts []int, rtpMin, rtpMax int) string {
	var parts []string
	for _, p := range sipPorts {
		parts = append(parts, fmt.Sprintf("port %d", p))
	}
	parts = append(parts, fmt.Sprintf("portrange %d-%d", rtpMin, rtpMax))
	return "udp and (" + strings.Join(parts, " or ") + ")"
}
