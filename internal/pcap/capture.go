//go:build pcap

package pcap

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sippulse/sipvault/internal/capture"
)

// Source captures SIP and RTCP packets using libpcap.
type Source struct {
	handle     *pcap.Handle
	events     chan capture.CaptureEvent
	done       chan struct{}
	sipPorts   []int
	rtpChecker func(int) bool // returns true if port needs RTP capture
	defragger  *ip4defrag.IPv4Defragmenter
}

// NewSource opens a pcap handle on the given interface and captures SIP,
// RTP, and RTCP packets. sipPorts lists the UDP ports considered SIP traffic.
// Other traffic in the rtpPortMin–rtpPortMax range is classified as RTP when
// rtpChecker(port) returns true, and as RTCP otherwise. rtpChecker may be nil.
func NewSource(iface string, sipPorts []int, rtpPortMin, rtpPortMax int, rtpChecker func(int) bool) (*Source, error) {
	const snapLen = 65535
	const promisc = true
	const timeout = 100 * time.Millisecond // read timeout for pcap_next

	handle, err := pcap.OpenLive(iface, snapLen, promisc, timeout)
	if err != nil {
		return nil, fmt.Errorf("pcap: open %s: %w", iface, err)
	}

	filter := buildBPFFilter(sipPorts, rtpPortMin, rtpPortMax)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("pcap: set filter: %w", err)
	}

	s := &Source{
		handle:     handle,
		events:     make(chan capture.CaptureEvent, 256),
		done:       make(chan struct{}),
		sipPorts:   sipPorts,
		rtpChecker: rtpChecker,
		defragger:  ip4defrag.NewIPv4Defragmenter(),
	}

	go s.run()
	return s, nil
}

// Events returns a read-only channel of CaptureEvents.
func (s *Source) Events() <-chan capture.CaptureEvent {
	return s.events
}

// Close stops the capture loop and releases the pcap handle.
func (s *Source) Close() error {
	select {
	case <-s.done:
		// Already closed.
	default:
		close(s.done)
	}
	s.handle.Close()
	return nil
}

func (s *Source) run() {
	defer close(s.events)

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	var pktCount, sipCount, decodeFailCount int

	for {
		select {
		case <-s.done:
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			// On timeout or transient read error, check if we should stop.
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		pktCount++
		raw := packet.Data()
		isInvite := bytes.Contains(raw, []byte("INVITE sip:"))

		ev, ok := s.decodePacket(packet)
		if !ok {
			decodeFailCount++
			if isInvite {
				// Failed decode of a packet that looks like an INVITE is
				// a real bug worth surfacing.
				log.Printf("pcap: INVITE packet FAILED decode! pkt #%d", pktCount)
			}
			continue
		}
		if ev.Type == capture.EventSIP {
			sipCount++
		} else if isInvite {
			log.Printf("pcap: INVITE classified as type=%d (not SIP!) src=%s:%d dst=%s:%d", ev.Type, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
		}

		select {
		case s.events <- ev:
		case <-s.done:
			return
		}
	}
}

func (s *Source) decodePacket(packet gopacket.Packet) (capture.CaptureEvent, bool) {
	var ev capture.CaptureEvent

	// Extract IPv4 layer.
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return ev, false
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Reassemble IP fragments. IncompletePacket means we need more
	// fragments; nil error + non-nil result means reassembly is done.
	reassembled, err := s.defragger.DefragIPv4(ip)
	if err != nil {
		return ev, false
	}
	if reassembled == nil {
		// Fragment stored, waiting for more pieces.
		return ev, false
	}

	// Re-decode the reassembled packet to get the UDP layer.
	var udp *layers.UDP
	if reassembled == ip {
		// Not fragmented — use original packet's UDP layer.
		ul := packet.Layer(layers.LayerTypeUDP)
		if ul == nil {
			return ev, false
		}
		udp, _ = ul.(*layers.UDP)
	} else {
		// Reassembled — decode UDP from the reassembled IPv4 payload.
		var u layers.UDP
		if err := u.DecodeFromBytes(reassembled.Payload, gopacket.NilDecodeFeedback); err != nil {
			return ev, false
		}
		udp = &u
	}
	if udp == nil {
		return ev, false
	}

	payload := udp.Payload
	if len(payload) == 0 {
		return ev, false
	}

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	ev = capture.CaptureEvent{
		Type:      classifyPacket(srcPort, dstPort, s.sipPorts, s.rtpChecker),
		Timestamp: packet.Metadata().Timestamp.UnixNano(),
		Data:      append([]byte(nil), payload...), // copy payload
		SrcIP:     net.IP(append([]byte(nil), ip.SrcIP...)),
		DstIP:     net.IP(append([]byte(nil), ip.DstIP...)),
		SrcPort:   srcPort,
		DstPort:   dstPort,
	}

	return ev, true
}

// classifyPacket decides whether a packet is SIP, RTP, or RTCP based on the port.
func classifyPacket(srcPort, dstPort uint16, sipPorts []int, rtpChecker func(int) bool) capture.EventType {
	return ClassifyPacket(srcPort, dstPort, sipPorts, rtpChecker)
}

// buildBPFFilter constructs a BPF filter string that captures UDP traffic on
// the given SIP ports and the RTP/RTCP port range.
func buildBPFFilter(sipPorts []int, rtpMin, rtpMax int) string {
	var parts []string
	for _, p := range sipPorts {
		parts = append(parts, fmt.Sprintf("port %d", p))
	}
	parts = append(parts, fmt.Sprintf("portrange %d-%d", rtpMin, rtpMax))
	udpFilter := "udp and (" + strings.Join(parts, " or ") + ")"
	// Also capture IP fragments (non-first fragments lack UDP header so
	// "udp" alone won't match them). Needed for reassembly of large SIP
	// messages that exceed the MTU.
	return "(" + udpFilter + ") or (ip[6:2] & 0x1fff != 0)"
}
