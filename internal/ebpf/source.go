//go:build ebpf && linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/sippulse/sipvault/internal/capture"
	"github.com/sippulse/sipvault/internal/pcap"
)

// Available reports that the eBPF backend is compiled in. Used by main.go
// to decide whether to wire the eBPF case in the capture-mode switch.
const Available = true

// Source captures SIP / RTP / RTCP packets via an AF_PACKET raw socket
// with an in-kernel cBPF filter attached via SO_ATTACH_FILTER. It is the
// libpcap-free analogue of internal/pcap.Source and produces the same
// capture.CaptureEvent shape, so internal/capture.Reader does not need
// to know which backend is feeding it.
type Source struct {
	fd         int
	iface      string
	sipPorts   []int
	rtpMin     int
	rtpMax     int
	rtpChecker func(int) bool

	events chan capture.CaptureEvent
	done   chan struct{}
	wg     sync.WaitGroup

	defragger *ip4defrag.IPv4Defragmenter
}

// htons converts a host-byte-order uint16 to network byte order.
func htons(v uint16) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v >> 8), byte(v)})
}

// NewSource opens an AF_PACKET raw socket bound to the given interface
// (empty string = all interfaces), attaches a cBPF filter that lets only
// IPv4 UDP traffic through, and starts the packet read loop.
//
// sipPorts and rtpMin/rtpMax are used by userspace classification only —
// the in-kernel filter is intentionally minimal. rtpChecker may be nil.
func NewSource(iface string, sipPorts []int, rtpMin, rtpMax int, rtpChecker func(int) bool) (*Source, error) {
	if rtpMin < 0 || rtpMax < 0 || rtpMin > rtpMax {
		return nil, fmt.Errorf("ebpf: invalid RTP port range %d-%d", rtpMin, rtpMax)
	}

	// Resolve interface index. Empty iface = bind to all (ifindex 0).
	var ifindex int
	if iface != "" {
		ni, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("ebpf: interface %q: %w", iface, err)
		}
		ifindex = ni.Index
	}

	// Open AF_PACKET / SOCK_RAW socket for ETH_P_ALL.
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, proto)
	if err != nil {
		return nil, fmt.Errorf("ebpf: open AF_PACKET socket: %w (need CAP_NET_RAW or root)", err)
	}

	// Bind to interface (or 0 for all).
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifindex,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ebpf: bind to interface %q: %w", iface, err)
	}

	// Compile and attach the cBPF filter.
	insns := BuildSocketFilter()
	raw, err := bpf.Assemble(insns)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ebpf: assemble filter: %w", err)
	}

	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: rawToSockFilter(raw),
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ebpf: SO_ATTACH_FILTER: %w", err)
	}

	s := &Source{
		fd:         fd,
		iface:      iface,
		sipPorts:   sipPorts,
		rtpMin:     rtpMin,
		rtpMax:     rtpMax,
		rtpChecker: rtpChecker,
		events:     make(chan capture.CaptureEvent, 256),
		done:       make(chan struct{}),
		defragger:  ip4defrag.NewIPv4Defragmenter(),
	}

	if iface == "" {
		log.Printf("ebpf: capture started on all interfaces, kernel cBPF filter attached")
	} else {
		log.Printf("ebpf: capture started on %s (ifindex=%d), kernel cBPF filter attached", iface, ifindex)
	}

	s.wg.Add(1)
	go s.run()
	return s, nil
}

// rawToSockFilter converts the raw assembled cBPF program into the
// pointer-form unix.SockFprog expects.
func rawToSockFilter(raw []bpf.RawInstruction) *unix.SockFilter {
	if len(raw) == 0 {
		return nil
	}
	out := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		out[i] = unix.SockFilter{
			Code: ins.Op,
			Jt:   ins.Jt,
			Jf:   ins.Jf,
			K:    ins.K,
		}
	}
	return &out[0]
}

// Events returns the read-only event channel.
func (s *Source) Events() <-chan capture.CaptureEvent {
	return s.events
}

// Close stops the read loop and closes the socket.
func (s *Source) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	// Closing the fd unblocks the in-flight Recvfrom with EBADF.
	err := unix.Close(s.fd)
	s.wg.Wait()
	return err
}

func (s *Source) run() {
	defer s.wg.Done()
	defer close(s.events)

	// 65535 is the max IPv4 datagram size; AF_PACKET also adds the
	// link-layer header, so 64KiB is comfortably enough.
	buf := make([]byte, 65536)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINTR) {
				return
			}
			// Transient error — log and continue.
			log.Printf("ebpf: recvfrom: %v", err)
			continue
		}
		if n <= 0 {
			continue
		}

		ev, ok := s.decode(buf[:n], time.Now())
		if !ok {
			continue
		}

		select {
		case s.events <- ev:
		case <-s.done:
			return
		}
	}
}

// decode parses an Ethernet+IPv4+UDP frame and produces a CaptureEvent.
// Returns ok=false for frames the userspace cannot use (non-IPv4, non-UDP,
// truncated, or fragments still pending reassembly).
func (s *Source) decode(frame []byte, now time.Time) (capture.CaptureEvent, bool) {
	var ev capture.CaptureEvent

	// Decode Ethernet → IPv4 → UDP using gopacket. This mirrors the
	// pcap source's decode path.
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	if pkt.ErrorLayer() != nil {
		return ev, false
	}

	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return ev, false
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Reassemble fragments via the same defragger as the pcap source.
	reassembled, err := s.defragger.DefragIPv4(ip)
	if err != nil || reassembled == nil {
		return ev, false
	}

	var udp *layers.UDP
	if reassembled == ip {
		ul := pkt.Layer(layers.LayerTypeUDP)
		if ul == nil {
			return ev, false
		}
		udp, _ = ul.(*layers.UDP)
	} else {
		var u layers.UDP
		if err := u.DecodeFromBytes(reassembled.Payload, gopacket.NilDecodeFeedback); err != nil {
			return ev, false
		}
		udp = &u
	}
	if udp == nil || len(udp.Payload) == 0 {
		return ev, false
	}

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	ev = capture.CaptureEvent{
		Type:      pcap.ClassifyPacket(srcPort, dstPort, s.sipPorts, s.rtpChecker),
		Timestamp: now.UnixNano(),
		Data:      append([]byte(nil), udp.Payload...),
		SrcIP:     net.IP(append([]byte(nil), ip.SrcIP...)),
		DstIP:     net.IP(append([]byte(nil), ip.DstIP...)),
		SrcPort:   srcPort,
		DstPort:   dstPort,
	}

	// Drop UDP traffic that doesn't fall in any of our port buckets.
	// Userspace acts as the equivalent of the pcap layer's port filter.
	if !s.portIsRelevant(srcPort, dstPort) {
		return ev, false
	}

	return ev, true
}

// portIsRelevant returns true when at least one side of a UDP packet
// matches a configured SIP port or falls inside the RTP/RTCP range.
// Mirrors the libpcap-side BPF filter the pcap backend installs.
func (s *Source) portIsRelevant(srcPort, dstPort uint16) bool {
	for _, sp := range s.sipPorts {
		if uint16(sp) == srcPort || uint16(sp) == dstPort {
			return true
		}
	}
	if s.rtpMax > 0 {
		if int(srcPort) >= s.rtpMin && int(srcPort) <= s.rtpMax {
			return true
		}
		if int(dstPort) >= s.rtpMin && int(dstPort) <= s.rtpMax {
			return true
		}
	}
	return false
}
