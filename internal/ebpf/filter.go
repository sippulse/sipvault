// Package ebpf provides a kernel-BPF socket-filter capture backend that
// removes libpcap from the runtime dependency chain.
//
// v1 uses a classic-BPF (cBPF) socket filter attached via SO_ATTACH_FILTER
// to an AF_PACKET raw socket. The kernel filter is intentionally minimal —
// it accepts UDP and IPv4 fragments and drops everything else — with port
// matching performed in userspace. Future revisions may move port matching
// into BPF, switch to eBPF maps for dynamic configuration, or add XDP /
// kprobe paths; the userspace surface (Source interface) is independent
// of the in-kernel filter strategy.
//
// This file is build-tag-free so the program assembly can be unit tested
// on any platform.
package ebpf

import "golang.org/x/net/bpf"

// EtherType / IP-protocol constants used by the filter.
const (
	ethTypeIPv4 = 0x0800
	ipProtoUDP  = 17

	// retLenAccept is the truncation length returned for accepted frames.
	// Setting this to 65535 means "deliver the full frame".
	retLenAccept = 65535
)

// BuildSocketFilter assembles a classic-BPF (cBPF) program suitable for
// SO_ATTACH_FILTER on an AF_PACKET raw socket bound to an Ethernet link.
//
// Pseudo-code:
//
//	if EtherType   != 0x0800 (IPv4) → DROP
//	if IPv4 fragment offset != 0    → ACCEPT (userspace reassembles)
//	if IP protocol != UDP           → DROP
//	                                 → ACCEPT
//
// Userspace performs port-based classification (SIP / RTP / RTCP) using
// the same logic the libpcap backend uses, so the kernel program does
// not need to know which ports are configured in agent.conf.
func BuildSocketFilter() []bpf.Instruction {
	return []bpf.Instruction{
		// 0: load EtherType (skb[12:14])
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 1: if EtherType != 0x0800 (IPv4), drop. SkipTrue jumps over the
		//    drop instruction to "load frag offset" at index 3.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ethTypeIPv4, SkipTrue: 1},
		// 2: drop (non-IPv4)
		bpf.RetConstant{Val: 0},

		// 3: load IPv4 frag offset + flags (skb[20:22])
		bpf.LoadAbsolute{Off: 20, Size: 2},
		// 4: mask off the flags, keep only the 13-bit fragment offset
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x1FFF},
		// 5: if frag offset != 0 (i.e. non-first fragment), accept. The
		//    userspace defragmenter will stitch them together.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 3},

		// 6: load IP protocol (skb[23])
		bpf.LoadAbsolute{Off: 23, Size: 1},
		// 7: if proto != UDP, drop. SkipTrue jumps over the drop ret.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProtoUDP, SkipTrue: 1},
		// 8: drop (non-UDP)
		bpf.RetConstant{Val: 0},

		// 9: accept (UDP, or IPv4 non-first-fragment via the SkipFalse=3 above)
		bpf.RetConstant{Val: retLenAccept},
	}
}
