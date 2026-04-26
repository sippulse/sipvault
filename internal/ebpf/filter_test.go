package ebpf

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestBuildSocketFilter_Assembles(t *testing.T) {
	insns := BuildSocketFilter()

	// Confirm the program assembles to a valid cBPF program. Assemble()
	// validates jump offsets and instruction widths.
	raw, err := bpf.Assemble(insns)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(raw) != len(insns) {
		t.Fatalf("assembled length mismatch: got %d, want %d", len(raw), len(insns))
	}

	// Sanity: the program should fit comfortably in the kernel limit
	// (4096 instructions for a single cBPF program).
	if len(insns) > 4096 {
		t.Fatalf("program exceeds kernel cBPF limit: %d", len(insns))
	}
}

// TestBuildSocketFilter_Decisions runs the assembled program through a
// pure-Go cBPF VM (bpf.NewVM) and checks each branch against synthetic
// Ethernet+IP+UDP packets.
func TestBuildSocketFilter_Decisions(t *testing.T) {
	vm, err := bpf.NewVM(BuildSocketFilter())
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// Helper to build a 60-byte minimal Ethernet + IPv4 + UDP frame.
	makeUDP := func(fragOff uint16, ipProto byte) []byte {
		f := make([]byte, 60)
		// EtherType IPv4 at offset 12-13
		f[12] = 0x08
		f[13] = 0x00
		// IP version 4, IHL 5 at offset 14
		f[14] = 0x45
		// Fragment offset + flags at offset 20-21
		f[20] = byte(fragOff >> 8)
		f[21] = byte(fragOff & 0xFF)
		// IP protocol at offset 23
		f[23] = ipProto
		return f
	}

	cases := []struct {
		name   string
		frame  []byte
		accept bool
	}{
		{"udp first fragment (offset=0)", makeUDP(0x0000, ipProtoUDP), true},
		{"udp non-first fragment", makeUDP(0x0001, ipProtoUDP), true},
		{"tcp instead of udp", makeUDP(0x0000, 6), false},
		{"icmp instead of udp", makeUDP(0x0000, 1), false},
		{"non-ipv4 ethertype", func() []byte {
			f := makeUDP(0, ipProtoUDP)
			f[12] = 0x86
			f[13] = 0xDD // IPv6
			return f
		}(), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := vm.Run(c.frame)
			if err != nil {
				t.Fatalf("vm.Run: %v", err)
			}
			got := n > 0
			if got != c.accept {
				t.Fatalf("verdict mismatch: got n=%d (accept=%v), want accept=%v", n, got, c.accept)
			}
		})
	}
}
