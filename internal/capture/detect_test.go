package capture

import "testing"

func TestParseKernelVersion_Standard(t *testing.T) {
	major, minor := parseKernelVersion("5.15.0-100-generic")
	if major != 5 || minor != 15 {
		t.Fatalf("got %d.%d, want 5.15", major, minor)
	}
}

func TestParseKernelVersion_CentOS7(t *testing.T) {
	major, minor := parseKernelVersion("3.10.0-1160.el7.x86_64")
	if major != 3 || minor != 10 {
		t.Fatalf("got %d.%d, want 3.10", major, minor)
	}
}

func TestParseKernelVersion_Kernel4_18(t *testing.T) {
	major, minor := parseKernelVersion("4.18.0-348.el8.x86_64")
	if major != 4 || minor != 18 {
		t.Fatalf("got %d.%d, want 4.18", major, minor)
	}
}

func TestParseKernelVersion_Empty(t *testing.T) {
	major, minor := parseKernelVersion("")
	if major != 0 || minor != 0 {
		t.Fatalf("got %d.%d, want 0.0", major, minor)
	}
}

func TestParseKernelVersion_SingleNumber(t *testing.T) {
	major, minor := parseKernelVersion("5")
	if major != 0 || minor != 0 {
		t.Fatalf("got %d.%d, want 0.0 for single-component version", major, minor)
	}
}

func TestParseKernelVersion_MajorMinorOnly(t *testing.T) {
	major, minor := parseKernelVersion("6.8")
	if major != 6 || minor != 8 {
		t.Fatalf("got %d.%d, want 6.8", major, minor)
	}
}

func TestDetectMode_ReturnsValidValue(t *testing.T) {
	// On any system, DetectMode should return one of the two valid values.
	mode := DetectMode()
	if mode != "ebpf" && mode != "pcap" {
		t.Fatalf("unexpected mode: %q", mode)
	}
}
