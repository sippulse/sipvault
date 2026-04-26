package capture

import (
	"os"
	"strconv"
	"strings"
)

// DetectMode determines whether to use eBPF or pcap capture.
// Returns "ebpf" or "pcap".
func DetectMode() string {
	major, minor := kernelVersion()

	// eBPF perf event arrays require kernel 4.18+.
	if major < 4 || (major == 4 && minor < 18) {
		return "pcap"
	}

	// Check for BTF support (modern eBPF with CO-RE).
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		// BTF not available — check for basic BPF support.
		if _, err := os.Stat("/proc/sys/kernel/unprivileged_bpf_disabled"); err != nil {
			return "pcap"
		}
	}

	return "ebpf"
}

// kernelVersion returns the major and minor kernel version numbers
// by reading /proc/sys/kernel/osrelease.
func kernelVersion() (int, int) {
	return parseKernelVersion(readKernelRelease())
}

// readKernelRelease reads the kernel release string from /proc.
func readKernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parseKernelVersion extracts major and minor version from a kernel
// release string such as "5.15.0-100-generic" or "4.18.0-el7".
func parseKernelVersion(ver string) (int, int) {
	if ver == "" {
		return 0, 0
	}

	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}

	major, _ := strconv.Atoi(parts[0])

	// Minor may have a non-numeric suffix like "18-el7".
	minorStr := parts[1]
	if idx := strings.IndexFunc(minorStr, func(r rune) bool {
		return r < '0' || r > '9'
	}); idx > 0 {
		minorStr = minorStr[:idx]
	}
	minor, _ := strconv.Atoi(minorStr)

	return major, minor
}
