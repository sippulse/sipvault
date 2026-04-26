package capture

import (
	"os"
	"strconv"
	"strings"
)

// DetectMode determines which capture backend to use when the operator
// selects "auto". The eBPF backend is opt-in via explicit mode = ebpf;
// auto-detect intentionally pins to pcap so existing installs are not
// silently switched on upgrade. To use eBPF, set capture.mode = ebpf in
// the agent config and run a binary built with `-tags ebpf`.
func DetectMode() string {
	_, _ = kernelVersion()
	return "pcap"
}

// kernelHasEBPFSupport reports whether the running kernel meets the
// minimum requirements for the eBPF backend. Currently advisory only —
// the eBPF source itself surfaces a clear error if the kernel is too old.
func kernelHasEBPFSupport() bool {
	major, minor := kernelVersion()
	if major < 4 || (major == 4 && minor < 18) {
		return false
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if _, err := os.Stat("/proc/sys/kernel/unprivileged_bpf_disabled"); err != nil {
			return false
		}
	}
	return true
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
