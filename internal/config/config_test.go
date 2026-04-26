package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFullConfigParsing(t *testing.T) {
	ini := `
[server]
address = 10.0.0.1:9060
customer_id = acme
token = secret123

[capture]
mode = pcap
sip_ports = 5060,5080
interface = eth0
log_file = /var/log/opensips.log
rtp_port_min = 12000
rtp_port_max = 28000

[buffer]
path = /var/lib/sipvault/buffer.dat
max_size = 104857600

[logging]
level = debug
`
	path := writeConfig(t, ini)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ServerAddr != "10.0.0.1:9060" {
		t.Fatalf("ServerAddr: got %q", cfg.ServerAddr)
	}
	if cfg.CustomerID != "acme" {
		t.Fatalf("CustomerID: got %q", cfg.CustomerID)
	}
	if cfg.Token != "secret123" {
		t.Fatalf("Token: got %q", cfg.Token)
	}
	if cfg.CaptureMode != "pcap" {
		t.Fatalf("CaptureMode: got %q", cfg.CaptureMode)
	}
	if len(cfg.SIPPorts) != 2 || cfg.SIPPorts[0] != 5060 || cfg.SIPPorts[1] != 5080 {
		t.Fatalf("SIPPorts: got %v", cfg.SIPPorts)
	}
	if cfg.Interface != "eth0" {
		t.Fatalf("Interface: got %q", cfg.Interface)
	}
	if cfg.LogFile != "/var/log/opensips.log" {
		t.Fatalf("LogFile: got %q", cfg.LogFile)
	}
	if cfg.RTPPortMin != 12000 {
		t.Fatalf("RTPPortMin: got %d", cfg.RTPPortMin)
	}
	if cfg.RTPPortMax != 28000 {
		t.Fatalf("RTPPortMax: got %d", cfg.RTPPortMax)
	}
	if cfg.BufferPath != "/var/lib/sipvault/buffer.dat" {
		t.Fatalf("BufferPath: got %q", cfg.BufferPath)
	}
	if cfg.BufferMax != 104857600 {
		t.Fatalf("BufferMax: got %d", cfg.BufferMax)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel: got %q", cfg.LogLevel)
	}
}

func TestDefaultsWhenSectionsMissing(t *testing.T) {
	// Minimal config: only server section.
	ini := `
[server]
address = 10.0.0.1:9060
customer_id = test
token = tok
`
	path := writeConfig(t, ini)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.SIPPorts) != 1 || cfg.SIPPorts[0] != 5060 {
		t.Fatalf("expected default SIPPorts [5060], got %v", cfg.SIPPorts)
	}
	if cfg.Interface != "" {
		t.Fatalf("expected empty Interface for auto-detect, got %q", cfg.Interface)
	}
	if cfg.CaptureMode != "auto" {
		t.Fatalf("expected default CaptureMode auto, got %q", cfg.CaptureMode)
	}
	if cfg.LogFile != "" {
		t.Fatalf("expected empty LogFile, got %q", cfg.LogFile)
	}
	if cfg.RTPPortMin != 10000 {
		t.Fatalf("expected default RTPPortMin 10000, got %d", cfg.RTPPortMin)
	}
	if cfg.RTPPortMax != 30000 {
		t.Fatalf("expected default RTPPortMax 30000, got %d", cfg.RTPPortMax)
	}
	if cfg.BufferPath != "/var/lib/sipvault/buffer.dat" {
		t.Fatalf("expected default BufferPath, got %q", cfg.BufferPath)
	}
	if cfg.BufferMax != 104857600 {
		t.Fatalf("expected default BufferMax 104857600, got %d", cfg.BufferMax)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default LogLevel info, got %q", cfg.LogLevel)
	}
}

func TestMultipleSIPPorts(t *testing.T) {
	ini := `
[capture]
sip_ports = 5060, 5080, 5090
`
	path := writeConfig(t, ini)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := []int{5060, 5080, 5090}
	if len(cfg.SIPPorts) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(cfg.SIPPorts))
	}
	for i, p := range cfg.SIPPorts {
		if p != expected[i] {
			t.Fatalf("port %d: got %d, want %d", i, p, expected[i])
		}
	}
}

func TestInvalidFileReturnsError(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/agent.conf")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestEmptyFileReturnsDefaults(t *testing.T) {
	path := writeConfig(t, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ServerAddr != "" {
		t.Fatalf("expected empty ServerAddr, got %q", cfg.ServerAddr)
	}
	if len(cfg.SIPPorts) != 1 || cfg.SIPPorts[0] != 5060 {
		t.Fatalf("expected default SIPPorts, got %v", cfg.SIPPorts)
	}
	if cfg.CaptureMode != "auto" {
		t.Fatalf("expected default CaptureMode auto, got %q", cfg.CaptureMode)
	}
	if cfg.LogFile != "" {
		t.Fatalf("expected empty LogFile, got %q", cfg.LogFile)
	}
	if cfg.RTPPortMin != 10000 {
		t.Fatalf("expected default RTPPortMin, got %d", cfg.RTPPortMin)
	}
	if cfg.RTPPortMax != 30000 {
		t.Fatalf("expected default RTPPortMax, got %d", cfg.RTPPortMax)
	}
	if cfg.BufferPath != "/var/lib/sipvault/buffer.dat" {
		t.Fatalf("expected default BufferPath, got %q", cfg.BufferPath)
	}
	if cfg.BufferMax != 104857600 {
		t.Fatalf("expected default BufferMax, got %d", cfg.BufferMax)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default LogLevel, got %q", cfg.LogLevel)
	}
}

func TestCommentsIgnored(t *testing.T) {
	ini := `
# This is a comment
; This is also a comment
[server]
address = 10.0.0.1:9060
# customer_id = wrong
customer_id = right
`
	path := writeConfig(t, ini)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.CustomerID != "right" {
		t.Fatalf("expected customer_id 'right', got %q", cfg.CustomerID)
	}
}
