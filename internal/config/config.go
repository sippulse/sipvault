package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the sipvault-agent configuration.
type Config struct {
	ServerAddr  string // server address "host:port"
	CustomerID  string // customer identifier
	Token       string // authentication token
	SIPPorts    []int  // SIP ports to capture, default [5060]
	Interface   string // network interface, default auto-detect (empty)
	CaptureMode string // "auto", "ebpf", or "pcap" — default "auto"
	LogFile     string // path to OpenSIPS log file for pcap mode (empty = disabled)
	RTPPortMin  int    // minimum RTP port range, default 10000
	RTPPortMax  int    // maximum RTP port range, default 30000
	BufferPath  string // disk buffer path
	BufferMax   int64  // disk buffer max size in bytes
	LogLevel    string // logging level

	// TLS (HEP over TLS to :9061). When enabled the agent uses HEP/TLS instead
	// of the plaintext binary protocol.
	TLSEnabled    bool   // [tls] enabled = true
	TLSServerName string // [tls] server_name — SNI hostname (defaults to ServerAddr host)
	TLSCACert     string // [tls] ca_cert — PEM CA file for self-signed certs (empty = system roots)
}

// defaults
const (
	defaultSIPPort     = 5060
	defaultCaptureMode = "auto"
	defaultRTPPortMin  = 10000
	defaultRTPPortMax  = 30000
	defaultBufferPath  = "/var/lib/sipvault/buffer.dat"
	defaultBufferMax   = 104857600 // 100 MB
	defaultLogLevel    = "info"
)

// LoadConfig parses an INI-format config file and returns a Config
// with defaults applied for any missing values.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()

	cfg := &Config{
		SIPPorts:    []int{defaultSIPPort},
		CaptureMode: defaultCaptureMode,
		RTPPortMin:  defaultRTPPortMin,
		RTPPortMax:  defaultRTPPortMax,
		BufferPath:  defaultBufferPath,
		BufferMax:   defaultBufferMax,
		LogLevel:    defaultLogLevel,
	}

	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Section header.
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			section = strings.TrimSpace(line[1:end])
			continue
		}

		// Key=value pair.
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		value := strings.TrimSpace(line[eqIdx+1:])

		switch section {
		case "server":
			switch key {
			case "address":
				cfg.ServerAddr = value
			case "customer_id":
				cfg.CustomerID = value
			case "token":
				cfg.Token = value
			}
		case "capture":
			switch key {
			case "mode":
				cfg.CaptureMode = value
			case "sip_ports":
				ports, err := parsePorts(value)
				if err != nil {
					return nil, fmt.Errorf("config: sip_ports: %w", err)
				}
				cfg.SIPPorts = ports
			case "interface":
				cfg.Interface = value
			case "log_file":
				cfg.LogFile = value
			case "rtp_port_min":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("config: rtp_port_min: %w", err)
				}
				cfg.RTPPortMin = n
			case "rtp_port_max":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("config: rtp_port_max: %w", err)
				}
				cfg.RTPPortMax = n
			}
		case "buffer":
			switch key {
			case "path":
				cfg.BufferPath = value
			case "max_size":
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("config: max_size: %w", err)
				}
				cfg.BufferMax = n
			}
		case "logging":
			switch key {
			case "level":
				cfg.LogLevel = value
			}
		case "tls":
			switch key {
			case "enabled":
				cfg.TLSEnabled = value == "true" || value == "1" || value == "yes"
			case "server_name":
				cfg.TLSServerName = value
			case "ca_cert":
				cfg.TLSCACert = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("config: reading file: %w", err)
	}

	return cfg, nil
}

// parsePorts parses a comma-separated list of port numbers.
func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		ports = append(ports, n)
	}
	return ports, nil
}
