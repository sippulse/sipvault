package sip

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// Errors returned by the SDP parser.
var (
	ErrNoMediaLine = errors.New("sdp: no media line found")
)

// SDPInfo holds extracted SDP session description data.
type SDPInfo struct {
	MediaPort   int      // port from the first m= line
	Codecs      []string // e.g., ["PCMU/8000", "PCMA/8000"]
	SSRC        uint32   // from a=ssrc line, 0 if not present
	RTCPEnabled bool     // true if RTCP is expected (default true per RFC 3605)
	RTCPPort    int      // explicit RTCP port from a=rtcp line, 0 = use default (RTP+1)
}

// ParseSDP extracts media port, codecs, and SSRC from an SDP body.
func ParseSDP(body []byte) (*SDPInfo, error) {
	if len(body) == 0 {
		return nil, ErrNoMediaLine
	}

	// Normalise line endings.
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))

	info := &SDPInfo{RTCPEnabled: true} // RFC 3605 default: RTCP on RTP+1
	foundMedia := false

	// Collect rtpmap payload types: pt → encoding name.
	rtpmaps := make(map[string]string)

	lines := bytes.Split(body, []byte("\n"))

	// First pass: collect all rtpmap lines.
	for _, line := range lines {
		s := string(line)
		if strings.HasPrefix(s, "a=rtpmap:") {
			// Format: a=rtpmap:<pt> <encoding>/<clock>[/<params>]
			rest := s[len("a=rtpmap:"):]
			parts := strings.SplitN(rest, " ", 2)
			if len(parts) == 2 {
				pt := strings.TrimSpace(parts[0])
				enc := strings.TrimSpace(parts[1])
				rtpmaps[pt] = enc
			}
		}
	}

	// Second pass: process m= and a=ssrc.
	for _, line := range lines {
		s := string(line)

		if !foundMedia && strings.HasPrefix(s, "m=audio ") {
			// m=audio <port> <proto> <fmt list...>
			parts := strings.Fields(s)
			if len(parts) < 4 {
				continue
			}
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			info.MediaPort = port
			foundMedia = true

			// Build codec list from payload types listed in m= line.
			for _, pt := range parts[3:] {
				if enc, ok := rtpmaps[pt]; ok {
					info.Codecs = append(info.Codecs, enc)
				}
			}
		}

		if strings.HasPrefix(s, "a=ssrc:") {
			// a=ssrc:<ssrc-id> <attribute>
			rest := s[len("a=ssrc:"):]
			parts := strings.SplitN(rest, " ", 2)
			if len(parts) >= 1 {
				ssrc, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
				if err == nil && info.SSRC == 0 {
					info.SSRC = uint32(ssrc)
				}
			}
		}

		if strings.HasPrefix(s, "a=rtcp:") {
			// a=rtcp:<port> [nettype addrtype address]
			rest := strings.TrimSpace(s[len("a=rtcp:"):])
			portStr := strings.Fields(rest)[0]
			port, err := strconv.Atoi(portStr)
			if err == nil {
				if port == 0 {
					info.RTCPEnabled = false
				} else {
					info.RTCPEnabled = true
					info.RTCPPort = port
				}
			}
		}

		if strings.TrimSpace(s) == "a=rtcp-mux" {
			info.RTCPEnabled = true
		}
	}

	if !foundMedia {
		return nil, ErrNoMediaLine
	}

	return info, nil
}
