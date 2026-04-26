package sip

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// Errors returned by the SIP parser.
var (
	ErrEmptyMessage  = errors.New("sip: empty message")
	ErrMalformed     = errors.New("sip: malformed message")
	ErrMissingCallID = errors.New("sip: missing Call-ID header")
)

// Message represents a parsed SIP message.
type Message struct {
	IsResponse bool
	Method     string // for requests
	StatusCode int    // for responses
	CallID     string
	From       string
	To         string
	CSeq       string
	Body       []byte // SDP body if present
}

// compactHeaders maps compact single-character header names to canonical forms.
var compactHeaders = map[string]string{
	"i": "call-id",
	"f": "from",
	"t": "to",
	"m": "contact",
	"v": "via",
	"l": "content-length",
	"c": "content-type",
	"e": "content-encoding",
	"s": "subject",
	"k": "supported",
}

// ParseMessage parses a raw SIP message.
func ParseMessage(raw []byte) (*Message, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyMessage
	}

	// Split header section from body. SIP uses CRLFCRLF or LFLF as separator.
	headerBytes, body := splitHeaderBody(raw)

	// Normalise line endings: replace CRLF with LF for uniform processing.
	headerBytes = bytes.ReplaceAll(headerBytes, []byte("\r\n"), []byte("\n"))

	// Unfold continuation lines (lines starting with SP or HTAB).
	headerBytes = unfoldHeaders(headerBytes)

	lines := bytes.Split(headerBytes, []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, ErrMalformed
	}

	msg := &Message{}

	// Parse start line.
	startLine := string(lines[0])
	if err := parseStartLine(startLine, msg); err != nil {
		return nil, err
	}

	// Parse headers.
	headers := make(map[string]string) // lower-case canonical name → value
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 1 {
			continue
		}
		name := strings.TrimSpace(string(line[:colonIdx]))
		value := strings.TrimSpace(string(line[colonIdx+1:]))

		canonical := strings.ToLower(name)
		// Check compact form.
		if expanded, ok := compactHeaders[canonical]; ok {
			canonical = expanded
		}

		// Store first occurrence (SIP headers can repeat, but we only need first).
		if _, exists := headers[canonical]; !exists {
			headers[canonical] = value
		}
	}

	// Extract required Call-ID.
	callID, ok := headers["call-id"]
	if !ok || callID == "" {
		return nil, ErrMissingCallID
	}
	msg.CallID = callID
	msg.From = headers["from"]
	msg.To = headers["to"]
	msg.CSeq = headers["cseq"]

	if len(body) > 0 {
		msg.Body = body
	}

	return msg, nil
}

// splitHeaderBody separates SIP headers from the body.
func splitHeaderBody(raw []byte) (headers, body []byte) {
	// Try CRLFCRLF first.
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	// Fall back to LFLF.
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	// No body.
	return raw, nil
}

// unfoldHeaders joins continuation lines (lines starting with space or tab)
// with the preceding line.
func unfoldHeaders(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	var result [][]byte

	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(result) > 0 {
			// Continuation: append to previous line with a single space.
			result[len(result)-1] = append(result[len(result)-1], ' ')
			result[len(result)-1] = append(result[len(result)-1], bytes.TrimLeft(line, " \t")...)
		} else {
			result = append(result, line)
		}
	}

	return bytes.Join(result, []byte("\n"))
}

// parseStartLine parses the SIP request line or status line.
func parseStartLine(line string, msg *Message) error {
	if strings.HasPrefix(line, "SIP/") {
		// Response: "SIP/2.0 200 OK"
		msg.IsResponse = true
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return ErrMalformed
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return ErrMalformed
		}
		msg.StatusCode = code
		return nil
	}

	// Request: "INVITE sip:user@host SIP/2.0"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return ErrMalformed
	}
	msg.Method = parts[0]
	return nil
}
