package sip

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(), name))
	if err != nil {
		t.Fatalf("reading test file %s: %v", name, err)
	}
	return data
}

func TestParseINVITE(t *testing.T) {
	raw := readTestFile(t, "invite.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	if msg.IsResponse {
		t.Fatal("expected request, got response")
	}
	if msg.Method != "INVITE" {
		t.Fatalf("method: got %q, want INVITE", msg.Method)
	}
	if msg.CallID != "a84b4c76e66710@pc33.atlanta.example.com" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
	if msg.From == "" {
		t.Fatal("From header is empty")
	}
	if msg.To == "" {
		t.Fatal("To header is empty")
	}
	if msg.CSeq != "314159 INVITE" {
		t.Fatalf("CSeq: got %q, want %q", msg.CSeq, "314159 INVITE")
	}
	if len(msg.Body) == 0 {
		t.Fatal("expected SDP body")
	}
}

func TestParse200OK(t *testing.T) {
	raw := readTestFile(t, "response_200.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	if !msg.IsResponse {
		t.Fatal("expected response")
	}
	if msg.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", msg.StatusCode)
	}
	if msg.CallID != "a84b4c76e66710@pc33.atlanta.example.com" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
	if len(msg.Body) == 0 {
		t.Fatal("expected SDP body")
	}
}

func TestParseBYE(t *testing.T) {
	raw := readTestFile(t, "bye.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	if msg.IsResponse {
		t.Fatal("expected request")
	}
	if msg.Method != "BYE" {
		t.Fatalf("method: got %q, want BYE", msg.Method)
	}
	if msg.CallID != "a84b4c76e66710@pc33.atlanta.example.com" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
	if msg.CSeq != "231 BYE" {
		t.Fatalf("CSeq: got %q", msg.CSeq)
	}
	if len(msg.Body) != 0 {
		t.Fatal("expected no body for BYE")
	}
}

func TestParseCANCEL(t *testing.T) {
	raw := readTestFile(t, "cancel.sip")
	msg, err := ParseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}

	if msg.IsResponse {
		t.Fatal("expected request")
	}
	if msg.Method != "CANCEL" {
		t.Fatalf("method: got %q, want CANCEL", msg.Method)
	}
}

func TestParse_Responses(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		statusCode int
	}{
		{
			name: "100 Trying",
			raw: "SIP/2.0 100 Trying\r\n" +
				"Via: SIP/2.0/UDP host;branch=z9hG4bK123\r\n" +
				"Call-ID: trying-test@host\r\n" +
				"From: <sip:a@b>;tag=1\r\n" +
				"To: <sip:c@d>\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Content-Length: 0\r\n\r\n",
			statusCode: 100,
		},
		{
			name: "180 Ringing",
			raw: "SIP/2.0 180 Ringing\r\n" +
				"Via: SIP/2.0/UDP host;branch=z9hG4bK456\r\n" +
				"Call-ID: ring-test@host\r\n" +
				"From: <sip:a@b>;tag=2\r\n" +
				"To: <sip:c@d>;tag=9\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Content-Length: 0\r\n\r\n",
			statusCode: 180,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessage([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			if !msg.IsResponse {
				t.Fatal("expected response")
			}
			if msg.StatusCode != tt.statusCode {
				t.Fatalf("status: got %d, want %d", msg.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestParse_MultilineHeader(t *testing.T) {
	raw := "INVITE sip:bob@host SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP\r\n" +
		" pc33.atlanta.example.com;branch=z9hG4bK776\r\n" +
		"Call-ID: multiline-test@host\r\n" +
		"From: Alice\r\n" +
		"\t<sip:alice@atlanta.example.com>;tag=1\r\n" +
		"To: <sip:bob@host>\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	if msg.CallID != "multiline-test@host" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
	// From should be unfolded and contain the continuation.
	if msg.From == "" {
		t.Fatal("From should not be empty after unfolding")
	}
}

func TestParse_CompactHeaders(t *testing.T) {
	raw := "INVITE sip:bob@host SIP/2.0\r\n" +
		"v: SIP/2.0/UDP host;branch=z9hG4bK999\r\n" +
		"i: compact-callid@host\r\n" +
		"f: <sip:alice@host>;tag=77\r\n" +
		"t: <sip:bob@host>\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"l: 0\r\n\r\n"

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	if msg.CallID != "compact-callid@host" {
		t.Fatalf("callID: got %q, want compact-callid@host", msg.CallID)
	}
	if msg.From == "" {
		t.Fatal("From missing with compact header 'f'")
	}
	if msg.To == "" {
		t.Fatal("To missing with compact header 't'")
	}
}

func TestParse_MissingCallID(t *testing.T) {
	raw := "INVITE sip:bob@host SIP/2.0\r\n" +
		"From: <sip:alice@host>\r\n" +
		"To: <sip:bob@host>\r\n" +
		"CSeq: 1 INVITE\r\n\r\n"

	_, err := ParseMessage([]byte(raw))
	if err != ErrMissingCallID {
		t.Fatalf("expected ErrMissingCallID, got %v", err)
	}
}

func TestParse_EmptyMessage(t *testing.T) {
	_, err := ParseMessage(nil)
	if err != ErrEmptyMessage {
		t.Fatalf("expected ErrEmptyMessage, got %v", err)
	}

	_, err = ParseMessage([]byte{})
	if err != ErrEmptyMessage {
		t.Fatalf("expected ErrEmptyMessage, got %v", err)
	}
}

func TestParse_LFOnly(t *testing.T) {
	raw := "BYE sip:bob@host SIP/2.0\n" +
		"Call-ID: lf-only@host\n" +
		"From: <sip:alice@host>;tag=1\n" +
		"To: <sip:bob@host>;tag=2\n" +
		"CSeq: 2 BYE\n\n"

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.CallID != "lf-only@host" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
	if msg.Method != "BYE" {
		t.Fatalf("method: got %q", msg.Method)
	}
}

func TestParse_CaseInsensitiveHeaders(t *testing.T) {
	raw := "INVITE sip:bob@host SIP/2.0\r\n" +
		"CALL-ID: case-test@host\r\n" +
		"FROM: <sip:alice@host>;tag=1\r\n" +
		"TO: <sip:bob@host>\r\n" +
		"CSEQ: 1 INVITE\r\n\r\n"

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.CallID != "case-test@host" {
		t.Fatalf("callID: got %q", msg.CallID)
	}
}
