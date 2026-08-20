package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRingBufferKeepsTheMostRecentBytes(t *testing.T) {
	r := newRingBuffer(10)

	r.Write([]byte("abcdef"))
	if got := string(r.Bytes()); got != "abcdef" {
		t.Fatalf("got %q", got)
	}

	// Overflow: the oldest bytes are what a user no longer needs.
	r.Write([]byte("ghijkl"))
	if got := string(r.Bytes()); got != "cdefghijkl" {
		t.Fatalf("got %q, want the last 10 bytes", got)
	}
}

// TestRingBufferHandlesAWriteLargerThanItself covers someone catting a file
// bigger than the whole buffer, which must keep the tail rather than
// misbehaving or copying byte by byte.
func TestRingBufferHandlesAWriteLargerThanItself(t *testing.T) {
	r := newRingBuffer(8)
	r.Write([]byte("0123456789abcdef"))

	if got := string(r.Bytes()); got != "89abcdef" {
		t.Fatalf("got %q, want the last 8 bytes of the input", got)
	}
}

func TestRingBufferIsBoundedUnderContinuousOutput(t *testing.T) {
	r := newRingBuffer(1024)

	// A terminal producing output for a long time must not grow without
	// limit, which is the whole point of the ring.
	for i := 0; i < 10000; i++ {
		r.Write([]byte("some output line that a command might print\n"))
	}

	if len(r.Bytes()) != 1024 {
		t.Fatalf("buffer holds %d bytes, want exactly its capacity", len(r.Bytes()))
	}
	if len(r.buf) != 1024 {
		t.Fatalf("backing array grew to %d bytes", len(r.buf))
	}
}

func TestRingBufferEmpty(t *testing.T) {
	r := newRingBuffer(16)
	if len(r.Bytes()) != 0 {
		t.Fatal("a fresh buffer should be empty")
	}
	r.Write(nil)
	if len(r.Bytes()) != 0 {
		t.Fatal("writing nothing should change nothing")
	}
}

func TestControlRoundTrip(t *testing.T) {
	original := Control{
		Type:       ControlHostKeyPrompt,
		TerminalID: "term-1",
		HostKey: &HostKeyInfo{
			Hostname:    "router1.example.com",
			Port:        22,
			KeyType:     "ssh-ed25519",
			Fingerprint: "SHA256:abc123",
		},
	}

	encoded, err := original.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeControl(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Type != original.Type || decoded.TerminalID != original.TerminalID {
		t.Fatalf("control message did not round-trip: %+v", decoded)
	}
	if decoded.HostKey == nil || decoded.HostKey.Fingerprint != "SHA256:abc123" {
		t.Fatalf("host key info did not round-trip: %+v", decoded.HostKey)
	}
}

func TestDecodeControlRejectsRubbish(t *testing.T) {
	cases := map[string]string{
		"not json":   "this is not json",
		"empty":      "",
		"no type":    `{"cols":80}`,
		"json array": `["resize"]`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeControl([]byte(input)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestErrorMessagesCarryACode confirms the interface can branch on a failure
// without matching on prose, which would break the moment wording changed.
func TestErrorMessagesCarryACode(t *testing.T) {
	msg := errorMessage(ErrCodeHostKeyChanged, "The host key has changed.")
	if msg.Type != ControlError {
		t.Errorf("type = %q", msg.Type)
	}
	if msg.Code != ErrCodeHostKeyChanged {
		t.Errorf("code = %q", msg.Code)
	}
	if msg.Message == "" {
		t.Error("a human-readable message should accompany the code")
	}
}

func TestStatusMessage(t *testing.T) {
	msg := statusMessage(StatusConnected)
	if msg.Type != ControlStatus || msg.Status != StatusConnected {
		t.Fatalf("got %+v", msg)
	}
}

// TestReplayBytesIsSensible guards against the buffer being tuned to
// something that would either lose useful context or hold megabytes per idle
// terminal.
func TestReplayBytesIsSensible(t *testing.T) {
	if ReplayBytes < 64*1024 {
		t.Errorf("ReplayBytes = %d; too small to restore useful context after a reconnect", ReplayBytes)
	}
	if ReplayBytes > 4*1024*1024 {
		t.Errorf("ReplayBytes = %d; an idle terminal would hold too much", ReplayBytes)
	}
}

func TestDetachedGraceIsSensible(t *testing.T) {
	if DetachedGrace < time.Minute {
		t.Error("the grace period is too short to survive a lift or a tunnel")
	}
	if DetachedGrace > time.Hour {
		t.Error("a forgotten tab would hold a production session open too long")
	}
}

// TestReplayPreservesOrder is what makes a reattached terminal legible: the
// scrollback must read the way it was printed.
func TestReplayPreservesOrder(t *testing.T) {
	r := newRingBuffer(ReplayBytes)

	var expected bytes.Buffer
	for i := 0; i < 100; i++ {
		line := strings.Repeat("x", 40) + "\n"
		r.Write([]byte(line))
		expected.WriteString(line)
	}

	if got := string(r.Bytes()); got != expected.String() {
		t.Fatal("replay did not preserve the order output was written in")
	}
}
