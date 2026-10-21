package securecrt

// Probe: does a SecureCRT settings-export XML carry a Config Passphrase that
// decrypts with an empty configuration passphrase?
//
// If it does, a user migrating from SecureCRT can bring every saved session
// password across without typing anything, because the settings export is
// (by design) portable. If it does not, the user has to type the config
// passphrase at import — the fallback we have today.
//
// Runs only when BKD_SECURECRT_PROBE_XML points at an XML the operator wants
// to test. Skipped in CI and on anyone else's machine. Only prints the first
// three characters of any recovered secret — enough to confirm the chain
// without dumping credentials into the test log.

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

type probeNode struct {
	XMLName xml.Name
	Name    string      `xml:"name,attr"`
	Value   string      `xml:",chardata"`
	Nodes   []probeNode `xml:",any"`
}

func (n probeNode) find(path ...string) *probeNode {
	cur := n
	for _, want := range path {
		var next *probeNode
		for i := range cur.Nodes {
			if cur.Nodes[i].Name == want {
				next = &cur.Nodes[i]
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = *next
	}
	return &cur
}

func probeMask(s string) string {
	if len(s) == 0 {
		return "<empty>"
	}
	if len(s) <= 6 {
		return fmt.Sprintf("<%d chars>", len(s))
	}
	return fmt.Sprintf("%q… (%d chars total)", s[:3], len(s))
}

func probeLooksPrintable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func TestConfigPassphraseRecoveryFromExport(t *testing.T) {
	path := os.Getenv("BKD_SECURECRT_PROBE_XML")
	if path == "" {
		t.Skip("set BKD_SECURECRT_PROBE_XML to the path of a SecureCRT export XML to run")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var root probeNode
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse: %v", err)
	}

	security := root.find("Security")
	if security == nil {
		t.Fatal("no <key name=\"Security\"> in the XML")
	}
	stored := strings.TrimSpace(security.find("Passphrase").Value)
	t.Logf("stored Security.Passphrase ciphertext: %q… (%d chars)", stored[:9], len(stored))

	candidates := []struct {
		label string
		input string
	}{
		{"empty", ""},
		{"vandyke", "vandyke"},
		{"SecureCRT", "SecureCRT"},
	}

	var winner string
	var found bool
	for _, c := range candidates {
		plain, err := DecryptPassword(stored, c.input)
		if err != nil {
			t.Logf("  %-10s input: %v", c.label, err)
			continue
		}
		// A decrypt that returned nothing is still a decrypt: SecureCRT writes
		// the Configuration Passphrase into the export so a restore can read
		// it back, and when the user has no Configuration Passphrase set
		// (the default) the plaintext IS the empty string. Every session
		// password in the file is then encrypted under the same empty input.
		if !probeLooksPrintable(plain) && plain != "" {
			t.Logf("  %-10s input: decoded to %d non-printable bytes", c.label, len(plain))
			continue
		}
		t.Logf("  %-10s input: %s", c.label, probeMask(plain))
		if !found {
			winner, found = plain, true
			switch {
			case plain == "":
				t.Logf("  → the recovered Config Passphrase is empty: this installation has no master passphrase set")
			default:
				t.Logf("  → recovered the Config Passphrase using %q as input", c.label)
			}
		}
	}
	if !found {
		t.Fatal("the stored passphrase did not decrypt with any fixed input tried")
	}

	// Prove the end-to-end chain: use the recovered passphrase on a real
	// stored session password from the same file. First match only.
	re := regexp.MustCompile(`<string name="Password V2">([^<]+)</string>`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Log("no Password V2 found; config-passphrase recovery alone is enough")
		return
	}
	sessionPlain, err := DecryptPassword(string(m[1]), winner)
	if err != nil {
		t.Fatalf("session password did not decrypt with the recovered config passphrase: %v", err)
	}
	t.Logf("sample session password: %s", probeMask(sessionPlain))
	t.Log("End-to-end chain works: the XML is self-recoverable.")
}
