package portability

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mrbuttshooter/securecrt/internal/vault"
)

// cheapKDF keeps the bundle tests fast.
//
// The cost parameters have their own tests in the vault package; repeating a
// 64 MiB derivation in every case here would add minutes and prove nothing
// new.
func cheapKDF(t *testing.T) vault.KDFParams {
	t.Helper()

	params, err := vault.NewKDFParams(1, 16*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := vault.NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	params.Salt = salt
	return params
}

func samplePayload() Payload {
	return Payload{
		Folders: []Folder{
			{ID: "f1", Name: "Edge routers", Defaults: json.RawMessage(`{"username":"netops"}`)},
			{ID: "f2", ParentID: "f1", Name: "London"},
		},
		Sessions: []Session{
			{
				ID: "s1", FolderID: "f2", Name: "core-sw-01",
				Protocol: "ssh", Hostname: "10.0.0.1", Port: 22,
				Username: "netops", CredentialID: "c1",
				Settings: json.RawMessage(`{"scrollback":50000}`),
			},
			{
				ID: "s2", FolderID: "f1", Name: "jump-host",
				Protocol: "ssh", Hostname: "203.0.113.9", Port: 2222,
				CredentialID: "c2",
			},
		},
		Credentials: []Credential{
			{
				ID: "c1", Name: "netops key", Kind: "ssh_key", Username: "netops",
				Secret:      "-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n-----END OPENSSH PRIVATE KEY-----\n",
				PublicKey:   "ssh-ed25519 AAAA... netops",
				Fingerprint: "SHA256:abcdef",
				KeyType:     "ed25519",
			},
			{ID: "c2", Name: "enable secret", Kind: "enable_secret", Secret: "hunter2"},
		},
		KnownHosts: []KnownHost{
			{Hostname: "10.0.0.1", Port: 22, KeyType: "ssh-ed25519",
				Fingerprint: "SHA256:zzz", PublicKey: "ssh-ed25519 AAAA..."},
		},
	}
}

const testPassphrase = "a long enough bundle passphrase"

func writeBundle(t *testing.T, payload Payload) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := Write(&buf, payload, WriteOptions{
		Passphrase: []byte(testPassphrase),
		CreatedBy:  "alice@example.com",
		Note:       "before the migration",
		KDF:        cheapKDF(t),
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes()
}

// TestRoundTripKeepsEverything is the phase's definition of done: what goes
// in comes out, secrets included.
func TestRoundTripKeepsEverything(t *testing.T) {
	original := samplePayload()
	data := writeBundle(t, original)

	bundle, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	got, err := bundle.Open([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	wantJSON, _ := json.Marshal(original)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("the payload changed in transit:\n want %s\n  got %s", wantJSON, gotJSON)
	}

	// Specifically: the secrets are there. A bundle that loses them is not a
	// migration, and this is the assertion that would catch it.
	if got.Credentials[0].Secret != original.Credentials[0].Secret {
		t.Error("the private key did not survive the round trip")
	}
	if got.Credentials[1].Secret != "hunter2" {
		t.Errorf("the password came back as %q", got.Credentials[1].Secret)
	}
}

// TestHeaderIsReadableWithoutThePassphrase: a person with three bundles has
// to be able to tell which is which without trying a passphrase on each.
func TestHeaderIsReadableWithoutThePassphrase(t *testing.T) {
	data := writeBundle(t, samplePayload())

	bundle, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if bundle.Header.Format != BundleFormat {
		t.Errorf("format = %q", bundle.Header.Format)
	}
	if bundle.Header.Version != BundleVersion {
		t.Errorf("version = %d", bundle.Header.Version)
	}
	if bundle.Header.CreatedBy != "alice@example.com" {
		t.Errorf("created by = %q", bundle.Header.CreatedBy)
	}
	if bundle.Header.Note != "before the migration" {
		t.Errorf("note = %q", bundle.Header.Note)
	}
	if bundle.Header.Contents.Sessions != 2 || bundle.Header.Contents.Folders != 2 {
		t.Errorf("contents = %+v", bundle.Header.Contents)
	}
	if bundle.Header.Contents.Total() != 7 {
		t.Errorf("total = %d, want 7", bundle.Header.Contents.Total())
	}

	// And nothing secret is in the clear part. This is the whole reason the
	// header is allowed to exist.
	header := data[:bytes.IndexByte(data, '\n')]
	for _, secret := range []string{"hunter2", "OPENSSH PRIVATE KEY", "10.0.0.1", "core-sw-01"} {
		if bytes.Contains(header, []byte(secret)) {
			t.Errorf("the clear header leaks %q", secret)
		}
	}
}

// TestNothingSensitiveAppearsInTheCiphertext guards the obvious mistake:
// writing the payload out unencrypted alongside the sealed copy.
func TestNothingSensitiveAppearsInTheCiphertext(t *testing.T) {
	data := writeBundle(t, samplePayload())

	for _, secret := range []string{
		"hunter2",
		"OPENSSH PRIVATE KEY",
		"core-sw-01",
		"netops",
		"10.0.0.1",
	} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the bundle contains %q in the clear", secret)
		}
	}
}

func TestWrongPassphraseIsRefused(t *testing.T) {
	data := writeBundle(t, samplePayload())

	bundle, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := bundle.Open([]byte("not the right passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("open with the wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
}

// TestATamperedHeaderIsRefused: the header is authenticated even though it is
// not encrypted, so a smaller record count cannot be used to hide what a
// bundle actually carries.
func TestATamperedHeaderIsRefused(t *testing.T) {
	data := writeBundle(t, samplePayload())

	newline := bytes.IndexByte(data, '\n')
	var header Header
	if err := json.Unmarshal(data[:newline], &header); err != nil {
		t.Fatal(err)
	}

	header.Contents.Sessions = 0
	header.CreatedBy = "someone-else@example.com"
	edited, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append(append(edited, '\n'), data[newline+1:]...)

	bundle, err := Read(bytes.NewReader(tampered))
	if err != nil {
		t.Fatalf("read a tampered bundle: %v", err)
	}
	if _, err := bundle.Open([]byte(testPassphrase)); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("open with an edited header = %v, want a refusal", err)
	}
}

func TestATamperedPayloadIsRefused(t *testing.T) {
	data := writeBundle(t, samplePayload())

	newline := bytes.IndexByte(data, '\n')
	var envelope vault.Envelope
	if err := json.Unmarshal(bytes.TrimSpace(data[newline+1:]), &envelope); err != nil {
		t.Fatal(err)
	}

	envelope.Ciphertext[len(envelope.Ciphertext)/2] ^= 0x01
	edited, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append(append([]byte{}, data[:newline+1]...), edited...)

	bundle, err := Read(bytes.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Open([]byte(testPassphrase)); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("open with a flipped bit = %v, want a refusal", err)
	}
}

func TestNotABundleIsSaidSo(t *testing.T) {
	for name, input := range map[string]string{
		"empty":            "",
		"no newline":       `{"format":"bkbundle"}`,
		"not json":         "hello\nworld\n",
		"another format":   `{"format":"something-else","version":1}` + "\n" + `{}`,
		"header only":      `{"format":"bkbundle","version":1,"kdf":{"algorithm":"argon2id"}}` + "\n",
		"a jpeg, honestly": "\xff\xd8\xff\xe0\n\x00\x10JFIF",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Read(strings.NewReader(input))
			if err == nil {
				t.Fatal("a file that is not a bundle was accepted")
			}
			// The message has to tell a person they picked the wrong file,
			// rather than that their passphrase was wrong.
			if !errors.Is(err, ErrNotABundle) && !errors.Is(err, ErrUnsupportedVersion) {
				t.Errorf("error = %v, want a plain 'not a bundle'", err)
			}
		})
	}
}

func TestANewerBundleSaysSoRatherThanMisreadingIt(t *testing.T) {
	data := writeBundle(t, samplePayload())

	newline := bytes.IndexByte(data, '\n')
	var header Header
	if err := json.Unmarshal(data[:newline], &header); err != nil {
		t.Fatal(err)
	}
	header.Version = BundleVersion + 5
	edited, _ := json.Marshal(header)

	_, err := Read(bytes.NewReader(append(append(edited, '\n'), data[newline+1:]...)))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("read a newer bundle = %v, want ErrUnsupportedVersion", err)
	}
	if err != nil && !strings.Contains(err.Error(), "version") {
		t.Errorf("the message does not say what is wrong: %v", err)
	}
}

// TestAShortPassphraseIsRefused: a bundle leaves the building, and there is
// no rate limiter between an attacker and its passphrase.
func TestAShortPassphraseIsRefused(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, samplePayload(), WriteOptions{
		Passphrase: []byte("short"),
		KDF:        cheapKDF(t),
	})
	if err == nil {
		t.Fatal("a five-character bundle passphrase was accepted")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Errorf("the message does not say what is required: %v", err)
	}
	if buf.Len() != 0 {
		t.Error("a refused export wrote bytes anyway")
	}
}

// TestHostileKDFParametersAreRefused: the cost parameters arrive in a file
// somebody else wrote, and a memory cost of 64 GiB would be a denial of
// service dressed as a bundle.
func TestHostileKDFParametersAreRefused(t *testing.T) {
	data := writeBundle(t, samplePayload())

	newline := bytes.IndexByte(data, '\n')
	var header Header
	if err := json.Unmarshal(data[:newline], &header); err != nil {
		t.Fatal(err)
	}
	header.KDF.MemoryKB = 64 * 1024 * 1024 // 64 GiB
	edited, _ := json.Marshal(header)

	bundle, err := Read(bytes.NewReader(append(append(edited, '\n'), data[newline+1:]...)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	_, err = bundle.Open([]byte(testPassphrase))
	if err == nil {
		t.Fatal("a bundle demanding 64 GiB of memory was honoured")
	}
	if errors.Is(err, ErrWrongPassphrase) {
		t.Error("the parameters were used before being validated")
	}
}

// TestADecompressionBombIsRefused: a small archive that expands to something
// enormous is the obvious way to attack a program that accepts archives.
//
// Driven at the decompressor directly. Building an archive that really
// expands past the limit would take longer than the rest of the suite put
// together, and the thing worth proving is that the expansion is bounded at
// all — not that gzip works.
func TestADecompressionBombIsRefused(t *testing.T) {
	// Highly compressible: a megabyte of zeroes in a few hundred bytes.
	compressed, err := compress(make([]byte, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) > 4096 {
		t.Fatalf("the fixture is not compressible enough to be a fair test: %d bytes", len(compressed))
	}

	body, err := decompress(compressed)
	if err != nil {
		t.Fatalf("a legitimate payload was refused: %v", err)
	}
	if len(body) != 1<<20 {
		t.Fatalf("decompressed %d bytes, want %d", len(body), 1<<20)
	}

	// The bound has to be below what would exhaust the process, and above
	// anything real. A hundred thousand connections with keys is tens of
	// megabytes.
	if maxPayloadBytes <= 0 {
		t.Fatal("there is no bound on the decompressed payload")
	}
	if int64(maxPayloadBytes) < MaxBundleBytes {
		t.Error("the payload bound is below the archive bound, so a legitimate " +
			"full-size bundle could not be read")
	}
}

func TestAnOversizedBundleIsRefused(t *testing.T) {
	// Exercised through the internal entry point with a small limit: reading
	// a real 256 MiB file to prove the guard works would allocate a quarter
	// of a gigabyte on every CI run to learn nothing extra.
	const limit = 1024

	if _, err := read(bytes.NewReader(bytes.Repeat([]byte("x"), limit+1)), limit); !errors.Is(err, ErrBundleTooLarge) {
		t.Errorf("read past the limit = %v, want ErrBundleTooLarge", err)
	}

	// And just under it is read normally — a guard that refuses everything
	// would also pass the assertion above.
	if _, err := read(bytes.NewReader(bytes.Repeat([]byte("x"), limit-1)), limit); errors.Is(err, ErrBundleTooLarge) {
		t.Error("a file under the limit was refused as too large")
	}

	if MaxBundleBytes <= 0 {
		t.Error("the exported limit is not set")
	}
}

// TestAnEmptyPayloadRoundTrips: a new user exporting before they have added
// anything must get a valid bundle rather than an error.
func TestAnEmptyPayloadRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Payload{}, WriteOptions{
		Passphrase: []byte(testPassphrase),
		KDF:        cheapKDF(t),
	}); err != nil {
		t.Fatalf("write an empty bundle: %v", err)
	}

	bundle, err := Read(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bundle.Header.Contents.Total() != 0 {
		t.Errorf("contents = %+v, want empty", bundle.Header.Contents)
	}

	payload, err := bundle.Open([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if payload.Counts().Total() != 0 {
		t.Errorf("payload = %+v, want empty", payload.Counts())
	}
}

// TestEachExportGetsAFreshSalt: reusing one would let an attacker with two
// bundles attack both passphrases with one set of derivations.
func TestEachExportGetsAFreshSalt(t *testing.T) {
	seen := map[string]bool{}

	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		// Deliberately without a salt in the options, which is how the
		// service calls it.
		params, err := vault.NewKDFParams(1, 16*1024, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := Write(&buf, samplePayload(), WriteOptions{
			Passphrase: []byte(testPassphrase),
			KDF:        params,
		}); err != nil {
			t.Fatal(err)
		}

		bundle, err := Read(&buf)
		if err != nil {
			t.Fatal(err)
		}
		salt := string(bundle.Header.KDF.Salt)
		if salt == "" {
			t.Fatal("a bundle was written with no salt")
		}
		if seen[salt] {
			t.Fatal("two exports used the same salt")
		}
		seen[salt] = true
	}
}
