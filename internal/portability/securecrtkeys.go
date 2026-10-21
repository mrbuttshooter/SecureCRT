package portability

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/mrbuttshooter/securecrt/internal/portability/ppk"
	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// maxIndexedFiles bounds how much of an upload is indexed while looking for
// key files: a Config folder is a few hundred files, and anything far beyond
// that is not a SecureCRT configuration.
const maxIndexedFiles = 20000

// secureCRTKeys finds and converts the private keys SecureCRT sessions name.
//
// SecureCRT keeps a key by path, outside its configuration, so a key comes
// across only when its file was uploaded beside the Config folder. Each file
// becomes one credential however many sessions use it: SecureCRT's own model
// is one key file shared by every session that names it, and a credential
// per session would turn one key rotation into hundreds.
//
// What SecureCRT does not keep is the key's passphrase: it is asked for at
// connect time and at most cached in memory, never written to the config.
// So an encrypted key is opened with the passphrase given at import, and
// stored decrypted — the vault encrypts it — or, without one, imported as it
// is, with the passphrase to be set on the credential.
type secureCRTKeys struct {
	fsys       fs.FS
	passphrase string
	prefix     string

	// index maps a lower-cased base name to every path with that name.
	index map[string][]string
	// done remembers each file already turned into a credential.
	done map[string]string

	credentials []Credential
	warnings    []string

	// missing groups the sessions whose key was not found, by stored path,
	// so a key used by two hundred sessions is reported once.
	missing map[string][]string
	// failed holds one message per key file that was found but not usable.
	failed map[string]string

	converted int
}

func newSecureCRTKeys(fsys fs.FS, passphrase, prefix string) *secureCRTKeys {
	k := &secureCRTKeys{
		fsys: fsys, passphrase: passphrase, prefix: prefix,
		index:   map[string][]string{},
		done:    map[string]string{},
		missing: map[string][]string{},
		failed:  map[string]string{},
	}
	if fsys == nil {
		return k
	}
	count := 0
	_ = fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is skipped, not fatal
		}
		if count++; count > maxIndexedFiles {
			return fs.SkipAll
		}
		if strings.EqualFold(path.Ext(name), ".ini") {
			return nil
		}
		key := strings.ToLower(path.Base(name))
		k.index[key] = append(k.index[key], name)
		return nil
	})
	for name := range k.index {
		sort.Strings(k.index[name])
	}
	return k
}

// credentialFor returns the credential for the key a session names, or ""
// when there is none to give. sessionName is for the messages.
func (k *secureCRTKeys) credentialFor(raw, sessionName string) string {
	identity := securecrt.ResolveIdentity(raw)
	if identity.Hardware {
		k.failed["hardware:"+raw] = fmt.Sprintf(
			"%q signs in with a smart card or token key (%s). There is no key file to copy, "+
				"so give the connection a key or password here instead.", sessionName, raw)
		return ""
	}
	if len(identity.Names) == 0 {
		return ""
	}

	candidates := []string{}
	if identity.Relative != "" {
		candidates = append(candidates, identity.Relative)
		if path.Ext(identity.Relative) == "" {
			candidates = append(candidates, identity.Relative+".ppk")
		}
	}
	for _, name := range identity.Names {
		matches, ambiguous := k.pick(name, raw)
		if ambiguous != "" {
			k.failed["ambiguous:"+strings.ToLower(name)] = ambiguous
			return ""
		}
		candidates = append(candidates, matches...)
	}

	found := false
	var tried []string
	for _, candidate := range candidates {
		// Each file is read and judged once, however many sessions name it:
		// a configuration of thousands of sessions on one key must not mean
		// thousands of reads of it.
		if id, ok := k.done[candidate]; ok {
			if id != "" {
				k.forget(tried)
				return id
			}
			found = true
			tried = append(tried, candidate)
			continue
		}
		if k.fsys == nil {
			continue
		}
		data, err := readAtMost(k.fsys, candidate, ppk.MaxFileBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			found = true
			k.done[candidate] = ""
			k.failed[candidate] = fmt.Sprintf("%s could not be read: %v", path.Base(candidate), err)
			tried = append(tried, candidate)
			continue
		}
		found = true
		credential, problem := k.convert(data, candidate)
		if credential == nil {
			k.done[candidate] = ""
			k.failed[candidate] = problem
			tried = append(tried, candidate)
			continue
		}
		if problem != "" {
			k.warnings = append(k.warnings, problem)
		}
		k.done[candidate] = credential.ID
		k.credentials = append(k.credentials, *credential)
		k.forget(tried)
		return credential.ID
	}

	if !found {
		k.missing[raw] = append(k.missing[raw], sessionName)
	}
	return ""
}

// forget drops the failures recorded for files that a later candidate made
// irrelevant — an unreadable SecureCRT-format Identity beside an
// Identity.ppk that imported is not something to warn about.
func (k *secureCRTKeys) forget(paths []string) {
	for _, p := range paths {
		delete(k.failed, p)
	}
}

// pick chooses among the uploaded files called name. One is the answer; with
// several — two different id_rsa files from two folders — the one whose
// folders match the end of SecureCRT's stored path wins, and if that still
// does not decide it, nothing is attached rather than possibly the wrong key.
func (k *secureCRTKeys) pick(name, raw string) (matches []string, ambiguous string) {
	all := k.index[strings.ToLower(name)]
	if len(all) <= 1 {
		return all, ""
	}

	stored := strings.Split(strings.ToLower(strings.ReplaceAll(raw, `\`, "/")), "/")
	if len(stored) > 0 {
		stored = stored[:len(stored)-1] // the directories only
	}
	score := func(p string) int {
		dirs := strings.Split(strings.ToLower(path.Dir(p)), "/")
		n := 0
		for i, j := len(dirs)-1, len(stored)-1; i >= 0 && j >= 0 && dirs[i] == stored[j]; i, j = i-1, j-1 {
			n++
		}
		return n
	}

	best, bestScore, tie := "", -1, false
	for _, p := range all {
		switch s := score(p); {
		case s > bestScore:
			best, bestScore, tie = p, s, false
		case s == bestScore:
			tie = true
		}
	}
	if tie {
		return nil, fmt.Sprintf("The upload has %d files called %s (%s), and the session's "+
			"key path %s does not say which one it uses. Keep only the right one in the zip "+
			"and import again.", len(all), name, firstFew(all), raw)
	}
	return []string{best}, ""
}

// convert turns one key file into a credential, or explains why it cannot.
// A credential with a message means it imported with a caveat.
func (k *secureCRTKeys) convert(data []byte, name string) (*Credential, string) {
	base := path.Base(name)
	text := bytes.TrimSpace(data)

	credential := &Credential{
		ID:   uuid.Must(uuid.NewV7()).String(),
		Name: fmt.Sprintf("%s key: %s", k.prefix, strings.TrimSuffix(base, path.Ext(base))),
		Kind: "ssh_key",
	}

	switch {
	case bytes.HasPrefix(text, []byte("PuTTY-User-Key-File-")):
		key, err := ppk.Parse(data, []byte(k.passphrase))
		switch {
		case errors.Is(err, ppk.ErrPassphraseRequired):
			return nil, fmt.Sprintf("%s is a PuTTY key protected by a passphrase. Enter it as "+
				"the key passphrase and import again.", base)
		case errors.Is(err, ppk.ErrWrongPassphrase):
			return nil, fmt.Sprintf("The key passphrase given did not open %s.", base)
		case err != nil:
			return nil, fmt.Sprintf("%s is not a PuTTY key this reader understands: %v", base, err)
		}
		material, err := key.OpenSSH()
		if err != nil {
			return nil, fmt.Sprintf("%s could not be converted: %v", base, err)
		}
		public, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Sprintf("%s has an unreadable public half: %v", base, err)
		}
		credential.Secret = string(material)
		describe(credential, public)
		k.converted++
		return credential, ""

	case bytes.Contains(text, []byte("PRIVATE KEY-----")) && bytes.HasPrefix(text, []byte("-----BEGIN ")):
		raw, err := ssh.ParseRawPrivateKey(data)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			if k.passphrase == "" {
				// Still worth bringing: it works once its passphrase is set
				// on the credential, and leaving it behind helps nobody.
				credential.Secret = string(data)
				if missing.PublicKey != nil {
					describe(credential, missing.PublicKey)
				}
				return credential, fmt.Sprintf("%s is encrypted. It was imported, but enter its "+
					"passphrase on the credential (or as the key passphrase here) before it will connect.", base)
			}
			raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(k.passphrase))
			if err != nil {
				return nil, fmt.Sprintf("The key passphrase given did not open %s.", base)
			}
		} else if err != nil {
			return nil, fmt.Sprintf("%s is not a private key this reader understands: %v", base, err)
		}

		// Stored decrypted: the vault is what protects it now, and a second
		// passphrase would only be something else to forget.
		block, err := ssh.MarshalPrivateKey(raw, "")
		if err != nil {
			return nil, fmt.Sprintf("%s could not be converted: %v", base, err)
		}
		signer, err := ssh.NewSignerFromKey(raw)
		if err != nil {
			return nil, fmt.Sprintf("%s could not be read: %v", base, err)
		}
		credential.Secret = string(pem.EncodeToMemory(block))
		describe(credential, signer.PublicKey())
		k.converted++
		return credential, ""

	case bytes.Contains(text, []byte("BEGIN SSH2 ENCRYPTED PRIVATE KEY")):
		return nil, fmt.Sprintf("%s is in the SSH Communications (ssh.com) format, which this "+
			"importer does not read. Convert it to OpenSSH format and import again.", base)

	case bytes.Contains(text, []byte("BEGIN SSH2 PUBLIC KEY")) || bytes.HasPrefix(text, []byte("ssh-")) ||
		bytes.HasPrefix(text, []byte("ecdsa-")):
		return nil, fmt.Sprintf("%s holds only a public key; the private key is the file "+
			"beside it with the same name and no .pub.", base)

	default:
		// SecureCRT's own private-key format, which VanDyke documents only
		// as proprietary. SecureCRT itself converts it, and that is far safer
		// than guessing at an undocumented layout.
		return nil, fmt.Sprintf("%s is in SecureCRT's own key format, which only VanDyke "+
			"software reads. In SecureCRT choose Tools → Convert Private Key to OpenSSH "+
			"Format, pick this key, save the result in its place (same name), add it to "+
			"the zip and import again.", base)
	}
}

func describe(credential *Credential, public ssh.PublicKey) {
	credential.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	credential.Fingerprint = ssh.FingerprintSHA256(public)
	credential.KeyType = public.Type()
}

// report adds what happened to the keys to an import's warnings and notes.
func (k *secureCRTKeys) report(out *Import, fromXML bool) {
	if k.converted > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"Imported %d SecureCRT key file%s. Your vault encrypts them, so they are "+
				"stored without a separate passphrase.", k.converted, plural(k.converted)))
	}
	out.Warnings = append(out.Warnings, k.warnings...)

	failures := make([]string, 0, len(k.failed))
	for _, message := range k.failed {
		failures = append(failures, message)
	}
	sort.Strings(failures)
	out.Warnings = append(out.Warnings, failures...)

	paths := make([]string, 0, len(k.missing))
	for raw := range k.missing {
		paths = append(paths, raw)
	}
	sort.Strings(paths)
	for _, raw := range paths {
		sessions := k.missing[raw]
		who := fmt.Sprintf("%q", sessions[0])
		if len(sessions) > 1 {
			who = fmt.Sprintf("%d sessions (%s and others)", len(sessions), who)
		}
		if fromXML {
			out.Warnings = append(out.Warnings, fmt.Sprintf(
				"%s use%s the key %s. A settings XML holds key paths, not keys: import the "+
					"zipped Config folder with the key file added to bring it across.",
				who, singularS(len(sessions)), raw))
			continue
		}
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%s use%s the key %s, which was not in the upload. SecureCRT keeps keys outside "+
				"its Config folder (by default Identity in Documents, or ~/.ssh): add the file "+
				"to the zip and import again.",
			who, singularS(len(sessions)), raw))
	}
}

// singularS is the verb ending for a subject of n: "uses" for one, "use" for many.
func singularS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}
