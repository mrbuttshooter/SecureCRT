package portability

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/mrbuttshooter/securecrt/internal/portability/ppk"
	"golang.org/x/crypto/ssh"
)

// Reading the keys a PuTTY user actually has.
//
// PuTTY sessions name a key by path, not by value, so a session list on its
// own arrives with the keys missing. Uploading the .ppk files alongside it
// closes that gap: they are converted to OpenSSH keys here, which is what
// PuTTYgen's "Export OpenSSH key" does one file at a time.
//
// The converted key is stored unencrypted, because the vault encrypts it
// again on the way in. A second passphrase the user has to remember, on top
// of the vault passphrase that already protects it, would be protection
// against nothing.

// maxPPKFiles bounds how many key files one upload may contain.
const maxPPKFiles = 10000

// puttyKeys is the result of scanning an upload for .ppk files.
type puttyKeys struct {
	// credentials is what to import.
	credentials []Credential

	// byName maps a key's basename, lowercased, to its credential ID, so a
	// session naming "C:\Users\me\keys\core.ppk" finds it.
	byName map[string]string

	warnings []string
	notes    []string
}

// readPuTTYKeys walks an uploaded tree and converts every .ppk in it.
//
// Failures are warnings rather than errors. A directory of keys where one is
// corrupt, or protected by a passphrase nobody remembers, should still bring
// the other nineteen across — an import that refuses everything because of
// one bad file is an import nobody can use.
func readPuTTYKeys(fsys fs.FS, passphrase string) puttyKeys {
	out := puttyKeys{byName: map[string]string{}}

	var paths []string
	_ = fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is skipped, not fatal
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".ppk") {
			paths = append(paths, name)
		}
		if len(paths) >= maxPPKFiles {
			return fs.SkipAll
		}
		return nil
	})

	if len(paths) == 0 {
		return out
	}

	// Stable order, so two imports of one upload produce the same result and
	// the same credential names.
	sort.Strings(paths)

	var (
		needPassphrase []string
		wrongSecret    []string
		converted      int
	)

	for _, name := range paths {
		data, err := readAtMost(fsys, name, ppk.MaxFileBytes)
		if err != nil {
			out.warnings = append(out.warnings,
				fmt.Sprintf("%s could not be read: %v", path.Base(name), err))
			continue
		}

		key, err := ppk.Parse(data, []byte(passphrase))
		switch {
		case err == ppk.ErrPassphraseRequired:
			needPassphrase = append(needPassphrase, path.Base(name))
			continue
		case err == ppk.ErrWrongPassphrase:
			wrongSecret = append(wrongSecret, path.Base(name))
			continue
		case err != nil:
			out.warnings = append(out.warnings,
				fmt.Sprintf("%s is not a key this reader understands: %v", path.Base(name), err))
			continue
		}

		material, err := key.OpenSSH()
		if err != nil {
			out.warnings = append(out.warnings,
				fmt.Sprintf("%s could not be converted: %v", path.Base(name), err))
			continue
		}

		public, err := key.PublicKey()
		if err != nil {
			out.warnings = append(out.warnings,
				fmt.Sprintf("%s has an unreadable public half: %v", path.Base(name), err))
			continue
		}

		label := strings.TrimSuffix(path.Base(name), path.Ext(name))
		if key.Comment != "" && key.Comment != label {
			label = fmt.Sprintf("%s (%s)", label, key.Comment)
		}

		credential := Credential{
			ID:          uuid.Must(uuid.NewV7()).String(),
			Name:        "PuTTY: " + label,
			Kind:        "ssh_key",
			Secret:      string(material),
			PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))),
			Fingerprint: ssh.FingerprintSHA256(public),
			KeyType:     public.Type(),
		}

		out.credentials = append(out.credentials, credential)
		out.byName[strings.ToLower(path.Base(name))] = credential.ID
		converted++
	}

	if converted > 0 {
		out.notes = append(out.notes, fmt.Sprintf(
			"Converted %d PuTTY key file%s to OpenSSH format. Your vault encrypts "+
				"them, so they are stored without a separate passphrase.",
			converted, plural(converted)))
	}

	if len(needPassphrase) > 0 {
		out.warnings = append(out.warnings, fmt.Sprintf(
			"%d key file%s encrypted and no passphrase was given (%s). "+
				"Supply it and import again to bring them across.",
			len(needPassphrase), isAre(len(needPassphrase)), firstFew(needPassphrase)))
	}
	if len(wrongSecret) > 0 {
		out.warnings = append(out.warnings, fmt.Sprintf(
			"The passphrase given did not open %d key file%s (%s). "+
				"PuTTY allows a different passphrase on each key.",
			len(wrongSecret), plural(len(wrongSecret)), firstFew(wrongSecret)))
	}

	return out
}

// readAtMost reads a file, refusing one larger than the limit rather than
// truncating it — a truncated key is not a key, and reporting it as one would
// produce a confusing failure much later.
func readAtMost(fsys fs.FS, name string, limit int64) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than the %d byte limit", limit)
	}
	return data, nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isAre(n int) string {
	if n == 1 {
		return " is"
	}
	return "s are"
}

// firstFew names up to three files, so a warning about twenty of them is
// still a sentence rather than a wall.
func firstFew(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:3], ", "), len(names)-3)
}
