package portability

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/mrbuttshooter/securecrt/internal/portability/securecrt"
)

// Turning an uploaded file into a payload.
//
// This lives here rather than beside the HTTP handlers because the browser is
// not the only way in: an administrator migrating a team of eighty drives the
// same conversion from the command line. One code path means an import cannot
// behave differently depending on which door it came through.

// ErrUnknownSource names a source the reader has never heard of.
var ErrUnknownSource = errors.New("portability: unknown import source")

// ErrNotAnArchive reports a file that was expected to be a zip and was not.
var ErrNotAnArchive = errors.New("portability: this is not a zip archive")

// Bounds on what an uploaded zip may expand to.
//
// An archive's compressed size says nothing about its uncompressed size, so
// without these a few hundred kilobytes could ask for a few hundred gigabytes.
const (
	MaxArchiveEntries    = 200000
	MaxArchiveEntryBytes = 16 << 20
	MaxArchiveTotalBytes = 512 << 20
)

// UploadOptions carry the answers a particular source needs.
//
// One struct for every source rather than one per source: the fields are few,
// they are all optional, and a caller filling in the two that matter reads
// better than five near-identical option types.
type UploadOptions struct {
	// BundlePassphrase opens a .bkbundle.
	BundlePassphrase string

	// ConfigPassphrase is SecureCRT's own configuration passphrase, set in
	// its Global Options. Most installations have none.
	ConfigPassphrase string

	// SkipPasswords leaves SecureCRT's saved passwords behind.
	SkipPasswords bool

	// KeyPassphrase is tried against encrypted PuTTY .ppk files.
	KeyPassphrase string

	// ImportKeys and ImportKnownHosts control an OpenSSH directory import.
	ImportKeys       bool
	ImportKnownHosts bool

	// FolderName is where a CSV's rows land.
	FolderName string
}

// ReadUpload converts uploaded bytes into an Import.
//
// filename is used only to tell one shape of upload from another — a PuTTY
// .reg from a zipped .putty directory — and to name the file in an error.
func ReadUpload(source Source, filename string, data []byte, opts UploadOptions) (Import, error) {
	switch source {
	case SourceBundle:
		bundle, err := Read(bytes.NewReader(data))
		if err != nil {
			return Import{}, err
		}
		payload, err := bundle.Open([]byte(opts.BundlePassphrase))
		if err != nil {
			return Import{}, err
		}
		return Import{
			Source: SourceBundle, Payload: payload,
			Warnings: []string{}, Notes: []string{},
		}, nil

	case SourceSecureCRT:
		// Two official containers: the zipped Config folder, and the single
		// XML that Tools > Export Settings writes. The XML is often the only
		// artefact a locked-down desktop can produce, so both are welcome.
		if securecrt.IsSecureCRTXML(data) {
			return FromSecureCRTXML(data, SecureCRTOptions{
				ConfigPassphrase: opts.ConfigPassphrase,
				SkipPasswords:    opts.SkipPasswords,
			})
		}
		fsys, err := ArchiveFS(data, filename)
		if err != nil {
			return Import{}, err
		}
		return FromSecureCRT(fsys, SecureCRTOptions{
			ConfigPassphrase: opts.ConfigPassphrase,
			SkipPasswords:    opts.SkipPasswords,
		})

	case SourceOpenSSH:
		fsys, err := ArchiveFS(data, filename)
		if err != nil {
			return Import{}, err
		}
		return FromSSHDirectory(fsys, SSHConfigOptions{
			ImportKeys:       opts.ImportKeys,
			ImportKnownHosts: opts.ImportKnownHosts,
		})

	case SourcePuTTY:
		// A .reg is one file; a .putty directory arrives as an archive.
		if strings.HasSuffix(strings.ToLower(filename), ".reg") {
			return FromPuTTYRegistry(bytes.NewReader(data), PuTTYOptions{
				FolderName: opts.FolderName,
			})
		}
		fsys, err := ArchiveFS(data, filename)
		if err != nil {
			return Import{}, err
		}
		return FromPuTTYDirectory(fsys, PuTTYOptions{
			FolderName:    opts.FolderName,
			KeyPassphrase: opts.KeyPassphrase,
		})

	case SourceCSV:
		return FromCSV(bytes.NewReader(data), CSVOptions{FolderName: opts.FolderName})

	default:
		return Import{}, fmt.Errorf("%w: %q", ErrUnknownSource, source)
	}
}

// ArchiveFS opens an uploaded zip as a filesystem.
//
// Configurations are directories, and a browser can only upload files, so a
// zip is what arrives. The bounds are the whole reason this is not two lines.
func ArchiveFS(data []byte, filename string) (fs.FS, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotAnArchive, filename)
	}

	if len(reader.File) > MaxArchiveEntries {
		return nil, fmt.Errorf("portability: the archive holds more than %d files",
			MaxArchiveEntries)
	}

	var total uint64
	for _, entry := range reader.File {
		if entry.UncompressedSize64 > MaxArchiveEntryBytes {
			return nil, fmt.Errorf("portability: %s expands to more than %d MiB",
				entry.Name, MaxArchiveEntryBytes>>20)
		}
		total += entry.UncompressedSize64
		if total > MaxArchiveTotalBytes {
			return nil, fmt.Errorf("portability: the archive expands to more than %d MiB",
				MaxArchiveTotalBytes>>20)
		}
	}

	// A zip made by zipping a folder has everything under one directory,
	// which would put "Sessions" one level below where the readers look.
	return stripSingleRoot(reader), nil
}

// stripSingleRoot descends past a lone top-level directory.
//
// Zipping a folder on any desktop produces exactly that shape, so without
// this every upload would need the user to have zipped the folder's contents
// rather than the folder — a distinction nobody should have to know about.
func stripSingleRoot(reader *zip.Reader) fs.FS {
	root := ""
	for _, entry := range reader.File {
		name := strings.TrimPrefix(entry.Name, "./")
		if name == "" {
			continue
		}
		// Archives from macOS carry a metadata directory that is not part of
		// what the user zipped.
		if strings.HasPrefix(name, "__MACOSX/") {
			continue
		}

		slash := strings.Index(name, "/")
		if slash < 0 {
			return reader // a file at the top level: nothing to strip
		}

		first := name[:slash]
		if root == "" {
			root = first
			continue
		}
		if root != first {
			return reader
		}
	}

	if root == "" {
		return reader
	}
	nested, err := fs.Sub(reader, root)
	if err != nil {
		return reader
	}
	return nested
}
