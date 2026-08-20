// Package sftpx browses and moves files on a host over SFTP.
//
// It layers on an established sshx connection rather than dialling its own.
// SSH multiplexes channels, so a file transfer and a shell share one TCP
// connection, one authentication and — on equipment that counts them — one
// vty line. Opening a second connection just to list a directory is what
// makes a device refuse the fifth engineer of the morning.
//
// # Paths
//
// SFTP paths are always slash-separated, whatever the remote operating
// system, so this package uses "path" throughout and never "path/filepath".
// A server running on Windows would otherwise be addressed with the
// separator of whichever machine bkd happens to run on.
//
// # Contexts
//
// The underlying library predates contexts and mostly does not take them.
// Where a call is a single bounded round trip, cancellation is checked before
// it starts. Where a call streams — reads and writes, recursive walks — the
// context is honoured inside the loop, which is where a user cancelling a
// large transfer actually needs it to take effect.
package sftpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mrbuttshooter/securecrt/internal/proto/sshx"
	"github.com/pkg/sftp"
)

// Errors callers distinguish.
var (
	// ErrNotFound means the path does not exist.
	ErrNotFound = errors.New("sftpx: no such file or directory")

	// ErrPermission means the remote host refused on permissions.
	ErrPermission = errors.New("sftpx: permission denied")

	// ErrExists means the destination is already there.
	ErrExists = errors.New("sftpx: already exists")

	// ErrNotSupported means the server does not implement the operation.
	// Plenty of embedded SFTP servers omit chown, symlinks or statvfs.
	ErrNotSupported = errors.New("sftpx: the server does not support that")

	// ErrIsDirectory means a file operation was aimed at a directory.
	ErrIsDirectory = errors.New("sftpx: that is a directory")
)

// MaxConcurrentRequests bounds how many SFTP requests are in flight at once.
//
// The default of 64 is tuned for local networks. Transfers to equipment
// across a WAN benefit from more outstanding requests, because SFTP is
// request/response and latency otherwise dominates; 128 roughly doubles
// throughput on a 100 ms link without troubling a well-behaved server.
const MaxConcurrentRequests = 128

// MaxPacket is the payload size per read or write request.
//
// 32 KiB is the largest every SFTP server is required to accept. Larger
// packets are faster where they work and a hard failure where they do not,
// which is a poor trade for a tool meant to reach whatever is on the network.
const MaxPacket = 32 * 1024

// Client is an SFTP session on an existing SSH connection.
type Client struct {
	sftp *sftp.Client

	// names resolves numeric owners to names, read from the remote host once
	// and cached. Nil until loaded, and left nil on hosts that do not
	// publish them.
	names *nameTable
}

// Open starts an SFTP subsystem on an established SSH connection.
func Open(c *sshx.Client) (*Client, error) {
	if c == nil {
		return nil, errors.New("sftpx: no SSH connection")
	}

	client, err := sftp.NewClient(c.Conn(),
		sftp.MaxConcurrentRequestsPerFile(MaxConcurrentRequests),
		sftp.MaxPacket(MaxPacket),
		sftp.UseConcurrentReads(true),
		sftp.UseConcurrentWrites(true),
	)
	if err != nil {
		return nil, fmt.Errorf("sftpx: start the SFTP subsystem: %w", translate(err))
	}

	return &Client{sftp: client}, nil
}

// Close ends the SFTP session. The SSH connection underneath is untouched.
func (c *Client) Close() error {
	return c.sftp.Close()
}

// Entry describes one directory entry.
//
// Built by hand rather than passing os.FileInfo outward: the interesting
// parts of a remote listing — whether a symlink resolves to a directory, who
// owns it by name — are not on that interface, and the ones that are (Sys())
// hand callers a raw protocol struct to reinterpret.
type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`

	// Mode is the permission bits in octal, as a user would type them into
	// chmod: "0644". Rendered rather than numeric because that is the form
	// the value is discussed and entered in.
	Mode string `json:"mode"`

	// ModeString is the ls-style rendering: "drwxr-xr-x".
	ModeString string `json:"mode_string"`

	IsDir     bool `json:"is_dir"`
	IsSymlink bool `json:"is_symlink"`

	// LinkTarget is where a symlink points, unresolved. Empty if the link
	// could not be read.
	LinkTarget string `json:"link_target,omitempty"`

	// TargetIsDir reports whether a symlink resolves to a directory, so the
	// interface knows whether it can be navigated into. False for a broken
	// link, which is also how a broken link is detected.
	TargetIsDir bool `json:"target_is_dir,omitempty"`

	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`

	// Owner and Group are names when the host publishes them, empty
	// otherwise. Empty is not an error: plenty of appliances have no
	// /etc/passwd to read.
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
}

// List reads a directory.
//
// Symlinks cost one extra round trip each, to learn whether they resolve to a
// directory. That is worth paying: without it the interface cannot tell a
// user whether a link can be opened, and a browser that refuses to enter a
// symlinked directory is immediately annoying on any real system.
func (c *Client) List(ctx context.Context, dir string) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	dir = normalise(dir)

	infos, err := c.sftp.ReadDirContext(ctx, dir)
	if err != nil {
		return nil, translate(err)
	}

	entries := make([]Entry, 0, len(infos))
	for _, info := range infos {
		entry := c.entryFrom(dir, info)

		if entry.IsSymlink {
			c.resolveLink(&entry)
		}
		entries = append(entries, entry)
	}

	sortEntries(entries)
	return entries, nil
}

// Stat describes one path, following symlinks.
func (c *Client) Stat(ctx context.Context, p string) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}

	p = normalise(p)

	// Lstat first so a symlink is reported as one; Stat alone would silently
	// describe the target and the interface could not show the difference.
	info, err := c.sftp.Lstat(p)
	if err != nil {
		return Entry{}, translate(err)
	}

	entry := c.entryFrom(path.Dir(p), info)
	entry.Path = p
	entry.Name = path.Base(p)
	if entry.IsSymlink {
		c.resolveLink(&entry)
	}
	return entry, nil
}

// entryFrom converts one listing record.
func (c *Client) entryFrom(dir string, info os.FileInfo) Entry {
	mode := info.Mode()

	entry := Entry{
		Name:       info.Name(),
		Path:       path.Join(dir, info.Name()),
		Size:       info.Size(),
		ModTime:    info.ModTime(),
		Mode:       fmt.Sprintf("%04o", mode.Perm()),
		ModeString: mode.String(),
		IsDir:      mode.IsDir(),
		IsSymlink:  mode&fs.ModeSymlink != 0,
	}

	if stat, ok := info.Sys().(*sftp.FileStat); ok && stat != nil {
		entry.UID = stat.UID
		entry.GID = stat.GID
		if c.names != nil {
			entry.Owner = c.names.user(stat.UID)
			entry.Group = c.names.group(stat.GID)
		}
	}

	return entry
}

// resolveLink fills in where a symlink points and whether that is a directory.
//
// Failures are left as a broken link rather than surfaced: a dangling symlink
// is a normal thing to find in a directory, not a reason to fail the listing
// it appears in.
func (c *Client) resolveLink(entry *Entry) {
	target, err := c.sftp.ReadLink(entry.Path)
	if err != nil {
		return
	}
	entry.LinkTarget = target

	info, err := c.sftp.Stat(entry.Path)
	if err != nil {
		return
	}
	entry.TargetIsDir = info.IsDir()
}

// sortEntries orders a listing directories-first, then by name.
//
// Case-insensitively, because a listing that puts Makefile before readme and
// after README reads as though it were unsorted.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]

		aDir := a.IsDir || a.TargetIsDir
		bDir := b.IsDir || b.TargetIsDir
		if aDir != bDir {
			return aDir
		}

		lowerA, lowerB := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if lowerA != lowerB {
			return lowerA < lowerB
		}
		return a.Name < b.Name
	})
}

// RealPath resolves a path to its canonical absolute form.
func (c *Client) RealPath(p string) (string, error) {
	resolved, err := c.sftp.RealPath(normalise(p))
	if err != nil {
		return "", translate(err)
	}
	return resolved, nil
}

// Home is the directory an SFTP session starts in.
//
// Resolved from "." rather than assumed to be /home/<user>: it is whatever
// the server chose, which on network equipment is frequently neither.
func (c *Client) Home() (string, error) {
	return c.RealPath(".")
}

// Mkdir creates a directory, and any missing parents.
func (c *Client) Mkdir(p string) error {
	if err := c.sftp.MkdirAll(normalise(p)); err != nil {
		return translate(err)
	}
	return nil
}

// Rename moves a path. Used for both renaming and moving; SFTP has one verb.
func (c *Client) Rename(from, to string) error {
	from, to = normalise(from), normalise(to)

	// PosixRename replaces an existing destination atomically. Servers that
	// lack the extension fall back to plain rename, which refuses to
	// overwrite — a refusal is the safer failure, so the fallback is the
	// right way round.
	if err := c.sftp.PosixRename(from, to); err != nil {
		if fallbackErr := c.sftp.Rename(from, to); fallbackErr != nil {
			return translate(fallbackErr)
		}
	}
	return nil
}

// Remove deletes a file or an empty directory.
func (c *Client) Remove(p string) error {
	if err := c.sftp.Remove(normalise(p)); err != nil {
		return translate(err)
	}
	return nil
}

// RemoveAll deletes a path and everything beneath it.
//
// The context is checked as the walk proceeds, so cancelling a delete of a
// large tree stops rather than running to completion in the background.
func (c *Client) RemoveAll(ctx context.Context, p string) error {
	p = normalise(p)

	info, err := c.sftp.Lstat(p)
	if err != nil {
		return translate(err)
	}

	// A symlink to a directory is removed as a link. Following it would
	// delete the target's contents, which is never what "delete this link"
	// was meant to do.
	if !info.IsDir() {
		return c.Remove(p)
	}

	entries, err := c.sftp.ReadDirContext(ctx, p)
	if err != nil {
		return translate(err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.RemoveAll(ctx, path.Join(p, entry.Name())); err != nil {
			return err
		}
	}

	if err := c.sftp.RemoveDirectory(p); err != nil {
		return translate(err)
	}
	return nil
}

// Chmod sets permission bits.
func (c *Client) Chmod(p string, mode fs.FileMode) error {
	if err := c.sftp.Chmod(normalise(p), mode.Perm()); err != nil {
		return translate(err)
	}
	return nil
}

// Chown sets the owner and group.
//
// Either may be -1 to leave it alone, matching chown(2) — the interface needs
// to change a group without knowing or disturbing the owner.
func (c *Client) Chown(ctx context.Context, p string, uid, gid int) error {
	p = normalise(p)

	if uid < 0 || gid < 0 {
		info, err := c.Stat(ctx, p)
		if err != nil {
			return err
		}
		if uid < 0 {
			uid = int(info.UID)
		}
		if gid < 0 {
			gid = int(info.GID)
		}
	}

	if err := c.sftp.Chown(p, uid, gid); err != nil {
		return translate(err)
	}
	return nil
}

// Symlink creates a symbolic link at linkPath pointing at target.
func (c *Client) Symlink(target, linkPath string) error {
	if err := c.sftp.Symlink(target, normalise(linkPath)); err != nil {
		return translate(err)
	}
	return nil
}

// ReadLink returns where a symlink points, without resolving it.
func (c *Client) ReadLink(p string) (string, error) {
	target, err := c.sftp.ReadLink(normalise(p))
	if err != nil {
		return "", translate(err)
	}
	return target, nil
}

// Chtimes sets access and modification times.
func (c *Client) Chtimes(p string, atime, mtime time.Time) error {
	if err := c.sftp.Chtimes(normalise(p), atime, mtime); err != nil {
		return translate(err)
	}
	return nil
}

// Reader opens a file for reading from an offset.
//
// The offset is what makes a resumed download and an HTTP range request
// possible without re-reading everything before it.
func (c *Client) Reader(p string, offset int64) (io.ReadCloser, error) {
	f, err := c.sftp.Open(normalise(p))
	if err != nil {
		return nil, translate(err)
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, translate(err)
		}
	}
	return f, nil
}

// Writer opens a file for writing at an offset.
//
// At offset zero the file is truncated, which is what an overwrite means. At
// any other offset it is not, because that is a resumed upload continuing a
// partial file — truncating there would discard exactly the bytes the resume
// exists to keep.
func (c *Client) Writer(p string, offset int64) (io.WriteCloser, error) {
	p = normalise(p)

	flags := os.O_WRONLY | os.O_CREATE
	if offset == 0 {
		flags |= os.O_TRUNC
	}

	f, err := c.sftp.OpenFile(p, flags)
	if err != nil {
		return nil, translate(err)
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, translate(err)
		}
	}
	return f, nil
}

// Size reports a file's length, for resuming and for progress.
func (c *Client) Size(p string) (int64, error) {
	info, err := c.sftp.Stat(normalise(p))
	if err != nil {
		return 0, translate(err)
	}
	if info.IsDir() {
		return 0, ErrIsDirectory
	}
	return info.Size(), nil
}

// ParseMode reads permission bits written the way chmod takes them: "755",
// "0644", "0o600".
//
// The inverse of what Entry.Mode renders, so a value shown to a user can be
// handed straight back. Only the permission bits are accepted; setuid and the
// file-type bits are not settable through this path and quietly accepting
// them would misreport what happened.
func ParseMode(s string) (fs.FileMode, error) {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(s, "0o"), "0O")
	if trimmed == "" {
		return 0, fmt.Errorf("sftpx: %q is not a mode", s)
	}

	value, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("sftpx: %q is not an octal mode", s)
	}
	if value > 0o777 {
		return 0, fmt.Errorf("sftpx: %q sets bits beyond the permission bits", s)
	}

	return fs.FileMode(value), nil
}

// normalise cleans a path and makes a relative one relative to the session's
// starting directory, which is what a bare "docs" means to a user typing it.
func normalise(p string) string {
	if p == "" {
		return "."
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	return path.Clean(p)
}

// translate maps library and protocol errors onto the ones callers branch on.
//
// The SFTP status codes arrive as text on an *sftp.StatusError, so matching
// on the sentinel errors the library maps them to is more reliable than
// reading the message.
func translate(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %s", ErrNotFound, err)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w: %s", ErrPermission, err)
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("%w: %s", ErrExists, err)
	}

	var status *sftp.StatusError
	if errors.As(err, &status) {
		switch status.Code {
		case uint32(sftp.ErrSSHFxNoSuchFile):
			return fmt.Errorf("%w: %s", ErrNotFound, err)
		case uint32(sftp.ErrSSHFxPermissionDenied):
			return fmt.Errorf("%w: %s", ErrPermission, err)
		case uint32(sftp.ErrSSHFxOpUnsupported):
			return fmt.Errorf("%w: %s", ErrNotSupported, err)
		}
	}

	return err
}
