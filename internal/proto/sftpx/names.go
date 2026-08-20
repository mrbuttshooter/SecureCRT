package sftpx

import (
	"bufio"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
)

// nameTable maps numeric owners to names.
//
// SFTP version 3 carries only numeric UIDs and GIDs in the attributes this
// library exposes, so a listing would otherwise read "1000 1000" where every
// other tool a user has ever used says "alice staff". The names are read from
// the host's own /etc/passwd and /etc/group over the same SFTP session.
//
// This is best-effort by design. Plenty of things worth connecting to — a
// switch, a router, an appliance with a cut-down SFTP server — have neither
// file, and there the listing simply shows numbers. That is a normal outcome,
// not a failure worth reporting.
type nameTable struct {
	mu     sync.RWMutex
	users  map[uint32]string
	groups map[uint32]string
}

// maxNameFileBytes bounds how much of /etc/passwd is read.
//
// A directory-service-backed host can have an enormous one, and the whole
// point here is a cheap nicety; spending megabytes of transfer on it before
// the first listing appears would be a bad trade. A file larger than this is
// read up to the limit and the remaining entries stay numeric.
const maxNameFileBytes = 512 * 1024

// LoadOwnerNames reads the host's user and group names.
//
// Call it once per session, before listing. Errors are deliberately not
// returned: every failure mode here — no such file, no permission, not a
// Unix host — means "show numbers", which is what happens if this is never
// called at all.
func (c *Client) LoadOwnerNames(ctx context.Context) {
	table := &nameTable{
		users:  map[uint32]string{},
		groups: map[uint32]string{},
	}

	table.users = c.readNameFile(ctx, "/etc/passwd")
	table.groups = c.readNameFile(ctx, "/etc/group")

	if len(table.users) == 0 && len(table.groups) == 0 {
		return
	}

	c.names = table
}

// readNameFile parses the colon-separated name:x:id: format both files share.
func (c *Client) readNameFile(ctx context.Context, p string) map[uint32]string {
	out := map[uint32]string{}

	f, err := c.sftp.Open(p)
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(io.LimitReader(f, maxNameFileBytes))
	for scanner.Scan() {
		if ctx.Err() != nil {
			return out
		}

		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}

		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}

		// First entry wins. Duplicate IDs happen — root and toor share 0 on
		// BSD — and the first is conventionally the canonical one.
		if _, seen := out[uint32(id)]; !seen {
			out[uint32(id)] = fields[0]
		}
	}

	return out
}

func (t *nameTable) user(uid uint32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.users[uid]
}

func (t *nameTable) group(gid uint32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.groups[gid]
}

// LookupUser resolves a username to a UID, so chown can be given a name.
//
// Reports false when names were never loaded or the name is unknown, which
// the caller distinguishes from a numeric ID the user typed directly.
func (c *Client) LookupUser(name string) (int, bool) {
	return lookup(c.names, func(t *nameTable) map[uint32]string { return t.users }, name)
}

// LookupGroup resolves a group name to a GID.
func (c *Client) LookupGroup(name string) (int, bool) {
	return lookup(c.names, func(t *nameTable) map[uint32]string { return t.groups }, name)
}

func lookup(t *nameTable, pick func(*nameTable) map[uint32]string, name string) (int, bool) {
	if t == nil {
		return 0, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for id, candidate := range pick(t) {
		if candidate == name {
			return int(id), true
		}
	}
	return 0, false
}

// OwnerNamesAvailable reports whether the host published names.
//
// The interface uses it to decide whether to offer a name field for chown or
// only a numeric one, rather than accepting a name it has no way to resolve.
func (c *Client) OwnerNamesAvailable() bool { return c.names != nil }
