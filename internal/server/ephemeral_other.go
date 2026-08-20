//go:build !linux

package server

// describeEphemeralOverlap has nothing to check off Linux.
//
// The deployment target is a Linux server; elsewhere the ephemeral range is
// not readable in a portable way, and guessing at it would produce a warning
// that is wrong more often than useful.
func describeEphemeralOverlap(int, int) string { return "" }
