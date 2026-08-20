//go:build linux

package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ephemeralRange reports the ports the kernel hands out for outbound
// connections.
//
// Worth knowing at startup because a tunnel range inside it will
// intermittently fail to bind against a socket bkd cannot see — the kernel
// gave that port to somebody's outbound connection — and the symptom is a
// feature that works nineteen times out of twenty. That reads as flakiness
// rather than as the configuration mistake it is, so the server says so once
// while an operator is still looking at the logs.
func ephemeralRange() (low, high int, ok bool) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, false
	}

	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return 0, 0, false
	}

	low, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, false
	}
	high, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, false
	}
	return low, high, true
}

// describeEphemeralOverlap returns a warning when the ranges collide, or "".
func describeEphemeralOverlap(tunnelLow, tunnelHigh int) string {
	low, high, ok := ephemeralRange()
	if !ok || tunnelLow == 0 {
		return ""
	}
	if tunnelHigh < low || tunnelLow > high {
		return ""
	}
	return fmt.Sprintf(
		"tunnels.port_range %d-%d overlaps this kernel's ephemeral range %d-%d, "+
			"so a tunnel will sometimes fail to bind against an outbound "+
			"connection using the same port; choose a range below %d",
		tunnelLow, tunnelHigh, low, high, low)
}
