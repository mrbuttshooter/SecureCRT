package tunnel

import (
	"context"
	"fmt"
	"net"
)

// Where a remote forward is allowed to reach.
//
// `ssh -R` reverses the direction of trust. Every other tunnel here dials
// outward from a connection the user authenticated: the far end is a device
// they already have an account on, and the worst a hostile one can do is lie
// about its own contents. A remote forward dials *inward*, from this server,
// on behalf of whoever connected to a port on that device — and this server
// is not one person's laptop. It holds the whole team's encrypted
// credentials, its own API, and whatever else the operator runs beside it.
//
// So the destination is checked, and the check is not configurable. Two
// families are refused:
//
//   - Loopback. bkd's own API is on loopback in the default deployment,
//     behind a reverse proxy that terminates TLS and is the only thing meant
//     to reach it. So is the database socket. A remote forward to 127.0.0.1
//     would hand a compromised switch the unauthenticated inside of the
//     application, which is the opposite of what the person opening the
//     tunnel had in mind.
//   - Link-local. 169.254.169.254 is the cloud metadata service on every
//     major provider, and on most of them it answers instance credentials to
//     anything that asks. fe80::/10 is the same idea over IPv6.
//
// Unspecified (0.0.0.0, ::) and multicast go with them: neither is a
// meaningful destination, and both have a history of being routed somewhere
// surprising.
//
// The rest of the network is *not* refused, and that is deliberate rather
// than an oversight. Reaching an internal service — a repository, a package
// mirror, a licence server — from lab equipment that has no route to it is
// the reason the feature exists. policy.allow_remote_forwards is where an
// operator decides whether that trade is one they want at all.
//
// # Why this is checked per connection
//
// A hostname is resolved when it is dialled, not when the tunnel is opened.
// Checking only at open time would be defeated by a name that answers a
// public address once and 127.0.0.1 afterwards — DNS rebinding, which is a
// twenty-year-old technique and not an exotic one. So the guard runs against
// the addresses actually resolved, on every connection, and the check at open
// time exists only to fail early with a comprehensible message.

// lookupIP is the resolver, indirected so a test can hand back an answer that
// is hard to arrange otherwise — in particular a name resolving to a routable
// address *and* a loopback one, which is the shape of a rebinding attack and
// the case the loop below exists for.
var lookupIP = net.DefaultResolver.LookupIPAddr

// checkDestination refuses an address a remote forward must not dial.
func checkDestination(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("%w: %s is this server itself", ErrDestinationOff, ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is link-local, which is where cloud "+
			"instance credentials live", ErrDestinationOff, ip)
	case ip.IsUnspecified():
		return fmt.Errorf("%w: %s is not an address", ErrDestinationOff, ip)
	case ip.IsMulticast():
		return fmt.Errorf("%w: %s is multicast", ErrDestinationOff, ip)
	case ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is interface-local", ErrDestinationOff, ip)
	}
	return nil
}

// resolveDestination looks a host up and returns the addresses that survive
// the guard.
//
// Every resolved address is checked, not the first: a name that answers both
// a routable address and a loopback one must not be dialled at all, because
// which one a dialler picks is not something this code decides.
func resolveDestination(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := checkDestination(ip); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}

	addrs, err := lookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("tunnel: resolving %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("tunnel: %q resolves to nothing", host)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if err := checkDestination(addr.IP); err != nil {
			return nil, fmt.Errorf("%w (%s)", err, host)
		}
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// dialDestination opens a connection to a checked address.
//
// It dials the resolved IP rather than the name, so the address that passed
// the guard is the address that is connected to. Handing the name back to the
// dialler would resolve it a second time and could reach somewhere else.
func dialDestination(ctx context.Context, host string, port int) (net.Conn, error) {
	ips, err := resolveDestination(ctx, host)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp",
			net.JoinHostPort(ip.String(), fmt.Sprint(port)))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
