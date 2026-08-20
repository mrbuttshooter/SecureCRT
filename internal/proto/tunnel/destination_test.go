package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
)

// The destination guard, which is what stands between a remote forward and
// the inside of this server.

func TestWhatARemoteForwardMayReach(t *testing.T) {
	allowed := []string{
		"10.1.2.3",      // the ordinary case: a private network worth reaching
		"192.168.1.1",   //
		"172.16.0.9",    //
		"93.184.216.34", // and a public one
		"2001:db8::1",   //
		"100.64.0.1",    // carrier-grade NAT, which is somebody's real network
	}
	for _, addr := range allowed {
		if err := checkDestination(net.ParseIP(addr)); err != nil {
			t.Errorf("%s should be reachable: %v", addr, err)
		}
	}

	refused := map[string]string{
		"127.0.0.1":       "this server's own interior",
		"127.0.0.53":      "the stub resolver, still loopback",
		"::1":             "loopback over IPv6",
		"169.254.169.254": "cloud instance credentials",
		"169.254.1.1":     "link-local generally",
		"fe80::1":         "link-local over IPv6",
		"0.0.0.0":         "not an address",
		"::":              "not an address either",
		"224.0.0.1":       "multicast",
		"ff02::1":         "multicast over IPv6",
	}
	for addr, why := range refused {
		err := checkDestination(net.ParseIP(addr))
		if err == nil {
			t.Errorf("%s must be refused (%s)", addr, why)
			continue
		}
		if !errors.Is(err, ErrDestinationOff) {
			t.Errorf("%s refused with the wrong error: %v", addr, err)
		}
	}
}

// TestANameThatAlsoAnswersLoopbackIsRefusedEntirely is the rebinding case.
//
// A name that resolves to both a routable address and 127.0.0.1 must not be
// dialled at all. Taking the first answer, or filtering to the ones that pass,
// would leave which address gets used up to the resolver's ordering — and an
// attacker chooses that ordering.
func TestANameThatAlsoAnswersLoopbackIsRefusedEntirely(t *testing.T) {
	original := lookupIP
	t.Cleanup(func() { lookupIP = original })

	lookupIP = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("93.184.216.34")},
			{IP: net.ParseIP("127.0.0.1")},
		}, nil
	}

	if _, err := resolveDestination(context.Background(), "rebind.example"); err == nil {
		t.Fatal("a name answering loopback among its addresses must be refused")
	} else if !errors.Is(err, ErrDestinationOff) {
		t.Fatalf("refused with the wrong error: %v", err)
	}
}

// TestANameWithOnlyRoutableAnswersIsAllowed keeps the guard from being one
// that refuses everything, which would pass the test above just as well.
func TestANameWithOnlyRoutableAnswersIsAllowed(t *testing.T) {
	original := lookupIP
	t.Cleanup(func() { lookupIP = original })

	lookupIP = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("10.0.0.7")},
			{IP: net.ParseIP("10.0.0.8")},
		}, nil
	}

	ips, err := resolveDestination(context.Background(), "mirror.internal")
	if err != nil {
		t.Fatalf("an internal name must be reachable: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %d addresses, want both", len(ips))
	}
}

// TestANameThatResolvesToNothingIsNotSilentlyDialled.
func TestANameThatResolvesToNothingIsNotSilentlyDialled(t *testing.T) {
	original := lookupIP
	t.Cleanup(func() { lookupIP = original })

	lookupIP = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return nil, nil
	}
	if _, err := resolveDestination(context.Background(), "nowhere.internal"); err == nil {
		t.Fatal("a name with no addresses must be an error, not an empty allow")
	}
}
