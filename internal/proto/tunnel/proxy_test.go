package tunnel

import (
	"net/http"
	"strings"
	"testing"
)

// The proxy's job at the edges: what it strips going out, and what it
// replaces coming back.

// TestBkdCookiesNeverReachTheDevice.
//
// A browser will not send them — the device is on a different origin, which
// is the whole design — but a reverse proxy in front of this could, and the
// cost of being wrong is the user's entire session. Belt as well as braces.
func TestBkdCookiesNeverReachTheDevice(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "http://device/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Cookie", "bkd_session=secret; deviceprefs=dark; bkd_csrf=token")

	stripBkdCookies(r)

	got := r.Header.Get("Cookie")
	for _, banned := range []string{"bkd_session", "bkd_csrf", "secret", "token"} {
		if strings.Contains(got, banned) {
			t.Errorf("%q survived into the device's request: %q", banned, got)
		}
	}
	if !strings.Contains(got, "deviceprefs=dark") {
		t.Errorf("the device's own cookie was dropped: %q", got)
	}
}

func TestStrippingCookiesLeavesNoEmptyHeader(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "http://device/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Cookie", "bkd_session=secret")

	stripBkdCookies(r)

	if _, present := r.Header["Cookie"]; present {
		t.Errorf("an empty Cookie header was left behind: %q", r.Header.Get("Cookie"))
	}
}

// TestADevicesOwnHeadersDoNotSurvive. A device's policy is written for the
// network it thinks it is on; ours is the one that holds here.
func TestADevicesOwnHeadersDoNotSurvive(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Content-Security-Policy", "default-src *")
	resp.Header.Set("Content-Security-Policy-Report-Only", "default-src *")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000")

	hardenProxiedResponse(resp)

	if got := resp.Header.Get("Content-Security-Policy"); strings.Contains(got, "*") {
		t.Errorf("the device's policy survived: %q", got)
	}
	if resp.Header.Get("Content-Security-Policy-Report-Only") != "" {
		t.Error("a report-only policy from the device survived")
	}
	if resp.Header.Get("X-Frame-Options") != "" {
		t.Error("the device's framing policy survived; ours governs here")
	}
	// A device's HSTS would apply to its hostname under our wildcard domain,
	// which is not the device's to decide.
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("the device set HSTS on a hostname it does not own")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff was not applied")
	}
}

// TestTheProxyPolicyConfinesTheDeviceToItsOwnOrigin. Whatever the device's
// firmware runs, it runs somewhere it cannot reach bkd from.
func TestTheProxyPolicyConfinesTheDeviceToItsOwnOrigin(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	hardenProxiedResponse(resp)

	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "default-src 'self'") {
		t.Errorf("the policy does not confine the device to its own origin: %q", policy)
	}
	for _, directive := range []string{"frame-ancestors 'self'", "form-action 'self'", "base-uri 'self'"} {
		if !strings.Contains(policy, directive) {
			t.Errorf("the policy is missing %q: %q", directive, policy)
		}
	}
}

// TestOnlyTunnelHostnamesResolveToTunnels. The host-based branch decides
// whether a request is proxied at all, so it must not match anything else.
func TestOnlyTunnelHostnamesResolveToTunnels(t *testing.T) {
	m := &Manager{cfg: Config{Domain: "tunnels.example.com"}, tunnels: map[string]*Tunnel{}}

	live := &Tunnel{ID: "abc", Kind: KindWeb, UserID: "alice"}
	m.tunnels["abc"] = live

	if _, ok := m.TunnelForHost("abc.tunnels.example.com"); !ok {
		t.Error("a tunnel's own hostname did not resolve")
	}
	if _, ok := m.TunnelForHost("abc.tunnels.example.com:443"); !ok {
		t.Error("a port on the hostname broke the match")
	}
	if _, ok := m.TunnelForHost("ABC.Tunnels.Example.Com"); !ok {
		t.Error("hostnames are case-insensitive")
	}

	for _, host := range []string{
		"bkd.example.com",                   // the application itself
		"tunnels.example.com",               // the bare domain
		"abc.tunnels.example.com.evil.test", // a suffix that merely contains it
		"nested.abc.tunnels.example.com",    // an extra label
		"missing.tunnels.example.com",       // no such tunnel
		"",
	} {
		if _, ok := m.TunnelForHost(host); ok {
			t.Errorf("%q was treated as a tunnel hostname", host)
		}
	}
}

// TestANonWebTunnelIsNotServedOverHTTP. A SOCKS tunnel has a listener, not a
// hostname; resolving one here would proxy to whatever its Host field held.
func TestANonWebTunnelIsNotServedOverHTTP(t *testing.T) {
	m := &Manager{cfg: Config{Domain: "tunnels.example.com"}, tunnels: map[string]*Tunnel{}}
	m.tunnels["sox"] = &Tunnel{ID: "sox", Kind: KindSOCKS, UserID: "alice"}

	if _, ok := m.TunnelForHost("sox.tunnels.example.com"); ok {
		t.Error("a SOCKS tunnel was served as a web tunnel")
	}
}

// TestWithNoDomainNothingResolves, which is what makes the feature genuinely
// off rather than merely unadvertised.
func TestWithNoDomainNothingResolves(t *testing.T) {
	m := &Manager{cfg: Config{Domain: ""}, tunnels: map[string]*Tunnel{}}
	m.tunnels["abc"] = &Tunnel{ID: "abc", Kind: KindWeb}

	if _, ok := m.TunnelForHost("abc."); ok {
		t.Error("a tunnel resolved with no domain configured")
	}
	if m.WebTunnelsEnabled() {
		t.Error("web tunnels report themselves enabled with no domain")
	}
}
