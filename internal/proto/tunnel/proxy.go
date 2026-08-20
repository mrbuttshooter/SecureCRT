package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Serving a device's own web interface.
//
// # Why this is not served from bkd's origin
//
// A switch's web interface is untrusted markup. Served under bkd's own
// hostname it would be same-origin with the application, and bkd's CSRF
// cookie is readable by JavaScript — it has to be, that is how double-submit
// works — while the session cookie is attached to same-origin requests
// automatically. So one script on one compromised device would have the
// user's entire API access: every credential they can read, every host they
// can reach. `script-src 'self'` does not help, because the device's scripts
// would *be* self.
//
// So each tunnel is served from its own hostname beneath a configured
// wildcard domain. That is a genuinely separate origin: no access to bkd's
// cookies, no access to its DOM, and the device's own cookies scoped to a
// name that stops existing when the tunnel does. Without a domain configured
// there is nowhere safe to put this, so the feature is simply unavailable —
// which is why the default is empty rather than clever.
//
// # Why the response is not rewritten
//
// Device interfaces are full of absolute paths. Serving them under a path
// prefix would break every one of them, which is the other reason for the
// subdomain: the path stays the root, so `/js/app.js` means what it says.
// Rewriting bodies to fix that would mean parsing and editing attacker-
// influenced HTML and JavaScript on every response, forever, and failing
// silently whenever a URL was assembled by string concatenation.

// proxyIdleTimeout bounds an idle upstream connection inside the proxy's
// transport, so a device that goes away does not hold a channel open.
const proxyIdleTimeout = 90 * time.Second

// HostFor returns the hostname a web tunnel is served at.
func (m *Manager) HostFor(t *Tunnel) string {
	if m.cfg.Domain == "" || t.Kind != KindWeb {
		return ""
	}
	return t.ID + "." + m.cfg.Domain
}

// URLFor returns the address a user visits to reach a web tunnel.
func (m *Manager) URLFor(t *Tunnel) string {
	host := m.HostFor(t)
	if host == "" {
		return ""
	}
	return "https://" + host + "/"
}

// TunnelForHost resolves the tunnel a request's Host header addresses.
//
// Returns false for anything that is not a tunnel hostname, which is how the
// server tells a proxied request from an ordinary one.
func (m *Manager) TunnelForHost(hostHeader string) (*Tunnel, bool) {
	if m.cfg.Domain == "" {
		return nil, false
	}

	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	suffix := "." + strings.ToLower(m.cfg.Domain)
	if !strings.HasSuffix(host, suffix) {
		return nil, false
	}

	id := strings.TrimSuffix(host, suffix)
	if id == "" || strings.Contains(id, ".") {
		return nil, false
	}

	t, ok := m.lookup(id)
	if !ok || t.Kind != KindWeb {
		return nil, false
	}
	return t, true
}

// ProxyHandler serves a web tunnel.
//
// Authentication is the caller's job — this is mounted behind the same
// session check as everything else, and additionally checks that the signed-in
// user owns the tunnel. A tunnel's hostname contains its identifier, which is
// a UUIDv7 and therefore guessable from another one, so the hostname is not
// treated as a credential.
func (m *Manager) ProxyHandler(t *Tunnel) http.Handler {
	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
	}
	if t.Port == 443 {
		target.Scheme = "https"
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			t.touch()
			return t.conn.Client().Conn().DialContext(ctx, "tcp", target.Host)
		},
		// The device's certificate cannot be verified and pretending
		// otherwise would be theatre: these are self-signed certificates on
		// appliances, generated at manufacture and never rotated. What is
		// verified is the SSH host key of the hop this tunnel terminates on;
		// the segment from there to the device is inside the network the user
		// is already trusting. docs/SECURITY.md says so plainly.
		//
		// #nosec G402 -- see above; the guarantee is the SSH host key, not this.
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout:     proxyIdleTimeout,
		MaxIdleConnsPerHost: 4,
		DisableCompression:  true,
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host

			// Forwarding headers are deliberately not set. They would tell
			// the device the browser's address, which it has no business
			// knowing and which some appliances write into their own logs and
			// access rules.
			r.Out.Header.Del("X-Forwarded-For")
			r.Out.Header.Del("X-Forwarded-Host")
			r.Out.Header.Del("X-Forwarded-Proto")

			// bkd's own cookies must never reach the device. They are on a
			// different origin so a browser will not send them, but a
			// misconfigured proxy in front could, and the cost of being wrong
			// here is the whole session.
			stripBkdCookies(r.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			t.touch()
			hardenProxiedResponse(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			t.fail(err)
			http.Error(w,
				"The device did not answer through this tunnel: "+err.Error(),
				http.StatusBadGateway)
		},
	}

	return proxy
}

// stripBkdCookies removes this application's own cookies from a request bound
// for a device.
func stripBkdCookies(r *http.Request) {
	raw := r.Header.Get("Cookie")
	if raw == "" {
		return
	}

	var kept []string
	for _, part := range strings.Split(raw, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.HasPrefix(strings.ToLower(name), "bkd_") {
			continue
		}
		kept = append(kept, strings.TrimSpace(part))
	}

	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

// hardenProxiedResponse replaces whatever policy the device sent with one of
// our own.
//
// A device's own headers are written for the network it thinks it is on. Its
// CSP — if it has one at all — will not name this origin, and its
// X-Frame-Options may forbid the framing the interface uses. Ours are the
// ones that hold here.
func hardenProxiedResponse(resp *http.Response) {
	h := resp.Header

	h.Del("Content-Security-Policy-Report-Only")
	h.Del("X-Frame-Options")
	h.Del("Strict-Transport-Security")

	// Confined to its own origin: a device page may load its own assets and
	// submit its own forms, and may reach nothing else. In particular it may
	// not frame, script, or connect back to bkd.
	h.Set("Content-Security-Policy",
		"default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; "+
			"frame-ancestors 'self'; base-uri 'self'; form-action 'self'")

	// 'unsafe-inline' and 'unsafe-eval' above are not a lapse. Device
	// firmware is full of inline handlers and generated script, and a policy
	// that broke every switch GUI would simply mean nobody used the feature
	// and reached for a plaintext alternative instead. The confinement that
	// matters is default-src 'self': whatever the page runs, it runs on a
	// throwaway origin with no access to bkd's.

	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// ProxyUnavailable explains why a web tunnel cannot be served.
func ProxyUnavailable(w http.ResponseWriter) {
	http.Error(w, fmt.Sprintf(
		"Web tunnels are not configured on this server. A device's own pages "+
			"cannot be served from this application's address — a script on the "+
			"device would inherit the session — so they need a separate domain, "+
			"set in tunnels.domain. See docs/TUNNELS.md."),
		http.StatusServiceUnavailable)
}
