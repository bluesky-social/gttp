package gttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ipLookuper is the minimum subset of *net.Resolver used by checkIPPolicy.
// Defined as an interface so tests can inject a stub without standing up
// a real DNS server.
type ipLookuper interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// resolverFunc adapts a lookup function to ipLookuper.
type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

// normalizeURL returns a canonical string form of u for loop detection.
// Applies RFC 3986 §6.2 syntax-based equivalence plus default-port stripping
// and query-parameter ordering.
//
// Paths and percent-encoding are preserved as-is: many servers distinguish
// /foo vs /FOO and /foo%20bar vs /foo bar, so we must not assume equivalence.
func normalizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()

	// Strip the default port for the scheme.
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	var hostPort string
	if port != "" {
		hostPort = host + ":" + port
	} else {
		hostPort = host
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(hostPort)
	b.WriteString(u.EscapedPath())

	if raw := u.RawQuery; raw != "" {
		b.WriteByte('?')
		b.WriteString(canonicalizeQuery(raw))
	}

	return b.String()
}

// canonicalizeQuery parses and re-encodes a query string with keys sorted
// lexically and, within each key, values sorted lexically. This produces a
// deterministic string for loop detection.
func canonicalizeQuery(raw string) string {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		// Fall back to the raw string. A parse error means the server sent
		// something odd; treat it as opaque bytes.
		return raw
	}

	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	first := true
	for _, k := range keys {
		vs := append([]string(nil), vals[k]...)
		sort.Strings(vs)
		ek := url.QueryEscape(k)
		for _, v := range vs {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// redirectConfig holds all knobs the redirect guard needs.
type redirectConfig struct {
	maxRedirects     int
	allowDowngrade   bool
	allowPrivate     bool
	strictInitial    bool
	sensitiveHeaders []string // caller-supplied, canonical form not enforced
	resolver         ipLookuper
	ipPolicyAtDial   bool
}

// redirectGuard bundles loop detection, scheme-downgrade refusal, SSRF
// filtering, and sensitive-header scrubbing into a single CheckRedirect.
type redirectGuard struct {
	cfg redirectConfig
}

func newRedirectGuard(cfg redirectConfig) *redirectGuard {
	return &redirectGuard{cfg: cfg}
}

// check is called by http.Client before each redirect. `req` is the
// upcoming request; `via` is the chain so far (earliest first). It returns
// nil to allow the redirect, or a sentinel-wrapped error to refuse.
func (g *redirectGuard) check(req *http.Request, via []*http.Request) error {
	// 1. Numeric limit.
	if g.cfg.maxRedirects > 0 && len(via) >= g.cfg.maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", ErrTooManyRedirects, g.cfg.maxRedirects)
	}

	target := req.URL
	canonical := normalizeURL(target)

	// 2. Loop detection.
	for _, prev := range via {
		if normalizeURL(prev.URL) == canonical {
			return fmt.Errorf("%w: %s", ErrRedirectLoop, canonical)
		}
	}

	// 3. Scheme downgrade.
	if !g.cfg.allowDowngrade && len(via) > 0 {
		prev := via[len(via)-1].URL
		if prev.Scheme == "https" && target.Scheme == "http" {
			return fmt.Errorf("%w: %s -> %s", ErrSchemeDowngrade, prev.String(), target.String())
		}
	}

	// 4. SSRF guard.
	if !g.cfg.allowPrivate && !g.cfg.ipPolicyAtDial {
		if err := g.checkIPPolicy(req.Context(), target.Hostname()); err != nil {
			return err
		}
	}

	// 5. Cross-origin header scrubbing.
	if len(g.cfg.sensitiveHeaders) > 0 && len(via) > 0 {
		prev := via[len(via)-1].URL
		if !sameOrigin(prev, target) {
			for _, h := range g.cfg.sensitiveHeaders {
				req.Header.Del(h)
			}
		}
	}

	return nil
}

// checkInitial applies the SSRF policy to the initial request URL if strict
// mode is enabled. Called by the safety transport before dispatch.
func (g *redirectGuard) checkInitial(req *http.Request) error {
	if !g.cfg.strictInitial {
		return nil
	}
	return g.checkIPPolicy(req.Context(), req.URL.Hostname())
}

// checkIPPolicy re-resolves host using the configured resolver (or the
// default) and fails if ANY returned address is in a blocked range. If the
// host is a literal IP, we check it directly without resolving.
func (g *redirectGuard) checkIPPolicy(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedByIPPolicy, ip)
		}
		return nil
	}

	resolver := g.cfg.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %w", ErrBlockedByIPPolicy, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: resolve %s: no addresses", ErrBlockedByIPPolicy, host)
	}
	for _, ipa := range ips {
		if isBlockedIP(ipa.IP) {
			return fmt.Errorf("%w: %s resolves to %s", ErrBlockedByIPPolicy, host, ipa.IP)
		}
	}
	return nil
}

// sameOrigin returns true if a and b share scheme, host and port.
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		a.Port() == b.Port()
}
