package gttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase scheme", "HTTP://example.com/", "http://example.com/"},
		{"lowercase host", "http://EXAMPLE.COM/", "http://example.com/"},
		{"strip default http port", "http://example.com:80/", "http://example.com/"},
		{"strip default https port", "https://example.com:443/", "https://example.com/"},
		{"keep non-default port", "http://example.com:8080/", "http://example.com:8080/"},
		{"drop fragment", "http://example.com/p#frag", "http://example.com/p"},
		{"sort query params", "http://example.com/?b=2&a=1", "http://example.com/?a=1&b=2"},
		{"case-sensitive path", "http://example.com/FOO", "http://example.com/FOO"},
		{"preserve percent-encoding", "http://example.com/foo%20bar", "http://example.com/foo%20bar"},
		{"empty query", "http://example.com/", "http://example.com/"},
		{"empty path root", "http://example.com", "http://example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.in)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.in, err)
			}
			got := normalizeURL(u)
			if got != tt.want {
				t.Errorf("normalizeURL(%s) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeURLEquivalence(t *testing.T) {
	// Two URLs that differ only in normalization-irrelevant ways must normalize equal.
	pairs := [][2]string{
		{"HTTPS://x.com:443/p?b=2&a=1#top", "https://x.com/p?a=1&b=2"},
		{"http://EXAMPLE.com:80/a", "HTTP://example.com/a"},
	}
	for _, p := range pairs {
		u1, _ := url.Parse(p[0])
		u2, _ := url.Parse(p[1])
		if normalizeURL(u1) != normalizeURL(u2) {
			t.Errorf("not equal: %q vs %q → %q vs %q",
				p[0], p[1], normalizeURL(u1), normalizeURL(u2))
		}
	}
}

func TestNormalizeURLDistinct(t *testing.T) {
	// Paths are case-sensitive; must NOT collapse.
	u1, _ := url.Parse("http://x.com/FOO")
	u2, _ := url.Parse("http://x.com/foo")
	if normalizeURL(u1) == normalizeURL(u2) {
		t.Error("path case should not be normalized")
	}
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func newReq(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	return req
}

func TestRedirectGuardNumericLimit(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   2,
		allowPrivate:   true, // don't SSRF-block in this unit test
		allowDowngrade: true,
	})
	req := newReq(t, "http://example.com/3")
	via := []*http.Request{
		newReq(t, "http://example.com/0"),
		newReq(t, "http://example.com/1"),
	}
	err := g.check(req, via)
	if !errors.Is(err, ErrTooManyRedirects) {
		t.Errorf("err = %v, want ErrTooManyRedirects", err)
	}
}

func TestRedirectGuardLoopDetection(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowPrivate:   true,
		allowDowngrade: true,
	})
	// Target normalizes to the same as via[0].
	req := newReq(t, "http://example.com/a?c=2&b=1")
	via := []*http.Request{
		newReq(t, "http://example.com/a?b=1&c=2"),
	}
	err := g.check(req, via)
	if !errors.Is(err, ErrRedirectLoop) {
		t.Errorf("err = %v, want ErrRedirectLoop", err)
	}
}

func TestRedirectGuardSchemeDowngrade(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects: 10,
		allowPrivate: true,
	})
	req := newReq(t, "http://example.com/")
	via := []*http.Request{
		newReq(t, "https://example.com/"),
	}
	err := g.check(req, via)
	if !errors.Is(err, ErrSchemeDowngrade) {
		t.Errorf("err = %v, want ErrSchemeDowngrade", err)
	}
}

func TestRedirectGuardSchemeDowngradeAllowed(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowPrivate:   true,
		allowDowngrade: true,
	})
	req := newReq(t, "http://example.com/")
	via := []*http.Request{
		newReq(t, "https://example.com/"),
	}
	if err := g.check(req, via); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestRedirectGuardIPLiteralBlockedPrivate(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
		// allowPrivate: false → SSRF active
	})
	req := newReq(t, "http://10.0.0.1/")
	err := g.check(req, nil)
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("err = %v, want ErrBlockedByIPPolicy", err)
	}
}

func TestRedirectGuardIPLiteralAllowedPublic(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
	})
	req := newReq(t, "http://1.1.1.1/")
	if err := g.check(req, nil); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestRedirectGuardOptOutAllowsPrivate(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
		allowPrivate:   true,
	})
	req := newReq(t, "http://10.0.0.1/")
	if err := g.check(req, nil); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestRedirectGuardCrossOriginScrubsSensitiveHeader(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:     10,
		allowDowngrade:   true,
		allowPrivate:     true,
		sensitiveHeaders: []string{"X-Custom-Auth"},
	})
	req := newReq(t, "http://b.example.com/")
	req.Header.Set("X-Custom-Auth", "secret")
	via := []*http.Request{
		newReq(t, "http://a.example.com/"),
	}
	if err := g.check(req, via); err != nil {
		t.Fatalf("check: %v", err)
	}
	if v := req.Header.Get("X-Custom-Auth"); v != "" {
		t.Errorf("header still present: %q", v)
	}
}

func TestRedirectGuardSameOriginPreservesSensitiveHeader(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:     10,
		allowDowngrade:   true,
		allowPrivate:     true,
		sensitiveHeaders: []string{"X-Custom-Auth"},
	})
	req := newReq(t, "http://a.example.com/next")
	req.Header.Set("X-Custom-Auth", "keep-me")
	via := []*http.Request{
		newReq(t, "http://a.example.com/prev"),
	}
	if err := g.check(req, via); err != nil {
		t.Fatalf("check: %v", err)
	}
	if v := req.Header.Get("X-Custom-Auth"); v != "keep-me" {
		t.Errorf("header altered: %q, want keep-me", v)
	}
}

func TestRedirectGuardCheckInitialStrict(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:  10,
		strictInitial: true,
	})
	req := newReq(t, "http://127.0.0.1/whatever")
	err := g.checkInitial(req)
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("err = %v, want ErrBlockedByIPPolicy", err)
	}
}

func TestRedirectGuardCheckInitialNonStrictNoop(t *testing.T) {
	g := newRedirectGuard(redirectConfig{
		maxRedirects:  10,
		strictInitial: false,
	})
	req := newReq(t, "http://127.0.0.1/")
	if err := g.checkInitial(req); err != nil {
		t.Errorf("err = %v, want nil (non-strict)", err)
	}
}

func TestSameOriginHelper(t *testing.T) {
	cases := []struct {
		a, b string
		same bool
	}{
		{"http://x/", "http://x/", true},
		{"http://x/", "http://X/", true},     // host case-insensitive
		{"http://x:80/", "http://x/", false}, // port-literal mismatch at this helper level
		{"http://x/", "https://x/", false},
		{"http://x:8080/", "http://x:8081/", false},
		{"http://a/", "http://b/", false},
	}
	for _, c := range cases {
		if got := sameOrigin(mustParse(t, c.a), mustParse(t, c.b)); got != c.same {
			t.Errorf("sameOrigin(%s,%s) = %v, want %v", c.a, c.b, got, c.same)
		}
	}
	if sameOrigin(nil, mustParse(t, "http://x/")) {
		t.Error("nil should not be same-origin")
	}
}

func TestRedirectLoopDetectedViaClient(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/a", http.StatusFound)
	})

	// Loopback is private; opt out so only the loop detection fires.
	client := New(WithNoRetries(), WithAllowPrivateRedirects())
	resp, err := client.Get(srv.URL + "/a")
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrRedirectLoop) {
		t.Errorf("err = %v, want ErrRedirectLoop", err)
	}
}

func TestSchemeDowngradeRefusedViaClient(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain")
	}))
	defer httpSrv.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpSrv.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()

	base := tlsSrv.Client()
	client := New(
		WithNoRetries(),
		WithAllowPrivateRedirects(),
		WithTLSConfig(base.Transport.(*http.Transport).TLSClientConfig),
	)
	resp, err := client.Get(tlsSrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrSchemeDowngrade) {
		t.Errorf("err = %v, want ErrSchemeDowngrade", err)
	}
}

func TestSchemeDowngradeAllowedViaClient(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain")
	}))
	defer httpSrv.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpSrv.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()

	base := tlsSrv.Client()
	client := New(
		WithNoRetries(),
		WithAllowPrivateRedirects(),
		WithAllowSchemeDowngrade(),
		WithTLSConfig(base.Transport.(*http.Transport).TLSClientConfig),
	)
	resp, err := client.Get(tlsSrv.URL)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain" {
		t.Errorf("body = %q, want plain", body)
	}
}

func TestSSRFRedirectToLoopbackBlockedViaClient(t *testing.T) {
	// By default, loopback is blocked on redirect. This test uses a public
	// test server (httptest.Server) that redirects to 127.0.0.1:1 — the
	// target IP is loopback, so the guard must fire. But httptest.Server
	// itself is ALSO on 127.0.0.1, meaning the INITIAL connection is to
	// loopback. We're in the initial-URL-is-loopback edge case. The
	// default guard only applies to redirects; the initial URL goes
	// through unless WithStrictSSRFProtection is set.
	// So this test: initial URL is loopback (allowed, non-strict), and
	// the guard fires only on redirect — which is still loopback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/inside", http.StatusFound)
	}))
	defer srv.Close()

	client := New(WithNoRetries())
	resp, err := client.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("err = %v, want ErrBlockedByIPPolicy", err)
	}
}

func TestSSRFAllowedWithOptOutViaClient(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "inside")
	}))
	defer target.Close()

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer front.Close()

	client := New(WithNoRetries(), WithAllowPrivateRedirects())
	resp, err := client.Get(front.URL)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "inside" {
		t.Errorf("body = %q", body)
	}
}

func TestSSRFStrictBlocksInitialViaClient(t *testing.T) {
	client := New(WithNoRetries(), WithStrictSSRFProtection())
	_, err := client.Get("http://127.0.0.1:1/whatever")
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("err = %v, want ErrBlockedByIPPolicy", err)
	}
}

func TestSensitiveHeaderStrippedOnCrossOriginRedirectViaClient(t *testing.T) {
	var got atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-Custom-Auth"))
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	// Redirect from front to target — different ports, so cross-origin even
	// though both are 127.0.0.1. sameOrigin compares scheme+host+port.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer front.Close()

	client := New(
		WithNoRetries(),
		WithAllowPrivateRedirects(),
		WithSensitiveHeaders("X-Custom-Auth"),
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL, http.NoBody)
	req.Header.Set("X-Custom-Auth", "super-secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	resp.Body.Close()
	if v, _ := got.Load().(string); v != "" {
		t.Errorf("target saw header %q, want empty", v)
	}
}

func TestSameOriginRedirectKeepsSensitiveHeaderViaClient(t *testing.T) {
	var got atomic.Value
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-Custom-Auth"))
		fmt.Fprint(w, "ok")
	})

	client := New(
		WithNoRetries(),
		WithAllowPrivateRedirects(),
		WithSensitiveHeaders("X-Custom-Auth"),
	)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/a", http.NoBody)
	req.Header.Set("X-Custom-Auth", "keep-me")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	resp.Body.Close()
	if v, _ := got.Load().(string); v != "keep-me" {
		t.Errorf("target saw %q, want keep-me", v)
	}
}

// fakeResolver returns canned responses in order. Each call to LookupIPAddr
// returns the next slice in `returns`; subsequent calls after the last
// response repeat the last one.
type fakeResolver struct {
	returns [][]net.IPAddr
	calls   atomic.Int32
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	i := int(f.calls.Add(1)) - 1
	if i >= len(f.returns) {
		i = len(f.returns) - 1
	}
	return f.returns[i], nil
}

func TestSSRFDNSRebindingCaughtAtRedirectTime(t *testing.T) {
	// First lookup: public IP. Second lookup: private IP. The guard must
	// re-resolve at redirect check time, NOT cache the initial resolution.
	res := &fakeResolver{
		returns: [][]net.IPAddr{
			{{IP: net.ParseIP("1.1.1.1")}},
			{{IP: net.ParseIP("10.0.0.1")}},
		},
	}
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
		resolver:       res,
	})

	// First call (simulates an initial probe) — public, passes.
	if err := g.checkIPPolicy(context.Background(), "example.com"); err != nil {
		t.Errorf("first lookup err = %v, want nil", err)
	}
	// Second call — now returns private IP, must be blocked.
	err := g.checkIPPolicy(context.Background(), "example.com")
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("second lookup err = %v, want ErrBlockedByIPPolicy", err)
	}
	if res.calls.Load() != 2 {
		t.Errorf("expected 2 DNS lookups, got %d", res.calls.Load())
	}
}

func TestSSRFMultiIPFailsClosedOnAnyPrivate(t *testing.T) {
	// Resolver returns public + private in one response. ANY private must
	// block.
	res := &fakeResolver{
		returns: [][]net.IPAddr{
			{
				{IP: net.ParseIP("1.1.1.1")},
				{IP: net.ParseIP("10.0.0.1")},
			},
		},
	}
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
		resolver:       res,
	})
	err := g.checkIPPolicy(context.Background(), "mixed.example.com")
	if !errors.Is(err, ErrBlockedByIPPolicy) {
		t.Errorf("err = %v, want ErrBlockedByIPPolicy", err)
	}
}

func TestSSRFMultiIPAllPublicPasses(t *testing.T) {
	res := &fakeResolver{
		returns: [][]net.IPAddr{
			{
				{IP: net.ParseIP("1.1.1.1")},
				{IP: net.ParseIP("8.8.8.8")},
			},
		},
	}
	g := newRedirectGuard(redirectConfig{
		maxRedirects:   10,
		allowDowngrade: true,
		resolver:       res,
	})
	if err := g.checkIPPolicy(context.Background(), "cdn.example.com"); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

// The redirect guard's IP-policy lookup must go through WithLookupIPAddr too,
// and the policy must still apply to the answers it returns.
func TestRedirectGuardUsesLookupFunc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "a.invalid" {
			http.Redirect(w, r, "http://b.invalid/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	newClient := func(answer string, looked *[]string) *http.Client {
		var mu sync.Mutex
		return New(
			WithNoRetries(), WithNoProxy(),
			WithLookupIPAddr(func(_ context.Context, host string) ([]net.IPAddr, error) {
				mu.Lock()
				*looked = append(*looked, host)
				mu.Unlock()
				return []net.IPAddr{{IP: net.ParseIP(answer)}}, nil
			}),
			// Outside strict mode the dialer gets hostnames; send them all to
			// the local server, which routes on the Host header.
			WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, srv.Listener.Addr().String())
			}),
		)
	}

	t.Run("public answer follows the redirect", func(t *testing.T) {
		var looked []string
		res, err := newClient("203.0.113.10", &looked).Get("http://a.invalid/")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || string(body) != "ok" {
			t.Fatalf("body = %q, err = %v", body, err)
		}
		if len(looked) != 1 || looked[0] != "b.invalid" {
			t.Fatalf("lookups = %v, want [b.invalid]", looked)
		}
	})

	t.Run("private answer is blocked", func(t *testing.T) {
		var looked []string
		res, err := newClient("10.0.0.1", &looked).Get("http://a.invalid/")
		if res != nil {
			_ = res.Body.Close()
		}
		if !errors.Is(err, ErrBlockedByIPPolicy) {
			t.Fatalf("err = %v, want ErrBlockedByIPPolicy", err)
		}
		if len(looked) != 1 || looked[0] != "b.invalid" {
			t.Fatalf("lookups = %v, want [b.invalid]", looked)
		}
	})
}
