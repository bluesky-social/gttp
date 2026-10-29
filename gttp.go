// Package gttp provides a robust HTTP client with reasonable defaults and
// tunable behavior.
//
// The returned *http.Client is fully standard — callers use client.Do,
// client.Get, etc. Built-in protections:
//
//   - Retry with exponential backoff + jitter, Retry-After honoring
//   - HTTP/2 health-check pings (detects black-holed connections)
//   - TLS 1.2+ minimum, session cache by default
//   - Idle timeout on request-body writes and response-body reads (30s)
//   - Decompression-bomb guard (1000:1 ratio)
//   - Redirect loop detection, scheme-downgrade refusal, SSRF filter on
//     private / loopback / link-local / CGNAT / NAT64 / IMDS addresses
//
// All defaults can be overridden via Option values. See the With* options
// below.
//
// Basic usage:
//
//	client := gttp.New() // be sure to reuse this single object across multiple requests!
//	resp, err := client.Get("https://example.com")
//
// With options:
//
//	client := gttp.New(
//	    gttp.WithTimeout(10 * time.Second),
//	    gttp.WithRetries(5),
//	    gttp.WithAdditionalRetryableStatusCodes(500),
//	)
package gttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// Default configuration values. All can be overridden via Option values.
const (
	DefaultTimeout               = 30 * time.Second
	DefaultMaxRedirects          = 5
	DefaultMaxIdleConns          = 20
	DefaultMaxIdleConnsPerHost   = 20
	DefaultMaxConnsPerHost       = 100
	DefaultIdleConnTimeout       = 90 * time.Second
	DefaultTLSHandshakeTimeout   = 5 * time.Second
	DefaultResponseHeaderTimeout = 10 * time.Second
	DefaultDialTimeout           = 5 * time.Second
	DefaultDialKeepAlive         = 30 * time.Second
	DefaultMaxRetries            = 3
	DefaultRetryWaitMin          = 250 * time.Millisecond
	DefaultRetryWaitMax          = 2 * time.Second
	DefaultExpectContinueTimeout = 2 * time.Second
	DefaultMaxRetryBodyBytes     = 4 << 20 // 4 MiB
	DefaultMaxRetryAfter         = 1 * time.Minute
	DefaultIdleTimeout           = 30 * time.Second
	DefaultMaxCompressionRatio   = 1000.0
)

// defaultTLSSessionCacheCapacity is the LRU size used when the caller hasn't
// provided a ClientSessionCache. 32 covers session reuse across a handful of
// distinct hosts without unbounded memory growth.
const defaultTLSSessionCacheCapacity = 32

type config struct {
	// Client-level
	timeout      time.Duration
	maxRedirects int
	userAgent    string

	// Transport-level
	maxIdleConns           int
	maxIdleConnsPerHost    int
	maxConnsPerHost        int
	idleConnTimeout        time.Duration
	tlsHandshakeTimeout    time.Duration
	responseHeaderTimeout  time.Duration
	maxResponseHeaderBytes int64
	dialTimeout            time.Duration
	dialKeepAlive          time.Duration
	expectContinueTimeout  time.Duration
	disableKeepAlives      bool
	disableCompression     bool
	forceHTTP2             bool
	http2ReadIdleTimeout   time.Duration
	http2PingTimeout       time.Duration
	dialContext            func(ctx context.Context, network, address string) (net.Conn, error)
	resolver               *net.Resolver
	lookupIPAddr           func(ctx context.Context, host string) ([]net.IPAddr, error)
	proxy                  func(*http.Request) (*url.URL, error)
	disableProxy           bool

	// Retries
	maxRetries           int
	retryWaitMin         time.Duration
	retryWaitMax         time.Duration
	maxRetryAfter        time.Duration
	maxRetryBodyBytes    int64
	retryableStatusCodes map[int]struct{}
	retryableMethods     map[string]struct{}
	checkRetry           func(req *http.Request, resp *http.Response, err error) bool
	retryObserver        func(attempt int, req *http.Request, resp *http.Response, err error)

	// TLS
	tlsConfig *tls.Config

	// Transport escape hatch
	transport http.RoundTripper

	// Slow-transfer
	idleTimeout   time.Duration
	minRate       int64
	minRateWindow time.Duration

	// Response size / decompression
	maxResponseBodyBytes int64
	maxCompressionRatio  float64
	bodyObserver         func(BodyObservation)

	// Redirect safety
	allowSchemeDowngrade  bool
	allowPrivateRedirects bool
	strictSSRFInitial     bool
	sensitiveHeaders      []string
}

func defaults() *config {
	return &config{
		timeout:               DefaultTimeout,
		maxRedirects:          DefaultMaxRedirects,
		maxIdleConns:          DefaultMaxIdleConns,
		maxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		maxConnsPerHost:       DefaultMaxConnsPerHost,
		idleConnTimeout:       DefaultIdleConnTimeout,
		tlsHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		responseHeaderTimeout: DefaultResponseHeaderTimeout,
		dialTimeout:           DefaultDialTimeout,
		dialKeepAlive:         DefaultDialKeepAlive,
		expectContinueTimeout: DefaultExpectContinueTimeout,
		forceHTTP2:            true,
		http2ReadIdleTimeout:  DefaultHTTP2ReadIdleTimeout,
		http2PingTimeout:      DefaultHTTP2PingTimeout,
		maxRetries:            DefaultMaxRetries,
		retryWaitMin:          DefaultRetryWaitMin,
		retryWaitMax:          DefaultRetryWaitMax,
		maxRetryAfter:         DefaultMaxRetryAfter,
		maxRetryBodyBytes:     DefaultMaxRetryBodyBytes,
		retryableStatusCodes: map[int]struct{}{
			http.StatusRequestTimeout:     {},
			http.StatusTooEarly:           {},
			http.StatusTooManyRequests:    {},
			http.StatusBadGateway:         {},
			http.StatusServiceUnavailable: {},
			http.StatusGatewayTimeout:     {},
		},
		retryableMethods: map[string]struct{}{
			http.MethodGet:     {},
			http.MethodHead:    {},
			http.MethodOptions: {},
		},
		idleTimeout:         DefaultIdleTimeout,
		maxCompressionRatio: DefaultMaxCompressionRatio,
	}
}

// Option configures the HTTP client.
type Option func(*config)

// New creates a new *http.Client with good defaults.
// All defaults can be overridden via Option values.
// As with all http.Clients, be sure to use the returned
// client across the lifetime of multiple requests.
func New(opts ...Option) *http.Client {
	cfg := defaults()
	for _, opt := range opts {
		opt(cfg)
	}

	cfg.maxRetries = max(cfg.maxRetries, 0)
	cfg.maxRedirects = max(cfg.maxRedirects, 0)
	if cfg.retryWaitMin <= 0 {
		cfg.retryWaitMin = DefaultRetryWaitMin
	}
	if cfg.retryWaitMax <= 0 {
		cfg.retryWaitMax = DefaultRetryWaitMax
	}
	if cfg.retryWaitMin > cfg.retryWaitMax {
		cfg.retryWaitMin, cfg.retryWaitMax = cfg.retryWaitMax, cfg.retryWaitMin
	}
	if cfg.maxRetryAfter <= 0 {
		cfg.maxRetryAfter = DefaultMaxRetryAfter
	}

	// Clamp negative durations for transport-level settings.
	// Zero is valid and means "no limit" for most of these.
	cfg.timeout = max(cfg.timeout, 0)
	cfg.dialTimeout = max(cfg.dialTimeout, 0)
	cfg.dialKeepAlive = max(cfg.dialKeepAlive, 0)
	cfg.idleConnTimeout = max(cfg.idleConnTimeout, 0)
	cfg.tlsHandshakeTimeout = max(cfg.tlsHandshakeTimeout, 0)
	cfg.responseHeaderTimeout = max(cfg.responseHeaderTimeout, 0)
	cfg.expectContinueTimeout = max(cfg.expectContinueTimeout, 0)

	var (
		base http.RoundTripper
		h2   *http2.Transport
	)
	if cfg.transport != nil {
		base = cfg.transport
	} else {
		tlsCfg := cfg.tlsConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		} else {
			tlsCfg = tlsCfg.Clone()
		}
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		// Enable TLS 1.2 ticket resumption and TLS 1.3 PSK resumption by
		// default. The Go stdlib does not install a default cache, so
		// without this every connection performs a full handshake.
		if tlsCfg.ClientSessionCache == nil {
			tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(defaultTLSSessionCacheCapacity)
		}

		// Build the dial function. WithDialContext supplies the underlying
		// connection operation; in strict direct mode it is still wrapped by
		// the IP-policy dialer, which resolves once and passes the validated
		// literal address to the caller-provided function.
		dialCtx := cfg.dialContext
		staggeredFallback := dialCtx == nil
		if dialCtx == nil {
			dialer := &net.Dialer{
				Timeout:   cfg.dialTimeout,
				KeepAlive: cfg.dialKeepAlive,
				Resolver:  cfg.resolver,
			}
			dialCtx = dialer.DialContext
		}

		// When the transport is direct, bind strict SSRF validation to the
		// actual dial. This removes the preflight/dial double resolution and
		// closes the DNS-rebinding window between them. A proxy resolves the
		// target outside this process, and a redirect-specific private-address
		// exception cannot be expressed at connection scope, so those clients
		// retain request-time preflight instead.
		if cfg.strictSSRFInitial && cfg.disableProxy && !cfg.allowPrivateRedirects {
			dialCtx = newIPPolicyDialContext(cfg.lookuper(), dialCtx, staggeredFallback)
		}

		proxyFn := http.ProxyFromEnvironment
		if cfg.proxy != nil {
			proxyFn = cfg.proxy
		}

		tr := &http.Transport{
			Proxy:                  proxyFn,
			DialContext:            dialCtx,
			MaxIdleConns:           cfg.maxIdleConns,
			MaxIdleConnsPerHost:    cfg.maxIdleConnsPerHost,
			MaxConnsPerHost:        cfg.maxConnsPerHost,
			IdleConnTimeout:        cfg.idleConnTimeout,
			TLSHandshakeTimeout:    cfg.tlsHandshakeTimeout,
			ResponseHeaderTimeout:  cfg.responseHeaderTimeout,
			MaxResponseHeaderBytes: cfg.maxResponseHeaderBytes,
			ExpectContinueTimeout:  cfg.expectContinueTimeout,
			ForceAttemptHTTP2:      cfg.forceHTTP2,
			DisableKeepAlives:      cfg.disableKeepAlives,
			DisableCompression:     true,
			TLSClientConfig:        tlsCfg,
		}
		if cfg.forceHTTP2 {
			// ConfigureTransports replaces ForceAttemptHTTP2's implicit
			// wiring with an explicit *http2.Transport whose ReadIdleTimeout
			// / PingTimeout we can set. Without these, dead half-open H/2
			// connections sit in the pool until the next use.
			//
			// The only documented failure mode is "t1 already has HTTP/2
			// configured", which cannot happen for a transport we just
			// constructed. A non-nil error here means the contract changed —
			// crash rather than silently falling back to unhealthy H/2.
			var err error
			h2, err = configureHTTP2(tr, cfg.http2ReadIdleTimeout, cfg.http2PingTimeout)
			if err != nil {
				panic(fmt.Sprintf("gttp: unexpected error configuring HTTP/2: %v", err))
			}
		}
		base = tr
	}

	// Only a gttp-owned, direct transport can guarantee that the address
	// validated by the IP policy is the address actually dialed. Custom
	// transports and proxies retain the existing request-time checks.
	ipPolicyAtDial := cfg.strictSSRFInitial && cfg.transport == nil && cfg.disableProxy && !cfg.allowPrivateRedirects

	// Construct the redirect guard first — the safety transport needs a pointer
	// to it for strict-SSRF checks on the initial URL.
	rGuard := newRedirectGuard(redirectConfig{
		maxRedirects:     cfg.maxRedirects,
		allowDowngrade:   cfg.allowSchemeDowngrade,
		allowPrivate:     cfg.allowPrivateRedirects,
		strictInitial:    cfg.strictSSRFInitial,
		sensitiveHeaders: cfg.sensitiveHeaders,
		resolver:         cfg.lookuper(),
		ipPolicyAtDial:   ipPolicyAtDial,
	})

	// safetyTransport sits between retry and the base transport.
	st := &safetyTransport{
		next: base,
		cfg: safetyConfig{
			compressionEnabled: !cfg.disableCompression,
			maxBytes:           cfg.maxResponseBodyBytes,
			idleTimeout:        cfg.idleTimeout,
			minRate:            cfg.minRate,
			minRateWindow:      cfg.minRateWindow,
			maxRatio:           cfg.maxCompressionRatio,
			bodyObserver:       cfg.bodyObserver,
			strictSSRFInitial:  cfg.strictSSRFInitial && !ipPolicyAtDial,
			redirectGuard:      rGuard,
		},
	}

	rt := &retryTransport{
		next:              st,
		maxRetries:        cfg.maxRetries,
		waitMin:           cfg.retryWaitMin,
		waitMax:           cfg.retryWaitMax,
		maxRetryAfter:     cfg.maxRetryAfter,
		maxRetryBodyBytes: cfg.maxRetryBodyBytes,
		retryableCodes:    cfg.retryableStatusCodes,
		retryableMethods:  cfg.retryableMethods,
		checkRetry:        cfg.checkRetry,
		retryObserver:     cfg.retryObserver,
		userAgent:         cfg.userAgent,
		http2Transport:    h2,
	}

	client := &http.Client{
		Transport: rt,
		Timeout:   cfg.timeout,
	}

	if cfg.maxRedirects == 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = rGuard.check
	}

	return client
}

// WithTimeout sets the overall client timeout (dial + TLS + headers + body).
// Default: 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithRedirectPolicy sets the maximum number of redirects to follow.
// Set to 0 to disable redirects. Default: 5.
func WithRedirectPolicy(n int) Option {
	return func(c *config) { c.maxRedirects = n }
}

// WithNoRedirects disables following redirects.
func WithNoRedirects() Option {
	return WithRedirectPolicy(0)
}

// WithUserAgent sets the User-Agent header on requests that don't already have one.
// By default, no User-Agent override is applied (the stdlib default is used).
func WithUserAgent(ua string) Option {
	return func(c *config) { c.userAgent = ua }
}

// WithMaxIdleConns sets the maximum number of idle connections across all hosts.
// Default: 20.
func WithMaxIdleConns(n int) Option {
	return func(c *config) { c.maxIdleConns = n }
}

// WithMaxIdleConnsPerHost sets the maximum number of idle connections per host.
// Default: 20 (stdlib default is 2).
func WithMaxIdleConnsPerHost(n int) Option {
	return func(c *config) { c.maxIdleConnsPerHost = n }
}

// WithMaxConnsPerHost sets the maximum total connections per host.
// 0 means unlimited. Default: 100.
func WithMaxConnsPerHost(n int) Option {
	return func(c *config) { c.maxConnsPerHost = n }
}

// WithIdleConnTimeout sets how long idle connections remain in the pool.
// Default: 90s.
func WithIdleConnTimeout(d time.Duration) Option {
	return func(c *config) { c.idleConnTimeout = d }
}

// WithTLSHandshakeTimeout sets the maximum time for TLS handshakes.
// Default: 5s.
func WithTLSHandshakeTimeout(d time.Duration) Option {
	return func(c *config) { c.tlsHandshakeTimeout = d }
}

// WithResponseHeaderTimeout sets the maximum time to wait for response headers
// after the request is fully written. 0 means no limit. Default: 10s.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(c *config) { c.responseHeaderTimeout = d }
}

// WithDialTimeout sets the maximum time to establish a TCP connection.
// Default: 5s (stdlib default is 30s).
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) { c.dialTimeout = d }
}

// WithRetries sets the maximum number of retries. 0 disables retries.
// Default: 3.
func WithRetries(n int) Option {
	return func(c *config) { c.maxRetries = n }
}

// WithNoRetries disables retry logic entirely.
func WithNoRetries() Option {
	return WithRetries(0)
}

// WithRetryWait sets the minimum and maximum wait times between retries.
// Backoff is exponential with full jitter within these bounds.
// Default: 250ms min, 2s max.
func WithRetryWait(minWait, maxWait time.Duration) Option {
	return func(c *config) {
		c.retryWaitMin = minWait
		c.retryWaitMax = maxWait
	}
}

// WithRetryableStatusCodes replaces the default retryable status codes.
// Default: 408, 425, 429, 502, 503, 504.
func WithRetryableStatusCodes(codes ...int) Option {
	return func(c *config) {
		c.retryableStatusCodes = make(map[int]struct{}, len(codes))
		for _, code := range codes {
			c.retryableStatusCodes[code] = struct{}{}
		}
	}
}

// WithAdditionalRetryableStatusCodes adds status codes to the default retryable set
// without replacing it. For example, to also retry on 500:
//
//	gttp.New(gttp.WithAdditionalRetryableStatusCodes(500))
func WithAdditionalRetryableStatusCodes(codes ...int) Option {
	return func(c *config) {
		for _, code := range codes {
			c.retryableStatusCodes[code] = struct{}{}
		}
	}
}

// WithRetryableMethods replaces the default retryable HTTP methods.
// Default: GET, HEAD, OPTIONS.
func WithRetryableMethods(methods ...string) Option {
	return func(c *config) {
		c.retryableMethods = make(map[string]struct{}, len(methods))
		for _, m := range methods {
			c.retryableMethods[m] = struct{}{}
		}
	}
}

// WithAdditionalRetryableMethods adds HTTP methods to the default retryable set
// without replacing it. For example, to also retry POST and PUT:
//
//	gttp.New(gttp.WithAdditionalRetryableMethods("POST", "PUT"))
func WithAdditionalRetryableMethods(methods ...string) Option {
	return func(c *config) {
		for _, m := range methods {
			c.retryableMethods[m] = struct{}{}
		}
	}
}

// WithMaxRetryAfter sets the maximum duration that a server-directed wait
// hint will be respected. If the server requests a longer delay, it will
// be capped at this value. Applies to Retry-After, RateLimit-Reset (RFC
// 9745 draft), and X-RateLimit-Reset (vendor-specific). Values are also
// floored at the minimum retry wait time (see WithRetryWait).
// Default: 1 minute.
func WithMaxRetryAfter(d time.Duration) Option {
	return func(c *config) { c.maxRetryAfter = d }
}

// WithMaxRetryBodyBytes sets the maximum request body size (in bytes) that will
// be buffered into memory for retry support. Bodies larger than this limit cause
// an error when retries are enabled and the body is not already seekable.
// Set to 0 for no limit. Default: 4 MiB.
func WithMaxRetryBodyBytes(n int64) Option {
	return func(c *config) { c.maxRetryBodyBytes = n }
}

// WithCheckRetry provides a custom function to determine if a request should be retried.
// When set, this overrides the default status-code and error classification logic,
// but the method check still applies first — only methods in the retryable set
// are candidates for retry. Return true to retry, false to stop.
func WithCheckRetry(fn func(req *http.Request, resp *http.Response, err error) bool) Option {
	return func(c *config) { c.checkRetry = fn }
}

// WithRetryObserver registers a callback that is invoked before each retry
// attempt. The attempt number is 0-indexed (0 = first failed attempt that
// will be retried). This is not called on the final exhausted attempt —
// only when a retry will actually follow. This is useful for logging or
// metrics.
func WithRetryObserver(fn func(attempt int, req *http.Request, resp *http.Response, err error)) Option {
	return func(c *config) { c.retryObserver = fn }
}

// WithTransport provides a custom base RoundTripper, bypassing the default
// transport construction. Retry logic and response-body guards (idle
// timeout, size cap, min-rate) are still applied on top, but note:
//
// The decompression-bomb guard (WithMaxCompressionRatio) is effectively
// disabled when a custom transport is supplied, because gttp can no longer
// control the base transport's DisableCompression setting. The caller's
// transport is presumed to handle Accept-Encoding / gzip decoding itself,
// and once stdlib's default transport auto-decodes, the response arrives
// without a Content-Encoding header for gttp to act on. If you need the
// bomb guard, use the default transport.
func WithTransport(rt http.RoundTripper) Option {
	return func(c *config) { c.transport = rt }
}

// WithTLSConfig sets a custom TLS configuration on the default transport.
// A minimum TLS version of 1.2 is enforced regardless of the provided config.
// This option is ignored when WithTransport is used.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *config) { c.tlsConfig = cfg }
}

// WithDisableKeepAlives disables HTTP keep-alives, making each request use a
// new connection. Useful for short-lived CLI tools.
func WithDisableKeepAlives() Option {
	return func(c *config) { c.disableKeepAlives = true }
}

// WithDisableCompression disables transparent gzip decompression.
// The client will not add Accept-Encoding: gzip and will not decompress
// responses automatically. This can be useful when Content-Length must match
// the actual body size.
func WithDisableCompression() Option {
	return func(c *config) { c.disableCompression = true }
}

// WithBodyObserver registers a callback invoked when a guarded response body
// is closed. This is intended for temporary diagnostics where callers need
// precise response byte counts without changing higher-level APIs.
func WithBodyObserver(fn func(BodyObservation)) Option {
	return func(c *config) { c.bodyObserver = fn }
}

// WithForceHTTP2 controls whether HTTP/2 is attempted when a custom TLS
// config is set. Default: true.
func WithForceHTTP2(force bool) Option {
	return func(c *config) { c.forceHTTP2 = force }
}

// WithHTTP2ReadIdleTimeout sets the duration after which an HTTP/2 health-check
// PING is sent when no frame has been received on a connection. This detects
// silently-dropped connections (e.g., by a load balancer) that would otherwise
// sit in the idle pool forever. Set to 0 to disable health checks.
// Default: 30s. Has no effect when WithForceHTTP2(false) or WithTransport is used.
func WithHTTP2ReadIdleTimeout(d time.Duration) Option {
	return func(c *config) { c.http2ReadIdleTimeout = d }
}

// WithHTTP2PingTimeout sets how long to wait for a response to an HTTP/2
// health-check PING before tearing the connection down.
// Default: 15s. Has no effect when WithForceHTTP2(false) or WithTransport is used.
func WithHTTP2PingTimeout(d time.Duration) Option {
	return func(c *config) { c.http2PingTimeout = d }
}

// WithExpectContinueTimeout sets the maximum time to wait for a server's
// first response headers after fully writing the request headers if the
// request has an "Expect: 100-continue" header. Default: 2s.
func WithExpectContinueTimeout(d time.Duration) Option {
	return func(c *config) { c.expectContinueTimeout = d }
}

// WithDialKeepAlive sets the TCP keep-alive interval for connections.
// Default: 30s.
func WithDialKeepAlive(d time.Duration) Option {
	return func(c *config) { c.dialKeepAlive = d }
}

// WithDialContext provides a custom function for establishing TCP connections.
// When set, WithDialTimeout and WithDialKeepAlive are ignored since they
// configure the default dialer that this replaces.
//
// WithResolver is likewise ignored in the general case, but not in strict
// direct mode: when WithStrictSSRFProtection and WithNoProxy are set without
// WithAllowPrivateRedirects, gttp resolves the request hostname itself with the
// configured resolver, validates the full answer set, and calls this function
// only with an already-validated literal IP address. In that mode WithResolver
// controls the validation lookup, and a custom dialer that performs its own
// name resolution never receives the original hostname. This is required to
// close the DNS-rebinding window between validation and dial.
//
// This option is ignored when WithTransport is used.
func WithDialContext(fn func(ctx context.Context, network, address string) (net.Conn, error)) Option {
	return func(c *config) { c.dialContext = fn }
}

// WithResolver sets a custom DNS resolver on the default dialer.
// This is useful for directing DNS queries to a specific server (e.g., 1.1.1.1)
// without replacing the entire dial function. Example:
//
//	gttp.New(gttp.WithResolver(&net.Resolver{
//	    PreferGo: true,
//	    Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
//	        return (&net.Dialer{}).DialContext(ctx, "udp", "1.1.1.1:53")
//	    },
//	}))
//
// The dialer does not use it when WithTransport is used, or when
// WithDialContext is used outside strict direct mode. In strict direct mode
// (WithStrictSSRFProtection and WithNoProxy without WithAllowPrivateRedirects)
// it drives the validation lookup even alongside WithDialContext; see
// WithDialContext for details.
//
// Independently of the dial, the redirect guard resolves each redirect target
// with this resolver to check the IP policy, including alongside
// WithDialContext or WithTransport. WithLookupIPAddr takes precedence for
// both of gttp's own lookups.
func WithResolver(r *net.Resolver) Option {
	return func(c *config) { c.resolver = r }
}

// lookuper returns the lookup behind gttp's own IP-policy checks.
func (c *config) lookuper() ipLookuper {
	if c.lookupIPAddr != nil {
		return resolverFunc(c.lookupIPAddr)
	}
	return c.resolver
}

// WithLookupIPAddr sets the function gttp uses for the DNS lookups it makes
// itself: the strict direct-mode dial validation (see WithDialContext) and the
// redirect guard's IP-policy check. It takes precedence over WithResolver for
// those lookups. Callers that keep their own DNS cache can pass its lookup here
// so gttp shares the cached answers instead of querying again.
//
// It does not change how the default dialer resolves outside strict direct
// mode; use WithResolver for that.
func WithLookupIPAddr(fn func(ctx context.Context, host string) ([]net.IPAddr, error)) Option {
	return func(c *config) { c.lookupIPAddr = fn }
}

// WithProxy sets a custom proxy function for the transport.
// The default is http.ProxyFromEnvironment. Use WithNoProxy to disable
// proxy support entirely.
// This option is ignored when WithTransport is used.
func WithProxy(fn func(*http.Request) (*url.URL, error)) Option {
	return func(c *config) {
		c.proxy = fn
		c.disableProxy = false
	}
}

// WithNoProxy disables proxy support, making all connections direct.
// This option is ignored when WithTransport is used.
func WithNoProxy() Option {
	return func(c *config) {
		c.proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
		c.disableProxy = true
	}
}

// WithMaxResponseHeaderBytes sets the maximum number of response bytes that
// the transport will read looking for the header. 0 means no limit.
// This option is ignored when WithTransport is used.
func WithMaxResponseHeaderBytes(n int64) Option {
	return func(c *config) { c.maxResponseHeaderBytes = n }
}

// WithIdleTimeout sets the idle timeout applied to both response-body reads
// and request-body writes. If no bytes flow in either direction for this long,
// the request is cancelled with ErrBodyIdleTimeout. 0 disables. Default: 30s.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *config) { c.idleTimeout = d }
}

// WithMinTransferRate sets a minimum average transfer rate (bytes per second)
// for the response body, measured over the given rolling window. If the
// observed rate stays below bps for a full window, the read fails with
// ErrBodyTransferTooSlow. Default: disabled. Matches curl --speed-limit /
// --speed-time.
func WithMinTransferRate(bps int64, window time.Duration) Option {
	return func(c *config) { c.minRate = bps; c.minRateWindow = window }
}

// WithMaxResponseBodyBytes sets a hard cap on the decompressed response
// body size. Reads past this limit fail with ErrResponseTooLarge. 0 disables
// (unlimited). Default: 0.
func WithMaxResponseBodyBytes(n int64) Option {
	return func(c *config) { c.maxResponseBodyBytes = n }
}

// WithMaxCompressionRatio sets the maximum allowed decompressed:compressed
// ratio when gzip decoding is in effect. The guard activates only once at
// least 64 KiB of compressed bytes have been read, to avoid false positives
// on small responses. 0 disables. Default: 1000.
func WithMaxCompressionRatio(r float64) Option {
	return func(c *config) { c.maxCompressionRatio = r }
}

// WithAllowSchemeDowngrade opts out of refusing https -> http redirects.
func WithAllowSchemeDowngrade() Option {
	return func(c *config) { c.allowSchemeDowngrade = true }
}

// WithAllowPrivateRedirects opts out of the SSRF redirect guard.
// When set, redirects to loopback / private / link-local / CGNAT / NAT64 / IMDS
// addresses are allowed.
func WithAllowPrivateRedirects() Option {
	return func(c *config) { c.allowPrivateRedirects = true }
}

// WithStrictSSRFProtection also applies the IP policy to the initial
// request URL (not just redirects). Useful for services accepting
// attacker-controlled URLs.
//
// Combine this with [WithNoProxy] to bind validation to the actual network
// connection: gttp resolves each hostname once per new connection, validates
// every returned address, and dials an approved literal address. With a proxy
// or custom transport, gttp cannot control the target dial and therefore
// retains request-time DNS preflight checks instead. The preflight path is
// also retained with [WithAllowPrivateRedirects], whose redirect-specific
// exception cannot be represented safely by a connection-wide dial policy.
func WithStrictSSRFProtection() Option {
	return func(c *config) { c.strictSSRFInitial = true }
}

// WithSensitiveHeaders marks additional header names to strip when a redirect
// crosses origins. The stdlib already strips Authorization and cookies; this
// extends the set for bearer tokens, API keys, and so on.
func WithSensitiveHeaders(names ...string) Option {
	return func(c *config) {
		c.sensitiveHeaders = append([]string(nil), names...)
	}
}
