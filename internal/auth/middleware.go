package auth

// Transport middleware for the /auth/v1 surface: CORS, client-IP resolution,
// per-IP rate limiting and the request timeout. Everything here is
// hand-rolled on purpose — the compatibility surface must not drag a third
// party HTTP middleware dependency into the module.

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/dilion-io/dilion/internal/netguard"
	"github.com/dilion-io/dilion/ports"
)

// ---- CORS ------------------------------------------------------------------

// corsAllowedMethods is upstream's list plus OPTIONS (upstream's cors library
// answers preflights itself and therefore does not list it).
var corsAllowedMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut,
	http.MethodDelete, http.MethodPatch, http.MethodOptions,
}

// corsDefaultAllowedHeaders mirrors upstream's defaults, plus apikey for
// direct browser use of the Supabase-compatible SDK without a gateway.
var corsDefaultAllowedHeaders = []string{
	"Accept", "Authorization", "Content-Type",
	"X-Client-Info", "X-Client-IP", "X-JWT-AUD",
	"x-use-cookie", "X-Supabase-Api-Version",
	"apikey",
}

// corsExposedHeaders mirrors upstream's ExposedHeaders.
var corsExposedHeaders = []string{"X-Total-Count", "Link", "X-Supabase-Api-Version"}

// corsAllowedHeaders is the built-in list plus the deployment's extras
// (GOTRUE_CORS_ALLOWED_HEADERS), de-duplicated, defaults first — upstream's
// CORSConfiguration.AllAllowedHeaders.
func corsAllowedHeaders(c *Config) []string {
	out := append([]string(nil), corsDefaultAllowedHeaders...)
	seen := make(map[string]bool, len(out))
	for _, h := range out {
		seen[strings.ToLower(h)] = true
	}
	if c != nil {
		for _, h := range c.CORS.AllowedHeaders {
			if h = strings.TrimSpace(h); h != "" && !seen[strings.ToLower(h)] {
				seen[strings.ToLower(h)] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// corsMiddleware answers preflights with 204 and decorates every other response
// with the permissive CORS headers gotrue clients expect.
//
// Origins are "*" and credentials are NOT allowed: /auth/v1 is a bearer-token
// API, so a wildcard origin without credentials is both sufficient and the only
// combination browsers accept.
func corsMiddleware(c *Config) func(http.Handler) http.Handler {
	allowedMethods := strings.Join(corsAllowedMethods, ", ")
	allowedHeaders := strings.Join(corsAllowedHeaders(c), ", ")
	exposedHeaders := strings.Join(corsExposedHeaders, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Expose-Headers", exposedHeaders)

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Methods", allowedMethods)
				h.Set("Access-Control-Allow-Headers", allowedHeaders)
				h.Set("Access-Control-Max-Age", "3600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- client IP -------------------------------------------------------------

type ipCtxKey struct{}

// clientIPMiddleware resolves the client address once per request and puts it on
// the context, so sessions, audit records and the rate limiter all agree on the
// same value.
func (a *api) clientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netguard.ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), a.trustedProxies)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ipCtxKey{}, ip)))
	})
}

// clientIP is the address of the caller, as clientIPMiddleware resolved it:
// X-Forwarded-For counts only as far as the operator's trusted proxies
// (Deps.TrustedProxies) vouch for it, since the header is whatever the client
// sends. Every rate limit and account lock keys on this value.
func clientIP(r *http.Request) string {
	if v, ok := r.Context().Value(ipCtxKey{}).(string); ok && v != "" {
		return v
	}
	return netguard.ClientIP(r.RemoteAddr, "", netguard.Networks{})
}

// clientIPInet returns clientIP in a form Postgres `inet` accepts, or nil when
// the address is not a valid IP (unit tests, unix sockets).
func clientIPInet(r *http.Request) *string {
	if ip := net.ParseIP(clientIP(r)); ip != nil {
		s := ip.String()
		return &s
	}
	return nil
}

// ---- rate limiting ---------------------------------------------------------

// Limiter names. Feature files rate-limit their routes with a.limit(<name>) —
// see Register. Names are stable; the limits behind them come from Config.
const (
	// LimiterToken is POST /token?grant_type=refresh_token
	// (GOTRUE_RATE_LIMIT_TOKEN_REFRESH).
	LimiterToken = "token"
	// LimiterTokenPassword is POST /token?grant_type=password. Upstream shares
	// the refresh limit; Dilion applies the (much stricter) OTP limit, because a
	// password grant is a credential-guessing surface and a refresh is not.
	LimiterTokenPassword = "token_password"
	// LimiterSignup is POST /signup (GOTRUE_RATE_LIMIT_OTP, as upstream).
	LimiterSignup = "signup"
	// LimiterAnonymous is POST /signup without email or phone
	// (GOTRUE_RATE_LIMIT_ANONYMOUS_USERS, per HOUR).
	LimiterAnonymous = "anonymous"
	// LimiterVerify is /verify (GOTRUE_RATE_LIMIT_VERIFY).
	LimiterVerify = "verify"
	// LimiterOTP is POST /otp (GOTRUE_RATE_LIMIT_EMAIL_SENT).
	LimiterOTP = "otp"
	// LimiterMagicLink is POST /magiclink (GOTRUE_RATE_LIMIT_EMAIL_SENT).
	LimiterMagicLink = "magiclink"
	// LimiterRecover is POST /recover (GOTRUE_RATE_LIMIT_EMAIL_SENT).
	LimiterRecover = "recover"
	// LimiterResend is POST /resend (GOTRUE_RATE_LIMIT_EMAIL_SENT).
	LimiterResend = "resend"
	// LimiterSMS is the SMS-sending endpoints (GOTRUE_RATE_LIMIT_SMS_SENT).
	LimiterSMS = "sms"
	// LimiterUser is PUT /user (GOTRUE_RATE_LIMIT_OTP, as upstream).
	LimiterUser = "user"
	// LimiterSSO is POST /sso (GOTRUE_RATE_LIMIT_SSO).
	LimiterSSO = "sso"
	// LimiterWeb3 is POST /token?grant_type=web3 (GOTRUE_RATE_LIMIT_WEB3).
	LimiterWeb3 = "web3"
	// LimiterPasskey is the passkey endpoints (GOTRUE_RATE_LIMIT_PASSKEY).
	LimiterPasskey = "passkey"
)

// rateWindow is upstream's rate-limit window: every GOTRUE_RATE_LIMIT_* number
// except ANONYMOUS_USERS is "requests per 5 minutes".
const rateWindow = 5 * time.Minute

// rateBurst is upstream's tollbooth burst for every per-5-minute limiter.
const rateBurst = 30

// buildLimiters wires the named limiters from the configuration.
func buildLimiters(c *Config) map[string]*rateLimiter {
	rl := c.RateLimits
	m := map[string]*rateLimiter{
		LimiterToken:         newRateLimiter(rl.TokenRefresh, rateWindow, rateBurst),
		LimiterTokenPassword: newRateLimiter(rl.OTP, rateWindow, rateBurst),
		LimiterSignup:        newRateLimiter(rl.OTP, rateWindow, rateBurst),
		LimiterUser:          newRateLimiter(rl.OTP, rateWindow, rateBurst),
		LimiterVerify:        newRateLimiter(rl.Verify, rateWindow, rateBurst),
		LimiterOTP:           newRateLimiter(rl.EmailSent, rateWindow, rateBurst),
		LimiterMagicLink:     newRateLimiter(rl.EmailSent, rateWindow, rateBurst),
		LimiterRecover:       newRateLimiter(rl.EmailSent, rateWindow, rateBurst),
		LimiterResend:        newRateLimiter(rl.EmailSent, rateWindow, rateBurst),
		LimiterSMS:           newRateLimiter(rl.SMSSent, rateWindow, rateBurst),
		LimiterSSO:           newRateLimiter(rl.SSO, rateWindow, rateBurst),
		LimiterWeb3:          newRateLimiter(rl.Web3, rateWindow, rateBurst),
		LimiterPasskey:       newRateLimiter(rl.Passkey, rateWindow, rateBurst),
		// Upstream measures anonymous sign-ins per hour, with the configured
		// number itself as the burst.
		LimiterAnonymous: newRateLimiter(rl.AnonymousUsers, time.Hour, int(rl.AnonymousUsers)),
	}
	return m
}

// limit returns a middleware that rate-limits by client IP under the given
// limiter name. An unknown name is a programming error and is fail-closed: the
// request is rejected, never silently unlimited.
func (a *api) limit(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.limitCheck(name, r); err != nil {
				a.writeError(r, w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitCheck consumes one token of the named limiter for this request's client
// IP, returning the gotrue 429 body when the bucket is empty. Handlers that
// choose their limiter dynamically (POST /token, POST /signup) call it directly.
func (a *api) limitCheck(name string, r *http.Request) error {
	l := a.limiters[name]
	if l == nil {
		a.log.ErrorContext(r.Context(), "auth: unknown rate limiter", "limiter", name)
		return tooManyRequestsError("Request rate limit reached")
	}
	// Keyed per instance too: one instance's traffic must not spend another
	// instance's budget for the same address.
	if !l.allow(ports.InstanceFromContext(r.Context()) + "|" + clientIP(r)) {
		return tooManyRequestsError("Request rate limit reached")
	}
	return nil
}

// rateLimiter is a per-key token bucket. Keys are client IPs.
type rateLimiter struct {
	// refill is the token replenishment rate, in tokens per second.
	refill float64
	// burst is the bucket size, i.e. the largest instantaneous spike allowed.
	burst float64
	// ttl is how long an idle bucket is kept before the janitor drops it.
	ttl time.Duration
	// now is injectable for tests.
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*rateBucket
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter allows `perWindow` requests per `window` per key, tolerating an
// instantaneous burst of `burst`. A perWindow of 0 means "burst only, then
// always deny", which is how upstream's tollbooth behaves for a zero rate.
func newRateLimiter(perWindow float64, window time.Duration, burst int) *rateLimiter {
	if burst < 1 {
		burst = 1
	}
	if window <= 0 {
		window = rateWindow
	}
	l := &rateLimiter{
		refill:  perWindow / window.Seconds(),
		burst:   float64(burst),
		ttl:     time.Hour,
		now:     time.Now,
		buckets: map[string]*rateBucket{},
	}
	registerJanitorTarget(l)
	return l
}

// allow consumes one token for key.
func (l *rateLimiter) allow(key string) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil {
		b = &rateBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed.Seconds()*l.refill)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been idle for longer than ttl AND are full
// again, so nothing is forgotten while it still owes tokens.
func (l *rateLimiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if now.Sub(b.last) < l.ttl {
			continue
		}
		if b.tokens+now.Sub(b.last).Seconds()*l.refill >= l.burst {
			delete(l.buckets, key)
		}
	}
}

// The janitor is one process-wide goroutine sweeping every live limiter. It
// holds only WEAK references, so a limiter whose *api has been collected (every
// test builds its own) disappears with it instead of keeping the map alive.
var (
	janitorOnce  sync.Once
	janitorMu    sync.Mutex
	janitorLimit []weak.Pointer[rateLimiter]
)

// janitorInterval is the base sweep period; each pass adds up to 50% jitter so
// many processes started together do not sweep in lockstep.
const janitorInterval = 5 * time.Minute

func registerJanitorTarget(l *rateLimiter) {
	janitorMu.Lock()
	janitorLimit = append(janitorLimit, weak.Make(l))
	janitorMu.Unlock()
	janitorOnce.Do(func() { go janitorLoop() })
}

func janitorLoop() {
	for {
		jitter := time.Duration(rand.Int64N(int64(janitorInterval / 2)))
		time.Sleep(janitorInterval + jitter)

		now := time.Now()
		janitorMu.Lock()
		live := janitorLimit[:0]
		for _, ref := range janitorLimit {
			if l := ref.Value(); l != nil {
				live = append(live, ref)
			}
		}
		for i := len(live); i < len(janitorLimit); i++ {
			janitorLimit[i] = weak.Pointer[rateLimiter]{}
		}
		janitorLimit = live
		targets := make([]*rateLimiter, 0, len(janitorLimit))
		for _, ref := range janitorLimit {
			if l := ref.Value(); l != nil {
				targets = append(targets, l)
			}
		}
		janitorMu.Unlock()

		for _, l := range targets {
			l.sweep(now)
		}
	}
}

// ---- request timeout -------------------------------------------------------

// timeoutMiddleware bounds a request by Config.APIMaxRequestDuration
// (GOTRUE_API_MAX_REQUEST_DURATION). On expiry the client gets gotrue's 504
// error body and the handler's later writes are discarded; the handler itself
// observes a cancelled context and unwinds on its own.
func timeoutMiddleware(a *api, d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if d <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()

			tw := newTimeoutWriter(w)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if rec := recover(); rec != nil {
						a.log.ErrorContext(ctx, "auth: handler panicked",
							"path", r.URL.Path, "panic", rec)
						tw.write(http.StatusInternalServerError,
							internalServerError("Unexpected failure, please check server logs for more information"))
					}
				}()
				next.ServeHTTP(tw, r.WithContext(ctx))
			}()

			select {
			case <-done:
				tw.flush()
			case <-ctx.Done():
				tw.write(http.StatusGatewayTimeout,
					httpError(http.StatusGatewayTimeout, ErrorCodeRequestTimeout, "Processing this request timed out, please retry after a moment."))
			}
		})
	}
}

// timeoutWriter buffers the handler's response privately (the model
// http.TimeoutHandler uses): the handler goroutine only ever touches the
// decoy header and body buffer, so it can never race the timeout goroutine
// on the real ResponseWriter — including Header() map mutations.
type timeoutWriter struct {
	dst http.ResponseWriter

	mu       sync.Mutex
	hdr      http.Header
	buf      bytes.Buffer
	status   int
	timedOut bool
}

func newTimeoutWriter(w http.ResponseWriter) *timeoutWriter {
	return &timeoutWriter{dst: w, hdr: http.Header{}}
}

func (t *timeoutWriter) Header() http.Header {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hdr
}

func (t *timeoutWriter) WriteHeader(status int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == 0 {
		t.status = status
	}
}

func (t *timeoutWriter) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return len(b), nil
	}
	if t.status == 0 {
		t.status = http.StatusOK
	}
	return t.buf.Write(b)
}

// flush copies the buffered response to the real writer. No-op after timeout.
func (t *timeoutWriter) flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return
	}
	dh := t.dst.Header()
	for k, v := range t.hdr {
		dh[k] = v
	}
	if t.status == 0 {
		t.status = http.StatusOK
	}
	t.dst.WriteHeader(t.status)
	_, _ = t.dst.Write(t.buf.Bytes())
}

// write emits a terminal JSON body directly, discarding the handler's buffer.
func (t *timeoutWriter) write(status int, body *HTTPError) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return
	}
	t.timedOut = true
	t.dst.Header().Set("Content-Type", "application/json")
	t.dst.WriteHeader(status)
	b, err := json.Marshal(body)
	if err != nil {
		b = []byte(`{"code":500,"error_code":"unexpected_failure","msg":"Unexpected failure"}`)
	}
	_, _ = t.dst.Write(b)
}
