package auth

// Per-instance auth hook settings (Dilion extension).
//
//	GET    /admin/hooks          -> {"hooks": [hookSettingView, ...]}  every hook, as it runs here
//	GET    /admin/hooks/{name}   -> hookSettingView
//	PUT    /admin/hooks/{name}   -> hookSettingView  (sets this instance's setting)
//	DELETE /admin/hooks/{name}   -> hookSettingView  (back to the server-wide setting)
//
// {name} is a HooksConfig key: custom_access_token, send_email, send_sms,
// before_user_created, after_user_created, mfa_verification_attempt,
// password_verification_attempt.
//
// Upstream configures hooks per process (GOTRUE_HOOK_*), which is per project
// there. A Dilion server serves many instances, so the server-wide setting is a
// default and each instance may replace it with a row in its own
// dilion_auth.hooks. The row wins whole — including enabled=false, which
// switches a server-wide hook off for that instance. The operator keeps two
// controls:
//
//   - HookEndpointConfig.Locked pins the server-wide setting: the row cannot be
//     written and one already stored is ignored.
//   - the ports.AuthHookSetting hook point vets every URI an instance uses,
//     when it is saved and again before each call, and decides whether its
//     calls are held to public addresses (ssrfGuard).
//
// Both drivers are allowed. A pg-functions hook runs in the instance's own
// database, which its admin already controls fully.
//
// The secrets are write-only: accepted on PUT, reported only as a count.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/ports"
)

func init() {
	registerFeature("admin_hooks", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin, a.requireAdminPermission(PermAuthSettingsManage))
			r.Get("/admin/hooks", a.handle(a.adminListHooks))
			r.Get("/admin/hooks/{name}", a.handle(a.adminGetHook))
			r.Put("/admin/hooks/{name}", a.handle(a.adminPutHook))
			r.Delete("/admin/hooks/{name}", a.handle(a.adminDeleteHook))
		})
	})
}

// Hook setting keys: the HooksConfig JSON names, which are also the
// dilion_auth.hooks primary keys.
const (
	hookCustomAccessToken           = "custom_access_token"
	hookSendEmail                   = "send_email"
	hookSendSMS                     = "send_sms"
	hookBeforeUserCreated           = "before_user_created"
	hookAfterUserCreated            = "after_user_created"
	hookMFAVerificationAttempt      = "mfa_verification_attempt"
	hookPasswordVerificationAttempt = "password_verification_attempt"
)

// hookKeys lists every hook in the order /admin/hooks reports them.
var hookKeys = []string{
	hookCustomAccessToken, hookSendEmail, hookSendSMS,
	hookBeforeUserCreated, hookAfterUserCreated,
	hookMFAVerificationAttempt, hookPasswordVerificationAttempt,
}

// byKey returns the server-wide setting of hook key.
func (h *HooksConfig) byKey(key string) (HookEndpointConfig, bool) {
	switch key {
	case hookCustomAccessToken:
		return h.CustomAccessToken, true
	case hookSendEmail:
		return h.SendEmail, true
	case hookSendSMS:
		return h.SendSMS, true
	case hookBeforeUserCreated:
		return h.BeforeUserCreated, true
	case hookAfterUserCreated:
		return h.AfterUserCreated, true
	case hookMFAVerificationAttempt:
		return h.MFAVerificationAttempt, true
	case hookPasswordVerificationAttempt:
		return h.PasswordVerificationAttempt, true
	}
	return HookEndpointConfig{}, false
}

const (
	// ErrorCodeHookNotFound is the 404 for an unknown {name}.
	ErrorCodeHookNotFound = "hook_not_found"
	// ErrorCodeHookLocked is the 403 for a hook the operator pinned.
	ErrorCodeHookLocked = "hook_locked"
)

// instanceHook is one dilion_auth.hooks row.
type instanceHook struct {
	Enabled   bool
	URI       string
	Secrets   []string
	UpdatedAt time.Time
}

// loadInstanceHook reads the instance's row for key; (nil, nil) when it has none.
func loadInstanceHook(ctx context.Context, q querier, key string) (*instanceHook, error) {
	var h instanceHook
	err := q.QueryRow(ctx, `select enabled, uri, secrets, updated_at from dilion_auth.hooks where name = $1`, key).
		Scan(&h.Enabled, &h.URI, &h.Secrets, &h.UpdatedAt)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// hookConfig returns the setting hook key runs with for the instance on ctx:
// the instance's own, unless it has none or the server-wide one is locked. q
// is the caller's transaction when one is open, nil otherwise.
//
// An instance setting that is enabled passes the operator's policy here, on
// every call, so tightening the policy takes effect on settings already saved.
func (a *api) hookConfig(ctx context.Context, q querier, key string) (HookEndpointConfig, error) {
	server, _ := a.cfg.Hooks.byKey(key)
	if server.Locked {
		return server, nil
	}
	if q == nil {
		pool, err := a.db(ctx)
		if err != nil {
			return HookEndpointConfig{}, err
		}
		q = pool
	}
	row, err := loadInstanceHook(ctx, q, key)
	if err != nil {
		return HookEndpointConfig{}, internalServerError("Database error loading hook setting").withInternal(err)
	}
	if row == nil {
		return server, nil
	}
	cfg := HookEndpointConfig{Enabled: row.Enabled, URI: row.URI, Secrets: row.Secrets}
	if !cfg.Enabled {
		return cfg, nil
	}
	guard, err := a.hookPolicy(ctx, key, cfg.URI)
	if err != nil {
		return HookEndpointConfig{}, internalServerError("Hook %s is not allowed by server policy", key).withInternal(err)
	}
	cfg.ssrfGuard = guard
	return cfg, nil
}

// hookEnabled reports whether hook key is on for the instance on ctx.
func (a *api) hookEnabled(ctx context.Context, q querier, key string) (bool, error) {
	cfg, err := a.hookConfig(ctx, q, key)
	return cfg.Enabled, err
}

// hookPolicy runs the operator's ports.AuthHookSetting policy for an instance
// setting and reports whether its calls must stay on public addresses. With no
// policy registered that is true for every http(s) URI.
func (a *api) hookPolicy(ctx context.Context, key, uri string) (bool, error) {
	web := isHTTPHookURI(uri)
	out, err := a.runHook(ctx, ports.AuthHookSetting, map[string]any{
		"hook":            key,
		"uri":             uri,
		"ssrf_protection": web,
	})
	if err != nil {
		return false, err
	}
	guard := web
	if v, ok := out["ssrf_protection"].(bool); ok {
		guard = v
	}
	return web && guard, nil
}

func isHTTPHookURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}

// ---- SSRF guard ------------------------------------------------------------

// errNonPublicAddress is what a guarded hook call fails with when the hook's
// host is, or resolves to, an address outside the public internet.
var errNonPublicAddress = errors.New("hook address is not public")

// nonPublicPrefixes are the ranges net/netip's predicates do not already
// cover: shared (CGNAT), "this network", IETF protocol assignments,
// benchmarking, reserved, and the IPv6 transition prefixes that can embed an
// IPv4 address of any kind.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
}

// isPublicAddr reports whether a guarded hook may connect to addr.
func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// guardedHookTransport carries the calls of guarded hooks. The check runs on
// the address actually dialled, after DNS resolution, so a name that resolves
// to a public address when saved and to an internal one later (DNS
// rebinding), or a redirect to an internal URL, is still refused. It ignores
// HTTP_PROXY: through a proxy the dialled address would be the proxy's.
var guardedHookTransport = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout: httpHookTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !isPublicAddr(ap.Addr()) {
				return errNonPublicAddress
			}
			return nil
		},
	}).DialContext,
	ForceAttemptHTTP2:   true,
	MaxIdleConns:        100,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

// checkPublicHost resolves a guarded URI's host when it is saved, so an admin
// learns straight away that it points inside the network; the dial-time check
// in guardedHookTransport is the one that holds.
func checkPublicHost(ctx context.Context, host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !isPublicAddr(addr) {
			return errNonPublicAddress
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s", host)
	}
	for _, addr := range addrs {
		if !isPublicAddr(addr) {
			return errNonPublicAddress
		}
	}
	return nil
}

// ---- admin surface ---------------------------------------------------------

// hookSettingView is how /admin/hooks reports one hook.
type hookSettingView struct {
	Name string `json:"name"`
	// Source is where the setting in force comes from: "instance" (this
	// instance's own) or "server" (the server-wide one).
	Source       string     `json:"source"`
	Enabled      bool       `json:"enabled"`
	URI          string     `json:"uri"`
	SecretsCount int        `json:"secrets_count"`
	Locked       bool       `json:"locked"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// HookSettingParams is the PUT body. secrets absent keeps the ones stored;
// present (even empty) replaces them.
type HookSettingParams struct {
	Enabled *bool     `json:"enabled"`
	URI     string    `json:"uri"`
	Secrets *[]string `json:"secrets"`
}

// hookView reports key as it runs for the instance on ctx.
func (a *api) hookView(ctx context.Context, q querier, key string) (hookSettingView, error) {
	server, _ := a.cfg.Hooks.byKey(key)
	v := hookSettingView{
		Name: key, Source: "server", Locked: server.Locked,
		Enabled: server.Enabled, URI: server.URI, SecretsCount: len(server.Secrets),
	}
	if server.Locked {
		return v, nil
	}
	row, err := loadInstanceHook(ctx, q, key)
	if err != nil {
		return v, internalServerError("Database error loading hook setting").withInternal(err)
	}
	if row != nil {
		updated := row.UpdatedAt.UTC()
		v.Source, v.Enabled, v.URI, v.SecretsCount, v.UpdatedAt = "instance", row.Enabled, row.URI, len(row.Secrets), &updated
	}
	return v, nil
}

// hookKeyParam resolves {name}, refusing a locked hook when forWrite.
func (a *api) hookKeyParam(r *http.Request, forWrite bool) (string, error) {
	key := chi.URLParam(r, "name")
	server, ok := a.cfg.Hooks.byKey(key)
	if !ok {
		return "", notFoundError(ErrorCodeHookNotFound, "Hook not found")
	}
	if forWrite && server.Locked {
		return "", forbiddenError(ErrorCodeHookLocked, "Hook %s is set by the server and cannot be changed", key)
	}
	return key, nil
}

// validateHookSetting checks an instance setting before it is stored.
func (a *api) validateHookSetting(ctx context.Context, key string, enabled bool, uri string, secrets []string) error {
	for _, s := range secrets {
		if _, err := decodeHookSecret(s); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "secrets must be v1,whsec_<base64> keys")
		}
	}
	if uri == "" {
		if enabled {
			return badRequestError(ErrorCodeValidationFailed, "uri is required to enable a hook")
		}
		return nil
	}
	var host string
	switch {
	case isHTTPHookURI(uri):
		u, err := url.Parse(uri)
		if err != nil || u.Hostname() == "" {
			return badRequestError(ErrorCodeValidationFailed, "uri must be an absolute http(s) URL")
		}
		host = u.Hostname()
	case strings.HasPrefix(uri, "pg-functions:"):
		if _, err := pgHookName(uri); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "uri must be pg-functions://<db>/<schema>/<function>")
		}
	default:
		return badRequestError(ErrorCodeValidationFailed, "uri must be http(s):// or pg-functions://")
	}
	// A disabled setting is checked for shape only: it makes no calls, and the
	// policy runs again once it is enabled.
	if !enabled {
		return nil
	}
	guard, err := a.hookPolicy(ctx, key, uri)
	if err != nil {
		reason := err
		if inner := errors.Unwrap(err); inner != nil {
			reason = inner // drop the registry's "hook auth_hook_setting[i]:" prefix
		}
		return badRequestError(ErrorCodeValidationFailed, "uri is not allowed: %s", reason.Error())
	}
	if guard {
		if err := checkPublicHost(ctx, host); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "uri is not allowed: %s", err.Error())
		}
	}
	return nil
}

func (a *api) adminListHooks(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	views := make([]hookSettingView, 0, len(hookKeys))
	for _, key := range hookKeys {
		v, err := a.hookView(ctx, pool, key)
		if err != nil {
			return err
		}
		views = append(views, v)
	}
	return sendJSON(w, http.StatusOK, map[string]any{"hooks": views})
}

func (a *api) adminGetHook(w http.ResponseWriter, r *http.Request) error {
	key, err := a.hookKeyParam(r, false)
	if err != nil {
		return err
	}
	pool, err := a.db(r.Context())
	if err != nil {
		return err
	}
	v, err := a.hookView(r.Context(), pool, key)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, v)
}

func (a *api) adminPutHook(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	key, err := a.hookKeyParam(r, true)
	if err != nil {
		return err
	}
	params := &HookSettingParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if params.Enabled == nil {
		return badRequestError(ErrorCodeValidationFailed, "enabled is required")
	}
	uri := strings.TrimSpace(params.URI)

	var view hookSettingView
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		secrets := []string{}
		if params.Secrets != nil {
			for _, s := range *params.Secrets {
				if s = strings.TrimSpace(s); s != "" {
					secrets = append(secrets, s)
				}
			}
		} else {
			cur, lerr := loadInstanceHook(ctx, tx, key)
			if lerr != nil {
				return internalServerError("Database error loading hook setting").withInternal(lerr)
			}
			if cur != nil {
				secrets = cur.Secrets
			}
		}
		if verr := a.validateHookSetting(ctx, key, *params.Enabled, uri, secrets); verr != nil {
			return verr
		}
		if _, eerr := tx.Exec(ctx, `
			insert into dilion_auth.hooks (name, enabled, uri, secrets, created_at, updated_at)
			values ($1, $2, $3, $4, $5, $5)
			on conflict (name) do update
			set enabled = excluded.enabled, uri = excluded.uri,
			    secrets = excluded.secrets, updated_at = excluded.updated_at`,
			key, *params.Enabled, uri, secrets, a.now()); eerr != nil {
			return internalServerError("Database error saving hook setting").withInternal(eerr)
		}
		v, verr := a.hookView(ctx, tx, key)
		view = v
		return verr
	}); err != nil {
		return err
	}
	a.emitAudit(r, auditOpts{Action: audit.ActionAuthHookChanged, Resource: "auth_hook:" + key})
	return sendJSON(w, http.StatusOK, view)
}

func (a *api) adminDeleteHook(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	key, err := a.hookKeyParam(r, true)
	if err != nil {
		return err
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	tag, err := pool.Exec(ctx, `delete from dilion_auth.hooks where name = $1`, key)
	if err != nil {
		return internalServerError("Database error deleting hook setting").withInternal(err)
	}
	if tag.RowsAffected() > 0 {
		a.emitAudit(r, auditOpts{Action: audit.ActionAuthHookChanged, Resource: "auth_hook:" + key})
	}
	v, err := a.hookView(ctx, pool, key)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, v)
}
