package auth

// Per-instance site settings: SiteURL and URIAllowList.
//
// Config is one value shared by every instance a mount serves. The two fields
// that name an instance's application — where its users are sent back to, and
// which other addresses may be — cannot be shared by a platform that serves
// one workspace per instance, so Deps.Settings (ports.AuthSettingsSource)
// supplies them per instance. siteMiddleware resolves them once per request
// and every read goes through a.site(ctx), which returns Config with those two
// fields replaced — or Config itself when the instance has none.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/dilion-io/dilion/ports"
)

type siteCtxKey struct{}

// siteEntry caches one instance's resolved Config with the settings it was
// built from, so a change in what the source returns rebuilds it.
type siteEntry struct {
	settings ports.AuthSettings
	cfg      *Config
}

// siteMiddleware resolves the request's instance settings before any handler
// runs, so a failing source fails the request up front instead of halfway
// through building an email or a redirect.
func (a *api) siteMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.siteSource == nil {
			next.ServeHTTP(w, r)
			return
		}
		cfg, err := a.resolveSite(r.Context())
		if err != nil {
			a.writeError(r, w, internalServerError("Error loading instance auth settings").withInternal(err))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), siteCtxKey{}, cfg)))
	})
}

// site is the configuration whose SiteURL and URIAllowList apply to the
// request's instance. Only those two fields differ from a.cfg.
func (a *api) site(ctx context.Context) *Config {
	if cfg, ok := ctx.Value(siteCtxKey{}).(*Config); ok {
		return cfg
	}
	return a.cfg
}

func (a *api) resolveSite(ctx context.Context) (*Config, error) {
	instanceID := ports.InstanceFromContext(ctx)
	s, err := a.siteSource(ctx, instanceID)
	if err != nil || s == nil {
		return a.cfg, err
	}
	if v, ok := a.siteCache.Load(instanceID); ok {
		e := v.(siteEntry)
		if e.settings.SiteURL == s.SiteURL && slices.Equal(e.settings.URIAllowList, s.URIAllowList) &&
			(e.settings.URIAllowList == nil) == (s.URIAllowList == nil) {
			return e.cfg, nil
		}
	}
	cfg, err := a.cfg.withSite(*s)
	if err != nil {
		return nil, fmt.Errorf("instance %q: %w", instanceID, err)
	}
	a.siteCache.Store(instanceID, siteEntry{
		settings: ports.AuthSettings{SiteURL: s.SiteURL, URIAllowList: slices.Clone(s.URIAllowList)},
		cfg:      cfg,
	})
	return cfg, nil
}

// withSite returns a copy of c with s applied. The copy shares everything
// else with c, which is read-only.
func (c *Config) withSite(s ports.AuthSettings) (*Config, error) {
	out := *c
	if s.SiteURL != "" {
		u, err := url.Parse(s.SiteURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("auth: SiteURL %q is not an absolute URL", s.SiteURL)
		}
		out.SiteURL = s.SiteURL
	}
	if s.URIAllowList != nil {
		out.URIAllowList = slices.Clone(s.URIAllowList)
		// compile appends to allowGlobs[:0]; left shared, it would overwrite
		// the server's own matchers.
		out.allowGlobs = nil
		if err := out.compile(); err != nil {
			return nil, err
		}
	}
	return &out, nil
}
