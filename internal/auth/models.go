package auth

import (
	"time"
)

// JSONMap mirrors gotrue's models.JSONMap (raw_app_meta_data / raw_user_meta_data).
type JSONMap map[string]any

// User is the gotrue user representation. Field ORDER and json tags (including
// `omitempty`) are copied from github.com/supabase/auth/internal/models.User so
// the serialized body is byte-comparable with upstream.
//
// Fields tagged `json:"-"` are DB-only and never leave the server.
type User struct {
	ID string `json:"id"`

	Aud       string `json:"aud"`
	Role      string `json:"role"`
	Email     string `json:"email"`
	IsSSOUser bool   `json:"-"`

	EncryptedPassword *string    `json:"-"`
	EmailConfirmedAt  *time.Time `json:"email_confirmed_at,omitempty"`
	InvitedAt         *time.Time `json:"invited_at,omitempty"`

	Phone            string     `json:"phone"`
	PhoneConfirmedAt *time.Time `json:"phone_confirmed_at,omitempty"`

	ConfirmationSentAt *time.Time `json:"confirmation_sent_at,omitempty"`

	// ConfirmedAt is a generated column (least(email_confirmed_at, phone_confirmed_at));
	// kept for backward compatibility with older clients.
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`

	RecoverySentAt *time.Time `json:"recovery_sent_at,omitempty"`

	EmailChange       string     `json:"new_email,omitempty"`
	EmailChangeSentAt *time.Time `json:"email_change_sent_at,omitempty"`

	PhoneChange       string     `json:"new_phone,omitempty"`
	PhoneChangeSentAt *time.Time `json:"phone_change_sent_at,omitempty"`

	ReauthenticationSentAt *time.Time `json:"reauthentication_sent_at,omitempty"`

	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty"`

	AppMetaData  JSONMap `json:"app_metadata"`
	UserMetaData JSONMap `json:"user_metadata"`

	// Factors is populated by loadFactors (mfa_models.go) on user-facing reads;
	// omitted from the body, exactly as upstream does for users without factors.
	Factors    []any      `json:"factors,omitempty"`
	Identities []Identity `json:"identities"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	BannedUntil *time.Time `json:"banned_until,omitempty"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	IsAnonymous bool       `json:"is_anonymous"`
}

// Identity is gotrue's models.Identity. Note the deliberately crossed json tags:
// the DB primary key `id` is exposed as `identity_id`, and `provider_id` as `id`
// — required for compatibility with gotrue-js's Identity type.
type Identity struct {
	ID           string     `json:"identity_id"`
	ProviderID   string     `json:"id"`
	UserID       string     `json:"user_id"`
	IdentityData JSONMap    `json:"identity_data,omitempty"`
	Provider     string     `json:"provider"`
	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Email        string     `json:"email,omitempty"`
}

// IsBanned reports whether banned_until is in the future.
func (u *User) IsBanned(now time.Time) bool {
	return u.BannedUntil != nil && u.BannedUntil.After(now)
}

// AccessTokenResponse is gotrue's session envelope, returned by /token and by
// /signup when confirmation is disabled.
type AccessTokenResponse struct {
	Token        string `json:"access_token"`
	TokenType    string `json:"token_type"` // always "bearer"
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
	User         *User  `json:"user"`
	// Provider tokens ride the PKCE exchange after an external OAuth flow
	// (upstream parity); empty otherwise.
	ProviderToken        string `json:"provider_token,omitempty"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty"`
}

// AdminListUsersResponse is the GET /admin/users body. `aud` is deprecated
// upstream but still emitted.
type AdminListUsersResponse struct {
	Users []*User `json:"users"`
	Aud   string  `json:"aud"`
}

// HealthCheckResponse is the GET /health body.
type HealthCheckResponse struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// session is the internal representation of an auth.sessions row.
type session struct {
	ID          string
	UserID      string
	NotAfter    *time.Time
	CreatedAt   time.Time
	RefreshedAt *time.Time
}

// lastRefreshedAt is upstream's models.Session.LastRefreshedAt: the most recent
// evidence that the session is alive — the later of sessions.refreshed_at, the
// presented refresh token's updated_at, and (as a floor) sessions.created_at.
func (s *session) lastRefreshedAt(rt *refreshToken) time.Time {
	last := s.CreatedAt
	if s.RefreshedAt != nil && s.RefreshedAt.After(last) {
		last = *s.RefreshedAt
	}
	if rt != nil && rt.UpdatedAt.After(last) {
		last = rt.UpdatedAt
	}
	return last
}

// refreshToken is the internal representation of an auth.refresh_tokens row.
type refreshToken struct {
	ID        int64
	Token     string
	UserID    string
	Parent    string
	SessionID *string
	Revoked   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
