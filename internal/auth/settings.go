package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func init() {
	registerFeature("settings", func(a *api, r chi.Router) {
		// Unauthenticated on purpose: supabase-js reads /settings before any
		// credential exists, to decide which sign-in options to render.
		r.Get("/settings", a.handle(a.settings))
	})
}

// ProviderSettings is the `external` object of GET /settings. Field order and
// json tags are copied from upstream api.ProviderSettings — supabase-js reads
// these keys by name, so none of them may be renamed or dropped.
type ProviderSettings struct {
	AnonymousUsers bool `json:"anonymous_users"`
	Apple          bool `json:"apple"`
	Azure          bool `json:"azure"`
	Bitbucket      bool `json:"bitbucket"`
	Discord        bool `json:"discord"`
	Facebook       bool `json:"facebook"`
	Snapchat       bool `json:"snapchat"`
	Figma          bool `json:"figma"`
	Fly            bool `json:"fly"`
	GitHub         bool `json:"github"`
	GitLab         bool `json:"gitlab"`
	Google         bool `json:"google"`
	Keycloak       bool `json:"keycloak"`
	Kakao          bool `json:"kakao"`
	Linkedin       bool `json:"linkedin"`
	LinkedinOIDC   bool `json:"linkedin_oidc"`
	Notion         bool `json:"notion"`
	Spotify        bool `json:"spotify"`
	Slack          bool `json:"slack"`
	SlackOIDC      bool `json:"slack_oidc"`
	WorkOS         bool `json:"workos"`
	Twitch         bool `json:"twitch"`
	Twitter        bool `json:"twitter"`
	Email          bool `json:"email"`
	Phone          bool `json:"phone"`
	Zoom           bool `json:"zoom"`
}

// Settings is the GET /settings body (upstream api.Settings).
type Settings struct {
	ExternalProviders            ProviderSettings `json:"external"`
	DisableSignup                bool             `json:"disable_signup"`
	MailerAutoconfirm            bool             `json:"mailer_autoconfirm"`
	PhoneAutoconfirm             bool             `json:"phone_autoconfirm"`
	SmsProvider                  string           `json:"sms_provider"`
	SAMLEnabled                  bool             `json:"saml_enabled"`
	SAMLPrivateKeyNextConfigured bool             `json:"saml_private_key_next_configured"`
	PasskeysEnabled              bool             `json:"passkeys_enabled"`
}

// settings implements GET /settings: the public description of what this
// deployment allows. It reflects Config and nothing else, so a provider a
// feature agent enables in the configuration shows up here automatically.
func (a *api) settings(w http.ResponseWriter, _ *http.Request) error {
	c := a.cfg
	on := func(provider string) bool { return c.External[provider].Enabled }

	return sendJSON(w, http.StatusOK, &Settings{
		ExternalProviders: ProviderSettings{
			AnonymousUsers: c.AnonymousUsersEnabled,
			Apple:          on("apple"),
			Azure:          on("azure"),
			Bitbucket:      on("bitbucket"),
			Discord:        on("discord"),
			Facebook:       on("facebook"),
			Snapchat:       on("snapchat"),
			Figma:          on("figma"),
			Fly:            on("fly"),
			GitHub:         on("github"),
			GitLab:         on("gitlab"),
			Google:         on("google"),
			Keycloak:       on("keycloak"),
			Kakao:          on("kakao"),
			Linkedin:       on("linkedin"),
			LinkedinOIDC:   on("linkedin_oidc"),
			Notion:         on("notion"),
			Spotify:        on("spotify"),
			Slack:          on("slack"),
			SlackOIDC:      on("slack_oidc"),
			WorkOS:         on("workos"),
			Twitch:         on("twitch"),
			Twitter:        on("twitter"),
			Email:          on("email"),
			Phone:          on("phone"),
			Zoom:           on("zoom"),
		},
		DisableSignup:     c.DisableSignup,
		MailerAutoconfirm: c.Mailer.Autoconfirm,
		PhoneAutoconfirm:  c.SMS.Autoconfirm,
		SmsProvider:       c.SMS.Provider,
		SAMLEnabled:       c.SAML.Enabled,
		// Dilion has no SAML key rotation slot yet; upstream reports whether a
		// "next" private key is staged, which is always false here.
		SAMLPrivateKeyNextConfigured: false,
		PasskeysEnabled:              c.Passkeys.Enabled,
	})
}
