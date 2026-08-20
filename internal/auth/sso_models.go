package auth

// The SSO / SAML 2.0 data model and its storage.
//
// Reproduces github.com/supabase/auth/internal/models/sso.go (SSOProvider,
// SAMLProvider, SSODomain, SAMLAttributeMapping, SAMLRelayState and their
// finders) on top of migration 0113_auth_sso_saml.sql.
//
// The JSON tags are the compatibility contract of GET/POST/PUT
// /admin/sso/providers — supabase-js and the Supabase CLI decode exactly these
// names, so do not rename them.
//
//	{
//	  "id": "<uuid>",
//	  "resource_id": "...",            (omitted when unset)
//	  "disabled": null|true|false,
//	  "saml": {
//	     "entity_id": "...",
//	     "metadata_xml": "...",        (omitted when blanked for a listing)
//	     "metadata_url": "...",        (omitted when unset)
//	     "attribute_mapping": {"keys": {...}},
//	     "name_id_format": "..."       (omitted when unset)
//	  },
//	  "domains": [{"domain": "example.com"}, ...],
//	  "created_at": "...", "updated_at": "..."
//	}

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---- error codes (upstream apierrors/errorcode.go) -------------------------

const (
	// ErrorCodeSAMLProviderDisabled is any /sso route while
	// GOTRUE_SAML_ENABLED is false (404 upstream, not 403).
	ErrorCodeSAMLProviderDisabled = "saml_provider_disabled"
	// ErrorCodeSAMLRelayStateNotFound is a RelayState UUID that names no row.
	ErrorCodeSAMLRelayStateNotFound = "saml_relay_state_not_found"
	// ErrorCodeSAMLRelayStateExpired is a RelayState older than
	// DefaultSAMLRelayStateValidityPeriod.
	ErrorCodeSAMLRelayStateExpired = "saml_relay_state_expired"
	// ErrorCodeSAMLIdPNotFound is an assertion from an EntityID no provider
	// has been registered for.
	ErrorCodeSAMLIdPNotFound = "saml_idp_not_found"
	// ErrorCodeSAMLAssertionNoUserID is an assertion without a persistent
	// subject identifier.
	ErrorCodeSAMLAssertionNoUserID = "saml_assertion_no_user_id"
	// ErrorCodeSAMLAssertionNoEmail is an assertion that carries no email
	// address, neither mapped nor guessed.
	ErrorCodeSAMLAssertionNoEmail = "saml_assertion_no_email"
	// ErrorCodeSSOProviderNotFound is POST /sso (or an admin route) naming an
	// SSO provider that does not exist.
	ErrorCodeSSOProviderNotFound = "sso_provider_not_found"
	// ErrorCodeSSOProviderDisabled is a provider whose `disabled` column is
	// true. Upstream answers 404, deliberately: a disabled provider must look
	// exactly like an absent one to an unauthenticated caller.
	ErrorCodeSSOProviderDisabled = "sso_provider_disabled"
	// ErrorCodeSAMLMetadataFetchFailed is a non-200 answer from metadata_url.
	ErrorCodeSAMLMetadataFetchFailed = "saml_metadata_fetch_failed"
	// ErrorCodeSAMLIdPAlreadyExists is a create whose metadata EntityID is
	// already registered.
	ErrorCodeSAMLIdPAlreadyExists = "saml_idp_already_exists"
	// ErrorCodeSSODomainAlreadyExists is a domain already assigned to another
	// provider.
	ErrorCodeSSODomainAlreadyExists = "sso_domain_already_exists"
	// ErrorCodeSAMLEntityIDMismatch is a metadata update that would change the
	// provider's EntityID.
	ErrorCodeSAMLEntityIDMismatch = "saml_entity_id_mismatch"
)

// ---- upstream defaults that Config does not carry --------------------------

// Config.SAML only carries {Enabled, PrivateKey} (conf.go, which this feature
// must not extend), so the remaining upstream knobs are compiled in at their
// upstream default. Each one is an operator-visible value; if they ever need to
// become configurable, they belong on conf.SAMLConfiguration next to
// Enabled/PrivateKey, spelled GOTRUE_SAML_*.
const (
	// DefaultSAMLRelayStateValidityPeriod mirrors
	// GOTRUE_SAML_RELAY_STATE_VALIDITY_PERIOD (upstream default 2 minutes,
	// set in conf.SAMLConfiguration.parseCertificateDer): the window in which
	// an IdP must post its assertion back after /sso started the flow.
	DefaultSAMLRelayStateValidityPeriod = 2 * time.Minute

	// samlMetadataForceRefresh mirrors upstream's IsSAMLMetadataStale fallback:
	// metadata that publishes neither validUntil nor cacheDuration is re-fetched
	// from metadata_url once a day.
	samlMetadataForceRefresh = 24 * time.Hour

	// samlMetadataExpiryWarning mirrors upstream's "(30*24*60) seconds" warning
	// threshold for static metadata_xml — 30 days, written the same way upstream
	// writes it (see samlacs.go).
	samlMetadataExpiryWarning = (30 * 24 * 60) * time.Second
)

// authMethodSSOSAML is flow_state.authentication_method / the `amr` method of a
// session issued by SAML (upstream models.SSOSAML.String()).
const authMethodSSOSAML = "sso/saml"

// amrSSOSAML is the `amr` method recorded on a session issued from a SAML
// assertion. Same string as the authentication method, as upstream.
const amrSSOSAML = authMethodSSOSAML

// SAMLProviderType is the only `type` POST /admin/sso/providers accepts
// (upstream api.SAMLProvider).
const SAMLProviderType = "saml"

// ssoProviderPrefix is the prefix of the identity provider name of an SSO
// account: an SSO identity's `provider` is "sso:<sso_provider_id>", which also
// makes each SSO provider its own account-linking domain
// (upstream models.GetAccountLinkingDomain).
const ssoProviderPrefix = "sso:"

// ssoProviderName returns the auth.identities.provider value of an SSO provider.
func ssoProviderName(ssoProviderID string) string { return ssoProviderPrefix + ssoProviderID }

// ---- models ----------------------------------------------------------------

// SAMLAttribute is one entry of a provider's attribute_mapping
// (upstream models.SAMLAttribute).
type SAMLAttribute struct {
	// Name is the primary SAML attribute Name (or FriendlyName) to read.
	Name string `json:"name,omitempty"`
	// Names are further attribute names, tried in order after Name.
	Names []string `json:"names,omitempty"`
	// Default is used when none of the names produced a value.
	Default any `json:"default,omitempty"`
	// Array collects EVERY value of the first matching attribute instead of
	// just the first one.
	Array bool `json:"array,omitempty"`
}

// SAMLAttributeMapping maps claim keys to SAML attributes
// (upstream models.SAMLAttributeMapping).
type SAMLAttributeMapping struct {
	Keys map[string]SAMLAttribute `json:"keys,omitempty"`
}

// Equal is upstream's SAMLAttributeMapping.Equal, used by the admin update to
// decide whether the mapping actually changed.
func (m *SAMLAttributeMapping) Equal(o *SAMLAttributeMapping) bool {
	if m == o {
		return true
	}
	if m == nil || o == nil {
		return false
	}
	if m.Keys == nil && o.Keys == nil {
		return true
	}
	if len(m.Keys) != len(o.Keys) {
		return false
	}
	for key, mine := range m.Keys {
		theirs, ok := o.Keys[key]
		if !ok {
			return false
		}
		if mine.Name != theirs.Name || len(mine.Names) != len(theirs.Names) || mine.Array != theirs.Array {
			return false
		}
		for i := range mine.Names {
			if mine.Names[i] != theirs.Names[i] {
				return false
			}
		}
		// Defaults arrive as decoded JSON on both sides, so a value comparison
		// through their JSON encoding is exact and avoids reflect.DeepEqual's
		// int/float64 surprises.
		if !jsonEqual(mine.Default, theirs.Default) {
			return false
		}
	}
	return true
}

func jsonEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	if aerr != nil || berr != nil {
		return false
	}
	return string(ab) == string(bb)
}

// SAMLProvider is one auth.saml_providers row (upstream models.SAMLProvider).
type SAMLProvider struct {
	ID            string `json:"-"`
	SSOProviderID string `json:"-"`

	EntityID    string  `json:"entity_id"`
	MetadataXML string  `json:"metadata_xml,omitempty"`
	MetadataURL *string `json:"metadata_url,omitempty"`

	AttributeMapping SAMLAttributeMapping `json:"attribute_mapping,omitempty"`

	NameIDFormat *string `json:"name_id_format,omitempty"`

	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

// SSODomain is one auth.sso_domains row (upstream models.SSODomain).
type SSODomain struct {
	ID            string `json:"-"`
	SSOProviderID string `json:"-"`

	Domain string `json:"domain"`

	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

// SSOProvider is one auth.sso_providers row plus its SAML connection and the
// email domains routed to it (upstream models.SSOProvider).
type SSOProvider struct {
	ID           string       `json:"id"`
	ResourceID   *string      `json:"resource_id,omitempty"`
	Disabled     *bool        `json:"disabled"`
	SAMLProvider SAMLProvider `json:"saml,omitempty"`
	SSODomains   []SSODomain  `json:"domains"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsEnabled is upstream's SSOProvider.IsEnabled: NULL means enabled, so a row
// written before the `disabled` column existed keeps working.
func (p *SSOProvider) IsEnabled() bool {
	return p == nil || p.Disabled == nil || !*p.Disabled
}

// samlRelayState is one auth.saml_relay_states row
// (upstream models.SAMLRelayState). It is server-side state only and never
// serialized to a client.
type samlRelayState struct {
	ID            string
	SSOProviderID string
	RequestID     string
	ForEmail      *string
	RedirectTo    string
	FlowStateID   *string
	CreatedAt     time.Time
}

// IsExpired reports whether the relay state is past its validity period
// (upstream: time.Since(relayState.CreatedAt) >= RelayStateValidityPeriod).
func (s *samlRelayState) IsExpired(now time.Time, validity time.Duration) bool {
	return now.Sub(s.CreatedAt) >= validity
}

// ---- storage: sso providers ------------------------------------------------

const ssoProviderColumns = `p.id::text, p.resource_id, p.disabled, p.created_at, p.updated_at,
	s.id::text, s.entity_id, s.metadata_xml, s.metadata_url,
	coalesce(s.attribute_mapping, '{}'::jsonb), s.name_id_format, s.created_at, s.updated_at`

const ssoProviderFrom = ` from auth.sso_providers p
	join auth.saml_providers s on s.sso_provider_id = p.id `

func scanSSOProvider(row pgx.Row) (*SSOProvider, error) {
	var (
		p                              SSOProvider
		createdAt, updatedAt           *time.Time
		samlCreatedAt, samlUpdatedAt   *time.Time
		attributeMapping               []byte
		metadataURL, nameIDFormat, rid *string
	)
	err := row.Scan(&p.ID, &rid, &p.Disabled, &createdAt, &updatedAt,
		&p.SAMLProvider.ID, &p.SAMLProvider.EntityID, &p.SAMLProvider.MetadataXML, &metadataURL,
		&attributeMapping, &nameIDFormat, &samlCreatedAt, &samlUpdatedAt)
	if err != nil {
		return nil, err
	}
	p.ResourceID = rid
	p.SAMLProvider.SSOProviderID = p.ID
	p.SAMLProvider.MetadataURL = metadataURL
	p.SAMLProvider.NameIDFormat = nameIDFormat
	if len(attributeMapping) > 0 {
		if err := json.Unmarshal(attributeMapping, &p.SAMLProvider.AttributeMapping); err != nil {
			return nil, err
		}
	}
	if createdAt != nil {
		p.CreatedAt = createdAt.UTC()
	}
	if updatedAt != nil {
		p.UpdatedAt = updatedAt.UTC()
	}
	if samlCreatedAt != nil {
		p.SAMLProvider.CreatedAt = samlCreatedAt.UTC()
	}
	if samlUpdatedAt != nil {
		p.SAMLProvider.UpdatedAt = samlUpdatedAt.UTC()
	}
	p.SSODomains = []SSODomain{}
	return &p, nil
}

// loadSSODomains fills in the provider's domains, in creation order.
func loadSSODomains(ctx context.Context, q querier, p *SSOProvider) error {
	rows, err := q.Query(ctx, `
		select id::text, domain, created_at, updated_at
		from auth.sso_domains where sso_provider_id = $1::uuid
		order by created_at, id`, p.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	p.SSODomains = []SSODomain{}
	for rows.Next() {
		var (
			d                    SSODomain
			createdAt, updatedAt *time.Time
		)
		if err := rows.Scan(&d.ID, &d.Domain, &createdAt, &updatedAt); err != nil {
			return err
		}
		d.SSOProviderID = p.ID
		if createdAt != nil {
			d.CreatedAt = createdAt.UTC()
		}
		if updatedAt != nil {
			d.UpdatedAt = updatedAt.UTC()
		}
		p.SSODomains = append(p.SSODomains, d)
	}
	return rows.Err()
}

// findSSOProviderByID is upstream's models.FindSSOProviderByID.
func findSSOProviderByID(ctx context.Context, q querier, id string) (*SSOProvider, error) {
	p, err := scanSSOProvider(q.QueryRow(ctx,
		`select `+ssoProviderColumns+ssoProviderFrom+`where p.id = $1::uuid`, id))
	if err != nil {
		return nil, err
	}
	return p, loadSSODomains(ctx, q, p)
}

// findSSOProviderByResourceID is upstream's
// models.FindSSOProviderByResourceID. The unique index is on lower(resource_id),
// so the lookup is case-insensitive too.
func findSSOProviderByResourceID(ctx context.Context, q querier, resourceID string) (*SSOProvider, error) {
	p, err := scanSSOProvider(q.QueryRow(ctx,
		`select `+ssoProviderColumns+ssoProviderFrom+`where lower(p.resource_id) = lower($1)`, resourceID))
	if err != nil {
		return nil, err
	}
	return p, loadSSODomains(ctx, q, p)
}

// findSSOProviderByDomain is upstream's models.FindSSOProviderByDomain. The
// unique index is on lower(domain) (migration 0113), so the match is
// case-insensitive — an operator who registered "Example.com" still answers
// "example.com".
func findSSOProviderByDomain(ctx context.Context, q querier, domain string) (*SSOProvider, error) {
	p, err := scanSSOProvider(q.QueryRow(ctx, `select `+ssoProviderColumns+ssoProviderFrom+`
		join auth.sso_domains d on d.sso_provider_id = p.id
		where lower(d.domain) = lower($1)`, strings.TrimSpace(domain)))
	if err != nil {
		return nil, err
	}
	return p, loadSSODomains(ctx, q, p)
}

// findSSOProviderByEntityID is upstream's models.FindSAMLProviderByEntityID: the
// SSO provider that owns a SAML EntityID.
func findSSOProviderByEntityID(ctx context.Context, q querier, entityID string) (*SSOProvider, error) {
	p, err := scanSSOProvider(q.QueryRow(ctx,
		`select `+ssoProviderColumns+ssoProviderFrom+`where s.entity_id = $1`, entityID))
	if err != nil {
		return nil, err
	}
	return p, loadSSODomains(ctx, q, p)
}

// listSSOProviders is upstream's models.FindAllSSOProvidersByFilter: an exact
// `resource_id` filter, otherwise a `resource_id_prefix` one, otherwise all.
func listSSOProviders(ctx context.Context, q querier, resourceID, resourcePrefix string) ([]*SSOProvider, error) {
	sql := `select ` + ssoProviderColumns + ssoProviderFrom
	args := []any{}
	switch {
	case resourceID != "":
		sql += `where p.resource_id = $1 `
		args = append(args, resourceID)
	case resourcePrefix != "":
		// Upstream's `resource_id LIKE <prefix>%`, reproduced verbatim — which
		// means a `%` or `_` inside the prefix is a LIKE wildcard there too.
		// This is an admin-only filter, so the looser match is harmless.
		sql += `where p.resource_id like $1 || '%' `
		args = append(args, resourcePrefix)
	}
	sql += `order by p.created_at, p.id`

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	out := []*SSOProvider{}
	for rows.Next() {
		p, err := scanSSOProvider(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, p := range out {
		if err := loadSSODomains(ctx, q, p); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// insertSSOProvider writes a provider, its SAML connection and its domains.
// Must run inside the caller's transaction.
func insertSSOProvider(ctx context.Context, tx querier, p *SSOProvider, now time.Time) error {
	p.ID = uuid.NewString()
	p.CreatedAt = now
	p.UpdatedAt = now

	if _, err := tx.Exec(ctx, `
		insert into auth.sso_providers (id, resource_id, disabled, created_at, updated_at)
		values ($1::uuid, $2, $3, $4, $4)`,
		p.ID, p.ResourceID, p.Disabled, now); err != nil {
		return err
	}

	mapping, err := json.Marshal(p.SAMLProvider.AttributeMapping)
	if err != nil {
		return err
	}
	p.SAMLProvider.ID = uuid.NewString()
	p.SAMLProvider.SSOProviderID = p.ID
	p.SAMLProvider.CreatedAt = now
	p.SAMLProvider.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
		insert into auth.saml_providers
			(id, sso_provider_id, entity_id, metadata_xml, metadata_url,
			 attribute_mapping, name_id_format, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7, $8, $8)`,
		p.SAMLProvider.ID, p.ID, p.SAMLProvider.EntityID, p.SAMLProvider.MetadataXML,
		p.SAMLProvider.MetadataURL, mapping, p.SAMLProvider.NameIDFormat, now); err != nil {
		return err
	}

	for i := range p.SSODomains {
		if err := insertSSODomain(ctx, tx, p.ID, &p.SSODomains[i], now); err != nil {
			return err
		}
	}
	return nil
}

func insertSSODomain(ctx context.Context, tx querier, providerID string, d *SSODomain, now time.Time) error {
	d.ID = uuid.NewString()
	d.SSOProviderID = providerID
	d.CreatedAt = now
	d.UpdatedAt = now
	_, err := tx.Exec(ctx, `
		insert into auth.sso_domains (id, sso_provider_id, domain, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3, $4, $4)`, d.ID, providerID, d.Domain, now)
	return err
}

func deleteSSODomain(ctx context.Context, tx querier, id string) error {
	_, err := tx.Exec(ctx, `delete from auth.sso_domains where id = $1::uuid`, id)
	return err
}

// updateSSOProviderRow persists resource_id / disabled.
func updateSSOProviderRow(ctx context.Context, tx querier, p *SSOProvider, now time.Time) error {
	_, err := tx.Exec(ctx, `
		update auth.sso_providers set resource_id = $2, disabled = $3, updated_at = $4
		where id = $1::uuid`, p.ID, p.ResourceID, p.Disabled, now)
	if err == nil {
		p.UpdatedAt = now
	}
	return err
}

// updateSAMLProviderRow persists the SAML half of a provider.
func updateSAMLProviderRow(ctx context.Context, tx querier, s *SAMLProvider, now time.Time) error {
	mapping, err := json.Marshal(s.AttributeMapping)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		update auth.saml_providers set
			metadata_xml = $2, metadata_url = $3, attribute_mapping = $4::jsonb,
			name_id_format = $5, updated_at = $6
		where id = $1::uuid`,
		s.ID, s.MetadataXML, s.MetadataURL, mapping, s.NameIDFormat, now)
	if err == nil {
		s.UpdatedAt = now
	}
	return err
}

// refreshSAMLMetadataXML persists a metadata document re-fetched from
// metadata_url during an ACS call (upstream's UpdateColumns("metadata_xml",
// "updated_at")). updated_at is what IsSAMLMetadataStale measures against, so it
// must move with the document.
func refreshSAMLMetadataXML(ctx context.Context, q querier, samlProviderID, metadataXML string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.saml_providers set metadata_xml = $2, updated_at = $3 where id = $1::uuid`,
		samlProviderID, metadataXML, now)
	return err
}

func deleteSSOProvider(ctx context.Context, tx querier, id string) error {
	// auth.saml_providers, auth.sso_domains and auth.saml_relay_states all
	// cascade off auth.sso_providers (migration 0113).
	_, err := tx.Exec(ctx, `delete from auth.sso_providers where id = $1::uuid`, id)
	return err
}

// ---- storage: relay states -------------------------------------------------

const samlRelayStateColumns = `id::text, sso_provider_id::text, request_id, for_email,
	coalesce(redirect_to, ''), flow_state_id::text, created_at`

func scanSAMLRelayState(row pgx.Row) (*samlRelayState, error) {
	var (
		s         samlRelayState
		createdAt *time.Time
	)
	if err := row.Scan(&s.ID, &s.SSOProviderID, &s.RequestID, &s.ForEmail,
		&s.RedirectTo, &s.FlowStateID, &createdAt); err != nil {
		return nil, err
	}
	if createdAt != nil {
		s.CreatedAt = createdAt.UTC()
	}
	return &s, nil
}

// insertSAMLRelayState records the SP-initiated request the IdP will answer.
// The row IS the CSRF/replay defence of the flow: its id is the RelayState the
// IdP echoes back, it names the only AuthnRequest id the assertion may respond
// to, and it is destroyed the moment it is used.
func insertSAMLRelayState(ctx context.Context, q querier, s *samlRelayState, now time.Time) error {
	s.ID = uuid.NewString()
	s.CreatedAt = now
	_, err := q.Exec(ctx, `
		insert into auth.saml_relay_states
			(id, sso_provider_id, request_id, for_email, redirect_to, flow_state_id, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3, $4, nullif($5, ''), $6::uuid, $7, $7)`,
		s.ID, s.SSOProviderID, s.RequestID, s.ForEmail, s.RedirectTo, s.FlowStateID, now)
	return err
}

func findSAMLRelayStateByID(ctx context.Context, q querier, id string) (*samlRelayState, error) {
	return scanSAMLRelayState(q.QueryRow(ctx,
		`select `+samlRelayStateColumns+` from auth.saml_relay_states where id = $1::uuid`, id))
}

// deleteSAMLRelayState is upstream's samlDestroyRelayState. Deleting the row
// cascades to nothing; the flow state it points at is destroyed separately.
func deleteSAMLRelayState(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.saml_relay_states where id = $1::uuid`, id)
	return err
}

// ---- storage: SSO users ----------------------------------------------------

// insertSSOUser creates an account owned by an SSO identity provider.
//
// It is store.go's insertUser with is_sso_user = TRUE, which is what releases
// the users_email_partial_key unique index (migration 0100: unique on email
// WHERE is_sso_user = false). Two different SAML providers may legitimately
// assert the same address for two different people, and neither may collide
// with a local password account of the same address.
func insertSSOUser(ctx context.Context, q querier, p newUserParams) (*User, error) {
	return scanUser(q.QueryRow(ctx, `
		insert into auth.users (
			instance_id, id, aud, role, email, phone, encrypted_password,
			email_confirmed_at, phone_confirmed_at,
			raw_app_meta_data, raw_user_meta_data,
			created_at, updated_at,
			is_sso_user, is_anonymous, is_super_admin,
			confirmation_token, recovery_token,
			email_change_token_new, email_change_token_current, email_change,
			phone_change_token, phone_change, reauthentication_token,
			email_change_confirm_status
		) values (
			$1::uuid, $2::uuid, $3, $4, nullif($5, ''), nullif($6, ''), $7,
			$8, $9,
			$10, $11,
			$12, $12,
			true, false, false,
			'', '',
			'', '', '',
			'', '', '',
			0
		)
		returning `+userColumns,
		nilUUID, p.ID, p.Aud, p.Role, p.Email, p.Phone, p.EncryptedPassword,
		p.EmailConfirmedAt, p.PhoneConfirmedAt,
		p.AppMetaData, p.UserMetaData,
		p.Now))
}

// findSSOIdentitiesByEmails returns the identities of ONE SSO provider whose
// identity_data email matches one of the (already lowercased) addresses.
//
// It is the SSO half of upstream's DetermineAccountLinking: because
// GetAccountLinkingDomain maps an "sso:<uuid>" provider to a linking domain of
// its own, an SSO assertion may only ever join an account that already holds an
// identity from the SAME provider. It must never reach a password account or an
// account from a different IdP that happens to share the address.
func findSSOIdentitiesByEmails(ctx context.Context, q querier, provider string, emails []string) ([]Identity, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		select `+identityColumns+` from auth.identities
		where provider = $1 and email = any($2::text[])
		order by created_at, id`, provider, emails)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Identity{}
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// setSessionNotAfter stamps the assertion's SessionNotOnOrAfter on the session
// that was just created (upstream GrantParams.SessionNotAfter). The session is
// located through the refresh token grantSession returned, which is the only
// handle the caller gets back.
func setSessionNotAfterForRefreshToken(ctx context.Context, q querier, refreshToken string, notAfter time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.sessions set not_after = $2, updated_at = now()
		where id = (select session_id from auth.refresh_tokens where token = $1)`,
		refreshToken, notAfter)
	return err
}
