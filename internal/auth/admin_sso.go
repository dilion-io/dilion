package auth

// /admin/sso/providers — the SSO identity provider registry.
//
//	GET    /admin/sso/providers            -> {"items": [SSOProvider, ...]}
//	POST   /admin/sso/providers            -> SSOProvider (201)
//	GET    /admin/sso/providers/{idp_id}   -> SSOProvider
//	PUT    /admin/sso/providers/{idp_id}   -> SSOProvider
//	DELETE /admin/sso/providers/{idp_id}   -> SSOProvider (the deleted one)
//
// Reproduces github.com/supabase/auth/internal/api/ssoadmin.go
// (loadSSOProvider, adminSSOProvidersList/Create/Get/Update/Delete).
//
// {idp_id} is the provider's UUID, or "resource_<resource_id>" to address it by
// the operator-chosen resource id (upstream's `resource_` prefix convention for
// infrastructure-as-code).
//
// These routes are mounted from THIS file rather than from auth.go's core
// /admin group, so the SSO feature stays self-contained; chi resolves the
// parameterised paths registered here alongside /admin/users.
//
// Unlike the /sso surface these are NOT gated on Config.SAML.Enabled: an
// operator must be able to register providers before switching SAML on, exactly
// as upstream allows.

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("admin_sso", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin, a.requireAdminPermission(PermAuthSettingsManage))
			r.Get("/admin/sso/providers", a.handle(a.adminListSSOProviders))
			r.Post("/admin/sso/providers", a.handle(a.adminCreateSSOProvider))
			r.Get("/admin/sso/providers/{idp_id}", a.handle(a.adminGetSSOProvider))
			r.Put("/admin/sso/providers/{idp_id}", a.handle(a.adminUpdateSSOProvider))
			r.Delete("/admin/sso/providers/{idp_id}", a.handle(a.adminDeleteSSOProvider))
		})
	})
}

// ssoResourcePrefix is upstream's `resource_` prefix on {idp_id}.
const ssoResourcePrefix = "resource_"

// loadAdminSSOProvider is upstream's loadSSOProvider: {idp_id} is either a UUID
// or "resource_<resource_id>".
func (a *api) loadAdminSSOProvider(r *http.Request) (*SSOProvider, error) {
	ctx := r.Context()
	pool, perr := a.db(ctx)
	if perr != nil {
		return nil, perr
	}

	idpParam := chi.URLParam(r, "idp_id")

	var (
		provider *SSOProvider
		err      error
	)
	if strings.HasPrefix(idpParam, ssoResourcePrefix) {
		provider, err = findSSOProviderByResourceID(ctx, pool, strings.TrimPrefix(idpParam, ssoResourcePrefix))
	} else {
		if _, uerr := uuid.Parse(idpParam); uerr != nil {
			return nil, notFoundError(ErrorCodeSSOProviderNotFound, "SSO Identity Provider not found")
		}
		provider, err = findSSOProviderByID(ctx, pool, idpParam)
	}
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeSSOProviderNotFound, "SSO Identity Provider not found")
		}
		return nil, internalServerError("Database error finding SSO Identity Provider").withInternal(err)
	}
	return provider, nil
}

// ---- GET /admin/sso/providers ----------------------------------------------

// adminListSSOProviders is upstream's adminSSOProvidersList. There is no
// pagination upstream either; the filters are `resource_id` and
// `resource_id_prefix`.
func (a *api) adminListSSOProviders(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	q := r.URL.Query()
	providers, err := listSSOProviders(ctx, pool, q.Get("resource_id"), q.Get("resource_id_prefix"))
	if err != nil {
		return internalServerError("Database error loading SSO Identity Providers").withInternal(err)
	}
	for _, p := range providers {
		// Upstream blanks the metadata XML so the listing is not ginormous.
		p.SAMLProvider.MetadataXML = ""
	}

	return sendJSON(w, http.StatusOK, map[string]any{"items": providers})
}

// ---- POST/PUT bodies -------------------------------------------------------

// CreateSSOProviderParams is the POST and PUT /admin/sso/providers body
// (upstream api.CreateSSOProviderParams).
type CreateSSOProviderParams struct {
	Type string `json:"type"`

	MetadataURL      string               `json:"metadata_url"`
	MetadataXML      string               `json:"metadata_xml"`
	Domains          []string             `json:"domains"`
	AttributeMapping SAMLAttributeMapping `json:"attribute_mapping"`
	NameIDFormat     string               `json:"name_id_format"`

	ResourceID *string `json:"resource_id,omitempty"`
	Disabled   *bool   `json:"disabled,omitempty"`
}

// validate is upstream's CreateSSOProviderParams.validate. forUpdate relaxes the
// two rules that only apply to a create: the `type` discriminator and the
// requirement that metadata be present at all.
func (p *CreateSSOProviderParams) validate(forUpdate bool) error {
	switch {
	case !forUpdate && p.Type != SAMLProviderType:
		return badRequestError(ErrorCodeValidationFailed, "Only 'saml' supported for SSO provider type")
	case p.MetadataURL != "" && p.MetadataXML != "":
		return badRequestError(ErrorCodeValidationFailed, "Only one of metadata_xml or metadata_url needs to be set")
	case !forUpdate && p.MetadataURL == "" && p.MetadataXML == "":
		return badRequestError(ErrorCodeValidationFailed, "Either metadata_xml or metadata_url must be set")
	case p.MetadataURL != "":
		metadataURL, err := url.ParseRequestURI(p.MetadataURL)
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "metadata_url is not a valid URL")
		}
		// HTTPS only: the metadata document carries the certificate every
		// assertion is verified against, so fetching it over plaintext would
		// make the whole SAML trust chain forgeable in transit.
		if metadataURL.Scheme != "https" {
			return badRequestError(ErrorCodeValidationFailed, "metadata_url is not a HTTPS URL")
		}
	}

	switch p.NameIDFormat {
	case "", samlNameIDFormats[0], samlNameIDFormats[1], samlNameIDFormats[2], samlNameIDFormats[3]:
		// valid
	default:
		return badRequestError(ErrorCodeValidationFailed,
			"name_id_format must be unspecified or one of %v", strings.Join(samlNameIDFormats, ", "))
	}
	return nil
}

// metadata is upstream's CreateSSOProviderParams.metadata: the raw document
// (inline or fetched) plus its parsed form.
func (a *api) ssoParamsMetadata(r *http.Request, p *CreateSSOProviderParams) ([]byte, *saml.EntityDescriptor, error) {
	var raw []byte
	switch {
	case p.MetadataXML != "":
		raw = []byte(p.MetadataXML)
	case p.MetadataURL != "":
		fetched, err := a.fetchSAMLMetadata(r.Context(), p.MetadataURL)
		if err != nil {
			return nil, nil, err
		}
		raw = fetched
	default:
		// Impossible if validate() ran first.
		return nil, nil, nil
	}

	metadata, err := parseSAMLMetadata(raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, metadata, nil
}

// ---- POST /admin/sso/providers ---------------------------------------------

// adminCreateSSOProvider is upstream's adminSSOProvidersCreate.
func (a *api) adminCreateSSOProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &CreateSSOProviderParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if err := params.validate(false /* forUpdate */); err != nil {
		return err
	}

	raw, metadata, err := a.ssoParamsMetadata(r, params)
	if err != nil {
		return err
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	existing, err := findSSOProviderByEntityID(ctx, pool, metadata.EntityID)
	if err != nil && !isNoRows(err) {
		return internalServerError("Database error finding SSO Identity Provider").withInternal(err)
	}
	if existing != nil {
		return unprocessableEntityError(ErrorCodeSAMLIdPAlreadyExists,
			"SAML Identity Provider with this EntityID (%s) already exists", metadata.EntityID)
	}

	provider := &SSOProvider{
		ResourceID: params.ResourceID,
		Disabled:   params.Disabled,
		SAMLProvider: SAMLProvider{
			EntityID:         metadata.EntityID,
			MetadataXML:      string(raw),
			AttributeMapping: params.AttributeMapping,
		},
	}
	if params.MetadataURL != "" {
		provider.SAMLProvider.MetadataURL = &params.MetadataURL
	}
	if params.NameIDFormat != "" {
		provider.SAMLProvider.NameIDFormat = &params.NameIDFormat
	}

	for _, domain := range params.Domains {
		owner, derr := findSSOProviderByDomain(ctx, pool, domain)
		if derr != nil && !isNoRows(derr) {
			return internalServerError("Database error finding SSO domain").withInternal(derr)
		}
		if owner != nil {
			return badRequestError(ErrorCodeSSODomainAlreadyExists,
				"SSO Domain '%s' is already assigned to an SSO identity provider (%s)", domain, owner.ID)
		}
		provider.SSODomains = append(provider.SSODomains, SSODomain{Domain: domain})
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if terr := insertSSOProvider(ctx, tx, provider, now); terr != nil {
			if isUniqueViolation(terr) {
				return unprocessableEntityError(ErrorCodeConflict,
					"Creating SSO provider failed, likely due to a conflict. Try again?").withInternal(terr)
			}
			return internalServerError("Database error creating SSO Identity Provider").withInternal(terr)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusCreated, provider)
}

// ---- GET /admin/sso/providers/{idp_id} -------------------------------------

func (a *api) adminGetSSOProvider(w http.ResponseWriter, r *http.Request) error {
	provider, err := a.loadAdminSSOProvider(r)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, provider)
}

// ---- PUT /admin/sso/providers/{idp_id} -------------------------------------

// adminUpdateSSOProvider is upstream's adminSSOProvidersUpdate: a DIFF update.
// A field that is absent from the body is left alone; `domains` is only touched
// when the key is present (a nil slice means "do not modify", `[]` means "remove
// all").
func (a *api) adminUpdateSSOProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &CreateSSOProviderParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	if err := params.validate(true /* forUpdate */); err != nil {
		return err
	}

	provider, err := a.loadAdminSSOProvider(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	modified := false
	updateSAMLProvider := false

	if params.MetadataXML != "" || params.MetadataURL != "" {
		raw, metadata, merr := a.ssoParamsMetadata(r, params)
		if merr != nil {
			return merr
		}
		// The EntityID is the identity of the connection: changing it would
		// silently repoint every existing SSO account at a different IdP.
		if provider.SAMLProvider.EntityID != metadata.EntityID {
			return badRequestError(ErrorCodeSAMLEntityIDMismatch,
				"SAML Metadata can be updated only if the EntityID matches for the provider; expected '%s' but got '%s'",
				provider.SAMLProvider.EntityID, metadata.EntityID)
		}
		if params.MetadataURL != "" {
			provider.SAMLProvider.MetadataURL = &params.MetadataURL
		}
		provider.SAMLProvider.MetadataXML = string(raw)
		updateSAMLProvider = true
		modified = true
	}

	updateDomains := params.Domains != nil

	var createDomains, deleteDomains []SSODomain
	keepDomains := map[string]bool{}

	for _, domain := range params.Domains {
		owner, derr := findSSOProviderByDomain(ctx, pool, domain)
		if derr != nil && !isNoRows(derr) {
			return internalServerError("Database error finding SSO domain").withInternal(derr)
		}
		if owner != nil {
			if owner.ID != provider.ID {
				return badRequestError(ErrorCodeSSODomainAlreadyExists,
					"SSO domain '%s' already assigned to another provider (%s)", domain, owner.ID)
			}
			keepDomains[strings.ToLower(domain)] = true
			continue
		}
		modified = true
		createDomains = append(createDomains, SSODomain{Domain: domain, SSOProviderID: provider.ID})
	}

	if updateDomains {
		for i, domain := range provider.SSODomains {
			if !keepDomains[strings.ToLower(domain.Domain)] {
				modified = true
				deleteDomains = append(deleteDomains, provider.SSODomains[i])
			}
		}
	}

	updateAttributeMapping := false
	if params.AttributeMapping.Keys != nil {
		updateAttributeMapping = !provider.SAMLProvider.AttributeMapping.Equal(&params.AttributeMapping)
		if updateAttributeMapping {
			modified = true
			provider.SAMLProvider.AttributeMapping = params.AttributeMapping
		}
	}

	nameIDFormat := ""
	if provider.SAMLProvider.NameIDFormat != nil {
		nameIDFormat = *provider.SAMLProvider.NameIDFormat
	}
	if params.NameIDFormat != nameIDFormat {
		modified = true
		updateSAMLProvider = true
		if params.NameIDFormat == "" {
			provider.SAMLProvider.NameIDFormat = nil
		} else {
			format := params.NameIDFormat
			provider.SAMLProvider.NameIDFormat = &format
		}
	}

	if params.ResourceID != nil {
		resourceID := *params.ResourceID
		switch {
		case resourceID == "" && provider.ResourceID != nil:
			provider.ResourceID = nil
			modified = true
		case resourceID != "" && (provider.ResourceID == nil || *provider.ResourceID != resourceID):
			provider.ResourceID = &resourceID
			modified = true
		}
	}

	if params.Disabled != nil {
		disabled := *params.Disabled
		if provider.Disabled == nil || *provider.Disabled != disabled {
			provider.Disabled = &disabled
			modified = true
		}
	}

	if modified {
		now := a.now()
		if err := a.inTx(ctx, func(tx pgx.Tx) error {
			if terr := updateSSOProviderRow(ctx, tx, provider, now); terr != nil {
				return terr
			}
			if updateDomains {
				for _, d := range deleteDomains {
					if terr := deleteSSODomain(ctx, tx, d.ID); terr != nil {
						return terr
					}
				}
				for i := range createDomains {
					if terr := insertSSODomain(ctx, tx, provider.ID, &createDomains[i], now); terr != nil {
						return terr
					}
				}
			}
			if updateAttributeMapping || updateSAMLProvider {
				if terr := updateSAMLProviderRow(ctx, tx, &provider.SAMLProvider, now); terr != nil {
					return terr
				}
			}
			// Re-read so the response carries exactly what was persisted.
			fresh, terr := findSSOProviderByID(ctx, tx, provider.ID)
			if terr != nil {
				return terr
			}
			provider = fresh
			return nil
		}); err != nil {
			return unprocessableEntityError(ErrorCodeConflict,
				"Updating SSO provider failed, likely due to a conflict. Try again?").withInternal(err)
		}
	}

	return sendJSON(w, http.StatusOK, provider)
}

// ---- DELETE /admin/sso/providers/{idp_id} ----------------------------------

// adminDeleteSSOProvider is upstream's adminSSOProvidersDelete: the deleted
// provider is echoed back.
//
// Deleting a provider cascades to its SAML connection, its domains and its
// pending relay states (migration 0113). It does NOT delete the accounts that
// were created through it — those keep their `sso:<id>` identities and become
// unreachable until an identically-identified provider is registered again,
// which is upstream's behaviour.
func (a *api) adminDeleteSSOProvider(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	provider, err := a.loadAdminSSOProvider(r)
	if err != nil {
		return err
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if terr := deleteSSOProvider(ctx, tx, provider.ID); terr != nil {
			return internalServerError("Database error deleting SSO Identity Provider").withInternal(terr)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, provider)
}
