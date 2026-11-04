package auth

// GET /sso/saml/metadata — this deployment's SP metadata document.
// POST /sso/saml/acs    — the Assertion Consumer Service.
//
// Reproduces github.com/supabase/auth/internal/api/samlacs.go (SamlAcs,
// handleSamlAcs, IsSAMLMetadataStale), samlassertion.go (SAMLAssertion and its
// attribute mapping) and the SAMLMetadata half of saml.go.
//
// Everything that can go wrong here is answered with a REDIRECT carrying the
// OAuth error triple, never with a JSON body: the caller is a browser posting a
// form from the IdP, not an API client. That is upstream's behaviour too.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

// ---- GET /sso/saml/metadata ------------------------------------------------

// samlMetadata serves the SP EntityDescriptor (upstream API.SAMLMetadata).
//
// The document is what an operator uploads to their Identity Provider, so its
// contents are a compatibility contract: the EntityID, the ACS location and the
// signing certificate must not drift between gotrue and Dilion for the same
// SITE_URL/key pair.
func (a *api) samlMetadata(w http.ResponseWriter, r *http.Request) error {
	// idpInitiated=true here only because the SP is built without IdP metadata;
	// it has no effect on the document.
	sp, err := a.newSAMLServiceProvider(r.Context(), nil, true)
	if err != nil {
		return err
	}
	metadata := sp.Metadata()

	download := r.FormValue("download") == "true"
	if download {
		// 5 year expiration, comparable to what GSuite does (upstream).
		metadata.ValidUntil = a.now().AddDate(5, 0, 0)
	}

	for i := range metadata.SPSSODescriptors {
		spd := &metadata.SPSSODescriptors[i]

		// The IdP-initiated flow can only sign the Assertion and not the whole
		// Response, so the SP must not advertise that it signs its requests —
		// crewjam/saml hardcodes the attribute otherwise.
		spd.AuthnRequestsSigned = nil

		// Advertise the NameID formats Dilion actually accepts.
		spd.NameIDFormats = []saml.NameIDFormat{
			saml.EmailAddressNameIDFormat,
			saml.PersistentNameIDFormat,
		}

		// Dilion does not implement encrypted assertions (upstream gates them
		// behind GOTRUE_SAML_ALLOW_ENCRYPTED_ASSERTIONS, which Config does not
		// carry), so only the signing key is published. Advertising an
		// encryption key we cannot use would make IdPs send assertions this
		// server is unable to decrypt.
		var keyDescriptors []saml.KeyDescriptor
		for _, kd := range spd.KeyDescriptors {
			if kd.Use == "signing" {
				keyDescriptors = append(keyDescriptors, kd)
			}
		}
		spd.KeyDescriptors = keyDescriptors
	}

	metadataXML, err := xml.Marshal(metadata)
	if err != nil {
		return internalServerError("Error serializing SAML Service Provider metadata").withInternal(err)
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Cache-Control", "public, max-age=600")
	if download {
		w.Header().Set("Content-Disposition", `attachment; filename="metadata.xml"`)
	}
	_, err = w.Write(metadataXML)
	return err
}

// ---- IdP metadata ----------------------------------------------------------

// parseSAMLMetadata is upstream's parseSAMLMetadata: the document must be valid
// UTF-8, must parse, must name an EntityID and must describe exactly one
// IDPSSODescriptor.
func parseSAMLMetadata(rawMetadata []byte) (*saml.EntityDescriptor, error) {
	if !utf8.Valid(rawMetadata) {
		return nil, badRequestError(ErrorCodeValidationFailed,
			"SAML Metadata XML contains invalid UTF-8 characters, which are not supported at this time")
	}
	metadata, err := samlsp.ParseMetadata(rawMetadata)
	if err != nil {
		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata is not valid XML").withInternal(err)
	}
	if metadata.EntityID == "" {
		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata does not contain an EntityID")
	}
	if len(metadata.IDPSSODescriptors) < 1 {
		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata does not contain any IDPSSODescriptor")
	}
	if len(metadata.IDPSSODescriptors) > 1 {
		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata contains multiple IDPSSODescriptors")
	}
	return metadata, nil
}

// maxSAMLMetadata caps a metadata_url download. A hostile or misconfigured URL
// must not be able to exhaust memory; upstream reads the body unbounded.
const maxSAMLMetadata = 1 << 20 // 1 MiB

// fetchSAMLMetadata is upstream's fetchSAMLMetadata: a plain GET of
// metadata_url. The request rides a.httpClient(), so it inherits the request
// timeout instead of hanging forever on a dead IdP.
func (a *api) fetchSAMLMetadata(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, internalServerError("Unable to create a request to metadata_url").withInternal(err)
	}
	req.Header.Set("Accept", "application/xml;charset=UTF-8")
	req.Header.Set("Accept-Charset", "UTF-8")

	res, err := a.httpClient().Do(req)
	if err != nil {
		return nil, badRequestError(ErrorCodeSAMLMetadataFetchFailed,
			"Error fetching SAML Metadata from URL '%s'", rawURL).withInternal(err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, badRequestError(ErrorCodeSAMLMetadataFetchFailed,
			"HTTP %v error fetching SAML Metadata from URL '%s'", res.StatusCode, rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxSAMLMetadata))
	if err != nil {
		return nil, internalServerError("Error reading SAML Metadata").withInternal(err)
	}
	return data, nil
}

// isSAMLMetadataStale is upstream's IsSAMLMetadataStale: the cached document is
// refreshed when it has expired, when its cacheDuration has elapsed since the
// row was last written, or — when it publishes neither — once a day.
func isSAMLMetadataStale(idpMetadata *saml.EntityDescriptor, p SAMLProvider, now time.Time) bool {
	expired := !idpMetadata.ValidUntil.IsZero() && now.After(idpMetadata.ValidUntil)
	cacheExceeded := idpMetadata.CacheDuration != 0 && now.After(p.UpdatedAt.Add(idpMetadata.CacheDuration))
	forced := idpMetadata.ValidUntil.IsZero() && idpMetadata.CacheDuration == 0 &&
		now.After(p.UpdatedAt.Add(samlMetadataForceRefresh))
	return expired || cacheExceeded || forced
}

// ---- POST /sso/saml/acs ----------------------------------------------------

// samlACS is upstream's API.SamlAcs: the wrapper that turns any failure into a
// redirect back to SiteURL carrying the error, because the caller is a browser.
func (a *api) samlACS(w http.ResponseWriter, r *http.Request) error {
	if err := a.handleSAMLACS(w, r); err != nil {
		a.redirectExternalError(w, r, a.site(r.Context()).SiteURL, err, http.StatusSeeOther)
	}
	return nil
}

// handleSAMLACS is upstream's handleSamlAcs.
func (a *api) handleSAMLACS(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	now := a.now()

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	relayStateValue := r.FormValue("RelayState")
	relayStateUUID, uuidErr := uuid.Parse(relayStateValue)
	relayStateURL, urlErr := url.ParseRequestURI(relayStateValue)

	var (
		entityID    string
		initiatedBy string
		redirectTo  string
		requestIDs  []string
		flowState   *oauthFlowState
	)

	switch {
	case uuidErr == nil && relayStateUUID != uuid.Nil:
		// A UUID RelayState means this is the SP-initiated flow we started.
		relayState, err := findSAMLRelayStateByID(ctx, pool, relayStateUUID.String())
		if err != nil {
			if isNoRows(err) {
				return notFoundError(ErrorCodeSAMLRelayStateNotFound,
					"SAML RelayState does not exist, try logging in again?")
			}
			return internalServerError("Error loading SAML RelayState").withInternal(err)
		}

		if relayState.IsExpired(now, DefaultSAMLRelayStateValidityPeriod) {
			if derr := deleteSAMLRelayState(ctx, pool, relayState.ID); derr != nil {
				return internalServerError(
					"SAML RelayState has expired and destroying it failed. Try logging in again?").withInternal(derr)
			}
			return unprocessableEntityError(ErrorCodeSAMLRelayStateExpired,
				"SAML RelayState has expired. Try logging in again?")
		}

		ssoProvider, err := findSSOProviderByID(ctx, pool, relayState.SSOProviderID)
		if err != nil {
			return internalServerError("Unable to find SSO Provider from SAML RelayState").withInternal(err)
		}
		if !ssoProvider.IsEnabled() {
			return notFoundError(ErrorCodeSSOProviderDisabled,
				"SSO Provider assigned for this domain is currently disabled")
		}

		initiatedBy = "sp"
		entityID = ssoProvider.SAMLProvider.EntityID
		redirectTo = relayState.RedirectTo
		requestIDs = append(requestIDs, relayState.RequestID)

		if relayState.FlowStateID != nil {
			fs, ferr := findOAuthFlowStateByID(ctx, pool, *relayState.FlowStateID)
			if ferr != nil && !isNoRows(ferr) {
				return internalServerError("Error loading flow state").withInternal(ferr)
			}
			if ferr == nil {
				flowState = fs
			}
		}

		// The relay state is single use: destroy it before the assertion is
		// even parsed, so a replayed POST can never find it again.
		if derr := deleteSAMLRelayState(ctx, pool, relayState.ID); derr != nil {
			return internalServerError("Error destroying SAML RelayState").withInternal(derr)
		}

	case relayStateValue == "" || urlErr == nil && relayStateURL != nil:
		// No RelayState, or a URL: an IdP-initiated flow, where the RelayState
		// is where the IdP wants the user to land.
		if r.FormValue("SAMLart") != "" {
			return badRequestError(ErrorCodeValidationFailed,
				"SAML Artifact response can only be used with SP initiated flow")
		}
		samlResponse := r.FormValue("SAMLResponse")
		if samlResponse == "" {
			return badRequestError(ErrorCodeValidationFailed, "SAMLResponse is missing")
		}
		responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "SAMLResponse is not a valid Base64 string")
		}
		// This peek is UNVERIFIED: it only names the IdP whose metadata will
		// then verify the signature. Nothing from it reaches the database.
		var peek saml.Response
		if err := xml.Unmarshal(responseXML, &peek); err != nil {
			return badRequestError(ErrorCodeValidationFailed,
				"SAMLResponse is not a valid XML SAML assertion").withInternal(err)
		}
		initiatedBy = "idp"
		entityID = peek.Issuer.Value
		redirectTo = relayStateValue

	default:
		return badRequestError(ErrorCodeValidationFailed, "SAML RelayState is not a valid UUID or URL")
	}

	ssoProvider, err := findSSOProviderByEntityID(ctx, pool, entityID)
	if err != nil {
		if isNoRows(err) {
			return notFoundError(ErrorCodeSAMLIdPNotFound,
				"A SAML connection has not been established with this Identity Provider")
		}
		return internalServerError("Error loading SSO Provider").withInternal(err)
	}
	if !ssoProvider.IsEnabled() {
		return notFoundError(ErrorCodeSSOProviderDisabled,
			"SSO Provider assigned for this domain is currently disabled")
	}

	idpMetadata, err := parseSAMLMetadata([]byte(ssoProvider.SAMLProvider.MetadataXML))
	if err != nil {
		return err
	}

	metadataModified := false
	switch {
	case ssoProvider.SAMLProvider.MetadataURL == nil || *ssoProvider.SAMLProvider.MetadataURL == "":
		// Static metadata_xml cannot be refreshed; warn the operator while
		// there is still time to act.
		if !idpMetadata.ValidUntil.IsZero() && idpMetadata.ValidUntil.Sub(now) <= samlMetadataExpiryWarning {
			a.log.WarnContext(ctx,
				"auth: SAML Metadata for identity provider will expire soon! Update its metadata_xml!",
				slog.String("sso_provider_id", ssoProvider.ID),
				slog.String("saml_entity_id", ssoProvider.SAMLProvider.EntityID),
				slog.String("expires_in", idpMetadata.ValidUntil.Sub(now).String()),
				slog.Time("valid_until", idpMetadata.ValidUntil))
		}
	case isSAMLMetadataStale(idpMetadata, ssoProvider.SAMLProvider, now):
		raw, ferr := a.fetchSAMLMetadata(ctx, *ssoProvider.SAMLProvider.MetadataURL)
		if ferr != nil {
			// Upstream fails SILENTLY here and keeps the cached document: a
			// temporarily unreachable metadata endpoint must not lock every
			// user out.
			a.log.WarnContext(ctx, "auth: SAML Metadata could not be retrieved, continuing with existing metadata",
				slog.String("sso_provider_id", ssoProvider.ID),
				slog.String("error", ferr.Error()))
		} else if refreshed, perr := parseSAMLMetadata(raw); perr != nil {
			a.log.WarnContext(ctx, "auth: SAML Metadata fetched from metadata_url is not usable, continuing with existing metadata",
				slog.String("sso_provider_id", ssoProvider.ID),
				slog.String("error", perr.Error()))
		} else {
			ssoProvider.SAMLProvider.MetadataXML = string(raw)
			idpMetadata = refreshed
			metadataModified = true
		}
	}

	sp, err := a.newSAMLServiceProvider(ctx, idpMetadata, initiatedBy == "idp")
	if err != nil {
		return err
	}

	// ParseResponse is what verifies the XML signature against the IdP's
	// metadata certificate, the audience, the destination, the validity window
	// and — for an SP-initiated flow — that InResponseTo names one of our
	// requestIDs. Everything below this line is trusted only because of it.
	spAssertion, err := sp.ParseResponse(r, requestIDs)
	if err != nil {
		if ire, ok := err.(*saml.InvalidResponseError); ok {
			return badRequestError(ErrorCodeValidationFailed,
				"SAML Assertion is not valid %s", ire.Response).withInternal(ire.PrivateErr)
		}
		return badRequestError(ErrorCodeValidationFailed, "SAML Assertion is not valid").withInternal(err)
	}
	assertion := &samlAssertion{Assertion: spAssertion}

	userID := assertion.UserID()
	if userID == "" {
		return badRequestError(ErrorCodeSAMLAssertionNoUserID,
			"SAML Assertion did not contain a persistent Subject Identifier attribute or Subject NameID uniquely identifying this user")
	}

	claims := assertion.Process(ssoProvider.SAMLProvider.AttributeMapping)

	email, _ := claims["email"].(string)
	if email == "" {
		// The mapping does not identify the email attribute; fall back to the
		// well-known attribute names and the NameID.
		email = assertion.Email()
	}
	if email == "" {
		return badRequestError(ErrorCodeSAMLAssertionNoEmail, "SAML Assertion does not contain an email address")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	claims["email"] = email

	providerClaims, err := samlProviderClaims(claims)
	if err != nil {
		return err
	}
	providerClaims.Subject = userID
	providerClaims.Issuer = ssoProvider.SAMLProvider.EntityID
	providerClaims.Email = email
	// An assertion is an authenticated statement by the IdP that this is the
	// user's address, which is exactly what "verified" means here.
	providerClaims.EmailVerified = true

	data := &userProvidedData{
		Emails:   []providerEmail{{Email: email, Verified: true, Primary: true}},
		Metadata: providerClaims,
	}

	providerType := ssoProviderName(ssoProvider.ID)
	notAfter := assertion.NotAfter()

	var (
		user        *User
		session     *AccessTokenResponse
		createdUser bool
	)
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var terr error
		user, createdUser, terr = a.createAccountFromSSOIdentity(ctx, tx, r, data, providerType)
		if terr != nil {
			return terr
		}

		if metadataModified {
			if uerr := refreshSAMLMetadataXML(ctx, tx, ssoProvider.SAMLProvider.ID,
				ssoProvider.SAMLProvider.MetadataXML, now); uerr != nil {
				return internalServerError("Error updating SAML Metadata").withInternal(uerr)
			}
		}

		if flowState != nil && flowState.IsPKCE() {
			// Re-read with the row locked: two assertions racing on the same
			// flow must not both mint an auth code.
			locked, lerr := findOAuthFlowStateByIDForUpdate(ctx, tx, flowState.ID)
			if lerr != nil {
				if isNoRows(lerr) {
					return badRequestError(ErrorCodeBadOAuthState, "OAuth state not found or expired")
				}
				return internalServerError("Error loading flow state").withInternal(lerr)
			}
			if locked.UserID != nil {
				return badRequestError(ErrorCodeFlowStateAlreadyUsed, "State has already been used")
			}
			if cerr := claimOAuthFlowState(ctx, tx, flowState.ID, user.ID, "", "", now); cerr != nil {
				return internalServerError("Error updating flow state").withInternal(cerr)
			}
			return nil
		}

		var gerr error
		session, gerr = a.grantSession(ctx, tx, user, r, amrSSOSAML)
		if gerr != nil {
			return gerr
		}
		if !notAfter.IsZero() {
			// The IdP told us when its session ends; Dilion's must not outlive
			// it (upstream GrantParams.SessionNotAfter).
			if serr := setSessionNotAfterForRefreshToken(ctx, tx, session.RefreshToken, notAfter.UTC()); serr != nil {
				return internalServerError("Error recording session validity").withInternal(serr)
			}
		}
		if flowState != nil {
			if derr := deleteFlowState(ctx, tx, flowState.ID); derr != nil {
				return internalServerError("Error consuming flow state").withInternal(derr)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if createdUser {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":  user.ID,
			"email":    user.Email,
			"provider": providerType,
		})
	}

	if !a.site(ctx).IsRedirectAllowed(redirectTo) {
		redirectTo = a.site(ctx).SiteURL
	}

	if flowState != nil && flowState.IsPKCE() {
		target, perr := prepPKCERedirectURL(redirectTo, *flowState.AuthCode)
		if perr != nil {
			return internalServerError("Error building the redirect URL").withInternal(perr)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return nil
	}

	http.Redirect(w, r, session.asRedirectURL(redirectTo, url.Values{}), http.StatusFound)
	return nil
}

// samlProviderClaims turns the mapped claim map into the shared provider claim
// model. Keys that the model has a field for are consumed; everything else ends
// up under `custom_claims`, which is upstream's structs.Map round trip.
func samlProviderClaims(claims map[string]any) (*providerClaims, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, internalServerError(
			"Mapped claims from provider could not be serialized into JSON").withInternal(err)
	}
	var mapped samlClaimsJSON
	if err := json.Unmarshal(raw, &mapped); err != nil {
		return nil, internalServerError(
			"Mapped claims from provider could not be deserialized from JSON").withInternal(err)
	}
	pc := mapped.toProviderClaims()

	custom := map[string]any{}
	for key, value := range claims {
		if samlReservedClaims[key] {
			continue
		}
		custom[key] = value
	}
	if len(custom) > 0 {
		pc.CustomClaims = custom
	}
	return pc, nil
}

// samlClaimsJSON is the subset of provider.Claims a SAML attribute mapping can
// populate by name. The json tags are upstream's provider.Claims tags.
type samlClaimsJSON struct {
	Name              string `json:"name"`
	FamilyName        string `json:"family_name"`
	GivenName         string `json:"given_name"`
	MiddleName        string `json:"middle_name"`
	NickName          string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	Profile           string `json:"profile"`
	Picture           string `json:"picture"`
	Website           string `json:"website"`
	Gender            string `json:"gender"`
	Birthdate         string `json:"birthdate"`
	ZoneInfo          string `json:"zoneinfo"`
	Locale            string `json:"locale"`
	UpdatedAt         string `json:"updated_at"`
	Email             string `json:"email"`
	Phone             string `json:"phone"`
	FullName          string `json:"full_name"`
	AvatarURL         string `json:"avatar_url"`
	Slug              string `json:"slug"`
	ProviderID        string `json:"provider_id"`
	UserName          string `json:"user_name"`
}

// samlReservedClaims are the keys samlClaimsJSON consumes; anything else a
// mapping produces is a custom claim.
var samlReservedClaims = map[string]bool{
	"name": true, "family_name": true, "given_name": true, "middle_name": true,
	"nickname": true, "preferred_username": true, "profile": true, "picture": true,
	"website": true, "gender": true, "birthdate": true, "zoneinfo": true,
	"locale": true, "updated_at": true, "email": true, "phone": true,
	"full_name": true, "avatar_url": true, "slug": true, "provider_id": true,
	"user_name": true, "iss": true, "sub": true, "aud": true, "iat": true,
	"exp": true, "email_verified": true, "phone_verified": true,
}

func (c samlClaimsJSON) toProviderClaims() *providerClaims {
	return &providerClaims{
		Name:              c.Name,
		FamilyName:        c.FamilyName,
		GivenName:         c.GivenName,
		MiddleName:        c.MiddleName,
		NickName:          c.NickName,
		PreferredUsername: c.PreferredUsername,
		Profile:           c.Profile,
		Picture:           c.Picture,
		Website:           c.Website,
		Gender:            c.Gender,
		Birthdate:         c.Birthdate,
		ZoneInfo:          c.ZoneInfo,
		Locale:            c.Locale,
		UpdatedAt:         c.UpdatedAt,
		Email:             c.Email,
		Phone:             c.Phone,
		FullName:          c.FullName,
		AvatarURL:         c.AvatarURL,
		Slug:              c.Slug,
		ProviderID:        c.ProviderID,
		UserName:          c.UserName,
	}
}

// ---- SSO account resolution ------------------------------------------------

// createAccountFromSSOIdentity is external_callback.go's
// createAccountFromExternalIdentity for an SSO provider.
//
// It is a SEPARATE function on purpose. Upstream's DetermineAccountLinking maps
// an "sso:<uuid>" provider onto a linking domain of its own
// (models.GetAccountLinkingDomain), which means an assertion may only ever join
// an account that already holds an identity from the SAME identity provider. It
// must NEVER link into a password account or into an account from another IdP
// that happens to assert the same address — that would let anybody who controls
// an IdP take over arbitrary local accounts by asserting their email. The
// package's determineAccountLinking implements only the "default" domain, so it
// cannot be reused here.
//
// The user rows created here carry is_sso_user = true, which releases the
// partial unique index on email and marks the account as provider-managed.
func (a *api) createAccountFromSSOIdentity(ctx context.Context, tx pgx.Tx, r *http.Request,
	data *userProvidedData, providerType string) (*User, bool, error) {

	aud := requestAud(r)
	now := a.now()
	identityData := data.Metadata.toMap()
	sub := data.Metadata.Subject
	if sub == "" {
		return nil, false, internalServerError("Error getting user id from external provider")
	}

	decision, err := a.determineSSOAccountLinking(ctx, tx, data.Emails, providerType, sub)
	if err != nil {
		return nil, false, err
	}

	var (
		user     *User
		identity *Identity
		created  bool
	)

	switch decision.Decision {
	case decisionAccountExists:
		user = decision.User
		identity = decision.Identity
		if err = updateProviderIdentity(ctx, tx, identity.ID, identityData, now); err != nil {
			return nil, false, internalServerError("Error updating identity").withInternal(err)
		}
		if user, err = a.mergeUserMetaData(ctx, tx, user, identityData, now); err != nil {
			return nil, false, err
		}
		if user, err = a.syncAppMetaDataProviders(ctx, tx, user, now); err != nil {
			return nil, false, err
		}

	case decisionLinkAccount:
		user = decision.User
		if identity, err = insertProviderIdentity(ctx, tx, user.ID, providerType, sub, identityData, now); err != nil {
			return nil, false, internalServerError("Error creating identity").withInternal(err)
		}
		if user, err = a.mergeUserMetaData(ctx, tx, user, identityData, now); err != nil {
			return nil, false, err
		}
		if user, err = a.syncAppMetaDataProviders(ctx, tx, user, now); err != nil {
			return nil, false, err
		}

	case decisionCreateAccount:
		if a.cfg.DisableSignup {
			return nil, false, unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
		}
		email := decision.CandidateEmail.Email

		// BeforeSignup is a validating hook: it may reject the sign-up and may
		// rewrite the email / user_metadata that get persisted.
		payload, herr := a.runHook(ctx, ports.BeforeSignup, map[string]any{
			"provider":      providerType,
			"email":         email,
			"phone":         "",
			"user_metadata": map[string]any(identityData),
		})
		if herr != nil {
			return nil, false, unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected: %v", herr)
		}
		if v, ok := payload["email"].(string); ok && v != "" {
			email = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := payload["user_metadata"].(map[string]any); ok && v != nil {
			identityData = JSONMap(v)
		}

		user, err = insertSSOUser(ctx, tx, newUserParams{
			ID:   uuid.NewString(),
			Aud:  aud,
			Role: RoleAuthenticated,
			// The assertion IS the confirmation of the address: an SSO account
			// never goes through Dilion's email confirmation flow.
			Email:            email,
			EmailConfirmedAt: &now,
			AppMetaData:      JSONMap{"provider": providerType, "providers": []any{providerType}},
			UserMetaData:     identityData,
			Now:              now,
		})
		if err != nil {
			return nil, false, internalServerError("Database error saving new user").withInternal(err)
		}
		created = true
		if identity, err = insertProviderIdentity(ctx, tx, user.ID, providerType, sub, identityData, now); err != nil {
			return nil, false, internalServerError("Error creating identity").withInternal(err)
		}

	default: // decisionMultipleAccounts
		return nil, false, internalServerError(
			"Multiple accounts with the same email address in the same linking domain detected")
	}

	if user.IsBanned(now) {
		return nil, false, forbiddenError(ErrorCodeUserBanned, "User is banned")
	}

	// A pre-existing SSO account may still be unconfirmed if it was created by
	// an admin; the assertion confirms it.
	if !isConfirmed(user) {
		confirmed, cerr := updateUserFields(ctx, tx, user.ID, now, map[string]any{
			"email_confirmed_at": now,
			"confirmation_token": "",
		})
		if cerr != nil {
			return nil, false, internalServerError("Error updating user").withInternal(cerr)
		}
		user = confirmed
	}

	ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
	if ierr != nil {
		return nil, false, internalServerError("Error loading identities").withInternal(ierr)
	}
	user.Identities = ids
	return user, created, nil
}

// determineSSOAccountLinking is the SSO branch of upstream's
// models.DetermineAccountLinking — the one whose linking domain is the provider
// itself:
//
//	identity (sso:<id>, sub) exists                    -> AccountExists
//	no verified email                                  -> CreateAccount
//	verified email matches an identity of THIS provider -> LinkAccount
//	several such identities on different users          -> MultipleAccounts
//	otherwise                                          -> CreateAccount
//
// Note what is deliberately absent: a lookup of users by email. Users are only
// ever reached through an identity of the same provider.
func (a *api) determineSSOAccountLinking(ctx context.Context, tx querier, emails []providerEmail,
	providerName, sub string) (accountLinkingResult, error) {

	var verifiedEmails []string
	var candidate providerEmail
	for _, e := range emails {
		if e.Verified || a.cfg.Mailer.Autoconfirm {
			verifiedEmails = append(verifiedEmails, strings.ToLower(e.Email))
		}
		if e.Primary {
			candidate = e
			candidate.Email = strings.ToLower(e.Email)
		}
	}

	identity, user, err := a.findLiveIdentity(ctx, tx, sub, providerName)
	if err != nil {
		return accountLinkingResult{}, err
	}
	if identity != nil {
		candidate.Email = user.Email
		return accountLinkingResult{
			Decision:       decisionAccountExists,
			User:           user,
			Identity:       identity,
			CandidateEmail: candidate,
		}, nil
	}

	if len(verifiedEmails) == 0 {
		return accountLinkingResult{Decision: decisionCreateAccount, CandidateEmail: candidate}, nil
	}

	similar, err := findSSOIdentitiesByEmails(ctx, tx, providerName, verifiedEmails)
	if err != nil {
		return accountLinkingResult{}, internalServerError("Database error finding identities").withInternal(err)
	}
	if len(similar) == 0 {
		return accountLinkingResult{Decision: decisionCreateAccount, CandidateEmail: candidate}, nil
	}

	linkingUserID := similar[0].UserID
	for _, i := range similar {
		if i.UserID != linkingUserID {
			return accountLinkingResult{Decision: decisionMultipleAccounts, CandidateEmail: candidate}, nil
		}
	}
	user, err = findUserByID(ctx, tx, linkingUserID)
	if err != nil {
		return accountLinkingResult{}, internalServerError("Database error finding user").withInternal(err)
	}
	return accountLinkingResult{
		Decision:       decisionLinkAccount,
		User:           user,
		CandidateEmail: candidate,
	}, nil
}

// ---- the assertion ---------------------------------------------------------

// samlAssertion is upstream's api.SAMLAssertion: the helpers that read a parsed,
// already VERIFIED assertion.
type samlAssertion struct {
	*saml.Assertion
}

// SAMLSubjectIDAttributeName is the OASIS subject-id attribute, the preferred
// persistent identifier of a SAML 2.0 subject.
const SAMLSubjectIDAttributeName = "urn:oasis:names:tc:SAML:attribute:subject-id"

// Attribute returns every value of the attributes whose Name or FriendlyName
// matches, case-insensitively (upstream SAMLAssertion.Attribute).
func (a *samlAssertion) Attribute(name string) []saml.AttributeValue {
	var values []saml.AttributeValue
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if strings.EqualFold(attr.Name, name) || strings.EqualFold(attr.FriendlyName, name) {
				values = append(values, attr.Values...)
			}
		}
	}
	return values
}

// UserID is upstream's SAMLAssertion.UserID: the best persistent identifier of
// the subject on the IdP side. It is the `provider_id` of the identity row, so
// its stability across logins is what makes an SSO account durable.
func (a *samlAssertion) UserID() string {
	if values := a.Attribute(SAMLSubjectIDAttributeName); len(values) > 0 {
		return values[0].Value
	}
	subjectID, isPersistent := a.SubjectID()
	if !isPersistent {
		// A transient NameID changes on every assertion and therefore cannot
		// identify a user at all.
		return ""
	}
	return subjectID
}

// SubjectID is upstream's SAMLAssertion.SubjectID.
func (a *samlAssertion) SubjectID() (string, bool) {
	if a.Subject == nil || a.Subject.NameID == nil || a.Subject.NameID.Value == "" {
		return "", false
	}
	if a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		return strings.ToLower(strings.TrimSpace(a.Subject.NameID.Value)), true
	}
	// Every format other than `transient` is regarded as persistent.
	return a.Subject.NameID.Value, a.Subject.NameID.Format != string(saml.TransientNameIDFormat)
}

// samlEmailAttributeNames are the attribute names upstream guesses an email
// address from, in order.
var samlEmailAttributeNames = []string{
	"urn:oid:0.9.2342.19200300.100.1.3",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	"http://schemas.xmlsoap.org/claims/EmailAddress",
	"mail",
	"Mail",
	"email",
}

// Email is upstream's SAMLAssertion.Email: the best guess when the attribute
// mapping does not name the email attribute.
func (a *samlAssertion) Email() string {
	for _, name := range samlEmailAttributeNames {
		for _, attr := range a.Attribute(name) {
			if attr.Value != "" {
				return attr.Value
			}
		}
	}
	if a.Subject != nil && a.Subject.NameID != nil &&
		a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		return a.Subject.NameID.Value
	}
	return ""
}

// Process applies the provider's attribute_mapping (upstream
// SAMLAssertion.Process). For every mapped key, Name is tried first, then each
// entry of Names in order; the FIRST name that yields a non-empty value wins
// (and, with Array, contributes all of its values). A key that matched nothing
// falls back to Default when one is configured. Never returns nil.
func (a *samlAssertion) Process(mapping SAMLAttributeMapping) map[string]any {
	out := map[string]any{}

	for key, mapper := range mapping.Keys {
		names := []string{}
		if mapper.Name != "" {
			names = append(names, mapper.Name)
		}
		names = append(names, mapper.Names...)

		setKey := false
		for _, name := range names {
			for _, attr := range a.Attribute(name) {
				if attr.Value == "" {
					continue
				}
				setKey = true
				if mapper.Array {
					if out[key] == nil {
						out[key] = []string{}
					}
					out[key] = append(out[key].([]string), attr.Value)
				} else {
					out[key] = attr.Value
					break
				}
			}
			if setKey {
				break
			}
		}
		if !setKey && mapper.Default != nil {
			out[key] = mapper.Default
		}
	}
	return out
}

// NotBefore is upstream's SAMLAssertion.NotBefore.
func (a *samlAssertion) NotBefore() time.Time {
	if a.Conditions != nil && !a.Conditions.NotBefore.IsZero() {
		return a.Conditions.NotBefore.UTC()
	}
	return time.Time{}
}

// NotAfter is upstream's SAMLAssertion.NotAfter: the IdP's SessionNotOnOrAfter,
// which bounds the Dilion session issued from this assertion.
func (a *samlAssertion) NotAfter() time.Time {
	var notOnOrAfter time.Time
	for _, statement := range a.AuthnStatements {
		if statement.SessionNotOnOrAfter == nil {
			continue
		}
		notOnOrAfter = *statement.SessionNotOnOrAfter
		if !notOnOrAfter.IsZero() {
			break
		}
	}
	return notOnOrAfter
}
