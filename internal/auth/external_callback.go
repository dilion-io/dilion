package auth

// GET|POST /callback — the provider's answer to GET /authorize.
//
// Reproduces github.com/supabase/auth/internal/api/external.go
// (ExternalProviderCallback, internalExternalProviderCallback,
// createAccountFromExternalIdentity), external_oauth.go (oAuthCallback) and
// internal/models/linking.go (DetermineAccountLinking).
//
// Everything that can go wrong after the flow state was loaded is answered with
// a REDIRECT carrying the OAuth error triple, never with a JSON body: the caller
// here is a browser coming back from the provider, not an API client.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

// providerOAuthError is an error the PROVIDER reported (…?error=access_denied).
// It is passed through to the client verbatim, as upstream's OAuthError is.
type providerOAuthError struct {
	Err         string
	Description string
}

func (e *providerOAuthError) Error() string {
	return fmt.Sprintf("oauth provider error %s: %s", e.Err, e.Description)
}

// externalProviderCallback is upstream's ExternalProviderCallback.
func (a *api) externalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if r.Method == http.MethodPost {
		// Apple (response_mode=form_post) sends state/code/user as a form.
		_ = r.ParseForm()
	}

	fs, err := a.loadExternalState(ctx, r)
	if err != nil {
		// The flow state is what names the client's redirect target, so a bad
		// state can only bounce to SiteURL (upstream loadFlowState).
		a.redirectExternalError(w, r, a.cfg.SiteURL, err, http.StatusSeeOther)
		return nil
	}

	rurl := a.externalRedirectURL(fs)
	if err := a.finishExternalCallback(w, r, fs, rurl); err != nil {
		a.redirectExternalError(w, r, rurl, err, http.StatusFound)
	}
	return nil
}

// loadExternalState is upstream's loadExternalState: `state` is the flow state's
// id and the row behind it carries the whole flow context.
func (a *api) loadExternalState(ctx context.Context, r *http.Request) (*oauthFlowState, error) {
	state := r.URL.Query().Get("state")
	if r.Method == http.MethodPost {
		if v := r.FormValue("state"); v != "" {
			state = v
		}
	}
	if state == "" {
		return nil, badRequestError(ErrorCodeBadOAuthCallback, "OAuth state parameter missing")
	}
	if _, err := uuid.Parse(state); err != nil {
		return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth state parameter is invalid")
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return nil, perr
	}
	fs, err := findOAuthFlowStateByID(ctx, pool, state)
	if err != nil {
		if isNoRows(err) {
			return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth state not found or expired")
		}
		return nil, internalServerError("Error loading flow state").withInternal(err)
	}
	if fs.AuthenticationMethod != authMethodOAuth {
		// The row belongs to an email flow; it is not a valid OAuth state.
		return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth state not found or expired")
	}
	if fs.IsExpired(a.now(), a.cfg.FlowStateExpiry) {
		return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth state has expired")
	}
	// user_id is NULL until a callback claims the flow, so a non-NULL value on a
	// PKCE flow means the state was already redeemed.
	if fs.IsPKCE() && fs.UserID != nil {
		return nil, badRequestError(ErrorCodeFlowStateAlreadyUsed, "State has already been used")
	}
	return fs, nil
}

// finishExternalCallback runs the exchange + account resolution + redirect.
func (a *api) finishExternalCallback(w http.ResponseWriter, r *http.Request, fs *oauthFlowState, rurl string) error {
	ctx := r.Context()

	rq := r.URL.Query()
	if r.Method == http.MethodPost && r.Form != nil {
		rq = r.Form
	}
	if extErr := rq.Get("error"); extErr != "" {
		return &providerOAuthError{Err: extErr, Description: rq.Get("error_description")}
	}
	code := rq.Get("code")
	if code == "" {
		return badRequestError(ErrorCodeBadOAuthCallback, "OAuth callback with missing authorization code missing")
	}

	p, _, err := a.provider(ctx, fs.ProviderType, "")
	if err != nil {
		return badRequestError(ErrorCodeOAuthProviderNotSupported, "Unsupported provider: %+v", err).withInternal(err)
	}

	hc := a.httpClient()
	tok, err := p.exchange(ctx, hc, code)
	if err != nil {
		// Never log or return the code itself beyond upstream's 4-character
		// prefix: it is a bearer credential until it is redeemed.
		return internalServerError("Unable to exchange external code: %s", code[:min(4, len(code))]).withInternal(err)
	}
	data, err := p.userData(ctx, hc, tok)
	if err != nil {
		return internalServerError("Error getting user profile from external provider").withInternal(err)
	}
	if parser, ok := p.(callbackUserParser); ok {
		if raw := rq.Get("user"); raw != "" {
			if perr := parser.parseCallbackUser(raw, data); perr != nil {
				return badRequestError(ErrorCodeValidationFailed, "Error parsing user data from external provider").withInternal(perr)
			}
		}
	}
	if len(data.Emails) == 0 {
		return internalServerError("Error getting user email from external provider")
	}
	data.applyPrimaryEmail()

	var (
		user        *User
		session     *AccessTokenResponse
		createdUser bool
	)
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var terr error
		if fs.LinkingTargetID != nil {
			user, terr = a.linkIdentityToUser(ctx, tx, r, *fs.LinkingTargetID, data, fs.ProviderType)
		} else {
			user, createdUser, terr = a.createAccountFromExternalIdentity(ctx, tx, r, data, fs.ProviderType)
		}
		if terr != nil {
			return terr
		}

		if fs.IsPKCE() {
			// Re-read the row with the lock held: two callbacks racing on the
			// same state must not both mint a session.
			locked, lerr := findOAuthFlowStateByIDForUpdate(ctx, tx, fs.ID)
			if lerr != nil {
				if isNoRows(lerr) {
					return badRequestError(ErrorCodeBadOAuthState, "OAuth state not found or expired")
				}
				return internalServerError("Error loading flow state").withInternal(lerr)
			}
			if locked.UserID != nil {
				return badRequestError(ErrorCodeFlowStateAlreadyUsed, "State has already been used")
			}
			if cerr := claimOAuthFlowState(ctx, tx, fs.ID, user.ID,
				tok.AccessToken, tok.RefreshToken, a.now()); cerr != nil {
				return internalServerError("Error updating flow state").withInternal(cerr)
			}
			return nil
		}

		// Implicit flow: the session is issued here and the flow state dies.
		var gerr error
		session, gerr = a.grantSession(ctx, tx, user, r, amrOAuth)
		if gerr != nil {
			return gerr
		}
		if derr := deleteFlowState(ctx, tx, fs.ID); derr != nil {
			return internalServerError("Error consuming flow state").withInternal(derr)
		}
		return nil
	}); err != nil {
		return err
	}

	if createdUser {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":    user.ID,
			"email":      user.Email,
			"provider":   fs.ProviderType,
			"project_id": DefaultProjectID,
		})
	}

	if fs.IsPKCE() {
		redirect, perr := prepPKCERedirectURL(rurl, *fs.AuthCode)
		if perr != nil {
			return internalServerError("Error building the redirect URL").withInternal(perr)
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return nil
	}

	q := url.Values{}
	q.Set("provider_token", tok.AccessToken)
	// Not every provider issues a refresh token (RFC 6749 §5.1).
	if tok.RefreshToken != "" {
		q.Set("provider_refresh_token", tok.RefreshToken)
	}
	http.Redirect(w, r, session.asRedirectURL(rurl, q), http.StatusFound)
	return nil
}

// ---- account linking -------------------------------------------------------

// accountDecision is upstream's models.AccountLinkingDecision.
type accountDecision int

const (
	decisionAccountExists accountDecision = iota
	decisionCreateAccount
	decisionLinkAccount
	decisionMultipleAccounts
)

type accountLinkingResult struct {
	Decision       accountDecision
	User           *User
	Identity       *Identity
	CandidateEmail providerEmail
}

// determineAccountLinking is upstream's models.DetermineAccountLinking, reduced
// to the single "default" linking domain (Dilion exposes no
// GOTRUE_EXPERIMENTAL_PROVIDER_LINKING_DOMAINS and no SSO providers yet):
//
//	identity (provider, sub) exists                 -> AccountExists   (sign in)
//	no verified email                               -> CreateAccount   (never link on an unverified address)
//	verified email matches an existing identity     -> LinkAccount     (to that identity's user)
//	verified email matches an existing user         -> LinkAccount     (backfilling the identity)
//	otherwise                                       -> CreateAccount
//	several users in the same linking domain        -> MultipleAccounts (caller errors)
func (a *api) determineAccountLinking(ctx context.Context, tx querier, emails []providerEmail,
	aud, providerName, sub string) (accountLinkingResult, error) {

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

	identity, err := findIdentityByProviderID(ctx, tx, sub, providerName)
	if err != nil && !isNoRows(err) {
		return accountLinkingResult{}, internalServerError("Database error finding identity").withInternal(err)
	}
	if identity != nil {
		user, uerr := findUserByID(ctx, tx, identity.UserID)
		if uerr != nil {
			return accountLinkingResult{}, internalServerError("Database error finding user").withInternal(uerr)
		}
		// The user may legitimately have no email; keep whatever it has.
		candidate.Email = user.Email
		return accountLinkingResult{
			Decision:       decisionAccountExists,
			User:           user,
			Identity:       identity,
			CandidateEmail: candidate,
		}, nil
	}

	if len(verifiedEmails) == 0 {
		// Nothing is proven about this address, so it must never be used to
		// join an existing account — and it cannot be claimed either if some
		// other account already owns it.
		if candidate.Email != "" {
			existing, eerr := findUserByEmail(ctx, tx, candidate.Email, aud)
			if eerr != nil && !isNoRows(eerr) {
				return accountLinkingResult{}, internalServerError("Database error finding user").withInternal(eerr)
			}
			if existing != nil {
				candidate.Email = ""
			}
		}
		return accountLinkingResult{Decision: decisionCreateAccount, CandidateEmail: candidate}, nil
	}

	similarIdentities, err := findIdentitiesByEmails(ctx, tx, verifiedEmails)
	if err != nil {
		return accountLinkingResult{}, internalServerError("Database error finding identities").withInternal(err)
	}
	similarUsers, err := findUsersByEmails(ctx, tx, verifiedEmails, aud)
	if err != nil {
		return accountLinkingResult{}, internalServerError("Database error finding users").withInternal(err)
	}

	if len(similarIdentities) == 0 {
		switch len(similarUsers) {
		case 0:
			return accountLinkingResult{Decision: decisionCreateAccount, CandidateEmail: candidate}, nil
		case 1:
			return accountLinkingResult{
				Decision:       decisionLinkAccount,
				User:           similarUsers[0],
				CandidateEmail: candidate,
			}, nil
		default:
			return accountLinkingResult{Decision: decisionMultipleAccounts, CandidateEmail: candidate}, nil
		}
	}

	linkingUserID := similarIdentities[0].UserID
	for _, i := range similarIdentities {
		if i.UserID != linkingUserID {
			return accountLinkingResult{Decision: decisionMultipleAccounts, CandidateEmail: candidate}, nil
		}
	}
	user, err := findUserByID(ctx, tx, linkingUserID)
	if err != nil {
		return accountLinkingResult{}, internalServerError("Database error finding user").withInternal(err)
	}
	return accountLinkingResult{
		Decision:       decisionLinkAccount,
		User:           user,
		CandidateEmail: candidate,
	}, nil
}

// createAccountFromExternalIdentity is upstream's
// createAccountFromExternalIdentity. It returns the resolved user and whether
// this call CREATED it (which decides whether the AfterSignup hook fires).
func (a *api) createAccountFromExternalIdentity(ctx context.Context, tx pgx.Tx, r *http.Request,
	data *userProvidedData, providerType string) (*User, bool, error) {

	aud := requestAud(r)
	now := a.now()
	identityData := data.Metadata.toMap()
	sub := data.Metadata.Subject
	if sub == "" {
		return nil, false, internalServerError("Error getting user id from external provider")
	}

	decision, err := a.determineAccountLinking(ctx, tx, data.Emails, aud, providerType, sub)
	if err != nil {
		return nil, false, err
	}

	var (
		user     *User
		identity *Identity
		created  bool
	)

	switch decision.Decision {
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

		// BeforeSignup is a validating hook (signup.go): it may reject the
		// sign-up and may rewrite the email / user_metadata that get persisted.
		payload, herr := a.runHook(ctx, ports.BeforeSignup, map[string]any{
			"provider":      providerType,
			"email":         email,
			"phone":         "",
			"user_metadata": map[string]any(identityData),
			"project_id":    DefaultProjectID,
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

		user, err = insertUser(ctx, tx, newUserParams{
			ID:           uuid.NewString(),
			Aud:          aud,
			Role:         RoleAuthenticated,
			Email:        email,
			AppMetaData:  JSONMap{"provider": providerType, "providers": []any{providerType}},
			UserMetaData: identityData,
			Now:          now,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return nil, false, badRequestError(ErrorCodeEmailExists, "%s", DuplicateEmailMessage)
			}
			return nil, false, internalServerError("Database error saving new user").withInternal(err)
		}
		created = true
		if identity, err = insertProviderIdentity(ctx, tx, user.ID, providerType, sub, identityData, now); err != nil {
			return nil, false, internalServerError("Error creating identity").withInternal(err)
		}

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

	default: // decisionMultipleAccounts
		return nil, false, internalServerError(
			"Multiple accounts with the same email address in the same linking domain detected")
	}

	if user.IsBanned(now) {
		return nil, false, forbiddenError(ErrorCodeUserBanned, "User is banned")
	}

	if !isConfirmed(user) {
		// The account may still hold an unconfirmed email+password or another
		// unconfirmed identity. Those are removed as the OAuth identity lands,
		// which is what closes the pre-account-takeover hole (upstream
		// models.User.RemoveUnconfirmedIdentities).
		var rerr error
		if user, rerr = a.removeUnconfirmedIdentities(ctx, tx, user, identity, identityData, now); rerr != nil {
			return nil, false, rerr
		}

		if decision.CandidateEmail.Verified || a.cfg.Mailer.Autoconfirm {
			confirmed, cerr := updateUserFields(ctx, tx, user.ID, now, map[string]any{
				"email_confirmed_at": now,
				"confirmation_token": "",
			})
			if cerr != nil {
				return nil, false, internalServerError("Error updating user").withInternal(cerr)
			}
			user = confirmed
		} else {
			// Upstream (AllowUnverifiedEmailSignIns = false, the default) mails a
			// confirmation where it can and refuses the sign-in either way.
			// commitAndFail keeps the user and identity rows that were just
			// written, so the account exists once the address is confirmed.
			if decision.CandidateEmail.Email != "" {
				if _, serr := a.sendConfirmation(ctx, tx, r, user, a.cfg.SiteURL, false); serr != nil {
					return nil, false, serr
				}
				return nil, false, commitAndFail(unprocessableEntityError(
					ErrorCodeProviderEmailNeedsVerification,
					"Unverified email with %v. A confirmation email has been sent to your %v email",
					providerType, providerType))
			}
			return nil, false, commitAndFail(unprocessableEntityError(
				ErrorCodeProviderEmailNeedsVerification,
				"Unverified email with %v. Verify the email with %v in order to sign in",
				providerType, providerType))
		}
	}

	ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
	if ierr != nil {
		return nil, false, internalServerError("Error loading identities").withInternal(ierr)
	}
	user.Identities = ids
	return user, created, nil
}

// DuplicateEmailMessage is upstream's DuplicateEmailMsg.
const DuplicateEmailMessage = "A user with this email address has already been registered"

// isConfirmed is upstream's models.User.IsConfirmed, which counts a confirmed
// PHONE as a confirmed account too.
func isConfirmed(u *User) bool {
	return u.EmailConfirmedAt != nil || u.PhoneConfirmedAt != nil
}

// mergeUserMetaData is upstream's models.User.UpdateUserMetaData: the identity's
// claims are merged into raw_user_meta_data (a nil value deletes a key).
func (a *api) mergeUserMetaData(ctx context.Context, tx querier, u *User, data JSONMap, now time.Time) (*User, error) {
	merged := JSONMap{}
	for k, v := range u.UserMetaData {
		merged[k] = v
	}
	for k, v := range data {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	updated, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{"raw_user_meta_data": merged})
	if err != nil {
		return nil, internalServerError("Database error updating user").withInternal(err)
	}
	return updated, nil
}

// syncAppMetaDataProviders is upstream's models.User.UpdateAppMetaDataProviders:
// app_metadata.providers is re-derived from the user's identities and
// app_metadata.provider follows the oldest one.
func (a *api) syncAppMetaDataProviders(ctx context.Context, tx querier, u *User, now time.Time) (*User, error) {
	providers, err := findUserProviders(ctx, tx, u.ID)
	if err != nil {
		return nil, internalServerError("Database error loading identities").withInternal(err)
	}
	meta := JSONMap{}
	for k, v := range u.AppMetaData {
		meta[k] = v
	}
	list := make([]any, 0, len(providers))
	for _, p := range providers {
		list = append(list, p)
	}
	meta["providers"] = list
	if len(providers) > 0 {
		meta["provider"] = providers[0]
	}
	updated, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{"raw_app_meta_data": meta})
	if err != nil {
		return nil, internalServerError("Database error updating user").withInternal(err)
	}
	return updated, nil
}

// removeUnconfirmedIdentities is upstream's
// models.User.RemoveUnconfirmedIdentities: an account that was never confirmed
// keeps ONLY the identity that just authenticated, loses its password, and has
// its metadata replaced by that identity's claims. Without this, anyone could
// pre-create an account with somebody else's address and wait for them to sign
// in through a provider.
func (a *api) removeUnconfirmedIdentities(ctx context.Context, tx querier, u *User, identity *Identity,
	identityData JSONMap, now time.Time) (*User, error) {

	if identity == nil {
		return u, nil
	}
	set := map[string]any{"raw_user_meta_data": identityData}
	if identity.Provider != ProviderEmail && identity.Provider != "phone" {
		set["encrypted_password"] = nil
	}
	updated, err := updateUserFields(ctx, tx, u.ID, now, set)
	if err != nil {
		return nil, internalServerError("Error updating user").withInternal(err)
	}
	if err := deleteOtherIdentities(ctx, tx, u.ID, identity.ID); err != nil {
		return nil, internalServerError("Error updating user").withInternal(err)
	}
	return a.syncAppMetaDataProviders(ctx, tx, updated, now)
}
