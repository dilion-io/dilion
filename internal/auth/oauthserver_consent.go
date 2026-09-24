package auth

// The consent half of the OAuth 2.1 authorization flow, plus the end user's
// view of the grants they have handed out.
//
//	GET    /oauth/authorizations/{authorization_id}           consent-screen payload
//	POST   /oauth/authorizations/{authorization_id}/consent   approve / deny
//	GET    /user/oauth/grants                                 list live grants
//	DELETE /user/oauth/grants?client_id=…                     revoke one grant
//
// Mirrors github.com/supabase/auth master, internal/api/oauthserver/authorize.go
// (OAuthServerGetAuthorization, OAuthServerConsent) and handlers.go
// (UserListOAuthGrants, UserRevokeOAuthGrant).
//
// All four require the END USER's access token: they are called by the hosted
// consent page, not by the OAuth client.
//
// # Claiming and locking
//
// The pending authorization row is created without a user (the browser had not
// authenticated yet at /oauth/authorize). The GET here CLAIMS it for the
// signed-in user, and every read that may mutate the row takes it FOR UPDATE
// SKIP LOCKED, so two concurrent tabs cannot both approve the same request and
// each walk away with a valid authorization code.

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OAuthConsentAction is the decision the consent page reports.
type OAuthConsentAction string

const (
	OAuthConsentActionApprove OAuthConsentAction = "approve"
	OAuthConsentActionDeny    OAuthConsentAction = "deny"
)

// ConsentRequest is the POST .../consent body.
type ConsentRequest struct {
	Action OAuthConsentAction `json:"action"`
}

// validateRequestOrigin is upstream's basic cross-origin guard: a browser
// always sends Origin on these requests, and the consent page lives on an
// allowed redirect URL, so an Origin that is not allowed is rejected. An ABSENT
// Origin is accepted — native apps and server-side callers do not send one.
func (a *api) validateRequestOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	if !a.cfg.IsRedirectAllowed(origin) {
		return badRequestError(ErrorCodeValidationFailed, "unauthorized request origin")
	}
	return nil
}

// oauthGetAuthorization handles GET /oauth/authorizations/{authorization_id}:
// the payload the consent screen renders.
//
// It has a side effect by design (upstream does the same): it claims the pending
// authorization for the signed-in user and, when that user has already consented
// to at least the requested scopes for this client, approves it right away and
// answers with {"redirect_url": …} instead of a consent payload — the "don't ask
// twice" path.
func (a *api) oauthGetAuthorization(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if err := a.validateRequestOrigin(r); err != nil {
		return err
	}
	user := userFrom(ctx)
	if user == nil {
		return forbiddenError(ErrorCodeBadJWT, "authentication required")
	}
	// Opening the request claims it and may approve it outright (an earlier
	// consent, a first-party client), so it needs the same assurance as
	// approving.
	if err := a.requireConsentAAL(ctx, user); err != nil {
		return err
	}

	authorizationID := chi.URLParam(r, "authorization_id")
	if authorizationID == "" {
		return badRequestError(ErrorCodeValidationFailed, "authorization_id is required")
	}

	var (
		authorization *oauthAuthorization
		client        *oauthClient
		autoApproved  bool
	)
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		o, err := a.lockPendingAuthorization(ctx, tx, authorizationID, "authorization request cannot be processed")
		if err != nil {
			return err
		}

		switch {
		case o.UserID == nil:
			if err := setOAuthAuthorizationUser(ctx, tx, o.ID, user.ID); err != nil {
				return internalServerError("error claiming authorization").withInternal(err)
			}
			o.UserID = &user.ID

			consent, cerr := findActiveOAuthConsent(ctx, tx, user.ID, o.ClientID)
			if cerr != nil {
				return internalServerError("error finding consent").withInternal(cerr)
			}
			if consent != nil && consent.HasAllScopes(o.GetScopeList()) {
				autoApproved = true
			}
		case *o.UserID != user.ID:
			// Never reveal that the authorization exists to anybody but its owner.
			a.log.WarnContext(ctx, "auth: oauth authorization belongs to a different user",
				"request_user_id", user.ID, "authorization_id", o.AuthorizationID)
			return notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found")
		}

		// The client is needed either way: for the consent screen's details,
		// or to learn that it is first-party and skips that screen. A
		// first-party client is approved whenever its owner opens the page,
		// including a reload of a request claimed earlier, and no consent row
		// is written — there was no consent to record.
		if !autoApproved {
			c, cerr := a.oauthClientByID(ctx, tx, o.ClientID)
			if cerr != nil {
				if isNoRows(cerr) {
					return notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found")
				}
				return internalServerError("error finding client").withInternal(cerr)
			}
			client = c
			autoApproved = c.isFirstParty()
		}

		if autoApproved {
			if err := approveOAuthAuthorization(ctx, tx, o, a.now()); err != nil {
				return internalServerError("Error auto-approving authorization").withInternal(err)
			}
		}
		authorization = o
		return nil
	}); err != nil {
		return err
	}

	if autoApproved {
		return sendJSON(w, http.StatusOK, ConsentResponse{RedirectURL: buildSuccessRedirectURL(authorization)})
	}

	return sendJSON(w, http.StatusOK, AuthorizationDetailsResponse{
		AuthorizationID: authorization.AuthorizationID,
		RedirectURI:     authorization.RedirectURI,
		Client:          clientDetails(client),
		User:            UserDetailsResponse{ID: user.ID, Email: user.Email},
		Scope:           authorization.Scope,
	})
}

// oauthConsent handles POST /oauth/authorizations/{authorization_id}/consent.
//
// approve: the row becomes `approved` and mints its single-use authorization
// code, the consent is stored (so the next authorization for the same scopes
// skips this screen), and the caller receives the redirect URL carrying
// ?code=&state=.
//
// deny: the row becomes `denied` and the caller receives the RFC 6749 error
// redirect (?error=access_denied) — a denial is reported to the CLIENT, not to
// the browser as an error page.
func (a *api) oauthConsent(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	if err := a.validateRequestOrigin(r); err != nil {
		return err
	}
	user := userFrom(ctx)
	if user == nil {
		return forbiddenError(ErrorCodeBadJWT, "authentication required")
	}

	body := &ConsentRequest{}
	if err := decodeBody(r, body); err != nil {
		return err
	}
	if body.Action != OAuthConsentActionApprove && body.Action != OAuthConsentActionDeny {
		return badRequestError(ErrorCodeValidationFailed, "action must be 'approve' or 'deny'")
	}
	// Denying gives nothing away, so only approving needs the step-up.
	if body.Action == OAuthConsentActionApprove {
		if err := a.requireConsentAAL(ctx, user); err != nil {
			return err
		}
	}

	authorizationID := chi.URLParam(r, "authorization_id")
	if authorizationID == "" {
		return badRequestError(ErrorCodeValidationFailed, "authorization_id is required")
	}

	var redirectURL string
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		o, err := a.lockPendingAuthorization(ctx, tx, authorizationID, "authorization request is no longer pending")
		if err != nil {
			return err
		}
		if o.UserID == nil || *o.UserID != user.ID {
			a.log.WarnContext(ctx, "auth: oauth authorization belongs to a different user",
				"request_user_id", user.ID, "authorization_id", o.AuthorizationID)
			return notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found")
		}

		now := a.now()
		if body.Action == OAuthConsentActionApprove {
			if err := approveOAuthAuthorization(ctx, tx, o, now); err != nil {
				return internalServerError("error approving authorization").withInternal(err)
			}
			if err := upsertOAuthConsent(ctx, tx, user.ID, o.ClientID, o.GetScopeList(), now); err != nil {
				return internalServerError("error storing consent").withInternal(err)
			}
			redirectURL = buildSuccessRedirectURL(o)
			return nil
		}

		if err := setOAuthAuthorizationStatus(ctx, tx, o.ID, OAuthAuthorizationDenied); err != nil {
			return internalServerError("error denying authorization").withInternal(err)
		}
		redirectURL = buildErrorRedirectURL(o.RedirectURI, oAuth2ErrorAccessDenied, "User denied the request", deref(o.State))
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, ConsentResponse{RedirectURL: redirectURL})
}

// requireConsentAAL asks an MFA user for an aal2 session before an
// application is authorized for them. Signing in to the application hands it
// the account, so a password alone must not be enough where a second factor
// exists. DEVIATION: upstream's OAuth server does not check the AAL here.
func (a *api) requireConsentAAL(ctx context.Context, user *User) error {
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	needed, err := a.stepUpRequired(ctx, pool, user)
	if err != nil {
		return err
	}
	if needed {
		return forbiddenError(ErrorCodeInsufficientAAL,
			"AAL2 session is required to authorize an application when MFA is enabled")
	}
	return nil
}

// lockPendingAuthorization loads an authorization FOR UPDATE and enforces the
// three states the consent flow accepts it in. An expired row is marked
// `expired` and reported as not-found, with the marking COMMITTED even though
// the request fails (commitAndFail) — the status must not silently roll back.
//
// notPendingMsg is the message for a row that exists but has already been
// decided; upstream words it differently on the two endpoints.
func (a *api) lockPendingAuthorization(ctx context.Context, tx querier, authorizationID, notPendingMsg string) (*oauthAuthorization, error) {
	o, err := findOAuthAuthorizationForUpdate(ctx, tx, authorizationID)
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found")
		}
		return nil, internalServerError("error finding authorization").withInternal(err)
	}
	if o.IsExpired(a.now()) {
		if o.Status == OAuthAuthorizationPending {
			if merr := setOAuthAuthorizationStatus(ctx, tx, o.ID, OAuthAuthorizationExpired); merr != nil {
				a.log.WarnContext(ctx, "auth: failed to mark authorization as expired", "error", merr.Error())
				return nil, notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found")
			}
		}
		return nil, commitAndFail(notFoundError(ErrorCodeOAuthAuthorizationNotFound, "authorization not found"))
	}
	if o.Status != OAuthAuthorizationPending {
		return nil, badRequestError(ErrorCodeValidationFailed, "%s", notPendingMsg)
	}
	return o, nil
}

// ---- the user's own grants -------------------------------------------------

// userListOAuthGrants handles GET /user/oauth/grants: every live consent of the
// signed-in user, newest first. Clients that have since been deleted are
// skipped rather than failing the whole listing.
func (a *api) userListOAuthGrants(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := userFrom(ctx)
	if user == nil {
		return forbiddenError(ErrorCodeBadJWT, "authentication required")
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	consents, err := listActiveOAuthConsents(ctx, pool, user.ID)
	if err != nil {
		return internalServerError("Error fetching OAuth grants").withInternal(err)
	}

	grants := make([]UserOAuthGrantResponse, 0, len(consents))
	for _, consent := range consents {
		client, cerr := a.oauthClientByID(ctx, pool, consent.ClientID)
		if cerr != nil {
			if isNoRows(cerr) {
				continue
			}
			return internalServerError("Error fetching client details").withInternal(cerr)
		}
		grants = append(grants, UserOAuthGrantResponse{
			Client:    clientDetails(client),
			Scopes:    consent.GetScopeList(),
			GrantedAt: consent.GrantedAt,
		})
	}
	return sendJSON(w, http.StatusOK, grants)
}

// userRevokeOAuthGrant handles DELETE /user/oauth/grants?client_id=…: the
// consent is revoked AND every session the user holds with that client is
// destroyed, which invalidates its refresh tokens immediately.
func (a *api) userRevokeOAuthGrant(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := userFrom(ctx)
	if user == nil {
		return forbiddenError(ErrorCodeBadJWT, "authentication required")
	}

	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	if clientID == "" {
		return badRequestError(ErrorCodeValidationFailed, "client_id query parameter is required")
	}
	if _, err := uuid.Parse(clientID); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "invalid client_id format")
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		revoked, err := revokeOAuthConsent(ctx, tx, user.ID, clientID, a.now())
		if err != nil {
			return internalServerError("Error revoking grant").withInternal(err)
		}
		if !revoked {
			return notFoundError(ErrorCodeOAuthConsentNotFound, "No active grant found for this client")
		}
		if err := revokeOAuthSessions(ctx, tx, user.ID, clientID); err != nil {
			return internalServerError("Error revoking OAuth sessions").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
