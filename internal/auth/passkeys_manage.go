package auth

// The user-facing passkey management surface — GET /passkeys,
// PATCH /passkeys/{passkey_id}, DELETE /passkeys/{passkey_id}.
//
// Reproduces github.com/supabase/auth/internal/api/passkey_manage.go.
//
// # What is deliberately NOT here
//
// Upstream imposes NO "you must keep at least one credential" rule and NO
// password re-check on DELETE: a user may delete their last passkey, and may do
// so without re-entering a password. The only gate is
// requirePasskeyManagementAAL (an AAL2 session once the account has a verified
// MFA factor). Matched exactly — inventing a last-credential rule would diverge
// from gotrue-js's expectations, and an account that keeps an email/password or
// OTP login is not locked out by losing its last passkey anyway.
//
// Upstream also carries a TODO(fm) noting that these operations should refuse to
// touch credentials that back an MFA WebAuthn factor. That cannot happen in
// Dilion: MFA factors live in auth.mfa_factors and are never returned by any
// query in passkey_models.go, so the two credential sets are disjoint.

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PasskeyListItem is one entry of GET /passkeys and the body of a successful
// PATCH (upstream api.PasskeyListItem). The credential id, the public key and
// the sign counter are deliberately absent — a client has no use for them and
// they are the parts worth not echoing.
type PasskeyListItem struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// PasskeyUpdateParams is the PATCH /passkeys/{passkey_id} body.
type PasskeyUpdateParams struct {
	FriendlyName string `json:"friendly_name"`
}

func toPasskeyListItem(c *passkeyCredential) PasskeyListItem {
	return PasskeyListItem{
		ID:           c.ID,
		FriendlyName: c.FriendlyName,
		CreatedAt:    c.CreatedAt,
		LastUsedAt:   c.LastUsedAt,
	}
}

func toPasskeyListItems(creds []*passkeyCredential) []PasskeyListItem {
	// Never nil: upstream's make([]PasskeyListItem, len(creds)) serialises an
	// empty list as `[]`, not `null`.
	items := make([]PasskeyListItem, len(creds))
	for i, c := range creds {
		items[i] = toPasskeyListItem(c)
	}
	return items
}

// ---- GET /passkeys ---------------------------------------------------------

// passkeyList implements upstream PasskeyList: the bare array of the
// authenticated user's passkeys, oldest first.
func (a *api) passkeyList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)

	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	creds, derr := findPasskeysByUserID(ctx, pool, u.ID)
	if derr != nil {
		return internalServerError("Database error loading passkeys").withInternal(derr)
	}
	return sendJSON(w, http.StatusOK, toPasskeyListItems(creds))
}

// ---- PATCH /passkeys/{passkey_id} ------------------------------------------

// passkeyUpdate implements upstream PasskeyUpdate: rename a passkey.
//
// Note the absence of an AAL2 gate — upstream requires one for registration and
// deletion but not for a rename, because a rename cannot change which
// credentials can sign in.
func (a *api) passkeyUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)

	passkeyID, err := passkeyIDParam(r)
	if err != nil {
		return err
	}

	params := &PasskeyUpdateParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}
	if params.FriendlyName == "" {
		return badRequestError(ErrorCodeValidationFailed, "friendly_name is required")
	}
	if len(params.FriendlyName) > passkeyFriendlyNameMaxLength {
		return badRequestError(ErrorCodeValidationFailed, "friendly_name must be 120 characters or less")
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	cred, cerr := findPasskeyByIDAndUserID(ctx, pool, passkeyID, u.ID)
	if cerr != nil {
		if isNoRows(cerr) {
			return notFoundError(ErrorCodeValidationFailed, "Passkey not found")
		}
		return internalServerError("Database error loading passkey").withInternal(cerr)
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if uerr := updatePasskeyFriendlyName(ctx, tx, cred.ID, params.FriendlyName, now); uerr != nil {
			return internalServerError("Database error updating passkey").withInternal(uerr)
		}
		return nil
	}); err != nil {
		return err
	}
	cred.FriendlyName = params.FriendlyName
	cred.UpdatedAt = now

	return sendJSON(w, http.StatusOK, toPasskeyListItem(cred))
}

// ---- DELETE /passkeys/{passkey_id} -----------------------------------------

// passkeyDelete implements upstream PasskeyDelete: 204 No Content, empty body.
func (a *api) passkeyDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)

	passkeyID, err := passkeyIDParam(r)
	if err != nil {
		return err
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	if err := a.requirePasskeyManagementAAL(ctx, pool, u); err != nil {
		return err
	}

	cred, cerr := findPasskeyByIDAndUserID(ctx, pool, passkeyID, u.ID)
	if cerr != nil {
		if isNoRows(cerr) {
			return notFoundError(ErrorCodeValidationFailed, "Passkey not found")
		}
		return internalServerError("Database error loading passkey").withInternal(cerr)
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if derr := deletePasskey(ctx, tx, cred.ID); derr != nil {
			return internalServerError("Database error deleting passkey").withInternal(derr)
		}
		return nil
	}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// passkeyIDParam reads {passkey_id}. Upstream answers a malformed id with 404
// (not 400) so an id that cannot exist and an id that does not exist are
// indistinguishable.
func passkeyIDParam(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "passkey_id")
	if _, err := uuid.Parse(raw); err != nil {
		return "", notFoundError(ErrorCodeValidationFailed, "Passkey not found")
	}
	return raw, nil
}
