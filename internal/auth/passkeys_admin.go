package auth

// The admin half of the passkey surface (upstream
// internal/api/passkey_admin.go).
//
//	GET    /admin/users/{user_id}/passkeys                -> [PasskeyListItem, ...]
//	DELETE /admin/users/{user_id}/passkeys/{passkey_id}   -> 204
//
// Mounted from THIS file rather than from the core /admin/users route group in
// auth.go, so the passkey feature stays self-contained — the same arrangement
// admin_factors.go uses. chi resolves these parameterised paths alongside the
// /admin/users subrouter.
//
// Two deliberate differences from the user-facing surface, both upstream's:
//
//   - there is NO requirePasskeyEnabled gate here. Upstream mounts the admin
//     routes under /admin, outside the /passkeys group the gate lives on, so an
//     operator can still LIST and REVOKE credentials after the feature has been
//     switched off — which is exactly when revocation matters most.
//   - there is NO AAL2 requirement. An operator removing a lost authenticator on
//     a user's behalf is precisely the case the user-facing rule cannot serve.
//
// Upstream has no admin PATCH: renaming is the user's business.

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/internal/audit"
)

func init() {
	registerFeature("admin_passkeys", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.Get("/admin/users/{user_id}/passkeys", a.handle(a.adminPasskeyList))
			r.Delete("/admin/users/{user_id}/passkeys/{passkey_id}", a.handle(a.adminPasskeyDelete))
		})
	})
}

// adminPasskeyList implements GET /admin/users/{user_id}/passkeys.
func (a *api) adminPasskeyList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	creds, derr := findPasskeysByUserID(ctx, pool, u.ID)
	if derr != nil {
		return internalServerError("Database error loading passkeys").withInternal(derr)
	}

	// The listing itself carries no personal-data VALUE (no credential id, no
	// public key — see PasskeyListItem), but it is a read of one identified
	// user's account contents, so it is recorded like the other admin reads
	// (project.md §5.1: the fact, not the value).
	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserDetailRead,
		Resource:    auditResourceUser(u.ID) + "/passkeys",
		AccessLevel: audit.AccessFull,
		ResultCount: len(creds),
		SubjectIDs:  []string{u.ID},
	})
	return sendJSON(w, http.StatusOK, toPasskeyListItems(creds))
}

// adminPasskeyDelete implements DELETE
// /admin/users/{user_id}/passkeys/{passkey_id}. Like the user-facing delete it
// answers 204 with an empty body (upstream AdminPasskeyDelete).
func (a *api) adminPasskeyDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}
	passkeyID, perr := passkeyIDParam(r)
	if perr != nil {
		return perr
	}

	pool, derr := a.db(ctx)
	if derr != nil {
		return derr
	}
	// Scoped to the target user: an operator cannot delete a credential of user
	// B through user A's URL.
	cred, cerr := findPasskeyByIDAndUserID(ctx, pool, passkeyID, u.ID)
	if cerr != nil {
		if isNoRows(cerr) {
			return notFoundError(ErrorCodeValidationFailed, "Passkey not found")
		}
		return internalServerError("Database error loading passkey").withInternal(cerr)
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if err := deletePasskey(ctx, tx, cred.ID); err != nil {
			return internalServerError("Database error deleting passkey").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserUpdated,
		Resource:    auditResourceUser(u.ID) + "/passkeys:" + cred.ID,
		AccessLevel: audit.AccessFull,
		ResultCount: 1,
		SubjectIDs:  []string{u.ID},
	})

	w.WriteHeader(http.StatusNoContent)
	return nil
}
