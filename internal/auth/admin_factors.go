package auth

// The admin half of the MFA surface (upstream internal/api/admin.go:
// adminUserGetFactors / adminUserUpdateFactor / adminUserDeleteFactor).
//
//	GET    /admin/users/{user_id}/factors               -> [Factor, ...]
//	PUT    /admin/users/{user_id}/factors/{factor_id}   -> Factor (friendly_name)
//	DELETE /admin/users/{user_id}/factors/{factor_id}   -> Factor
//
// These are mounted from THIS file rather than from the core /admin/users route
// group in auth.go, so the MFA feature stays self-contained. chi resolves the
// parameterised paths registered here ahead of the catch-all of the
// `/admin/users` subrouter, so both coexist on the same router.
//
// Unlike the user-facing DELETE /factors/{id}, the admin delete has NO aal2
// requirement: an operator removing a lost authenticator is exactly the case
// the user-facing rule cannot serve.

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-project/dilion/internal/audit"
)

func init() {
	registerFeature("admin_factors", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.Get("/admin/users/{user_id}/factors", a.handle(a.adminListFactors))
			r.Put("/admin/users/{user_id}/factors/{factor_id}", a.handle(a.adminUpdateFactor))
			r.Delete("/admin/users/{user_id}/factors/{factor_id}", a.handle(a.adminDeleteFactor))
		})
	})
}

// AdminUpdateFactorParams is the PUT /admin/users/{user_id}/factors/{factor_id}
// body (upstream adminUserUpdateFactorParams).
type AdminUpdateFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	Phone        string `json:"phone"`
}

// adminLoadFactor resolves {user_id}/{factor_id} into (user, factor).
func (a *api) adminLoadFactor(r *http.Request) (*User, *Factor, error) {
	u, err := a.loadAdminTargetUser(r)
	if err != nil {
		return nil, nil, err
	}
	pool, perr := a.db(r.Context())
	if perr != nil {
		return nil, nil, perr
	}
	f, ferr := a.loadOwnedFactor(r.Context(), pool, u, chi.URLParam(r, "factor_id"))
	if ferr != nil {
		return nil, nil, ferr
	}
	return u, f, nil
}

// adminListFactors implements GET /admin/users/{user_id}/factors. Upstream
// returns the bare array of the user's factors.
func (a *api) adminListFactors(w http.ResponseWriter, r *http.Request) error {
	u, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(r.Context())
	if perr != nil {
		return perr
	}
	factors, ferr := findFactorsByUserID(r.Context(), pool, u.ID)
	if ferr != nil {
		return internalServerError("Database error loading factors").withInternal(ferr)
	}

	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserDetailRead,
		Resource:    auditResourceUser(u.ID) + "/factors",
		AccessLevel: audit.AccessFull,
		ResultCount: len(factors),
		SubjectIDs:  []string{u.ID},
	})
	return sendJSON(w, http.StatusOK, factors)
}

// adminUpdateFactor implements PUT /admin/users/{user_id}/factors/{factor_id}.
//
// Upstream accepts a `friendly_name` on any factor and, for a phone factor, a
// `phone` (re-normalized to E.164); the phone update is guarded by
// `factor.IsPhoneFactor()`, so a `phone` sent for a TOTP/webauthn factor is
// ignored.
func (a *api) adminUpdateFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u, factor, err := a.adminLoadFactor(r)
	if err != nil {
		return err
	}

	params := &AdminUpdateFactorParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}

	if name := trimName(params.FriendlyName); name != "" {
		now := a.now()
		if err := a.inTx(ctx, func(tx pgx.Tx) error {
			if uerr := updateFactorFriendlyName(ctx, tx, factor.ID, name, now); uerr != nil {
				if isUniqueViolation(uerr, "mfa_factors_user_friendly_name_unique") {
					return unprocessableEntityError(ErrorCodeMFAFactorNameConflict,
						"A factor with the friendly name %q for this user already exists", name)
				}
				return internalServerError("Database error updating factor").withInternal(uerr)
			}
			return nil
		}); err != nil {
			return err
		}
		factor.FriendlyName = name
		factor.UpdatedAt = now
	}

	// Phone re-assignment, guarded to phone factors as upstream is.
	if params.Phone != "" && factor.FactorType == FactorTypePhone {
		phone, perr := validatePhone(params.Phone)
		if perr != nil {
			return perr
		}
		now := a.now()
		if err := a.inTx(ctx, func(tx pgx.Tx) error {
			if uerr := updateFactorPhone(ctx, tx, factor.ID, phone, now); uerr != nil {
				if isUniqueViolation(uerr, "unique_phone_factor_per_user") {
					return unprocessableEntityError(ErrorCodeMFAVerifiedFactorExists,
						"A phone factor already exists for this number, unenroll to continue")
				}
				return internalServerError("Database error updating factor").withInternal(uerr)
			}
			return nil
		}); err != nil {
			return err
		}
		factor.Phone = phone
		factor.UpdatedAt = now
	}

	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserUpdated,
		Resource:    auditResourceUser(u.ID) + "/factors:" + factor.ID,
		AccessLevel: audit.AccessFull,
		ResultCount: 1,
		SubjectIDs:  []string{u.ID},
	})
	return sendJSON(w, http.StatusOK, factor)
}

// adminDeleteFactor implements DELETE /admin/users/{user_id}/factors/{factor_id}.
// Upstream echoes the deleted factor back.
func (a *api) adminDeleteFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u, factor, err := a.adminLoadFactor(r)
	if err != nil {
		return err
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		return a.downgradeAndDeleteFactor(ctx, tx, factor)
	}); err != nil {
		return err
	}

	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserUpdated,
		Resource:    auditResourceUser(u.ID) + "/factors:" + factor.ID,
		AccessLevel: audit.AccessFull,
		ResultCount: 1,
		SubjectIDs:  []string{u.ID},
	})
	return sendJSON(w, http.StatusOK, factor)
}
