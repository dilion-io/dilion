package auth

import (
	"fmt"
	"math"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/ports"
)

// defaultPerPage matches gotrue's admin listing default.
const defaultPerPage int64 = 50

// Reserved roles are machine credentials, not attributes an auth.users row may
// acquire through the human-user administration API. Allowing either role here
// turns the next password/refresh grant into an authorization bypass.
func validateAdminUserRole(role string) (string, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return RoleAuthenticated, nil
	}
	switch strings.ToLower(role) {
	case RoleServiceRole, "supabase_admin":
		return "", badRequestError(ErrorCodeValidationFailed,
			"Role %q is reserved for machine credentials", role)
	default:
		return role, nil
	}
}

// userTokenRole sanitises legacy rows at every user-token issuance boundary.
func userTokenRole(role string) string {
	normalized, err := validateAdminUserRole(role)
	if err != nil {
		return RoleAuthenticated
	}
	return normalized
}

// AdminUserParams is the POST/PUT /admin/users body (wave-1 subset).
type AdminUserParams struct {
	ID           string         `json:"id"`
	Aud          string         `json:"aud"`
	Role         string         `json:"role"`
	Email        string         `json:"email"`
	Phone        string         `json:"phone"`
	Password     *string        `json:"password"`
	EmailConfirm bool           `json:"email_confirm"`
	PhoneConfirm bool           `json:"phone_confirm"`
	UserMetaData map[string]any `json:"user_metadata"`
	AppMetaData  map[string]any `json:"app_metadata"`
	BanDuration  string         `json:"ban_duration"`
}

// AdminUserDeleteParams is the optional DELETE /admin/users/{user_id} body.
type AdminUserDeleteParams struct {
	ShouldSoftDelete bool `json:"should_soft_delete"`
}

// loadAdminTargetUser resolves {user_id} into a user, gotrue-style.
func (a *api) loadAdminTargetUser(r *http.Request) (*User, error) {
	raw := chi.URLParam(r, "user_id")
	if _, err := uuid.Parse(raw); err != nil {
		return nil, notFoundError(ErrorCodeValidationFailed, "user_id must be an UUID")
	}
	pool, perr := a.db(r.Context())
	if perr != nil {
		return nil, perr
	}
	u, err := a.loadUserWithIdentities(r.Context(), pool, raw)
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeUserNotFound, "User not found")
		}
		return nil, internalServerError("Database error loading user").withInternal(err)
	}
	// Reading an account is users.admin's alone; changing one also needs
	// every permission the account holds (mayAdminister).
	if r.Method != http.MethodGet {
		if err := a.mayAdminister(r.Context(), u.ID); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// adminListUsers implements GET /admin/users with gotrue's page/per_page
// pagination: the body carries {"users":[...],"aud":"..."} and the page links
// live in the Link / X-Total-Count headers.
func (a *api) adminListUsers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	aud := requestAud(r)

	page, perPage, err := paginationParams(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	total, cerr := countUsers(ctx, pool, aud)
	if cerr != nil {
		return internalServerError("Database error finding users").withInternal(cerr)
	}

	users, lerr := listUsers(ctx, pool, aud, perPage, (page-1)*perPage)
	if lerr != nil {
		return internalServerError("Database error finding users").withInternal(lerr)
	}
	for _, u := range users {
		ids, ierr := findIdentitiesByUserID(ctx, pool, u.ID)
		if ierr != nil {
			return internalServerError("Database error finding identities").withInternal(ierr)
		}
		u.Identities = ids
	}

	addPaginationHeaders(w, r, page, perPage, total)

	// §5.3 manifest: the ids actually returned on this page, so "who read the
	// record of user X" stays answerable. AccessFull — unlike the masked
	// management plane, this surface returns real email addresses.
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserListRead,
		Resource:    auditResourceUsers,
		AccessLevel: audit.AccessFull,
		ResultCount: len(users),
		SubjectIDs:  ids,
	})

	return sendJSON(w, http.StatusOK, AdminListUsersResponse{Users: users, Aud: aud})
}

func paginationParams(r *http.Request) (page, perPage int64, err error) {
	page, perPage = 1, defaultPerPage
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		p, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil || p < 1 {
			return 0, 0, badRequestError(ErrorCodeValidationFailed, "Bad Pagination Parameters: invalid page")
		}
		page = p
	}
	if v := q.Get("per_page"); v != "" {
		p, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil || p < 1 {
			return 0, 0, badRequestError(ErrorCodeValidationFailed, "Bad Pagination Parameters: invalid per_page")
		}
		perPage = p
	}
	// Upstream takes any per_page; one request may still not read the whole
	// user table, and (page-1)*per_page must not overflow into a negative
	// offset.
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	if page > math.MaxInt64/perPage {
		return 0, 0, badRequestError(ErrorCodeValidationFailed, "Bad Pagination Parameters: invalid page")
	}
	return page, perPage, nil
}

// maxPerPage caps per_page on the admin lists.
const maxPerPage = 1000

// addPaginationHeaders reproduces gotrue's addPaginationHeaders.
func addPaginationHeaders(w http.ResponseWriter, r *http.Request, page, perPage, total int64) {
	totalPages := total / perPage
	if total%perPage > 0 {
		totalPages++
	}

	u, err := url.ParseRequestURI(r.URL.String())
	if err != nil {
		return
	}
	query := u.Query()

	header := ""
	if totalPages > page {
		query.Set("page", fmt.Sprintf("%v", page+1))
		u.RawQuery = query.Encode()
		header += "<" + u.String() + ">; rel=\"next\", "
	}
	query.Set("page", fmt.Sprintf("%v", totalPages))
	u.RawQuery = query.Encode()
	header += "<" + u.String() + ">; rel=\"last\""

	w.Header().Add("Link", header)
	w.Header().Add("X-Total-Count", fmt.Sprintf("%v", total))
}

// adminGetUser implements GET /admin/users/{user_id}.
func (a *api) adminGetUser(w http.ResponseWriter, r *http.Request) error {
	u, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}
	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserDetailRead,
		Resource:    auditResourceUser(u.ID),
		AccessLevel: audit.AccessFull,
		ResultCount: 1,
		SubjectIDs:  []string{u.ID},
	})
	return sendJSON(w, http.StatusOK, u)
}

// adminCreateUser implements POST /admin/users.
func (a *api) adminCreateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &AdminUserParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	if params.Email == "" && params.Phone == "" {
		return unprocessableEntityError(ErrorCodeValidationFailed, "Cannot create a user without either an email or phone")
	}
	if params.Phone != "" {
		return unprocessableEntityError(ErrorCodeValidationFailed, "Phone users are not supported")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}

	id := params.ID
	if id == "" {
		id = uuid.NewString()
	} else if _, err := uuid.Parse(id); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "ID must be a valid UUIDv4")
	} else if err := a.mayAdminister(ctx, id); err != nil {
		// Grants are keyed by user id, so a new account under the id of a
		// deleted one would inherit its roles.
		return err
	}

	aud := params.Aud
	if aud == "" {
		aud = requestAud(r)
	}
	role, rerr := validateAdminUserRole(params.Role)
	if rerr != nil {
		return rerr
	}

	var encrypted *string
	if params.Password != nil && *params.Password != "" {
		if herr := a.checkPasswordStrength(ctx, *params.Password); herr != nil {
			return herr
		}
		h, err := HashPassword(*params.Password)
		if err != nil {
			return internalServerError("Error hashing password").withInternal(err)
		}
		encrypted = &h
	}

	bannedUntil, herr := parseBanDuration(params.BanDuration, a.now())
	if herr != nil {
		return herr
	}

	now := a.now()
	var confirmedAt *time.Time
	if params.EmailConfirm {
		confirmedAt = &now
	}

	appMeta := JSONMap{"provider": ProviderEmail, "providers": []any{ProviderEmail}}
	for k, v := range params.AppMetaData {
		appMeta[k] = v
	}
	userMeta := JSONMap{}
	for k, v := range params.UserMetaData {
		userMeta[k] = v
	}

	var user *User
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var cerr error
		user, cerr = insertUser(ctx, tx, newUserParams{
			ID:                id,
			Aud:               aud,
			Role:              role,
			Email:             params.Email,
			EncryptedPassword: encrypted,
			EmailConfirmedAt:  confirmedAt,
			AppMetaData:       appMeta,
			UserMetaData:      userMeta,
			Now:               now,
		})
		if cerr != nil {
			if isUniqueViolation(cerr) {
				return unprocessableEntityError(ErrorCodeEmailExists,
					"A user with this email address has already been registered")
			}
			return internalServerError("Database error creating new user").withInternal(cerr)
		}

		identityData := JSONMap{
			"sub":            user.ID,
			"email":          params.Email,
			"email_verified": params.EmailConfirm,
			"phone_verified": false,
		}
		if ierr := insertIdentity(ctx, tx, user.ID, ProviderEmail, user.ID, identityData, now); ierr != nil {
			return internalServerError("Error creating identity").withInternal(ierr)
		}

		if bannedUntil != nil {
			if _, uerr := updateUserFields(ctx, tx, user.ID, now, map[string]any{"banned_until": *bannedUntil}); uerr != nil {
				return internalServerError("Database error updating user").withInternal(uerr)
			}
			user.BannedUntil = bannedUntil
		}

		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		user.Identities = ids
		return nil
	}); err != nil {
		return err
	}

	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserCreated,
		Resource:    auditResourceUser(user.ID),
		AccessLevel: audit.AccessNA,
		ResultCount: 1,
		SubjectIDs:  []string{user.ID},
	})

	return sendJSON(w, http.StatusOK, user)
}

// adminUpdateUser implements PUT /admin/users/{user_id}.
func (a *api) adminUpdateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	user, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}

	params := &AdminUserParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}

	now := a.now()
	set := map[string]any{}
	revokeSessions := false

	if e := strings.ToLower(strings.TrimSpace(params.Email)); e != "" && e != user.Email {
		if _, perr := mail.ParseAddress(e); perr != nil {
			return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
		}
		set["email"] = e
		if params.EmailConfirm {
			set["email_confirmed_at"] = now
		}
	} else if params.EmailConfirm && user.EmailConfirmedAt == nil {
		set["email_confirmed_at"] = now
	}

	if params.Role != "" {
		role, rerr := validateAdminUserRole(params.Role)
		if rerr != nil {
			return rerr
		}
		set["role"] = role
	}

	if params.Password != nil {
		if *params.Password == "" {
			set["encrypted_password"] = nil
		} else {
			if herr := a.checkPasswordStrength(ctx, *params.Password); herr != nil {
				return herr
			}
			h, herr2 := HashPassword(*params.Password)
			if herr2 != nil {
				return internalServerError("Error hashing password").withInternal(herr2)
			}
			set["encrypted_password"] = h
		}
		revokeSessions = true
	}

	if params.BanDuration != "" {
		bannedUntil, herr := parseBanDuration(params.BanDuration, now)
		if herr != nil {
			return herr
		}
		if bannedUntil == nil {
			set["banned_until"] = nil
		} else {
			set["banned_until"] = *bannedUntil
			revokeSessions = true
		}
	}

	if params.UserMetaData != nil {
		merged := JSONMap{}
		for k, v := range user.UserMetaData {
			merged[k] = v
		}
		for k, v := range params.UserMetaData {
			if v == nil {
				delete(merged, k)
				continue
			}
			merged[k] = v
		}
		set["raw_user_meta_data"] = merged
	}
	if params.AppMetaData != nil {
		merged := JSONMap{}
		for k, v := range user.AppMetaData {
			merged[k] = v
		}
		for k, v := range params.AppMetaData {
			if v == nil {
				delete(merged, k)
				continue
			}
			merged[k] = v
		}
		set["raw_app_meta_data"] = merged
	}

	if len(set) == 0 {
		return sendJSON(w, http.StatusOK, user)
	}

	var updated *User
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var uerr error
		updated, uerr = updateUserFields(ctx, tx, user.ID, now, set)
		if uerr != nil {
			if isUniqueViolation(uerr) {
				return unprocessableEntityError(ErrorCodeEmailExists,
					"A user with this email address has already been registered")
			}
			return internalServerError("Database error updating user").withInternal(uerr)
		}
		if e, ok := set["email"].(string); ok {
			if ierr := updateIdentityData(ctx, tx, user.ID, ProviderEmail, JSONMap{
				"sub":            user.ID,
				"email":          e,
				"email_verified": params.EmailConfirm,
				"phone_verified": false,
			}, now); ierr != nil {
				return internalServerError("Error updating identity").withInternal(ierr)
			}
		}
		if revokeSessions {
			if derr := deleteUserSessions(ctx, tx, user.ID); derr != nil {
				return internalServerError("Error revoking sessions").withInternal(derr)
			}
		}
		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		updated.Identities = ids
		return nil
	}); err != nil {
		return err
	}

	// The event records that the account was changed, never which values —
	// §5.1 값이 아닌 행위.
	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserUpdated,
		Resource:    auditResourceUser(updated.ID),
		AccessLevel: audit.AccessNA,
		ResultCount: 1,
		SubjectIDs:  []string{updated.ID},
	})

	return sendJSON(w, http.StatusOK, updated)
}

// adminDeleteUser implements DELETE /admin/users/{user_id} (project.md §2.5).
//
// Everything below happens in ONE transaction:
//  1. dilion_privacy.outbox <- {"event_type":"user.deleted", ...}  (ALWAYS, first)
//  2. sessions + refresh tokens revoked
//  3. the account itself: hard delete by default, soft delete (deleted_at set,
//     email/phone obfuscated to release the unique constraints) when the body
//     carries {"should_soft_delete": true} — upstream's flag and default.
//
// External deletion is deliberately NOT awaited: the outbox row is picked up
// asynchronously by the privacy engine, so an outage in a downstream system
// cannot stall the Auth API.
func (a *api) adminDeleteUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	user, err := a.loadAdminTargetUser(r)
	if err != nil {
		return err
	}

	params := &AdminUserDeleteParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}

	// BeforeUserDelete is validating: a hook may veto the deletion.
	if _, herr := a.runHook(ctx, ports.BeforeUserDelete, map[string]any{
		"user_id": user.ID,
		"email":   user.Email,
		"soft":    params.ShouldSoftDelete,
	}); herr != nil {
		return conflictError("User deletion rejected: %v", herr)
	}

	now := a.now()

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		// (1) Outbox first, unconditionally — the compliance-deletion request
		//     must exist even if the account row is already soft-deleted.
		if oerr := insertUserDeletedOutbox(ctx, tx, user.ID, "admin"); oerr != nil {
			return internalServerError("Error recording user.deleted event").withInternal(oerr)
		}

		// (2) Sessions and refresh tokens.
		if serr := deleteUserSessions(ctx, tx, user.ID); serr != nil {
			return internalServerError("Error deleting user's sessions").withInternal(serr)
		}
		if rerr := revokeUserRefreshTokens(ctx, tx, user.ID, now); rerr != nil {
			return internalServerError("Error revoking user's refresh tokens").withInternal(rerr)
		}

		// (3) Its management-plane roles.
		if rerr := revokeUserRoleAssignments(ctx, tx, user.ID, now); rerr != nil {
			return internalServerError("Error revoking user's roles").withInternal(rerr)
		}

		// (4) The account.
		if params.ShouldSoftDelete {
			if user.DeletedAt != nil {
				return nil // already soft deleted; upstream is a no-op here
			}
			if serr := softDeleteUser(ctx, tx, user, now); serr != nil {
				return internalServerError("Error soft deleting user").withInternal(serr)
			}
			if serr := softDeleteUserIdentities(ctx, tx, user.ID, now); serr != nil {
				return internalServerError("Error soft deleting user identities").withInternal(serr)
			}
			if serr := softDeleteUserCredentials(ctx, tx, user.ID); serr != nil {
				return internalServerError("Error removing soft deleted user's credentials").withInternal(serr)
			}
			return nil
		}
		if derr := hardDeleteUser(ctx, tx, user.ID); derr != nil {
			return internalServerError("Database error deleting user").withInternal(derr)
		}
		return nil
	}); err != nil {
		return err
	}

	// Emitted only after the transaction committed: the outbox row and the
	// account deletion are the source of truth, and a fail-open audit sink must
	// never be able to roll back an erasure.
	a.emitAudit(r, auditOpts{
		Action:      audit.ActionUserDeleted,
		Resource:    auditResourceUser(user.ID),
		AccessLevel: audit.AccessNA,
		ResultCount: 1,
		SubjectIDs:  []string{user.ID},
	})

	a.observeHook(ctx, ports.AfterUserDelete, map[string]any{
		"user_id": user.ID,
		"email":   user.Email,
		"soft":    params.ShouldSoftDelete,
	})

	// Upstream answers 200 with an empty JSON object. (openapi.yaml documents a
	// UserSchema here, but the implementation sends `{}` — the implementation is
	// what clients such as supabase-js are written against.)
	return sendJSON(w, http.StatusOK, map[string]any{})
}

// parseBanDuration accepts a Go duration ("24h") or "none" to lift a ban.
func parseBanDuration(s string, now time.Time) (*time.Time, *HTTPError) {
	if s == "" {
		return nil, nil
	}
	if s == "none" {
		return nil, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, badRequestError(ErrorCodeValidationFailed, "invalid format for ban duration")
	}
	t := now.Add(d)
	return &t, nil
}
