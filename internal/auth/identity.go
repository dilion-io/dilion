package auth

// Identity linking: the auth.identities storage helpers the OAuth flows share,
// plus the two endpoints that manage identities explicitly.
//
//	GET    /user/identities/authorize      start an OAuth flow that LINKS the
//	                                       resulting identity to the caller
//	DELETE /user/identities/{identity_id}  unlink one identity
//
// Reproduces github.com/supabase/auth/internal/api/identity.go (LinkIdentity,
// linkIdentityToUser, DeleteIdentity) and the identity half of
// internal/models/identity.go + user.go.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("identity", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAuthentication)
			r.Get("/user/identities/authorize", a.handle(a.linkIdentity))
			r.Delete("/user/identities/{identity_id}", a.handle(a.deleteIdentity))
		})
	})
}

// ---- storage ---------------------------------------------------------------

// findIdentityByProviderID is upstream's models.FindIdentityByIdAndProvider.
// findLiveIdentity finds the identity for a provider account together with its
// user. An identity still attached to a deleted user (one erased before
// erasure released provider_id) is released on the way, the way a soft delete
// does, and reported as absent: it must neither sign anyone in to the deleted
// account nor carry the provider's profile back onto it.
func (a *api) findLiveIdentity(ctx context.Context, tx querier, sub, provider string) (*Identity, *User, error) {
	identity, err := findIdentityByProviderID(ctx, tx, sub, provider)
	if isNoRows(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, internalServerError("Database error finding identity").withInternal(err)
	}
	user, err := findUserByID(ctx, tx, identity.UserID)
	if err != nil {
		return nil, nil, internalServerError("Database error finding user").withInternal(err)
	}
	if user.DeletedAt == nil {
		return identity, user, nil
	}
	if err := releaseIdentity(ctx, tx, identity, a.now()); err != nil {
		return nil, nil, internalServerError("Database error releasing identity").withInternal(err)
	}
	return nil, nil, nil
}

func findIdentityByProviderID(ctx context.Context, q querier, providerID, provider string) (*Identity, error) {
	i, err := scanIdentity(q.QueryRow(ctx,
		`select `+identityColumns+` from auth.identities
		 where provider_id = $1 and provider = $2`, providerID, provider))
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// findIdentitiesByEmails returns every identity whose (generated) email column
// matches one of the given, already lowercased addresses.
func findIdentitiesByEmails(ctx context.Context, q querier, emails []string) ([]Identity, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx,
		`select `+identityColumns+` from auth.identities
		 where email = any($1::text[]) order by created_at, id`, emails)
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

// findUsersByEmails returns the non-SSO users owning one of the addresses.
func findUsersByEmails(ctx context.Context, q querier, emails []string, aud string) ([]*User, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `select `+userColumns+` from auth.users
		 where instance_id = $1::uuid and lower(email) = any($2::text[]) and aud = $3
		   and is_sso_user = false and deleted_at is null
		 order by created_at, id`, nilUUID, emails, aud)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// insertProviderIdentity is upstream's models.NewIdentity + Create: it stamps
// last_sign_in_at and lowercases the email inside identity_data (which is what
// the generated `email` column indexes).
func insertProviderIdentity(ctx context.Context, q querier, userID, provider, providerID string,
	data JSONMap, now time.Time) (*Identity, error) {

	data = lowercaseIdentityEmail(data)
	i, err := scanIdentity(q.QueryRow(ctx, `
		insert into auth.identities
			(provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
		values ($1, $2::uuid, $3, $4, $5, $5, $5)
		returning `+identityColumns,
		providerID, userID, data, provider, now))
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// updateProviderIdentity refreshes a returning user's identity: upstream
// updates identity_data and last_sign_in_at on every sign-in.
func updateProviderIdentity(ctx context.Context, q querier, identityID string, data JSONMap, now time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.identities
		set identity_data = $2, last_sign_in_at = $3, updated_at = $3
		where id = $1::uuid`, identityID, lowercaseIdentityEmail(data), now)
	return err
}

func deleteIdentityByID(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.identities where id = $1::uuid`, id)
	return err
}

// deleteOtherIdentities removes every identity of a user except `keepID`.
func deleteOtherIdentities(ctx context.Context, q querier, userID, keepID string) error {
	_, err := q.Exec(ctx,
		`delete from auth.identities where user_id = $1::uuid and id <> $2::uuid`, userID, keepID)
	return err
}

// findUserProviders is upstream's models.FindProvidersByUser: the user's
// providers in identity age order, which fixes app_metadata.provider.
func findUserProviders(ctx context.Context, q querier, userID string) ([]string, error) {
	rows, err := q.Query(ctx,
		`select provider from auth.identities where user_id = $1::uuid order by created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// lowercaseIdentityEmail is upstream's Identity.BeforeCreate/BeforeUpdate.
func lowercaseIdentityEmail(data JSONMap) JSONMap {
	if data == nil {
		return JSONMap{}
	}
	if email, ok := data["email"].(string); ok {
		out := JSONMap{}
		for k, v := range data {
			out[k] = v
		}
		out["email"] = strings.ToLower(email)
		return out
	}
	return data
}

// identityEmailVerified is upstream's models.Identity.IsEmailVerified: a missing
// claim counts as UNVERIFIED.
func identityEmailVerified(i Identity) bool {
	v, ok := i.IdentityData["email_verified"].(bool)
	return ok && v
}

// ---- GET /user/identities/authorize ----------------------------------------

// linkIdentity is upstream's LinkIdentity: the same flow as GET /authorize, but
// the flow state carries the caller as its linking target, so the callback binds
// the new identity to THIS user instead of resolving an account by email.
func (a *api) linkIdentity(w http.ResponseWriter, r *http.Request) error {
	if !a.cfg.Security.ManualLinkingEnabled {
		return unprocessableEntityError(ErrorCodeManualLinkingDisabled, "Manual linking is disabled")
	}
	user := userFrom(r.Context())
	if user == nil {
		return internalServerError("Could not read user")
	}
	if err := a.requireSignInMethodStepUp(r.Context(), user, sessionIDFrom(claimsFrom(r.Context()))); err != nil {
		return err
	}
	return a.startExternalProviderFlow(w, r, user)
}

// linkIdentityToUser is upstream's linkIdentityToUser: the callback branch that
// attaches the provider identity to the flow's linking target.
//
// bySubject means the provider's `sub` IS a local user id
// (ports.OIDCProvider.LinkBySubject), so its identity can belong to that user
// and no other: linking it to anyone else is refused.
func (a *api) linkIdentityToUser(ctx context.Context, tx pgx.Tx, r *http.Request,
	targetUserID string, data *userProvidedData, providerType string, bySubject bool) (*User, error) {

	now := a.now()
	target, err := a.loadUserWithIdentities(ctx, tx, targetUserID)
	if err != nil {
		if isNoRows(err) {
			return nil, unprocessableEntityError(ErrorCodeUserNotFound, "Linking target user not found")
		}
		return nil, internalServerError("Database error loading user").withInternal(err)
	}

	sub := data.Metadata.Subject
	if sub == "" {
		return nil, internalServerError("Error getting user id from external provider")
	}
	if bySubject && sub != target.ID {
		return nil, unprocessableEntityError(ErrorCodeIdentityAlreadyExists,
			"This provider's identity can only be linked to the user it names")
	}

	existing, _, err := a.findLiveIdentity(ctx, tx, sub, providerType)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.UserID == target.ID {
			return nil, unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked")
		}
		return nil, unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to another user")
	}

	identityData := data.Metadata.toMap()
	if _, err := insertProviderIdentity(ctx, tx, target.ID, providerType, sub, identityData, now); err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to another user")
		}
		return nil, internalServerError("Error creating identity").withInternal(err)
	}

	if target.Email == "" {
		promoted, perr := a.updateUserEmailFromIdentities(ctx, tx, target, now)
		if perr != nil {
			return nil, perr
		}
		target = promoted

		if !data.Metadata.EmailVerified {
			if _, serr := a.sendConfirmation(ctx, tx, r, target, a.site(ctx).SiteURL, false); serr != nil {
				return nil, serr
			}
			return nil, commitAndFail(unprocessableEntityError(ErrorCodeEmailNotConfirmed,
				"Unverified email with %v. A confirmation email has been sent to your %v email",
				providerType, providerType))
		}
		confirmed, cerr := updateUserFields(ctx, tx, target.ID, now, map[string]any{
			"email_confirmed_at": now,
			"confirmation_token": "",
			// Adding a real identity ends the anonymous phase of an account.
			"is_anonymous": false,
		})
		if cerr != nil {
			return nil, internalServerError("Error updating user").withInternal(cerr)
		}
		target = confirmed
	}

	synced, serr := a.syncAppMetaDataProviders(ctx, tx, target, now)
	if serr != nil {
		return nil, serr
	}
	ids, ierr := findIdentitiesByUserID(ctx, tx, synced.ID)
	if ierr != nil {
		return nil, internalServerError("Error loading identities").withInternal(ierr)
	}
	synced.Identities = ids
	return synced, nil
}

// ---- DELETE /user/identities/{identity_id} ---------------------------------

// deleteIdentity is upstream's DeleteIdentity.
func (a *api) deleteIdentity(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	claims := claimsFrom(ctx)
	if claims == nil {
		return internalServerError("Could not read claims")
	}
	if aud := requestAud(r); claims.Audience == "" || claims.Audience != aud {
		return forbiddenError(ErrorCodeUnexpectedAudience, "Token audience doesn't match request audience")
	}
	if user := userFrom(ctx); user != nil {
		if err := a.requireSignInMethodStepUp(ctx, user, sessionIDFrom(claims)); err != nil {
			return err
		}
	}

	identityID := chi.URLParam(r, "identity_id")
	if _, err := uuid.Parse(identityID); err != nil {
		return notFoundError(ErrorCodeValidationFailed, "identity_id must be an UUID")
	}

	user := userFrom(ctx)
	if user == nil {
		return internalServerError("Could not read user")
	}
	if len(user.Identities) <= 1 {
		return unprocessableEntityError(ErrorCodeSingleIdentityNotDeletable,
			"User must have at least 1 identity after unlinking")
	}

	var target *Identity
	for i := range user.Identities {
		if user.Identities[i].ID == identityID {
			target = &user.Identities[i]
			break
		}
	}
	if target == nil {
		return unprocessableEntityError(ErrorCodeIdentityNotFound, "Identity doesn't exist")
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if err := deleteIdentityByID(ctx, tx, target.ID); err != nil {
			return internalServerError("Database error deleting identity").withInternal(err)
		}

		refreshed, ferr := a.loadUserWithIdentities(ctx, tx, user.ID)
		if ferr != nil {
			return internalServerError("Database error loading user").withInternal(ferr)
		}
		if target.Provider == "phone" {
			if _, perr := updateUserFields(ctx, tx, refreshed.ID, now, map[string]any{
				"phone":              nil,
				"phone_confirmed_at": nil,
			}); perr != nil {
				return internalServerError("Database error updating user phone").withInternal(perr)
			}
			refreshed, ferr = a.loadUserWithIdentities(ctx, tx, user.ID)
			if ferr != nil {
				return internalServerError("Database error loading user").withInternal(ferr)
			}
		} else {
			promoted, perr := a.updateUserEmailFromIdentities(ctx, tx, refreshed, now)
			if perr != nil {
				return perr
			}
			promoted.Identities = refreshed.Identities
			refreshed = promoted
		}

		if _, serr := a.syncAppMetaDataProviders(ctx, tx, refreshed, now); serr != nil {
			return serr
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]any{})
}

// updateUserEmailFromIdentities is upstream's
// models.User.UpdateUserEmailFromIdentities: after an identity comes or goes,
// users.email must still be the address of one of the remaining identities.
//
// Identities are ranked: provider-verified email first, then unverified, then
// identities without an email at all; ties break on age. The first candidate
// whose address no other account owns is promoted. A promoted address that was
// neither verified by the provider nor covered by Mailer.Autoconfirm leaves the
// account UNCONFIRMED.
func (a *api) updateUserEmailFromIdentities(ctx context.Context, tx querier, u *User, now time.Time) (*User, error) {
	identities, err := findIdentitiesByUserID(ctx, tx, u.ID)
	if err != nil {
		return nil, internalServerError("Database error loading identities").withInternal(err)
	}
	for _, i := range identities {
		if u.Email != "" && u.Email == i.Email {
			return u, nil // the current address is still backed by an identity
		}
	}

	rank := func(i Identity) int {
		switch {
		case i.Email == "":
			return 2
		case !identityEmailVerified(i):
			return 1
		default:
			return 0
		}
	}
	sort.SliceStable(identities, func(x, y int) bool {
		ix, iy := identities[x], identities[y]
		if rx, ry := rank(ix), rank(iy); rx != ry {
			return rx < ry
		}
		if !ix.CreatedAt.Equal(iy.CreatedAt) {
			return ix.CreatedAt.Before(iy.CreatedAt)
		}
		return ix.ID < iy.ID
	})

	var primary *Identity
	for i := range identities {
		candidate := identities[i]
		if candidate.Email == "" {
			primary = &identities[i]
			break
		}
		other, ferr := findUserByEmail(ctx, tx, candidate.Email, u.Aud)
		if ferr != nil && !isNoRows(ferr) {
			return nil, internalServerError("Database error finding user").withInternal(ferr)
		}
		if other == nil || other.ID == u.ID {
			primary = &identities[i]
			break
		}
	}
	if primary == nil {
		return nil, unprocessableEntityError(ErrorCodeEmailConflictIdentityNotDeletable,
			"Unable to unlink identity due to email conflict")
	}

	set := map[string]any{"email": nullIfEmpty(primary.Email)}
	if primary.Email == "" || (!identityEmailVerified(*primary) && !a.cfg.Mailer.Autoconfirm) {
		set["email_confirmed_at"] = nil
	}
	updated, err := updateUserFields(ctx, tx, u.ID, now, set)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeEmailConflictIdentityNotDeletable,
				"Unable to unlink identity due to email conflict")
		}
		return nil, internalServerError("Database error updating user email").withInternal(err)
	}

	// Tokens and pending changes were issued against the OLD address and can no
	// longer be trusted (upstream ClearAllPendingTokens).
	if err := clearAllOneTimeTokens(ctx, tx, u.ID); err != nil {
		return nil, internalServerError("Database error clearing tokens").withInternal(err)
	}
	if _, err := updateUserFields(ctx, tx, u.ID, now, map[string]any{
		"confirmation_token":         "",
		"recovery_token":             "",
		"email_change_token_current": "",
		"email_change_token_new":     "",
		"email_change":               "",
		"reauthentication_token":     "",
	}); err != nil {
		return nil, internalServerError("Database error clearing tokens").withInternal(err)
	}
	return updated, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
