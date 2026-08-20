package auth

// GET /oauth/userinfo — the OIDC UserInfo endpoint (OIDC Core §5.3), upstream
// internal/api/oauthserver/handlers.go OAuthUserInfo.
//
// The caller presents an ACCESS TOKEN (not an id_token) as a Bearer credential.
// What comes back is filtered by the scopes that were granted to the session the
// token was issued for — the scopes live on auth.sessions.scopes, written when
// the authorization-code grant created the session, so a token cannot widen its
// own claims.
//
// A token that belongs to no OAuth session (an ordinary Supabase sign-in) is
// answered with the bare `sub` claim, which is upstream's behaviour: the
// endpoint is a scope-filtered view, not a second GET /user.

import (
	"net/http"
)

// oauthUserInfo handles GET /oauth/userinfo.
func (a *api) oauthUserInfo(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	user := userFrom(ctx)
	if user == nil {
		return forbiddenError(ErrorCodeBadJWT, "authentication required")
	}

	// `sub` is required by the spec and is the only claim that is always present.
	userInfo := map[string]any{"sub": user.ID}

	sessionID := sessionIDFrom(claimsFrom(ctx))
	if sessionID == "" {
		return sendJSON(w, http.StatusOK, userInfo)
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	meta, err := findOAuthSessionMeta(ctx, pool, sessionID)
	if err != nil {
		if isNoRows(err) {
			return sendJSON(w, http.StatusOK, userInfo)
		}
		return internalServerError("Error loading session").withInternal(err)
	}
	scopes := parseScopeString(deref(meta.Scopes))
	if len(scopes) == 0 {
		return sendJSON(w, http.StatusOK, userInfo)
	}

	if hasScope(scopes, ScopeEmail) {
		if user.Email != "" {
			userInfo["email"] = user.Email
		}
		if user.EmailConfirmedAt != nil {
			userInfo["email_verified"] = true
		}
	}

	if hasScope(scopes, ScopeProfile) {
		if name := metaString(user.UserMetaData, "name"); name != "" {
			userInfo["name"] = name
		} else if user.Email != "" {
			userInfo["name"] = user.Email
		}
		if picture := metaString(user.UserMetaData, "picture"); picture != "" {
			userInfo["picture"] = picture
		} else if avatar := metaString(user.UserMetaData, "avatar_url"); avatar != "" {
			userInfo["picture"] = avatar
		}
		if username := metaString(user.UserMetaData, "preferred_username"); username != "" {
			userInfo["preferred_username"] = username
		} else if username := metaString(user.UserMetaData, "username"); username != "" {
			userInfo["preferred_username"] = username
		}
		if user.UpdatedAt.Unix() > 0 {
			userInfo["updated_at"] = user.UpdatedAt.Unix()
		}
		if user.UserMetaData != nil {
			userInfo["user_metadata"] = user.UserMetaData
		}
	}

	if hasScope(scopes, ScopePhone) {
		if user.Phone != "" {
			userInfo["phone"] = user.Phone
		}
		if user.PhoneConfirmedAt != nil {
			userInfo["phone_verified"] = true
		}
	}

	return sendJSON(w, http.StatusOK, userInfo)
}
