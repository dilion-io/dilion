package auth

import (
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/bytemare/opaque"
	"github.com/dilion-project/dilion/ports"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type opaqueSignupParams struct {
	Email      string          `json:"email"`
	Request    string          `json:"registration_request"`
	Data       map[string]any  `json:"data"`
	RedirectTo string          `json:"redirect_to"`
	Security   captchaSecurity `json:"gotrue_meta_security"`
}

// These inputs are authenticated inside the encrypted two-minute handshake.
// Finish accepts no email/user ID/metadata/policy overrides from the caller.
type opaqueSignupState struct {
	Email       string
	Aud         string
	Data        map[string]any
	RedirectTo  string
	Autoconfirm bool
}

type opaqueSignupResponse struct {
	User                 *User                `json:"user"`
	Session              *AccessTokenResponse `json:"session"` // always null: registration is not AKE
	ConfirmationRequired bool                 `json:"confirmation_required"`
}

func (a *api) opaqueSignupAllowed() error {
	if a.cfg.DisableSignup {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
	}
	if !a.cfg.External[ProviderEmail].Enabled {
		return unprocessableEntityError(ErrorCodeEmailProviderDisabled, "Email signups are disabled")
	}
	return nil
}

func opaqueSignupEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 320 {
		return "", badRequestError(ErrorCodeValidationFailed, "Invalid email address")
	}
	return email, nil
}

func (a *api) opaqueSignupStart(w http.ResponseWriter, r *http.Request) error {
	if err := a.opaqueSignupAllowed(); err != nil {
		return err
	}
	if err := a.verifyCaptcha(r); err != nil {
		return err
	}
	var p opaqueSignupParams
	if err := decodeOpaqueBody(r, &p); err != nil {
		return err
	}
	var err error
	p.Email, err = opaqueSignupEmail(p.Email)
	if err != nil {
		return err
	}
	data, err := opaqueBytes(p.Request)
	if err != nil {
		return err
	}
	if p.Data == nil {
		p.Data = map[string]any{}
	}
	ctx := r.Context()
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	// Separate shared signup budget; do not consume the account's login budget.
	account := opaqueEncode(a.opaqueMAC(ctx, "signup-rate", []byte(requestAud(r)+":"+p.Email)))
	var attempts int
	err = pool.QueryRow(ctx, `insert into auth.opaque_attempts(scope,account,window_start,attempts) values($1,$2,$3,1)
 on conflict(scope,account) do update set attempts=case when auth.opaque_attempts.window_start<=$3-interval '1 minute' then 1 else least(auth.opaque_attempts.attempts+1,11) end,
 window_start=case when auth.opaque_attempts.window_start<=$3-interval '1 minute' then $3 else auth.opaque_attempts.window_start end returning attempts`, opaqueScope(ctx), account, a.now()).Scan(&attempts)
	if err != nil {
		return opaqueDB(err)
	}
	if attempts > 10 {
		return tooManyRequestsError("Too many signup attempts")
	}
	server, serverID, err := a.opaqueServer(ctx, pool)
	if err != nil {
		return opaqueDB(err)
	}
	defer server.ServerKeyMaterial.Flush()
	request, err := server.Deserialize.RegistrationRequest(data)
	if err != nil {
		return opaqueInvalid()
	}
	payload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider": ProviderEmail, "authentication_method": "opaque", "email": p.Email, "phone": "", "user_metadata": p.Data, "project_id": DefaultProjectID,
	})
	if err != nil {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected")
	}
	if email, ok := payload["email"].(string); ok {
		p.Email, err = opaqueSignupEmail(email)
		if err != nil {
			return err
		}
	}
	if metadata, ok := payload["user_metadata"].(map[string]any); ok && metadata != nil {
		p.Data = metadata
	}
	// No account lookup or reservation at start: abandoned ceremonies create no
	// users. Random provisional IDs make responses independent of address usage.
	userID := uuid.NewString()
	identity := opaqueEncode(a.opaqueMAC(ctx, "identity", []byte(userID)))
	response, err := server.RegistrationResponse(request, []byte(identity), nil)
	if err != nil {
		return opaqueInvalid()
	}
	state := &opaqueState{UserID: userID, Identity: identity, Signup: &opaqueSignupState{
		Email: p.Email, Aud: requestAud(r), Data: p.Data, RedirectTo: a.cfg.RedirectURLOrSiteURL(p.RedirectTo), Autoconfirm: a.cfg.Mailer.Autoconfirm,
	}}
	id, err := a.putOpaqueState(ctx, "signup", state)
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, map[string]any{"suite": opaqueSuite, "handshake_id": id, "client_identity": identity, "server_identity": serverID, "registration_response": opaqueEncode(response.Serialize())})
}

func (a *api) opaqueSignupFinish(w http.ResponseWriter, r *http.Request) error {
	var p struct {
		ID     string `json:"handshake_id"`
		Record string `json:"registration_record"`
	}
	if err := decodeOpaqueBody(r, &p); err != nil {
		return err
	}
	ctx := r.Context()
	state, err := a.takeOpaqueState(ctx, "signup", p.ID)
	if err != nil {
		return err
	}
	if err := a.opaqueSignupAllowed(); err != nil {
		return err
	}
	signup := state.Signup
	if signup == nil || signup.Aud != requestAud(r) || signup.Autoconfirm != a.cfg.Mailer.Autoconfirm {
		return opaqueInvalid()
	}
	data, err := opaqueBytes(p.Record)
	if err != nil {
		return err
	}
	deserializer, err := opaque.DefaultConfiguration().Deserializer()
	if err != nil {
		return opaqueInvalid()
	}
	if _, err := deserializer.RegistrationRecord(data); err != nil {
		return opaqueInvalid()
	}
	now := a.now()
	// For confirmation-required signup, always return a fabricated user with
	// request metadata, never an existing account's UUID, status or identities.
	reply := &opaqueSignupResponse{User: sanitizedSignupUser(&SignupParams{Email: signup.Email, Data: signup.Data}, signup.Aud, now), ConfirmationRequired: !signup.Autoconfirm}
	var created *User
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		existing, err := findUserByEmail(ctx, tx, signup.Email, signup.Aud)
		if err != nil && !isNoRows(err) {
			return opaqueDB(err)
		}
		if existing != nil {
			// Never overwrite ANY existing credential, including unconfirmed users.
			// A duplicate request does not send mail; use the existing /resend flow.
			if signup.Autoconfirm {
				return unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
			}
			return nil
		}
		appMeta := JSONMap{"provider": ProviderEmail, "providers": []any{ProviderEmail}}
		if err := a.runBeforeUserCreated(ctx, tx, &User{ID: state.UserID, Aud: signup.Aud, Role: RoleAuthenticated, Email: signup.Email, AppMetaData: appMeta, UserMetaData: JSONMap(signup.Data), Identities: []Identity{}, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		var confirmed *time.Time
		if signup.Autoconfirm {
			confirmed = &now
		}
		user, err := insertUser(ctx, tx, newUserParams{ID: state.UserID, Aud: signup.Aud, Role: RoleAuthenticated, Email: signup.Email,
			EncryptedPassword: nil, EmailConfirmedAt: confirmed, AppMetaData: appMeta, UserMetaData: JSONMap(signup.Data), Now: now})
		if err != nil {
			return opaqueDB(err)
		}
		if err := insertIdentity(ctx, tx, user.ID, ProviderEmail, user.ID, JSONMap{"sub": user.ID, "email": user.Email, "email_verified": signup.Autoconfirm, "phone_verified": false}, now); err != nil {
			return opaqueDB(err)
		}
		version := uuid.NewString()
		if _, err := tx.Exec(ctx, `insert into auth.opaque_credentials(user_id,scope,version,identity,record) values($1,$2,$3,$4,$5)`, user.ID, opaqueScope(ctx), version, state.Identity, a.sealOpaque(ctx, "record:"+version, data)); err != nil {
			return opaqueDB(err)
		}
		if !signup.Autoconfirm {
			// Reuse confirmation tokens, delivery hooks, redirect allow-list and
			// /verify. Missing delivery configuration must not strand a new user.
			if a.mailer == nil && !a.cfg.Hooks.SendEmail.Enabled {
				return internalServerError("Email delivery must be configured for OPAQUE signup")
			}
			if _, err := a.sendConfirmation(ctx, tx, r, user, signup.RedirectTo, false); err != nil {
				return err
			}
		}
		created, err = a.loadUserWithIdentities(ctx, tx, user.ID)
		if err != nil {
			return opaqueDB(err)
		}
		if signup.Autoconfirm {
			reply.User = created
		}
		return nil
	})
	if err != nil {
		// Another signup (including the legacy route) can win the unique email
		// index race. Never expose it when confirmation is required, nor retry by
		// updating that account. The losing transaction has fully rolled back.
		if isUniqueViolation(err, "users_email_partial_key") {
			if signup.Autoconfirm {
				return unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
			}
			return sendJSON(w, http.StatusOK, reply)
		}
		return err
	}
	if created != nil {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{"user_id": created.ID, "email": created.Email, "provider": ProviderEmail, "authentication_method": "opaque", "project_id": DefaultProjectID})
		a.observeAfterUserCreated(ctx, created)
	}
	return sendJSON(w, http.StatusOK, reply)
}
