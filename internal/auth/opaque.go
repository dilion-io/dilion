package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bytemare/opaque"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const opaqueHandshakeTTL = 2 * time.Minute
const opaqueKeyTTL = 15 * time.Minute

func init() {
	registerFeature("opaque", func(a *api, r chi.Router) {
		if !a.cfg.Opaque.Enabled {
			return
		}
		r.Route("/opaque", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "no-store")
					r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
					next.ServeHTTP(w, r)
				})
			})
			r.With(a.limit(LimiterTokenPassword)).Post("/login/start", a.handle(a.opaqueLoginStart))
			r.With(a.limit(LimiterTokenPassword)).Post("/login/finish", a.handle(a.opaqueLoginFinish))
			r.With(a.limit(LimiterSignup)).Post("/signup/start", a.handle(a.opaqueSignupStart))
			r.With(a.limit(LimiterSignup)).Post("/signup/finish", a.handle(a.opaqueSignupFinish))
			r.Group(func(r chi.Router) {
				r.Use(a.requireAuthentication)
				r.With(a.limit(LimiterUser)).Post("/registration/start", a.handle(a.opaqueRegistrationStart))
				r.With(a.limit(LimiterUser)).Post("/registration/finish", a.handle(a.opaqueRegistrationFinish))
			})
		})
	})
}

type opaqueParams struct {
	Email    string          `json:"email"`
	Request  string          `json:"registration_request"`
	Record   string          `json:"registration_record"`
	ID       string          `json:"handshake_id"`
	KE1      string          `json:"ke1"`
	KE3      string          `json:"ke3"`
	Security captchaSecurity `json:"gotrue_meta_security"`
}

func decodeOpaque(r *http.Request) (*opaqueParams, error) {
	var p opaqueParams
	if err := decodeOpaqueBody(r, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func decodeOpaqueBody(r *http.Request, p any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(p); err != nil {
		return badRequestError(ErrorCodeBadJSON, "Invalid OPAQUE request")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return badRequestError(ErrorCodeBadJSON, "Invalid OPAQUE request")
	}
	return nil
}

func opaqueBytes(s string) ([]byte, error) {
	if len(s) == 0 || len(s) > 4096 {
		return nil, opaqueInvalid()
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, opaqueInvalid()
	}
	return b, nil
}
func opaqueEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func opaqueInvalid() error {
	return badRequestError(ErrorCodeInvalidCredentials, "Invalid or expired OPAQUE credentials")
}
func opaqueDB(err error) error {
	return internalServerError("OPAQUE storage unavailable").withInternal(err)
}

// Every security-relevant field is authenticated inside the ciphertext. A
// database row cannot be moved between ceremonies, instances, or IDs.
type opaqueState struct {
	Signup      *opaqueSignupState
	UserUpdated time.Time
	UserID      string
	SessionID   string
	Identity    string
	Version     string
	ClientMAC   []byte
	SessionKey  []byte
	Expires     time.Time
}

func (a *api) putOpaqueState(ctx context.Context, kind string, s *opaqueState) (string, error) {
	id := uuid.NewString()
	s.Expires = a.now().Add(opaqueHandshakeTTL)
	plain, marshalErr := json.Marshal(s)
	if marshalErr != nil {
		return "", internalServerError("Unable to encode OPAQUE state")
	}
	if len(plain) > 16<<10 {
		clear(plain)
		return "", badRequestError(ErrorCodeValidationFailed, "OPAQUE state exceeds size limit")
	}
	defer clear(plain)
	sealed := a.sealOpaque(ctx, kind+":"+id, plain)
	err := a.inTx(ctx, func(tx pgx.Tx) error {
		// Bound active state even under distributed IP spray. This short critical
		// section contains no crypto or external calls and works across replicas.
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(hashtextextended($1,0))`, "opaque-capacity:"+opaqueScope(ctx)); err != nil {
			return opaqueDB(err)
		}
		var count int
		if err := tx.QueryRow(ctx, `select count(*) from dilion_auth.opaque_handshakes where scope=$1 and expires_at>$2`, opaqueScope(ctx), a.now()).Scan(&count); err != nil {
			return opaqueDB(err)
		}
		if count >= 10000 {
			return tooManyRequestsError("OPAQUE is busy; retry later")
		}
		_, err := tx.Exec(ctx, `insert into dilion_auth.opaque_handshakes(id,scope,kind,state,expires_at) values($1,$2,$3,$4,$5)`, id, opaqueScope(ctx), kind, sealed, s.Expires)
		if err != nil {
			return opaqueDB(err)
		}
		return nil
	})
	return id, err
}

// Consume outside the issuance transaction: failed KE3, expiry, and failures
// during token issuance all burn the challenge, including across replicas.
func (a *api) takeOpaqueState(ctx context.Context, kind, id string) (*opaqueState, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, opaqueInvalid()
	}
	pool, err := a.db(ctx)
	if err != nil {
		return nil, err
	}
	var sealed []byte
	err = pool.QueryRow(ctx, `delete from dilion_auth.opaque_handshakes where id=$1 and scope=$2 and kind=$3 returning state`, id, opaqueScope(ctx), kind).Scan(&sealed)
	if isNoRows(err) {
		return nil, opaqueInvalid()
	}
	if err != nil {
		return nil, opaqueDB(err)
	}
	plain, err := a.openOpaque(ctx, kind+":"+id, sealed)
	if err != nil {
		return nil, opaqueInvalid()
	}
	defer clear(plain)
	var s opaqueState
	if err := json.Unmarshal(plain, &s); err != nil || !a.now().Before(s.Expires) {
		clear(s.SessionKey)
		clear(s.ClientMAC)
		return nil, opaqueInvalid()
	}
	return &s, nil
}

// Re-read and lock the user before making credential/session changes, so an
// account ban, password reset or deletion cannot race the final authorization.
func (a *api) opaqueUser(ctx context.Context, q querier, id string) (*User, error) {
	var locked string
	if err := q.QueryRow(ctx, `select id::text from auth.users where id=$1 for update`, id).Scan(&locked); err != nil {
		if isNoRows(err) {
			return nil, opaqueInvalid()
		}
		return nil, opaqueDB(err)
	}
	u, err := a.loadUserWithIdentities(ctx, q, id)
	if err != nil {
		return nil, opaqueDB(err)
	}
	if u.DeletedAt != nil || u.IsBanned(a.now()) || u.IsAnonymous || u.IsSSOUser || u.Email == "" || u.EmailConfirmedAt == nil {
		return nil, opaqueInvalid()
	}
	return u, nil
}

func (a *api) opaqueEnrollmentUser(ctx context.Context, q querier) (*User, error) {
	claims := claimsFrom(ctx)
	if claims == nil {
		return nil, opaqueInvalid()
	}
	u, err := a.opaqueUser(ctx, q, claims.Subject)
	if err != nil {
		return nil, err
	}
	sess, err := lockOpaqueSession(ctx, q, sessionIDFrom(claims))
	if err != nil || sess.UserID != u.ID || !a.sessionStillValid(sess, a.now()) || a.now().Sub(sess.CreatedAt) > 5*time.Minute {
		return nil, forbiddenError("reauthentication_needed", "Sign in again before OPAQUE enrollment")
	}
	if err := a.checkSinglePerUser(ctx, q, sess, nil, a.now()); err != nil {
		return nil, err
	}
	if err := a.requirePasskeyManagementAAL(ctx, q, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (a *api) opaqueRegistrationStart(w http.ResponseWriter, r *http.Request) error {
	p, err := decodeOpaque(r)
	if err != nil {
		return err
	}
	data, err := opaqueBytes(p.Request)
	if err != nil {
		return err
	}
	ctx := r.Context()
	pool, err := a.db(ctx)
	if err != nil {
		return err
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
	var user *User
	var version string
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		user, err = a.opaqueEnrollmentUser(ctx, tx)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `select version::text from dilion_auth.opaque_credentials where user_id=$1`, user.ID).Scan(&version)
		if isNoRows(err) {
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	identity := opaqueEncode(a.opaqueMAC(ctx, "identity", []byte(user.ID)))
	response, err := server.RegistrationResponse(request, []byte(identity), nil)
	if err != nil {
		return opaqueInvalid()
	}
	id, err := a.putOpaqueState(ctx, "registration", &opaqueState{UserID: user.ID, UserUpdated: user.UpdatedAt, Version: version, SessionID: sessionIDFrom(claimsFrom(ctx)), Identity: identity})
	if err != nil {
		return err
	}
	return sendJSON(w, 200, map[string]any{"suite": opaqueSuite, "handshake_id": id, "client_identity": identity, "server_identity": serverID, "registration_response": opaqueEncode(response.Serialize())})
}

func (a *api) opaqueRegistrationFinish(w http.ResponseWriter, r *http.Request) error {
	p, err := decodeOpaque(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	state, err := a.takeOpaqueState(ctx, "registration", p.ID)
	if err != nil {
		return err
	}
	if state.UserID != userFrom(ctx).ID || state.SessionID != sessionIDFrom(claimsFrom(ctx)) {
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
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		user, err := a.opaqueEnrollmentUser(ctx, tx)
		if err != nil {
			return err
		}
		if !user.UpdatedAt.Equal(state.UserUpdated) {
			return opaqueInvalid()
		}
		var current string
		err = tx.QueryRow(ctx, `select version::text from dilion_auth.opaque_credentials where user_id=$1`, user.ID).Scan(&current)
		if err != nil && !isNoRows(err) {
			return opaqueDB(err)
		}
		if current != state.Version {
			return opaqueInvalid()
		}
		// Delete+insert deliberately revokes keys tied to the previous version.
		if _, err := tx.Exec(ctx, `delete from dilion_auth.opaque_credentials where user_id=$1`, user.ID); err != nil {
			return opaqueDB(err)
		}
		version := uuid.NewString()
		sealed := a.sealOpaque(ctx, "record:"+version, data)
		_, err = tx.Exec(ctx, `insert into dilion_auth.opaque_credentials(user_id,scope,version,identity,record) values($1,$2,$3,$4,$5)`, user.ID, opaqueScope(ctx), version, state.Identity, sealed)
		if err != nil {
			return opaqueDB(err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, 200, map[string]bool{"success": true})
}

func (a *api) opaqueLoginStart(w http.ResponseWriter, r *http.Request) error {
	if err := a.verifyCaptcha(r); err != nil {
		return err
	}
	p, err := decodeOpaque(r)
	if err != nil {
		return err
	}
	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	if p.Email == "" || len(p.Email) > 320 {
		return opaqueInvalid()
	}
	data, err := opaqueBytes(p.KE1)
	if err != nil {
		return err
	}
	ctx := r.Context()
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	// A shared per-account limit supplements the existing per-process IP limit.
	account := opaqueEncode(a.opaqueMAC(ctx, "rate", []byte(requestAud(r)+":"+p.Email)))
	var attempts int
	err = pool.QueryRow(ctx, `insert into dilion_auth.opaque_attempts(scope,account,window_start,attempts) values($1,$2,$3,1)
 on conflict(scope,account) do update set attempts=case when dilion_auth.opaque_attempts.window_start<=$3-interval '1 minute' then 1 else least(dilion_auth.opaque_attempts.attempts+1,11) end,
 window_start=case when dilion_auth.opaque_attempts.window_start<=$3-interval '1 minute' then $3 else dilion_auth.opaque_attempts.window_start end returning attempts`, opaqueScope(ctx), account, a.now()).Scan(&attempts)
	if err != nil {
		return opaqueDB(err)
	}
	if attempts > 10 {
		return tooManyRequestsError("Too many authentication attempts")
	}
	server, serverID, err := a.opaqueServer(ctx, pool)
	if err != nil {
		return opaqueDB(err)
	}
	defer server.ServerKeyMaterial.Flush()
	request, err := server.Deserialize.KE1(data)
	if err != nil {
		return opaqueInvalid()
	}
	var userID, version, identity string
	var sealed []byte
	err = pool.QueryRow(ctx, `select c.user_id::text,c.version::text,c.identity,c.record from dilion_auth.opaque_credentials c join auth.users u on u.id=c.user_id where c.scope=$1 and lower(u.email)=$2 and u.aud=$3 and u.instance_id=$4::uuid and u.deleted_at is null and u.is_sso_user=false`, opaqueScope(ctx), p.Email, requestAud(r), nilUUID).Scan(&userID, &version, &identity, &sealed)
	var record *opaque.ClientRecord
	if isNoRows(err) {
		identity = opaqueEncode(a.opaqueMAC(ctx, "fake-identity", []byte(account)))
		record, err = opaque.DefaultConfiguration().GetFakeRecord([]byte(identity))
		if err == nil {
			record.ClientIdentity = []byte(identity)
			record.MaskingKey = a.opaqueMAC(ctx, "fake-masking", []byte(account))
		}
	} else if err == nil {
		var plain []byte
		plain, err = a.openOpaque(ctx, "record:"+version, sealed)
		if err == nil {
			reg, e := server.Deserialize.RegistrationRecord(plain)
			err = e
			if err == nil {
				record = &opaque.ClientRecord{RegistrationRecord: reg, ClientIdentity: []byte(identity), CredentialIdentifier: []byte(identity)}
			}
		}
		// Deserialized record may reference plain; clear only after GenerateKE2.
		defer clear(plain)
	}
	if err != nil {
		return opaqueDB(err)
	}
	response, output, err := server.GenerateKE2(request, record)
	if err != nil {
		return opaqueInvalid()
	}
	defer clear(output.ClientMAC)
	defer clear(output.SessionSecret)
	id, err := a.putOpaqueState(ctx, "login", &opaqueState{UserID: userID, Version: version, Identity: identity, ClientMAC: output.ClientMAC, SessionKey: output.SessionSecret})
	if err != nil {
		return err
	}
	return sendJSON(w, 200, map[string]any{"suite": opaqueSuite, "handshake_id": id, "client_identity": identity, "server_identity": serverID, "ke2": opaqueEncode(response.Serialize())})
}

func (a *api) opaqueLoginFinish(w http.ResponseWriter, r *http.Request) error {
	p, err := decodeOpaque(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	state, err := a.takeOpaqueState(ctx, "login", p.ID)
	if err != nil {
		return err
	}
	defer clear(state.ClientMAC)
	defer clear(state.SessionKey)
	data, err := opaqueBytes(p.KE3)
	if err != nil {
		return err
	}
	server, err := opaque.DefaultConfiguration().Server()
	if err != nil {
		return opaqueInvalid()
	}
	ke3, err := server.Deserialize.KE3(data)
	if err != nil {
		return opaqueInvalid()
	}
	if err := server.LoginFinish(ke3, state.ClientMAC); err != nil || state.UserID == "" || len(state.SessionKey) != 64 {
		return opaqueInvalid()
	}
	var token *AccessTokenResponse
	keyID := uuid.NewString()
	err = a.inTx(ctx, func(tx pgx.Tx) error {
		user, err := a.opaqueUser(ctx, tx, state.UserID)
		if err != nil {
			return err
		}
		var version string
		if err := tx.QueryRow(ctx, `select version::text from dilion_auth.opaque_credentials where user_id=$1 and scope=$2`, user.ID, opaqueScope(ctx)).Scan(&version); err != nil {
			if isNoRows(err) {
				return opaqueInvalid()
			}
			return opaqueDB(err)
		}
		if version != state.Version {
			return opaqueInvalid()
		}
		token, err = a.grantSession(ctx, tx, user, r, "opaque")
		if err != nil {
			return err
		}
		ts, err := a.tokensFor(ctx)
		if err != nil {
			return opaqueDB(err)
		}
		claims, err := ts.Verify(ctx, token.Token)
		if err != nil {
			return opaqueDB(err)
		}
		sessionID := sessionIDFrom(claims)
		expires := a.now().Add(opaqueKeyTTL)
		plain, _ := json.Marshal(opaqueStoredKey{Secret: state.SessionKey, Version: state.Version, Expires: expires})
		defer clear(plain)
		sealed := a.sealOpaque(ctx, "key:"+keyID+":"+sessionID, plain)
		_, err = tx.Exec(ctx, `insert into dilion_auth.opaque_session_keys(id,scope,session_id,credential_version,secret,expires_at) values($1,$2,$3,$4,$5,$6)`, keyID, opaqueScope(ctx), sessionID, state.Version, sealed, expires)
		if err != nil {
			return opaqueDB(err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, 200, struct {
		*AccessTokenResponse
		KeyID string `json:"key_id"`
	}{token, keyID})
}

// WithOpaqueSessionKey is the server-side integration point, NOT an HTTP key
// export endpoint. It verifies the bearer, live session and MFA on each use.
// fn must not retain the byte slice; it is cleared before this call returns.
// Keys expire after 15 minutes; refresh does not resurrect/extend OPAQUE keys.
func (m *Mount) WithOpaqueSessionKey(ctx context.Context, bearer, keyID string, fn func([]byte) error) error {
	a := m.a
	if !a.cfg.Opaque.Enabled || fn == nil {
		return opaqueInvalid()
	}
	if _, err := uuid.Parse(keyID); err != nil {
		return opaqueInvalid()
	}
	ts, err := a.tokensFor(ctx)
	if err != nil {
		return err
	}
	claims, err := ts.Verify(ctx, bearer)
	if err != nil {
		return opaqueInvalid()
	}
	ctx = withClaims(ctx, claims)
	return a.inTx(ctx, func(tx pgx.Tx) error {
		user, err := a.opaqueUser(ctx, tx, claims.Subject)
		if err != nil {
			return err
		}
		sess, err := lockOpaqueSession(ctx, tx, sessionIDFrom(claims))
		if err != nil || sess.UserID != user.ID || !a.sessionStillValid(sess, a.now()) {
			return opaqueInvalid()
		}
		if err := a.checkSinglePerUser(ctx, tx, sess, nil, a.now()); err != nil {
			return err
		}
		if err := a.requirePasskeyManagementAAL(ctx, tx, user); err != nil {
			return err
		}
		var sealed []byte
		var version string
		err = tx.QueryRow(ctx, `select secret,credential_version::text from dilion_auth.opaque_session_keys where id=$1 and scope=$2 and session_id=$3 and expires_at>$4`, keyID, opaqueScope(ctx), sess.ID, a.now()).Scan(&sealed, &version)
		if isNoRows(err) {
			return opaqueInvalid()
		}
		if err != nil {
			return opaqueDB(err)
		}
		plain, err := a.openOpaque(ctx, "key:"+keyID+":"+sess.ID, sealed)
		if err != nil {
			return opaqueInvalid()
		}
		defer clear(plain)
		var key opaqueStoredKey
		if err := json.Unmarshal(plain, &key); err != nil {
			return opaqueInvalid()
		}
		defer clear(key.Secret)
		if key.Version != version || len(key.Secret) != 64 || !a.now().Before(key.Expires) {
			return opaqueInvalid()
		}
		return fn(key.Secret)
	})
}

type opaqueStoredKey struct {
	Secret  []byte
	Version string
	Expires time.Time
}

// Holding a row lock through enrollment/key use serializes against logout.
// Callers also hold the account lock against credential reset/replacement.
func lockOpaqueSession(ctx context.Context, q querier, id string) (*session, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, opaqueInvalid()
	}
	var locked string
	if err := q.QueryRow(ctx, `select id::text from auth.sessions where id=$1 for update`, id).Scan(&locked); err != nil {
		return nil, err
	}
	return findSessionByID(ctx, q, id)
}
