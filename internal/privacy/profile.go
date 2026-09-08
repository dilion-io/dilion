package privacy

// PII Vault profile (§2.6 masked projection, §2.7 vault).
//
// The whole profile is a single JSON document
//
//	{"fields": {"<key>": {"value": "...", "hint": "EMAIL"}}}
//
// sealed with the subject's DEFAULT-scope DEK and stored in
// dilion_pii.user_profiles.enc_profile. One document (rather than a row per
// field) keeps the vault write path a single envelope operation and makes
// crypto-shredding total: once the DEFAULT DEK is destroyed the profile is
// unreadable by design, and the engine reports it as "not found".

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/dilion-io/dilion/ports"
)

const (
	// maxProfileFields caps the document size in field count.
	maxProfileFields = 100
	// maxProfileValueBytes caps a single field value.
	maxProfileValueBytes = 4 << 10
	// maskFiller is the redaction marker used by every hint.
	maskFiller = "****"
)

// profileKeyRe: lowercase, dot/dash/underscore separated, max 64 runes.
var profileKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// profileDoc is the on-disk (encrypted) shape. Only "fields" is defined; the
// wrapper leaves room for a future version/alg marker without a migration.
type profileDoc struct {
	Fields map[string]ProfileField `json:"fields"`
}

// GetProfile returns the subject's vault profile. full=false is the default
// projection: values are masked per field hint (§2.6). full=true reveals the
// raw values and is gated by the pii_reveal hook; the caller is responsible for
// the pii.reveal permission check and the PII_FULL_READ audit event.
func (e *Engine) GetProfile(ctx context.Context, projectID, userID string, full bool) (*Profile, error) {
	pid := normProject(projectID)
	uid, err := validUUID(userID)
	if err != nil {
		return nil, err
	}

	if full {
		// Validating hook: runs before anything is decrypted so a rejection
		// never touches plaintext.
		if err := e.runHook(ctx, ports.PIIReveal, map[string]any{
			"user_id": uid, "project_id": pid,
		}); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrPolicyViolation, err)
		}
	}

	fields, updatedAt, found, err := e.readProfile(ctx, uid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return projectProfile(uid, fields, updatedAt, full), nil
}

// UpdateProfile upserts the keys in set, deletes the keys in remove and
// returns the masked projection of the result. Read-modify-write: the document
// is decrypted, patched and re-sealed. An empty result deletes the row.
func (e *Engine) UpdateProfile(ctx context.Context, projectID, userID string, set map[string]ProfileField, remove []string) (*Profile, error) {
	pid := normProject(projectID)
	uid, err := validUUID(userID)
	if err != nil {
		return nil, err
	}
	// Instance-fixed definitions (if any) decide which keys exist and which hint
	// each one is stored with. Runs before the generic validation so an omitted
	// hint is filled in from the definition rather than rejected.
	set, err = e.applyPIIFieldDefs(set)
	if err != nil {
		return nil, err
	}
	if err := validateProfilePatch(set, remove); err != nil {
		return nil, err
	}
	// Retry optimistic patches: no pool connection is held during KMS calls.
	// The final transaction serialises with deletion creation, then compares the
	// encrypted snapshot. Concurrent patches therefore merge, never overwrite.
	for attempt := 0; attempt < 64; attempt++ {
		p, retry, err := e.patchProfile(ctx, pid, uid, set, remove)
		if !retry {
			return p, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: concurrent profile changes; retry the patch", ErrConflict)
}

func (e *Engine) patchProfile(ctx context.Context, pid, uid string, set map[string]ProfileField, remove []string) (*Profile, bool, error) {
	if active, err := e.hasActiveDeletion(ctx, uid); err != nil {
		return nil, false, err
	} else if active {
		return nil, false, fmt.Errorf("%w: deletion blocks profile writes", ErrConflict)
	}
	var before []byte
	err := e.pool.QueryRow(ctx, `select enc_profile from dilion_pii.user_profiles where user_id = $1::uuid`, uid).Scan(&before)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	fields, err := e.decodeProfile(ctx, uid, before)
	if err != nil {
		return nil, false, err
	}
	for k, f := range set {
		fields[k] = f
	}
	for _, k := range remove {
		delete(fields, k)
	}
	if len(fields) > maxProfileFields {
		return nil, false, fmt.Errorf("%w: profile has %d fields, max %d", ErrInvalidInput, len(fields), maxProfileFields)
	}
	var enc []byte
	if len(fields) > 0 {
		enc, err = e.sealProfile(ctx, uid, fields)
		if err != nil {
			return nil, false, err
		}
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock($1, hashtext($2))`, subjectMutationLockNS, uid); err != nil {
		return nil, false, err
	}
	active, err := e.hasActiveDeletionWith(ctx, tx, uid)
	if err != nil {
		return nil, false, err
	}
	var erased bool
	if err := tx.QueryRow(ctx, `select
		exists(select 1 from dilion_privacy.erasure_registry where tombstone_id = $1)
		or exists(select 1 from dilion_pii.subject_keys
		  where user_id = $2::uuid and scope = 'DEFAULT' and shredded_at is not null)`,
		e.tombstoneID(uid), uid).Scan(&erased); err != nil {
		return nil, false, err
	}
	if active || erased {
		return nil, false, fmt.Errorf("%w: deletion blocks profile writes", ErrConflict)
	}
	var current []byte
	err = tx.QueryRow(ctx, `select enc_profile from dilion_pii.user_profiles where user_id = $1::uuid`, uid).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	if found != (err == nil) || !bytes.Equal(before, current) {
		return nil, true, nil
	}
	now := e.now()
	if len(fields) == 0 {
		_, err = tx.Exec(ctx, `delete from dilion_pii.user_profiles where user_id = $1::uuid`, uid)
	} else {
		_, err = tx.Exec(ctx, `insert into dilion_pii.user_profiles (user_id, enc_profile, created_at, updated_at)
			values ($1::uuid, $2, $3, $3)
			on conflict (user_id) do update set enc_profile = excluded.enc_profile, updated_at = excluded.updated_at`, uid, enc, now)
	}
	if err != nil {
		return nil, false, err
	}
	if err := e.syncSearchIndex(ctx, tx, uid, fields); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	e.log.Info("pii profile updated", "project_id", pid, "user_id", uid, "fields", len(fields))
	if len(fields) == 0 {
		return projectProfile(uid, nil, nil, false), false, nil
	}
	return projectProfile(uid, fields, &now, false), false, nil
}

// ---- storage ---------------------------------------------------------------

// readProfile decrypts the stored document. found=false means "no row".
// A row that cannot be decrypted is reported as ErrNotFound: after a
// crypto-shred the profile is gone as far as every reader is concerned (§2.7).
func (e *Engine) readProfile(ctx context.Context, userID string) (map[string]ProfileField, *time.Time, bool, error) {
	return e.readProfileWith(ctx, e.pool, userID)
}

func (e *Engine) readProfileWith(ctx context.Context, db queryExecer, userID string) (map[string]ProfileField, *time.Time, bool, error) {
	var enc []byte
	var updatedAt *time.Time
	err := db.QueryRow(ctx,
		`select enc_profile, updated_at from dilion_pii.user_profiles where user_id = $1::uuid`, userID).
		Scan(&enc, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("privacy: read profile: %w", err)
	}
	fields, err := e.decodeProfile(ctx, userID, enc)
	return fields, updatedAt, true, err
}

func (e *Engine) decodeProfile(ctx context.Context, userID string, enc []byte) (map[string]ProfileField, error) {
	if len(enc) == 0 {
		return map[string]ProfileField{}, nil
	}
	plain, err := e.kms.Decrypt(ctx, userID, ports.KeyScopeDefault, enc)
	if err != nil {
		// Expected post-erasure (DEFAULT dek shredded). Never surfaced as a 500.
		e.log.Debug("pii profile is unreadable; treating as absent", "user_id", userID, "err", err)
		return nil, ErrNotFound
	}
	var doc profileDoc
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("privacy: decode profile: %w", err)
	}
	if doc.Fields == nil {
		doc.Fields = map[string]ProfileField{}
	}
	return doc.Fields, nil
}

// sealProfile encrypts the document with the subject's DEFAULT-scope DEK, the
// key destroyed first by the erasure pipeline.
func (e *Engine) sealProfile(ctx context.Context, userID string, fields map[string]ProfileField) ([]byte, error) {
	plain, err := json.Marshal(profileDoc{Fields: fields})
	if err != nil {
		return nil, fmt.Errorf("privacy: encode profile: %w", err)
	}
	ct, err := e.kms.Encrypt(ctx, userID, ports.KeyScopeDefault, plain)
	if err != nil {
		return nil, fmt.Errorf("privacy: seal profile: %w", err)
	}
	return ct, nil
}

func (e *Engine) hasActiveDeletion(ctx context.Context, userID string) (bool, error) {
	return e.hasActiveDeletionWith(ctx, e.pool, userID)
}

func (e *Engine) hasActiveDeletionWith(ctx context.Context, db queryExecer, userID string) (bool, error) {
	const q = `select exists (
		select 1 from dilion_privacy.personal_data_requests
		where user_id = $1::uuid and type = 'DELETION'
		  and status in ('REQUESTED','PROCESSING','MANUAL_REVIEW'))`
	var ok bool
	if err := db.QueryRow(ctx, q, userID).Scan(&ok); err != nil {
		return false, fmt.Errorf("privacy: active deletion check: %w", err)
	}
	return ok, nil
}

// ---- instance-fixed field definitions ---------------------------------------
//
// An instance may pin the shape of its vault (ports.InstanceResolver.PIIFields,
// EngineDeps.PIIFieldsYAML):
//
//	pii-fields:
//	  email:     {hint: EMAIL}
//	  full_name: {hint: NAME}
//
// With definitions in place a write may only use the defined keys, and the
// stored hint always comes from the definition — a caller cannot downgrade
// `email` to GENERIC and thereby weaken the masked projection (§2.6). Without
// them (the single-instance default) fields stay free-form and the request
// carries the hint.

// piiFieldsDoc is the on-disk shape. The pointer distinguishes "no pii-fields
// key at all" (free-form) from "pii-fields: {}" (a mistake, rejected).
type piiFieldsDoc struct {
	Fields *map[string]piiFieldDef `yaml:"pii-fields"`
}

type piiFieldDef struct {
	Hint string `yaml:"hint"`
}

// ParsePIIFields validates and loads instance-fixed PII field definitions.
// Empty input returns a nil map, meaning free-form fields.
func ParsePIIFields(b []byte) (map[string]FieldHint, error) {
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var doc piiFieldsDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("privacy: parse pii-fields: %w", err)
	}
	if doc.Fields == nil {
		return nil, errors.New("privacy: pii-fields document has no `pii-fields` key")
	}
	if len(*doc.Fields) == 0 {
		return nil, errors.New("privacy: pii-fields must define at least one field (omit the document for free-form fields)")
	}
	out := make(map[string]FieldHint, len(*doc.Fields))
	for k, def := range *doc.Fields {
		if !profileKeyRe.MatchString(k) {
			return nil, fmt.Errorf("privacy: pii-fields: key %q must match %s", k, profileKeyRe)
		}
		h := FieldHint(strings.ToUpper(strings.TrimSpace(def.Hint)))
		if !validHint(h) {
			return nil, fmt.Errorf("privacy: pii-fields: field %q has unknown hint %q "+
				"(want EMAIL, NAME, PHONE, ADDRESS or GENERIC)", k, def.Hint)
		}
		out[k] = h
	}
	return out, nil
}

// PIIFieldDefs exposes the instance's field definitions (nil = free-form).
func (e *Engine) PIIFieldDefs() map[string]FieldHint {
	if e.piiFields == nil {
		return nil
	}
	out := make(map[string]FieldHint, len(e.piiFields))
	for k, v := range e.piiFields {
		out[k] = v
	}
	return out
}

// applyPIIFieldDefs enforces the definitions on a write and returns the patch
// with every hint resolved. Without definitions the patch is returned as-is.
func (e *Engine) applyPIIFieldDefs(set map[string]ProfileField) (map[string]ProfileField, error) {
	if e.piiFields == nil || len(set) == 0 {
		return set, nil
	}
	out := make(map[string]ProfileField, len(set))
	for k, f := range set {
		want, ok := e.piiFields[k]
		if !ok {
			return nil, fmt.Errorf("%w: field %q is not defined for this instance; allowed keys: %s",
				ErrInvalidInput, k, strings.Join(e.allowedPIIKeys(), ", "))
		}
		// The hint is optional on the wire; when supplied it must agree with the
		// definition rather than silently losing.
		if f.Hint != "" && f.Hint != want {
			return nil, fmt.Errorf("%w: field %q is defined with hint %s, got %s",
				ErrInvalidInput, k, want, f.Hint)
		}
		out[k] = ProfileField{Value: f.Value, Hint: want}
	}
	return out, nil
}

func (e *Engine) allowedPIIKeys() []string {
	keys := make([]string, 0, len(e.piiFields))
	for k := range e.piiFields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ---- validation ------------------------------------------------------------

func validateProfilePatch(set map[string]ProfileField, remove []string) error {
	if len(set) > maxProfileFields {
		return fmt.Errorf("%w: %d fields in one write, max %d", ErrInvalidInput, len(set), maxProfileFields)
	}
	for k, f := range set {
		if !profileKeyRe.MatchString(k) {
			return fmt.Errorf("%w: field key %q must match %s", ErrInvalidInput, k, profileKeyRe)
		}
		if f.Hint == "" {
			// Only reachable without instance-fixed definitions: with them the
			// hint has already been filled in from the definition.
			return fmt.Errorf("%w: field %q requires a hint (this instance defines no fixed PII fields)",
				ErrInvalidInput, k)
		}
		if !validHint(f.Hint) {
			// Defaulting an unknown hint to GENERIC would silently downgrade a
			// caller's masking intent, so it is rejected instead.
			return fmt.Errorf("%w: field %q has unknown hint %q", ErrInvalidInput, k, f.Hint)
		}
		if len(f.Value) > maxProfileValueBytes {
			return fmt.Errorf("%w: field %q value is %d bytes, max %d",
				ErrInvalidInput, k, len(f.Value), maxProfileValueBytes)
		}
	}
	for _, k := range remove {
		if !profileKeyRe.MatchString(k) {
			return fmt.Errorf("%w: field key %q must match %s", ErrInvalidInput, k, profileKeyRe)
		}
	}
	return nil
}

func validHint(h FieldHint) bool {
	switch h {
	case HintEmail, HintName, HintPhone, HintAddress, HintGeneric:
		return true
	}
	return false
}

// ---- projection / masking (§2.6) -------------------------------------------

func projectProfile(userID string, fields map[string]ProfileField, updatedAt *time.Time, full bool) *Profile {
	out := &Profile{
		UserID:    userID,
		Fields:    make(map[string]ProfileField, len(fields)),
		View:      ViewMasked,
		UpdatedAt: updatedAt,
	}
	if full {
		out.View = ViewFull
	}
	for k, f := range fields {
		if full {
			out.Fields[k] = f
			continue
		}
		out.Fields[k] = ProfileField{Value: maskValue(f.Value, f.Hint), Hint: f.Hint}
	}
	return out
}

// maskValue is the hint-driven masked projection. Everything is rune-based:
// 홍길동 masks to 홍**, never to a broken byte prefix. An unknown hint on a
// stored document (written before a hint was retired) falls back to GENERIC.
func maskValue(v string, hint FieldHint) string {
	switch hint {
	case HintEmail:
		return maskEmail(v)
	case HintName:
		return maskName(v)
	case HintPhone:
		return maskPhone(v)
	case HintAddress:
		return maskAddress(v)
	default:
		return maskFiller
	}
}

// maskEmail keeps the first rune of the localpart and the whole domain:
// joseph@example.com -> j**@example.com. A value with no "@" is not an address
// we can reason about, so it degrades to the GENERIC mask.
func maskEmail(v string) string {
	at := strings.LastIndex(v, "@")
	if at < 0 {
		return maskFiller
	}
	local, domain := []rune(v[:at]), v[at+1:]
	if len(local) < 1 {
		return "**@" + domain
	}
	return string(local[0]) + "**@" + domain
}

// maskName keeps the first rune only: 홍길동 -> 홍**.
func maskName(v string) string {
	r := []rune(v)
	if len(r) < 1 {
		return "**"
	}
	return string(r[0]) + "**"
}

// maskPhone normalises to <first3>-****-<last4> over the digits of the value,
// so formatting differences (+82 10-1234-5678 vs 01012345678) mask alike.
// Fewer than 8 digits cannot spare 7 without becoming identifying: mask fully.
func maskPhone(v string) string {
	digits := make([]rune, 0, len(v))
	for _, r := range v {
		if unicode.IsDigit(r) {
			digits = append(digits, r)
		}
	}
	if len(digits) < 8 {
		return maskFiller
	}
	return string(digits[:3]) + "-****-" + string(digits[len(digits)-4:])
}

// maskAddress keeps the first whitespace-delimited token (city/province) and
// drops the rest: "서울시 강남구 테헤란로 1" -> "서울시 ***".
func maskAddress(v string) string {
	tokens := strings.Fields(v)
	if len(tokens) == 0 {
		return maskFiller
	}
	return tokens[0] + " ***"
}
