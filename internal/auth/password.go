package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the bcrypt work factor used for `auth.users.encrypted_password`.
// gotrue's default is 10; keeping the same cost means password hashes are
// interchangeable with an upstream Supabase deployment in both directions.
const BcryptCost = 10

// hashCost is the cost HashPassword uses: BcryptCost, except in this
// package's tests, which hash hundreds of passwords and lower it (main_test.go).
var hashCost = BcryptCost

// MinPasswordLength mirrors gotrue's default GOTRUE_PASSWORD_MIN_LENGTH.
const MinPasswordLength = 6

// MaxPasswordLength is upstream api.MaxPasswordLength: bcrypt ignores input
// past 72 bytes, so accepting a longer password would make distinct passwords
// equivalent.
const MaxPasswordLength = 72

// ErrPasswordTooLong is returned when a password exceeds bcrypt's 72-byte input
// limit (bytes beyond it are silently ignored by the algorithm, so accepting
// them would make distinct passwords equivalent).
var ErrPasswordTooLong = errors.New("auth: password exceeds 72 bytes")

// HashPassword returns a bcrypt hash suitable for auth.users.encrypted_password.
func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// ComparePassword reports whether password matches the stored bcrypt hash.
// It returns a non-nil error on mismatch (bcrypt.ErrMismatchedHashAndPassword).
func ComparePassword(hash, password string) error {
	if hash == "" {
		return bcrypt.ErrMismatchedHashAndPassword
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ---- password strength (upstream api.checkPasswordStrength) ---------------

// WeakPasswordError is upstream api.WeakPasswordError: a password that does not
// meet the configured policy, with the machine-readable REASONS a client shows
// next to its password field.
//
// The reasons are upstream's exact strings:
//
//	"length"     shorter than Password.MinLength
//	"characters" misses one of Password.RequiredCharacters' sets
//	"pwned"      found in the HaveIBeenPwned corpus
//
// It is never returned to a handler on its own: weakPasswordError wraps it in
// the HTTPError envelope, whose MarshalJSON renders it as upstream's
// `weak_password` payload.
type WeakPasswordError struct {
	Message string   `json:"message,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func (e *WeakPasswordError) Error() string { return e.Message }

// weakPasswordError builds upstream's 422 weak_password body:
//
//	{"code":422,"error_code":"weak_password","msg":"...",
//	 "weak_password":{"reasons":["length","characters","pwned"]}}
//
// The reasons ride along as the HTTPError's internal cause, which is where
// MarshalJSON below picks them up. Doing it this way means every EXISTING
// call site (admin.go, generate_link.go, ...) renders the richer body without
// being touched, and errors.go stays owned by nobody in particular.
func weakPasswordError(message string, reasons []string) *HTTPError {
	e := unprocessableEntityError(ErrorCodeWeakPassword, "%s", message)
	e.internal = &WeakPasswordError{Message: message, Reasons: reasons}
	return e
}

// weakPasswordPayload is the `weak_password` object of the error body.
type weakPasswordPayload struct {
	Reasons []string `json:"reasons,omitempty"`
}

// MarshalJSON renders the gotrue error body, plus upstream's `weak_password`
// payload when the error carries a *WeakPasswordError cause.
//
// Field order and tags are unchanged for every other error:
//
//	{"code":400,"error_code":"validation_failed","msg":"..."}
func (e *HTTPError) MarshalJSON() ([]byte, error) {
	// The alias sheds the method set, so json.Marshal below does not recurse.
	type alias HTTPError
	out := struct {
		*alias
		WeakPassword *weakPasswordPayload `json:"weak_password,omitempty"`
	}{alias: (*alias)(e)}

	if wpe, ok := e.internal.(*WeakPasswordError); ok {
		out.WeakPassword = &weakPasswordPayload{Reasons: wpe.Reasons}
	}
	return json.Marshal(out)
}

// checkPasswordStrength is upstream's api.checkPasswordStrength: the ONE place
// a new password is judged, used by /signup, PUT /user, the admin user
// endpoints and /admin/generate_link.
//
// The checks run in upstream's order and the messages are upstream's verbatim,
// because clients surface them to end users:
//
//	> 72 bytes            400 validation_failed (bcrypt truncates past that)
//	< MinLength           422 weak_password, reason "length"
//	missing a class       422 weak_password, reason "characters"
//	pwned (HIBP on)       422 weak_password, reason "pwned"
//
// A failing HIBP lookup is fail-OPEN with a WARN log unless
// Security.HIBPFailClosed is set (hibp.go).
func (a *api) checkPasswordStrength(ctx context.Context, password string) *HTTPError {
	if len(password) > MaxPasswordLength {
		return badRequestError(ErrorCodeValidationFailed,
			"Password cannot be longer than %v characters", MaxPasswordLength)
	}

	minLength := a.cfg.Password.MinLength
	if minLength <= 0 {
		minLength = MinPasswordLength
	}

	var messages, reasons []string

	if len(password) < minLength {
		reasons = append(reasons, "length")
		messages = append(messages, fmt.Sprintf("Password should be at least %d characters.", minLength))
	}

	// Each configured set must contribute at least one character. Upstream
	// reports the WHOLE list in the message and adds the reason only once.
	for _, characterSet := range a.cfg.Password.RequiredCharacters {
		if characterSet != "" && !strings.ContainsAny(password, characterSet) {
			reasons = append(reasons, "characters")
			messages = append(messages, fmt.Sprintf(
				"Password should contain at least one character of each: %s.",
				strings.Join(a.cfg.Password.RequiredCharacters, ", ")))
			break
		}
	}

	if a.cfg.Security.HIBPEnabled {
		pwned, err := a.isPasswordPwned(ctx, password)
		switch {
		case err != nil && a.cfg.Security.HIBPFailClosed:
			return internalServerError(
				"Unable to perform password strength check with HaveIBeenPwned.org.").withInternal(err)
		case err != nil:
			a.log.WarnContext(ctx,
				"auth: unable to perform password strength check with HaveIBeenPwned.org, pwned passwords are being allowed",
				"error", err)
		case pwned:
			reasons = append(reasons, "pwned")
			messages = append(messages,
				"Password is known to be weak and easy to guess, please choose a different one.")
		}
	}

	if len(reasons) > 0 {
		return weakPasswordError(strings.Join(messages, " "), reasons)
	}
	return nil
}

// refreshTokenAlphabet matches upstream's legacy refresh-token shape
// (`^[a-z0-9]{12}$`, see internal/api/token_refresh.go), so gotrue-js and the
// Supabase CLI accept tokens issued by Dilion without changes.
const refreshTokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// refreshTokenLength is upstream's crypto.SecureAlphanumeric(12).
const refreshTokenLength = 12

// newRefreshToken returns a cryptographically random opaque refresh token.
// Rejection sampling keeps the distribution uniform over the alphabet.
func newRefreshToken() (string, error) {
	const maxByte = 255 - (256 % len(refreshTokenAlphabet))
	var sb strings.Builder
	sb.Grow(refreshTokenLength)
	buf := make([]byte, refreshTokenLength)
	for sb.Len() < refreshTokenLength {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if sb.Len() == refreshTokenLength {
				break
			}
			if int(b) > maxByte {
				continue
			}
			sb.WriteByte(refreshTokenAlphabet[int(b)%len(refreshTokenAlphabet)])
		}
	}
	return sb.String(), nil
}

// obfuscateValue reproduces gotrue's models.obfuscateValue: a deterministic,
// irreversible replacement used on soft delete so the unique constraints on
// auth.users.email / .phone are released without freeing the value for reuse
// by an attacker who knows the address.
func obfuscateValue(id, value string) string {
	sum := sha256.Sum256([]byte(id + value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func obfuscateEmail(userID, email string) string { return obfuscateValue(userID, email) }

func obfuscatePhone(userID, phone string) string {
	// Upstream truncates to 15 chars: the column was VARCHAR(15) before it
	// became text, and existing rows must keep round-tripping.
	return obfuscateValue(userID, phone)[:15]
}

func obfuscateIdentityProviderID(userID, provider, providerID string) string {
	return obfuscateValue(userID, provider+":"+providerID)
}
