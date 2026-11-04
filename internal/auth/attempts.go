package auth

// Failed credential attempts per account.
//
// The per-IP limiters (middleware.go) cannot stop guessing spread over many
// addresses, and a 6-digit code falls to a few hundred thousand guesses. So the
// checks that compare a secret — password sign-in, a typed OTP, an MFA code, a
// reauthentication nonce — also count failures per account in
// dilion_auth.auth_attempts: past the limit within the window, the check is
// refused before the secret is even compared, until the window passes. A
// success clears the count.
//
// Failures are written on the pool, outside the request's transaction, so a
// failure that rolls the transaction back is still counted.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// attemptWindow is how long failures count, and how long a locked account
// stays locked.
const attemptWindow = 15 * time.Minute

// Attempt kinds and their failure limits per window.
const (
	attemptPassword = "password"
	attemptOTP      = "otp"
	attemptFactor   = "factor"
	attemptNonce    = "nonce"
)

var attemptLimits = map[string]int{
	attemptPassword: 10,
	attemptOTP:      5,
	attemptFactor:   5,
	attemptNonce:    5,
}

// credentialFailureCodes are the answers that mean "the secret was wrong".
var credentialFailureCodes = map[string]bool{
	ErrorCodeInvalidCredentials:         true,
	ErrorCodeOTPExpired:                 true,
	ErrorCodeMFAVerificationFailed:      true,
	ErrorCodeReauthenticationNotValid:   true,
	ErrorCodeWebAuthnVerificationFailed: true,
}

func attemptKey(kind, account string) string {
	sum := sha256.Sum256([]byte(kind + ":" + account))
	return hex.EncodeToString(sum[:])
}

// throttled runs check, the comparison of a secret for account, under the
// per-account failure limit of kind.
func (a *api) throttled(ctx context.Context, kind, account string, check func() error) error {
	if account == "" {
		return check()
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	key := attemptKey(kind, account)
	now := a.now()
	var failures int
	var start time.Time
	err = pool.QueryRow(ctx, `select failures, window_start from dilion_auth.auth_attempts where account = $1`, key).
		Scan(&failures, &start)
	if err != nil && !isNoRows(err) {
		return internalServerError("Database error checking attempts").withInternal(err)
	}
	if err == nil && now.Before(start.Add(attemptWindow)) && failures >= attemptLimits[kind] {
		return tooManyRequestsError("Too many failed attempts, try again later")
	}

	cerr := check()
	var he *HTTPError
	switch {
	case cerr == nil:
		if _, err := pool.Exec(ctx, `delete from dilion_auth.auth_attempts where account = $1`, key); err != nil {
			a.log.WarnContext(ctx, "auth: clearing attempts failed", "error", err.Error())
		}
	case errors.As(cerr, &he) && credentialFailureCodes[he.ErrorCode]:
		if _, err := pool.Exec(ctx, `
			insert into dilion_auth.auth_attempts (account, window_start, failures) values ($1, $2, 1)
			on conflict (account) do update set
				failures = case when auth_attempts.window_start <= $2 - $3 * interval '1 second' then 1
				                else auth_attempts.failures + 1 end,
				window_start = case when auth_attempts.window_start <= $2 - $3 * interval '1 second' then $2
				                    else auth_attempts.window_start end`,
			key, now, int(attemptWindow.Seconds())); err != nil {
			a.log.WarnContext(ctx, "auth: recording a failed attempt failed", "error", err.Error())
		}
	}
	return cerr
}
