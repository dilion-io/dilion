package auth

// HaveIBeenPwned ("pwned password") check, k-anonymity flavour.
//
// Upstream calls github.com/supabase/hibp from checkPasswordStrength when
// GOTRUE_PASSWORD_HIBP_ENABLED is on; this is that client, reduced to the one
// call gotrue makes and with no new module dependency (stdlib net/http).
//
// # The protocol
//
// The password itself never leaves the process. What is sent is the first FIVE
// hex characters of its SHA-1; the service answers with every known hash that
// shares that prefix, as `SUFFIX:COUNT` lines, and the match is done locally:
//
//	GET https://api.pwnedpasswords.com/range/5BAA6
//	Add-Padding: true
//
//	1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493
//	...
//
// `Add-Padding: true` is what upstream sends: the response is stuffed with
// synthetic entries so its SIZE does not leak how many real hashes share the
// prefix. Padded entries carry a COUNT OF ZERO and must be ignored — treating
// one as a hit would reject a perfectly good password.
//
// # Failure policy: OPEN
//
// A network error, a non-200, or a malformed body means "unknown", and the
// password is ACCEPTED with a WARN log. That is upstream's behaviour with
// GOTRUE_PASSWORD_HIBP_FAIL_CLOSED unset (the default): an outage at a third
// party must not take signups down. Security.HIBPFailClosed flips it to a 500,
// exactly as upstream does.

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// defaultHIBPBaseURL is the public range API. Security.HIBPBaseURL overrides it.
const defaultHIBPBaseURL = "https://api.pwnedpasswords.com"

// hibpUserAgent identifies the caller. The service asks every client to send a
// descriptive one and answers 403 to some generic agents.
const hibpUserAgent = "dilion-auth"

// hibpTimeout bounds one range lookup. It is deliberately short: the check sits
// in the request path of a signup.
const hibpTimeout = DefaultCaptchaTimeout

// isPasswordPwned reports whether the password appears in the HaveIBeenPwned
// corpus. The error is non-nil only when the LOOKUP failed; the caller decides
// whether that is fatal (Security.HIBPFailClosed).
func (a *api) isPasswordPwned(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(fmt.Sprintf("%x", sum))
	prefix, suffix := digest[:5], digest[5:]

	base := strings.TrimRight(strings.TrimSpace(a.cfg.Security.HIBPBaseURL), "/")
	if base == "" {
		base = defaultHIBPBaseURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/range/"+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("auth: build hibp request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", hibpUserAgent)

	resp, err := (&http.Client{Timeout: hibpTimeout}).Do(req)
	if err != nil {
		return false, fmt.Errorf("auth: hibp range request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("auth: hibp range request: unexpected status %d", resp.StatusCode)
	}

	// A range response is a few hundred KB at most; the cap is there so a
	// misconfigured HIBPBaseURL cannot stream unbounded data into the handler.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return false, fmt.Errorf("auth: read hibp response: %w", err)
	}
	return hibpRangeContains(string(body), suffix), nil
}

// hibpRangeContains scans a range response for a suffix with a NON-ZERO count.
// Zero-count rows are the `Add-Padding` decoys.
func hibpRangeContains(body, suffix string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		got, countRaw, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(got), suffix) {
			continue
		}
		count, err := strconv.ParseInt(strings.TrimSpace(countRaw), 10, 64)
		if err != nil {
			// A row for our suffix that we cannot parse is treated as a hit:
			// the conservative reading of a corrupt line about THIS password.
			return true
		}
		return count > 0
	}
	return false
}
