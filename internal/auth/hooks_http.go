package auth

// HTTP webhook driver for the external auth hooks (Standard Webhooks spec).
//
// This is Dilion's port of github.com/supabase/auth/internal/hooks/hookshttp.
// A hook configured with an http(s):// URI is delivered as a signed POST:
//
//	POST <uri>
//	Content-Type: application/json
//	webhook-id:        <uuid v4>
//	webhook-timestamp: <unix seconds>
//	webhook-signature: v1,<base64 hmac-sha256(secret, id.timestamp.body)>
//	Accept-Encoding:   identity
//
//	<the hook payload, JSON>
//
// The signing string is exactly "<id>.<timestamp>.<body>" (Standard Webhooks),
// the digest is HMAC-SHA256, and the signature is base64(std) of the raw digest
// prefixed "v1,". Each configured secret produces one signature and they are
// joined with ", " in the header, so a hook can verify against any secret in the
// list — that is how secret ROTATION works: sign with all, the receiver accepts
// the one it still knows.
//
// Secrets are configured as "v1,whsec_<base64-key>" (Config.Hooks.<h>.Secrets).
// The "v1," prefix names the scheme, "whsec_" the symmetric-key format; the
// base64 body decodes to the raw HMAC key.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/internal/netguard"
)

// HTTP hook driver defaults (upstream hookshttp constants). They are package
// vars, not consts, so a test can shorten the timeout / drop the backoff without
// standing up a slow server; production never mutates them.
var (
	httpHookTimeout       = 5 * time.Second
	httpHookRetries       = 3
	httpHookBackoff       = 2 * time.Second
	httpHookResponseLimit = int64(200 * 1024) // 200 KiB
)

// symmetricSecretPrefix is the "v1," scheme tag every configured HTTP hook secret
// carries; whsecPrefix is the Standard Webhooks symmetric-key marker.
const (
	symmetricSecretPrefix = "v1,"
	whsecPrefix           = "whsec_"
)

// dispatchHTTPHook delivers in to the configured webhook and decodes the JSON
// response into out. It is upstream's Dispatcher.Dispatch + runHTTPHook.
func (a *api) dispatchHTTPHook(ctx context.Context, cfg HookEndpointConfig, in, out any) error {
	body, err := a.runHTTPHook(ctx, cfg, in)
	if err != nil {
		return err
	}
	if body != nil && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			var he *HTTPError
			if errors.As(err, &he) {
				return he
			}
			return internalServerError("Error unmarshaling hook JSON output").withInternal(err)
		}
	}
	return nil
}

// runHTTPHook performs the signed POST with upstream's retry/timeout/status
// handling and returns the (already error-checked) response body, or nil for a
// 204.
func (a *api) runHTTPHook(ctx context.Context, cfg HookEndpointConfig, in any) ([]byte, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, internalServerError("Error marshaling hook JSON input").withInternal(err)
	}

	client := &http.Client{Timeout: httpHookTimeout}
	if cfg.ssrfGuard {
		client.Transport = netguard.Transport(http.DefaultTransport, a.outbound)
	}
	ctx, cancel := context.WithTimeout(ctx, httpHookTimeout)
	defer cancel()

	for i := 0; i < httpHookRetries; i++ {
		msgID := uuid.NewString()
		now := time.Now()
		sigs, serr := signHookPayload(cfg.Secrets, msgID, now, payload)
		if serr != nil {
			return nil, internalServerError("Error generating hook signatures").withInternal(serr)
		}

		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(cfg.URI), bytes.NewReader(payload))
		if rerr != nil {
			return nil, internalServerError("Hook failed to build request").withInternal(rerr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("webhook-id", msgID)
		req.Header.Set("webhook-timestamp", fmt.Sprintf("%d", now.Unix()))
		req.Header.Set("webhook-signature", strings.Join(sigs, ", "))
		// Go's client defaults to gzip, which omits Content-Length; identity keeps
		// the length so a receiver can read the body plainly (upstream does this).
		req.Header.Set("Accept-Encoding", "identity")

		rsp, derr := client.Do(req)
		if derr != nil {
			if errors.Is(derr, netguard.ErrNotPublic) {
				// Not transient: retrying would dial the same address.
				return nil, internalServerError("Hook URI does not resolve to a public address").withInternal(derr)
			}
			if errors.Is(derr, context.DeadlineExceeded) {
				return nil, unprocessableEntityError(ErrorCodeHookTimeout,
					"Failed to reach hook within maximum time of %.0f seconds", httpHookTimeout.Seconds())
			}
			var netErr net.Error
			if (errors.As(derr, &netErr) && netErr.Timeout()) || i < httpHookRetries-1 {
				select {
				case <-ctx.Done():
					return nil, unprocessableEntityError(ErrorCodeHookTimeout,
						"Failed to reach hook within maximum time of %.0f seconds", httpHookTimeout.Seconds())
				case <-time.After(httpHookBackoff):
				}
				continue
			}
			return nil, unprocessableEntityError(ErrorCodeHookTimeoutAfterRetry,
				"Failed to reach hook after maximum retries").withInternal(derr)
		}

		body, done, herr := a.readHookResponse(rsp)
		if herr != nil {
			return nil, herr
		}
		if !done {
			// 429 / 503 with a retry-after: try again.
			continue
		}
		return body, nil
	}
	return nil, internalServerError("Service currently unavailable due to hook")
}

// readHookResponse maps a webhook status to (body, done, error), reproducing
// upstream's switch: done=false asks the caller to retry.
func (a *api) readHookResponse(rsp *http.Response) ([]byte, bool, error) {
	defer rsp.Body.Close()

	switch rsp.StatusCode {
	case http.StatusNoContent:
		return nil, true, nil

	case http.StatusOK, http.StatusAccepted:
		contentType := rsp.Header.Get("Content-Type")
		if contentType == "" {
			return nil, true, badRequestError(ErrorCodeHookPayloadInvalidContentType,
				"Invalid Content-Type: Missing Content-Type header")
		}
		mediaType, _, mErr := mime.ParseMediaType(contentType)
		if mErr != nil {
			return nil, true, badRequestError(ErrorCodeHookPayloadInvalidContentType,
				"Invalid Content-Type header: %s", mErr.Error())
		}
		if mediaType != "application/json" {
			return nil, true, badRequestError(ErrorCodeHookPayloadInvalidContentType,
				"Invalid JSON response. Received content-type: %s", contentType)
		}

		limited := &io.LimitedReader{R: rsp.Body, N: httpHookResponseLimit}
		body, rErr := io.ReadAll(limited)
		if rErr != nil {
			return nil, true, internalServerError("Error reading hook response").withInternal(rErr)
		}
		if limited.N <= 0 {
			if n, _ := rsp.Body.Read(make([]byte, 1)); n > 0 {
				return nil, true, unprocessableEntityError(ErrorCodeHookPayloadOverSizeLimit,
					"Payload size exceeded size limit of %d bytes", httpHookResponseLimit)
			}
		}
		if cErr := checkHookError(body); cErr != nil {
			return nil, true, cErr
		}
		return body, true, nil

	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		if rsp.Header.Get("retry-after") != "" {
			return nil, false, nil
		}
		return nil, true, internalServerError("Service currently unavailable due to hook")

	case http.StatusBadRequest:
		return nil, true, internalServerError("Invalid payload sent to hook")
	case http.StatusUnauthorized:
		return nil, true, internalServerError("Hook requires authorization token")
	default:
		return nil, true, internalServerError("Unexpected status code returned from hook: %d", rsp.StatusCode)
	}
}

// signHookPayload produces one "v1,<base64>" signature per configured secret over
// the Standard Webhooks signing string "<id>.<timestamp>.<body>". It is upstream
// hookshttp.generateSignatures. An empty secret list yields no signature header,
// which is valid for hooks the receiver does not verify.
func signHookPayload(secrets []string, msgID string, ts time.Time, payload []byte) ([]string, error) {
	var out []string
	toSign := fmt.Sprintf("%s.%d.%s", msgID, ts.Unix(), payload)
	for _, secret := range secrets {
		key, err := decodeHookSecret(secret)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(toSign))
		out = append(out, symmetricSecretPrefix+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return out, nil
}

// decodeHookSecret parses a configured "v1,whsec_<base64>" secret into the raw
// HMAC key. Anything else (missing scheme tag, non-symmetric key) is rejected,
// matching upstream's "invalid signature format".
func decodeHookSecret(secret string) ([]byte, error) {
	s := strings.TrimSpace(secret)
	if !strings.HasPrefix(s, symmetricSecretPrefix) {
		return nil, errors.New("invalid signature format")
	}
	s = strings.TrimPrefix(s, symmetricSecretPrefix)
	if !strings.HasPrefix(s, whsecPrefix) {
		return nil, errors.New("invalid signature format")
	}
	s = strings.TrimPrefix(s, whsecPrefix)
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook secret: %w", err)
	}
	return key, nil
}
