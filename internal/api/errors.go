package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/privacy"
)

// errorTypeBase is the documentation URI prefix used in the problem `type`
// member (docs/api-conventions.md "Error 응답").
const errorTypeBase = "https://dilion.dev/errors/"

// Problem is the RFC 9457 problem details body returned by every /privacy/v1
// and /iam/v1 endpoint. It is huma's ErrorModel plus the `code` extension that
// frontends branch on.
type Problem struct {
	Type     string              `json:"type,omitempty" format:"uri" doc:"URI reference to documentation for this error type."`
	Title    string              `json:"title,omitempty" doc:"Short, human-readable summary of the problem type."`
	Status   int                 `json:"status,omitempty" doc:"HTTP status code."`
	Detail   string              `json:"detail,omitempty" doc:"Human-readable explanation specific to this occurrence."`
	Instance string              `json:"instance,omitempty" format:"uri" doc:"URI reference identifying this specific occurrence."`
	Code     string              `json:"code" enum:"validation_failed,unauthenticated,permission_denied,not_found,conflict,idempotency_conflict,legal_hold_active,policy_violation,rate_limited,reauthentication_needed,internal" doc:"Machine-readable error code."`
	Errors   []*huma.ErrorDetail `json:"errors,omitempty" nullable:"false" doc:"Optional list of individual error details."`
}

func (p *Problem) Error() string {
	if p.Detail != "" {
		return p.Detail
	}
	return p.Title
}

// GetStatus satisfies huma.StatusError.
func (p *Problem) GetStatus() int { return p.Status }

// ContentType satisfies huma.ContentTypeFilter so errors are served as
// application/problem+json.
func (p *Problem) ContentType(ct string) string {
	if ct == "application/json" {
		return "application/problem+json"
	}
	return ct
}

// Add satisfies the shape huma uses for validation error accumulation.
func (p *Problem) Add(err error) {
	var d huma.ErrorDetailer
	if errors.As(err, &d) {
		p.Errors = append(p.Errors, d.ErrorDetail())
		return
	}
	p.Errors = append(p.Errors, &huma.ErrorDetail{Message: err.Error()})
}

// NewProblem builds a problem with an explicit machine-readable code.
func NewProblem(status int, code, detail string, errs ...error) *Problem {
	p := &Problem{
		Type:   errorTypeBase + strings.ReplaceAll(code, "_", "-"),
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Code:   code,
	}
	for _, err := range errs {
		if err == nil {
			continue
		}
		p.Add(err)
	}
	return p
}

// defaultCode maps a bare HTTP status to the conventional code, used for errors
// raised by huma itself (body parsing, param validation, ...).
func defaultCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return httpapi.CodeUnauthenticated
	case http.StatusForbidden:
		return httpapi.CodePermissionDenied
	case http.StatusNotFound:
		return httpapi.CodeNotFound
	case http.StatusConflict:
		return httpapi.CodeConflict
	case http.StatusTooManyRequests:
		return httpapi.CodeRateLimited
	case http.StatusBadRequest, http.StatusUnprocessableEntity,
		http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType,
		http.StatusNotAcceptable, http.StatusRequestTimeout:
		return httpapi.CodeValidationFailed
	default:
		if status >= 400 && status < 500 {
			return httpapi.CodeValidationFailed
		}
		return httpapi.CodeInternal
	}
}

// installErrorModel replaces huma's error constructor so that *every* error —
// including the ones huma raises internally for validation — carries the `code`
// extension and the problem+json content type. It runs once per process.
var installErrorModel = sync.OnceFunc(func() {
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		return NewProblem(status, defaultCode(status), msg, errs...)
	}
})

// ---- Sentinel error mapping ----

// mapPrivacyError maps the privacy engine's sentinel errors to problem codes
// (docs/api-conventions.md). Unknown errors become an opaque 500 — engine
// internals never reach the client.
func mapPrivacyError(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, privacy.ErrNotFound):
		return NewProblem(http.StatusNotFound, httpapi.CodeNotFound, "resource not found")
	case errors.Is(err, privacy.ErrIdempotencyReplay):
		return NewProblem(http.StatusConflict, httpapi.CodeIdempotencyConflict,
			"the same Idempotency-Key was used with a different request body")
	case errors.Is(err, privacy.ErrLegalHold):
		return NewProblem(http.StatusConflict, httpapi.CodeLegalHoldActive,
			"a legal hold is active for this subject")
	case errors.Is(err, privacy.ErrConflict):
		return NewProblem(http.StatusConflict, httpapi.CodeConflict, err.Error())
	case errors.Is(err, privacy.ErrPolicyViolation):
		return NewProblem(http.StatusBadRequest, httpapi.CodePolicyViolation, err.Error())
	case errors.Is(err, privacy.ErrInvalidInput):
		return NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed, err.Error())
	default:
		slog.ErrorContext(ctx, "privacy call failed", "error", err)
		return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal, "internal error")
	}
}

// mapAuditError maps internal/audit read errors to problem codes.
func mapAuditError(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrNotFound):
		return NewProblem(http.StatusNotFound, httpapi.CodeNotFound, "resource not found")
	case errors.Is(err, audit.ErrInvalid):
		return NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed, err.Error())
	default:
		slog.ErrorContext(ctx, "audit read failed", "error", err)
		return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal, "internal error")
	}
}

// mapIAMError maps internal/iam sentinel errors to problem codes.
func mapIAMError(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, iam.ErrNotFound):
		return NewProblem(http.StatusNotFound, httpapi.CodeNotFound, "resource not found")
	case errors.Is(err, iam.ErrConflict):
		return NewProblem(http.StatusConflict, httpapi.CodeConflict, err.Error())
	case errors.Is(err, iam.ErrInvalid), errors.Is(err, iam.ErrBuiltin):
		return NewProblem(http.StatusUnprocessableEntity, httpapi.CodeValidationFailed, err.Error())
	case errors.Is(err, iam.ErrUnauthenticated):
		return NewProblem(http.StatusUnauthorized, httpapi.CodeUnauthenticated, "invalid credentials")
	default:
		slog.ErrorContext(ctx, "iam call failed", "error", err)
		return NewProblem(http.StatusInternalServerError, httpapi.CodeInternal, "internal error")
	}
}
