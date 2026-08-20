// Package privacy is the compliance engine (project.md §2.8–§2.10).
// This file is the CONTRACT between the engine (implementer: agent C) and the
// HTTP layer (consumer: agent D). Do not modify without lead approval.
package privacy

import (
	"context"
	"time"

	"github.com/dilion-io/dilion/httpapi"
)

// ---- Enums (UPPER_SNAKE_CASE per api-conventions) ----

type RequestType string

const (
	RequestDeletion          RequestType = "DELETION"
	RequestExport            RequestType = "EXPORT"
	RequestConsentWithdrawal RequestType = "CONSENT_WITHDRAWAL"
)

type RequestStatus string

const (
	StatusRequested    RequestStatus = "REQUESTED"
	StatusProcessing   RequestStatus = "PROCESSING"
	StatusDone         RequestStatus = "DONE"
	StatusManualReview RequestStatus = "MANUAL_REVIEW"
	StatusCanceled     RequestStatus = "CANCELED"
)

type ErasureAction string

const (
	ActionDelete      ErasureAction = "DELETE"
	ActionAnonymize   ErasureAction = "ANONYMIZE"
	ActionCryptoShred ErasureAction = "CRYPTO_SHRED"
	ActionKeep        ErasureAction = "KEEP"
)

type DestinationType string

const (
	DestinationWebhook   DestinationType = "WEBHOOK"
	DestinationConnector DestinationType = "CONNECTOR"
)

// ---- DTOs ----

type Request struct {
	ID          string        `json:"id"`
	UserID      string        `json:"user_id"`
	Type        RequestType   `json:"type"`
	Status      RequestStatus `json:"status"`
	PolicyID    string        `json:"policy_id"`
	ScheduledAt time.Time     `json:"scheduled_at"`
	RequestedAt time.Time     `json:"requested_at"`
	CompletedAt *time.Time    `json:"completed_at"`
}

type CreateRequestInput struct {
	UserID         string
	Type           RequestType
	Immediate      bool   // 즉시 파기 경로 (§2.9): grace 생략, scheduled_at = now
	IdempotencyKey string // optional
	RequestedBy    string // actor id (audit용)
}

type ConsentState struct {
	Purpose       string     `json:"purpose"`
	Granted       bool       `json:"granted"`
	PolicyVersion string     `json:"policy_version"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ReconfirmDue  *time.Time `json:"reconfirm_due"` // 확인 고지 예정 시각 (nullable)
}

type ConsentChange struct {
	Purpose       string `json:"purpose"`
	Granted       bool   `json:"granted"`
	PolicyVersion string `json:"policy_version"`
	Source        string `json:"source"` // ui | api | import
}

type Destination struct {
	ID      string          `json:"id"`
	Type    DestinationType `json:"type"`
	Name    string          `json:"name"`
	Config  map[string]any  `json:"config"` // webhook: {url, identity_field}; secret은 미노출
	Enabled bool            `json:"enabled"`
}

type CreateDestinationInput struct {
	Type   DestinationType
	Name   string
	Config map[string]any
	Secret string // webhook HMAC secret (저장은 hash/암호화, 응답 미노출)
}

type LegalHold struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Domain     *string    `json:"domain"` // nil = subject 전체
	Reason     string     `json:"reason"`
	Basis      string     `json:"basis"`
	CreatedAt  time.Time  `json:"created_at"`
	ReleasedAt *time.Time `json:"released_at"`
}

type CreateHoldInput struct {
	UserID    string
	Domain    *string
	Reason    string
	Basis     string
	CreatedBy string
}

// ---- PII Profile (project.md §2.6/§2.7 — Vault + masked projection) ----

type FieldHint string

const (
	HintEmail   FieldHint = "EMAIL"   // j**@domain.com
	HintName    FieldHint = "NAME"    // 홍**
	HintPhone   FieldHint = "PHONE"   // 010-****-1234 (앞 3, 뒤 4 유지)
	HintAddress FieldHint = "ADDRESS" // 첫 토큰 + " ***"
	HintGeneric FieldHint = "GENERIC" // ****
)

type ProfileField struct {
	Value string    `json:"value"`
	Hint  FieldHint `json:"hint"`
}

type ProfileView string

const (
	ViewMasked ProfileView = "MASKED"
	ViewFull   ProfileView = "FULL"
)

// Profile is the decrypted projection of dilion_pii.user_profiles.
// Fields is an arbitrary key→field map (custom PII fields supported).
type Profile struct {
	UserID    string                  `json:"user_id"`
	Fields    map[string]ProfileField `json:"fields"`
	View      ProfileView             `json:"view"`
	UpdatedAt *time.Time              `json:"updated_at"`
}

// ---- Sentinel errors (D maps these to problem+json codes) ----

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrNotFound          Error = "privacy: not found"
	ErrConflict          Error = "privacy: conflict"             // 진행 중 요청 중복 등
	ErrIdempotencyReplay Error = "privacy: idempotency conflict" // 같은 키, 다른 body
	ErrLegalHold         Error = "privacy: legal hold active"
	ErrPolicyViolation   Error = "privacy: policy violation" // required consent 위반 등
)

// ---- Service (C implements, D consumes) ----

type Service interface {
	// Requests
	CreateRequest(ctx context.Context, in CreateRequestInput) (*Request, error)
	GetRequest(ctx context.Context, id string) (*Request, error)
	ListRequests(ctx context.Context, status *RequestStatus, p httpapi.ListParams) (httpapi.Page[Request], error)
	CancelRequest(ctx context.Context, id string) (*Request, error) // REQUESTED(유예 중)만 가능

	// Consents (user 단위 현재 상태 projection + append-only ledger 기록)
	GetConsents(ctx context.Context, userID string) ([]ConsentState, error)
	UpdateConsent(ctx context.Context, userID string, ch ConsentChange) (*ConsentState, error)

	// Destinations
	CreateDestination(ctx context.Context, in CreateDestinationInput) (*Destination, error)
	GetDestination(ctx context.Context, id string) (*Destination, error)
	ListDestinations(ctx context.Context, p httpapi.ListParams) (httpapi.Page[Destination], error)
	UpdateDestination(ctx context.Context, id string, enabled *bool, config map[string]any) (*Destination, error)
	DeleteDestination(ctx context.Context, id string) error

	// PII Profile (custom field 지원; full=false는 hint 기반 masked 프로젝션.
	// full=true는 호출자가 pii.reveal 권한·사유·PII_FULL_READ 감사를 책임진다.)
	GetProfile(ctx context.Context, userID string, full bool) (*Profile, error)
	// UpdateProfile: set은 upsert, remove는 키 삭제. masked 프로젝션을 반환.
	UpdateProfile(ctx context.Context, userID string, set map[string]ProfileField, remove []string) (*Profile, error)

	// Legal holds (§2.9)
	CreateHold(ctx context.Context, in CreateHoldInput) (*LegalHold, error)
	ReleaseHold(ctx context.Context, id, releasedBy string) (*LegalHold, error)
	ListHolds(ctx context.Context, userID *string, p httpapi.ListParams) (httpapi.Page[LegalHold], error)
}
