package privacy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/ports"
)

const (
	maxTaskAttempts    = 5
	maxTasksPerTick    = 25
	maxEvidenceBody    = 2048
	backoffBase        = 5 * time.Second
	backoffCap         = 15 * time.Minute
	stuckRunningAfter  = 10 * time.Minute
	eventPrivacyDelete = "privacy.delete"
	eventReconfirmDue  = "consent.reconfirm_due"
)

// Task actions.
const (
	TaskActionDelete    = "DELETE"
	TaskActionReconfirm = "RECONFIRM_NOTICE"
)

type task struct {
	ID            string
	RequestID     string
	UserID        string
	DestinationID string
	Action        string
	AttemptCount  int
	CreatedAt     time.Time
	Payload       []byte
}

// signPayload implements the §3.2 signature base string: "<unix>.<body>".
func signPayload(secret string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d.", ts)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// signatureHeader renders the Dilion-Signature header value.
func signatureHeader(secret string, ts int64, body []byte) string {
	return fmt.Sprintf("t=%d,v1=%s", ts, signPayload(secret, ts, body))
}

// backoffFor returns the delay before attempt n+1 (exponential + jitter).
func backoffFor(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Duration(float64(backoffBase) * math.Pow(2, float64(attempt-1)))
	if d > backoffCap || d <= 0 {
		d = backoffCap
	}
	// full jitter on the last 25% to avoid thundering herds
	return d + time.Duration(rand.Int64N(int64(d/4)+1))
}

// runTasksOnce claims and executes a batch of due delivery tasks.
func (e *Engine) runTasksOnce(ctx context.Context) error {
	// Tasks left 'running' by a crashed worker are re-claimed after
	// stuckRunningAfter; the attempt counter still applies, so a task that
	// repeatedly kills its worker ends up dead-lettered rather than looping.
	const claim = `update dilion_privacy.tasks t
		set status = 'running', started_at = $1, attempt_count = t.attempt_count + 1
		where t.id in (
			select id from dilion_privacy.tasks
			where (status in ('pending','failed') and next_attempt_at <= $1)
			   or (status = 'running' and started_at < $3)
			order by next_attempt_at limit $2 for update skip locked)
		returning t.id, t.request_id, t.user_id::text, t.destination_id, t.action,
		          t.attempt_count, t.created_at, t.payload`
	rows, err := e.pool.Query(ctx, claim, e.now(), maxTasksPerTick, e.now().Add(-stuckRunningAfter))
	if err != nil {
		return fmt.Errorf("privacy: claim tasks: %w", err)
	}
	var batch []task
	for rows.Next() {
		var t task
		if err := rows.Scan(&t.ID, &t.RequestID, &t.UserID, &t.DestinationID, &t.Action,
			&t.AttemptCount, &t.CreatedAt, &t.Payload); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: claim tasks: %w", err)
		}
		batch = append(batch, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: claim tasks: %w", err)
	}

	for _, t := range batch {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := e.executeTask(ctx, t); err != nil {
			e.log.Error("task execution failed", "task_id", t.ID, "err", err)
		}
	}
	return nil
}

type destinationRow struct {
	ID        string
	Type      DestinationType
	Name      string
	Config    map[string]any
	SecretEnc []byte
	Enabled   bool
}

func (e *Engine) loadDestination(ctx context.Context, id string) (*destinationRow, error) {
	var d destinationRow
	var cfg []byte
	err := e.pool.QueryRow(ctx,
		`select id, type, name, config, secret_enc, enabled from dilion_privacy.destinations where id = $1`, id).
		Scan(&d.ID, &d.Type, &d.Name, &cfg, &d.SecretEnc, &d.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: load destination: %w", err)
	}
	d.Config = map[string]any{}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &d.Config); err != nil {
			return nil, fmt.Errorf("privacy: destination config: %w", err)
		}
	}
	return &d, nil
}

func (e *Engine) executeTask(ctx context.Context, t task) error {
	dst, err := e.loadDestination(ctx, t.DestinationID)
	if errors.Is(err, ErrNotFound) {
		return e.failTask(ctx, t, "DESTINATION_MISSING", map[string]any{"destination_id": t.DestinationID}, true)
	}
	if err != nil {
		return e.failTask(ctx, t, "DESTINATION_LOAD_FAILED", map[string]any{"error": err.Error()}, false)
	}
	if !dst.Enabled {
		return e.failTask(ctx, t, "DESTINATION_DISABLED", map[string]any{"destination_id": dst.ID}, true)
	}

	switch dst.Type {
	case DestinationWebhook:
		return e.executeWebhook(ctx, t, dst)
	case DestinationConnector:
		return e.executeConnector(ctx, t, dst)
	default:
		return e.failTask(ctx, t, "UNKNOWN_DESTINATION_TYPE", map[string]any{"type": string(dst.Type)}, true)
	}
}

// eventBody builds the delivery document (§3.2).
func (e *Engine) eventBody(ctx context.Context, t task) (map[string]any, error) {
	event := eventPrivacyDelete
	if t.Action == TaskActionReconfirm {
		event = eventReconfirmDue
	}
	requestedAt := t.CreatedAt
	var at time.Time
	err := e.pool.QueryRow(ctx,
		`select requested_at from dilion_privacy.personal_data_requests where id = $1`, t.RequestID).Scan(&at)
	if err == nil {
		requestedAt = at
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("privacy: request lookup: %w", err)
	}

	body := map[string]any{
		"event":        event,
		"id":           httpapi.NewID("evt"),
		"request_id":   t.RequestID,
		"user_id":      t.UserID,
		"requested_at": requestedAt.UTC().Format(time.RFC3339),
	}
	// Extra fields for non-erasure events (purpose, policy_version...).
	if len(t.Payload) > 0 {
		var extra map[string]any
		if err := json.Unmarshal(t.Payload, &extra); err == nil {
			for k, v := range extra {
				if _, taken := body[k]; !taken {
					body[k] = v
				}
			}
		}
	}
	return body, nil
}

func (e *Engine) executeWebhook(ctx context.Context, t task, dst *destinationRow) error {
	rawURL, _ := dst.Config["url"].(string)
	if rawURL == "" {
		return e.failTask(ctx, t, "DESTINATION_URL_MISSING", nil, true)
	}
	doc, err := e.eventBody(ctx, t)
	if err != nil {
		return err
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	secret, err := e.destinationSecret(ctx, dst.SecretEnc)
	if err != nil {
		return e.failTask(ctx, t, "SECRET_UNAVAILABLE", map[string]any{"error": err.Error()}, false)
	}

	ts := e.now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return e.failTask(ctx, t, "REQUEST_BUILD_FAILED", map[string]any{"error": err.Error()}, true)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", t.ID)
	req.Header.Set("Dilion-Signature", signatureHeader(secret, ts, body))
	req.Header.Set("User-Agent", "dilion-privacy/1")

	resp, err := e.http.Do(req)
	if err != nil {
		return e.failTask(ctx, t, "TRANSPORT_ERROR", map[string]any{
			"error": err.Error(), "url": rawURL, "event_id": doc["id"],
		}, false)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxEvidenceBody))

	// §3.2: an HTTP 200 is not the evidence — the receipt is. We record the
	// receipt fields returned by the peer alongside the transport result.
	evidence := map[string]any{
		"transport":     "webhook",
		"url":           rawURL,
		"event":         doc["event"],
		"event_id":      doc["id"],
		"http_status":   resp.StatusCode,
		"signature_ts":  ts,
		"attempt":       t.AttemptCount,
		"response_body": string(respBody),
	}
	var receipt struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &receipt); err == nil && receipt.Status != "" {
		evidence["receipt_request_id"] = receipt.RequestID
		evidence["receipt_status"] = receipt.Status
		evidence["receipt_verified"] = receipt.RequestID == t.RequestID
	} else {
		evidence["receipt_verified"] = false
		evidence["receipt_missing"] = true
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		evidence["error"] = fmt.Sprintf("http %d", resp.StatusCode)
		return e.failTask(ctx, t, fmt.Sprintf("HTTP_%d", resp.StatusCode), evidence, false)
	}
	if v, _ := evidence["receipt_verified"].(bool); !v {
		e.log.Warn("webhook returned 2xx without a matching execution receipt",
			"task_id", t.ID, "destination_id", dst.ID)
	}
	return e.completeTask(ctx, t, evidence)
}

func (e *Engine) executeConnector(ctx context.Context, t task, dst *destinationRow) error {
	name, _ := dst.Config["connector"].(string)
	c, ok := e.connectors[name]
	if !ok {
		return e.failTask(ctx, t, "CONNECTOR_NOT_REGISTERED", map[string]any{"connector": name}, true)
	}
	receipt, err := c.Execute(ctx, ports.ConnectorTask{
		TaskID:        t.ID,
		RequestID:     t.RequestID,
		UserID:        t.UserID,
		DestinationID: dst.ID,
		Action:        t.Action,
		Config:        dst.Config,
	})
	evidence := map[string]any{
		"transport": "connector",
		"connector": name,
		"attempt":   t.AttemptCount,
	}
	if err != nil {
		evidence["error"] = err.Error()
		return e.failTask(ctx, t, "CONNECTOR_ERROR", evidence, false)
	}
	evidence["receipt_status"] = receipt.Status
	evidence["receipt_code"] = receipt.ResultCode
	evidence["receipt_detail"] = receipt.Detail
	evidence["receipt_task_id"] = receipt.TaskID
	if !receipt.CompletedAt.IsZero() {
		evidence["receipt_completed_at"] = receipt.CompletedAt.UTC().Format(time.RFC3339)
	}
	evidence["receipt_verified"] = receipt.TaskID == t.ID
	if receipt.Status != "completed" {
		return e.failTask(ctx, t, "CONNECTOR_"+receipt.ResultCode, evidence, false)
	}
	return e.completeTask(ctx, t, evidence)
}

func (e *Engine) completeTask(ctx context.Context, t task, evidence map[string]any) error {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx, `update dilion_privacy.tasks
		set status = 'completed', completed_at = $2, evidence = $3::jsonb, error_code = null
		where id = $1`, t.ID, e.now(), string(raw)); err != nil {
		return fmt.Errorf("privacy: complete task: %w", err)
	}
	e.log.Info("delivery task completed", "task_id", t.ID, "request_id", t.RequestID,
		"destination_id", t.DestinationID, "attempt", t.AttemptCount)
	return nil
}

// failTask records the failed attempt and either schedules a retry or moves the
// task to the dead-letter state (§3.2 retry + DLQ requirement).
func (e *Engine) failTask(ctx context.Context, t task, code string, evidence map[string]any, terminal bool) error {
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidence["error_code"] = code
	evidence["attempt"] = t.AttemptCount
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	dead := terminal || t.AttemptCount >= maxTaskAttempts
	status, next := "failed", e.now().Add(backoffFor(t.AttemptCount))
	if dead {
		status, next = "dead", e.now()
	}
	if _, err := e.pool.Exec(ctx, `update dilion_privacy.tasks
		set status = $2, error_code = $3, evidence = $4::jsonb, next_attempt_at = $5
		where id = $1`, t.ID, status, code, string(raw), next); err != nil {
		return fmt.Errorf("privacy: fail task: %w", err)
	}
	if dead {
		e.log.Error("delivery task dead-lettered", "task_id", t.ID, "request_id", t.RequestID,
			"destination_id", t.DestinationID, "code", code, "attempts", t.AttemptCount)
	} else {
		e.log.Warn("delivery task failed; will retry", "task_id", t.ID, "code", code,
			"attempt", t.AttemptCount, "next_attempt_at", next)
	}
	return nil
}
