package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

const destinationCols = `id, type, name, config, enabled`

// minWebhookSecret is the shortest HMAC key a webhook destination accepts.
const minWebhookSecret = 32

func scanDestination(row pgx.Row) (*Destination, error) {
	var d Destination
	var cfg []byte
	if err := row.Scan(&d.ID, &d.Type, &d.Name, &cfg, &d.Enabled); err != nil {
		return nil, err
	}
	d.Config = map[string]any{}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &d.Config); err != nil {
			return nil, fmt.Errorf("privacy: destination config: %w", err)
		}
	}
	// The secret is never part of the projection (§3.2).
	delete(d.Config, "secret")
	return &d, nil
}

func validateDestination(t DestinationType, cfg map[string]any) error {
	switch t {
	case DestinationWebhook:
		raw, _ := cfg["url"].(string)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%w: webhook destination requires config.url (absolute http(s) URL)", ErrInvalidInput)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%w: webhook url scheme must be http or https", ErrInvalidInput)
		}
	case DestinationConnector:
		if name, _ := cfg["connector"].(string); strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: connector destination requires config.connector", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unknown destination type %q", ErrInvalidInput, t)
	}
	return nil
}

// CreateDestination registers a delivery target. The HMAC secret is stored
// encrypted under the system KMS subject and never returned.
func (e *Engine) CreateDestination(ctx context.Context, in CreateDestinationInput) (*Destination, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	cfg := in.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	delete(cfg, "secret")
	if err := validateDestination(in.Type, cfg); err != nil {
		return nil, err
	}
	if in.Type == DestinationConnector {
		name, _ := cfg["connector"].(string)
		if _, ok := e.connectors[name]; !ok {
			return nil, fmt.Errorf("%w: no connector %q is registered", ErrInvalidInput, name)
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("privacy: destination config: %w", err)
	}

	// Receivers act on these calls — a privacy.delete erases an account — so
	// they must be able to tell them from forgeries: a webhook is signed, and
	// with a key worth the name.
	if in.Type == DestinationWebhook && len(in.Secret) < minWebhookSecret {
		return nil, fmt.Errorf("%w: a webhook destination needs a secret of at least %d bytes", ErrInvalidInput, minWebhookSecret)
	}
	var secretEnc []byte
	if in.Secret != "" {
		secretEnc, err = e.kms.Encrypt(ctx, systemSubjectID, ports.KeyScopeDefault, []byte(in.Secret))
		if err != nil {
			return nil, fmt.Errorf("privacy: encrypt destination secret: %w", err)
		}
	}

	const ins = `insert into dilion_privacy.destinations
		(id, type, name, config, secret_enc, enabled, created_at)
		values ($1,$2,$3,$4::jsonb,$5,true,$6) returning ` + destinationCols
	d, err := scanDestination(e.pool.QueryRow(ctx, ins, httpapi.NewID("dst"), in.Type, in.Name,
		string(raw), secretEnc, e.now()))
	if err != nil {
		return nil, fmt.Errorf("privacy: create destination: %w", err)
	}
	e.log.Info("destination created", "destination_id", d.ID, "type", d.Type)
	return d, nil
}

func (e *Engine) GetDestination(ctx context.Context, id string) (*Destination, error) {
	const q = `select ` + destinationCols + ` from dilion_privacy.destinations
		where id = $1`
	d, err := scanDestination(e.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: get destination: %w", err)
	}
	return d, nil
}

func (e *Engine) ListDestinations(ctx context.Context, p httpapi.ListParams) (httpapi.Page[Destination], error) {
	p = p.Norm()
	var zero httpapi.Page[Destination]
	cur, err := decodeIDCursor(p.Cursor)
	if err != nil {
		return zero, err
	}
	const q = `select ` + destinationCols + ` from dilion_privacy.destinations
		where $1 = '' or id > $1
		order by id limit $2`
	rows, err := e.pool.Query(ctx, q, cur, p.Limit+1)
	if err != nil {
		return zero, fmt.Errorf("privacy: list destinations: %w", err)
	}
	defer rows.Close()
	var items []Destination
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			return zero, fmt.Errorf("privacy: list destinations: %w", err)
		}
		items = append(items, *d)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("privacy: list destinations: %w", err)
	}
	return page(items, p.Limit, func(d Destination) *string { return encodeIDCursor(d.ID) }), nil
}

// UpdateDestination patches enabled and/or config (config is replaced whole).
func (e *Engine) UpdateDestination(ctx context.Context, id string, enabled *bool, config map[string]any) (*Destination, error) {
	cur, err := e.GetDestination(ctx, id)
	if err != nil {
		return nil, err
	}
	next := cur.Config
	if config != nil {
		delete(config, "secret")
		if err := validateDestination(cur.Type, config); err != nil {
			return nil, err
		}
		next = config
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return nil, fmt.Errorf("privacy: destination config: %w", err)
	}
	en := cur.Enabled
	if enabled != nil {
		en = *enabled
	}
	const upd = `update dilion_privacy.destinations set config = $2::jsonb, enabled = $3
		where id = $1 returning ` + destinationCols
	d, err := scanDestination(e.pool.QueryRow(ctx, upd, id, string(raw), en))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: update destination: %w", err)
	}
	return d, nil
}

func (e *Engine) DeleteDestination(ctx context.Context, id string) error {
	tag, err := e.pool.Exec(ctx, `delete from dilion_privacy.destinations where id = $1`,
		id)
	if err != nil {
		return fmt.Errorf("privacy: delete destination: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	e.log.Info("destination deleted", "destination_id", id)
	return nil
}

// destinationSecret decrypts the stored HMAC secret for signing.
func (e *Engine) destinationSecret(ctx context.Context, enc []byte) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	plain, err := e.kms.Decrypt(ctx, systemSubjectID, ports.KeyScopeDefault, enc)
	if err != nil {
		return "", fmt.Errorf("privacy: decrypt destination secret: %w", err)
	}
	return string(plain), nil
}
