package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dilion-io/dilion/ports"
)

// newProfileUser seeds a subject and clears the placeholder vault row that
// newUser writes for the erasure pipeline, so the profile starts empty.
func (env *testEnv) newProfileUser(t *testing.T) string {
	t.Helper()
	id := env.newUser(t)
	if _, err := env.pool.Exec(env.ctx,
		`delete from dilion_pii.user_profiles where user_id = $1::uuid`, id); err != nil {
		t.Fatalf("clear seeded profile: %v", err)
	}
	return id
}

func (env *testEnv) profileRows(t *testing.T, userID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(env.ctx,
		`select count(*) from dilion_pii.user_profiles where user_id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	return n
}

func TestProfileRoundtripMaskedAndFull(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.GetProfile(env.ctx, "default", user, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get before write err = %v, want ErrNotFound", err)
	}

	set := map[string]ProfileField{
		"email":        {Value: "joseph@example.com", Hint: HintEmail},
		"name":         {Value: "홍길동", Hint: HintName},
		"phone":        {Value: "010-1234-5678", Hint: HintPhone},
		"home.address": {Value: "서울시 강남구 테헤란로 1", Hint: HintAddress},
		"nickname":     {Value: "dilion-dev", Hint: HintGeneric},
	}
	upd, err := env.e.UpdateProfile(env.ctx, "default", user, set, nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.View != ViewMasked {
		t.Errorf("update view = %s, want MASKED (writes never echo raw PII)", upd.View)
	}
	if upd.UpdatedAt == nil || !upd.UpdatedAt.Equal(env.clock.Now()) {
		t.Errorf("updated_at = %v, want the injected clock", upd.UpdatedAt)
	}

	masked, err := env.e.GetProfile(env.ctx, "default", user, false)
	if err != nil {
		t.Fatalf("get masked: %v", err)
	}
	if masked.View != ViewMasked || masked.UserID != user {
		t.Errorf("masked = %+v", masked)
	}
	want := map[string]string{
		"email": "j**@example.com", "name": "홍**", "phone": "010-****-5678",
		"home.address": "서울시 ***", "nickname": "****",
	}
	for k, v := range want {
		if masked.Fields[k].Value != v {
			t.Errorf("masked[%s] = %q, want %q", k, masked.Fields[k].Value, v)
		}
		if masked.Fields[k].Hint != set[k].Hint {
			t.Errorf("masked[%s] hint = %q, want %q", k, masked.Fields[k].Hint, set[k].Hint)
		}
	}
	if masked.UpdatedAt == nil || !masked.UpdatedAt.Equal(env.clock.Now()) {
		t.Errorf("get updated_at = %v", masked.UpdatedAt)
	}

	full, err := env.e.GetProfile(env.ctx, "default", user, true)
	if err != nil {
		t.Fatalf("get full: %v", err)
	}
	if full.View != ViewFull {
		t.Errorf("view = %s, want FULL", full.View)
	}
	for k, f := range set {
		if full.Fields[k].Value != f.Value {
			t.Errorf("full[%s] = %q, want %q", k, full.Fields[k].Value, f.Value)
		}
	}

	// The vault row must be ciphertext: no plaintext PII on disk (§2.7).
	var enc []byte
	if err := env.pool.QueryRow(env.ctx,
		`select enc_profile from dilion_pii.user_profiles where user_id = $1::uuid`, user).Scan(&enc); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if !strings.HasPrefix(string(enc), "enc:") {
		t.Errorf("profile is not sealed with the subject dek: %q", enc)
	}
	// The DEFAULT scope is what the erasure pipeline shreds first.
	var scopes int
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_pii.subject_keys
		where user_id = $1::uuid and scope = 'DEFAULT'`, user).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if scopes != 1 {
		t.Errorf("DEFAULT subject keys = %d, want 1", scopes)
	}

	// A partial write only touches the named keys.
	env.clock.Advance(time.Hour)
	after, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"name": {Value: "김철수", Hint: HintName}}, nil)
	if err != nil {
		t.Fatalf("partial update: %v", err)
	}
	if len(after.Fields) != len(set) {
		t.Fatalf("fields = %d, want %d (upsert must not drop the others)", len(after.Fields), len(set))
	}
	if after.Fields["name"].Value != "김**" || after.Fields["email"].Value != "j**@example.com" {
		t.Errorf("after partial update = %+v", after.Fields)
	}
	if after.UpdatedAt == nil || !after.UpdatedAt.Equal(env.clock.Now()) {
		t.Errorf("updated_at not advanced: %v", after.UpdatedAt)
	}

	if _, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"BadKey": {Value: "x", Hint: HintGeneric}}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad key err = %v, want ErrInvalidInput", err)
	}
	if _, err := env.e.GetProfile(env.ctx, "default", "not-a-uuid", false); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad uuid err = %v, want ErrInvalidInput", err)
	}
}

func TestProfileRemoveKeysAndRowDeletion(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"email":    {Value: "joseph@example.com", Hint: HintEmail},
		"name":     {Value: "홍길동", Hint: HintName},
		"nickname": {Value: "dev", Hint: HintGeneric},
	}, nil); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	got, err := env.e.UpdateProfile(env.ctx, "default", user, nil, []string{"nickname", "never.stored"})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, still := got.Fields["nickname"]; still {
		t.Error("removed key still present")
	}
	if len(got.Fields) != 2 {
		t.Fatalf("fields = %+v, want email+name", got.Fields)
	}
	if env.profileRows(t, user) != 1 {
		t.Error("row must survive a partial removal")
	}

	// set + remove in one call; remove wins for keys in both.
	got, err = env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"phone": {Value: "01012345678", Hint: HintPhone}}, []string{"email"})
	if err != nil {
		t.Fatalf("set+remove: %v", err)
	}
	if _, still := got.Fields["email"]; still || got.Fields["phone"].Value != "010-****-5678" {
		t.Fatalf("fields = %+v", got.Fields)
	}

	// Emptying the document drops the row entirely.
	empty, err := env.e.UpdateProfile(env.ctx, "default", user, nil, []string{"name", "phone"})
	if err != nil {
		t.Fatalf("remove all: %v", err)
	}
	if len(empty.Fields) != 0 || empty.View != ViewMasked || empty.UpdatedAt != nil {
		t.Errorf("emptied profile = %+v", empty)
	}
	if n := env.profileRows(t, user); n != 0 {
		t.Errorf("profile rows = %d, want the row deleted when no fields remain", n)
	}
	if _, err := env.e.GetProfile(env.ctx, "default", user, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after emptying err = %v, want ErrNotFound", err)
	}
	// A removal against an absent profile is a no-op, not an error.
	if _, err := env.e.UpdateProfile(env.ctx, "default", user, nil, []string{"name"}); err != nil {
		t.Errorf("remove on absent profile: %v", err)
	}
}

func TestProfileWriteBlockedByActiveDeletion(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"name": {Value: "홍길동", Hint: HintName}}, nil); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	if _, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"name": {Value: "김철수", Hint: HintName}}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("write during deletion err = %v, want ErrConflict", err)
	}
	if _, err := env.e.UpdateProfile(env.ctx, "default", user, nil, []string{"name"}); !errors.Is(err, ErrConflict) {
		t.Errorf("remove during deletion err = %v, want ErrConflict", err)
	}
	// Reads stay available while the request is in the grace window.
	got, err := env.e.GetProfile(env.ctx, "default", user, false)
	if err != nil || got.Fields["name"].Value != "홍**" {
		t.Fatalf("get during deletion = %+v (%v)", got, err)
	}

	// Cancelling releases the gate.
	if _, err := env.e.CancelRequest(env.ctx, "default", req.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"name": {Value: "김철수", Hint: HintName}}, nil); err != nil {
		t.Errorf("write after cancel: %v", err)
	}
}

func TestProfileUnreadableAfterCryptoShred(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"email": {Value: "joseph@example.com", Hint: HintEmail},
	}, nil); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := env.kms.DestroyDEK(env.ctx, user, ports.KeyScopeDefault); err != nil {
		t.Fatalf("shred: %v", err)
	}

	// The row is still there, but nobody can read it — that is the point.
	if env.profileRows(t, user) != 1 {
		t.Fatal("test setup: the vault row should still exist")
	}
	if _, err := env.e.GetProfile(env.ctx, "default", user, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("masked get after shred err = %v, want ErrNotFound", err)
	}
	if _, err := env.e.GetProfile(env.ctx, "default", user, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("full get after shred err = %v, want ErrNotFound", err)
	}
	if _, err := env.e.UpdateProfile(env.ctx, "default", user,
		map[string]ProfileField{"name": {Value: "홍길동", Hint: HintName}}, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("write after shred err = %v, want ErrNotFound", err)
	}
}

func TestProfileErasurePipelineRemovesTheVaultRow(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"email": {Value: "joseph@example.com", Hint: HintEmail},
	}, nil); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{
		UserID: user, Type: RequestDeletion, Immediate: true}); err != nil {
		t.Fatalf("create request: %v", err)
	}
	env.drain(t, 2)

	if n := env.profileRows(t, user); n != 0 {
		t.Errorf("vault rows after erasure = %d, want 0", n)
	}
	if _, err := env.e.GetProfile(env.ctx, "default", user, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after erasure err = %v, want ErrNotFound", err)
	}
}

func TestProfileRevealHookGatesFullView(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newProfileUser(t)

	if _, err := env.e.UpdateProfile(env.ctx, "default", user, map[string]ProfileField{
		"email": {Value: "joseph@example.com", Hint: HintEmail},
	}, nil); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	var calls int
	var gotUser, gotProject any
	env.hooks.Register(ports.PIIReveal, func(_ context.Context, p map[string]any) (map[string]any, error) {
		calls++
		gotUser, gotProject = p["user_id"], p["project_id"]
		if calls > 1 {
			return nil, errors.New("reveal reason missing")
		}
		return nil, nil
	})

	if _, err := env.e.GetProfile(env.ctx, "default", user, false); err != nil {
		t.Fatalf("masked get: %v", err)
	}
	if calls != 0 {
		t.Error("the masked projection must not trigger pii_reveal")
	}

	full, err := env.e.GetProfile(env.ctx, "default", user, true)
	if err != nil {
		t.Fatalf("full get: %v", err)
	}
	if full.Fields["email"].Value != "joseph@example.com" {
		t.Errorf("full = %+v", full.Fields)
	}
	if gotUser != user || gotProject != "default" {
		t.Errorf("hook payload = user %v / project %v", gotUser, gotProject)
	}

	// A rejecting hook blocks the reveal (fail-closed).
	if _, err := env.e.GetProfile(env.ctx, "default", user, true); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("rejected reveal err = %v, want ErrPolicyViolation", err)
	}
}
