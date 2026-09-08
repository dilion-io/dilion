package privacy

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dilion-io/dilion/ports"
)

func TestConsentProjectionMatchesLedgerWithEqualClock(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	for _, granted := range []bool{true, false, true, false} {
		if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{
			Purpose: "marketing.email", Granted: granted,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var matches bool
	if err := env.pool.QueryRow(env.ctx, `select cs.granted = (ce.action = 'GRANT') and cs.updated_at = ce.created_at
		from dilion_privacy.consent_state cs
		join lateral (select action, created_at from dilion_privacy.consent_events
		  where user_id = cs.user_id and purpose = cs.purpose and action in ('GRANT','WITHDRAW')
		  order by created_at desc, id desc limit 1) ce on true
		where cs.user_id = $1::uuid`, user).Scan(&matches); err != nil || !matches {
		t.Fatalf("projection diverged from ledger: %v %v", matches, err)
	}
}

func TestConsentBackfillAndBoundedReconciliation(t *testing.T) {
	env := newTestEngine(t, "compliance:\n  retention-batch-size: 1\n")
	for i := 0; i < 3; i++ {
		user := env.newUser(t)
		env.setPolicy(t, user, "kr")
		if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{
			Purpose: "marketing.email", Granted: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Recreate the projection as an existing installation would be backfilled.
	if _, err := env.pool.Exec(env.ctx, "delete from dilion_privacy.consent_state"); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/0202_consent_state.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(env.ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	for i := 0; i < 5; i++ {
		if err := env.e.scanReconfirmDue(env.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := env.pool.QueryRow(env.ctx, "select count(*) from dilion_privacy.consent_events where action='RECONFIRM_NOTICE'").Scan(&n); err != nil || n != 3 {
		t.Fatalf("backfilled schedules did not drain: %d %v", n, err)
	}
	// A new policy revision must eventually refresh every row, including rows
	// behind the cursor, without issuing another notice inside the period.
	env.e.policyRevision = "new-policy-revision"
	for i := 0; i < 5; i++ {
		if err := env.e.scanReconfirmDue(env.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.pool.QueryRow(env.ctx, "select count(*) from dilion_privacy.consent_state where schedule_revision=$1", env.e.policyRevision).Scan(&n); err != nil || n != 3 {
		t.Fatalf("policy revision not refreshed: %d %v", n, err)
	}
}

func TestConcurrentReconfirmScansEmitOneNotice(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "kr")
	if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{Purpose: "marketing.email", Granted: true}); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := env.e.scanReconfirmDue(env.ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var n int
	if err := env.pool.QueryRow(env.ctx, "select count(*) from dilion_privacy.outbox where event_type='consent.reconfirm_due'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate/missing notice: %d %v", n, err)
	}
}

func TestReconfirmSkipsShreddedKeysBeforeBatchLimit(t *testing.T) {
	env := newTestEngine(t, "compliance:\n  retention-batch-size: 1\n")
	for _, user := range []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"} {
		env.setPolicy(t, user, "kr")
		if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{Purpose: "marketing.email", Granted: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.kms.DestroyDEK(env.ctx, "00000000-0000-4000-8000-000000000001", ports.KeyScopeConsent); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatal(err)
	}
	var user string
	if err := env.pool.QueryRow(env.ctx, "select aggregate_id from dilion_privacy.outbox where event_type='consent.reconfirm_due'").Scan(&user); err != nil || user != "00000000-0000-4000-8000-000000000002" {
		t.Fatalf("shredded subject starved eligible notice: %s %v", user, err)
	}
}

func TestReconfirmRejectsStalePolicyAndWithdrawnCandidates(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "kr")
	st, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{
		Purpose: "marketing.email", Granted: true, PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := reconfirmCandidate{UserID: user, Purpose: st.Purpose, GrantedAt: st.UpdatedAt,
		Version: st.PolicyVersion, PolicyID: "kr"}
	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	env.setPolicy(t, user, "gdpr") // no reconfirmation under this policy
	if emitted, err := env.e.emitReconfirmNotice(env.ctx, c, env.clock.Now()); err != nil || emitted {
		t.Fatalf("stale policy emitted=%v err=%v", emitted, err)
	}
	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatal(err)
	}
	var due *time.Time
	if err := env.pool.QueryRow(env.ctx, "select next_reconfirm_at from dilion_privacy.consent_state where user_id=$1::uuid", user).Scan(&due); err != nil || due != nil {
		t.Fatalf("disabled policy retained due schedule: %v %v", due, err)
	}
	env.setPolicy(t, user, "kr")
	if _, err := env.e.UpdateConsent(env.ctx, "default", user, ConsentChange{
		Purpose: st.Purpose, Granted: false,
	}); err != nil {
		t.Fatal(err)
	}
	if emitted, err := env.e.emitReconfirmNotice(env.ctx, c, env.clock.Now()); err != nil || emitted {
		t.Fatalf("withdrawn candidate emitted=%v err=%v", emitted, err)
	}
}
