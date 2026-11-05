// Command perf measures how many concurrent requests a running Dilion server
// sustains, and at what latency, with a given number of accounts in its
// database. It is what .github/workflows/perf.yml runs; locally:
//
//	make up && DILION_DSN=... DILION_JWT_SECRET=... go run ./cmd/dilion &
//	go run ./test/perf -dsn postgres://dilion:dilion@localhost:55432/dilion_dev \
//	    -url http://localhost:8787 -accounts 1000
//
// It seeds the accounts straight into auth.users (one bcrypt hash at the
// server's cost, shared by all of them), then runs each scenario in steps of
// increasing concurrency. Every step is a closed loop: that many virtual users
// each send their next request as soon as the previous one answers, with no
// think time, so "concurrency" is requests in flight, not people signed in.
// A step passes when its p95 latency is within -slo and fewer than 1% of its
// requests fail; the ramp stops at the first step that does not. The largest
// passing step is the scenario's sustained concurrency.
//
// Scenarios:
//
//	sign-in        POST /token?grant_type=password for a random account
//	               (bcrypt dominates: this is the CPU-bound path)
//	session-check  per virtual user, signed in beforehand: GET /user, over
//	               and over (what a client or an API checking a session
//	               sends most)
//	session-mix    per virtual user, signed in beforehand: four GET /user,
//	               then one POST /token?grant_type=refresh_token rotating
//	               its own token (signed-in clients, refresh included)
//
// The server, Postgres and this load generator share one machine in CI, so
// the numbers are for comparing runs with each other, not a capacity plan.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/dilion-io/dilion/internal/auth"
)

const password = "perf-password-1"

type config struct {
	dsn, url string
	accounts int
	levels   []int
	duration time.Duration
	slo      time.Duration
	out      string
	summary  string

	// profileURL is the server's pprof base URL; when set, a CPU profile is
	// taken during each scenario's step at concurrency profileAt and saved
	// in profileDir as cpu-<scenario>.pprof.
	profileURL string
	profileAt  int
	profileDir string
	// pgstat collects each scenario's heaviest statements from
	// pg_stat_statements (the extension must be preloaded).
	pgstat bool
}

// step is one concurrency level of one scenario.
type step struct {
	Concurrency int     `json:"concurrency"`
	Requests    int     `json:"requests"`
	Errors      int     `json:"errors"`
	ErrorRate   float64 `json:"error_rate"`
	RPS         float64 `json:"rps"`
	P50ms       float64 `json:"p50_ms"`
	P95ms       float64 `json:"p95_ms"`
	P99ms       float64 `json:"p99_ms"`
	MaxMs       float64 `json:"max_ms"`
	Pass        bool    `json:"pass"`
	// FirstError is a sample of what failed, for the log.
	FirstError string `json:"first_error,omitempty"`
}

type scenarioResult struct {
	Name string `json:"name"`
	// MaxConcurrency is the largest step that passed (0: none did).
	MaxConcurrency int    `json:"max_concurrency"`
	Steps          []step `json:"steps"`
	// Statements are the scenario's heaviest SQL statements by total
	// execution time (-pgstat).
	Statements []statement `json:"statements,omitempty"`
}

// statement is one pg_stat_statements row.
type statement struct {
	Query   string  `json:"query"`
	Calls   int64   `json:"calls"`
	TotalMs float64 `json:"total_ms"`
	MeanMs  float64 `json:"mean_ms"`
}

type report struct {
	Accounts  int              `json:"accounts"`
	SLOp95ms  float64          `json:"slo_p95_ms"`
	StepSecs  float64          `json:"step_seconds"`
	SeedSecs  float64          `json:"seed_seconds"`
	Scenarios []scenarioResult `json:"scenarios"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "perf:", err)
		os.Exit(1)
	}
}

func run() error {
	var cfg config
	var levels string
	flag.StringVar(&cfg.dsn, "dsn", "", "Postgres DSN of the server's database (seeded directly)")
	flag.StringVar(&cfg.url, "url", "http://localhost:8787", "server base URL")
	flag.IntVar(&cfg.accounts, "accounts", 1000, "accounts to seed")
	flag.StringVar(&levels, "levels", "1,5,10,25,50,100,200,400", "concurrency steps, comma-separated")
	flag.DurationVar(&cfg.duration, "duration", 15*time.Second, "length of each step")
	flag.DurationVar(&cfg.slo, "slo", 500*time.Millisecond, "p95 latency a step must stay within")
	flag.StringVar(&cfg.out, "out", "", "write the report as JSON to this file")
	flag.StringVar(&cfg.summary, "summary", "", "append a Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
	flag.StringVar(&cfg.profileURL, "profile-url", "", "server pprof base URL (DILION_PPROF_ADDR), e.g. http://127.0.0.1:6060")
	flag.IntVar(&cfg.profileAt, "profile-at", 50, "concurrency step to take each scenario's CPU profile at")
	flag.StringVar(&cfg.profileDir, "profile-dir", ".", "directory for the CPU profiles")
	flag.BoolVar(&cfg.pgstat, "pgstat", false, "record each scenario's heaviest statements from pg_stat_statements")
	combine := flag.String("combine", "", "instead of running: compare these comma-separated JSON reports in the -summary file")
	flag.Parse()
	if *combine != "" {
		return combineReports(strings.Split(*combine, ","), cfg.summary)
	}
	if cfg.dsn == "" {
		return errors.New("-dsn is required")
	}
	for _, f := range strings.Split(levels, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			return fmt.Errorf("-levels: %q is not a positive integer", f)
		}
		cfg.levels = append(cfg.levels, n)
	}

	ctx := context.Background()
	start := time.Now()
	if err := seed(ctx, cfg.dsn, cfg.accounts); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	rep := report{
		Accounts: cfg.accounts,
		SLOp95ms: ms(cfg.slo),
		StepSecs: cfg.duration.Seconds(),
		SeedSecs: time.Since(start).Seconds(),
	}
	fmt.Printf("seeded %d accounts in %.1fs\n", cfg.accounts, rep.SeedSecs)

	c := newClient(cfg)
	for _, sc := range []struct {
		name string
		vu   func(ctx context.Context, id int) (func(context.Context) error, error)
	}{
		{"sign-in", c.signInUser},
		{"session-check", c.sessionCheckUser},
		{"session-mix", c.sessionUser},
	} {
		res := scenarioResult{Name: sc.name}
		if cfg.pgstat {
			if err := resetStatements(ctx, cfg.dsn); err != nil {
				return err
			}
		}
		for _, n := range cfg.levels {
			var profile string
			if cfg.profileURL != "" && n == cfg.profileAt {
				profile = fmt.Sprintf("%s/cpu-%s.pprof", cfg.profileDir, sc.name)
			}
			st, err := runStep(ctx, cfg, n, sc.vu, profile)
			if err != nil {
				return fmt.Errorf("%s at %d: %w", sc.name, n, err)
			}
			res.Steps = append(res.Steps, st)
			fmt.Printf("%-13s c=%-4d rps=%8.1f p50=%7.1fms p95=%7.1fms p99=%7.1fms err=%5.2f%% %s\n",
				sc.name, n, st.RPS, st.P50ms, st.P95ms, st.P99ms, 100*st.ErrorRate, verdict(st.Pass))
			if st.FirstError != "" {
				fmt.Printf("              first error: %s\n", st.FirstError)
			}
			if !st.Pass {
				break
			}
			res.MaxConcurrency = n
		}
		if cfg.pgstat {
			stmts, err := topStatements(ctx, cfg.dsn)
			if err != nil {
				return err
			}
			res.Statements = stmts
		}
		rep.Scenarios = append(rep.Scenarios, res)
	}

	if cfg.out != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(cfg.out, b, 0o644); err != nil {
			return err
		}
	}
	if cfg.summary != "" {
		f, err := os.OpenFile(cfg.summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		writeSummary(f, rep)
	}
	return nil
}

func verdict(pass bool) string {
	if pass {
		return "pass"
	}
	return "FAIL"
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func email(i int) string { return fmt.Sprintf("perf-%d@load.test", i) }

// seed replaces the database's accounts with n confirmed email accounts,
// perf-0@load.test … perf-(n-1)@load.test, all with the same password.
func seed(ctx context.Context, dsn string, n int) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, q := range []string{
		`delete from auth.users where email like 'perf-%@load.test'`,
		`insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
			raw_app_meta_data, raw_user_meta_data, created_at, updated_at, is_sso_user, is_anonymous)
		 select '00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
			'perf-' || g || '@load.test', $2, now(),
			'{"provider":"email","providers":["email"]}', '{}', now(), now(), false, false
		 from generate_series(0, $1 - 1) g`,
		`insert into auth.identities (provider_id, user_id, identity_data, provider, created_at, updated_at)
		 select id::text, id, jsonb_build_object('sub', id::text, 'email', email, 'email_verified', true),
			'email', now(), now()
		 from auth.users where email like 'perf-%@load.test'`,
		`analyze auth.users`,
		`analyze auth.identities`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{n, string(hash)}
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return fmt.Errorf("%.40s…: %w", q, err)
		}
	}
	return tx.Commit(ctx)
}

// ---- HTTP ------------------------------------------------------------------

type client struct {
	cfg  config
	http *http.Client
}

func newClient(cfg config) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 2048
	tr.MaxIdleConnsPerHost = 2048
	tr.MaxConnsPerHost = 0
	return &client{cfg: cfg, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (c *client) do(ctx context.Context, method, path, bearer string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.url+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %.120s", method, path, resp.StatusCode, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (c *client) signIn(ctx context.Context, account int) (tokenResponse, error) {
	var tok tokenResponse
	err := c.do(ctx, http.MethodPost, "/auth/v1/token?grant_type=password", "",
		map[string]string{"email": email(account), "password": password}, &tok)
	return tok, err
}

// signInUser is a sign-in virtual user: every iteration signs a random
// account in.
func (c *client) signInUser(_ context.Context, _ int) (func(context.Context) error, error) {
	return func(ctx context.Context) error {
		_, err := c.signIn(ctx, rand.IntN(c.cfg.accounts))
		return err
	}, nil
}

// sessionCheckUser is a signed-in virtual user that only checks its session:
// it signs in once (not measured), then every iteration reads /user, which
// verifies the token and loads the user and the session it names.
func (c *client) sessionCheckUser(ctx context.Context, id int) (func(context.Context) error, error) {
	tok, err := c.signIn(ctx, id%c.cfg.accounts)
	if err != nil {
		return nil, fmt.Errorf("sign in virtual user %d: %w", id, err)
	}
	return func(ctx context.Context) error {
		return c.do(ctx, http.MethodGet, "/auth/v1/user", tok.AccessToken, nil, nil)
	}, nil
}

// sessionUser is a signed-in virtual user: it signs in once (not measured),
// then every iteration reads /user, refreshing its session every fifth time.
func (c *client) sessionUser(ctx context.Context, id int) (func(context.Context) error, error) {
	tok, err := c.signIn(ctx, id%c.cfg.accounts)
	if err != nil {
		return nil, fmt.Errorf("sign in virtual user %d: %w", id, err)
	}
	i := 0
	return func(ctx context.Context) error {
		i++
		if i%5 == 0 {
			var next tokenResponse
			if err := c.do(ctx, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", "",
				map[string]string{"refresh_token": tok.RefreshToken}, &next); err != nil {
				return err
			}
			tok = next
			return nil
		}
		return c.do(ctx, http.MethodGet, "/auth/v1/user", tok.AccessToken, nil, nil)
	}, nil
}

// ---- load ------------------------------------------------------------------

func runStep(ctx context.Context, cfg config, n int,
	newVU func(ctx context.Context, id int) (func(context.Context) error, error), profile string) (step, error) {

	vus := make([]func(context.Context) error, n)
	{
		// Virtual users are set up (signed in) concurrently, before the clock.
		var wg sync.WaitGroup
		var mu sync.Mutex
		var firstErr error
		sem := make(chan struct{}, 32)
		for i := range n {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				vu, err := newVU(ctx, i)
				mu.Lock()
				defer mu.Unlock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				vus[i] = vu
			}()
		}
		wg.Wait()
		if firstErr != nil {
			return step{}, firstErr
		}
	}

	type sample struct {
		lat []time.Duration
		err int
		msg string
	}
	samples := make([]sample, n)
	stepCtx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()
	began := time.Now()
	var wg sync.WaitGroup
	profiled := make(chan error, 1)
	if profile != "" {
		// The profile covers the step but its first and last second, while
		// every virtual user is busy.
		secs := max(1, int(cfg.duration.Seconds())-2)
		go func() {
			time.Sleep(time.Second)
			profiled <- fetchProfile(ctx, cfg.profileURL, secs, profile)
		}()
	} else {
		profiled <- nil
	}
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := &samples[i]
			for stepCtx.Err() == nil {
				t0 := time.Now()
				// The request itself is not cut off at the step's end: a slow
				// answer counts with its full latency.
				err := vus[i](ctx)
				lat := time.Since(t0)
				if err != nil {
					s.err++
					if s.msg == "" {
						s.msg = err.Error()
					}
					continue
				}
				s.lat = append(s.lat, lat)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(began)
	if err := <-profiled; err != nil {
		return step{}, fmt.Errorf("cpu profile: %w", err)
	}

	var lat []time.Duration
	st := step{Concurrency: n}
	for _, s := range samples {
		lat = append(lat, s.lat...)
		st.Errors += s.err
		if st.FirstError == "" {
			st.FirstError = s.msg
		}
	}
	st.Requests = len(lat) + st.Errors
	if st.Requests == 0 {
		return st, nil
	}
	slices.Sort(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return ms(lat[min(len(lat)-1, int(p*float64(len(lat))))])
	}
	st.ErrorRate = float64(st.Errors) / float64(st.Requests)
	st.RPS = float64(len(lat)) / elapsed.Seconds()
	st.P50ms, st.P95ms, st.P99ms = pct(0.50), pct(0.95), pct(0.99)
	if len(lat) > 0 {
		st.MaxMs = ms(lat[len(lat)-1])
	}
	st.Pass = len(lat) > 0 && st.P95ms <= ms(cfg.slo) && st.ErrorRate < 0.01
	return st, nil
}

// ---- report ----------------------------------------------------------------

func writeSummary(w io.Writer, rep report) {
	fmt.Fprintf(w, "### %d accounts\n\n", rep.Accounts)
	fmt.Fprintf(w, "Each step: %gs closed loop, no think time. Pass: p95 ≤ %gms and errors < 1%%. Seeded in %.1fs.\n\n",
		rep.StepSecs, rep.SLOp95ms, rep.SeedSecs)
	for _, sc := range rep.Scenarios {
		fmt.Fprintf(w, "**%s** — sustained concurrency: **%d**\n\n", sc.Name, sc.MaxConcurrency)
		fmt.Fprintln(w, "| concurrency | rps | p50 ms | p95 ms | p99 ms | max ms | errors | |")
		fmt.Fprintln(w, "|---:|---:|---:|---:|---:|---:|---:|---|")
		for _, s := range sc.Steps {
			mark := "✅"
			if !s.Pass {
				mark = "❌"
			}
			fmt.Fprintf(w, "| %d | %.1f | %.1f | %.1f | %.1f | %.1f | %.2f%% | %s |\n",
				s.Concurrency, s.RPS, s.P50ms, s.P95ms, s.P99ms, s.MaxMs, 100*s.ErrorRate, mark)
		}
		fmt.Fprintln(w)
		if len(sc.Statements) > 0 {
			fmt.Fprintf(w, "<details><summary>%s: heaviest SQL statements</summary>\n\n", sc.Name)
			fmt.Fprintln(w, "| calls | total ms | mean ms | statement |")
			fmt.Fprintln(w, "|---:|---:|---:|---|")
			for _, st := range sc.Statements {
				fmt.Fprintf(w, "| %d | %.0f | %.3f | `%s` |\n", st.Calls, st.TotalMs, st.MeanMs,
					strings.ReplaceAll(st.Query, "|", "\\|"))
			}
			fmt.Fprint(w, "\n</details>\n\n")
		}
	}
}

// combineReports writes one table comparing the reports of several runs (the
// account counts of the CI matrix): each scenario's sustained concurrency and
// the latency and throughput at that step.
func combineReports(paths []string, summary string) error {
	var reps []report
	for _, p := range paths {
		b, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			return err
		}
		var r report
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		reps = append(reps, r)
	}
	slices.SortFunc(reps, func(a, b report) int { return a.Accounts - b.Accounts })
	w := io.Writer(os.Stdout)
	if summary != "" {
		f, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintln(w, "## Performance by account count")
	fmt.Fprintln(w)
	if len(reps) > 0 {
		fmt.Fprintf(w, "Sustained concurrency is the largest step with p95 ≤ %gms and errors < 1%% "+
			"(closed loop, no think time, %gs per step); latency and throughput are at that step.\n\n",
			reps[0].SLOp95ms, reps[0].StepSecs)
	}
	fmt.Fprintln(w, "| accounts | scenario | sustained concurrency | rps | p50 ms | p95 ms | p99 ms | peak rps (any step) |")
	fmt.Fprintln(w, "|---:|---|---:|---:|---:|---:|---:|---:|")
	for _, r := range reps {
		for _, sc := range r.Scenarios {
			var at step
			peak := 0.0
			for _, s := range sc.Steps {
				if s.Concurrency == sc.MaxConcurrency {
					at = s
				}
				peak = max(peak, s.RPS)
			}
			fmt.Fprintf(w, "| %d | %s | %d | %.1f | %.1f | %.1f | %.1f | %.1f |\n",
				r.Accounts, sc.Name, sc.MaxConcurrency, at.RPS, at.P50ms, at.P95ms, at.P99ms, peak)
		}
	}
	fmt.Fprintln(w)
	return nil
}

// fetchProfile saves a CPU profile of secs seconds from the server's pprof.
func fetchProfile(ctx context.Context, base string, secs int, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", base, secs), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d", req.URL, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func resetStatements(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `create extension if not exists pg_stat_statements`); err != nil {
		return fmt.Errorf("pg_stat_statements: %w", err)
	}
	_, err = pool.Exec(ctx, `select pg_stat_statements_reset()`)
	return err
}

// topStatements reads the heaviest statements since the last reset.
func topStatements(ctx context.Context, dsn string) ([]statement, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `
		select regexp_replace(query, '\s+', ' ', 'g'), calls, total_exec_time, mean_exec_time
		from pg_stat_statements
		where dbid = (select oid from pg_database where datname = current_database())
		  and query not ilike '%pg_stat_statements%'
		order by total_exec_time desc limit 12`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []statement
	for rows.Next() {
		var st statement
		if err := rows.Scan(&st.Query, &st.Calls, &st.TotalMs, &st.MeanMs); err != nil {
			return nil, err
		}
		if len(st.Query) > 160 {
			st.Query = st.Query[:160] + "…"
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
