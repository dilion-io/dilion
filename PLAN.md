# Dilion 구현 계획 (Lead Architect)

기준 문서: [project.md](project.md). 이 문서는 구현 분할·계약·파일 소유권을 정의한다.

## 1. 기술 스택 / 리포 구조

- Go 1.26, go-chi v5, huma v2, pgx v5, Postgres 16 (로컬 dev DB: `dilion_dev`)
- 모듈: `github.com/dilion-project/dilion`
- **API 표면 2종:**
  - `/auth/v1/*` — Supabase Auth 호환. **huma를 쓰지 않고 chi에 직접 구현** (upstream JSON 계약을 바이트 수준으로 따라야 하므로). OpenAPI 계약은 upstream openapi.yaml.
  - `/privacy/v1/*`, `/iam/v1/*` — 자체 API. **huma v2로 구현** → huma가 OpenAPI 3.1 문서를 생성 (`cmd/openapi`가 `web/openapi.yaml`로 export, frontend codegen 입력). huma는 코드에서 스펙을 생성하므로 스펙-구현 불일치가 구조적으로 없음.

```
dilion.go            # NewServer + options (integration 시 최종 wiring)
ports/               # 공유 인터페이스 (계약 — 수정 금지)
httpapi/             # ID/pagination/error 컨벤션 헬퍼 (계약 — 수정 금지)
internal/privacy/service.go  # privacy Service 인터페이스 + DTO (계약 — 수정 금지)
internal/store/      # [A] pgx pool, migration runner
internal/auth/       # [B] Supabase Auth 호환 엔진
internal/privacy/    # [C] 컴플라이언스 엔진 (service.go 구현)
internal/iam/        # [D] RBAC + API key + 기본 Authorizer
internal/audit/      # [D] audit sink 기본 구현 + 이벤트 상수
internal/api/        # [D] huma 핸들러 (/privacy/v1, /iam/v1)
migrations/          # SQL (소유권별 번호 대역)
cmd/dilion/          # [A] 서버 바이너리
cmd/openapi/         # [D] openapi.yaml export
web/                 # [wave2] 샘플 프론트 (supabase-js + openapi codegen)
docs/api-conventions.md
```

## 2. 작업 분할 (Wave 1 — 병렬 4개, Opus)

| Agent | 범위 | 소유 파일 | migrations 대역 |
| --- | --- | --- | --- |
| A: core | store, migration runner, cmd/dilion, 기본 KMS(local AES-GCM)/mailer(dev logger), dilion.go 초안 | `internal/store/**`, `cmd/dilion/**`, `dilion.go`, `internal/kmslocal/**`, `internal/devmail/**` | `0001_core` (extensions, CREATE SCHEMA) |
| B: auth | Supabase Auth 호환: signup, token(password/refresh), user CRUD, logout, admin users, JWKS; 삭제 시 outbox insert | `internal/auth/**` | `01xx` (`auth.*`) |
| C: compliance | policy engine, consent ledger, requests/erasure pipeline, retention, legal hold, outbox dispatcher + webhook | `internal/privacy/**` (service.go 제외 신규 파일) | `02xx` (`dilion_privacy.*`, `dilion_pii.*`) |
| D: platform API | huma /privacy/v1 + /iam/v1, RBAC, audit, auth 미들웨어, cmd/openapi | `internal/api/**`, `internal/iam/**`, `internal/audit/**`, `cmd/openapi/**` | `03xx` (`dilion_authz.*`, `dilion_audit.*`) |

Wave 2 (wave 1 통합 후): 샘플 프론트(web/), 통합 테스트, 계약 검증.

**공통 규칙 (모든 agent):**
- `go.mod`/`go.sum` 수정 금지 (필요 의존성은 최종 보고에 기재). 이미 chi/huma/pgx/jwt/uuid/yaml/x-crypto 포함됨.
- `ports/`, `httpapi/`, `internal/privacy/service.go`, 타 agent 소유 파일 수정 금지. 문제 발견 시 보고만.
- 코드는 `go build ./...` 통과 필수 (단, 타 도메인 미완성으로 인한 dilion.go/cmd 빌드 실패는 A만 해당·허용). DB 불필요한 로직은 `_test.go` 유닛 테스트 작성. DB 필요한 테스트는 `DILION_TEST_DB` env가 있을 때만 실행.
- migration 파일명: `NNNN_name.sql` (up만, 단방향). 러너는 사전순 적용.

## 3. 교차 도메인 계약

### 3.1 Register 시그니처 (integration에서 dilion.go가 호출)

```go
// internal/auth
func Register(r chi.Router, d Deps)   // Deps: Pool *pgxpool.Pool, Signer ports.TokenSigner(자체 구현 노출),
                                      //       Mailer ports.Mailer, Hooks *hooks.Registry, JWTSecret []byte
// internal/api
func RegisterPrivacyAPI(api huma.API, svc privacy.Service, d Deps)
func RegisterIAMAPI(api huma.API, d Deps)   // Deps: Pool, Verifier ports.TokenVerifier, Authz ports.Authorizer, Audit ports.AuditSink
```

- B는 `ports.TokenSigner`/`ports.TokenVerifier` 구현을 `auth.NewTokenService(secret []byte) *TokenService`로 노출 (HS256, `sub`=user UUID, `role`=`authenticated|service_role`).
- D의 기본 Authorizer: `iam.NewAuthorizer(pool *pgxpool.Pool) ports.Authorizer`.
- D의 기본 AuditSink: `audit.NewSink(pool *pgxpool.Pool) ports.AuditSink`.

### 3.2 Outbox 이벤트 (B가 쓰고 C가 소비)

테이블 `dilion_privacy.outbox` (C의 migration이 생성):
`id uuid PK default gen_random_uuid(), event_type text, aggregate_id text, payload jsonb, created_at timestamptz default now(), published_at timestamptz`

B의 admin user delete는 **한 트랜잭션**에서: ①`auth.users` soft-delete(`deleted_at`) + 세션/refresh token 폐기 ② outbox insert:

```json
{ "event_type": "user.deleted", "aggregate_id": "<user uuid>",
  "payload": { "user_id": "<uuid>", "project_id": "default", "requested_by": "admin" } }
```

C의 dispatcher가 미발행 outbox를 폴링해 `personal_data_requests(type=DELETION)` 생성.

### 3.3 privacy.Service (C 구현, D 소비)

`internal/privacy/service.go`에 확정 (수정 금지). D는 이 인터페이스만 import.

### 3.4 Hook 레지스트리

`ports.HookPoint`/`HookFunc` 사용. 구현은 A가 `internal/hooks`(Registry: Register/Run — observe·mutate·reject)로 제공, B/C는 `*hooks.Registry`를 Deps로 받음.

### 3.5 프로젝트/테넌시

Wave 1은 단일 프로젝트 `"default"`로 고정 (`project_id text not null default 'default'` 컬럼은 스키마에 포함). 멀티테넌시 활성화는 이후 wave.

## 4. DB / 마이그레이션

- `0001_core.sql` (A): `create extension if not exists pgcrypto;` + `create schema if not exists auth, dilion_privacy, dilion_pii, dilion_authz, dilion_audit;`
- `auth.*` (B): Supabase Auth 호환 컬럼 구성. **반드시 upstream(supabase/auth master migrations)을 조회해 실제 컬럼명을 따를 것.** wave 1 범위: `users, identities, refresh_tokens, sessions` (+ 필요한 최소 컬럼, 나머지 컬럼도 가능한 한 포함).
- `dilion_*` 테이블 정의는 project.md §4를 따른다 (컬럼 추가는 자유, 명시된 컬럼·UNIQUE 제약은 준수).

## 5. Wave 1 기능 범위 (수직 슬라이스)

- Auth: email/password signup → JWT 발급(access+refresh) → GET/PUT user → logout; admin users list/get/create/delete(outbox 연동); JWKS(HS256이므로 빈 배열 대신 501 응답 + TODO 주석 가능, RS256는 이후 wave).
- Privacy: 정책 YAML 로드/검증/resolve/스냅샷 (kr/gdpr/hipaa 내장), DELETION 요청 생성(grace/즉시), erasure pipeline 실행(steps 100–1000, legal hold 게이트, destruction_logs dedup, 재실행 안전), consent append/조회 + required-keys 판정, reconfirm 스캐너(outbox 이벤트 발행), webhook 발송(HMAC-SHA256 `Dilion-Signature: t=<unix>,v1=<hex>`, 재시도 5회 지수 backoff, 실패 시 status=DEAD).
- IAM: 내장 permission/role seed, role 부여/회수(이력), scoped API key 발급(`dk_` + random, SHA-256 hash 저장), Authorizer(Can), 감사 이벤트 기록.
- API: /privacy/v1 requests(POST/GET/LIST/cancel), consents(GET/PUT), destinations(CRUD), holds(POST/DELETE/LIST); /iam/v1 roles/assignments/api-keys. Bearer 인증(관리 평면: `service_role` JWT 또는 API key), permission 검사, 감사 기록.

## 6. 미결/후속 (wave 2+)

전체 auth 표면(OAuth/MFA/SAML/passkey/OPAQUE), RS256+JWKS, export 파이프라인, retention 스캐너 배치화, immudb sink, 멀티테넌시, 관리 콘솔.
