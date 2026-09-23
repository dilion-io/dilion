# Dilion — Identity & Privacy Platform

> **한 문장 정의:** Supabase Auth API·DB와 완전 호환되는 자체 구현 인증 서버 위에, canonical `user_id`를 기반으로 **PII Vault + 권한 기반 마스킹 + 동의 원장(Consent Ledger) + 분산 삭제 오케스트레이션 + 불변 감사 로그**를 결합한, 임베더블·플러그인 가능한 Identity Lifecycle & Privacy Orchestration 플랫폼.

이 문서는 본 프로젝트의 제1문서(source of truth)입니다. 목적, 설계 원칙, 아키텍처, 데이터 모델, 기능 범위를 정의합니다.

---

## 1. 프로젝트 목적

사용자 계정 관리 + 인증 + 컴플라이언스 대응(데이터 삭제, 동의 관리 등)을 하나의 플랫폼으로 제공합니다.

단순한 "로그인 + 회원탈퇴 API" 제품은 Auth0, Clerk, Cognito와 경쟁하게 됩니다. 이 프로젝트는 제품의 중심을 **Identity Lifecycle + Privacy Orchestration**에 두어 차별화합니다:

- **인증(Auth):** Supabase Auth API 완전 호환(OAuth2/OIDC, Passkey 포함) — 기존 supabase-js/gotrue-js 클라이언트 코드가 그대로 동작. 여기에 OPAQUE(RFC 9807) 등 강화된 인증 수단 추가
- **개인정보 보호(Privacy):** PII를 Vault에서 관리하고, 권한에 따라 마스킹된 프로젝션 제공
- **동의(Consent):** append-only 동의 원장으로 "특정 시점에 이 사용자에게 마케팅 권한이 있었는가?"를 재구성 가능
- **삭제(Erasure):** 고객사의 외부 DB·SaaS까지 포함한 분산 삭제 워크플로우를 오케스트레이션
- **증빙(Evidence):** 모든 개인정보 접근·처리를 불변 감사 로그로 기록
- **임베더블:** 사용자는 `dilion.NewServer(...)`로 인스턴스를 생성하고, hook·KMS·저장소 등을 자유롭게 커스터마이징 가능

도입 조직 입장의 핵심 가치는 다음 두 가지 질문에 `user_id` 하나로 답할 수 있게 되는 것입니다:

1. "이 사용자의 데이터는 어디에 있고, 삭제 요청 시 전부 처리되었는가?" (증빙 포함)
2. "이 사용자의 개인정보를 누가, 언제, 어떤 권한으로 조회·수정·내보내기·삭제했는가?"

---

## 2. 핵심 설계 원칙

### 2.1 Canonical `user_id` 하나로 통일

이 플랫폼이 메인 스토리지이므로 별도의 Identity Graph는 두지 않습니다. `auth.users.id` (UUID)가 전체 플랫폼의 canonical 식별자입니다.

```
users.id = UUID (canonical)

auth session      ─┐
identity           │
consent            │
privacy request    ├── user_id = 같은 UUID
audit              │
webhook task       │
external deletion ─┘
```

JWT의 `sub` claim이 곧 `users.id`이며, 외부 시스템에도 SDK를 통해 같은 UUID를 사용하도록 권장합니다 (`customer.orders.user_id`, `customer.profiles.user_id`).

### 2.2 Supabase Auth 완전 호환 — API와 DB 모두

인증 서버는 **전체 기능을 직접 구현**하며, Supabase Auth와 두 층위에서 완전 호환을 확보합니다:

**API 호환:**
- [supabase/auth의 openapi.yaml](https://github.com/supabase/auth/blob/master/openapi.yaml)을 호환성 기준(contract)으로 삼습니다.
- URL만이 아니라 request/response JSON, HTTP status, error format, JWT claims, refresh-token semantics, OAuth callback semantics, pagination header까지 일치시킵니다.
- `/.well-known/jwks.json`, `/.well-known/openid-configuration` 등 OIDC discovery 포함.
- openapi.yaml 기반의 계약 테스트(contract test)를 CI에 상시 운영합니다.

**DB 호환:**
- `auth.*` schema(users, identities, sessions, refresh_tokens, mfa_factors 등)를 Supabase Auth와 동일한 구조로 유지합니다. 기존 Supabase 프로젝트의 데이터를 그대로 이관하거나, `auth.users`를 참조하는 기존 SQL/트리거/RLS 정책이 수정 없이 동작해야 합니다.

**네임스페이스 분리:**

```
/auth/v1/*        — Supabase Auth 호환 표면 (signup, token, user, logout, admin/users, ...)
/privacy/v1/*     — requests, consents, destinations, webhooks (자체 기능)
```

자체 기능은 호환 표면을 오염시키지 않도록 별도 네임스페이스와 `dilion_` prefix를 붙인 별도 schema(`dilion_privacy.*`, `dilion_pii.*` 등)에 둡니다. **모든 확장 객체(schema, 테이블, 설정 키 등)는 `dilion` prefix를 사용**하여 호환 대상과 명확히 구분합니다.

### 2.3 인증 기능

Supabase Auth가 제공하는 인증 표면을 모두 구현하고, 그 위에 강화된 인증 수단을 추가합니다.

**호환 표면 (Supabase Auth 동등):**
- 이메일/비밀번호, magic link, 전화(OTP)
- **OAuth2/OIDC 소셜 로그인** — provider 연동, authorization code + PKCE, callback semantics 호환
- **Passkey (WebAuthn)** — Supabase Auth의 passkey 등록·인증·관리·admin API 및 MFA WebAuthn factor와 호환. `auth.webauthn_credentials` / `auth.webauthn_challenges` 테이블을 그대로 사용. 구현은 go-webauthn(github.com/go-webauthn/webauthn) 사용.
- MFA (TOTP, WebAuthn factor), SAML SSO
- Anonymous sign-in, identity linking

**확장 인증 (자체 차별화):**
- **OPAQUE (RFC 9807)** — 비밀번호가 서버에 평문/해시 형태로도 전달되지 않는 aPAKE 기반 등록·로그인. 서버 침해 시에도 pre-computation attack에 저항. Supabase Auth에 대응물이 없으므로 확장 endpoint와 `dilion_auth` schema에 둡니다.

확장 인증은 별도 endpoint로 제공하되, 성공 시 발급되는 세션/토큰은 호환 표면과 동일한 semantics(JWT claims, refresh token)를 따릅니다. 즉 어떤 인증 수단으로 로그인하든 이후의 API 사용 경험은 동일합니다.

### 2.4 플러그인 가능한 임베더블 설계

Dilion은 완성형 서버 바이너리이면서 동시에 **라이브러리**입니다. 사용자는 자신의 애플리케이션에 임베드하여 커스터마이징할 수 있습니다:

```go
srv := dilion.NewServer(
    dilion.WithDatabase(pool),
    dilion.WithKMS(myKMS),                    // 사용자 지정 KMS
    dilion.WithMailer(myMailer),              // 이메일 발송 구현체 교체
    dilion.WithHook(dilion.BeforeSignup, fn), // 지점별 hook
    dilion.WithHook(dilion.AfterUserDelete, fn),
    dilion.WithConnector("my-crm", myConnector),
    dilion.WithAuthorizer(myAuthorizer),      // 권한 판정 교체 (§2.11)
)
```

**설계 요건:**

- **Hook 지점:** 인증·계정·프라이버시 수명주기의 주요 지점(signup 전/후, 토큰 발급 시 custom claims 주입, 사용자 삭제 전/후, 동의 변경, privacy task 실행 전/후, PII reveal 시 등)에 hook을 설치할 수 있어야 합니다. hook은 검증(reject 가능)·변형(mutate)·관찰(observe) 세 종류의 계약을 구분합니다.
- **사용자 지정 KMS:** PII 암호화 키, JWT signing key 등 키 관리는 인터페이스 뒤에 두고, AWS KMS/GCP KMS/Vault/HSM 등 사용자 구현체로 교체 가능해야 합니다.
- **교체 가능한 구성요소:** mailer, SMS sender, token signer, rate limiter, connector, audit sink, authorizer(§2.11) 등은 모두 인터페이스 기반으로 주입합니다.
- **기본값의 완결성:** 아무것도 주입하지 않아도 (`dilion.NewServer(dilion.WithDatabase(pool))`) 완전한 기능의 서버가 동작해야 합니다. 커스터마이징은 opt-in입니다.
- **멀티 DB 인스턴스 (커스터마이징 전용):** 하나의 서버가 완전히 격리된 여러 DB(인스턴스마다 자체 `auth.*`+`dilion_*`)를 서비스할 수 있습니다. `InstanceResolver` 인터페이스가 인스턴스별 리소스(DB pool, KMS, 컴플라이언스 정책, PII field 정의)를 **동적으로** 제공하며, 요청의 인스턴스 선택은 embedder가 context 주입으로 수행합니다. **내장 HTTP 라우팅은 제공하지 않습니다** — 요청이 어느 인스턴스인지 고르는 것은 embedder의 책임입니다. 반면 **토큰-인스턴스 결합은 Dilion이 키로 보장합니다**: `InstanceResolver.JWT`가 인스턴스마다 자체 JWT 키 자료(key set / secret / issuer)를 제공하고, 각 인스턴스는 자기 키로만 서명·검증하며 자기 JWKS만 발행합니다. 따라서 A 인스턴스의 토큰은 B의 `/auth/v1/*`뿐 아니라 B의 JWKS/secret을 신뢰하는 PostgREST 등 외부 검증자에서도 거부됩니다(클레임 검사는 외부 검증자를 막지 못하므로 키 분리가 유일한 결합 수단입니다). 기본 데몬과 예제는 단일 인스턴스만 사용합니다. 인스턴스별 기본 KMS가 필요한 embedder는 `dilion.NewLocalKMS(pool, kek)`로 내장 로컬 KMS를 직접 만들 수 있습니다.
- **코드로 정의하는 ID 연동 (커스터마이징 전용):** 테넌트별 IdP 등록을 이미 자기 데이터로 알고 있는 플랫폼이 이를 인스턴스 DB마다 복제하지 않도록, 코드 소스를 **DB보다 먼저** 조회합니다. 소스가 `(nil, nil)`을 돌려주면 기존 경로로 넘어가고, 오류는 요청을 실패시킵니다(넘어가지 않음).
  - **RP 쪽 — `WithProviderSource`:** 인스턴스별 OIDC provider(issuer, client_id/secret, redirect_uri, scopes)를 돌려줍니다. 내장 provider와 `auth.custom_oauth_providers`보다 먼저 봅니다. redirect_uri가 비어 있으면 요청이 들어온 호스트의 `/callback`으로 유도하므로 정의 하나로 모든 테넌트 호스트를 처리합니다. `LinkBySubject`를 켜면 IdP의 `sub`가 곧 로컬 user id가 되어 email이 아닌 id로 사용자를 찾거나 그 id로 생성합니다. 이는 provider에게 인스턴스의 모든 계정에 대한 권한을 주는 것이므로 **코드로 정의한 provider에서만** 허용하고, 관리 API로 등록하는 provider에는 두지 않습니다.
- hook에서의 실패가 호환 표면의 semantics를 깨지 않도록, hook 오류 처리 정책(fail-open/fail-closed)을 지점별로 명시합니다.

### 2.5 계정 삭제와 컴플라이언스 삭제의 분리 (Transactional Outbox)

`DELETE /auth/v1/admin/users/{id}` 는 "인증 계정 삭제"와 "컴플라이언스 삭제 요청 생성"을 **하나의 DB 트랜잭션**으로 atomic하게 연결하되, 외부 시스템 삭제는 비동기로 처리합니다:

```
DELETE /auth/v1/admin/users/abc
          │
     DB Transaction
      ┌──────┴───────┐
      ▼              ▼
 auth 계정        outbox insert
 disable/delete   (user.deleted)
      └──────┬───────┘
             │ commit → 호환 응답 즉시 반환 (SDK 입장에서는 완료)
             │
             ▼ 비동기
     Privacy Orchestrator
      ┌──────┼────────┐
      ▼      ▼        ▼
    CRM   App DB   Analytics
```

**외부 삭제가 끝날 때까지 HTTP 요청을 붙잡으면 안 됩니다.** 외부 시스템 하나의 장애가 Auth API 안정성을 해치기 때문입니다.

outbox의 `user.deleted` 이벤트는 `personal_data_requests(type=DELETION)`를 생성하며, 이후의 실제 파기는 §2.9의 파기 파이프라인이 수행합니다 (self-service 탈퇴는 정책의 grace period 적용, admin 삭제는 즉시 실행 여부를 옵션으로 선택).

### 2.6 마스킹 ≠ 삭제 — 상태를 명확히 구분

`홍**`, `j**@domain.com` 같은 응답 마스킹만으로는 컴플라이언스(파기 의무)를 만족하지 못합니다. canonical `user_id`로 orders/payments/logs와 연결 가능한 한 여전히 개인정보입니다(한국 개인정보보호법의 결합 용이성 기준, GDPR의 pseudonymised data 기준).[^gdpr-rec26][^edpb-pseudo][^pipa-28-2]

| 상태 | DB 원본 | API 응답 | 의미 |
| --- | --- | --- | --- |
| Normal | 원본 존재 | 원본 | 일반 처리 |
| Masked | 원본 존재 | `홍**` | 노출 최소화 (접근통제) |
| Pseudonymized | 별도 연결정보 존재 | 가명 ID | 보호 강화 |
| Erased | 원본 제거 | 없음 | 파기 처리 |
| Anonymized | 재식별 불가 | 익명 데이터 | 개인정보 범위 이탈 가능 |

- **마스킹의 용도는 data minimization / least privilege**입니다. `support.read` 권한은 masked 응답, `pii.read` 권한만 원본 응답을 받습니다.
- 단, `/auth/v1/user`(본인 조회) 등 호환 표면은 마스킹하지 않습니다. 마스킹은 admin API / 별도 scope에서 적용합니다.
- 완전 삭제 사용자의 잔존 데이터(anonymize 대상)는 식별 필드 제거 + `user_id` 절단(NULL)으로 처리합니다. 연결 가능한 매핑을 보유하면 가명처리이고, 매핑까지 파기해야 익명화에 가까워집니다.

### 2.7 PII Vault

`auth.*` schema는 DB 호환성을 위해 그대로 유지하되, 확장 개인정보는 별도 Vault로 분리합니다:

```
auth.users (호환 유지)         dilion_pii.user_profiles (Vault)
──────────────────────         ────────────────────────────────
id, email, phone, ...    ──▶   user_id, name, address,
                        1:1    확장 프로필, 민감정보 ...  (암호화 저장)
```

- 일반 서비스는 `user_id`만 사용. PII가 필요한 서비스만 PII Service를 거쳐 permission check → decrypt → raw/masked projection.
- row DELETE는 스토리지 특성(MVCC, WAL, 페이지·백업 잔존)상 물리적 삭제를 보장하지 않습니다. 따라서 Vault의 PII는 암호화 저장을 전제로 하고, 파기 시 row 삭제와 키 폐기를 병행합니다.
- Vault의 암호화 키는 KMS 인터페이스(§2.4)를 통해 관리합니다. 사용자 단위 DEK(subject key)는 **스코프 단위**로 분리합니다: `DEFAULT` 스코프(일반 PII — 파기 시 즉시 shred)와 `CONSENT` 스코프(동의 증적 — 파기 후에도 정책의 보존기간 동안 유지, `shred_after` 도래 시 shred). 키 폐기(**crypto-shredding**)는 보조 전략이며, 이것만으로 법적 파기 요건이 자동 충족된다고 보장하면 안 됩니다 (백업·복제 구조와 적용 법률에 따라 검토 필요).[^datatilsynet][^kr-easylaw]
- 삭제 시에는 Vault의 crypto-erase와 함께 `auth.users`의 PII 필드(email, phone 등)도 파기합니다 (§2.9 파이프라인).
- **PII field 정의는 인스턴스 단위로 고정**할 수 있습니다: 인스턴스별 선언(`pii-fields: {<key>: {hint: ...}}`)이 있으면 정의되지 않은 key의 쓰기는 거부되고, 마스킹 hint는 쓰기 요청이 아니라 정의에서 가져옵니다(같은 key가 다른 hint로 저장되는 것을 차단). 정의가 없으면 자유 형식(free-form) custom field로 동작합니다.

### 2.8 정책 주도 컴플라이언스 (Policy-as-Data)

**법률별 하드코딩 금지.** 코드는 정책의 실행 엔진이고, 법률 지식(유예기간, 보존기간·근거, 도메인별 파기 액션, 필수 동의 키, 재동의 주기)은 전부 YAML 정책 데이터로 외부화합니다.

**컴플라이언스 코드 분기:** 적용 정책은 **계정별로 기록되는 컴플라이언스 코드(policy id)** 로 결정합니다. GDPR 적용 여부는 사용자의 위치가 아니라 컨트롤러의 establishment/targeting(Art. 3)으로,[^edpb-territorial] HIPAA는 위치와 무관하게 BA 계약 관계로 결정되므로, 위치 기반 자동 판정은 하지 않습니다.

- 계정 생성 시 `dilion_privacy.subject_policies`에 컴플라이언스 코드가 **명시적으로 할당**됩니다(배포자의 명시 지정, 없으면 `default-policy`). 할당 근거(`source`)를 함께 기록합니다.
- 컴플라이언스 코드 변경은 "매우 민감" 등급 감사 이벤트이며, 진행 중인 요청에는 스냅샷된 정책이 유지됩니다.
- 복수 프레임워크가 동시에 적용되는 경우(예: HIPAA+GDPR)를 위한 자동 병합 규칙은 두지 않습니다. 해당 조합은 배포자가 전체 내용을 명시적으로 작성한 사용자 정의 정책으로 다룹니다.
- 내장 정책(`kr`, `gdpr`, `hipaa` 등)을 제공하고, 사용자 정의 설정은 내장값과 병합합니다(정책의 한 섹션을 제공하면 해당 섹션은 통째로 대체).

```yaml
compliance:
  default-policy: gdpr       # 명시 할당이 없을 때 적용되는 기본 컴플라이언스 코드
  retention-batch-size: 1000
  policies:
    kr:                      # 내장 kr 정책의 섹션 오버라이드
      erasure:
        grace-period-days: 30          # 탈퇴 요청 → 파기 실행 유예. 처리방침에 보유기간으로 고지할 것
        domains:                       # ErasureStep defaultAction 오버라이드 (KEEP이면 스킵)
          audit-log: KEEP              # 접속기록은 안전성 확보조치 기준 §8의 보존 의무(1~2년) 대상 —
                                       # 탈퇴 시 절단 금지, retention(P3Y) 경과 후 DELETE[^kr-safety]
      retention:
        - domain: consent-evidence     # row 삭제가 아니라 CONSENT 스코프 DEK shred
          period: P3Y
          from: erasure                # 파기 완료 시각 기준 (shred_after 스냅샷)
          action: CRYPTO_SHRED
          basis: "신용정보법 §20②"      # 증적 문자열 — 로직에 미사용, destruction_logs로 복사
        - domain: audit-log
          period: P3Y
          from: created
          action: DELETE
      consent:
        required-keys: [terms, privacy]
        reconfirm:
          "marketing.*": P2Y           # 주기 도래 시 확인 고지 이벤트(webhook/hook) 발송 + 발송 증적 기록
```

**설계 요건:**

- **정책 스냅샷:** 요청 생성 시점에 계정의 컴플라이언스 코드와 해석 결과(정책 id, grace deadline, retention 기간)를 요청 row에 스냅샷합니다. 이후 정책 파일이 바뀌거나 계정의 코드가 변경·파기되어도 진행 중인 파이프라인에 영향이 없습니다.
- **`basis`는 증적:** 로직에 사용하지 않고 `destruction_logs`에 복사되어 "무슨 근거로 보존/파기했는가"의 감사 답변이 됩니다.
- **Retention 스캐너:** `period` + `from`(created | erasure) 기준으로 만료분을 `retention-batch-size` 단위 배치로 처리합니다. action은 `DELETE`(row 삭제) 또는 `CRYPTO_SHRED`(스코프 DEK 폐기). legal hold(§2.9) 대상은 만료되어도 건너뜁니다.
- **정책 검증:** 정책 YAML은 로드 시 schema validation을 거치며, 알 수 없는 domain/action은 기동 실패로 처리합니다(런타임에 조용히 무시 금지).

### 2.9 파기 파이프라인 (Erasure Pipeline)

탈퇴 요청은 즉시 파기가 아니라 정책의 `grace-period-days` 유예를 거칩니다. 유예 중에는 계정 비활성화 + 세션/토큰 즉시 폐기 상태이며 요청 철회가 가능합니다.[^gdpr-art12][^gdpr-art17][^pipa-21][^kr-std-guideline] 단, **정보주체가 즉시 파기를 요청하면 유예를 생략**할 수 있어야 하고(`scheduled_at = now`), 유예 만료 후에는 지체 없이(한국 정책 기준 5일 이내) 파기가 실행되도록 스케줄러 SLA를 보장합니다. 유예기간은 "철회 가능 기간"이라는 별도 보유 목적·기간으로 처리방침에 고지합니다.

```
personal_data_requests(type=DELETION, status∈{REQUESTED,PROCESSING},
                       scheduled_at ≤ now) 조회 (DONE이면 no-op)
  → 스냅샷된 정책 로드
  → Legal hold 게이트 (hold가 걸린 subject는 실행 보류 → MANUAL_REVIEW)
  → Before hooks → status=PROCESSING
  → ErasureStep 순서 실행 (정책 domains로 defaultAction 오버라이드, KEEP은 스킵)
      100 credential          DELETE       (password, OPAQUE record)
      200 refresh-token       DELETE
      300 session             DELETE
      400 mfa-factor          DELETE       (TOTP, WebAuthn factor)
      500 passkey             DELETE       (auth.webauthn_credentials)
      600 oauth-identity      ANONYMIZE    (auth.identities — provider email/profile 제거 + subject 가명화)
      700 external-system     EXECUTE      (connector fan-out: webhook/SaaS API, §3.1 — receipt 수집)
      800 audit-log           ANONYMIZE    (subject 절단, row 보존 — 접속기록 보존 의무가 있는
                                            정책(kr 등)은 KEEP 오버라이드, retention 경과 후 처리)
      900 subject-key         CRYPTO_SHRED (DEFAULT 스코프 즉시 shred +
                                            CONSENT 스코프에 shred_after = now + 정책 기간 스냅샷)
     1000 account             ANONYMIZE    (auth.users email/phone/metadata + PII Vault 절단,
                                            erasure registry 기록, DELETED 마킹)
      —   consent             (step 자체가 없음 — 원장은 KEEP,
                               retention의 consent-evidence 항목이 수명 관리)
  → step별 destruction_logs 기록 ((request_id, domain) UNIQUE로 재실행 dedup)
  → status=DONE → After hooks
```

**재실행 안전성 (크래시/재부팅):**

- 모든 step은 idempotent합니다. 파이프라인 러너는 재기동 시 `REQUESTED`/`PROCESSING` 요청을 재조회하여 이어서 실행하고, `destruction_logs`의 `(request_id, domain)` UNIQUE로 이미 완료된 step은 건너뜁니다.
- `external-system` step은 §2.5의 outbox와 connector task 단위 재시도로 부분 실패를 다룹니다: at-least-once delivery + idempotent consumer (`execute(task_id)`, `task_id UNIQUE`), retry + exponential backoff, dead-letter queue, manual retry.
- 사용자 정의 ErasureStep을 hook/plugin(§2.4)으로 파이프라인 순서에 삽입할 수 있습니다.

**Legal hold — 일급 엔터티:**

법적 분쟁·수사 협조·규제 보존 명령 등으로 파기를 중단해야 하는 경우를 runbook 언급이 아니라 데이터 모델의 일급 엔터티(`dilion_privacy.legal_holds`)로 다룹니다.[^cfr-164-308][^hhs-faq580]

- hold는 subject 단위 또는 (subject, domain) 단위로 설정하며 `reason`/`basis` 증적을 남깁니다.
- **3중 게이트:** ① 파기 파이프라인은 실행 전 hold를 조회해 대상 요청을 MANUAL_REVIEW로 보류, ② retention 스캐너는 hold 대상 row/키를 건너뜀, ③ 백업 복원 시 erasure registry replay도 hold 대상을 skip(§2.10). 세 경로 모두 같은 테이블을 참조해야 우회가 생기지 않습니다.
- hold 설정·해제는 "매우 민감" 등급 감사 이벤트로 기록하고, 해제 시 보류된 요청이 자동으로 재개됩니다.

### 2.10 Backup — Beyond Use와 Restore-time Replay

오프라인 백업에서 특정 사용자 row만 즉시 지우기 어렵다는 사실 자체가 곧 위반은 아닙니다(ICO 가이드도 established schedule에 따른 소멸을 인정).[^ico-erasure][^gdpr-art5] 핵심은 백업 파일을 수정하려 하지 않고, **백업을 "beyond use" 상태로 유지하며 restore 과정을 erasure-aware하게 만드는 것**입니다:

- **Beyond use:** 백업은 immutable + DR(재해복구) 전용. 백업을 mount해서 일상 업무·분석용으로 조회하는 것을 금지합니다 ("탈퇴했는데 옛 데이터 좀 확인" → 금지).
- **유한 retention + 목적 문서화:** "오프라인이니까 영구보관"은 불가. 예: hourly snapshot 48h / daily 30d / weekly offline 12w처럼 계층별 기간을 정하고, "랜섬웨어/DR 대응을 위해 최대 N일 필요"처럼 목적과 기간을 문서화합니다(storage limitation + accountability).
- **Restore-time erasure replay:** live DB에서는 즉시 삭제하고, 복원 시에는 백업 시점 이후의 삭제를 재적용합니다.

**Erasure Registry (Deletion Tombstone):**

```
Production DB ──backup──▶ Immutable Backup (유한 retention, beyond use)
                                │ disaster
                                ▼
                          Restore staging
                                │
                    Erasure Registry replay      ◀── 복원 대상 백업보다 최신인
                    (erased_at > backup_created_at)   registry 사본 기준
                                │
                          Validation → Production
```

- **Registry rollback 주의:** registry는 기본적으로 main DB(`dilion_privacy.erasure_registry`)에 저장되므로, 오래된 백업을 그대로 복원하면 그 시점 이후의 삭제 이력이 함께 사라집니다. 따라서 restore runbook은 replay 전에 **복원 대상 백업보다 최신인 registry 사본**(장애 직전 DB에서 export, 또는 가장 최근 백업)을 확보해 그것을 기준으로 replay합니다.
- **선택 옵션 — immudb 백엔드:** erasure registry를 immudb에 기록하도록 구성하면 애플리케이션 DB 백업 lifecycle과 자연히 분리되어 rollback 문제가 원천 차단됩니다. immudb를 사용하는 경우 감사 로그(audit sink)도 DB 대신 immudb에 기록하며(§5.4), immudb는 레코드 삭제가 불가능하므로 subject 연관 레코드는 **암호화 저장**하여 파기 요청 시 키 폐기(crypto-erase)로 삭제 의무에 대응합니다.
- **Tombstone 식별자 역설:** registry에 email/원본 ID를 영구 보관하면 "삭제를 위해 개인정보를 영구 보관"하는 문제가 생깁니다. 별도의 tombstone identifier(keyed hash/HMAC 기반 lookup)로 기록합니다.
- **Restore runbook을 정식 절차 + 감사 대상으로:** isolated staging 복원 → backup timestamp 확인 → **legal hold·법정 보존 판정 조회(§2.9)** → 이후 erasure registry 조회·replay(**hold·보존 대상은 skip**) → 만료 키 검증 → reconciliation 검사 → 승인(validation) → production open. hold 확인이 replay보다 **앞**에 와야 보존 의무 기록("retrievable exact copies")을 replay가 파괴하는 사고를 막을 수 있습니다.[^cfr-164-308] 복원 행위 자체를 audit event로 남깁니다. 복원 사고로 삭제된 개인정보가 되살아나는 것이 백업 자체보다 현실적인 위험입니다.

**두 종류의 키 파기를 분리 (crypto-shredding과의 결합):**

```
시간 retention 만료  → period/day data key destroy   (백업 속 ciphertext도 복호화 불가)
특정 사용자 erasure  → subject key destroy            (identity/correlation 절단)
```

- period key 하나에 여러 사용자의 데이터가 묶이므로, 개인 탈퇴를 period key 파기로 처리할 수 없습니다(§2.7의 subject key가 담당). 반대로 대규모 로그의 시간 기반 retention에는 period key shred가 효율적입니다.
- **envelope encryption 함정:** wrapped DEK가 DB 백업 안에 있고 master KEK가 살아 있으면 옛 백업은 여전히 복호화 가능합니다. 따라서 개인별 삭제의 기본 보장은 restore-time replay이고, crypto-shredding은 wrapping hierarchy가 삭제 상태를 보존하는 범위에서 보조 전략으로 사용합니다.

### 2.11 권한 모델 (Authorization)

**두 평면 분리 — 호환 평면에는 권한 모델을 얹지 않습니다:**

- **호환 평면 (end-user):** Supabase Auth의 JWT 모델(`role: anon | authenticated | service_role`, `sub`)을 그대로 유지합니다. 최종 사용자의 권한은 본인 리소스 소유권(`sub == user_id`) 검사가 전부이며(`/auth/v1/user`, 본인 동의, 본인 privacy request), 고객 앱의 데이터 접근 통제는 기존 방식(RLS + JWT claims)이 그대로 동작합니다. 고객 앱 자체의 권한은 custom claims/app_metadata로 JWT에 실어 RLS에서 소비합니다.
- **관리 평면 (operator/admin + machine key):** Dilion의 admin/privacy API에 적용되는 내장 RBAC. 아래 내용은 전부 이 평면에 해당합니다. 인증 수단은 `service_role` JWT, scoped API key, 그리고 **RBAC role이 부여된 일반 사용자 access token** — 사용자 토큰은 deny-by-default로 `role_assignments`에 할당된 권한만 갖습니다. Supabase 호환 admin 표면(`/auth/v1/admin/*`)도 동일하게 사용자 토큰 + `users.admin` permission을 허용합니다.

**내장 RBAC:**

- 플랫 permission 문자열 + role 번들 구조의 정적 RBAC입니다. ABAC/ReBAC은 사용하지 않습니다 — 규제 감사(CC6.3 recertification, 안전성 확보조치 기준 제5조)는 "누가 무엇을 할 수 있는지 열거 가능"할 것을 요구하며, 조건식 권한은 열거 가능성을 해칩니다.
- 권한은 **permission 이름**으로 식별되며 배포 단위 전체에 적용됩니다. **deny-by-default** — `pii.read` 없는 모든 조회는 masked 프로젝션(§2.6)입니다.
- 내장 permission:

```
users.read                  # 마스킹된 사용자 조회/검색
pii.read                    # 마스킹 해제된 프로젝션
pii.reveal                  # 원본 열람 (사유 입력 — hipaa 프로파일에서는 필수)
pii.export                  # export 실행
privacy.requests.manage     # DSR 생성/승인/MANUAL_REVIEW 처리
holds.manage                # legal hold 설정/해제
policies.manage             # 컴플라이언스 정책 변경
destinations.manage         # webhook/connector 설정
keys.manage                 # API key 발급/회수
audit.read                  # 감사 로그 열람 (쓰기 permission은 존재하지 않음)
```

- 내장 role 번들: `viewer`(users.read) / `support`(+ pii.read) / `privacy-officer`(+ requests·holds·export) / `security-admin`(+ audit.read, keys) / `owner`(전부).
- **사용자 정의 permission·role:** 채택자는 자기 서비스용 permission과 role을 등록할 수 있습니다. 사용자 정의 permission은 네임스페이스가 필수(예: `myapp.orders.refund`)이며, 무접두 내장 permission과 충돌하지 않습니다. 등록된 permission은 hook·Authorizer·채택자 자체 API의 판정에 사용됩니다.

**권한 이력 = 컴플라이언스 데이터:** 안전성 확보조치 기준 제5조(접근권한 부여·변경·말소 내역의 기록·보관, 인사이동 시 지체 없는 변경)에 따라 role 할당은 현재 상태가 아니라 **이력 보존형**(`role_assignments` — granted/revoked)으로 기록합니다.[^kr-safety] 권한 부여·회수는 "매우 민감" 등급 감사 이벤트(§5.2)이며, 이 이력으로 CC6.3 recertification 리포트("현재 `pii.reveal` 보유자 + 부여 근거")를 생성합니다.

**Machine key:** `service_role`은 호환을 위해 인정하되, 전권 키이므로 사용 자체를 "매우 민감" 감사 이벤트로 기록합니다. 권장 경로는 **scoped API key**(최소 스코프, 만료·회수 가능, hash 저장)입니다.

**Authorizer 인터페이스:** 권한 판정은 `Authorizer` 인터페이스 뒤에 있으며 `dilion.WithAuthorizer(...)`로 교체할 수 있습니다(§2.4). 기본 구현은 내장 RBAC 테이블이고, 외부 IdP·정책 엔진(OPA 등) 연동은 이 인터페이스로 구현합니다. Authorizer는 판정만 담당하므로, 교체하더라도 감사 이벤트 기록과 masked-by-default 동작은 유지됩니다.

**운영 안전장치:**

- **직무 분리(SoD):** `holds.manage`와 파기 실행 권한 분리, `policies.manage`는 변경-승인 분리(CC8.1)와 연결. 감사 로그는 어떤 권한으로도 수정 불가(§5.4).
- **관리 평면 MFA는 정책 데이터가 아니라 제품 기본값입니다.** 관할별로 방향이 갈리는 법률 지식이 아니므로(한국 고시 제6조는 외부 접속 시 안전한 인증수단을 사실상 요구,[^kr-safety] SOC 2 CC6.1 감사인 기대, HIPAA도 강화 추세, 금지하는 관할 없음) compliance YAML의 항목으로 두지 않고 관리 평면에서 상시 요구합니다. 개발 환경용 해제는 `NewServer` 옵션으로만 가능하며, 해제 상태는 기동 시 경고 + 감사 이벤트로 기록됩니다.
- admin 세션 비활성 타임아웃(§8.12).

---

## 3. 전체 아키텍처

```
                         ┌─────────────────────┐
supabase-js / gotrue-js ─▶  API Gateway        │
                         └──────────┬──────────┘
                                    │
               ┌────────────────────┼────────────────────┐
               │                    │                    │
         /auth/v1/*           account lifecycle    /privacy/v1/*
               ▼                    ▼                    ▼
         Auth Engine         Account Service       Privacy Service
     (Supabase Auth 호환      canonical user        consent / DSR
      + OPAQUE 확장)               │                     │
               │                    │                    │
               └────────────┬───────┘                    │
                            ▼                            ▼
                     Main PostgreSQL          ┌─────────────────────┐
                     auth.* (호환)            │ Privacy Orchestrator │
                     dilion_* (확장)          │ (workflow + policy)  │
                                              └──────────┬──────────┘
                                                         │
                                    ┌────────────────────┴───────────────┐
                                    ▼                                    ▼
                                 Webhook                           SaaS Connector
                                    │                                    │
                                    ▼                                    ▼
                               Customer API                       Salesforce/S3/
                                                                  Analytics 등
                                                         │
                                                         ▼
                                              Audit / Evidence Store
```

Auth Engine, Account Service, Privacy Service, Orchestrator는 모두 `dilion.NewServer(...)`가 구성하는 하나의 임베더블 서버 안의 모듈이며, hook·KMS·connector 주입 지점(§2.4)이 각 모듈 경계에 위치합니다.

### 3.1 Connector 계층 — 외부 데이터 삭제 실행 방식

| 방식 | 용도 | 비고 |
| --- | --- | --- |
| **Webhook** | 대상 서비스가 자체 삭제 API 보유 (자체 DB 삭제 포함) | |
| **SaaS Connector** | Salesforce, HubSpot, S3 등 API 보유 시스템 | 인터페이스 기반, 사용자 정의 connector 주입 가능 |

**핵심 기술 결정: 대상 시스템의 DB credential을 받지 않습니다.** 외부 DB에 대한 직접 접근 방식은 제공하지 않으며, 모든 외부 삭제는 대상 시스템이 노출한 webhook/API를 통해 대상 시스템 스스로 실행합니다. Dilion에는 작업 명령과 결과/evidence(execution receipt)만 남습니다. 보안 심사와 엔터프라이즈 도입에서 결정적으로 유리합니다.[^vanta-cc92][^cfr-164-314]

### 3.2 Webhook 프로토콜

전달:

```json
{
  "event": "privacy.delete",
  "id": "evt_...",
  "request_id": "pr_123",
  "user_id": "2d5f7f...",
  "requested_at": "..."
}
```

수신측 응답은 `{ "request_id": "pr_123", "status": "completed" }` 형태이되, **HTTP 200을 삭제 증빙으로 간주하지 않습니다.** 별도의 execution receipt(PrivacyTask 기록)를 증빙으로 남깁니다.

Webhook 필수 요건: HMAC 또는 asymmetric signature, timestamp, replay protection, idempotency key, retry + exponential backoff, dead-letter queue.

수신측 처리 예시 (삭제 + 익명화 혼합):

```sql
DELETE FROM profiles WHERE user_id = $1;
UPDATE orders SET customer_name = NULL, customer_email = NULL, user_id = NULL
WHERE user_id = $1;
```

### 3.3 대상 시스템 설정 모델 (선언적)

```yaml
systems:
  - name: primary-app
    connector: webhook
    identity:
      field: user_id
  - name: crm
    connector: webhook
    identity:
      field: email
  - name: analytics
    connector: amplitude
    identity:
      field: user_id
```

호출은 API 하나:

```
POST /privacy/v1/requests
{ "user_id": "...", "type": "delete" }
```

---

## 4. 데이터 모델

```sql
-- auth schema — Supabase Auth와 완전 동일 구조 (DB 호환성 계약)
auth.users / auth.identities / auth.sessions / auth.refresh_tokens
auth.mfa_factors / auth.mfa_challenges          -- WebAuthn MFA factor 컬럼 포함
auth.webauthn_credentials / auth.webauthn_challenges   -- Passkey (upstream 스키마 그대로)
...

-- 확장 인증 (dilion prefix)
dilion_auth.opaque_records (user_id, registration_record, ...)   -- OPAQUE (RFC 9807)

-- PII Vault
dilion_pii.user_profiles (user_id, name, address, ...)   -- KMS 관리 키로 암호화 저장
dilion_pii.subject_keys  (user_id, scope,          -- DEFAULT | CONSENT
                          key_ref, shred_after, shredded_at)

-- Privacy
dilion_privacy.subject_policies (user_id, policy_id,  -- 계정별 컴플라이언스 코드
                                 source,              -- explicit | default
                                 assigned_at)         -- 변경은 "매우 민감" 감사 이벤트 (§2.8)
dilion_privacy.consent_events (id, user_id, purpose, action, policy_version,
                               created_at, source, region, evidence)  -- append-only
dilion_privacy.personal_data_requests
                  (id, user_id, type,              -- DELETION | EXPORT | CONSENT_WITHDRAWAL
                   status,                         -- REQUESTED | PROCESSING | DONE | MANUAL_REVIEW
                   policy_id, scheduled_at,        -- 정책 스냅샷 + grace deadline
                   requested_at, completed_at)
dilion_privacy.destruction_logs
                  (id, request_id, domain, action, basis, executed_at,
                   UNIQUE(request_id, domain))     -- 재실행 dedup + 파기 증적
dilion_privacy.tasks     (id, request_id, user_id, destination_id, action, status,
                          attempt_count, created_at, started_at, completed_at,
                          error_code, evidence)    -- external-system step의 connector 실행 단위
dilion_privacy.destinations (id, type,                -- webhook | connector
                             config, secret_ref, enabled)
dilion_privacy.legal_holds (id, user_id, domain,      -- domain NULL = subject 전체
                            reason, basis,
                            created_at, released_at)  -- 파기 파이프라인·retention 스캐너·
                                                      -- restore replay 3중 게이트 (§2.9)
dilion_privacy.erasure_registry
                  (tombstone_id,                   -- keyed hash/HMAC 식별자 (원본 ID 미보관)
                   erased_at, request_id, reason)  -- 복원 시 replay 기준, 선택적 immudb 백엔드 (§2.10)

-- 이벤트 연동
dilion_privacy.outbox (id, event_type, aggregate_id, payload,
                       created_at, published_at)

-- 권한 (관리 평면 RBAC — §2.11)
dilion_authz.permissions      (name)                  -- 사용자 정의 permission 등록 (네임스페이스 필수)
dilion_authz.roles            (id, name, permissions[])   -- 내장 + 사용자 정의
dilion_authz.role_assignments (actor_id, role_id,
                               granted_by, granted_at,
                               revoked_by, revoked_at)  -- 이력 보존 (고시 §5 기록 의무, CC6.3 리포트)
dilion_authz.api_keys         (id, key_hash, scopes[],
                               expires_at, last_used_at)

-- 감사
dilion_audit.events   (event_id, actor_id, actor_type, action, resource,
                       access_level, request_id, result_count, ip, user_agent, created_at)
dilion_audit.subjects (event_id, subject_id)          -- 역방향 추적용
```

- `auth.*`는 호환성 계약의 일부이므로 자체 컬럼·테이블을 추가하지 않습니다. Passkey처럼 upstream에 이미 존재하는 기능은 upstream 스키마(`auth.webauthn_credentials` 등)를 그대로 사용합니다. 확장은 전부 `dilion_*` schema에서 `user_id` FK로 연결합니다.

### Consent는 현재 상태가 아니라 원장(Ledger)

`marketing_consent = false` 같은 현재 상태만 저장하지 않고 append-only 이벤트로 기록합니다:[^edpb-consent][^kr-network50]

```
2026-01-03 ACCEPT   marketing v1.3
2026-03-10 ACCEPT   marketing v1.4
2026-08-01 WITHDRAW marketing v1.4
```

→ "4월 3일에 이 사용자에게 마케팅 메시지를 보낼 권한이 있었는가?"를 재구성 가능.

- 필수 동의 키(`required-keys`)와 재동의 확인 고지 주기(`reconfirm`)는 코드가 아니라 정책 데이터(§2.8 consent 섹션)를 따릅니다. `reconfirm` 주기가 도래하면 확인 고지 이벤트(webhook/hook)를 발송하고 발송 증적을 원장에 남깁니다 — 동의를 자동 만료시키지 않습니다.
- 동의 증적은 `CONSENT` 스코프 DEK로 암호화되어, 계정 파기 후에도 정책 보존기간 동안 유지되다가 `shred_after` 도래 시 crypto-shred 됩니다. 원장 row 자체는 파기 파이프라인의 step이 아닙니다(§2.9).

---

## 5. 감사 로그 (Audit / Evidence)

### 5.1 원칙

> **마스킹된 목록 조회도 로그를 남긴다. 그러나 개인정보 값 자체는 로그에 남기지 않는다.**

- 한국 개인정보보호법의 접속기록 기준(접속자 식별자, 접속일시, 접속지, 처리한 정보주체, 수행업무)을 충족하도록 설계합니다.[^kr-safety][^cfr-164-312] 마스킹 화면 조회도 `user_id`로 연결 가능한 이상 감사 대상입니다.
- 응답 본문을 통째로 로그에 저장하지 않습니다 (감사 로그가 또 하나의 개인정보 DB가 되는 것 방지). 검색 조건에 개인정보가 포함되면 `[REDACTED]` 처리합니다.
- "누가, 언제, 어디서, 어떤 권한(access_level)으로, 어떤 범위를, 무슨 행위로" 접근했는지만 기록합니다.

### 5.2 이벤트 등급

| 행위 | 수준 |
| --- | --- |
| 관리자 로그인, 목록/검색/마스킹 상세 조회 | 기본 |
| 원본 PII 조회(FULL_READ), 개인정보 수정 | 강화 |
| Export, 사용자 삭제, 동의 변경, 권한 변경, API Key 생성, Privacy webhook 실행 | 매우 민감 |

**"Reveal PII"는 별도의 privileged operation**으로 만듭니다: 기본 화면은 마스킹 → [원본 보기] 클릭 → `pii.read` 권한 검사 (+필요시 사유 입력) → 원본 표시 + `PII_FULL_READ` 이벤트 기록. 이 지점에도 hook(§2.4)이 설치 가능합니다.

### 5.3 Access Event + Subject Manifest 분리

목록 100건 조회 시 100개 `user_id`를 이벤트 본문에 넣지 않고, `dilion_audit.events`(1건) + `dilion_audit.subjects`(N건)로 분리합니다. 이로써 역방향 추적이 가능해집니다:

```
"누가 user_123의 개인정보를 봤는가?"
user_123 → dilion_audit.subjects → dilion_audit.events
  2026-08-01 admin_A LIST_READ
  2026-08-03 admin_A FULL_PII_READ
```

이 역방향 조회 자체가 핵심 컴플라이언스 기능입니다.

### 5.4 로그 자체의 보호

audit log는 append-only 저장소로 운영합니다. application은 APPEND only, tenant admin은 READ only, `UPDATE audit_logs`가 불가능한 구조.[^isms-cc72][^kr-safety] audit sink는 인터페이스로 주입 가능하며, 선택적으로 **immudb 백엔드**를 구성할 수 있습니다 — 이 경우 감사 로그는 DB 대신 immudb에 기록되고, immudb는 레코드 삭제가 불가능하므로 파기 요청 대응을 위해 subject 연관 레코드를 암호화 저장하여 키 폐기로 삭제 의무에 대응합니다(§2.10).

---

## 6. 기능 범위

전체 기능을 처음부터 구현합니다. 단계적 축소 버전(MVP)은 두지 않습니다.

1. **Identity** — Supabase Auth API·DB 완전 호환 인증 엔진: 이메일/비밀번호, magic link, 전화 OTP, OAuth2/OIDC 소셜 로그인, Passkey/WebAuthn(go-webauthn), MFA(TOTP·WebAuthn), SAML SSO, anonymous sign-in, identity linking, admin API, OIDC discovery/JWKS
2. **확장 인증** — OPAQUE (RFC 9807)
3. **PII Vault** — KMS 기반 암호화 저장, 스코프 분리 DEK(DEFAULT/CONSENT), 권한 기반 마스킹/reveal, crypto-shredding
4. **Consent** — consent definition, versioning, append-only consent ledger, 정책 기반 필수 키, 재동의 확인 고지 이벤트 발송 + 증적
5. **Compliance Engine** — YAML 정책 데이터(법률별 하드코딩 금지), 계정별 컴플라이언스 코드 기반 PolicyResolver, 정책 스냅샷, retention 배치 스캐너, legal hold, destruction_logs 증적
6. **Privacy Request** — delete(grace period + erasure pipeline), export, consent withdrawal
7. **Connector** — webhook, REST API/SaaS connector, 사용자 정의 connector 인터페이스
8. **Workflow** — queue, retry, idempotency, 재실행 안전성(크래시/재부팅), partial failure, manual retry, erasure registry(restore-time replay)
9. **Authorization** — 관리 평면 내장 RBAC(deny-by-default), 사용자 정의 permission·role, 이력 보존형 할당 + recertification 리포트, scoped API key, 관리 평면 MFA 기본 요구
10. **Compliance Evidence** — immutable audit trail, destruction_logs(basis 포함), 요청자/요청시간, 시스템별 처리 결과, retention exception, 완료 report, 역방향 접근 추적
11. **임베더블 API** — `dilion.NewServer(...)`, hook 지점(사용자 정의 ErasureStep 포함), KMS/mailer/SMS/signer/audit sink/Authorizer 주입

---

## 7. 주요 리스크 및 고려사항 요약

- **호환성 범위:** URL 호환만으로는 부족. openapi.yaml을 계약으로 삼되 시맨틱(에러 포맷, JWT claims, refresh token 동작, OAuth callback)까지 계약 테스트로 검증. `auth.*` schema는 자체 컬럼 추가 없이 동일 구조 유지. `/auth/v1/user` 등 호환 표면은 마스킹 금지.
- **인증 표면의 넓이:** OAuth/PKCE/Passkey/MFA/SAML/refresh token edge case까지 전부 직접 구현하므로 보안 리뷰와 테스트 커버리지가 최우선. WebAuthn·OPAQUE는 검증된 Go 라이브러리(go-webauthn 등)를 사용하고 프로토콜을 자체 구현하지 않는다.
- **hook 안전성:** 사용자 hook의 실패·지연이 호환 표면의 semantics를 깨지 않도록 지점별 fail-open/fail-closed 정책과 timeout을 명시한다.
- **credential 비보유 원칙:** 대상 시스템의 DB 접속 정보를 저장하지 않는다. 외부 삭제는 대상 시스템이 노출한 webhook/API를 통해서만 실행한다.
- **HTTP 200 ≠ 삭제 증빙:** execution receipt와 evidence를 분리 관리.
- **마스킹을 삭제로 오인하는 설계 금지:** Masking과 Erasure는 절대 같은 operation이 아니다.
- **법률 지식은 데이터:** 유예기간·보존기간·필수 동의 키를 코드에 하드코딩하면 관할 추가·법 개정마다 릴리스가 필요해진다. 정책 YAML의 schema validation과 버전 관리, 내장 정책의 법적 검토 프로세스가 필수.
- **컴플라이언스 코드 할당의 정확성:** 적용 정책은 계정별 명시 할당이 결정하며, GDPR 적용 여부는 위치가 아닌 Art. 3 기준(establishment/targeting)이므로 할당 규칙 정의는 배포자 책임이다. UI locale·IP 같은 위치 신호로 자동 판정하지 않는다.
- **법정 보존 데이터:** 정책의 retention/KEEP 판정 없이 일괄 삭제하면 오히려 컴플라이언스 위반. `basis` 증적과 함께 별도 관리 필수.
- **백업 복원 리스크:** erasure registry replay 절차가 없으면 복원 시 삭제된 데이터가 부활한다. 오래된 백업 복원 시에는 복원 대상보다 최신인 registry 사본을 확보해 replay해야 하며(immudb 백엔드 구성 시 자연 분리), 백업은 beyond use(유한 retention + DR 전용) 상태를 유지한다.
- **crypto-shredding 한계:** 보조 전략일 뿐, 법적 파기 요건 자동 충족을 보장하지 않는다. 특히 wrapped DEK가 백업에 포함되고 KEK가 살아 있으면 옛 백업은 복호화 가능하며, period key는 여러 사용자를 묶으므로 개인별 erasure 수단이 될 수 없다.
- **감사 로그의 개인정보화 방지:** 값이 아닌 행위를 기록한다.

---

## 8. 컴플라이언스 검증 결과 (2026-08 기준)

아키텍처 주요 부분을 GDPR / 한국 개인정보 법제 / SOC 2 (AICPA TSC) / HIPAA와 대조 검증한 결과입니다. 판정: **적절**(현행 설계로 충족) / **보완**(추가 구현·문서화 필요).

### 8.1 인증 엔진·접근통제 (§2.3, §2.6)

- **SOC 2 — 적절.** 최소권한, 권한 스코프별 마스킹, "Reveal PII" privileged operation + 사유 + 강화 이벤트는 CC6.1–6.3 및 privileged access 감사 기대치와 일치.[^aicpa-tsc]
- **HIPAA — 적절/보완.** canonical UUID는 §164.312(a)(2)(i) 고유 사용자 식별을, MFA/Passkey/OPAQUE는 §164.312(d)를 충족하고, 마스킹/reveal 흐름은 minimum necessary(§164.502(b))와 정합.[^cfr-164-312][^cfr-164-502][^hhs-min-necessary] 보완: 비활성 시간 기반 자동 로그오프(§164.312(a)(2)(iii)) 명시, HIPAA 관할에서 reveal 사유 입력 필수화.

### 8.2 PII Vault + KMS + Crypto-shredding (§2.7)

- **GDPR — 적절.** 키 파기 단독을 파기로 공인한 EDPB 지침은 없으며, "crypto-shredding은 보조 전략"이라는 보수적 입장이 규제 현실과 부합.[^datatilsynet][^edpb-pseudo]
- **한국법 — 적절.** 고시 제7조의 암호화 대상·키 관리 절차 요건을 상회. 파기 방법으로서의 키 완전 파기는 정부 안내에 등장하나 고시 명문 열거 방식은 아님.[^kr-safety][^kr-easylaw] 유의: 주민등록번호류는 내부망에서도 무조건 암호화 대상이므로 Vault 외부 저장 금지 데이터 분류 가이드 필요.
- **SOC 2 — 적절/보완.** envelope encryption + DEK 스코프 분리는 표준 이상. 보완: KEK/DEK **rotation 주기·절차** 문서화.[^aicpa-tsc]
- **HIPAA — 보완.** 암호화가 Vault에 한정됨 — `auth.*` 포함 at-rest 암호화, 전 구간 TLS 1.2+, 백업 암호화까지 NIST SP 800-111 정합으로 확장해야 breach notification safe harbor 확보.[^hhs-breach][^nist-80066]

### 8.3 마스킹/가명처리/익명화 구분 (§2.6)

- **GDPR — 적절.** Recital 26·EDPB 가명처리 지침(01/2025)과 정확히 일치.[^gdpr-rec26][^edpb-pseudo]
- **한국법 — 적절.** 법 제2조(가명처리)·제28조의2(가명정보 특례)·익명정보 개념과 일치.[^pipa-28-2] 파기 후 잔존 가명 데이터를 계속 활용하려면 가명정보 특례의 목적 제한이 적용됨을 채택자 문서에 명시.
- **HIPAA — 보완.** "Anonymized"가 §164.514(b) 비식별화(Safe Harbor 18개 식별자 전부 제거 또는 Expert Determination)를 자동 충족하지 않음 — `user_id` 절단 후에도 날짜·우편번호·IP 등이 남으면 PHI. HMAC tombstone은 개인정보에서 유도된 코드이므로(§164.514(c)) 파기 레지스트리 용도로만 쓰고 비식별화 주장에는 사용 불가.[^cfr-164-514][^hhs-deid]

### 8.4 동의 원장 (§4)

- **GDPR — 적절.** Art. 7(1) 동의 입증 책임을 충족하며, 파기 후 증적 보존은 Art. 17(3)(b)/(e)로 정당화 가능 — GDPR 정책에서도 보존 근거(`basis`)를 소멸시효 등으로 구체화할 것.[^edpb-consent][^gdpr-art17]
- **한국법 — 적절/보완.** `reconfirm P2Y`는 정보통신망법 §50⑧ + 시행령 §62의3(2년마다 수신동의 **확인**)과 정합 — 법상 의무가 "확인 고지"이므로 주기 도래 시 확인 고지 이벤트(webhook/hook) 발송 + 발송 증적 기록으로 대응하며, 동의를 자동 만료시키지 않는다(§2.8, §4).[^kr-network50] 보완: 만 14세 미만 법정대리인 동의 플로우(법 제22조의2) 부재[^pipa-22-2], 계약 이행에 필요한 정보는 동의 남발 대신 제15조①4호 근거 수집이 PIPC 권고 방향.
- **SOC 2 — 적절.** P2(choice/consent) 증적 재구성 요구에 부합.[^auditpath-privacy]

### 8.5 Policy-as-Data / 정책 분기 (§2.8)

- **GDPR — 적절.** GDPR 적용 여부는 사용자 위치가 아니라 Art. 3의 establishment/targeting 기준으로 결정되므로(EDPB Guidelines 3/2018 — EU 설립 컨트롤러는 사용자의 국적·거주지와 무관하게 전체 처리에 GDPR 적용), 정책 분기를 위치 신호가 아닌 계정별 컴플라이언스 코드 명시 할당(`dilion_privacy.subject_policies`)으로 결정하는 설계(§2.8)가 이와 정합. 할당 규칙 정의가 배포자 책임이라는 점은 문서화 대상.[^edpb-territorial]
- **한국법 — 적절.** 1년 미이용자 유효기간제는 2023.9.15. 폐지 확인 — 하드코딩 없이 자율 정책 데이터로 다루는 접근이 현행법과 부합.[^kr-expiry]
- **SOC 2 — 보완.** schema validation + 기동 실패는 검증 축 충족. 정책 파일 변경에 CC8.1 변경관리(작성자-승인자 분리, PR 리뷰 + 승인 증적)를 태우는 절차 명시 필요.[^auditpath-cc81]

### 8.6 Grace Period (§2.9)

- **GDPR — 적절.** "without undue delay"는 Art. 12(3)의 1개월(+2개월 연장) 이행 창과 함께 해석 — 30일 유예는 창 내. 단 `grace-period-days` > 1개월 설정 시 연장 고지 요건 문서화.[^gdpr-art12][^gdpr-art17][^ico-erasure]
- **한국법 — 적절 (조건부).** 표준 개인정보 보호지침 제10조는 "정당한 사유가 없는 한 **5일 이내** 파기"로 구체화 — 이에 따라 유예기간은 "철회 가능 기간"이라는 별도 보유 목적·기간으로 처리방침에 고지하고, 유예 만료 후 5일 이내 파기 실행을 SLA로 보장하며, 정보주체의 즉시 파기 요청 경로(유예 생략)를 제공한다(§2.9).[^pipa-21][^kr-std-guideline][^privacy-portal]
- **HIPAA — 보완.** HIPAA에는 삭제권이 없으므로 hipaa 프로파일에서는 grace period 개념 대신 DELETION 요청 자체를 MANUAL_REVIEW로 강제 라우팅한다(§8.12).[^hhs-faq580]

### 8.7 파기 파이프라인 (§2.9)

- **GDPR — 적절.** 비동기 외부 파기는 1개월 창과 충돌하지 않음 — 단 retry/DLQ 지연이 창을 넘지 않도록 SLA 모니터링 필요.[^gdpr-art12] Connector가 processor인 경우 execution receipt는 기술 증빙일 뿐, Art. 28 서면 계약이 별도로 필요.[^gdpr-art28][^gdpr-art19]
- **한국법 — 적절.** 접속기록은 안전성 확보조치 기준 제8조에 따라 "처리한 정보주체 정보"를 포함한 채 최소 1~2년(5만명 이상/고유식별·민감정보 처리 시 2년) 보존해야 하는, 법 제21조③ 단서의 법령 보존 대상.[^kr-safety] 이에 따라 내장 kr 정책은 `audit-log: KEEP`(탈퇴 시 절단 금지)이며, 삭제는 retention(P3Y — 2년 요건 충족) 경과 후에만 실행한다(§2.8).
- **HIPAA — 보완.** 의료기록에는 삭제권이 없고 주법상 6–10년 보존 의무가 있으므로 파기 억제가 전제 — legal hold 일급 엔터티(§2.9)가 파기 파이프라인·retention 스캐너·restore replay 3곳을 게이트한다. KEEP 중심의 `hipaa` 내장 프로파일(retention ≥ P6Y[^cfr-164-316], DELETION MANUAL_REVIEW 강제)은 §8.12 로드맵 항목.[^hhs-faq580]
- **SOC 2 — 적절.** `(request_id, domain, action, basis)` destruction_logs는 P4.3/C1.2 파기 증적 기대치와 일치.[^auditpath-privacy]

### 8.8 백업/복원 (§2.10)

- **GDPR — 적절.** ICO "beyond use" 개념(immutable + 유한 retention + DR 전용 + established schedule 소멸)과 storage limitation(Art. 5(1)(e))에 정합. restore-time replay는 복원 시 데이터 부활 공백을 메우는 설계.[^ico-erasure][^gdpr-art5]
- **SOC 2 — 보완.** A1.2는 충족하나 A1.3의 **정기 복구 테스트**(최소 연 1회, erasure registry replay 동작 검증 포함, 결과·시정조치 기록) 케이던스가 설계에 없음.[^isms-a13]
- **HIPAA — 적절.** §164.308(a)(7)은 "retrievable exact copies"를 요구 — restore runbook은 legal hold·법정 보존 판정을 erasure registry replay보다 **앞**에 두어, 보존 의무 기록이 replay로 파괴되지 않도록 게이트한다(§2.10).[^cfr-164-308]

### 8.9 Connector / 위·수탁 (§3.1–3.3)

- **GDPR — 적절.** receipt 기반 증빙은 Art. 19(수신자 통지)·accountability에 부합. processor 대상에는 Art. 28 계약 별도 필요(8.7 참조).[^gdpr-art19][^gdpr-art28]
- **한국법 — 보완.** 호스팅형 제공 시 운영사는 법 제26조의 수탁자 — 위수탁 계약 문서화·수탁자 공개 지원 기능 필요. destination이 국외로 데이터를 보내면 제28조의8(국외이전) 적용 — destination별 국외이전 여부·국가·법적 근거 메타데이터 관리 필요.[^pipa-26][^pipa-28-8]
- **SOC 2 — 적절.** 대상 시스템 credential 비보유(직접 DB 접근 미제공, webhook/API 연동만)는 CC9.2 관점에서 공격 표면과 위탁 범위를 줄이는 통제. 단 자체 서브프로세서(클라우드/메일러 등) 관리 프로그램은 조직 차원 별도 수립.[^vanta-cc92]
- **HIPAA — 적절/보완.** BA-하청 체인 flow-down(§164.314)과 정합. 보완: BAA 체계(특히 mailer/SMS로 PHI가 나가는 경로), §164.410 침해 통지(60일, 영향자 식별 — audit subjects 역방향 추적이 직접 기여), §164.528 disclosure accounting 리포트 기능.[^cfr-164-314][^cfr-164-410][^hhs-baa]

### 8.10 감사 로그 (§5)

- **한국법 — 적절.** 고시 제8조의 필수 항목(계정·일시·접속지·정보주체·수행업무)을 events+subjects 구조가 충족하고, append-only + 권한 분리(UPDATE 불가)로 위·변조 방지 요건 충족(선택적 immudb 백엔드로 강화 가능). "값이 아닌 행위 기록" 원칙도 문제없음(요구되는 것은 정보주체 식별정보이지 개인정보 값이 아님). 월 1회 이상 점검은 운영 의무 — 점검 리포트 기능 권장.[^kr-safety]
- **GDPR — 적절.** data minimization·Art. 30·Art. 32 정합.[^gdpr-art5][^gdpr-art30][^gdpr-art32]
- **HIPAA — 적절/보완.** §164.312(b) 충족. 보완: hipaa 프로파일에서 audit 보존 ≥ 6년(§164.316(b)(2)(i)), audit sink로 immudb 백엔드 사용 권장, 정기 로그 검토 기능(§164.308(a)(1)(ii)(D)).[^cfr-164-312][^cfr-164-316]
- **SOC 2 — 적절.** CC7.2/CC6.1 로그 무결성 기대치 충족.[^isms-cc72]

### 8.11 설계 차원의 gap (전 프레임워크 공통 — 운영·탐지 계층)

기록(record) 설계는 충분하나 **탐지(detect)·검토(review)·대응(respond)** 계층이 설계에 없음:[^isms-cc72][^aicpa-tsc]

1. 이상 탐지·알림 (CC7.2): `PII_FULL_READ` 대량 발생, 비정상 export, DLQ 적체에 대한 detection policy/SIEM 연동
2. 로그 정기 검토 워크플로우 (CC4.1, 한국 고시 월 1회 점검, HIPAA §164.308(a)(1)(ii)(D))
3. 보안 인시던트 대응 절차 (CC7.3–7.5) 및 breach notification 워크플로우 (SOC 2 P6, HIPAA §164.410, 개보법 제34조)
4. 접근권한 정기 recertification의 수행 주기·절차 (CC6.3 — 리포트 생성 자체는 §2.11의 할당 이력이 지원), KEK/DEK rotation 절차 (CC6.1)
5. 가용성: capacity/HA/RTO·RPO 목표와 정기 복구 테스트 (A1.1/A1.3)
6. Export 파이프라인 명세: Art. 20 기계판독 가능 형식(JSON/CSV/XML), 이동권 vs 열람권 범위 구분, 1개월 기한 추적[^gdpr-art20][^wp242]

### 8.12 HIPAA 개선 계획 (BA-ready 로드맵)

현행 설계에서 HIPAA Business Associate로 판매 가능해지기 위한 항목. 구조(정책 외부화, KEEP 오버라이드, `basis` 증적, append-only 감사, subject manifest, credential 비보유 원칙)는 그대로 활용한다.

1. **`hipaa` 내장 정책 프로파일** — 삭제권이 없는 관할이므로 erasure를 KEEP 중심으로 억제:[^hhs-faq580][^cfr-164-316]

   ```yaml
   policies:
     hipaa:
       erasure:
         grace-period-days: 0           # 삭제권 없음 — DELETION 요청은 MANUAL_REVIEW 강제
         manual-review: required
         domains:
           external-system: KEEP        # 의료기록 삭제 fan-out 금지 (시스템별 화이트리스트 예외)
           audit-log: KEEP              # §164.312(b) 추적성
           account: KEEP                # credential만 DELETE, PII는 보존
           oauth-identity: KEEP
       retention:
         - { domain: audit-log,        period: P6Y,  from: created, action: DELETE,
             basis: "45 CFR 164.316(b)(2)(i)" }
         - { domain: consent-evidence, period: P6Y,  from: created, action: CRYPTO_SHRED,
             basis: "45 CFR 164.316(b)(2)(i)" }   # authorization 문서(§164.508)도 6년
         - { domain: medical-record,   period: P10Y, from: created, action: KEEP,
             basis: "State medical record retention law (고객사 오버라이드 전제)" }
   ```

   필요한 스키마 확장: DELETION의 MANUAL_REVIEW 강제 라우팅 옵션, 삭제 대신 **정정(§164.526 amendment)** 워크플로우.
2. **Legal hold 일급 엔터티** — §2.9의 3중 게이트(파기 파이프라인·retention 스캐너·restore replay)가 담당.
3. **BAA 체계 + 침해 대응** — 자사 BAA 템플릿, 하위 벤더(클라우드/KMS/**mailer·SMS** — PHI가 나가는 경로)와의 BAA 체인(§164.314)[^cfr-164-314][^hhs-baa]; §164.410 침해 통지 워크플로우(60일, `dilion_audit.subjects` 역방향 추적 기반 영향자 목록 export)[^cfr-164-410]; §164.528 disclosure accounting 리포트(감사 데이터는 이미 있음 — 리포트 기능만 추가).
4. **암호화 커버리지 확장** — Vault 한정 암호화를 `auth.*` 포함 DB 전체 at-rest, 전 구간 TLS 1.2+, 백업 파일 암호화로 확장하고 NIST SP 800-111 정합성을 문서화 → breach notification safe harbor 확보.[^hhs-breach][^nist-80066]
5. **세션·접근 보강** — 비활성 시간 기반 자동 로그오프(§164.312(a)(2)(iii), admin 콘솔 포함), hipaa 프로파일에서 PII reveal 사유 입력 **필수화**.[^cfr-164-312]
6. **운영 절차 기능화** — 정기 감사로그 검토 리포트(§164.308(a)(1)(ii)(D)), contingency plan 정기 테스트(§164.308(a)(7)(ii)(D)) 케이던스 문서화.[^cfr-164-308]
7. **비식별화 정합 장치** — ANONYMIZE 액션에 Safe Harbor 18개 식별자 체크리스트 수준의 필드 규칙 또는 Expert Determination 증적 첨부 기능; hipaa 프로파일에서는 audit sink로 immudb 백엔드 사용 권장.[^cfr-164-514][^hhs-deid]

### 검증 각주

[^gdpr-art5]: GDPR Art. 5 (principles — storage limitation, minimisation, accountability): https://gdpr-info.eu/art-5-gdpr/
[^gdpr-art12]: GDPR Art. 12(3) (1개월 이행 창 + 2개월 연장): https://gdpr-info.eu/art-12-gdpr/
[^gdpr-art17]: GDPR Art. 17 (right to erasure, 17(3) 예외): https://gdpr-info.eu/art-17-gdpr/
[^gdpr-art19]: GDPR Art. 19 (수정·삭제의 수신자 통지 의무): https://gdpr-info.eu/art-19-gdpr/
[^gdpr-art20]: GDPR Art. 20 (data portability): https://gdpr-info.eu/art-20-gdpr/
[^gdpr-art28]: GDPR Art. 28 (processor 서면 계약): https://gdpr-info.eu/art-28-gdpr/
[^gdpr-art30]: GDPR Art. 30 (records of processing): https://gdpr-info.eu/art-30-gdpr/
[^gdpr-art32]: GDPR Art. 32 (security of processing): https://gdpr-info.eu/art-32-gdpr/
[^gdpr-rec26]: GDPR Recital 26 (가명처리 데이터는 여전히 개인정보): https://gdpr-info.eu/recitals/no-26/
[^edpb-territorial]: EDPB Guidelines 3/2018 (territorial scope, Art. 3): https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-32018-territorial-scope-gdpr-article-3-version_en
[^edpb-consent]: EDPB Guidelines 05/2020 (consent): https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en
[^edpb-pseudo]: EDPB Guidelines 01/2025 (pseudonymisation): https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf
[^ico-erasure]: ICO — Right to erasure (backup "beyond use"): https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/
[^datatilsynet]: 덴마크 Datatilsynet — 삭제(sletning) 가이드: https://www.datatilsynet.dk/regler-og-vejledning/behandlingssikkerhed/sletning
[^wp242]: WP29 Guidelines on data portability (wp242): https://ec.europa.eu/information_society/newsroom/image/document/2016-51/wp242_en_40852.pdf
[^pipa-21]: 개인정보 보호법 제21조 (파기): https://www.law.go.kr/법령/개인정보보호법
[^pipa-22-2]: 개인정보 보호법 제22조의2 (만 14세 미만 아동): https://www.law.go.kr/법령/개인정보보호법/제22조의2
[^pipa-26]: 개인정보 보호법 제26조 (업무위탁): https://www.law.go.kr/법령/개인정보보호법/제26조
[^pipa-28-2]: 개인정보 보호법 제28조의2 (가명정보 처리): https://www.law.go.kr/법령/개인정보보호법/제28조의2
[^pipa-28-8]: 개인정보 보호법 제28조의8 (국외 이전): https://www.law.go.kr/법령/개인정보보호법/제28조의8
[^kr-std-guideline]: 표준 개인정보 보호지침 제10조 ("정당한 사유가 없는 한 5일 이내" 파기): https://www.law.go.kr/LSW//admRulInfoP.do?admRulSeq=2100000257592&chrClsCd=010201
[^kr-safety]: 개인정보의 안전성 확보조치 기준 (제7조 암호화, 제8조 접속기록 1~2년 보관·월 1회 점검·위변조 방지): https://www.law.go.kr/LSW//admRulInfoP.do?admRulSeq=2100000229672&chrClsCd=010201
[^kr-easylaw]: 생활법령정보 — 개인정보의 파기 방법(암호화 후 키 완전 파기 포함): https://easylaw.go.kr/CSP/CnpClsMain.laf?popMenu=ov&csmSeq=1257&ccfNo=2&cciNo=2&cnpClsNo=3
[^kr-network50]: 정보통신망법 제50조⑧ + 시행령 제62조의3 (수신동의 2년마다 확인): https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률/제50조
[^kr-expiry]: 개인정보 유효기간제(구 제39조의6) 2023.9.15. 폐지: https://www.law.go.kr/법령/개인정보보호법
[^privacy-portal]: 개인정보 포털 — 파기 안내: https://www.privacy.go.kr/front/contents/cntntsView.do?contsNo=121
[^aicpa-tsc]: AICPA 2017 Trust Services Criteria (2022 revised points of focus): https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
[^isms-cc72]: SOC 2 CC7.2 (system operations — 로그 무결성·이상 탐지): https://www.isms.online/soc-2/controls/system-operations-cc7-2-explained/
[^isms-a13]: SOC 2 A1.3 (recovery plan testing): https://www.isms.online/soc-2/controls/availability-a1-3-explained/
[^auditpath-privacy]: SOC 2 Privacy criteria P1–P8: https://www.auditpath.io/blog/soc2-privacy-criteria
[^auditpath-cc81]: SOC 2 CC8.1 (change management): https://www.auditpath.io/blog/soc2-change-management
[^vanta-cc92]: SOC 2 CC9.2 (third-party risk): https://www.vanta.com/collection/tprm/third-party-risk-requirements-soc-2
[^cfr-164-308]: 45 CFR §164.308 (administrative safeguards — contingency plan, 로그 검토): https://www.law.cornell.edu/cfr/text/45/164.308
[^cfr-164-312]: 45 CFR §164.312 (technical safeguards — access/audit/integrity/encryption): https://www.law.cornell.edu/cfr/text/45/164.312
[^cfr-164-314]: 45 CFR §164.314 (BA 계약 요건): https://www.law.cornell.edu/cfr/text/45/164.314
[^cfr-164-316]: 45 CFR §164.316 (문서화 6년 보존): https://www.law.cornell.edu/cfr/text/45/164.316
[^cfr-164-410]: 45 CFR §164.410 (BA 침해 통지 60일): https://www.law.cornell.edu/cfr/text/45/164.410
[^cfr-164-502]: 45 CFR §164.502(b) (minimum necessary): https://www.law.cornell.edu/cfr/text/45/164.502
[^cfr-164-514]: 45 CFR §164.514 (de-identification — Safe Harbor/Expert Determination): https://www.law.cornell.edu/cfr/text/45/164.514
[^hhs-min-necessary]: HHS — Minimum Necessary Requirement: https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/minimum-necessary-requirement/index.html
[^hhs-deid]: HHS — De-identification guidance: https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html
[^hhs-breach]: HHS — Breach notification safe harbor (암호화 지침): https://www.hhs.gov/hipaa/for-professionals/breach-notification/guidance/index.html
[^hhs-faq580]: HHS FAQ 580 — HIPAA는 의료기록 보존 기간을 정하지 않음(주법 지배): https://www.hhs.gov/hipaa/for-professionals/faq/580/does-hipaa-require-covered-entities-to-keep-medical-records-for-any-period/index.html
[^hhs-baa]: HHS — Sample BAA provisions: https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions/index.html
[^nist-80066]: NIST SP 800-66r2 (HIPAA Security Rule 구현 가이드): https://csrc.nist.gov/pubs/sp/800/66/r2/final
