# Dilion API 규약 (/privacy/v1, /iam/v1)

frontend codegen(openapi.yaml 기반)에 영향을 주는 모든 규칙. `/auth/v1/*`는 Supabase Auth 호환 표면이므로 이 규약의 적용 대상이 아니다(upstream 계약을 따름).

## URL / Method

- 리소스는 **복수형 kebab-case**: `/privacy/v1/requests`, `/privacy/v1/destinations`, `/iam/v1/api-keys`.
- 중첩은 1단계까지: `/iam/v1/roles/{roleId}/assignments`.
- **GET** 조회/목록, **POST** 생성 및 액션(`POST /privacy/v1/requests/{id}/cancel`), **PATCH** 부분 수정, **DELETE** 삭제. PUT은 쓰지 않는다.
- 액션은 동사 하나의 POST 하위 경로로만 표현한다.

## Operation / DTO 네이밍

- operationId: camelCase `동사+리소스` — `listPrivacyRequests`, `createPrivacyRequest`, `cancelPrivacyRequest`, `revealUserPII`.
- OpenAPI schema 이름: PascalCase. 응답 리소스는 명사(`PrivacyRequest`), 생성/수정 body는 `Create*Body` / `Update*Body`, 목록은 `*Page`.
- JSON 필드: **snake_case** (Supabase 생태계와 통일).

## Resource identifier

- Dilion 소유 리소스 ID: `<prefix>_<32 hex>` (`^[a-z]{2,4}_[0-9a-f]{32}$`), 예: `pr_`, `dst_`, `hold_`, `role_`, `key_`, `evt_`. `httpapi.NewID(prefix)` 사용.
- 사용자 식별자는 예외적으로 **bare UUID** (Supabase 호환 canonical `user_id`).
- API key 원문 토큰: `dk_<48 random url-safe>` — 발급 응답에서 1회만 노출.

## 날짜/시간, 기간

- 모든 시각은 **RFC 3339 UTC** (`2026-08-12T03:04:05Z`), 필드명은 `*_at`.
- 기간은 ISO-8601 duration (`P3Y`, `P30D`) — 정책 데이터와 동일 표기.

## Enum

- 모든 enum 값은 **UPPER_SNAKE_CASE**: `DELETION | EXPORT | CONSENT_WITHDRAWAL`, `REQUESTED | PROCESSING | DONE | MANUAL_REVIEW | CANCELED`, `DELETE | ANONYMIZE | CRYPTO_SHRED | KEEP`.
- OpenAPI에 enum으로 선언해 codegen이 union type을 생성하게 한다.

## nullable / optional

- **응답**: 항상 존재하는 필드는 required로 선언. 값이 없을 수 있는 필드는 `nullable`(`*T` + huma `nullable`)로 명시하고 `null`을 내려준다 — 응답에서 "필드 생략"으로 없음을 표현하지 않는다.
- **요청**: optional 필드는 포인터 + `omitempty`. `null`과 "생략"을 구분하지 않는다(둘 다 미변경/미지정).

## Pagination / Sorting / Filtering

- **Cursor 기반**: `?limit=`(기본 20, 최대 100) + `?cursor=`(opaque string).
- 응답 envelope:

```json
{ "items": [ ... ], "next_cursor": "..." }   // next_cursor: string | null
```

- Sorting: `?sort=field` 오름차순, `?sort=-field` 내림차순, 콤마 다중. 허용 필드는 endpoint별 enum으로 문서화.
- Filtering: 정확 일치는 리소스 필드명 그대로 query param(`?status=PROCESSING`). 검색은 `?q=` — **`q` 값은 감사 로그에 `[REDACTED]` 처리**.

## Error 응답

- 전 endpoint 공통 **RFC 9457 Problem Details** (`application/problem+json`, huma 기본 모델):

```json
{ "type": "https://dilion.dev/errors/permission-denied", "title": "Forbidden",
  "status": 403, "detail": "requires permission pii.reveal",
  "code": "permission_denied", "errors": [ ... ] }
```

- `code`: 기계 판독용 snake_case 문자열 (frontend 분기 기준). 목록: `validation_failed`, `unauthenticated`, `permission_denied`, `not_found`, `conflict`, `idempotency_conflict`, `legal_hold_active`, `policy_violation`, `rate_limited`, `internal`.
- **Validation**: 422 + `errors[]` (huma `ErrorDetail`: `message`, `location`, `value`). **PII로 분류된 필드는 `value`를 echo하지 않는다.**
- 401 `unauthenticated` / 403 `permission_denied`(detail에 필요 permission 명시, 발생 시 감사 이벤트). 타 테넌트 리소스는 404로 응답(존재 노출 방지).

## HTTP status code

| 상황 | code |
| --- | --- |
| 조회/목록/액션 성공 | 200 |
| 생성 | 201 + `Location` |
| 비동기 접수 (privacy request 생성) | 202 |
| 삭제 | 204 |
| schema/validation 오류 | 422 |
| 시맨틱 거부 (grace 중 중복 요청 등) | 400 또는 409 |
| 인증/권한 | 401 / 403 |
| idempotency 충돌 | 409 |

## Authentication

- `Authorization: Bearer <token>` — 관리 평면이 받는 자격증명 3종:
  1. `service_role` JWT — 권한 검사 우회(사용 자체가 "매우 민감" 감사 대상)
  2. scoped API key(`dk_...`) — 자체 scope로 제한 후 RBAC 검사
  3. **일반 사용자 access token**(`role=authenticated`) — actor_id=사용자 UUID로 RBAC(role_assignments) 검사. deny-by-default: role이 할당되지 않은 사용자는 403.
- `POST /privacy/v1/requests`는 `Idempotency-Key` 헤더 지원(같은 키 재시도 시 최초 응답 재반환).
