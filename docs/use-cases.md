# Dilion 사용 사례 (Use Cases)

실제 운영 시나리오별로 "무엇을, 어떤 API로, 어떤 권한으로" 수행하는지 정리한 문서입니다.
API 규약은 [api-conventions.md](api-conventions.md), 설계 배경은 [project.md](../project.md)를 참조하세요.

각 시나리오 끝의 **현재 한계** 항목은 지금 구조/API로 어렵거나 불가능한 부분이며, 종합 개선
제안은 문서 하단의 [개선 제안](#개선-제안--현재-구조로-어려운-부분)에 모아 두었습니다.

## 공통 전제

- 관리 평면(`/privacy/v1`, `/iam/v1`) 호출 자격증명은 3종: scoped API key(`dk_...`, 권장),
  RBAC role이 할당된 일반 사용자 access token, `service_role` JWT(사용 자체가 "매우 민감" 감사
  대상). 아래 예시는 API key를 사용합니다.
- 모든 관리 평면 조회는 감사 이벤트를 남깁니다 — "이 조회도 기록된다"는 전제로 운영 절차를
  설계하세요(§5).
- 예시의 base URL은 dev 기준 `http://localhost:8787` 입니다.

---

## 1. 마케팅 동의자에게 이메일 발송 — 수신자 목록 추출

**시나리오:** 마케팅팀이 `marketing` 목적에 동의(및 미철회)한 사용자들의 이메일 목록을 뽑아
캠페인을 발송하려 한다. 정보통신망법 §50 / GDPR 관점에서 "발송 시점에 유효한 동의"가 있는
사용자에게만 보내야 하고, 발송 근거를 증빙으로 남겨야 한다.

```bash
# 1) (선택) 세그먼트 확인 — user_id 수준, 이메일 미포함 (users.read)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/consents?purpose=marketing&granted=true"

# 2) 수신자 목록 추출 — 이메일 포함, 사유 필수 (pii.export)
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"purpose":"marketing","fields":["email"],"reason":"2026-09 뉴스레터 캠페인",
       "limit":1000}' \
  http://localhost:8787/privacy/v1/consents/export
# → { "items":[{"user_id":"...","email":"a@b.com","phone":null}], "next_cursor":"..." }
#   next_cursor가 null이 될 때까지 반복 (body의 cursor로 전달)
```

- export는 **원장의 최신 상태가 GRANT인 사용자만**, 탈퇴(파기)·삭제된 계정을 제외하고
  반환합니다. 페이지마다 `CONSENT_AUDIENCE_EXPORT`("매우 민감", AccessFull) 감사 이벤트가
  사유·대상자 manifest와 함께 기록되므로, 이 기록 자체가 "발송 시점에 동의가 있었다"는
  증빙의 출발점입니다(§4).
- 사용자가 수신거부하면 [7. 동의 수집/철회](#7-동의-수집철회-기록-가입수신거부-플로우)의
  PATCH(또는 본인이 직접 `/privacy/v1/me/consents`)로 즉시 원장에 반영하세요. 다음 추출부터
  자동 제외됩니다.

**필요 권한:** 세그먼트 조회는 `users.read`, 이메일 포함 추출은 `pii.export` + 사유 필수 —
동의자 목록 추출은 그 자체가 대량 PII 처리이므로 reveal과 같은 급의 privileged operation
입니다.

---

## 2. 회원 탈퇴 (삭제 요청 → 유예 → 파기)

**시나리오:** 사용자가 앱에서 "회원 탈퇴"를 누른다. 정책(예: `kr`)의 유예기간 동안 철회
가능해야 하고, 유예 만료 후 파기 파이프라인(§2.9)이 credential → 세션 → 외부 시스템 →
계정 순으로 실행되어야 한다.

**Self-service (권장):** 최종 사용자의 access token(`role=authenticated`)만으로 동작하며,
RBAC role이 필요 없습니다 — 소유권(sub == user_id)이 곧 권한입니다(§2.11).

```bash
# 사용자 본인이 탈퇴 요청 (202 Accepted, Idempotency-Key 지원)
curl -X POST -H "Authorization: Bearer $USER_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"DELETION"}' \
  http://localhost:8787/privacy/v1/me/requests
# → { "id":"pr_...", "status":"REQUESTED", "policy_id":"kr", "scheduled_at":"<유예 만료 시각>" }

# 즉시 파기를 원하면 (유예 생략 — 표준지침상 제공 의무)
... -d '{"type":"DELETION","immediate":true}' ...

# 본인 요청 목록 / 유예 중 철회 (타인 요청은 404 — 존재 노출 방지)
curl -H "Authorization: Bearer $USER_ACCESS_TOKEN" \
  http://localhost:8787/privacy/v1/me/requests
curl -X POST -H "Authorization: Bearer $USER_ACCESS_TOKEN" \
  http://localhost:8787/privacy/v1/me/requests/pr_.../cancel
```

**관리 평면 (백엔드/운영자 대행):** `privacy.requests.manage` 권한으로 동일 작업 수행.

```bash
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -H "Idempotency-Key: withdraw-$USER_ID" \
  -d '{"user_id":"'$USER_ID'","type":"DELETION"}' \
  http://localhost:8787/privacy/v1/requests

# 특정 사용자의 DSR 이력 / 유형·기간 조회
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/requests?user_id=$USER_ID"
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/requests?type=DELETION&requested_after=2026-08-01T00:00:00Z&status=PROCESSING"
```

- `DELETE /auth/v1/admin/users/{id}`(Supabase 호환)도 outbox를 통해 같은 DELETION 요청을
  생성합니다 — 기존 supabase-js 코드의 admin 삭제가 자동으로 컴플라이언스 파이프라인을
  탑니다(§2.5).
- legal hold가 걸린 사용자의 요청은 파기 시점에 `MANUAL_REVIEW`로 보류됩니다(§2.9).

---

## 3. CS 상담원의 사용자 정보 조회 (마스킹 → 필요 시 reveal)

**시나리오:** 상담원이 문의 전화를 받고 사용자 프로필을 확인한다. 기본은 마스킹된 값으로
충분하고, 본인 확인 등 원본이 꼭 필요할 때만 사유를 남기고 열람한다(§2.6 최소권한).

```bash
# 사용자 찾기 — email/phone/vault 필드 정확 일치 검색 (users.read, USER_SEARCH 기록)
# 정확히 한 가지 기준만 지정. 결과는 user_id만 — 값은 아래의 profile 조회로 잇는다.
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/users?email=customer%40example.com"
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/users?field=name&value=%ED%99%8D%EA%B8%B8%EB%8F%99"
# → { "items":[{"user_id":"...","source":"AUTH_EMAIL","field_key":null}], ... }
#   vault 필드 검색은 keyed blind index 기반 equality 매치 (부분 일치 불가).
#   검색어는 감사 로그에 기록되지 않는다 (§5.1 — 매치된 subject manifest만 남음).

# 기본 조회 — 항상 마스킹 프로젝션 (users.read, PII_MASKED_READ 기록)
curl -H "Authorization: Bearer $KEY" \
  http://localhost:8787/privacy/v1/users/$USER_ID/profile
# → { "view":"MASKED", "fields": { "name": {"value":"홍**","hint":"NAME"}, ... } }

# 원본 열람 — 별도 privileged operation (pii.reveal + 사유 필수, PII_FULL_READ 기록)
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"reason":"본인 확인 요청 — 티켓 #4821"}' \
  http://localhost:8787/privacy/v1/users/$USER_ID/profile/reveal

# 프로필 수정 (pii.write, PII_UPDATE 기록 — 응답은 다시 마스킹 뷰)
curl -X PATCH -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"set":{"address":{"value":"서울시 ...","hint":"ADDRESS"}}}' \
  http://localhost:8787/privacy/v1/users/$USER_ID/profile
```

**필요 권한:** 내장 role 번들 기준 `support`(users.read + pii.read)면 마스킹 조회까지,
reveal은 `pii.reveal` 보유자만. GET/reveal/PATCH가 각각 다른 permission이므로 "조회는 넓게,
원본 열람은 좁게" 배치가 가능합니다.

**현재 한계:**
- 이메일이 `auth.users.email`(인증용)과 Vault 프로필 필드(예: `email`)에 **이원화**될 수
  있는데, 어느 쪽이 진실 원본인지의 가이드/동기화 장치가 없습니다. → [제안 P8](#p8-authusers-pii와-vault-프로필의-관계-정의)

---

## 4. "누가 이 사용자의 개인정보를 봤는가" — 감사 대응

**시나리오:** 특정 사용자가 "내 정보를 누가 열람했는지 알려달라"고 요구하거나(개보법 열람권,
HIPAA §164.528 disclosure accounting), 내부 감사에서 특정 상담원의 열람 내역을 점검한다.

```bash
# 역방향 추적: 이 사용자를 subject manifest에 포함한 모든 이벤트 (§5.3)
# from/to로 기간 창 지정 가능 (from 이상, to 미만 — 월 1회 점검 리포트용)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/iam/v1/audit/events?subject_id=$USER_ID&from=2026-08-01T00:00:00Z&to=2026-09-01T00:00:00Z"

# 특정 행위자 기준, 원본 열람만
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/iam/v1/audit/events?actor_id=$ADMIN_ID&action=PII_FULL_READ"

# 이벤트 상세 (reveal 사유 포함)
curl -H "Authorization: Bearer $KEY" \
  http://localhost:8787/iam/v1/audit/events/evt_...
```

**필요 권한:** `audit.read` (내장 번들로는 `security-admin` 이상).

**현재 한계:** 월 1회 점검(고시 §8)용 정기 리포트 *생성*은 아직 API가 아닌 운영 절차의
몫입니다(§8.11) — 기간 창 조회(`from`/`to`)가 그 재료를 제공합니다.

---

## 5. 외부 시스템(자사 DB·CRM 등) 연동 삭제

**시나리오:** 사용자 데이터가 Dilion 외부(서비스 DB의 orders, CRM, 분석 도구)에도 있다.
탈퇴 시 이 시스템들에도 삭제가 전파되고, 시스템별 처리 결과가 증빙으로 남아야 한다.

```bash
# 1) 삭제 수신 webhook을 destination으로 등록 (destinations.manage)
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"type":"WEBHOOK","name":"primary-app",
       "config":{"url":"https://api.example.com/privacy/delete","identity_field":"user_id"},
       "secret":"whsec_..."}' \
  http://localhost:8787/privacy/v1/destinations
```

수신 측은 HMAC 서명을 검증하고 자체 DB에서 삭제/익명화를 실행합니다(§3.2). 이후 파기
파이프라인의 `external-system` step이 등록된 destination 전체로 fan-out하며, 실패는
재시도(+DLQ)로 처리됩니다. HTTP 200이 아니라 별도의 execution receipt(task 기록)가
증빙입니다.

**설계 원칙:** 외부 시스템의 DB credential은 받지 않습니다 — webhook/API 방식만 제공(§3.1).

**현재 한계:** destination까지는 API로 관리되지만, **request별 task(수행 결과·receipt·재시도
상태)를 조회하는 API가 없습니다.** "CRM 삭제가 실패해서 DLQ에 쌓였는지"를 운영자가 API로
볼 수 없고, 수동 재시도 endpoint도 없습니다. → [제안 P5](#p5-파기-증빙-조회-destruction-logs--connector-tasks)

---

## 6. 삭제 완료 증빙 리포트 (컴플라이언스 감사 대응)

**시나리오:** 규제기관/감사인이 "작년 X월 탈퇴한 사용자 건이 실제로 전부 파기되었는지"
증빙을 요구한다. 설계상 근거 데이터는 전부 존재합니다 — step별 `destruction_logs`(action,
basis, executed_at), connector task receipt, 감사 이벤트.

**현재 가능한 방법:** `GET /privacy/v1/requests/{id}`로 상태(`DONE`, `completed_at`)까지는
확인되지만, **step별 파기 내역과 근거(basis)는 API로 노출되지 않아** self-host DB의
`dilion_privacy.destruction_logs`를 직접 조회해야 합니다.

**현재 한계:** 파기 증빙이 이 제품의 핵심 가치("이 사용자의 데이터는 어디에 있고, 전부
처리되었는가 — 증빙 포함")인데 조회 표면이 없습니다. → [제안 P5](#p5-파기-증빙-조회-destruction-logs--connector-tasks)

---

## 7. 동의 수집/철회 기록 (가입·수신거부 플로우)

**시나리오:** 가입 화면에서 필수(terms, privacy)/선택(marketing) 동의를 받고, 이후 사용자가
설정 화면이나 메일 하단 링크로 수신거부한다. 모든 변경은 "언제, 어떤 정책 버전에, 어디서"와
함께 원장에 남아야 한다.

```bash
# 가입 완료 직후 백엔드가 동의 기록 (consents.write — DSR 권한과 분리된 별도 permission,
# 가입 플로우 서버 키에는 이 scope만 부여하면 된다)
curl -X PATCH -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"purpose":"marketing","granted":true,"policy_version":"v1.4","source":"UI"}' \
  http://localhost:8787/privacy/v1/users/$USER_ID/consents

# 수신거부 (원장에 WITHDRAW append — 기존 행 수정 아님)
... -d '{"purpose":"marketing","granted":false,"policy_version":"v1.4","source":"UI"}' ...

# 또는 사용자 본인이 직접 (access token만으로 — source는 UI로 고정)
curl -X PATCH -H "Authorization: Bearer $USER_ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"purpose":"marketing","granted":false,"policy_version":"v1.4"}' \
  http://localhost:8787/privacy/v1/me/consents
```

- 필수 동의 키는 정책 데이터(`consent.required-keys`)가 결정합니다 — 코드 하드코딩 금지(§2.8).
- 동의 증적은 `CONSENT` 스코프 DEK로 암호화되어 계정 파기 후에도 정책 보존기간 동안
  유지됩니다(§4) — "탈퇴자가 과거 수신에 대해 이의 제기"하는 경우에 대응 가능합니다.

**현재 한계:** 원장이 append-only로 쌓이지만 **이력을 읽는 API가 없습니다.** 현재 상태
projection(`GET .../consents`)만 노출되므로, "4월 3일 시점에 동의가 있었는가"라는 문서의
대표 질문에 API로 답할 수 없습니다. → [제안 P6](#p6-동의-원장-이력--시점-질의-api)

---

## 8. 재동의(2년) 확인 고지 운영 — 정보통신망법 §50⑧

**시나리오:** kr 정책의 `reconfirm: {"marketing.*": P2Y}`에 따라, 동의 후 2년이 도래한
사용자에게 확인 고지를 보내고 발송 증적을 남겨야 한다.

**현재 동작:** 내장 스캐너가 주기 도래 사용자를 찾아 확인 고지 이벤트를 발송하고 증적을
기록합니다(동의 자동 만료는 없음). 사용자별 상태는 `GET .../consents` 응답의
`reconfirm_due` 필드로, 대상자 전체 목록은 세그먼트 조회로 뽑습니다:

```bash
# 다음 30일 내 확인 고지가 도래하는 (user, purpose) 목록 (users.read)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/consents?reconfirm_due_before=2026-09-23T00:00:00Z"
```

자체 캠페인 도구로 고지를 발송한다면 이 목록을
[1번](#1-마케팅-동의자에게-이메일-발송--수신자-목록-추출)의 audience export와 조합하세요.
참고: 재동의 필터는 스캔 예산 내에서 동작하므로 한 페이지가 `limit`보다 짧을 수 있습니다 —
`next_cursor`가 null이 될 때까지 따라가면 전체가 커버됩니다.

---

## 9. 법적 분쟁 발생 — legal hold로 파기 중단

**시나리오:** 소송/수사 협조로 특정 사용자의 데이터 파기를 중단해야 한다. hold 중 탈퇴
요청이 오면 파기가 실행되지 않고 보류되어야 한다.

```bash
# hold 설정 (holds.manage — 파기 실행 권한과 직무 분리 권장, §2.11)
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"user_id":"'$USER_ID'","reason":"민사소송 2026가합1234 증거보전",
       "basis":"민사소송법 §344"}' \
  http://localhost:8787/privacy/v1/holds

# 해제 (보류되었던 요청은 자동 재개)
curl -X POST -H "Authorization: Bearer $KEY" \
  http://localhost:8787/privacy/v1/holds/hold_.../release

# 현재 유효한 hold만 조회 (active=false면 해제된 이력만)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/privacy/v1/holds?active=true"
```

hold는 파기 파이프라인·retention 스캐너·restore replay 3곳을 모두 게이트합니다(§2.9).
설정/해제는 "매우 민감" 감사 이벤트입니다.

---

## 10. 접근권한 정기 점검 (recertification, SOC 2 CC6.3)

**시나리오:** 분기마다 "현재 `pii.reveal`을 가진 사람이 누구이고, 언제 누가 부여했는가"를
보고하고, 퇴사자/이동자의 권한을 회수한다.

```bash
# 특정 permission의 현재 보유자 + 부여 근거
curl -H "Authorization: Bearer $KEY" \
  http://localhost:8787/iam/v1/permissions/pii.reveal/holders

# role별 할당 이력 (회수된 것 포함 — 고시 §5 기록 의무)
curl -H "Authorization: Bearer $KEY" \
  "http://localhost:8787/iam/v1/roles/$ROLE_ID/assignments?include_revoked=true"

# 회수 (이력 보존 — row 삭제가 아니라 revoked 마킹)
curl -X DELETE -H "Authorization: Bearer $KEY" \
  http://localhost:8787/iam/v1/assignments/42
```

---

## 11. 개인정보 열람/이동권 대응 (EXPORT)

**시나리오:** 사용자가 자기 데이터 사본을 요구한다(GDPR Art. 15/20, 개보법 열람권).

```bash
# 사용자 본인이 직접 (self-service)
curl -X POST -H "Authorization: Bearer $USER_ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"EXPORT"}' \
  http://localhost:8787/privacy/v1/me/requests

# 또는 운영자 대행 (privacy.requests.manage)
curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"user_id":"'$USER_ID'","type":"EXPORT"}' \
  http://localhost:8787/privacy/v1/requests
```

**현재 한계 (중요):** EXPORT 요청은 **접수만 되고 처리 파이프라인이 아직 없습니다**
([requests.go:179-182](../internal/privacy/requests.go#L179-L182), wave 2 예정). 산출물
생성·다운로드 API도 없으므로 현재는 프로필 reveal + 자체 조합으로 수동 대응해야 합니다.
→ [제안 P7](#p7-export-파이프라인--산출물-전달)

---

## 12. Supabase 프로젝트에서 이관 / supabase-js 그대로 사용

**시나리오:** 기존 Supabase Auth 기반 앱을 Dilion으로 옮기면서 클라이언트 코드를 바꾸고
싶지 않다.

- `/auth/v1/*`가 upstream openapi.yaml 기준 호환이므로 supabase-js/gotrue-js의 URL만
  바꾸면 signup/login/OAuth/MFA/passkey가 그대로 동작합니다(파리티 스위트가 CI에서 상시
  검증).
- DB도 `auth.*` schema 동일 구조이므로 기존 데이터 이관 및 `auth.users`를 참조하는 기존
  SQL/트리거/RLS가 수정 없이 동작합니다(§2.2).
- 이관 직후부터 admin 삭제가 자동으로 파기 파이프라인을 타므로, destination 등록(§5)과
  정책 코드 할당만 하면 컴플라이언스 기능이 켜집니다.

---

## 13. Go 애플리케이션에 임베드 (라이브러리 사용)

**시나리오:** 별도 데몬이 아니라 자사 Go 서버 안에 인증+프라이버시를 내장하고, 가입 검증
로직·자체 KMS·자체 CRM connector를 주입하고 싶다.

```go
srv := dilion.NewServer(
    dilion.WithDatabase(pool),
    dilion.WithKMS(myKMS),
    dilion.WithHook(dilion.BeforeSignup, blockDisposableEmail), // reject 가능
    dilion.WithConnector("my-crm", myCRMDeleter),               // 파기 fan-out 대상
)
```

아무것도 주입하지 않아도 완전한 기능으로 동작하며(기본값의 완결성, §2.4), hook으로 토큰
custom claims 주입·사용자 정의 ErasureStep 삽입·PII reveal 감시 등이 가능합니다.

---

## 개선 제안 — 현재 구조로 어려운 부분

위 시나리오들을 실제로 수행해 보며 드러난 API 공백입니다. **P1–P4와 부수 개선 3건은
2026-08-24에 구현되었습니다** — 아래 "구현된 제안" 요약을 참조하고, P5–P8이 남은
제안입니다.

### 구현된 제안 (2026-08-24)

- **P1. 동의 세그먼트 조회 + audience export** — `GET /privacy/v1/consents`
  (`purpose`/`granted`/`reconfirm_due_before` 필터, `users.read`) +
  `POST /privacy/v1/consents/export` (`pii.export` + 사유 필수, 페이지마다
  `CONSENT_AUDIENCE_EXPORT` 감사). 원장이 진실 원본으로 유지되며 projection은
  DISTINCT ON 스캔 — 볼륨 증가 시 현재 상태 캐시 테이블로 교체 가능(계약 불변).
  → [사례 1](#1-마케팅-동의자에게-이메일-발송--수신자-목록-추출), [사례 8](#8-재동의2년-확인-고지-운영--정보통신망법-508)
- **P2. Self-service 표면** — `/privacy/v1/me/requests`(POST/GET/cancel),
  `/privacy/v1/me/consents`(GET/PATCH). `role=authenticated` 토큰만 허용하고 모든 작업을
  토큰의 sub로 강제(타인 요청은 404). API key·service_role은 403. 감사에는
  `actor_type=user` + subject manifest로 기록. → [사례 2](#2-회원-탈퇴-삭제-요청--유예--파기)
- **P3. Request 목록 필터** — `?user_id=` `?type=` `?requested_after/before=` 추가.
- **P4. 사용자 검색** — `GET /privacy/v1/users?email=|phone=|field=&value=` (정확히 한
  기준). email/phone은 auth.users 직접 매치, vault 필드는 blind index
  (`dilion_pii.profile_search_index`, tombstone key에서 파생한 HMAC — equality only,
  프로필 쓰기와 같은 트랜잭션으로 유지, 파기 시 함께 삭제, migration 0201). 결과는
  user_id만, 검색어는 감사 로그에 미기록(`USER_SEARCH`). 인덱스는 쓰기 시점에 생성되므로
  이 마이그레이션 이전에 저장된 프로필은 다음 쓰기 전까지 필드 검색에 잡히지 않는다.
- **부수 개선** — audit events `?from=&to=` 기간 창; holds `?active=` 필터;
  `consents.write` permission 분리(migration 0304 — privacy-officer/security-admin/owner에
  자동 부여, `updateUserConsent`는 이제 이 권한을 요구).

### P5. 파기 증빙 조회 (destruction logs + connector tasks)

**문제:** 파기 증빙(destruction_logs)과 외부 삭제 receipt(tasks)가 DB에만 있고 API가 없어,
제품의 핵심 질문("전부 처리되었는가? 증빙은?")에 API로 답할 수 없다(사례 5·6). DLQ 적체
확인·수동 재시도도 불가.

**제안:**

```
GET  /privacy/v1/requests/{id}/logs    # step별 domain/action/basis/executed_at
GET  /privacy/v1/requests/{id}/tasks   # destination별 status/attempts/evidence(receipt)
POST /privacy/v1/tasks/{id}/retry      # DLQ 수동 재시도 (privacy.requests.manage)
```

이 세 개면 "삭제 완료 리포트"를 외부 감사에 그대로 제출할 수 있고, 운영자가 부분 실패를
API로 관제할 수 있다.

### P6. 동의 원장 이력 + 시점 질의 API

**문제:** 원장은 append-only로 쌓이지만 읽기는 현재 상태 projection뿐이라, 문서의 대표
질문 "4월 3일에 마케팅 권한이 있었는가"를 API로 답할 수 없다(사례 7).

**제안:**

```
GET /privacy/v1/users/{id}/consents/history?purpose=marketing   # 원장 이벤트 나열
GET /privacy/v1/users/{id}/consents?at=2026-04-03T00:00:00Z     # 시점 재구성 projection
```

`at` 질의는 분쟁 대응의 킬러 기능이므로 감사에 별도 action(예: `CONSENT_POINT_READ`)으로
남긴다.

### P7. EXPORT 파이프라인 + 산출물 전달

**문제:** EXPORT는 접수만 되고 처리되지 않는다(사례 11). Art. 20은 기계판독 가능 형식과
1개월 기한을 요구한다.

**제안:** 파기 파이프라인과 대칭 구조의 export 파이프라인(wave 2 예정 항목 구체화):
auth 계정 + Vault 프로필 + 동의 이력을 JSON으로 조립하고, 외부 시스템에는
`privacy.export` webhook으로 데이터 기여를 수집. 산출물은 암호화 저장 + 만료를 두고
`GET /privacy/v1/requests/{id}/artifact`(권한 `pii.export`, 다운로드마다 감사)로 전달.
P2의 `/me` 표면과 결합하면 사용자 본인 다운로드까지 완결된다.

### P8. `auth.users` PII와 Vault 프로필의 관계 정의

**문제:** 이메일·전화가 `auth.users`(인증용)와 Vault 프로필 필드 양쪽에 존재할 수 있는데,
어느 쪽이 진실 원본이고 언제 동기화되는지 규칙이 없다. 사례 1(이메일 추출)과 사례 3(CS
조회)에서 두 값이 어긋나는 순간 운영 사고가 된다.

**제안:** "인증 식별자(email/phone)는 `auth.users`가 원본, Vault는 확장 PII만"을 규칙으로
문서화하고, Vault에 `EMAIL` hint 필드를 쓸 때는 인증 이메일의 복제가 아니라 별도 연락처
용도임을 명시. 필요하면 email 변경 시 hook(`AfterUserUpdate`)으로 Vault 동기화를 채택자가
선택하게 한다.

### 부수 개선 (소규모)

- **audit events 기간 필터** (`?from=&to=`) — 사례 4의 정기 점검·리포트에 필요.
- **`GET /privacy/v1/holds`의 `active=true` 필터** — 현재는 released 포함 전체가 반환된다.
- **consent PATCH의 권한 완화 검토** — 동의 기록(`updateUserConsent`)이
  `privacy.requests.manage`를 요구하는데, 이는 DSR 승인과 동급의 강한 권한이다. 가입
  플로우의 서버 키에 DSR 관리 권한까지 쥐여주게 되므로 `consents.write` 같은 별도
  permission 분리가 최소권한에 맞다.
