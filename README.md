# Dilion

Supabase Auth 호환 인증 + Privacy Orchestration 플랫폼. 설계 문서: [project.md](project.md) · 구현 계획: [PLAN.md](PLAN.md) · API 규약: [docs/api-conventions.md](docs/api-conventions.md)

## Quickstart (dev)

```bash
make up        # 1) Postgres 기동 (docker compose, :55432 — 테스트 DB 자동 생성)
make dev       # 2) API 서버 :8787 (migrations 자동 적용, dev 정책: 유예 0일)
make dev-web   # 3) 샘플 프론트 :5173 (별도 터미널; /auth·/privacy·/iam proxy → :8787)
```

- 관리 평면 호출용 dev 토큰: `make e2e-token` → `web/.env.local`의 `VITE_DILION_SERVICE_TOKEN=`에 설정 (7일 유효, secret `devsecret-e2e`).
- PII 암호화 마스터 키는 `.dev/master.key`에 자동 생성·유지됩니다 (삭제하면 기존 Vault 데이터 복호화 불가).
- 전체 종료/초기화: `make down` (볼륨 포함 삭제 — 모든 dev 데이터 리셋).

## 테스트

```bash
make test      # 유닛 테스트만 (DB 불필요)
make test-db   # 전체 (DB 통합, -race) — make up 자동 수행
make ci        # CI와 동일한 전체 게이트 (test-db + openapi drift + web build/lint)
```

CI는 [.github/workflows/ci.yml](.github/workflows/ci.yml) — backend(compose로 DB 기동 → `make test-db` → openapi drift 검사)와 frontend(codegen drift → typecheck/build → lint) 2개 job.

## 구조

- `/auth/v1/*` — Supabase Auth 호환 (chi 직접 구현, upstream 계약 준수)
- `/privacy/v1/*`, `/iam/v1/*` — 자체 API (huma v2 → OpenAPI 자동 생성 → `web/openapi.yaml` → 프론트 codegen)
- `make openapi` — 스펙 재생성. 핸들러 변경 후 필수 (CI가 drift를 잡음)
- 샘플 프론트: [web/README.md](web/README.md) (operation UI 커버리지 표 포함)
