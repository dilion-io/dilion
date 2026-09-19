# Dilion

[한국어](README.md) · [English](README.en.md)

Dilion은 Go와 PostgreSQL로 만든 인증·개인정보 관리 서버입니다.
Supabase Auth 호환 API로 회원가입과 로그인을 처리하고, 같은 사용자 ID를 기준으로
개인정보 보관, 동의 이력, 회원 탈퇴에 따른 삭제 작업을 관리합니다.

개인정보는 Vault에 암호화해 저장하고, 조회 권한에 따라 마스킹하거나 원문을 제공합니다.
동의와 철회는 이력으로 남기며, 삭제 요청은 유예 기간을 거쳐 비동기 작업으로 처리합니다.
외부 시스템의 삭제 처리는 커넥터로 연결할 수 있습니다.
API 호출 예시와 처리 제약은 [사용 사례](docs/use-cases.md)에 정리되어 있습니다.

서버를 독립 프로세스로 실행하거나 `dilion.NewServer(...)`로 Go 애플리케이션에 넣을 수 있습니다.
메일·SMS, KMS, 훅, 삭제 커넥터는 Go 인터페이스로 교체할 수 있습니다.

## 로컬 실행

Go 1.26.8 이상, Docker Compose, GNU Make가 필요합니다.

```bash
make dev
```

PostgreSQL을 `localhost:55432`에 띄우고 마이그레이션을 적용한 뒤,
API 서버를 `http://localhost:8787`에서 실행합니다.

```bash
curl http://localhost:8787/healthz
```

샘플 관리 화면은 다른 터미널에서 실행합니다. Node.js 22 이상이 필요합니다.

```bash
make web-install
make dev-web
```

화면 주소는 `http://localhost:5173`입니다. 관리 API용 개발 토큰 설정은
[web/README.md](web/README.md)를 참고하세요. `service_role` 토큰을 운영 브라우저에 노출하면 안 됩니다.

개발용 PII 암호화 키는 `.dev/master.key`에 보관됩니다. 이 파일을 잃으면 기존 Vault 데이터를
복호화할 수 없습니다. DB를 보존하며 중지하려면 `docker compose stop`을 사용하세요.
`make down`은 DB 볼륨도 삭제합니다.

## 배포 이미지와 패키지

릴리스는 커밋 메시지로 시작합니다. `js/packages/auth-js/package.json`의 버전을 올리고
제목이 정확히 `chore(release): v<버전>`인 커밋을 기본 브랜치에 푸시하면, 워크플로가
`v<버전>` 태그를 만든 뒤 서버 이미지와 JS SDK를 같은 버전으로 함께 발행합니다.

```bash
# js/packages/auth-js/package.json 의 version 을 0.1.0-rc1 로 올린 뒤
git commit -am 'chore(release): v0.1.0-rc1'
git push
```

태그는 릴리스 봇(`dilion-release[bot]`)이 만들며, 그 태그 푸시가 실제 발행 실행을
시작합니다. 따라서 릴리스 하나는 워크플로 실행 두 번으로 나뉩니다 — 커밋 푸시가
태그를 만들고, 태그 푸시가 게이트와 발행을 수행합니다. 발행은 항상 태그에서
실행되므로 npm provenance와 이미지 attestation에도 브랜치가 아닌 태그가 기록됩니다.

`v*` 태그를 직접 푸시해도 같은 릴리스가 실행되며, 이때는 태그 생성 실행만 없습니다.
커밋이 말하는 버전과 package.json 의 버전이 어긋나면 태그도 만들지 않고 아무것도
발행하지 않은 채 실패합니다. 제목이 위 형식과 정확히 일치하지 않는 커밋은 릴리스로
보지 않으며, 릴리스처럼 보이는 경우에만 경고를 남깁니다.

서버 이미지는 GitHub Container Registry에 `linux/amd64`와 `linux/arm64`로 올라갑니다.

```bash
docker run --rm -p 8787:8787 \
  -e DILION_DSN='postgres://dilion:dilion@host:5432/dilion' \
  ghcr.io/dilion-io/dilion:latest
```

마이그레이션은 서버가 시작할 때 직접 적용하므로 별도 단계가 필요하지 않습니다.
`DILION_JWT_SECRET`과 `DILION_MASTER_KEY`를 주지 않으면 부팅마다 임시 키를 만들므로
운영에서는 반드시 지정해야 합니다. 재시작하면 발급한 토큰이 무효가 되고 저장된
개인정보를 복호화할 수 없습니다. 환경 변수 전체 목록은
[cmd/dilion/main.go](cmd/dilion/main.go)의 주석에 있습니다.

같은 이미지를 로컬에서 빌드하려면 `make docker-build`를 사용합니다.

JS SDK는 npm에 발행됩니다.

```bash
npm install @dilion-io/auth-js
```

사전 릴리스(`v0.1.0-rc1` 등)는 npm `next` 태그로만 올라가고 이미지의 `latest`도
갱신하지 않습니다.

## 인증과 SDK

인증 API의 기본 경로는 `/auth/v1`입니다. 이메일·비밀번호, OTP, OAuth/OIDC,
Passkey, MFA, SAML SSO를 구현하며, 외부 제공자를 사용하는 방식은 별도 설정이 필요합니다.
개인정보 API는 `/privacy/v1`, 역할·권한·API 키 관리는 `/iam/v1`에서 제공합니다.

일반 인증에는 `@supabase/supabase-js`를 사용할 수 있습니다.
OPAQUE를 사용하려면 저장소의 [`@dilion-io/auth-js`](js/packages/auth-js/README.md)를 사용하세요.
이 SDK는 Supabase 라이브러리를 의존성으로 가져오고, 기존 클라이언트에 `auth.opaque`를 추가합니다.
기존 `auth.signUp()`이나 `auth.signInWithPassword()`의 동작은 바꾸지 않습니다.
빌드 방법은 [js/README.md](js/README.md)에 있습니다.

### OPAQUE 회원가입과 로그인

OPAQUE는 비밀번호를 서버에 보내지 않고 가입·로그인하는 인증 방식입니다.
서버에 `DILION_AUTH_OPAQUE_MASTER_KEY`를 설정하면 활성화됩니다.
값은 무작위 32바이트를 패딩 없는 base64url로 인코딩한 문자열이어야 합니다.
이 키는 PII 암호화 키와 별개이며, 재시작 후에도 유지하고 모든 서버 복제본에서 동일하게 사용해야 합니다.
명시적으로 끄려면 `DILION_AUTH_OPAQUE_ENABLED=false`를 설정하세요.

```ts
import { createClient } from '@dilion-io/auth-js'

const client = createClient('https://auth.example.com', 'your-anon-key')

const signup = await client.auth.opaque.signUp({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (signup.error) throw signup.error
```

신규 가입에는 기존 로그인 세션이 필요하지 않으며, 서버에 일반 비밀번호 해시를 만들지 않습니다.
가입 응답의 `session`은 `null`입니다. `confirmation_required`가 `true`이면 이메일 확인을 마친 뒤 로그인합니다.

```ts
const login = await client.auth.opaque.signInWithPassword({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (login.error) throw login.error

const { session, key_id, session_key, export_key } = login.data
```

`session_key`는 클라이언트와 서버가 각각 도출하는 공유 키입니다.
서버에서는 `Server.WithOpaqueSessionKey(...)`로 사용할 수 있습니다.
`export_key`는 클라이언트만 보유하며, 두 키 모두 JWT나 SDK 세션 저장소에 넣지 않습니다.
가입 시 받은 `export_key`는 로그인 성공 전까지 데이터 암호화에 사용하면 안 됩니다.

기존 계정의 OPAQUE 등록, CAPTCHA, 키 파생·만료, 비밀번호 복구 제약은
[OPAQUE 문서](docs/opaque.md)를 참고하세요. 이 구현과 암호 라이브러리는 독립 보안 감사를 받지 않았습니다.

## 호환 범위

Supabase Auth의 HTTP API와 `auth.*` 스키마 호환을 목표로 하지만, 모든 API가 완전히 호환되는 것은 아닙니다.

[Parity 테스트](test/parity/README.md)는 실제 GoTrue와 응답을 비교합니다.
GitHub Actions 실행 summary에는 테스트 결과로 생성한 지원표가 표시되며,
각 항목을 **구현됨·부분 호환·미구현·미검증**으로 구분합니다.
의도적인 차이는 [deviations.yaml](test/parity/deviations.yaml)에 기록합니다.
SDK와 최신 Supabase·TypeScript의 호환성은 매일 별도 workflow로 검사합니다.

## 개발

```bash
make test       # 빌드, 정적 검사, DB 없는 테스트
make test-db    # PostgreSQL 통합 테스트와 race 검사
make ci         # DB 테스트, OpenAPI 검사, 웹 빌드·검사
make parity     # GoTrue 비교 테스트
```

테스트는 전용 DB의 데이터를 초기화합니다. 운영 DB를 테스트에 연결하지 마세요.
CI에서는 별도 job으로 `govulncheck`도 실행합니다.

한국어 README가 원본입니다. 수정 후 다음 스크립트로 영어 README를 생성합니다.
Node.js 22 이상과 인증된 Claude Code CLI가 필요합니다.

```bash
node scripts/translate-readme.mjs
```

스크립트는 `claude -p`를 호출합니다. GitHub Actions도 같은 스크립트를 사용합니다.
CLI 설치와 workflow secret 설정은 [README 번역 자동화](docs/readme-translation.md)를 참고하세요.

## 문서

- [사용 사례](docs/use-cases.md): 동의 수집, 개인정보 조회, 삭제 요청의 API 예시와 제약
- [OPAQUE](docs/opaque.md): 서버 설정, 인증 흐름, 키 관리
- [SDK](js/packages/auth-js/README.md): Supabase 클라이언트 연결과 OPAQUE API
- [API 규약](docs/api-conventions.md): API 변경과 OpenAPI 생성 절차
- [설계](project.md) · [개발 계획](PLAN.md): 설계 배경과 구현 계획

`make dev`의 고정 JWT 비밀과 삭제 유예 0일 정책은 로컬 개발용입니다.
운영 환경에서는 TLS, 영속 키, DB 백업, 메일·SMS 제공자와 접근 권한을 별도로 구성해야 합니다.

## 라이선스

[Apache License 2.0](LICENSE)
