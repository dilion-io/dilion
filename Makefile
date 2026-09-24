SHELL := /bin/bash
# docker compose plugin 우선, 없으면 standalone docker-compose
COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo 'docker compose' || echo 'docker-compose')
PGHOST ?= localhost
PGPORT ?= 55432
DSN_BASE := postgres://dilion:dilion@$(PGHOST):$(PGPORT)
DEV_DSN ?= $(DSN_BASE)/dilion_dev
# Where the sample front-end is served from. A passkey is bound to this origin,
# so it must match what the browser address bar actually shows — override it
# when `npm run dev` runs on another port.
DEV_WEB_ORIGIN ?= http://localhost:5173
MASTER_KEY_FILE := .dev/master.key
OPAQUE_KEY_FILE := .dev/opaque.key
DOCKER_IMAGE ?= ghcr.io/dilion-io/dilion
DOCKER_VERSION ?= dev

.PHONY: help up down ps build vet test test-db openapi openapi-check \
        docker-build \
        web-install web-check dev dev-web e2e-token ci clean \
        parity-up parity-test parity-down parity \
        upstream-spec-sync upstream-spec-check

help: ## 타깃 목록
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

## ---- 환경 (docker compose) ----

up: ## Postgres 기동 (healthy 대기, 테스트 DB 자동 생성)
	$(COMPOSE) up -d --wait db

down: ## 환경 종료 + 볼륨 삭제 (데이터 초기화)
	$(COMPOSE) down -v

ps: ## 컨테이너 상태
	$(COMPOSE) ps

## ---- 백엔드 ----

build: ## go build 전체
	go build ./...

vet: ## go vet 전체
	go vet ./...

test: build vet ## 유닛 테스트 (DB 불필요; DB 테스트는 skip)
	go test ./...

# CI 리포팅용(선택). 경로를 주면 4개 스위트의 `go test -json`(test2json) 스트림을
# 그 파일에 누적한다 — CI 가 robherley/go-test-action 으로 렌더한다.
# 비어 있으면 지금까지처럼 사람이 읽는 기본 출력만 나온다. 게이트 자체는 동일.
GOTEST_JSON ?=
GOTEST_FLAGS := -race -count=1 -timeout 20m $(if $(GOTEST_JSON),-json,)
# tee 로 로그 가시성은 유지하되, pipefail 로 go test 의 실패 코드가 tee 에 삼켜지지
# 않게 한다 (각 레시피 줄에 지역적으로만 건다 — 다른 타깃 영향 없음).
GOTEST_PIPE := $(if $(GOTEST_JSON),| tee -a '$(GOTEST_JSON)',)
GOTEST_RUN := set -o pipefail;

test-db: up build vet ## 전체 테스트 (DB 통합 포함, -race). GOTEST_JSON=<path> 로 test2json 수집
	@$(if $(GOTEST_JSON),mkdir -p "$$(dirname '$(GOTEST_JSON)')" && rm -f '$(GOTEST_JSON)',true)
	$(GOTEST_RUN) DILION_TEST_DB='$(DSN_BASE)/dilion_test_a' go test $(GOTEST_FLAGS) \
		./internal/store/... ./internal/kmslocal/... ./internal/devmail/... $(GOTEST_PIPE)
	$(GOTEST_RUN) DILION_TEST_DB='$(DSN_BASE)/dilion_test_b' go test $(GOTEST_FLAGS) ./internal/auth/... $(GOTEST_PIPE)
	$(GOTEST_RUN) DILION_TEST_DB=1 DILION_TEST_DB_DSN='$(DSN_BASE)/dilion_test_c' go test $(GOTEST_FLAGS) ./internal/privacy/... $(GOTEST_PIPE)
	$(GOTEST_RUN) DILION_TEST_DB=1 go test $(GOTEST_FLAGS) ./internal/api/... ./internal/iam/... ./internal/audit/... $(GOTEST_PIPE)
	$(GOTEST_RUN) DILION_TEST_DB=1 DILION_TEST_DB_DSN_H1='$(DSN_BASE)/dilion_test_h1' \
		DILION_TEST_DB_DSN_H2='$(DSN_BASE)/dilion_test_h2' go test $(GOTEST_FLAGS) . $(GOTEST_PIPE)

openapi: ## web/openapi.yaml 재생성 (huma → OpenAPI 3.1)
	go run ./cmd/openapi

openapi-check: openapi ## 스펙-커밋 불일치 검출 (CI용; git 필요)
	git diff --exit-code web/openapi.yaml

## ---- 컨테이너 이미지 ----

# 릴리스 워크플로(.github/workflows/release.yml)가 굽는 것과 같은 Dockerfile 이다.
# CI 는 멀티아키(amd64+arm64)로 굽고 여기서는 호스트 아키텍처만 굽는다 — 그 외에는
# 동일한 빌드다. VERSION 라벨은 CI 에서 태그 값으로, 로컬에서는 dev 로 남는다.
docker-build: ## 서버 이미지 빌드 (DOCKER_VERSION / DOCKER_IMAGE 로 태그 지정)
	docker build \
	  --build-arg VERSION='$(DOCKER_VERSION)' \
	  --build-arg REVISION='$(shell git rev-parse HEAD 2>/dev/null || echo unknown)' \
	  --build-arg CREATED='$(shell date -u +%Y-%m-%dT%H:%M:%SZ)' \
	  -t '$(DOCKER_IMAGE):$(DOCKER_VERSION)' .

## ---- 프론트엔드 ----

web-install: ## npm ci
	cd web && npm ci

web-check: ## codegen + typecheck/build + lint
	cd web && npm run gen:api && npm run build && npx oxlint

## ---- 개발 서버 ----

$(MASTER_KEY_FILE):
	@mkdir -p .dev && head -c32 /dev/urandom | base64 > $@ && echo "generated $@"

# OPAQUE has its own key, separate from the PII master key (docs/opaque.md).
# Unpadded base64url is the form the configuration accepts.
$(OPAQUE_KEY_FILE):
	@mkdir -p .dev && head -c32 /dev/urandom | basenc --base64url | tr -d '=' > $@ \
		&& echo "generated $@"

# Passkeys need a relying party. The browser reaches the app through the Vite
# proxy at DEV_WEB_ORIGIN, and direct calls to :8787 also happen, so both are
# allowed; the RP id is the registrable domain they share. An origin that is not
# on this list fails registration with `webauthn_verification_failed`, which is
# WebAuthn working as intended rather than a misconfiguration to route around.
dev: up $(MASTER_KEY_FILE) $(OPAQUE_KEY_FILE) ## API 서버 기동 :8787 (migrations 자동 적용, OPAQUE·passkey 켜짐)
	DILION_DSN='$(DEV_DSN)' \
	DILION_JWT_SECRET='devsecret-e2e' \
	DILION_MASTER_KEY="$$(cat $(MASTER_KEY_FILE))" \
	DILION_AUTH_OPAQUE_MASTER_KEY="$$(cat $(OPAQUE_KEY_FILE))" \
	DILION_AUTH_PASSKEY_ENABLED='true' \
	DILION_AUTH_WEBAUTHN_RP_ID='localhost' \
	DILION_AUTH_WEBAUTHN_RP_ORIGINS='$(DEV_WEB_ORIGIN),http://localhost:8787' \
	DILION_ADDR=':8787' \
	DILION_POLICY_FILE='dev/policy.dev.yaml' \
	DILION_DEV_NO_ADMIN_MFA='true' \
	go run ./cmd/dilion

dev-web: ## 샘플 프론트 기동 :5173 (proxy → :8787)
	cd web && npm run dev

e2e-token: ## dev service_role JWT 발급 (web/.env.local 갱신용)
	@node -e "const c=require('crypto');const b=o=>Buffer.from(JSON.stringify(o)).toString('base64url');const h=b({alg:'HS256',typ:'JWT'});const p=b({sub:'00000000-0000-0000-0000-000000000000',role:'service_role',aud:'authenticated',iat:Math.floor(Date.now()/1e3),exp:Math.floor(Date.now()/1e3)+604800});const s=c.createHmac('sha256','devsecret-e2e').update(h+'.'+p).digest('base64url');console.log(h+'.'+p+'.'+s)"

## ---- CI 진입점 ----

ci: test-db openapi-check web-check ## CI가 실행하는 전체 게이트

# 기본은 flagged 프로파일(OAuth 서버/passkeys/manual-linking 활성) — 51/69 op 검증.
# 기능 플래그 없는 기본 프로파일만 원하면: make parity PARITY_FLAGS=0
PARITY_FLAGS ?= 1
PARITY_BASE_FILE := -f test/parity/compose.parity.yml
PARITY_FLAGS_FILE := $(if $(filter-out 0,$(PARITY_FLAGS)),-f test/parity/compose.parity.flags.yml,)
PARITY := $(COMPOSE) $(PARITY_BASE_FILE) $(PARITY_FLAGS_FILE)
PARITY_DILION_URL ?= http://localhost:8787/auth/v1
PARITY_GOTRUE_URL ?= http://localhost:9999
PARITY_JWT_SECRET ?= parity-super-secret-shared-jwt-key-0123456789
# CI 리포팅용(선택). 경로를 주면 하네스가 커버리지/KNOWN/FAIL 요약을 마크다운으로
# 그 파일에 쓴다 (CI 는 $GITHUB_STEP_SUMMARY 에 그대로 붙인다). 비어 있으면 미작성.
#   예: PARITY_SUMMARY_FILE=/tmp/parity.md make parity-test
PARITY_SUMMARY_FILE ?=

parity-up: ## parity 스택 기동 (postgres + upstream gotrue + dilion)
	$(PARITY) up -d --build
	@echo "waiting for gotrue…";  until curl -fs $(PARITY_GOTRUE_URL)/health >/dev/null; do sleep 1; done
	@echo "waiting for dilion…";  until curl -fs $(PARITY_DILION_URL)/health >/dev/null; do sleep 1; done
	@echo "parity stack up: dilion :8787  gotrue :9999 (flags=$(PARITY_FLAGS))"

parity-test: ## upstream supabase/auth 대비 차등 + 커버리지 스위트 (PARITY_SUMMARY_FILE=<path> 로 md 요약)
	PARITY_DILION_URL=$(PARITY_DILION_URL) \
	PARITY_GOTRUE_URL=$(PARITY_GOTRUE_URL) \
	PARITY_JWT_SECRET=$(PARITY_JWT_SECRET) \
	PARITY_FLAGS=$(PARITY_FLAGS) \
	PARITY_SUMMARY_FILE='$(PARITY_SUMMARY_FILE)' \
	go test -tags parity ./test/parity/ -run TestParity -v

parity-down: ## parity 스택 종료 + 볼륨 삭제
	$(PARITY) down -v

parity: parity-up ## 스택 기동 → 테스트 → 종료 (teardown 보장)
	@set -e; trap '$(PARITY) down -v' EXIT; $(MAKE) parity-test

## ---- upstream 스펙 (conformance oracle) ----

# internal/auth/upstreamspec/openapi.yaml 은 upstream supabase/auth 의 openapi.yaml
# 을 그대로(verbatim) 벤더링한 것이다. 런타임 코드는 이 패키지를 import 하지 않으며,
# 생성된 타입은 오직 internal/auth/upstream_conformance_test.go 의 대조군으로만 쓴다.
# 자세한 배경은 internal/auth/upstreamspec/doc.go 와 SOURCE.md 참고.
UPSTREAM_SPEC_REPO ?= supabase/auth
UPSTREAM_SPEC_REF ?= master
UPSTREAM_SPEC_URL := https://raw.githubusercontent.com/$(UPSTREAM_SPEC_REPO)/$(UPSTREAM_SPEC_REF)/openapi.yaml
UPSTREAM_SPEC_API := https://api.github.com/repos/$(UPSTREAM_SPEC_REPO)/commits?path=openapi.yaml&sha=$(UPSTREAM_SPEC_REF)&per_page=1
UPSTREAM_SPEC_DIR := internal/auth/upstreamspec
UPSTREAM_SPEC := $(UPSTREAM_SPEC_DIR)/openapi.yaml
GOBIN_DIR := $(shell go env GOPATH)/bin

upstream-spec-sync: ## upstream openapi.yaml 재수집 + 타입 재생성 (SOURCE.md 수동 갱신 필요)
	curl -fsSL '$(UPSTREAM_SPEC_URL)' -o $(UPSTREAM_SPEC)
	PATH="$$PATH:$(GOBIN_DIR)" go generate ./$(UPSTREAM_SPEC_DIR)/
	@echo
	@echo "벤더링한 커밋 (SOURCE.md 에 기록할 것):"
	@curl -fsSL '$(UPSTREAM_SPEC_API)' | grep -m1 '"sha"' || true
	@echo "sha256: $$(sha256sum $(UPSTREAM_SPEC) | cut -d' ' -f1)"
	@echo "fetched: $$(date -u +%Y-%m-%d)"
	@git --no-pager diff --stat $(UPSTREAM_SPEC_DIR) || true

upstream-spec-check: ## 벤더링 스펙 ↔ upstream master 드리프트 검출 (CI 경고용, 네트워크 필요)
	@tmp=$$(mktemp); trap 'rm -f $$tmp' EXIT; \
	curl -fsSL '$(UPSTREAM_SPEC_URL)' -o $$tmp; \
	if diff -q $(UPSTREAM_SPEC) $$tmp >/dev/null; then \
		echo "upstream-spec-check: OK — $(UPSTREAM_SPEC) 는 $(UPSTREAM_SPEC_REPO)@$(UPSTREAM_SPEC_REF) 와 동일"; \
	else \
		echo "upstream-spec-check: DRIFT — upstream openapi.yaml 이 변경됨"; \
		echo "  vendored: $$(wc -l < $(UPSTREAM_SPEC)) lines, sha256 $$(sha256sum $(UPSTREAM_SPEC) | cut -d' ' -f1)"; \
		echo "  upstream: $$(wc -l < $$tmp) lines, sha256 $$(sha256sum $$tmp | cut -d' ' -f1)"; \
		echo "  --- diffstat ---"; \
		diff -u $(UPSTREAM_SPEC) $$tmp | diffstat 2>/dev/null || diff -u $(UPSTREAM_SPEC) $$tmp | \
			awk '/^\+[^+]/{a++} /^-[^-]/{d++} END{printf "  +%d / -%d lines\n", a+0, d+0}'; \
		echo "  --- 변경된 스키마/경로 (첫 60줄) ---"; \
		diff -u $(UPSTREAM_SPEC) $$tmp | grep -E '^[-+][^-+]' | head -60; \
		echo; \
		echo "  대응: make upstream-spec-sync 후 SOURCE.md 갱신, go test ./internal/auth/ -run TestUpstreamSpecConformance"; \
		exit 1; \
	fi

clean: ## 빌드 산출물 정리
	rm -rf web/dist
