SHELL := /bin/bash
# docker compose plugin 우선, 없으면 standalone docker-compose
COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo 'docker compose' || echo 'docker-compose')
PGHOST ?= localhost
PGPORT ?= 55432
DSN_BASE := postgres://dilion:dilion@$(PGHOST):$(PGPORT)
DEV_DSN ?= $(DSN_BASE)/dilion_dev
MASTER_KEY_FILE := .dev/master.key

.PHONY: help up down ps build vet test test-db openapi openapi-check \
        web-install web-check dev dev-web e2e-token ci clean \
        parity-up parity-test parity-down parity

help: ## 타깃 목록
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

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

test-db: up build vet ## 전체 테스트 (DB 통합 포함, -race)
	DILION_TEST_DB='$(DSN_BASE)/dilion_test_a' go test -race -count=1 \
		./internal/store/... ./internal/kmslocal/... ./internal/devmail/...
	DILION_TEST_DB='$(DSN_BASE)/dilion_test_b' go test -race -count=1 ./internal/auth/...
	DILION_TEST_DB=1 DILION_TEST_DB_DSN='$(DSN_BASE)/dilion_test_c' go test -race -count=1 ./internal/privacy/...
	DILION_TEST_DB=1 go test -race -count=1 ./internal/api/... ./internal/iam/... ./internal/audit/...

openapi: ## web/openapi.yaml 재생성 (huma → OpenAPI 3.1)
	go run ./cmd/openapi

openapi-check: openapi ## 스펙-커밋 불일치 검출 (CI용; git 필요)
	git diff --exit-code web/openapi.yaml

## ---- 프론트엔드 ----

web-install: ## npm ci
	cd web && npm ci

web-check: ## codegen + typecheck/build + lint
	cd web && npm run gen:api && npm run build && npx oxlint

## ---- 개발 서버 ----

$(MASTER_KEY_FILE):
	@mkdir -p .dev && head -c32 /dev/urandom | base64 > $@ && echo "generated $@"

dev: up $(MASTER_KEY_FILE) ## API 서버 기동 :8787 (migrations 자동 적용)
	DILION_DSN='$(DEV_DSN)' \
	DILION_JWT_SECRET='devsecret-e2e' \
	DILION_MASTER_KEY="$$(cat $(MASTER_KEY_FILE))" \
	DILION_ADDR=':8787' \
	DILION_POLICY_FILE='dev/policy.dev.yaml' \
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

parity-up: ## parity 스택 기동 (postgres + upstream gotrue + dilion)
	$(PARITY) up -d --build
	@echo "waiting for gotrue…";  until curl -fs $(PARITY_GOTRUE_URL)/health >/dev/null; do sleep 1; done
	@echo "waiting for dilion…";  until curl -fs $(PARITY_DILION_URL)/health >/dev/null; do sleep 1; done
	@echo "parity stack up: dilion :8787  gotrue :9999 (flags=$(PARITY_FLAGS))"

parity-test: ## upstream supabase/auth 대비 차등 + 커버리지 스위트
	PARITY_DILION_URL=$(PARITY_DILION_URL) \
	PARITY_GOTRUE_URL=$(PARITY_GOTRUE_URL) \
	PARITY_JWT_SECRET=$(PARITY_JWT_SECRET) \
	PARITY_FLAGS=$(PARITY_FLAGS) \
	go test -tags parity ./test/parity/ -run TestParity -v

parity-down: ## parity 스택 종료 + 볼륨 삭제
	$(PARITY) down -v

parity: parity-up ## 스택 기동 → 테스트 → 종료 (teardown 보장)
	@set -e; trap '$(PARITY) down -v' EXIT; $(MAKE) parity-test

clean: ## 빌드 산출물 정리
	rm -rf web/dist
