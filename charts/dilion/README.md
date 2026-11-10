# dilion Helm chart

Dilion 서버(`ghcr.io/dilion-io/dilion`)를 Kubernetes에 배포합니다. 마이그레이션은
서버가 시작할 때 직접 적용하므로 Job이나 init container는 없습니다.

## 설치

DB 연결 문자열과, 재시작 후에도 유지돼야 하는 두 키가 필요합니다. 없으면 차트가
렌더링을 거부합니다 — 서버는 키가 없을 때 pod마다 임시 키를 만들기 때문에, 한 pod가
발급한 토큰과 암호화한 개인정보를 다른 pod가 읽지 못합니다.

```bash
kubectl create secret generic dilion \
  --from-literal=DILION_DSN='postgres://dilion:pass@postgres:5432/dilion?sslmode=require' \
  --from-literal=DILION_MASTER_KEY="$(head -c32 /dev/urandom | base64)" \
  --from-literal=DILION_JWT_SECRET="$(head -c48 /dev/urandom | base64)"

helm install dilion ./charts/dilion \
  --set secrets.existingSecret=dilion \
  --set config.DILION_TRUSTED_PROXIES=10.0.0.0/8 \
  --set config.DILION_AUTH_SITE_URL=https://app.example.com
```

`DILION_MASTER_KEY`는 저장된 개인정보의 KEK입니다. 잃어버리면 그 데이터를 복호화할
수 없으므로 Secret과 별도로 백업하세요. ES256 서명을 쓰려면 `DILION_JWT_SECRET` 대신
(또는 함께) `DILION_AUTH_JWT_KEYS`에 JWK set을 넣습니다.

기존 Secret의 **모든 키가 환경 변수로** 주입되므로 키 이름은 환경 변수 이름 그대로여야
합니다. Secret을 차트가 만들게 하려면 `secrets.dsn`, `secrets.masterKey`,
`secrets.jwtSecret`(또는 `secrets.jwtKeys`)을 values로 줍니다. 이 경우 값이 Helm
release 기록에 남는다는 점에 유의하세요.

## 설정

| 값 | 용도 |
| --- | --- |
| `config` | 민감하지 않은 환경 변수(`DILION_*`, `DILION_AUTH_*`). 전체 목록은 [cmd/dilion/main.go](../../cmd/dilion/main.go)와 [internal/auth/conf.go](../../internal/auth/conf.go) |
| `secrets.extra` | 민감한 추가 환경 변수(Twilio 토큰, CAPTCHA secret 등) |
| `policy` / `piiFields` | `DILION_POLICY_FILE` / `DILION_PII_FIELDS_FILE`로 마운트되는 YAML 문자열 |
| `extraEnv`, `extraEnvFrom` | `valueFrom` 등 Kubernetes 형식의 env |

`DILION_ADDR`, `DILION_METRICS_ADDR`, 파일 경로 변수는 포트·마운트와 어긋나지 않도록
차트가 직접 설정하며 `config`로 덮어쓸 수 없습니다. ConfigMap이나 차트가 만든 Secret이
바뀌면 pod가 다시 뜹니다.

Ingress나 로드밸런서 뒤에서는 `config.DILION_TRUSTED_PROXIES`를 반드시 지정하세요.
지정하지 않으면 모든 클라이언트가 프록시 주소 하나를 공유하므로 rate limit도 함께
받습니다.

모든 replica가 privacy worker도 실행합니다. Postgres 잠금으로 서로 조율하므로 replica를
늘려도 안전하지만, replica마다 polling 부하가 더해집니다(`DILION_PRIVACY_POLL_INTERVAL`).

## 메트릭

`metrics.enabled`(기본 켜짐)이면 서버가 `:9090/metrics`를 API와 **다른 listener**로
열고, 차트는 이를 별도 ClusterIP Service `<release>-metrics`로 노출합니다. API Service를
LoadBalancer로 바꾸거나 Ingress를 켜도 메트릭은 클러스터 밖으로 나가지 않습니다.

Prometheus Operator를 쓴다면 ServiceMonitor를 켭니다. `labels`는 Prometheus의
`serviceMonitorSelector`와 맞아야 합니다.

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack
```

| 메트릭 | 종류 | 레이블 |
| --- | --- | --- |
| `dilion_http_requests_total` | counter | `route`, `method`, `code` |
| `dilion_http_request_duration_seconds` | histogram | `route`, `method` |
| `dilion_http_requests_in_flight` | gauge | |
| `dilion_db_pool_max_connections` | gauge | `instance_id` |
| `dilion_db_pool_connections` | gauge | `instance_id`, `state` (acquired, idle, constructing) |
| `dilion_db_pool_acquires_total`, `_empty_acquires_total`, `_canceled_acquires_total` | counter | `instance_id` |
| `dilion_db_pool_acquire_wait_seconds_total` | counter | `instance_id` |
| `dilion_db_pool_scrape_error` | gauge | |
| `dilion_privacy_worker_runs_total` | counter | `worker`, `result` (ok, error) |
| `dilion_privacy_worker_run_duration_seconds` | histogram | `worker` |
| `dilion_privacy_deliveries_total` | counter | `outcome` (completed, retry, dead) |
| `dilion_build_info` | gauge | `version` |

Go runtime(`go_*`)과 프로세스(`process_*`) 메트릭도 함께 나옵니다.

- `route`는 URL 경로가 아니라 라우트 패턴(`/auth/v1/admin/users/*`)이므로 사용자 ID나
  토큰이 시계열이 되지 않습니다. 어느 라우트에도 맞지 않은 요청은 `unmatched` 하나로
  모입니다.
- 요청·worker 메트릭에는 instance 레이블이 없습니다. 워크스페이스마다 instance를 두는
  배포에서는 시계열 수가 instance 수에 비례해 늘어나기 때문입니다. pool 메트릭만
  instance별이며, 레이블 이름은 Prometheus가 scrape 대상에 쓰는 `instance`와 겹치지
  않도록 `instance_id`입니다.
- `dilion_privacy_deliveries_total{outcome="dead"}`가 늘었다면 webhook/connector 전달이
  재시도를 모두 소진한 것이므로 사람이 확인해야 합니다.

예시 알림 규칙:

```yaml
- alert: DilionDeliveryDeadLettered
  expr: increase(dilion_privacy_deliveries_total{outcome="dead"}[15m]) > 0
- alert: DilionPrivacyWorkerFailing
  expr: sum by (worker) (rate(dilion_privacy_worker_runs_total{result="error"}[10m])) > 0
  for: 15m
- alert: DilionDBPoolSaturated
  expr: |
    dilion_db_pool_connections{state="acquired"}
      / ignoring(state) dilion_db_pool_max_connections > 0.9
  for: 10m
```

## 검증

```bash
make helm-lint
```
