# 컴플라이언스 정책 검토 자동화

`internal/privacy/builtin_policies.yaml`의 보관 기간·삭제 설정·동의 재확인 주기와 법적 근거를
`claude -p`가 웹 검색으로 현행 법령과 대조합니다. 법령이 바뀌었거나 값이 틀렸으면 수정 PR을,
수정 없이 사람이 확인해야 할 항목만 있으면 이슈를 엽니다. 결과는 법률 자문이 아닙니다.
PR을 병합하기 전에 보고서에 인용된 원문을 직접 확인하세요.

## 로컬 실행

```bash
npm install --global @anthropic-ai/claude-code@2.1.263
node scripts/review-compliance-policies.mjs --out /tmp/compliance-review
node --test scripts/review-compliance-policies.test.mjs
go run ./scripts/check-compliance-policies
```

Claude Code 로그인 또는 `ANTHROPIC_API_KEY`가 필요하며 사용 요금이 발생합니다.
기본 모델은 `opus`, 호출 예산 상한은 10 USD, 제한 시간은 30분입니다.
`COMPLIANCE_REVIEW_MODEL`과 `COMPLIANCE_REVIEW_MAX_BUDGET_USD`로 변경할 수 있습니다.
제안이 채택되면 정책 파일을 그 자리에서 수정하므로 `git diff`로 확인할 수 있습니다.
출력 디렉터리에는 `report.md`(사람용 보고서)와 `review.json`(요약·해시)이 남습니다.

## 안전 장치

- Claude는 임시 디렉터리에서 안전 모드로 실행되며 `WebSearch`·`WebFetch` 외의 도구는 쓸 수 없습니다.
  저장소 파일은 정책 YAML 본문만 전달합니다.
- 웹 페이지와 YAML은 신뢰하지 않는 데이터로 취급하도록 지시하고, 응답은 JSON schema로 받습니다.
- 모든 항목에 https 출처가 있어야 합니다. 수정은 `개정됨`·`오류` 항목만 제안할 수 있고,
  파일에서 정확히 한 번 일치하는 문자열 치환만 허용합니다. 하나라도 어긋나면 아무것도 쓰지 않습니다.
- 수정된 파일은 `go run ./scripts/check-compliance-policies`로 서버 시작 시와 같은 정책 로더 검증을
  통과해야 하며, 실패하면 원래 파일로 되돌립니다.
- `go test ./internal/privacy` 결과는 보고서에만 적습니다. 테스트는 법적 값 대신 고정된 테스트 정책
  (`internal/privacy/policy_fixture_test.go`)을 쓰므로 값 변경만으로는 실패하지 않습니다. 실패는
  `TestBuiltinPoliciesAreValid` 같은 구조 검사(정책 누락, 법적 근거 누락 등)에 걸렸다는 뜻입니다.
- 보고서의 `@멘션`은 무력화해 PR·이슈 본문이 임의의 사용자에게 알림을 보내지 않게 합니다.

## GitHub Actions 설정

1. **Settings → Secrets and variables → Actions**에 `ANTHROPIC_API_KEY` secret 또는
   `ANTHROPIC_FEDERATION_JSON_TEMPLATE` secret을 등록합니다. README 번역과 같은 자격증명입니다.
2. 필요하면 `COMPLIANCE_REVIEW_MODEL`, `COMPLIANCE_REVIEW_MAX_BUDGET_USD` repository variable을 설정합니다.
3. **Settings → Actions → General**에서 *Allow GitHub Actions to create and approve pull requests*를
   켭니다. 꺼져 있으면 PR 생성 단계가 실패합니다.

workflow는 매월 1일, 기본 브랜치의 정책 파일·스크립트·workflow가 바뀔 때, 수동 실행 시 동작합니다.
검토 job은 읽기 권한과 Claude 자격증명만 갖고, PR·이슈를 여는 job은 Claude를 실행하지 않습니다.
게시 job은 검토 대상 파일의 해시가 기본 브랜치와 다르면 실패하고, 산출물 해시도 다시 확인합니다.

수정 PR은 `automation/compliance-policy-review` 브랜치 하나를 재사용해 매번 갱신합니다.
그 브랜치에 사람이 커밋을 올렸으면 강제 push하지 않고 새 보고서를 PR 댓글로만 남깁니다.
`GITHUB_TOKEN`으로 만든 PR에는 CI가 자동 실행되지 않습니다. 테스트 갱신 커밋을 push하거나
PR을 닫았다 다시 열어 CI를 실행하세요. 모든 실행 결과는 job summary와 `compliance-review`
artifact에도 남습니다.

CLI 사용법: [Claude Code 비대화형 실행](https://code.claude.com/docs/en/headless).
