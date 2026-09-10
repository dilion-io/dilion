# README 번역 자동화

`README.md`는 한국어 원본이고 `README.en.md`는 `claude -p`로 생성합니다.
Node.js 22 이상과 Claude Code CLI 2.1.263 기준으로 구성했으며, 별도 Node 패키지는 필요 없습니다.

## 로컬 실행

```bash
npm install --global @anthropic-ai/claude-code@2.1.263
node scripts/translate-readme.mjs
node scripts/translate-readme.mjs --check
node --test scripts/translate-readme.test.mjs
```

Claude Code에 로그인하거나 `ANTHROPIC_API_KEY`를 안전하게 환경변수로 제공하세요.
스크립트는 API 키를 파일에 저장하거나 출력하지 않습니다. 원본 README 본문은 Anthropic에
전송되므로 비밀이나 비공개 개인정보를 README에 넣지 마세요. 사용 요금이 발생할 수 있습니다.

기본 모델은 `sonnet`, 호출 예산 상한은 3 USD, 제한 시간은 5분입니다.
`README_TRANSLATION_MODEL`과 `README_TRANSLATION_MAX_BUDGET_USD`로 변경할 수 있습니다.
원본 해시가 일치하면 재호출하지 않으며 `--force`는 같은 원본도 다시 번역합니다.
`--check`는 API를 호출하지 않고 원본 해시와 문서 구조를 확인합니다.

번역은 임시 작업 디렉터리에서 안전 모드·도구 비활성화·MCP 비활성화로 실행됩니다.
README 이외의 저장소 파일이나 `todo.md`를 모델에 전달하지 않습니다. 코드 블록·인라인 코드·
링크 목적지는 번역 전에 자리표시자로 보호하고 번역 후 원문을 복원합니다. 성공한 JSON 응답만
받아 자리표시자 누락·중복, 코드, 링크 목적지, 제목 개수를 검증한 뒤 파일을 원자적으로 교체합니다.
코드 블록 안의 주석은 재현성을 위해 한국어 원본 그대로 유지합니다.
오류·빈 응답·구조 변경·동시 원본 수정이 있으면 기존 영어 파일을 보존합니다.
구조 검사는 번역 의미의 정확성까지 보장하지 않으므로 생성된 diff도 검토하세요.

## GitHub Actions 설정

1. 저장소 **Settings → Secrets and variables → Actions**에 `ANTHROPIC_API_KEY` secret을 등록합니다.
2. 필요하면 `README_TRANSLATION_MODEL` repository variable을 설정합니다.
3. GitHub Actions의 `GITHUB_TOKEN` 쓰기가 허용되어 있어야 합니다. 기본 브랜치 보호 규칙이
   봇의 직접 커밋을 막으면 자동 반영은 실패합니다. 보호 규칙을 우회하는 PAT는 사용하지 않습니다.
   이 경우 `readme-en` artifact를 내려받아 검토 후 별도 PR로 반영하거나 게시 정책을 조정하세요.
4. workflow를 기본 브랜치에 반영합니다. 이후 원본 README·스크립트·workflow의 push 또는
   Actions의 수동 실행으로 번역합니다. 기능 브랜치와 PR에서는 유료 번역을 실행하지 않습니다.

workflow는 로컬과 동일한 스크립트를 실행하고 `README.en.md`만 봇 커밋합니다.
모델 호출 단계에는 Git 자격증명을 저장하지 않으며, 봇 push에는 `GITHUB_TOKEN`을 사용합니다.
영어 파일만 수정하는 봇 커밋은 경로 필터에서 제외되어 번역 루프를 만들지 않습니다.
변경이 없으면 커밋하지 않으며, 원격 변경에는 rebase 후 원본 해시를 다시 확인합니다.
충돌·새 원본 변경·브랜치 보호 오류 시 강제 push하지 않고 실패합니다.
`GITHUB_TOKEN`으로 만든 push는 일반적으로 다른 push workflow를 실행하지 않습니다.

CLI 사용법: [Claude Code 비대화형 실행](https://code.claude.com/docs/en/headless).
