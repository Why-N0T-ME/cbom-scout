# cbom-scout — Claude Code 작업 안내

암호자산 자동 식별 도구. 소스코드·설정·인증서·TLS 엔드포인트를 스캔해 CycloneDX 1.6 CBOM 을 만들고
NIST IR 8547 기준 정책으로 PQC 전환 대상을 판정한다. 사용자 대상 문서·주석·메시지는 **한국어**로 쓴다.

## 명령

```bash
python -m pip install -e ".[dev]"     # 개발 설치 (Python 3.10+)
python -m pytest -q                   # 전체 테스트 — 커밋 전 반드시 통과
cbom-scout scan examples/demo-app -v  # 데모 실행 (취약 예제라 종료 코드 1이 정상)
```

## 구조 (src/cbom_scout/)

- `catalog.py` 알고리즘 지식 베이스(상태·primitive·양자 보안 수준). 판정 기준을 바꿀 땐 여기와 정책 파일만 고친다.
- `inventory.py` 발견 결과 → CycloneDX 구성요소, `scanners/` 코드·인증서·TLS 스캐너
- `cbom.py` 직렬화·병합, `policy.py` 정책 평가, `report.py` 리포트, `cli.py` 진입점
- `policies/*.json` 내장 정책, `tests/schemas/` CycloneDX 공식 스키마(테스트에서 CBOM 검증)

## 규칙

- **판정 기준은 데이터로 둔다.** 알고리즘 상태는 `catalog.py`, 조치는 정책 JSON. 스캐너 코드에 판정을 하드코딩하지 않는다 (암호 민첩성).
- **키·비밀 값은 절대 CBOM·로그·리포트에 쓰지 않는다.** 위치와 메타데이터만 기록한다.
- 출력 CBOM 은 CycloneDX 1.6 스키마를 통과해야 한다 (`tests/test_policy_cli.py::test_cbom_schema_valid`).
- 새 탐지 규칙에는 오탐 테스트를 함께 넣는다. 오탐은 미탐만큼 도입을 막는다.
- Windows 와 Linux 둘 다에서 돌아야 한다. 경로는 `os.path` 로 다루고, CBOM 의 위치는 `/` 구분 상대경로로 남긴다.
- 의도적으로 취약한 파일은 `examples/`, `tests/` 에만 둔다 (`.cbomignore` 가 자체 스캔에서 제외).

## Git

- `main` 에 직접 커밋하지 않는다. `feature/<짧은-이름>` 브랜치 → PR. **병합은 사용자가 한다.**
- 커밋 메시지는 한국어, `feat:` `fix:` `test:` `docs:` `ci:` 접두어.
- 릴리스는 `docs/releases/vX.Y.Z.md` 작성 후 Actions → Release 워크플로로 만든다.

## 기능 개발은 파이프라인으로

사용자가 기능 개발이나 개선을 요청하면 [docs/pipeline.md](docs/pipeline.md) 를 따른다.
역할: PM(`pm`) → 개발(메인 세션) → 테스터(`tester`) → 보고(`reporter`). 정의는 `.claude/agents/`.
작은 수정(오타, 한 줄 버그)은 파이프라인 없이 바로 고쳐도 된다.
