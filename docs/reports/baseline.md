# 보고서: 기준선(baseline) 비교

- 작성일: 2026-11-26
- 명세: `docs/specs/baseline.md` (확인 필요 1~8 모두 권장안으로 승인)
- 브랜치: `feature/baseline` → [PR #1](https://github.com/Why-N0T-ME/cbom-scout/pull/1)
- 관련: [PR #2](https://github.com/Why-N0T-ME/cbom-scout/pull/2) (`fix/console-encoding`)
- 검증: `docs/test-reports/baseline-1.md`, `baseline-2.md`, `baseline-3.md`

## 1. 한 줄 결론

`scan`·`check` 에 `--baseline FILE` 이 생겼다. 이 옵션을 주면 기준 CBOM 대비 **새로 생긴 위반이 있을 때만** PR 이 실패한다. 3회차 검증을 통과했고(완료 기준 36/36, 테스트 153개 통과) PR #1 CI 도 모두 녹색이다. **할 일: PR #1 과 PR #2 를 검토하고 병합.**

## 2. 배경

레거시 MD5·RSA 가 이미 있는 저장소에 cbom-scout 를 PR CI 로 붙이면, PR 이 아무것도 바꾸지 않아도 기존 위반 때문에 매번 종료 코드 1로 실패했다. 그래서 `--fail-on never` 로 꺼 버리게 되고, PR 이 새로 들여오는 취약 암호도 막지 못했다. 이번 기능은 기준 CBOM(예: `main` 스캔 결과)과 비교해 신규 위반만 실패로 판정한다.

## 3. 변경 요약

### 사용법

```bash
# main 에서 기준선 생성
cbom-scout scan . -o baseline.json --fail-on never

# PR 에서: 기준선 대비 신규 위반만 종료 코드 1
cbom-scout scan . --baseline baseline.json --markdown report.md -v
# 기준선 대비: 신규 실패 1 / 신규 경고 0 / 신규 참고 0 · 기존 4건 · 해결 1건 → 실패
```

GitHub Action 입력은 `baseline: baseline.json` 이다. 기본값 `""` 이면 기존 명령줄과 같다. 기준선 파일은 사용자 워크플로가 준비한다. 예시는 `examples/workflows/cbom-scan.yml` 에 있다.

### 판정 규칙

- 같은 발견인지는 **(자산, 파일 경로)** 로 판단한다. 줄 번호는 보지 않는다. 코드가 위아래로 움직여도, 같은 파일에 같은 알고리즘이 한 번 더 늘어도 "기존"이다.
- 줄 번호가 식별자에 들어 있던 비밀키·설정 파일 TLS 도 줄이 바뀌면 기존으로 본다. TLS 엔드포인트는 `host:port` 의 포트까지 구분한다.
- 정책이 엄격해지거나 `fail_after` 날짜가 지나도 기존 위반은 PR 을 실패시키지 않는다. 리포트에는 현재 판정으로 계속 나온다.
- 파일 이동·이름 변경은 신규로 본다. 이전 위치는 "해결됨"으로 나온다.
- 다른 도구가 만든 CycloneDX 기준선도 받는다. 알고리즘 이름은 대소문자를 무시하고 `bom-ref` 가 없어도 된다. 경로의 `\`·앞 `./` 는 정규화하고, 대소문자는 구분한다.

### 출력

- 콘솔: 기존 요약 다음 줄에 `기준선 대비: …` 줄이 붙는다. `-v` 에서는 항목별로 `[신규]`·`[기존]` 이 표시된다.
- 마크다운·HTML 리포트: 신규 위반, 기존 위반(접힘), 해결됨 순서.
- GitHub 주석: 신규 위치에만 단다.
- 출력 CBOM: 위반 구성요소에 `cbom-scout:baseline` = `new`/`existing` 를 붙인다. CycloneDX 1.6 스키마를 통과한다.
- 기준선 파일이 없거나, 디렉터리이거나, 깨졌거나, CycloneDX 가 아니면 종료 코드 2 로 멈춘다. 한국어 메시지를 내고 트레이스백은 없으며 출력 파일을 만들지 않는다. 정책 위반(종료 코드 1)과 구분된다.
- `--baseline` 이 없으면 종료 코드, 콘솔, 리포트, CBOM 모두 이전과 같다.

### 바뀐 파일

`git diff --stat main...feature/baseline` 기준 14개 파일, +2193/-38.

- 새 모듈 `src/cbom_scout/baseline.py` (289줄)
- 수정: `cli.py`, `policy.py`, `report.py`, `action.yml`, `README.md`, `examples/workflows/cbom-scan.yml`
- 테스트: `tests/test_baseline.py`, `tests/acceptance/test_baseline.py`

판정 기준(`catalog.py`, 정책 JSON)은 바꾸지 않았다.

## 4. 검증 결과

| 회차 | 판정 | 전체 테스트 | 완료 기준 | 결함 |
|---|---|---|---|---|
| 1 | 불통과 | 118 통과 / 6 실패 | 35/36 (AC-32 부분) | D1 `check` 에서 pass 구성요소에 옛 `baseline` 속성이 남음 (보통), D2 `--baseline` 없는 `check` 에도 같은 문제 (낮음), D3 구성요소 형식이 잘못된 기준선에서 트레이스백·종료 코드 1 (보통) |
| 2 | 불통과 | 134 통과 / 5 실패 | 36/36 | D1·D2 수정, D3 부분 수정. 새 결함: D4 `bom-ref` 없는 외부 기준선에서 트레이스백 (높음), D5 문자열 아닌 속성 값에서 트레이스백 (보통), D6 bom-ref 가 중복되면 해결 건수가 부풀려짐 (낮음) |
| 3 | **통과** | **153 통과 / 0 실패** | **36/36** | 이번 기능의 결함 없음 |

- 수정 루프: **2회** (`2fa448b` → D1~D3, `89530fc` → D4~D6)
- 남은 결함: **0건**
- 비밀 값: 키 본문이 CBOM·리포트·stderr·stdout 어디에도 나오지 않음을 확인했다 (AC-13).
- Windows 경로: 백슬래시·한글·공백 경로, UTF-8 BOM 기준선, CP949 기준선(종료 코드 2)을 확인했다.
- CI (PR #1): `test (3.10)`, `test (3.12)`, `test (3.13)`, `action-demo` 모두 통과.
- 메인 세션의 추가 검증: 잘못된 형식의 기준선 1,500개로 `scan`·`check` 양쪽을 무작위 퍼징했고 예외는 0건이었다. 이 결과는 테스트 보고서에 없으며 메인 세션이 보고한 내용이다.
- 테스터 환경의 제약: Windows 에서 `cbom-scout.exe` 를 직접 실행하면 권한 거부가 나서, 같은 진입점을 `python -m cbom_scout.cli` 로 실행해 검증했다.

### PR #2 와의 관계

- PR #2 는 기존 버그를 고친다. Windows 의 비 UTF-8 콘솔에서 한국어 출력이 `UnicodeEncodeError` 로 죽던 문제다. CI 는 녹색이다.
- 두 PR 모두 커밋 `0bd0706` "fix: Windows 에서 CBOM 을 cp1252 로 읽어 실패하던 테스트 수정"을 포함한다. 먼저 병합한 쪽이 이 커밋을 가져간다. 나중 PR 이 충돌하는지는 확인하지 못했다.

## 5. 남은 위험과 다음 단계

알려진 한계 (명세 범위 밖이거나 명세에 기준이 없는 것):

1. **외부 도구 기준선의 `a.py:3` 형식.** 루트 파일 위치를 `host:port` 로 보고 줄 번호를 떼지 않는다. 그래서 현재 `a.py` 와 다른 위치로 판정되어 신규가 된다. `app/a.py:3` 처럼 `/` 가 있는 경로는 영향이 없다.
2. **파일 이동·이름 변경은 신규.** 대규모 디렉터리 정리 PR 은 실패할 수 있다. 이 경우 기준선을 새로 만들면 된다.
3. **중첩 구성요소.** `components[].components` 는 보지 않는다. cbom-scout 출력은 평탄해서 영향이 없다.

테스터 관찰 (기존 코드 문제, 이번 범위 밖, 후속 이슈 후보):

- **O1 (낮음).** `check` 가 `bom-ref` 없는 현재 CBOM 구성요소를 버린다(`inventory.merge_component`). 그래서 이런 외부 CBOM 을 `check` 하면 신규 위반을 놓친다. `--baseline` 없이도 같다.
- **O2 (낮음).** `parameterSetIdentifier` 에 `²` 같은 문자가 있으면 `check` 에서 `ValueError` 트레이스백이 난다(`policy._status_of`). 기준선에 있으면 종료 코드 2 로 거부된다.

운영 시 주의:

- 기준선과 현재 스캔은 같은 작업 디렉터리 기준으로 만들어야 한다. 경로가 하나도 겹치지 않으면 경고가 나온다.
- 기준선 파일을 지정했는데 없으면 종료 코드 2 다. 워크플로에서는 파일이 있을 때만 넘긴다.

다음 단계:

1. 사용자가 PR #1, #2 를 검토하고 병합한다.
2. O1·O2 와 한계 1 을 후속 이슈로 등록할지 정한다.
3. 필요하면 `--baseline-optional` 이나 기준선 자동 준비 기능을 별도 명세로 검토한다.
