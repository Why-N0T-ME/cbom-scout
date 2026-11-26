# 테스트 보고서 — 기준선(baseline) 비교, 3회차

- 명세: `docs/specs/baseline.md` (승인 2026-11-26)
- 브랜치: `feature/baseline` (검증 대상 수정 커밋 `89530fc`, HEAD `506522a` 기준 작업 트리)
- 인수 테스트: `tests/acceptance/test_baseline.py` (2회차까지 70개 + 3회차 추가 6개 함수, 매개변수 포함 75개)
- 환경: Windows 11, Python 3.10.5. `cbom-scout.exe` 직접 실행은 이 환경에서 권한 거부(126)라 같은 진입점을 `python -m cbom_scout.cli` 로 실행. `PYTHONIOENCODING=utf-8`

## 판정: **통과**

2회차 결함 D4·D5·D6 의 수정을 확인했다. AC-1~AC-36 은 검증 방법 그대로 모두 통과한다.
3회차 추가 점검(수정 경로 회귀, 비객체·비 UTF-8 기준선, 내부 임시 ref 노출)에서 이번 기능의 결함은 나오지 않았다.
기존 `check`·`policy` 동작에서 비롯된 낮은 등급 관찰 2건은 아래에 적었으며 판정에는 반영하지 않았다.

## 실행 결과

- `python -m pytest -q` 전체: **153 통과, 0 실패** (기존 테스트, 1·2·3회차 인수 테스트 포함)
- `scan examples/demo-app -o d.json --fail-on never` → 0. 이어서 `scan examples/demo-app -o d2.json --baseline d.json` → 0, `신규 실패 0 / 신규 경고 0 / 신규 참고 0 · 기존 32건 · 해결 0건 → 통과`
- `scan examples\demo-app -o d3.json --baseline <스크래치>\한글 폴더\기준선.json` (백슬래시·한글·공백 경로) → 0, 같은 결과
- `--baseline <스크래치>/없음/기준선.json` → 2, `기준선 파일을 찾을 수 없습니다: …`
- `scan examples/demo-app -o x.json --markdown x.md` (기준선 없음) → 1. stderr·`x.md` 에 `기준선` 없음, `x.json` 에 `cbom-scout:baseline` 없음

## 2회차 결함 재확인

| ID | 결과 | 근거 |
|---|---|---|
| D4 bom-ref 없는 기준선에서 트레이스백 | 수정됨 | `test_r2_foreign_baseline_without_bom_ref`(0), `..._resolved`(0, 해결 1건) 통과. 해결 항목은 리포트에 원래 이름·위치(`sha1` — `app/z.py`)로 나오고 내부 임시 ref `baseline/N` 은 리포트·HTML·stderr·CBOM 어디에도 나오지 않음 (`test_r3_resolved_without_bom_ref_no_internal_ref_leak`), 출력 CBOM 1.6 스키마 통과 |
| D5 문자열 아닌 `properties[].value` | 수정됨 | 두 입력 모두 종료 코드 2, `기준선 파일의 components[0] 형식이 올바르지 않습니다 (properties[].value 가 문자열이 아님)`, 트레이스백 없음. `name` 이 빠진 속성 항목은 정상 비교(0) |
| D6 bom-ref 중복 시 해결 건수 부풀림 | 수정됨 | `test_r2_duplicate_bom_ref_resolved_count` 해결 1건. 같은 발견 단위가 기준선 두 구성요소에 있어도 해결 1건 (`test_r3_duplicate_unit_in_two_baseline_components`) |

## 완료 기준별 결과

| ID | 결과 | 근거 |
|---|---|---|
| AC-1 | 통과 | 명령 C 0, `--baseline` 없이 1 |
| AC-2 | 통과 | 줄 이동 0 |
| AC-3 | 통과 | 1, 신규 절 `app/b.py` 만, 기존 절 `app/a.py` |
| AC-4 | 통과 | 1, 신규 SHA-1 / 기존 MD5 |
| AC-5 | 통과 | pwarn 0 + 신규 절 RSA-2048 "경고", `--fail-on warn` 1 |
| AC-6 | 통과 | `--fail-on warn`·`info` 모두 0 |
| AC-7 | 통과 | 0, `해결 1건`, 해결 절 MD5·`app/a.py` |
| AC-8 | 통과 | check 0 / 1 |
| AC-9 | 통과 | demo-app 자기 비교 0, 신규 0 (CLI 직접 실행으로도 확인) |
| AC-10 | 통과 | 0 |
| AC-11 | 통과 | 비밀키 줄 이동 0 |
| AC-12 | 통과 | 1, 신규 절 `app/secret2.txt` |
| AC-13 | 통과 | cur.json·md·html·stderr(-v)·stdout(GITHUB_ACTIONS) 어디에도 키 본문 없음 |
| AC-14 | 통과 | nginx.conf 줄 이동 0 |
| AC-15 | 통과 | 8443 추가 1(신규 절 8443 만), 443 만 0 |
| AC-16 | 통과 | 2, `기준선`·경로, 트레이스백 없음, 출력 파일 없음 (scan·check) |
| AC-17 | 통과 | 2 |
| AC-18 | 통과 | 2 |
| AC-19 | 통과 | `{}`, `[]`, SPDX 각 2. 추가로 `null`, `5`, 빈 파일, `"CycloneDX"`, `true` 각 2 |
| AC-20 | 통과 | 빈 목록·키 없음 각 1, MD5 신규 |
| AC-21 | 통과 | 명세 예시 0, bom-ref 를 뺀 형태도 0 |
| AC-22 | 통과 | `app\a.py` 0, `./app/a.py` 0, `App/a.py` 1 |
| AC-23 | 통과 | 경고 + 1, 빈 경우 경고 없음 |
| AC-24 | 통과 | 0 |
| AC-25 | 통과 | 0, 기존 절 RSA-2048 "실패" |
| AC-26 | 통과 | 1, 신규 `app/c.py`, 해결 `app/a.py` |
| AC-27 | 통과 | 정규식 일치 (1,0,0,1,0,실패) |
| AC-28 | 통과 | `[신규]`+SHA-1, `[기존]`+MD5 |
| AC-29 | 통과 | `::error file=app/b.py,line=2`, `app/a.py` 주석 없음 |
| AC-30 | 통과 | 판정 줄·절 순서·`<details>`·0건 문구·STEP_SUMMARY |
| AC-31 | 통과 | 신규 행 `app/b.py`, 기존 행 `app/a.py` |
| AC-32 | 통과 | scan·check 모두 속성 규칙 충족, 1.6 스키마 통과 |
| AC-33 | 통과 | 기존 테스트 전체 통과, demo 1, 기준선 흔적 없음 |
| AC-34 | 통과 | 2 |
| AC-35 | 통과 | 도움말·README |
| AC-36 | 통과 | `action.yml` `baseline` 입력 |

### 명세 외 점검

| 항목 | 결과 |
|---|---|
| Windows 백슬래시·한글·공백 경로 기준선, 없는 한글 경로 | 통과 |
| UTF-8 BOM 기준선 | 통과 |
| CP949 등 비 UTF-8 기준선 | 통과 (2, `기준선 파일을 읽을 수 없습니다 … (UnicodeDecodeError)`) |
| 최상위가 객체가 아닌 JSON·빈 파일 | 통과 (2) |
| 재평가 단계 오류(compare) 시 출력 파일·STEP_SUMMARY 미생성 | 통과 (2, `-o`·`--markdown`·`--html`·STEP_SUMMARY 모두 없음) |
| 해결 항목에 내부 임시 ref 노출 | 없음 |
| 키 본문 노출 | 없음 |
| CycloneDX 1.6 스키마 | 통과 |

## 결함 목록

이번 기능(기준선 비교)의 결함: **없음**.

아래 2건은 이 브랜치가 바꾸지 않은 기존 코드에서 비롯된 관찰이다. 판정에는 반영하지 않았고 자동 테스트도 넣지 않았다 (넣으면 이번 기능과 무관하게 스위트가 실패한다). 후속 이슈 후보로 넘긴다.

### O1 — `check` 가 bom-ref 없는 현재 CBOM 구성요소를 버려, 기준선 비교가 비대칭이 된다 (낮음)

- 재현:
  ```
  echo {"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":"md5","cryptoProperties":{"assetType":"algorithm"},"evidence":{"occurrences":[{"location":"app/a.py"}]}}]} > nobr.json
  cbom-scout check nobr.json --baseline nobr.json
  ```
- 기대: 자기 자신과 비교이므로 기존 1건, 해결 0건.
- 실제: `자산 0개 … 기준선 대비: … 기존 0건 · 해결 1건 → 통과`. `inventory.merge_component()` 가 bom-ref 없는 구성요소를 건너뛰어(기존 동작, `main` 과 같음) 현재 쪽에서는 사라지고, D4 수정으로 기준선 쪽에서는 남기 때문이다. 같은 이유로 bom-ref 없는 외부 CBOM 을 `check` 하면 신규 위반도 놓친다. 이건 `--baseline` 없이도 마찬가지(자산 0개 → 통과)다.

### O2 — 숫자로 변환할 수 없는 숫자 문자(`²`)가 든 `parameterSetIdentifier` (낮음)

- 재현: 구성요소 `{"bom-ref":"r","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"²"}}, …}`
  - `cbom-scout check sup.json` → `ValueError` 트레이스백 (기존 `policy._status_of` 의 `str.isdigit()` 후 `int()`; `main` 과 같음)
  - 같은 구성요소가 기준선에 있으면 → 종료 코드 2, `기준선 구성요소를 평가할 수 없습니다 (ValueError): base.json`. 트레이스백·출력 파일은 없어 명세 오류 기대는 충족한다. 다만 스키마상 유효한 기준선이 거부된다.

## 명세가 모호해 판정할 수 없던 점

1. **중첩 구성요소**: CycloneDX 는 `components[].components` 중첩을 허용한다. 명세는 "기준선의 모든 `cryptographic-asset` 구성요소"라고 하지만 구현은 최상위만 본다 (중첩된 MD5 만 있는 기준선 → MD5 신규, 1). cbom-scout 출력은 평탄해서 AC 에는 영향이 없고, 현재 스캔 쪽 정책 평가도 최상위만 보므로 결함으로 올리지 않았다.
2. **외부 도구 CBOM 의 `파일:줄` 위치** (1·2회차와 같음): 루트 파일 `a.py:3` 은 엔드포인트로 보아 줄 번호를 떼지 않는다. 명세에 기준이 없다.
3. **형식 검증 범위** (1·2회차와 같음): 구성요소 내부 값이 이상할 때 오류 2 로 할지 건너뛸지 명세에 없다. 인수 테스트는 트레이스백이 없으면 0·2 를 모두 허용한다.
4. 비 UTF-8 콘솔에서 한글이 `\uXXXX` 로 나오는 문제는 기능 이전부터 있던 것으로 범위 밖으로 보았다.
