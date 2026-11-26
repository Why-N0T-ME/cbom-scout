# 테스트 보고서 — 기준선(baseline) 비교, 2회차

- 명세: `docs/specs/baseline.md` (승인 2026-11-26)
- 브랜치: `feature/baseline` (검증 대상 수정 커밋 `2fa448b`, HEAD `1b6e251` 기준 작업 트리)
- 인수 테스트: `tests/acceptance/test_baseline.py` (1회차 64개 + 2회차 추가 6개 함수, 매개변수 포함 70개)
- 환경: Windows 11, Python 3.10.5. `cbom-scout.exe` 직접 실행은 이 환경에서 권한 거부(126)되어 같은 진입점을 `python -m cbom_scout.cli` 로 실행. `PYTHONIOENCODING=utf-8`

## 판정: **불통과**

1회차 결함 D1·D2·D3 는 모두 수정을 확인했다. AC-1~AC-36 은 검증 방법 그대로 모두 통과한다.
다만 CycloneDX 에서 **선택 필드인 `bom-ref` 가 없는 기준선**(다른 도구가 만든 CBOM)에서 트레이스백·종료 코드 1 이 난다(D4, 높음). 정책 위반과 구분되지 않아 PR CI 가 매번 실패한다. D3 수정도 `properties[].value` 형식은 다루지 않아 같은 계열의 트레이스백이 남는다(D5).

## 실행 결과

- `python -m pytest -q` 전체: **134 통과, 5 실패**. 기존 테스트(`tests/test_*.py`)와 1회차 인수 테스트는 모두 통과. 실패 5건은 모두 2회차 추가 테스트(D4·D5·D6 재현용)이다.
  - `test_r2_foreign_baseline_without_bom_ref` (D4)
  - `test_r2_foreign_baseline_without_bom_ref_resolved` (D4)
  - `test_r2_malformed_property_value_no_traceback[props0]`, `[props1]` (D5)
  - `test_r2_duplicate_bom_ref_resolved_count` (D6)
- `scan examples/demo-app -o d.json --fail-on never` 후 `scan examples/demo-app -o d2.json --baseline d.json` → 종료 코드 0, `신규 실패 0 / 신규 경고 0 / 신규 참고 0 · 기존 32건 · 해결 0건 → 통과`
- `--baseline <스크래치>/없는/기준선.json` (한글 경로) → `cbom-scout: 기준선 파일을 찾을 수 없습니다: …/없는/기준선.json`, 종료 코드 2
- `scan examples/demo-app -o x.json` (기준선 없음) → 종료 코드 1 (기존 동작 유지)

## 1회차 결함 재확인

| ID | 결과 | 근거 |
|---|---|---|
| D1 `check --baseline` 에서 pass 구성요소에 옛 `cbom-scout:baseline` 잔존 | 수정됨 | `test_ac32_check_pass_component_has_no_baseline_prop` 통과. 재평가 출력도 1.6 스키마 통과 (`test_r2_check_rerun_output_schema_valid`) |
| D2 `--baseline` 없는 `check` 출력에 옛 속성 잔존 | 수정됨 | `test_extra_check_stale_baseline_prop` 통과 |
| D3 구성요소 형식이 잘못된 기준선에서 트레이스백 | 부분 수정 | 1회차 4가지 입력과 비객체 구성요소는 종료 코드 2 + `기준선 파일의 components[i] 형식이 올바르지 않습니다 (…)`. `properties[].value` 형식은 검사하지 않음 (D5) |

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
| AC-9 | 통과 | demo-app 자기 비교 0, 신규 0 |
| AC-10 | 통과 | 0 |
| AC-11 | 통과 | 비밀키 줄 이동 0 |
| AC-12 | 통과 | 1, 신규 절 `app/secret2.txt` |
| AC-13 | 통과 | 모든 출력에 키 본문 없음 |
| AC-14 | 통과 | nginx.conf 줄 이동 0 |
| AC-15 | 통과 | 8443 추가 1(신규 절 8443 만), 443 만 0 |
| AC-16 | 통과 | 2, `기준선`·경로, 트레이스백 없음, 출력 파일 없음 |
| AC-17 | 통과 | 2 |
| AC-18 | 통과 | 2 |
| AC-19 | 통과 | `{}`, `[]`, SPDX 각 2 |
| AC-20 | 통과 | 빈 목록·키 없음 각 1, MD5 신규 |
| AC-21 | 통과 (검증 방법 기준) | 명세 예시(bom-ref 있음)는 0. 단 bom-ref 를 뺀 외부 CBOM 은 실패 (D4) |
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
| AC-32 | 통과 | scan·check 양쪽 모두 속성 규칙 충족, 1.6 스키마 통과 |
| AC-33 | 통과 | 기존 테스트 전체 통과, demo 1, 기준선 흔적 없음 |
| AC-34 | 통과 | 2 |
| AC-35 | 통과 | 도움말·README |
| AC-36 | 통과 | `action.yml` `baseline` 입력 |

### 명세 외 점검

| 항목 | 결과 |
|---|---|
| Windows 백슬래시·한글·공백 경로 기준선 (1회차 테스트 재실행) | 통과 |
| 없는 한글 경로 기준선 | 통과 (2) |
| UTF-8 BOM 기준선 | 통과 (이번에 정상 읽기) |
| `check` 재평가 출력 스키마 | 통과 |
| bom-ref 없는 외부 기준선 | **실패** (D4) |
| `properties[].value` 가 문자열이 아닌 기준선 | **실패** (D5) |
| bom-ref 중복 기준선 | **실패** (D6) |

## 결함 목록

### D4 — `bom-ref` 가 없는 기준선 구성요소에서 트레이스백·종료 코드 1 (높음)

- 재현 (T/app/a.py = F0):
  ```
  echo {"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"md5","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"hash"}},"evidence":{"occurrences":[{"location":"app/a.py"}]}}]} > base.json
  cbom-scout scan app -o cur.json --baseline base.json
  ```
- 기대: AC-21 과 같은 입력에서 `bom-ref` 만 뺀 것이다. CycloneDX 1.6 에서 `bom-ref` 는 선택 필드이고, 명세는 "다른 도구가 만든 CBOM 도 bom-ref 와 무관하게 이름으로 맞춘다"고 한다 → 종료 코드 0. 최소한 트레이스백 없이 종료 코드 2.
- 실제: `KeyError: 'bom-ref'` (`policy.py` evaluate 99행, `baseline.compare()` 가 해결됨 계산을 위해 기준선 구성요소를 재평가하는 중), 종료 코드 1. 정책 위반 1 과 구분되지 않는다. `_component_problem()` 은 bom-ref 가 "있을 때 문자열인지"만 보고 없는 경우를 걸러 내지 않는다. 현재 MD5 와 무관한 구성요소(예: `app/z.py` 의 sha1)라도 bom-ref 가 없으면 같은 트레이스백이 난다.
- 테스트: `test_r2_foreign_baseline_without_bom_ref`, `test_r2_foreign_baseline_without_bom_ref_resolved`

### D5 — `properties[].value` 가 문자열이 아닌 기준선에서 트레이스백 (보통)

- 재현 (F0, 명령 C):
  - 구성요소 `properties: [{"name":"cbom-scout:scanners","value":5}]`, 위치 `app/a.py:2` (line 필드 없음) → `AttributeError: 'int' object has no attribute 'split'` (`baseline._is_endpoint`)
  - `properties: [{"name":"cbom-scout:status","value":["broken"]}]` → `TypeError: unhashable type: 'list'` (`policy.evaluate`)
- 기대: D3 와 같이 종료 코드 2, `기준선` 포함 한국어 메시지, 트레이스백 없음 (또는 해당 값을 무시하고 정상 판정).
- 실제: 트레이스백, 종료 코드 1. D3 수정의 형식 검사가 `properties` 를 "객체 목록인지"까지만 본다.
- 테스트: `test_r2_malformed_property_value_no_traceback[props0]`, `[props1]`

### D6 — bom-ref 가 중복된 기준선에서 해결 건수가 부풀려진다 (낮음)

- 재현: 기준선에 `bom-ref:"x"` 인 구성요소 2개 (`md5` @ `app/a.py`, `sha1` @ `app/z.py`), F0 에서 명령 C
- 기대: 해결 1건 (sha1 @ `app/z.py`). 또는 잘못된 기준선으로 종료 코드 2.
- 실제: `해결 2건`. `compare()` 의 `bmap` 이 bom-ref 로 구성요소를 찾아 두 finding 이 모두 마지막 구성요소(sha1)를 가리킨다. CycloneDX 는 bom-ref 고유성을 요구하므로 잘못된 입력이지만, 조용히 틀린 숫자를 낸다. 종료 코드에는 영향 없음.
- 테스트: `test_r2_duplicate_bom_ref_resolved_count`

## 명세가 모호해 판정할 수 없던 점

1. **bom-ref 없는 구성요소**: 명세 AC-21 예시에는 bom-ref 가 들어 있어 검증 방법 자체는 통과한다. 그러나 명세 식별 규칙 표가 "bom-ref 와 무관하게 이름으로 맞춘다"고 명시하고 CycloneDX 에서 bom-ref 가 선택 필드이므로 D4 를 결함(높음)으로 올렸다. 오류 2 로 처리할지 정상 비교할지는 명세가 정하지 않았으나, 어느 쪽이든 트레이스백·종료 코드 1 은 명세 "문제" 절과 어긋난다.
2. **형식 검증 범위** (1회차 1번과 동일): 구성요소 내부 필드가 틀릴 때 오류 2 로 할지 건너뛸지 명세에 없다. D5 테스트는 0 또는 2 를 모두 허용한다.
3. **외부 도구 CBOM 의 `파일:줄` 위치** (1회차 3번과 동일): 루트 파일 `a.py:3` 은 엔드포인트로 판정되어 줄 번호를 떼지 않는다. 명세에 기준이 없어 결함으로 올리지 않았다.
4. 비 UTF-8 콘솔에서 한글이 `\uXXXX` 로 나오는 문제는 기능 이전부터 있던 것으로 범위 밖으로 보았다.
