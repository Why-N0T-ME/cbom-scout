# 테스트 보고서 — 기준선(baseline) 비교, 1회차

- 명세: `docs/specs/baseline.md` (승인 2026-11-26)
- 브랜치: `feature/baseline` (`4569edd`)
- 인수 테스트: `tests/acceptance/test_baseline.py` (64개)
- 환경: Windows 11, Python 3.10.5. CLI 는 `python -m cbom_scout.cli` 로 하위 프로세스 실행 (이 환경에서 `cbom-scout.exe` 직접 실행이 권한 거부되어 같은 진입점 `cbom_scout.cli:main` 을 모듈로 호출)

## 판정: **불통과**

AC-1~AC-36 의 검증 방법은 모두 그대로 통과했다. 다만 AC-32 의 "`pass` 구성요소에는 이 속성이 없다"가 `check --baseline` 경로에서 깨진다(D1). 기준선 파일 형식 오류 처리에도 트레이스백이 나는 빈틈이 있다(D3).

## 실행 결과

- `python -m pytest -q` 전체: **118 통과, 6 실패**. 기존 테스트(`tests/test_*.py`)는 모두 통과하고, 실패 6건은 모두 인수 테스트의 결함 재현용이다.
  - `test_ac32_check_pass_component_has_no_baseline_prop` (D1)
  - `test_extra_check_stale_baseline_prop` (D2)
  - `test_extra_malformed_components_no_traceback[*]` 4건 (D3)
- `scan examples/demo-app -o d.json --fail-on never` 다음 `scan examples/demo-app -o d2.json --baseline d.json -v` → 종료 코드 0, `신규 실패 0 / 신규 경고 0 / 신규 참고 0 · 기존 32건 · 해결 0건 → 통과`
- `--baseline nope.json` → `cbom-scout: 기준선 파일을 찾을 수 없습니다: …nope.json`, 종료 코드 2

## 완료 기준별 결과

| ID | 결과 | 근거 |
|---|---|---|
| AC-1 | 통과 | 명령 C 종료 0, `--baseline` 없이 1 |
| AC-2 | 통과 | 주석·빈 줄 추가로 줄 이동 → 0 |
| AC-3 | 통과 | 1, 신규 절 `app/b.py`만, 기존 절 `app/a.py` |
| AC-4 | 통과 | 1, 신규 SHA-1 / 기존 MD5 |
| AC-5 | 통과 | pwarn 0, 신규 절 RSA-2048 행 "경고", `--fail-on warn` 1 |
| AC-6 | 통과 | `--fail-on warn`·`info` 모두 0 |
| AC-7 | 통과 | 0, stderr `해결 1건`, 해결 절에 MD5·`app/a.py` |
| AC-8 | 통과 | check 0 / 1 |
| AC-9 | 통과 | demo-app(인증서·키 자료·프로토콜·알고리즘 모두 있음) 자기 비교 0, 신규 0 |
| AC-10 | 통과 | `--fail-on never` 0 |
| AC-11 | 통과 | 비밀키 줄 이동 0 |
| AC-12 | 통과 | 1, 신규 절 `app/secret2.txt` |
| AC-13 | 통과 | cur.json·md·html·stderr(-v)·stdout(GITHUB_ACTIONS)·STEP_SUMMARY 어디에도 `MIIBOgIBAAJBAKj34` 없음 |
| AC-14 | 통과 | nginx.conf 줄 이동 0 |
| AC-15 | 통과 | 8443 추가 1(신규 절에 8443 만), 443 만 0 |
| AC-16 | 통과 | 2, `기준선`·경로 포함, 트레이스백 없음, 출력 파일 없음 (`check` 도 동일) |
| AC-17 | 통과 | 디렉터리 → 2 |
| AC-18 | 통과 | `{not json` → 2 |
| AC-19 | 통과 | `{}`, `[]`, SPDX 각각 2 |
| AC-20 | 통과 | 빈 목록·키 없음 각각 1, MD5 신규. specVersion 1.4/1.5 도 허용 |
| AC-21 | 통과 | 외부 도구 기준선(`md5`, line 없음) 0 |
| AC-22 | 통과 | `app\a.py` 0, `./app/a.py` 0, `App/a.py` 1 |
| AC-23 | 통과 | `겹치지 않습니다` 경고, 1. 빈 기준선·현재 위반 없음에서는 경고 없음 |
| AC-24 | 통과 | 같은 파일 MD5 추가 0 |
| AC-25 | 통과 | `--policy strict` 0, 기존 절 RSA-2048 행 "실패" |
| AC-26 | 통과 | 이름 변경 1, 신규 `app/c.py`, 해결 `app/a.py` |
| AC-27 | 통과 | 요약 줄 정규식 일치, (1,0,0,1,0,실패) |
| AC-28 | 통과 | `[신규]`+SHA-1, `[기존]`+MD5 같은 줄 |
| AC-29 | 통과 | `::error file=app/b.py,line=2` 있음, `file=app/a.py` 주석 없음 |
| AC-30 | 통과 | 판정 줄 `기준선 대비 판정: 🔴 실패`, 신규 절이 기존 절보다 앞, 기존 목록 `<details>` 안, 신규 0건 문구, STEP_SUMMARY 동일 |
| AC-31 | 통과 | `신규` 행에 `app/b.py`, `기존` 행에 `app/a.py` |
| AC-32 | **불통과(부분)** | `scan` 경로는 통과: SHA-1 `new`, MD5 `existing`, 신규·기존 혼합 `new`, pass 에 속성 없음, 1.6 스키마 통과. **`check --baseline` 에서는 입력 CBOM 에 남아 있던 `cbom-scout:baseline` 이 pass 구성요소에 그대로 남는다** (D1) |
| AC-33 | 통과 | 기존 테스트 전체 통과, demo 1, stderr·md·x.json 에 기준선 흔적 없음 |
| AC-34 | 통과 | `merge … --baseline` → 2 |
| AC-35 | 통과 | scan/check `--help` 에 `--baseline` + 한국어 설명, README 예시·종료 코드 설명 있음 |
| AC-36 | 통과 | `baseline` 입력 기본값 `""`, 값이 있을 때만 `--baseline` 추가 |

### 명세 외 점검

| 항목 | 결과 |
|---|---|
| 한글·공백 경로 폴더에서 `기준\기준선.json` 백슬래시 상대경로·절대경로 기준선 | 통과 (GitHub 주석 `file=app/b.py` 정상) |
| 없는 한글 경로 `없는\기준선.json` | 통과 (2, 경로 표시) |
| 스캔 대상 `app\sub` 백슬래시 | 통과 (CBOM 위치에 `\` 없음) |
| UTF-8 BOM 붙은 기준선 | 트레이스백 없음 (0 또는 2) |
| `--baseline` 출력 cur.json 을 다음 기준선으로 재사용 | 통과 |
| `-o` 와 `--baseline` 이 같은 파일 | 통과 (기준선을 먼저 읽음) |
| 구성요소 필드 형식이 이상한 기준선 | **실패** (D3) |
| 기준선 결과가 든 CBOM 을 `check` 로 재평가 | **실패** (D2) |

## 결함 목록

### D1 — `check --baseline` 출력에서 pass 구성요소에 이전 `cbom-scout:baseline` 이 남는다 (보통)

- 재현:
  ```
  # T/app/a.py = F0
  cbom-scout scan app -o base.json --fail-on never
  # app/b.py = F0 추가
  cbom-scout scan app -o cur.json --baseline base.json          # MD5 → baseline=new
  echo {"name":"allpass","status":{},"default":{"action":"pass"}} > pass.json
  cbom-scout check cur.json --baseline base.json --policy pass.json -o re.json
  ```
- 기대 (AC-32): `re.json` 의 MD5 는 `policy-action=pass` 이므로 `cbom-scout:baseline` 속성이 없다.
- 실제: MD5 에 `policy-action=pass` 와 `cbom-scout:baseline=new` 가 함께 있다. `baseline.compare()` 가 위반 구성요소에만 `set_prop` 하고, 입력에서 넘어온 기존 값을 지우지 않는다. 후속 도구가 이 CBOM 만 보고 "신규 위반"을 고르면 잘못 고른다.
- 테스트: `test_ac32_check_pass_component_has_no_baseline_prop`

### D2 — `--baseline` 없는 `check` 도 입력의 `cbom-scout:baseline` 을 그대로 출력한다 (낮음)

- 재현: 위 D1 의 cur.json 으로 `cbom-scout check cur.json -o re.json --fail-on never`
- 기대: 기준선 비교를 하지 않은 결과이므로 `cbom-scout:baseline` 이 없다 (AC-33 "`--baseline` 없이는 출력 CBOM 이 지금과 같다"는 취지; `policy-action` 은 재평가 값으로 덮어쓰는데 `baseline` 만 옛 값이 남는다).
- 실제: `cbom-scout:baseline=new` 가 남는다.
- 테스트: `test_extra_check_stale_baseline_prop`

### D3 — CycloneDX 이지만 구성요소 형식이 잘못된 기준선에서 트레이스백·종료 코드 1 (보통)

- 재현 (`base.json` 내용별, F0 에서 명령 C):
  - `{"bomFormat":"CycloneDX","components":[{"type":"cryptographic-asset","name":"md5","evidence":"x"}]}` → `AttributeError: 'str' object has no attribute 'get'` (`baseline.units_of`)
  - `…"cryptoProperties":"x"…` → `AttributeError` (`baseline.asset_key`)
  - `…"name":5,"cryptoProperties":{"assetType":"algorithm"}…` → `AttributeError: 'int' object has no attribute 'lower'`
  - `…"evidence":{"occurrences":[{"location":null}]}…` → `TypeError` (기준선 구성요소를 `policy.evaluate` 로 재평가하는 중)
- 기대: 기준선 파일 문제는 종료 코드 2, 한국어 메시지, 트레이스백 없음 (명세 "기준선 파일 형식·오류" 공통 기대, 문제 절 "정책 위반과 구분이 안 된다").
- 실제: 트레이스백, 종료 코드 1 → 정책 위반과 구분되지 않는다. 출력 파일은 만들지 않는다.
- 테스트: `test_extra_malformed_components_no_traceback[*]`

## 명세가 모호해 판정할 수 없던 점

1. **형식 검증 범위**: 명세는 "최상위 객체 + `bomFormat`" 만 검사하라고 정한다. 구성요소 내부 필드 형식이 틀린 경우(D3)를 오류 2 로 할지, 해당 구성요소를 건너뛸지 정해 두지 않았다. D3 는 "트레이스백·종료 코드 1 이 정책 위반과 섞인다"는 문제 절에 근거해 결함으로 올렸다.
2. **`check` 입력에 이미 든 `cbom-scout:baseline`**: AC-32 는 `scan` 출력만 예로 든다. `check` 입력에서 넘어온 값을 지워야 하는지는 명시하지 않았다. pass 구성요소 규칙(D1)은 AC-32 문장 그대로 적용했고, `--baseline` 없는 경우(D2)는 취지에 따라 낮음으로 올렸다.
3. **외부 도구 CBOM 의 `파일:줄` 위치**: 위치에 `/` 가 없고 `scanners` 속성도 없으면 TLS 엔드포인트로 보고 `:숫자` 를 떼지 않는다. 그래서 외부 기준선의 `a.py:3`(루트 파일)과 현재 `a.py` 는 다른 위치로 판정된다. 명세 표에는 이 경우의 기준이 없어 결함으로 올리지 않았다.
4. **AC-35 "한국어 설명"**: 도움말에서 `--baseline` 뒤 300자 안에 한글이 있는지만 확인했다.
5. 이 환경에서는 stderr 가 비 UTF-8 콘솔로 갈 때 한글이 `\uXXXX` 로 출력된다. 기준선 기능 이전부터 요약 줄도 그랬으므로 이번 범위로 보지 않았다 (테스트는 `PYTHONIOENCODING=utf-8` 로 실행).
