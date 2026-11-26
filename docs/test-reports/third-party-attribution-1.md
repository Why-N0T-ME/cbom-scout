# 테스트 보고서 — 외부 파일 출처·라이선스 관리 (1회차)

- 명세: `docs/specs/third-party-attribution.md` (승인)
- 브랜치: `feature/third-party-attribution` (HEAD `d7e3ade`)
- 인수 테스트: `tests/acceptance/test_third_party_attribution.py` (111개)
- 실행 환경: Linux, Python 3 (로컬). Windows 는 실행하지 못함 (아래 "판정할 수 없던 점")

## 판정: **불통과**

치명·높음 결함은 없다. 현재 저장소 상태로는 AC 대부분을 만족하지만, AC-5 가 금지하는 "빈 값" 라이선스가
공백 문자열이면 통과하고(결함 1), AC-4 의 "최소 `tests/schemas/`" 가 매니페스트 수정 한 줄로 꺼진다(결함 2).
둘 다 명세에 직접 적힌 요구라 보통으로 분류했고, 수정 범위는 작다.

## 실행 결과

| 명령 | 결과 |
|---|---|
| `python3 -m pytest -q` (전체) | 279 통과, 8 실패 — 실패 8개는 모두 이번 인수 테스트의 결함 재현. 기존 176개 테스트는 전부 통과 |
| `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py` | 103 통과, 8 실패 |
| `python3 -m pip wheel . --no-deps -w <tmp>` | 성공. wheel 에 `*schema.json` 없음, `policies/*.json` 은 있음 |

## 완료 기준별 결과

| ID | 결과 | 근거 |
|---|---|---|
| AC-1 | 통과 | NOTICE 의 스키마별 블록에 이름·원저작·라이선스·원본 URL·경로 모두 있음. JSF 블록에 Anders Rundgren 있음 (`test_ac1_*`) |
| AC-2 | 통과 (낮음 결함 3건) | 루트 `third_party.json` 의 3개 항목이 필수 필드·형식 충족. 누락·빈 값·형식 오류·`modified:true` 시 `modifications` 누락 모두 실패 처리. 단 `modifications` 가 비문자열/공백이거나 날짜가 `2026-13-45` 여도 통과 (결함 3, 5) |
| AC-3 | 통과 (낮음 결함 1건) | 등록 경로 모두 존재. 없는 경로·`\`·절대경로·`./`·`..` 거부. Windows 식 `\` 경로가 `/` 로 정규화됨(ntpath 모의), 한글·공백 경로에서 정상. 단 `path` 가 숫자면 어느 검사에도 안 걸림 (결함 4) |
| AC-4 | **불통과 (보통)** | 미등록 파일은 경로와 "third_party.json 에 등록" 안내로 실패, `README.md` 만 제외, 하위 폴더도 검사. 그러나 `vendored_dirs` 에서 `tests/schemas/` 를 빼면 검사가 꺼짐 (결함 2) |
| AC-5 | **불통과 (보통)** | 허용 7종 통과, Semgrep·NOASSERTION·빈 값·GPL/LGPL/AGPL/MPL (대소문자, 앞뒤 공백, `OR` 식 포함) 실패, CC-BY-4.0 은 코드 파일에 거부. 그러나 공백만 있는 라이선스(`"   "`)는 통과 (결함 1) |
| AC-6 | 통과 | `spdx.schema.json` 항목에 `license_evidence` (배포본 이름 + Apache-2.0) 있음 |
| AC-7 | 통과 (낮음 결함 1건) | 현재 저장소에 흔적 없음. `src/`·`src/cbom_scout/policies/`·`tests/`·`examples/` 에 넣은 흔적 3종 모두 탐지, 대소문자 무시, 한글 경로 정상, `docs/`·`CLAUDE.md`·`.claude/`·`NOTICE` 제외. 단 UTF-16 파일은 놓침 (결함 6) |
| AC-8 | 통과 | `modified:true` 텍스트 파일에서 원본·라이선스·수정 고지 중 하나라도 없으면 실패, 다 있으면 통과. JSON 은 매니페스트로 대신 |
| AC-9 | 통과 | CLAUDE.md "외부 코드·데이터" 절에 등록 절차, 허용·금지 라이선스, 참고만 정의, Semgrep 복사 금지, 수정 고지, 자동 검사 한계 모두 있음 |
| AC-10 | 통과 | `_template.md` 에 "외부 자료" 절 (출처·라이선스·복사/참고만 표) |
| AC-11 | 통과 | README 라이선스 절이 NOTICE·third_party.json 을 가리킴, `tests/schemas/README.md` 가 NOTICE 를 가리킴 |
| AC-12 | 통과 | 저장소 사본으로 wheel 생성 → `schema.json`·`tests/` 없음 |
| AC-13 | 통과 (Linux 한정) | 기존 176개 테스트(`test_cbom_schema_valid` 포함) 통과. Windows 는 검증 못 함 |

## 결함 목록

### 결함 1 — 공백만 있는 라이선스가 통과한다 (보통, AC-5)
- 재현: `python3 -m pytest -q "tests/acceptance/test_third_party_attribution.py::test_ac5_forbidden_or_unknown_license_fails[   ]"`
  또는 `tpc.check_fields({"vendored_dirs": [], "files": [ent(license="   ")]})`
- 기대: 문제 보고 (명세: 알 수 없음 = 빈 값은 금지)
- 실제: `[]`. 필수 항목 검사는 `""`·`None` 만 비교해 통과시키고, `check_license` 는 `strip()` 후 빈 값이면 "이미 보고됨"이라며 빈 목록을 돌려준다. 두 검사가 서로 상대가 잡는다고 가정해 빈틈이 생김.

### 결함 2 — `vendored_dirs` 에서 `tests/schemas/` 를 빼면 미등록 검사가 꺼진다 (보통, AC-4)
- 재현: `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py::test_ac4_cannot_bypass_by_removing_tests_schemas_from_vendored_dirs`
  (매니페스트 `vendored_dirs: []` + `tests/schemas/bom-1.7.schema.json` 미등록 → `check_all`)
- 기대: 실패 (명세: 외부 파일 전용 디렉터리는 "최소 `tests/schemas/`")
- 실제: `[]` (통과). 허용 라이선스 목록은 "같은 변경에서 늘리지 못하게" 코드에 둔 반면, 검사 대상 디렉터리는 매니페스트에서 지울 수 있어 같은 우회가 가능하다. 최소 목록을 `third_party_check.py` 에 상수로 두고 매니페스트 값과 합치는 방식이 일관적이다.

### 결함 3 — `modifications` 가 문자열이 아니거나 공백이어도 통과 (낮음, AC-2)
- 재현: `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py::test_ac2_modifications_must_be_nonblank_string`
- 기대: `["목록"]`, `1`, `"   "` 모두 문제 보고 (명세: `modifications`(문자열) 필수)
- 실제: 셋 다 통과 (참/거짓 판정만 함)

### 결함 4 — `path` 가 문자열이 아니면 어느 검사에도 걸리지 않는다 (낮음, AC-2/AC-3)
- 재현: `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py::test_ac3_non_string_path_rejected` (`path: 123`)
- 기대: 형식 오류 또는 "파일이 없습니다"
- 실제: `check_fields` 는 문자열일 때만 경로 형식을 보고, `check_paths_exist` 는 문자열이 아니면 건너뜀 → 문제 0건

### 결함 5 — 존재하지 않는 날짜가 `retrieved` 로 통과 (낮음, AC-2)
- 재현: `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py::test_ac2_retrieved_must_be_real_date` (`2026-13-45`)
- 기대: 문제 보고 (`datetime.date.fromisoformat` 등으로 실제 날짜 확인)
- 실제: 정규식 `\d{4}-\d{2}-\d{2}` 만 보므로 통과
- 비고: "형식" 만 요구한다고 읽으면 결함이 아닐 수 있음 (아래 모호한 점 3)

### 결함 6 — UTF-16 파일의 Semgrep 흔적을 놓친다 (낮음, AC-7)
- 재현: `python3 -m pytest -q tests/acceptance/test_third_party_attribution.py::test_ac7_marker_in_utf16_file`
- 기대: 탐지 (명세: "어떤 파일에도")
- 실제: `utf-8, errors="ignore"` 로 읽어 NUL 바이트가 섞인 문자열이 되므로 놓침. BOM 감지 후 utf-16 으로 다시 읽으면 막을 수 있음. 명세가 인정한 "흔적 검사의 한계" 범위라 낮음.

## 참고 관찰 (결함 아님)

- `check_notice` 는 NOTICE 에 `path`·`name`·`source_url` 만 대조하고 원저작(`author`)·라이선스는 대조하지 않는다. AC-1 은 현재 NOTICE 내용으로 만족하지만, 매니페스트와 NOTICE 의 라이선스가 어긋나도 테스트는 통과한다.
- setuptools 가 루트 `NOTICE` 를 자동으로 wheel 의 `dist-info/licenses/NOTICE` 에 넣는다. NOTICE 문구("배포 패키지에는 포함되지 않습니다")는 스키마 파일 얘기라 모순은 없고, 오히려 배포본에 고지가 따라가서 바람직하다.
- 흔적 검사는 `"Semgrep Rules  License"`(공백 둘)나 줄바꿈으로 끊긴 문구, `.zip`·`.gz` 안의 파일은 보지 않는다. 명세가 문자열 일치와 그 한계를 명시했으므로 결함으로 올리지 않았다.
- 흔적 검사 대상 파일 자체(테스트 코드)가 흔적 문자열을 직접 쓰면 저장소 전체 검사에 걸린다. 이번에 인수 테스트를 쓰면서 실제로 한 번 걸렸다 (조각을 이어 붙여 해결). 새 테스트 작성자도 같은 함정에 빠질 수 있으니 `SEMGREP_MARKERS` 의 주석처럼 안내가 유지돼야 한다.

## 명세가 모호해 판정할 수 없던 점

1. **AC-13 Windows:** 명세는 "Windows·Linux 모두에서 통과(CI 3개 Python 버전 녹색)" 라고 하지만 `.github/workflows/ci.yml` 은 `ubuntu-latest` 만 돈다. CI 녹색은 Windows 통과를 뜻하지 않는다. 로컬에서는 `ntpath` 모의로 경로 정규화만 확인했다. CI 매트릭스에 `windows-latest` 를 넣을지 결정이 필요하다.
2. **CC-BY-4.0 의 "문서·데이터" 범위:** 구현은 확장자 목록(`.py`, `.js` 등)으로 코드 여부를 가른다. Semgrep 류 탐지 규칙(`.yaml`)이나 정규식 목록(`.txt`·`.json`)이 "데이터" 인지 "코드" 인지 명세에 없다. 현재는 데이터로 취급돼 CC-BY-4.0 이 허용된다.
3. **`retrieved` 형식:** "YYYY-MM-DD" 가 형식만인지 실제 날짜인지 명세에 없다 (결함 5).
4. **매니페스트가 없거나 JSON 이 깨진 경우:** 명세에 동작이 없다. 현재는 예외로 테스트가 오류 처리되어 결과적으로 실패하므로 막히긴 한다 (인수 테스트는 예외 발생만 확인).
