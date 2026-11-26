# 외부 파일 출처·라이선스 관리

- 상태: 승인 (2026-11-27, 확인 필요 1~5 모두 권장안)
- 작성: 메인 세션 (사용자 직접 요청, PM 에이전트 미경유)
- 요청 원문: "CycloneDX 스키마처럼 남의 파일을 넣을 때는 출처와 라이선스를 남기기. Semgrep 규칙처럼 라이선스가 까다로운 건 복사하지 말고 참고만 하기. 이걸로 명세 작성해봐"

## 문제

저장소는 공개돼 있고, 남이 만든 파일이 이미 들어 있다(`tests/schemas/` 의 CycloneDX 스키마 3개).
지금은 출처가 README 두 곳에 문장으로만 적혀 있어, 파일이 늘어나면 무엇이 남의 것이고 어떤 라이선스인지 추적할 수 없다.
또 앞으로 정규식 보완·평가용 예제 작업에서 Semgrep 규칙, CBOMkit 규칙, 벤치마크 사례를 가져오고 싶어질 텐데, 이를 막거나 기록하게 하는 장치가 없다.
에이전트는 각자 새 맥락에서 시작하므로, 규칙은 사람의 기억이 아니라 저장소 파일과 테스트로 강제돼야 한다.

## 현재 상태 (저장소에서 확인한 사실, 커밋 `3ba7a00`)

| 경로 | 원저작 | 라이선스 | 현재 표기 |
|---|---|---|---|
| `tests/schemas/bom-1.6.schema.json` | OWASP CycloneDX | Apache-2.0 (파일 안 `$comment` 에 명시) | `tests/schemas/README.md`, `README.md` 라이선스 절 |
| `tests/schemas/jsf-0.82.schema.json` | JSON Signature Format (Anders Rundgren), CycloneDX 배포본 | Apache-2.0 (파일 안 `$comment` 에 명시) | 위와 같음 (JSF 원저작자는 표기 안 됨) |
| `tests/schemas/spdx.schema.json` | CycloneDX 배포본 (SPDX 라이선스 ID 목록) | 파일 안에 표기 없음 (`$comment` 는 버전 `v1.1-3.29.0` 뿐) | 위와 같음 |
| `LICENSE` | Apache License 2.0 전문 | 라이선스 본문 자체 | — |

- 세 스키마는 `cyclonedx-python-lib` 11.13.0 배포본(`cyclonedx/schema/_res/`)에서 복사했다. 원본은 [CycloneDX/specification](https://github.com/CycloneDX/specification).
- 세 스키마는 `tests/` 에만 있고 `pyproject.toml` 의 패키지 데이터(`policies/*.json`)에 포함되지 않는다. 즉 배포되는 패키지(wheel)에는 들어가지 않는다.
- 그 밖의 파일(`examples/` 인증서 포함)은 이 저장소에서 직접 만든 것이다.

## 배경: Semgrep 규칙 라이선스

- `semgrep/semgrep-rules` 저장소의 규칙은 [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license) 을 따르며, 공식 FAQ 는 이 규칙을 **내부 업무 용도로만** 쓸 수 있다고 설명한다 ([Semgrep FAQ](https://semgrep.dev/docs/faq/overview)).
- 2024년 12월 변경으로 내부·비경쟁·비SaaS 용도로 제한됐고, Semgrep 문서는 이것이 오픈소스 라이선스가 아니라고 밝힌다 ([Semgrep 비교 문서](https://docs.semgrep.dev/faq/comparisons/opengrep-1)).
- 레지스트리의 제3자 규칙은 원 저장소의 라이선스를 따른다. 예: Trail of Bits 규칙은 AGPL-3.0 ([Semgrep 라이선스 문서](https://docs.semgrep.dev/licensing)).
- 따라서 Apache-2.0 인 이 저장소에 규칙 본문을 복사해 공개하는 것은 허용되지 않는다고 보고 **금지**한다. 규칙을 읽고 어떤 API 가 위험한지 배우는 것은 허용한다(아래 "참고만"의 정의).

## 목표와 범위

- 이번에 하는 것:
  - 저장소 안 외부 파일을 기계가 읽을 수 있는 목록(매니페스트)과 사람이 읽는 `NOTICE` 로 관리한다.
  - 목록과 실제 파일이 어긋나거나, 허용되지 않은 라이선스가 들어오거나, Semgrep 규칙 라이선스 흔적이 코드에 들어오면 **테스트가 실패**하게 한다.
  - `CLAUDE.md` 와 명세 템플릿에 외부 자료 규칙을 넣어 모든 에이전트가 따르게 한다.
  - 기존 CycloneDX 스키마 3개를 새 방식으로 등록한다.
- 이번에 하지 않는 것:
  - 법률 검토, 특허 검토.
  - 런타임 의존성(`cryptography` 등 pip 패키지)의 라이선스 점검. 저장소에 복사해 넣은 파일만 다룬다 (후속 후보).
  - 모든 파일에 SPDX 헤더를 다는 REUSE 방식 도입 (확인 필요 4).
  - 기존 문서의 출처 링크 형식 정리.

## 용어

- **외부 파일:** 이 저장소 밖에서 만들어진 파일을 그대로 또는 고쳐서 넣은 것. 코드, 스키마, 규칙, 데이터, 테스트 사례, 문서 조각을 모두 포함한다.
- **참고만:** 외부 자료를 읽고 사실(어떤 API·알고리즘이 위험한지)과 아이디어를 얻은 뒤, 이 저장소의 형식과 표현으로 **새로 작성**하는 것. 패턴 문자열, 정규식, YAML 규칙 본문, 메시지 문구, 메타데이터, 테스트 코드를 복사하거나 기계적으로 바꿔 쓰는 것은 "참고"가 아니라 "복사"다.
- **등록:** 외부 파일을 매니페스트와 `NOTICE` 에 기록하는 것.

## 사용자 시나리오

1. 개발 세션이 CycloneDX 1.7 스키마를 `tests/schemas/` 에 추가하면서 등록을 빠뜨리면 `pytest` 가 실패하고, 실패 메시지가 등록할 파일 경로와 필요한 항목을 알려 준다.
2. 개발 세션이 Semgrep 규칙을 복사해 `src/` 에 넣으면, 규칙 메타데이터에 남은 라이선스 문구 때문에 `pytest` 가 실패한다.
3. CBOMkit(Apache-2.0)의 탐지 규칙 일부를 가져와 고쳐 쓰면, 매니페스트에 `modified: true` 와 변경 내용을 적고 파일 안에 변경 고지를 남겨야 테스트가 통과한다.
4. 사용자가 저장소를 둘러보다 `NOTICE` 를 열면 남의 파일이 무엇이고 어디서 왔는지 한눈에 본다.

## 완료 기준 (테스터가 그대로 검증)

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-1 | 저장소 루트에 `NOTICE` 가 있고, 등록된 외부 파일마다 이름, 원저작(프로젝트·저작자), 라이선스, 원본 URL, 저장소 내 경로가 적혀 있다. CycloneDX 스키마 3개와 JSF 원저작자(Anders Rundgren)가 포함된다. | 파일을 읽어 각 항목 문자열 확인 |
| AC-2 | 기계용 매니페스트(확인 필요 1, 권장 `third_party.json`)가 있고, 항목마다 `path`, `name`, `license`(SPDX ID 또는 `LicenseRef-…`), `source_url`, `version`, `retrieved`(YYYY-MM-DD), `modified`(bool) 를 가진다. `modified: true` 이면 `modifications`(문자열)도 필수다. | JSON 로드 후 필드·형식 검사 테스트 |
| AC-3 | 매니페스트의 모든 `path` 가 실제로 존재한다. 경로는 `/` 구분 상대경로이며 Windows 에서도 같은 결과다. | 매니페스트 항목마다 `os.path.exists` 테스트. 없는 경로를 넣은 임시 매니페스트로 실패 확인 |
| AC-4 | 외부 파일 전용 디렉터리(최소 `tests/schemas/`)의 파일은 `README.md` 를 빼고 전부 매니페스트에 있다. 미등록 파일이 있으면 테스트가 실패하고, 메시지에 그 경로와 "third_party.json 에 등록" 안내가 나온다. | 임시 디렉터리에 미등록 파일을 둔 상태로 검사 함수 실행 → 실패와 메시지 확인 |
| AC-5 | 매니페스트의 `license` 는 허용 목록(확인 필요 2)에 있어야 한다. 금지 목록 — `LicenseRef-scancode-semgrep-rules-1.0`(Semgrep Rules License), 알 수 없음(`NOASSERTION`, 빈 값), 확인 필요 3 의 결론에 따른 카피레프트 — 이면 실패한다. | 금지 라이선스를 넣은 임시 매니페스트로 실패 확인 |
| AC-6 | 라이선스가 파일 안에 적혀 있지 않은 외부 파일(`spdx.schema.json`)도 매니페스트에 근거(`license_evidence`: 배포본 이름과 그 라이선스)가 적혀 있다. | 해당 항목에 `license_evidence` 존재 확인 |
| AC-7 | `src/`, `tests/`(이 검사 테스트 자신 제외), `examples/`, `src/cbom_scout/policies/` 의 어떤 파일에도 Semgrep 규칙 라이선스 흔적(`Semgrep Rules License`, `semgrep.dev/legal/rules-license`, `LicenseRef-scancode-semgrep`)이 없다. `docs/`, `CLAUDE.md`, `.claude/`, `NOTICE` 는 정책을 설명하므로 제외한다. 대소문자는 구분하지 않는다. | 흔적 문자열을 넣은 임시 파일로 실패 확인, 현재 저장소에서 통과 확인 |
| AC-8 | `modified: true` 인 외부 파일은 파일 자체에도 변경 고지(원본, 라이선스, "이 저장소에서 수정함")가 있다. 텍스트 파일만 해당하며, 주석을 넣을 수 없는 JSON 은 매니페스트 기록으로 대신한다. | `modified: true` 텍스트 항목을 둔 임시 매니페스트로 고지 누락 시 실패 확인 |
| AC-9 | `CLAUDE.md` 에 "외부 코드·데이터" 절이 생기고 다음을 담는다: 등록 절차(매니페스트 + `NOTICE`), 허용·금지 라이선스, "참고만"의 정의, Semgrep 규칙 복사 금지, 수정 시 고지. | 절 제목과 각 항목 문자열 확인 |
| AC-10 | `docs/specs/_template.md` 에 "외부 자료" 절(가져올 자료의 출처·라이선스·참고/복사 구분)이 추가된다. | 템플릿에 절 존재 확인 |
| AC-11 | `README.md` 의 라이선스 절이 `NOTICE` 와 매니페스트를 가리킨다. `tests/schemas/README.md` 도 `NOTICE` 를 가리킨다. | 문자열 확인 |
| AC-12 | 배포 패키지(wheel)에 `tests/schemas/` 가 포함되지 않는다는 점이 유지된다. | `python -m pip wheel . --no-deps -w <tmp>` 후 wheel 목록에 `schema.json` 없음 확인 |
| AC-13 | 기존 테스트가 모두 통과하고, 출력 CBOM 은 계속 CycloneDX 1.6 스키마를 통과한다. 새 검사는 Windows·Linux 모두에서 통과한다(CI 3개 Python 버전 녹색). | `python -m pytest -q`, CI |

## 설계 메모

- 검사 로직은 테스트 파일에 직접 두기보다 작은 함수로 분리해(예: `tests/third_party_check.py`) 임시 디렉터리·임시 매니페스트로 실패 경우를 검증할 수 있게 한다. 제품 코드(`src/`)에는 넣지 않는다 — 도구 기능이 아니라 저장소 관리 규칙이다.
- "외부 파일 전용 디렉터리" 목록은 매니페스트 안에 함께 둔다(예: `"vendored_dirs": ["tests/schemas/"]`). 새 디렉터리를 만들면 여기에 추가한다.
- AC-7 의 흔적 검사는 복사를 완전히 막지 못한다(메타데이터를 지우고 복사하면 통과). 마지막 방어선은 `CLAUDE.md` 규칙과 리뷰다. 이 한계를 `CLAUDE.md` 에 적는다.
- 하위 호환: CLI·Action·CBOM 형식은 바뀌지 않는다.

## 확인 필요 (사용자 결정)

- [x] 1. **매니페스트 형식** — (가) `third_party.json` + `NOTICE` 둘 다 (권장: 테스트로 검증 가능하고 사람도 읽기 쉬움) / (나) `NOTICE` 만 (간단하지만 기계 검증이 약함)
- [x] 2. **허용 라이선스 목록** — 권장: `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `CC0-1.0`, 문서·데이터에 한해 `CC-BY-4.0`
- [x] 3. **카피레프트(GPL·LGPL·AGPL·MPL) 파일** — 권장: 저장소에 넣는 것은 금지. 외부 도구로 실행만 하는 것(예: Semgrep 엔진 LGPL)은 해당 없음
- [x] 4. **REUSE/SPDX 파일 헤더** — 권장: 이번에는 하지 않음. 외부 파일이 10개를 넘으면 재검토
- [x] 5. **매니페스트 위치** — 권장: 루트 `third_party.json` (대안: `docs/third-party.json`)

## 작업 단위

1. 매니페스트와 `NOTICE` 작성, CycloneDX 스키마 3개 등록 (AC-1, 2, 6)
2. 검사 함수와 테스트 (AC-3, 4, 5, 7, 8)
3. `CLAUDE.md`, 명세 템플릿, README 갱신 (AC-9, 10, 11)
4. wheel 확인과 전체 회귀 (AC-12, 13)
