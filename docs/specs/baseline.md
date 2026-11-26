# 기준선(baseline) 비교

- 상태: 승인 (2026-11-26, 확인 필요 1~8 모두 권장안)
- 작성: pm 에이전트
- 요청 원문: "기준선 비교 기능을 진행해줘. PR에서는 기준 CBOM 대비 새로 생긴 취약 암호만 실패로 처리하는 게 목표야."

## 문제

이미 레거시 취약 암호(MD5, RSA 등)가 있는 저장소에 cbom-scout 를 PR CI 로 붙이면, PR 이 아무것도 바꾸지 않아도 기존 위반 때문에 매번 종료 코드 1로 실패한다.
그래서 `--fail-on never` 로 끄거나 도입을 포기하게 되고, 정작 PR 이 **새로** 들여오는 취약 암호도 막지 못한다.
기준 CBOM(예: `main` 브랜치 스캔 결과)을 주면 그 대비 **새로 생긴 위반만** 실패로 판정하는 방법이 필요하다.

## 현재 동작 (코드로 확인한 사실)

- `scan`·`check` 는 `cli._finish()` 에서 `policy.evaluate()` → `should_fail(result, --fail-on)` 로 종료 코드를 정한다. 위반이 하나라도 `--fail-on` 이상이면 1, 아니면 0. 경로가 없으면 2, argparse 오류도 2.
- 정책 평가 단위(`Finding`)는 **구성요소(component) 하나**다. 같은 알고리즘이 여러 파일에 있어도 구성요소는 하나(`crypto/algorithm/MD5`)이고 위치는 `evidence.occurrences[]` 에 쌓인다.
- 위치 표기와 bom-ref 가 줄 번호에 묶인 경우가 있다. 줄 번호 이동에 견디려면 bom-ref 를 그대로 비교하면 안 된다.
  - 알고리즘: bom-ref `crypto/algorithm/<이름>`, occurrence `{"location": "app/a.py", "line": 2}`. 줄 번호는 별도 필드.
  - 코드에 들어 있는 비밀키(`scanners/code.py`): bom-ref `crypto/key/private-key/<경로-줄>`, name `private-key:<경로>:<줄>` → **줄 번호가 식별자에 들어 있다.**
  - 설정 파일 TLS 버전(`ssl_protocols`, `scanners/code.py::_record_tls_config`): bom-ref `crypto/protocol/tls/<경로-줄>`, occurrence location `"<경로>:<줄>"` (line 필드 없음) → **줄 번호가 식별자와 위치 문자열에 들어 있다.**
  - TLS 엔드포인트(`scanners/tls.py`): occurrence location `"host:port"`. 여기의 `:443` 은 줄 번호가 아니다.
  - 인증서: bom-ref `crypto/certificate/<지문 앞 24자>`. 인증서를 갱신하면 지문이 바뀐다.
- `cbom.load()` 는 파일이 없거나 JSON 이 깨지면 예외를 그대로 올린다(트레이스백, 종료 코드 1). 기준선 파일에 이 경로를 그대로 쓰면 "정책 위반"과 구분이 안 된다.
- `scan -o` 로 저장한 CBOM 에는 평가 후의 `cbom-scout:policy-action` 속성이 들어 있다. 따라서 일반 `scan` 출력이 곧 기준선 파일이 될 수 있다.

## 목표와 범위

- 이번에 하는 것:
  - `scan`, `check` 에 기준 CBOM 파일 옵션 `--baseline FILE` 추가 (이름은 확인 필요 1).
  - 기준선 대비 "신규 위반 / 기존 위반 / 해결됨" 분류, 종료 코드는 **신규 위반만** 기준.
  - 줄 번호 이동에 견디는 발견 식별 규칙.
  - 콘솔 요약, `-v` 상세, 마크다운·HTML 리포트, GitHub 주석, 출력 CBOM 에 신규/기존 구분 표시.
  - 기준선 파일이 없거나 깨졌을 때 종료 코드 2 와 한국어 오류 메시지.
  - README 사용법·종료 코드 설명 갱신. GitHub Action `baseline` 입력 (확인 필요 5).
- 이번에 하지 않는 것:
  - 기준선 파일을 자동으로 받아 오는 기능(아티팩트 다운로드, `git` 으로 main 체크아웃 후 스캔 등). 기준선 파일은 사용자가 준비한다.
  - 파일 이름 변경·이동 추적 (이동하면 신규로 본다 — AC-26).
  - 기준선 안의 개별 항목 예외 처리(억제 목록, 만료일 있는 예외). 정책 `overrides` 로 이미 이름 단위 예외는 가능하다.
  - `merge` 명령 변경.
  - 정책 JSON 형식·`catalog.py` 판정 기준 변경.

## 용어와 식별 규칙 (요구사항)

- **위반**: 현재 정책으로 평가한 결과 action 이 `info`·`warn`·`fail` 인 구성요소. `pass` 는 분류하지 않는다.
- **발견 단위**: `(자산 식별자, 위치 경로)` 쌍. 한 구성요소가 여러 파일에 있으면 파일마다 하나의 발견 단위다. occurrence 가 없는 구성요소는 위치 경로를 빈 문자열로 본다.
- **위치 경로**: occurrence 의 `location` 에서 줄 번호를 뺀 것. 다음을 정규화한다 — `\` → `/`, 앞의 `./` 제거. 대소문자는 구분한다 (확인 필요 8).
  - 설정 파일 TLS 프로토콜처럼 위치 문자열 끝에 `:<줄>` 이 붙은 경우 그 줄 번호도 뺀다.
  - TLS 엔드포인트의 `host:port` 는 그대로 둔다 (`api.example.com:443` 과 `:8443` 은 다른 위치).
- **자산 식별자** (자산 유형 `cryptoProperties.assetType` 별):

| 자산 유형 | 자산 식별자 | 비고 |
|---|---|---|
| `algorithm` | 자산 유형 + `name`(대소문자 무시) | 다른 도구가 만든 CBOM 도 bom-ref 와 무관하게 이름으로 맞춘다 |
| `certificate` | 자산 유형 + `name`(주체 DN) | 같은 경로에서 같은 주체로 갱신한 인증서는 기존으로 본다 |
| `related-crypto-material` | 자산 유형 + `relatedCryptoMaterialProperties.type` (예: `private-key`) | name·bom-ref 에 들어 있는 줄 번호는 무시 |
| `protocol` | 자산 유형 + `protocolProperties.type` (예: `tls`) | 위치 경로로 엔드포인트·설정 파일을 구분 |
| 그 밖 / 없음 | 자산 유형 + `name` | |

- **신규 발견 단위**: 현재 스캔의 위반 구성요소에서 나온 발견 단위 중, 기준선의 **모든** `cryptographic-asset` 구성요소에서 만든 발견 단위 집합에 없는 것. 기준선 구성요소의 `policy-action`·`status` 값은 비교에 쓰지 않는다 (확인 필요 3).
- **기존 발견 단위**: 현재 위반 구성요소의 발견 단위 중 기준선에 있는 것.
- **해결된 발견 단위**: 기준선 구성요소를 **현재 정책으로** 평가했을 때 위반인 것들의 발견 단위 중 현재 스캔에 없는 것.
- 한 구성요소가 신규와 기존 발견 단위를 함께 가질 수 있다 (예: MD5 가 `a.py` 에는 원래 있었고 `b.py` 에 새로 생김). 이때 그 구성요소는 리포트의 신규·기존 양쪽에 각각 해당 위치만 나온다.
- 같은 파일 안에서 같은 자산이 한 번 더 늘어난 경우는 발견 단위가 같으므로 기존이다 (확인 필요 2).

## 사용자 시나리오

1. 사용자가 `main` 에서 `cbom-scout scan . -o baseline.json --fail-on never` 로 기준선을 만들어 아티팩트로 보관한다.
2. PR CI 에서 `cbom-scout scan . --baseline baseline.json` 을 돌리면, 기존 MD5·RSA 는 리포트의 "기존 위반"에만 나오고 종료 코드는 0 이다.
3. PR 이 새 파일에 `hashlib.md5` 를 넣으면 "신규 위반"에 그 파일이 나오고, 해당 줄에 GitHub 오류 주석이 달리며 종료 코드 1 로 실패한다.
4. PR 이 레거시 MD5 를 SHA-384 로 바꾸면 "해결됨 1건"이 표시되고 통과한다.
5. 기준선 경로를 잘못 주면 "기준선 파일을 찾을 수 없습니다" 같은 메시지와 함께 종료 코드 2 로 멈춘다 (정책 위반 1 과 구분).

## 완료 기준 (테스터가 그대로 검증)

### 공통 준비

- 임시 디렉터리 `T` 를 작업 디렉터리(cwd)로 한다. 환경 변수 `GITHUB_STEP_SUMMARY`, `GITHUB_ACTIONS` 는 지정이 없으면 비운다.
- `T/app/a.py` (이하 **F0**):
  ```
  import hashlib
  hashlib.md5(b'')
  ```
- 기준선 **B0**: `cbom-scout scan app -o base.json --fail-on never` (위치는 `app/a.py` 로 기록된다).
- 정책 파일 **P_warn** (`T/pwarn.json`, 날짜에 좌우되지 않게 `fail_after` 없음):
  ```json
  {"name": "t-warn", "status": {"broken": {"action": "fail"}, "quantum-vulnerable": {"action": "warn"}}, "default": {"action": "info"}}
  ```
- RSA 코드 한 줄 **R**: `from cryptography.hazmat.primitives.asymmetric import rsa` 다음 줄에 `rsa.generate_private_key(public_exponent=65537, key_size=2048)`.
- "명령 C" 는 따로 적지 않으면 `cbom-scout scan app -o cur.json --baseline base.json` 이다.
- "트레이스백 없음" = stderr 에 `Traceback` 문자열이 없다.

### 정상 경로

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-1 | 변경이 없으면 기준선 대비 통과한다 | F0, B0 그대로 명령 C → 종료 코드 0. 같은 상태에서 `--baseline` 없이 `cbom-scout scan app -o cur.json` → 종료 코드 1 (기존 동작 유지) |
| AC-2 | 줄 번호만 바뀐 기존 위반은 신규가 아니다 | B0 생성 후 `a.py` 맨 앞에 `# 주석` 과 빈 줄 2개를 넣어 MD5 를 5번째 줄로 옮김 → 명령 C 종료 코드 0 |
| AC-3 | 새 파일에 생긴 취약 암호는 신규 위반으로 실패한다 | B0 생성 후 `app/b.py` 를 F0 와 같은 내용으로 추가 → 명령 C `--markdown r.md` 종료 코드 1. `r.md` 의 "신규 위반" 절에 `app/b.py` 가 있고 `app/a.py` 는 없다. "기존 위반" 절에 `app/a.py` 가 있다 |
| AC-4 | 기존 파일에 새 알고리즘이 생기면 신규 위반이다 | B0 생성 후 `a.py` 끝에 `hashlib.sha1(b'')` 추가 → 명령 C 종료 코드 1. 신규 절에 `SHA-1`, 기존 절에 `MD5` |
| AC-5 | 신규 위반의 종료 코드는 `--fail-on` 을 따른다 | B0 를 `--policy pwarn.json` 으로 생성. 이후 `a.py` 에 R 추가 → 명령 C `--policy pwarn.json` 은 종료 코드 0 이고 리포트 신규 절에 `RSA-2048` 이 경고로 나온다. 같은 명령에 `--fail-on warn` → 종료 코드 1 |
| AC-6 | 기존 위반은 `--fail-on` 수준과 무관하게 실패를 만들지 않는다 | `a.py` 에 R 을 넣은 상태로 `--policy pwarn.json` 기준선 생성 → 변경 없이 명령 C `--policy pwarn.json --fail-on warn` → 종료 코드 0 (`--fail-on info` 도 0) |
| AC-7 | 사라진 위반은 "해결됨"으로 보고되고 종료 코드에 영향이 없다 | B0 생성 후 `a.py` 2번째 줄을 `hashlib.sha384(b'')` 로 바꿈 → 명령 C `--markdown r.md` 종료 코드 0. stderr 요약에 `해결 1건`, `r.md` 에 "해결" 절과 `MD5`·`app/a.py` |
| AC-8 | `check` 명령도 같은 규칙을 따른다 | AC-1 상태에서 `cbom-scout check cur0.json --baseline base.json` (cur0.json 은 `--fail-on never` 로 만든 현재 스캔) → 0. AC-3 상태로 만든 cur0.json → 1 |
| AC-9 | 자기 자신과 비교하면 모든 자산 유형에서 통과한다 | `cbom-scout scan examples/demo-app -o d.json --fail-on never` 후 `cbom-scout scan examples/demo-app -o d2.json --baseline d.json` → 종료 코드 0, 신규 0건 (인증서·키 자료·설정 TLS 포함) |
| AC-10 | `--fail-on never` 는 신규 위반이 있어도 0 | AC-3 상태에서 명령 C `--fail-on never` → 0 |

### 줄 번호에 묶인 식별자 (견고성)

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-11 | 코드 속 비밀키는 줄이 바뀌어도 기존이다 | `app/secret.txt` 에 3줄 `-----BEGIN RSA PRIVATE KEY-----` / `MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu` / `-----END RSA PRIVATE KEY-----` 로 기준선 생성 → 맨 앞에 빈 줄 2개 추가 → 명령 C 종료 코드 0 |
| AC-12 | 다른 파일에 새 비밀키가 생기면 신규다 | AC-11 기준선 상태에서 같은 내용의 `app/secret2.txt` 추가 → 명령 C 종료 코드 1, 신규 절에 `app/secret2.txt` |
| AC-13 | 기준선 비교 결과 어디에도 키 본문이 나오지 않는다 | AC-11·AC-12 실행의 `cur.json`, `--markdown`, `--html` 출력, stderr(`-v` 포함), stdout(`GITHUB_ACTIONS=true`) 어디에도 `MIIBOgIBAAJBAKj34` 가 없다 |
| AC-14 | 설정 파일 TLS 설정은 줄이 바뀌어도 기존이다 | `app/nginx.conf` 에 `ssl_protocols TLSv1 TLSv1.2;` 한 줄로 기준선 생성 → 맨 앞에 `# 설정` 줄 5개 추가 → 명령 C 종료 코드 0 |
| AC-15 | TLS 엔드포인트는 포트까지 구분한다 | 직접 만든 CBOM 두 개로 `check`. 기준선: 구성요소 1개 `{"type":"cryptographic-asset","bom-ref":"crypto/protocol/tls/api.example.com-443","name":"TLS api.example.com:443","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.0"}},"evidence":{"occurrences":[{"location":"api.example.com:443"}]},"properties":[{"name":"cbom-scout:status","value":"broken"},{"name":"cbom-scout:scanners","value":"tls"}]}`. 현재: 같은 구성요소 + 443 을 8443 으로 바꾼 구성요소 → `check cur.json --baseline base.json` 종료 코드 1, 신규 절에 `api.example.com:8443` 만. 현재가 443 하나뿐이면 0 |

### 기준선 파일 형식·오류

기준선 파일은 CycloneDX JSON 이어야 한다: 최상위가 객체이고 `bomFormat` 이 `"CycloneDX"`. `components` 가 없으면 빈 목록으로 본다. `specVersion` 은 검사하지 않는다 (1.4~1.6 모두 허용). 오류 시 공통 기대: 종료 코드 2, stderr 에 `기준선` 이라는 단어와 지정한 경로, 트레이스백 없음, `-o`·`--markdown`·`--html` 파일을 만들지 않는다.

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-16 | 기준선 파일이 없으면 오류 2 | 명령 C 에서 `--baseline nope.json` (존재하지 않음) → 공통 기대 충족, `cur.json` 없음 |
| AC-17 | 기준선 경로가 디렉터리면 오류 2 | `--baseline app` → 공통 기대 충족 |
| AC-18 | 깨진 JSON 이면 오류 2 | 내용 `{not json` → 공통 기대 충족 |
| AC-19 | CycloneDX 가 아니면 오류 2 | 내용 `{}`, `[]`, `{"bomFormat":"SPDX"}` 각각 → 공통 기대 충족 |
| AC-20 | 빈 기준선은 "기준선 없음"과 같은 판정이다 | 내용 `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}` 및 `components` 키가 없는 `{"bomFormat":"CycloneDX","specVersion":"1.6"}` 각각 → 명령 C 종료 코드 1, MD5 가 신규 절에 있음 |
| AC-21 | 다른 도구가 만든 기준선(cbom-scout 속성 없음)도 맞춘다 | 기준선 구성요소 1개: `{"type":"cryptographic-asset","bom-ref":"foreign/md5","name":"md5","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"hash"}},"evidence":{"occurrences":[{"location":"app/a.py"}]}}` → F0 에서 명령 C 종료 코드 0 (이름 대소문자 무시, line 없음 허용) |
| AC-22 | 위치 경로 정규화 | AC-21 기준선의 location 을 `app\\a.py`(JSON 이스케이프, 실제 값 `app\a.py`) 로 바꾸면 0, `./app/a.py` 로 바꾸면 0, `App/a.py` 로 바꾸면 1 |
| AC-23 | 기준선과 현재 위치가 전혀 겹치지 않으면 경고한다 | 기준선 location 을 모두 `other/root/a.py` 로 바꾼 파일로 명령 C → stderr 에 `겹치지 않습니다` 포함 경고, 종료 코드는 규칙대로 1. 기준선이나 현재 위반이 비어 있으면 이 경고를 내지 않는다 |

### 정책·범위 결정에 따른 동작 (확인 필요 결과에 따라 기대값이 바뀔 수 있음)

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-24 | 같은 파일에서 같은 자산이 늘어도 기존이다 (확인 필요 2, 권장안 A 기준) | B0 생성 후 `a.py` 에 `hashlib.md5(b'x')` 줄 추가 → 명령 C 종료 코드 0 |
| AC-25 | 정책이 엄격해져도 기존 자산은 신규가 아니다 (확인 필요 3, 권장안 기준) | `a.py` 에 R 을 넣고 기본 정책으로 기준선 생성 → 변경 없이 명령 C `--policy strict` → 종료 코드 0. 리포트 기존 절에 `RSA-2048` 이 `실패` 로 표시 |
| AC-26 | 파일 이동·이름 변경은 신규로 본다 (알려진 한계) | B0 생성 후 `app/a.py` → `app/c.py` 이름 변경 → 명령 C 종료 코드 1, 신규 절에 `app/c.py`, 해결 절에 `app/a.py` |

### 출력 표시

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-27 | 콘솔 요약에 기준선 결과 줄이 추가된다 | 기존 `cbom-scout: 자산 …` 줄은 그대로 출력되고, 그 다음 stderr 줄이 정규식 `^기준선 대비: 신규 실패 (\d+) / 신규 경고 (\d+) / 신규 참고 (\d+) · 기존 (\d+)건 · 해결 (\d+)건 → (실패|경고|참고|통과)$` 에 맞는다. 숫자 단위는 발견 단위(자산, 위치 쌍). AC-4 상태에서 신규 실패 1, 기존 1, 해결 0, 판정 `실패` |
| AC-28 | `-v` 상세 줄에 신규·기존이 구분된다 | AC-4 상태에서 명령 C `-v` → stderr 에 `[신규]` 와 `SHA-1` 이 같은 줄에, `[기존]` 과 `MD5` 가 같은 줄에 있다 |
| AC-29 | GitHub 주석은 신규 위치에만 단다 | AC-3 상태, `GITHUB_ACTIONS=true` 로 명령 C → stdout 에 `::error file=app/b.py,line=2` 가 있고 `file=app/a.py` 가 들어간 `::error`·`::warning` 줄은 없다 |
| AC-30 | 마크다운 리포트 구조 | AC-3 상태 `--markdown r.md` → 판정 줄에 `기준선 대비` 문구와 판정(신규 위반 중 가장 높은 action)이 있다. 절 제목 `## 신규 위반 (기준선 대비)` 이 `## 기존 위반` 보다 먼저 나온다. 기존 위반 목록은 `<details>` 안에 있다. 신규가 0건이면 신규 절에 `기준선 대비 새로 생긴 위반이 없습니다` 가 나온다. `GITHUB_STEP_SUMMARY` 에도 같은 내용이 붙는다 |
| AC-31 | HTML 리포트에 구분이 보인다 | AC-3 상태 `--html r.html` → `신규` 표시가 있는 행에 `app/b.py`, `기존` 표시가 있는 행에 `app/a.py` |
| AC-32 | 출력 CBOM 에 구분 속성이 들어가고 스키마를 통과한다 | AC-4 상태 `cur.json`: SHA-1 구성요소에 `{"name":"cbom-scout:baseline","value":"new"}`, MD5 구성요소에 `"existing"`. 신규·기존 위치를 모두 가진 구성요소는 `"new"`. `pass` 구성요소에는 이 속성이 없다. `cur.json` 이 `tests/schemas/bom-1.6.schema.json` 검증 통과 (속성 이름은 확인 필요 6) |

### 하위 호환

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-33 | `--baseline` 없이는 동작이 바뀌지 않는다 | 기존 `python -m pytest -q` 전체 통과. `cbom-scout scan examples/demo-app -o x.json --markdown r.md` 종료 코드 1, stderr 에 `기준선` 이 없고, `r.md` 에 `기준선`·`신규 위반` 이 없으며, `x.json` 에 `cbom-scout:baseline` 속성이 없다 |
| AC-34 | `merge` 는 `--baseline` 을 받지 않는다 | `cbom-scout merge a.json -o m.json --baseline b.json` → 종료 코드 2 (argparse 오류) |
| AC-35 | 도움말과 문서 | `cbom-scout scan --help`, `cbom-scout check --help` 출력에 `--baseline` 과 한국어 설명. README 에 기준선 사용 예시와 "기준선 사용 시 종료 코드 1 은 신규 위반만" 설명, 종료 코드 2 에 기준선 오류 포함 |
| AC-36 | Action 입력 (확인 필요 5 가 "포함"일 때) | `action.yml` 에 입력 `baseline` (기본값 `""`) 이 있고, 값이 비어 있지 않을 때만 `--baseline <값>` 을 넘긴다. 비어 있으면 기존과 같은 명령줄 |

## 설계 메모

- 바뀌는 모듈
  - `cli.py`: `scan`·`check` 에 옵션 추가, 기준선 파일 검증(스캔 전에 해서 오류면 출력 파일을 만들지 않음), 종료 코드 판정을 신규 위반 기준으로.
  - 새 비교 로직(모듈 위치는 개발 재량, 예: `baseline.py`): 발견 단위 추출·정규화·분류. 자산 유형별 식별 규칙을 한곳에 모아 두면 규칙 변경이 쉽다. 판정 기준(어떤 상태가 위반인지)은 계속 정책·`catalog.py` 가 정한다 — 비교 로직은 "위반 여부"를 다시 판단하지 않는다.
  - `policy.py`: `should_fail` 과 같은 의미를 신규 위반 집합에 적용할 수 있어야 한다. 기존 `evaluate`·`should_fail` 시그니처와 결과는 그대로 (기존 테스트 호환).
  - `report.py`: 기준선 결과가 있을 때만 신규·기존·해결 절을 그린다. 없으면 출력이 지금과 같아야 한다.
  - `action.yml`, `README.md`, `examples/workflows/cbom-scan.yml`(PR 에서 기준선 쓰는 예시) — 범위 결정에 따름.
- CLI: `--baseline FILE` (scan, check). 다른 옵션 변경 없음.
- CBOM: 구성요소 `properties` 에 `cbom-scout:baseline` 추가. CycloneDX 1.6 은 `properties` 의 이름·값을 자유롭게 허용하고, 이름 공간 접두어(`cbom-scout:`)를 권장한다 — [CycloneDX 1.6 JSON 참조 (properties)](https://cyclonedx.org/docs/1.6/json/#components_items_properties), [CycloneDX 속성 분류(taxonomy)](https://github.com/CycloneDX/cyclonedx-property-taxonomy).
- 발견 위치는 CycloneDX 1.6 `evidence.occurrences[].location`/`line` 을 쓴다 — [CycloneDX 1.6 JSON 참조 (evidence.occurrences)](https://cyclonedx.org/docs/1.6/json/#components_items_evidence_occurrences). 다른 도구가 만든 CBOM 은 `line` 이 없거나 `location` 에 줄을 붙일 수 있으므로 정규화가 필요하다.
- GitHub 주석 형식은 기존과 같다 (`::error file=…,line=…`) — [GitHub 워크플로 명령](https://docs.github.com/actions/reference/workflow-commands-for-github-actions#setting-an-error-message). 기존 위치에는 주석을 달지 않는다.
- 비밀 값: 비교 과정에서 기준선·현재 CBOM 의 `additionalContext` 를 출력하지 않는다. 키 본문은 원래 CBOM 에 없지만 회귀 방지로 AC-13 을 둔다.
- 경로: 비교는 CBOM 에 기록된 `/` 구분 상대경로 문자열로 한다. Windows·Linux 에서 만든 기준선을 서로 바꿔 써도 같은 결과여야 한다 (AC-22). 기준선과 현재 스캔을 **같은 작업 디렉터리 기준**으로 만들어야 위치가 맞는다는 점을 README 에 적는다 (AC-23 경고가 이 실수를 알려 준다).
- 하위 호환: `--baseline` 이 없으면 종료 코드, 콘솔 출력, 리포트, CBOM 이 지금과 같다. 기존 종료 코드 의미(0 통과, 1 정책 위반, 2 사용법 오류)는 유지하고, 기준선 사용 시 1 의 의미만 "신규 정책 위반"으로 좁힌다.

## 확인 필요 (사용자 결정)

- [x] **1. 옵션 이름.** (a) `--baseline FILE` (b) `--baseline-cbom FILE` (c) `--diff-against FILE`. **권장: (a)** — 짧고 다른 도구(예: SARIF 기준선 기능)와 용어가 같다.
- [x] **2. 같은 파일에서 같은 자산이 늘어난 경우.** (A) 파일 단위로 보고 기존 처리 (B) 파일 안 개수가 늘면 신규 처리(어느 줄이 새것인지는 특정 못 해 파일 단위로 표시). **권장: (A)** — 줄 번호로는 "같은 호출"을 구분할 수 없어 (B)는 코드 정리·이동 때 오탐을 낸다. 프로젝트 규칙상 오탐은 미탐만큼 도입을 막는다. 대신 그 파일은 이미 기존 위반으로 리포트에 남는다. (B)를 고르면 AC-24 기대값이 1 로 바뀐다.
- [x] **3. 기존 자산의 조치가 올라간 경우** (정책 교체, `fail_after` 날짜 도래로 warn→fail, TLS 엔드포인트가 같은 주소에서 더 약해짐 등). (A) 기존으로 보고 실패시키지 않음, 리포트에만 현재 판정 표시 (B) 기준선의 `policy-action` 보다 올라가면 신규로 봄. **권장: (A)** — 기준선은 "이미 알고 있는 부채"이고, 2031-01-01 처럼 날짜로 일괄 승격될 때 모든 PR 이 갑자기 실패하는 것을 막는 게 이 기능의 목적이다. 또 다른 도구가 만든 기준선에는 `policy-action` 이 없다. (B)를 고르면 AC-25 기대값이 1 로 바뀐다.
- [x] **4. 기준선 파일이 없을 때.** (A) 종료 코드 2 로 중단 (B) 경고 후 기준선 없이 전체 평가 (C) 경고 후 통과. **권장: (A)** — 아티팩트 다운로드 실패를 조용히 넘기면 (B)는 PR 을 엉뚱하게 실패시키고 (C)는 신규 위반을 놓친다. 첫 도입처럼 기준선이 아직 없는 경우는 워크플로에서 파일이 있을 때만 옵션을 넘기면 된다. 필요하면 다음에 `--baseline-optional` 을 추가.
- [x] **5. GitHub Action `baseline` 입력을 이번 범위에 넣을지.** (A) 넣음 — 입력만 추가, 기준선 파일 준비는 사용자 워크플로 몫 (B) CLI 만. **권장: (A)** — 요청 목표가 PR CI 이고 변경이 작다. 넣으면 AC-36 적용.
- [x] **6. 출력 CBOM 구분 속성.** 이름·값: (a) `cbom-scout:baseline` = `new`/`existing` (b) `cbom-scout:baseline-status` = 동일 값 (c) CBOM 에는 넣지 않음. **권장: (a)** — 기존 속성(`status`, `policy-action`)과 짧은 이름 규칙이 같고, 후속 도구가 CBOM 만 보고도 신규 항목을 고를 수 있다.
- [x] **7. 해결된 위반 표시.** (A) 콘솔 요약에 건수 + 리포트에 목록 (B) 건수만 (C) 표시 안 함. **권장: (A)** — PR 리뷰어에게 전환 진척을 보여 주는 유일한 신호다. 종료 코드에는 어느 쪽이든 영향 없음.
- [x] **8. 위치 경로 대소문자.** (A) 구분 (B) 무시. **권장: (A)** — Linux CI 기준으로 다른 파일일 수 있고, CBOM 에 기록되는 경로는 스캐너가 실제 파일명에서 만든다. 정규화는 `\`→`/` 와 앞 `./` 제거만. (B)를 고르면 AC-22 의 `App/a.py` 기대값이 0 으로 바뀐다.

## 작업 단위

1. 발견 단위 추출·정규화·분류 로직과 단위 테스트 (자산 유형별 식별 규칙, 줄 번호 제거, TLS host:port 보존, 다른 도구 CBOM).
2. 기준선 파일 읽기·검증과 오류 메시지(종료 코드 2, 출력 파일 미생성).
3. `scan`·`check` 옵션 연결과 종료 코드 규칙, 콘솔 요약·`-v`·GitHub 주석.
4. 마크다운·HTML 리포트의 신규·기존·해결 절, 출력 CBOM 속성, 스키마 검증 테스트.
5. 오탐·엣지 테스트 (줄 이동, 비밀키·설정 TLS 줄 식별자, 이동 파일, 빈/깨진 기준선, 경로 정규화, 무겹침 경고).
6. README·`action.yml`·예시 워크플로 갱신 (확인 필요 5 결과에 따라).
