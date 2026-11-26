# 문맥 인식 탐지: 정규식 스캔의 오탐·미탐 보완

- 상태: **승인** (2026-11-27, 확인 필요 1~18 모두 추천안으로 결정) — 2차 개정 — 업계 조사 `docs/research/crypto-detection-survey.md` 반영, 사용자 지정: 신뢰도는 CycloneDX 표준 필드, 의존성은 라이브러리 식별까지)
- 작성: pm 에이전트
- 요청 원문: "외부 평가에서 지적된 '정규식 기반 스캔의 태생적 한계(오탐/미탐)'를 보완하는 기능의 명세를 docs/specs/ 에 작성해 달라. (평가의 다른 항목 — 오픈소스 성숙도, README 템플릿 문구, KMS/컨테이너/SSH 미구현 — 은 이번 범위가 아니다.)
  평가 원문: 소스코드를 구문 트리(AST)나 데이터 흐름으로 분석하지 않고 정규식 패턴 매칭으로 찾는다. / 변수에 암호 알고리즘 이름을 담아 넘기거나 외부 라이브러리 내부에서 호출되는 암호는 놓칠 수 있다(미탐). / 단순 주석이나 테스트용 문자열을 암호 사용으로 착각할 수 있다(오탐)."
- 개정 요청: "docs/research/crypto-detection-survey.md 를 읽고 그 내용을 명세에 반영하라. 1) 신뢰도는 CycloneDX 1.6 표준 필드로 표현한다(자체 속성 대신). 2) 의존성 분석의 완료 기준을 '라이브러리 식별' 수준으로 한정하라."

## 문제

cbom-scout 를 CI 에 붙인 보안 담당자는 주석으로 막아 둔 옛 코드나 로그 문자열 때문에 MD5·DES 가 "실패"로 뜨는 것을 보고 도구를 불신하게 되고(오탐), 반대로 `hashlib.new(ALG)` 처럼 변수로 알고리즘을 넘기거나 키 길이를 다음 줄에 쓴 코드는 통째로 빠지거나 심각도가 낮게 잡힌다(미탐).
또 결과가 어떤 근거로 나왔는지(구문 분석인지 문자열 매칭인지, 얼마나 확실한지, 테스트 코드인지)를 CBOM 에서 알 수 없고, 다른 CycloneDX 도구도 읽을 수 있는 형태로 남지 않는다.
개선 효과를 숫자로 보여 줄 기준 데이터도 없다.

## 배경 — 평가 지적과 현재 동작 (코드로 확인한 사실)

### 현재 탐지 방식

- `scanners/code.py::scan_code()` 는 파일을 줄 단위로 나눠(`text.splitlines()`) 확장자별 정규식 규칙(`RULES`)을 **한 줄씩** `rx.finditer(line)` 으로 적용한다. 구문 분석·데이터 흐름 분석은 없다(모듈 docstring 3~6행도 이를 명시).
- 여러 줄에 걸친 정보는 일부 규칙만 `_lookahead()` 로 다음 4~6줄을 정규식으로 훑는다: Java `KeyPairGenerator`(`.initialize(N)`, `ECGenParameterSpec`), JS `generateKeyPair`(`modulusLength`, `namedCurve`), WebCrypto(`length`).
- 대상 확장자: Python `.py`, Java 계열 `.java .kt .kts .scala`, Go, JS/TS, C/C++, C#, 설정 파일(`.conf .cfg .cnf .ini .yaml .yml .toml .properties .xml` + `sshd_config` 등 이름). `.json` 은 스캔하지 않는다. `.txt .env .sh` 는 비밀키 헤더만 본다.
- 어떤 API 의 몇 번째 인자가 알고리즘·키 길이인지는 정규식 안에 박혀 있다(`code.py` 257~328행). 알고리즘 **상태** 판정은 `catalog.py` 데이터로 분리돼 있지만 **API 지식**은 코드다.

### 평가 지적별 판정

| 지적 | 판정 | 근거 (코드) |
|---|---|---|
| AST·데이터 흐름 없이 정규식으로 찾는다 | **해당** | 위 "현재 탐지 방식". |
| 변수에 알고리즘 이름을 담아 넘기면 놓친다 | **해당** | 규칙이 리터럴 따옴표를 요구한다: `hashlib.new\(\s*['\"]`(269행), `Cipher.getInstance\(\s*\"`(282행), `createHash\(\s*['\"]`(306행) 등. `hashlib.new(ALG)`, `Cipher.getInstance(ALG)` 는 아무것도 기록되지 않는다. |
| (관련 미탐) import 별칭 | **해당** | Python 해시 규칙은 `\bhashlib\.` 접두어를 요구한다(268행). `import hashlib as hl; hl.md5()`, `from hashlib import md5; md5()` 는 미탐. |
| (관련 미탐) 여러 줄에 걸친 호출 | **해당, 심각도 왜곡** | `rsa.generate_private_key\((?:[^)]*key_size...)?`(257행)는 한 줄 안에서만 `key_size` 를 찾는다. `key_size=1024` 가 다음 줄이면 크기 없는 `RSA`(quantum-vulnerable → 경고)로 기록되고, 실제 상태인 `RSA-1024`(broken → 실패, `catalog.classify` 199~202행)를 놓친다. |
| 외부 라이브러리 내부 암호를 놓친다 | **해당 (설계상)** | `SKIP_DIRS` 가 `vendor`, `third_party`, `node_modules` 등을 건너뛴다(18~19행). 의존성 매니페스트 분석이 없다: `package.json` 은 `.json` 이라 읽지 않고, `requirements.txt` 는 비밀키 검사만, `pom.xml`·`pyproject.toml` 은 설정 파일 규칙(SSH·TLS)만 적용된다. 보완 수단은 TLS 엔드포인트 스캔과 CBOMkit 결과 `merge` 뿐이다. 업계 조사상 매니페스트로 알 수 있는 것은 "이 암호 라이브러리를 쓴다"까지이며, 라이브러리 내부 호출은 정적 분석 도구들도 대부분 분석하지 않는다(아래 "업계 동향"). |
| 주석을 암호 사용으로 착각한다 | **코드 파일: 해당 / 설정 파일: 이미 해결** | 코드 파일에는 주석 처리가 전혀 없다. `# hashlib.md5(x)`, `// Cipher.getInstance("DES")`, docstring 예제가 모두 탐지된다. `_lookahead` 도 주석 줄을 읽어 `// kpg.initialize(1024)` 의 크기를 가져올 수 있다. 다만 규칙이 모두 API 호출 모양(`hashlib.md5`, `Cipher.getInstance("…")`)에 걸려 있어 주석 속 단어 "MD5" 만으로는 탐지되지 않는다(PQC 문자열 규칙 예외, 아래). 설정 파일 규칙은 `^\s*KexAlgorithms…`(331~334행), `^\s*(?:ssl_protocols|SSLProtocol)`(368행)처럼 줄 시작에 고정돼 `#` 주석 줄은 이미 제외되고, `ssl_protocols … ; # TLSv1` 의 꼬리 주석도 `[^;#\n]` 로 잘린다. |
| 테스트용 문자열을 착각한다 | **부분 해결** | 테스트 경로를 자동으로 구분하지 않는다. 사용자가 `.cbomignore`·`--exclude` 로 빼야 한다(`cli._ignore_file`, 129~137행). 이 저장소의 `.cbomignore` 는 `tests/ examples/ docs/` 를 뺀다. 코드 안 문자열 리터럴도 구분하지 않아 `log.warning("hashlib.md5() 금지")` 가 MD5 로 잡힌다. 공통 PQC 문자열 규칙 `PQC_STR`(242~244, 328행)은 **모든 코드 파일의 따옴표 안 PQC 이름**을 잡으므로 로그·테스트 문자열 `"ML-KEM-768"` 도 PQC 사용으로 기록된다. 이미 있는 장치: `.json` 미스캔(테스트 `test_json_and_unrelated_groups_not_flagged`), TLS 그룹 화이트리스트(`_tls_groups`, 352~364행), 이진 파일·2MB 초과 파일 건너뛰기. |

### 함께 발견한 사실

- **속성 수준 오탐:** `modes.ECB()` 규칙(273행)은 암호와 무관하게 항상 `AES-ECB` 를 만든다. 데모 `examples/demo-app/src/payment.py:26` 의 `Cipher(algorithms.AES(key), modes.ECB())` 는 `AES` 와 `AES-ECB` 두 구성요소를 만들고, `Cipher(algorithms.TripleDES(k), modes.ECB())` 는 `3DES` + 잘못된 `AES-ECB` 를 만든다.
- **비밀 값 노출 위험:** occurrence 의 `additionalContext` 에 해당 줄 원문을 200자까지 넣는다(`inventory._occ` 48~49행, `code.py` 466행). `DES.new(b"0123456789abcdef", …)` 처럼 같은 줄에 하드코딩된 키가 있으면 CBOM 에 들어간다. CLAUDE.md 규칙("키·비밀 값은 CBOM 에 쓰지 않는다")과 충돌한다 → 확인 필요 14.
- `cbom.inventory_from_boms()` 는 `type == "cryptographic-asset"` 인 구성요소만 남긴다(61행). 라이브러리(`type: "library"`) 구성요소를 추가하면 `check`·`merge` 에서 사라진다.
- `Inventory.merge_component()` 는 occurrence·`cryptoFunctions`·`cbom-scout:scanners` 만 합친다. `evidence.identity` 를 추가하면 병합 규칙이 필요하다.
- CI(`.github/workflows/ci.yml`)는 `ubuntu-latest` 만 돈다. Windows 동작은 자동 검증되지 않는다.
- 비밀키 헤더(`PRIVATE_KEY_RE`)는 주석·문자열 여부와 무관하게 탐지된다. 주석 속 비밀키도 유출이므로 **이 동작은 유지해야 한다.**

### 신뢰도를 담을 CycloneDX 1.6 표준 필드 (저장소 스키마로 확인)

`tests/schemas/bom-1.6.schema.json` 에서 확인한 사실:

| 필드 | 스키마 위치 | 내용 | 이 명세에서의 쓰임 |
|---|---|---|---|
| `component.evidence` | 1060행 → `componentEvidence`(2085행) | `identity`, `occurrences`, `callstack` 등 | 근거 전체 |
| `evidence.identity` | 2091~2107행 | 배열 권장(단일 객체 형식은 deprecated) | **배열**로 쓴다 |
| `identity[].field` | 4806~4812행, 필수 | 열거값 `group, name, version, purl, cpe, omniborId, swhid, swid, hash` | 알고리즘은 `name`, 라이브러리는 `purl` |
| `identity[].confidence` | 4814~4819행 | 0~1 수 | 구성요소 전체 신뢰도 |
| `identity[].concludedValue` | 4821~4824행 | 문자열 | 결론 값(알고리즘 이름, purl) |
| `identity[].methods[]` | 4826~4868행, `technique`·`confidence` 필수, `value` 선택 | `technique` 열거값 `source-code-analysis, binary-analysis, manifest-analysis, ast-fingerprint, hash-comparison, instrumentation, dynamic-analysis, filename, attestation, other` | 탐지 방식별 신뢰도 |
| `occurrences[]` | 2108~2150행, `additionalProperties: false` | `bom-ref, location, line, offset, symbol, additionalContext` 만 | 위치·줄·**API 기호(`symbol`)** |

- **occurrence 수준에는 신뢰도 표준 필드가 없다.** 따라서 신뢰도는 구성요소 수준 `evidence.identity` 에만 기록하고, 위치별 근거는 표준 `occurrence.symbol`(탐지한 API 이름)로 남긴다. 위치별 신뢰도를 자체 속성으로 보충하지 않는다(사용자 결정 — 확인 필요 3 참고).
- 참고: [CycloneDX 1.6 JSON — evidence](https://cyclonedx.org/docs/1.6/json/#components_items_evidence), [identity](https://cyclonedx.org/docs/1.6/json/#components_items_evidence_identity), [occurrences](https://cyclonedx.org/docs/1.6/json/#components_items_evidence_occurrences).

### 업계 동향 (`docs/research/crypto-detection-survey.md` 요약)

| 도구 | 탐지 방식 | 이 명세에 준 시사점 |
|---|---|---|
| [CBOMkit / sonar-cryptography](https://github.com/PQCA/sonar-cryptography) | 파서 기반, 규칙마다 특정 API 와 "어느 인자에 암호 값이 있는가"를 정의 | API 지식을 데이터로 분리. Java·Go 는 이미 정밀 지원 → `merge` 연동 유지 |
| [Cryptoscope](https://arxiv.org/pdf/2503.19531) (IBM 연구) | ANTLR 구문 트리 + 데이터·제어 흐름. 의존 라이브러리 내부는 분석 안 함 | 같은 함수·모듈 상수 추적은 1차, 함수 간은 후속. 보고 수치: Java 7개 프로젝트·기준 자산 97개에서 재현율 92%(부분 일치 98%), 정밀도 97%. 정답 라벨은 사람이 대대적으로 고쳐야 했음 |
| [GitHub CodeQL](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/) | 사용자 정의 질의로 CBOM 생성 | 큰 프로그램은 함수 경계를 넘는 흐름이 필요 → 후속 |
| [cdxgen](https://github.com/cdxgen/cdxgen) | 정적 분석 + `tracebom` 실행 중 추적 | 실행 중 추적은 이번 범위 밖, 후속 후보 |
| [OPSWAT MetaDefender CBOM](https://www.opswat.com/docs/mdcore/software-bill-of-materials/cbom) | API 호출·import 탐지, 매니페스트에서 암호 라이브러리 보고(선언 줄 근거) | 매니페스트는 **라이브러리 식별**까지. 라이브러리에서 알고리즘 추론은 하지 않음 |
| [SandboxAQ AQtive Guard](https://sandboxaq.com/products) | 파일·네트워크·실행 중 분석기 | 실행 중 추적은 범위 밖 |
| [Semgrep](https://docs.semgrep.dev/kb/rules/understand-severities) | 구문 트리 패턴, 규칙별 신뢰도 | 낮은 신뢰도 탐지는 기록하되 빌드를 막지 않는 정책 옵션 |
| [CryptoAPI-Bench](https://yaogroup.cs.vt.edu/papers/IEEE_SecDev19_CryptoAPI-Bench.pdf), [CamBench](https://arxiv.org/pdf/2204.06447) | 오용 탐지 벤치마크 | 평가 말뭉치의 사례 출처로만 참고, 범주별 정답 라벨·사람 검수 |

## 목표와 범위

단계를 둘로 나눈다. 1차 안에서도 1a(문맥·AST·신뢰도·말뭉치)와 1b(라이브러리 식별)를 별도 PR 로 나눌지는 확인 필요 15.

### 1차 — 이번에 하는 것

- **(A) Python AST 분석:** 표준 `ast` 로 `.py` 를 구문 분석해 주석·docstring·문자열 리터럴을 코드와 구분하고, import 별칭과 **같은 파일 안**(모듈·같은 함수) 상수·변수·기본값 인자를 따라가 간접 알고리즘 이름과 키 길이를 해석한다. 여러 줄 호출과 `Cipher(algorithms.X, modes.Y)` 결합을 처리한다. 구문 오류 파일은 정규식으로 대체한다.
- **(A') Python API 지식 베이스를 데이터로:** "어떤 API 의 몇 번째(또는 어떤 이름의) 인자가 알고리즘·키 길이·곡선·모드인가"를 데이터 파일로 둔다. Python AST 엔진은 이 데이터를 읽는다(라이브러리 추가 = 데이터 추가).
- **(B) 그 밖의 언어 문맥 인식:** Java 계열·Go·JS/TS·C/C++·C# 에 주석·문자열 리터럴을 구분하는 토크나이저를 두고, 매치 시작 위치가 주석·문자열 안이면 버린다. `_lookahead` 도 코드 부분만 본다.
- **(C) 신뢰도·탐지 방식을 CycloneDX 표준 필드로:** 구성요소 `evidence.identity[]` 의 `confidence` 와 `methods[].technique`·`methods[].confidence`, 위치별 `occurrence.symbol` 에 기록한다. 신뢰도·방식용 `cbom-scout:` 자체 속성은 만들지 않는다.
- **(C') 신뢰도 정책 옵션:** 정책 파일에 선택 키를 두어, 신뢰도가 기준 미만인 자산은 기록하되 빌드를 실패시키지 않게(조치 상한 `info`) 할 수 있다. 내장 정책에는 넣지 않아 기본 동작은 그대로다.
- **(D) 테스트·예제 경로 구분 표시:** 발견 위치가 테스트·예제 경로인지 판정해 구성요소에 범위를 기록하고 리포트에 표시한다. **정책 판정·종료 코드는 바꾸지 않는다.**
- **(E) 암호 라이브러리 식별(매니페스트):** `requirements*.txt`, `pyproject.toml`, `package.json`, `pom.xml`, `go.mod` 에서 알려진 암호 라이브러리를 찾아 **이름·버전·선언 위치**를 CycloneDX `library` 구성요소로 기록하고 근거를 `manifest-analysis` 로 남긴다. 여기까지만 한다.
- **(F) 기존 엔진 유지:** 기존 정규식 동작을 그대로 쓰는 엔진 선택 옵션(비교·비상용).
- **(G) 평가용 말뭉치:** 범주별 정답 라벨(사람 검수)이 달린 말뭉치와, 엔진별 정밀도·재현율을 범주별로 내는 평가 도구.
- README "한계와 보완 방법" 절과 CLI 도움말, 정책 예시 갱신.

### 1차 — 이번에 하지 않는 것

- **라이브러리 식별 이상의 의존성 분석:** 라이브러리 내부 호출 추적, 라이브러리 → 알고리즘 추론, 라이브러리 자체 판정(예: 단종 `pycrypto` 경고, BouncyCastle PQC 지원 버전 여부), 알려진 라이브러리에 붙이는 참고 정보(확인 필요 17), 라이브러리와 알고리즘 구성요소 사이 `dependencies` 연결, 개발·전이 의존성 구분, lock 파일(`package-lock.json`, `poetry.lock`, `go.sum`), Gradle·`.csproj`·Cargo 매니페스트.
- 파일을 넘는 데이터 흐름(다른 모듈의 상수 import, 함수 간 인자 전달), 클래스 속성(`self.ALG`) 해석, f-string·문자열 연결 해석.
- Python 외 언어의 상수 전파(Java `static final`, Go `const`, JS `const`) — 확인 필요 10.
- Python 외 언어 정규식 규칙의 데이터화 — 확인 필요 18.
- tree-sitter 등 외부 파서 도입 — 확인 필요 1.
- 실행 중 추적(cdxgen `tracebom`, 상용 제품의 런타임 분석기 방식)과 바이너리 분석.
- CBOMkit 자동 실행·병합 — 확인 필요 16.
- 범위(테스트·예제)를 정책 판정에 반영하는 기능.
- `catalog.py` 판정 기준 변경. 인증서·TLS 스캐너 변경. 정책 파일 형식은 선택 키 하나 추가 외 변경 없음.
- 평가의 다른 항목(오픈소스 성숙도, README 템플릿 문구, KMS·컨테이너·SSH 스캐너).

### 후속 단계 후보 (우선순위 순, 이번 명세의 완료 기준 아님)

1. Java/Go/JS/C# 같은 파일 문자열 상수 전파. 정규식 규칙의 API 지식도 데이터로 이전.
2. Python 파일 간·함수 간 상수 해석(같은 패키지의 `constants.py`, 인자 전달), 클래스 속성.
3. 라이브러리 지식 확장: 알려진 라이브러리 참고 정보(liboqs, BouncyCastle PQC 지원 버전 등), 라이브러리 상태 판정, 라이브러리 → 제공 알고리즘 연결, 개발·전이 의존성 구분, lock 파일·Gradle·NuGet·Cargo.
4. 상위 API 규칙: JWT `algorithm="RS256"`/`alg`, liboqs 클래스(`oqs.KeyEncapsulation`), `ssl.PROTOCOL_TLSv1`, `requests`/`urllib3` TLS 설정.
5. CBOMkit 결과 자동 병합(Java·Go 정밀 분석 연동).
6. 정책에서 범위 사용(테스트 전용 상한), 사용자 정의 테스트 경로 패턴.
7. 실행 중 추적(협상된 TLS 스위트·로드된 암호 라이브러리 수집).
8. 말뭉치 지표를 근거로 tree-sitter 선택 설치 검토. SARIF 출력에 신뢰도 반영.
9. `hashlib.md5(usedforsecurity=False)` 같은 비보안 용도 표시, C 전처리기 `#if 0`, JS 템플릿 `${}` 보간·정규식 리터럴.

## 사용자 시나리오

1. 개발자가 `# hashlib.md5(data) 대신 sha256 사용` 이라는 주석을 남긴 PR 을 올리면, cbom-scout 는 MD5 를 보고하지 않는다.
2. `HASH = "sha1"` 을 정의하고 `hashlib.new(HASH, d)` 로 쓰는 코드는 SHA-1 위반으로 그 호출 줄에 주석이 달린다.
3. 보안 담당자는 CBOM 의 `evidence.identity` 를 다른 CycloneDX 도구(예: Dependency-Track)에서도 그대로 읽어 신뢰도가 낮은 발견만 따로 검토한다.
4. 도입 초기 팀은 정책에 신뢰도 기준을 넣어, 확신이 낮은 발견은 리포트에만 남기고 빌드는 막지 않는다.
5. 리포트에서 `tests/` 에서만 나온 자산에 "(테스트·예제 전용)" 표시가 붙어 있어 운영 코드 위반부터 처리할 수 있다.
6. 전사 인벤토리 담당자는 `requirements.txt`·`pom.xml` 에서 BouncyCastle·cryptography 같은 암호 라이브러리를 **어디서 어떤 버전으로 쓰는지** CBOM 으로 모은다.
7. 도입 담당자는 평가 도구로 "주석·문자열 오탐 0건, 간접 호출 재현율 90% 이상"을 범주별 수치로 보고한다.
8. 새 엔진에서 문제가 생기면 `--engine regex` 로 이전 동작으로 돌아간다.

## 용어와 규칙 (요구사항)

### 문맥

- **코드 문맥:** 주석·문자열 리터럴 밖의 소스 텍스트.
- **Python:** 주석(`#`)은 AST 에 없으므로 제외. **docstring**(모듈·클래스·함수 본문의 첫 문장이 문자열 식인 것)은 제외. 그 밖의 문자열 리터럴은 "API 인자 위치"(지식 베이스에 있는 암호 API 호출의 인자, 또는 그 인자로 쓰인 변수에 대입된 값)일 때만 알고리즘 이름으로 쓴다.
- **그 밖의 언어 — 최소 지원 문법:** `//` 줄 주석, `/* … */` 블록 주석(여러 줄, Javadoc `/** */` 포함), 백슬래시 이스케이프가 있는 `"…"`·`'…'`, Go 원시 문자열과 JS/TS 템플릿 리터럴 `` `…` ``, Java/Kotlin 텍스트 블록 `"""…"""`, C# verbatim `@"…"`(`""` 이스케이프). 닫히지 않은 문자열은 그 줄 끝에서, 닫히지 않은 블록 주석은 파일 끝에서 끝난 것으로 본다. 템플릿 리터럴 `${}` 보간 안쪽, JS 정규식 리터럴, C++ 원시 문자열 `R"(…)"`, 중첩 블록 주석(Kotlin·Scala)은 1차에서 정의하지 않는다(알려진 한계로 README 에 적는다).
- 정규식 규칙의 매치는 **매치 시작 위치가 코드 문맥일 때만** 기록한다. 예외: `PQC_STR` 규칙은 원래 문자열 리터럴을 대상으로 하므로 "주석 밖의 문자열 리터럴"이면 기록한다(신뢰도 0.3).
- 설정 파일 규칙과 비밀키 헤더 탐지는 바꾸지 않는다.

### 신뢰도와 탐지 방식 — 표준 필드 기록 규칙

발견 하나마다 (탐지 방식 `technique`, 신뢰도 수치)를 정한다. 수치는 아래 표(확인 필요 3 에서 승인)이며, 코드에 흩어 두지 않고 한 곳의 데이터로 둔다.

| 상황 | `technique` | 신뢰도 |
|---|---|---|
| Python AST: 지식 베이스 API 호출 + 리터럴 인자, 또는 import 별칭 해석 | `ast-fingerprint` | 0.9 |
| Python AST: 같은 파일에서 값이 하나뿐인 상수·변수로 해석 | `ast-fingerprint` | 0.9 |
| Python AST: 후보 값이 여럿(재대입·분기)이거나 함수 기본값 인자로 해석 | `ast-fingerprint` | 0.6 |
| Python AST: `Cipher(...)` 와 결합하지 못한 단독 `modes.ECB()` | `ast-fingerprint` | 0.6 |
| Python 구문 분석 실패로 정규식 대체 | `source-code-analysis` | 0.6 |
| 그 밖의 언어: 코드 문맥이 확인된 정규식 매치, 설정 파일 규칙, 비밀키 헤더 | `source-code-analysis` | 0.9 |
| `PQC_STR` 규칙(모든 언어, Python 포함) | 해당 엔진의 값 | 0.3 |
| `--engine regex` (기존 동작) | `source-code-analysis` | 0.6 |
| 의존성 매니페스트 | `manifest-analysis` | 0.9 |

**알고리즘·프로토콜·키 자료 구성요소** (코드 스캐너 발견이 하나 이상 있는 것):
- `evidence.identity` 는 길이 1 배열이고, 그 원소는 `field: "name"`, `concludedValue` = 구성요소 `name`, `methods` = 이 구성요소의 발견에 쓰인 `technique` 마다 하나씩(`technique` 알파벳순), 각 `methods[].confidence` = 그 방식 발견들의 최댓값, `confidence` = `methods[].confidence` 의 최댓값.
- 각 occurrence 의 `symbol` = 탐지 근거 API 의 정규 이름(별칭을 푼 이름. 예: `from hashlib import md5; md5()` → `hashlib.md5`, Java `Cipher.getInstance`). `PQC_STR`·설정 파일·비밀키 헤더 발견과 `--engine regex` 발견에는 `symbol` 을 넣지 않는다. 같은 (location, line) 에 대한 occurrence 는 구성요소당 하나다.
- 인증서·TLS 스캐너로만 나온 구성요소에는 `evidence.identity` 를 넣지 않는다(이번 범위 밖).

**라이브러리 구성요소:** `evidence.identity` = 길이 1 배열, 원소는 `field: "purl"`, `concludedValue` = purl, `confidence: 0.9`, `methods: [{"technique": "manifest-analysis", "confidence": 0.9}]`.

**금지:** `cbom-scout:confidence`, `cbom-scout:detection` 등 신뢰도·탐지 방식을 담는 `cbom-scout:` 속성은 만들지 않는다.

**병합(`merge`·`check`·`--merge`):** 같은 `bom-ref` 의 두 구성요소를 합치면 `field` 가 같은 identity 원소끼리 합친다 — `methods` 는 `technique` 별 최댓값, `confidence` 는 최댓값, `concludedValue` 는 앞의 것. 한쪽에만 identity 가 있으면 그것을 쓴다.

### 신뢰도 정책 옵션

- 정책 JSON 최상위 선택 키 `min_confidence`(0~1 수, 이름은 확인 필요 7). 있으면, `cryptographic-asset` 중 `evidence.identity` 에서 `field == "name"` 인 원소의 `confidence` 가 이 값 **미만**인 구성요소는 정책 평가 조치가 `info` 를 넘지 않는다(`warn`·`fail` → `info`, `pass`·`info` 는 그대로). 조치가 낮아진 경우 메시지 끝에 `(탐지 신뢰도 낮음 — 판정 보류)` 를 붙인다.
- `evidence.identity` 가 없는 구성요소(다른 도구 CBOM, 인증서·TLS)는 낮추지 않는다.
- 키가 없으면(내장 정책 `nist-ir8547`·`strict` 포함) 기존과 똑같이 평가한다. 값이 0~1 수가 아니면 종료 코드 2.

### 범위 (테스트·예제)

- 파일 경로 발견마다 `test` / `example` / `production` 중 하나로 분류한다. 기준 경로는 확인 필요 6(추천: **스캔 루트** 기준 상대경로).
- 기본 패턴(확인 필요 5 의 추천안):
  - `test`: 경로 구성요소 중 하나가 `test`, `tests`, `__tests__`, `testdata`, `spec` (대소문자 무시) / 파일 이름 `test_*.py`, `*_test.py`, `conftest.py`, `*_test.go`, `*Test.java`, `*Tests.java`, `*Test.kt`, `*Tests.cs`, `*Test.cs`, `*.test.{js,jsx,ts,tsx,mjs,cjs}`, `*.spec.{js,jsx,ts,tsx,mjs,cjs}`
  - `example`: 경로 구성요소 중 하나가 `example`, `examples`, `sample`, `samples`, `demo`, `demos` (대소문자 무시)
  - 둘 다 해당하면 `test`.
- 구성요소 속성 `cbom-scout:scope` = 그 구성요소의 파일 경로 발견들의 분류 집합을 알파벳순 쉼표로 이은 값(예: `production,test`). CycloneDX 에 경로 분류용 표준 필드가 없어 자체 속성으로 둔다. 파일 경로 발견이 없는 구성요소(TLS 엔드포인트)는 속성을 달지 않는다. 인증서·키 파일 발견도 분류한다.
- 병합 시 `cbom-scout:scope` 는 집합 합.
- 패턴 목록은 한 곳의 데이터로 둔다.

### 암호 라이브러리 식별 (매니페스트)

- 대상 파일(스캔 트리 안 어디든, `SKIP_DIRS`·`.cbomignore`·`--exclude` 적용): 이름이 `requirements*.txt` 인 파일, `pyproject.toml`(`[project].dependencies`, `[project.optional-dependencies]`, `[tool.poetry.dependencies]`, `[tool.poetry.group.*.dependencies]`), `package.json`(`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`), `pom.xml`(`<dependencies>/<dependency>`), `go.mod`(`require`).
- 암호 라이브러리 목록은 데이터 파일에 둔다(라이브러리 이름·생태계만. 상태·제공 알고리즘·참고 정보는 넣지 않는다). 초기 목록은 확인 필요 11.
- 구성요소 형식(확인 필요 12 추천안): `type: "library"`, `bom-ref` = purl, `name`, Maven 은 `group`, 정확히 고정된 버전이면 `version` 과 `purl@version`, 아니면 `version` 없이 purl 에 버전을 넣지 않고 속성 `cbom-scout:version-spec` 에 원문 지정자를 기록한다. 이름 정규화는 purl 규격을 따른다(PyPI 는 소문자·`_`→`-`, npm 범위 패키지는 `%40scope/name`). ([purl spec](https://github.com/package-url/purl-spec), [PEP 503 정규화](https://peps.python.org/pep-0503/#normalized-names))
- 근거: `evidence.identity`(위 규칙), `evidence.occurrences` = `{location: <매니페스트 경로>, line: <선언 줄>}`. 속성은 `cbom-scout:scanners = deps`, `cbom-scout:scope`, (필요 시) `cbom-scout:version-spec` 뿐이다.
- 라이브러리 구성요소에는 `cryptoProperties`, `cbom-scout:status`, `cbom-scout:policy-action` 이 없고, 정책 평가·콘솔 요약 자산 수·종료 코드에 영향을 주지 않는다. 라이브러리를 찾았다고 알고리즘 구성요소나 `dependencies` 연결을 만들지 않는다.

## 완료 기준 (테스터가 그대로 검증)

공통 전제:
- `T` 는 빈 임시 디렉터리다. 특별한 말이 없으면 작업 디렉터리를 `T` 로 두고 `cbom-scout scan . -o out.json --markdown r.md --html r.html --fail-on never --no-github-summary` 를 실행한다(이하 "기본 스캔"). 환경 변수 `GITHUB_ACTIONS`·`GITHUB_STEP_SUMMARY` 는 지운다.
- "구성요소 X" 는 `out.json` 의 `components[]` 중 `name == X` 인 것, "발견 (p, n)" 은 그 구성요소의 `evidence.occurrences[]` 에 `location == p`, `line == n` 인 원소가 있다는 뜻이다. "속성 k=v" 는 `properties[]` 에 `{"name": "cbom-scout:k", "value": "v"}` 가 있다는 뜻이다.
- **"근거 [AST c]"** 는 그 구성요소의 `evidence.identity` 원소(`field == "name"`)의 `methods` 에 `{"technique": "ast-fingerprint", "confidence": c}` 가 있다는 뜻, **"근거 [SRC c]"** 는 `technique: "source-code-analysis"`, **"근거 [MAN c]"** 는 `technique: "manifest-analysis"`. **"신뢰도 c"** 는 그 identity 원소의 `confidence == c`. "근거 [AST c] 만" 은 `methods` 가 그 하나뿐이라는 뜻.
- 파일 내용의 `⏎` 는 줄바꿈이다. 표시가 없으면 LF, UTF-8(BOM 없음).
- "main 결과" 는 커밋 `5bbfbeb` 코드로 같은 명령을 돌린 결과다.

### 1a-A. Python — 오탐 제거

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-1 | 주석 속 API 는 기록하지 않는다. | `T/app/a.py` = `import hashlib⏎# hashlib.md5(data) 는 쓰지 말 것⏎x = 1  # 예: hashlib.sha1(b"")⏎h = hashlib.sha256(b"")⏎`. 기본 스캔 → 구성요소 `MD5`·`SHA-1` 없음. 구성요소 `SHA-256` 에 발견 (`app/a.py`, 4), 근거 [AST 0.9] 만, 신뢰도 0.9. |
| AC-2 | docstring 속 API 는 기록하지 않는다. | `T/app/doc.py` = `"""모듈 설명: hashlib.md5(b"x") 예제"""⏎def f():⏎    """>>> rsa.generate_private_key(public_exponent=65537, key_size=1024)"""⏎    return 1⏎class C:⏎    """Cipher(algorithms.TripleDES(k), modes.ECB())"""⏎`. 기본 스캔 → `assetType == "algorithm"` 인 구성요소가 0개. |
| AC-3 | API 인자 위치가 아닌 문자열 리터럴 속 API 는 기록하지 않는다. | `T/app/s.py` = `import logging⏎logging.warning("hashlib.md5() 는 금지")⏎MSG = 'Cipher(algorithms.TripleDES(k), modes.ECB())'⏎`. 기본 스캔 → 구성요소 `MD5`, `3DES`, `3DES-ECB`, `AES-ECB` 모두 없음. |
| AC-4 | PQC 문자열은 코드 문맥 문자열이면 신뢰도 0.3 으로 기록하고, 주석·docstring 이면 기록하지 않는다. | `T/app/p.py` = `print("ML-KEM-768 지원 예정")⏎`, `T/app/q.py` = `"""ML-DSA-65 도입 검토"""⏎# "SLH-DSA-SHA2-128s"⏎`. 기본 스캔 → 구성요소 `ML-KEM-768` 에 발견 (`app/p.py`, 1), 근거 [AST 0.3] 만, 신뢰도 0.3, 그 occurrence 에 `symbol` 없음. `ML-DSA-65`·`SLH-DSA` 로 시작하는 구성요소 없음. |

### 1a-A. Python — 미탐 복구

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-5 | import 별칭을 해석하고, `symbol` 에는 별칭을 푼 정규 이름을 쓴다. import 문 자체는 발견이 아니다. | `T/a.py` = `import hashlib as hl⏎from hashlib import md5, sha1 as s1⏎hl.sha512(b"")⏎md5(b"")⏎s1(b"")⏎`. 기본 스캔 → 발견 `SHA-512`(`a.py`,3, `symbol == "hashlib.sha512"`), `MD5`(`a.py`,4, `symbol == "hashlib.md5"`), `SHA-1`(`a.py`,5, `symbol == "hashlib.sha1"`). 셋 다 근거 [AST 0.9]. 1·2행을 가리키는 발견은 없다. |
| AC-6 | 모듈 별칭으로 부른 cryptography API 를 해석한다. | `T/k.py` = `from cryptography.hazmat.primitives.asymmetric import rsa as r⏎k = r.generate_private_key(public_exponent=65537, key_size=1024)⏎`. 기본 스캔 → 구성요소 `RSA-1024` 발견 (`k.py`, 2), 속성 `status=broken`, 근거 [AST 0.9]. |
| AC-7 | 여러 줄 호출의 인자를 읽는다. 발견 줄은 호출이 시작되는 줄이다. | `T/m.py` = `from cryptography.hazmat.primitives.asymmetric import rsa⏎key = rsa.generate_private_key(⏎    public_exponent=65537,⏎    key_size=1024,⏎)⏎`. 기본 스캔 → 구성요소 `RSA-1024` 발견 (`m.py`, 2), `status=broken`. 이름이 정확히 `RSA` 인 구성요소 없음. 같은 트리를 `--engine regex` 로 스캔하면 구성요소 `RSA` 가 있고 `RSA-1024` 는 없다(기존 동작 보존). |
| AC-8 | 같은 파일 안에서 값이 하나뿐인 상수(문자열·정수)를 따라간다. 발견 줄은 사용하는 줄이다. | `T/c.py` = `import hashlib⏎HASH_ALG = "sha1"⏎KEY_BITS = 1024⏎def f(d):⏎    return hashlib.new(HASH_ALG, d)⏎from Crypto.PublicKey import RSA⏎k = RSA.generate(KEY_BITS)⏎`. 기본 스캔 → `SHA-1` 발견 (`c.py`,5, `symbol == "hashlib.new"`), 신뢰도 0.9; `RSA-1024` 발견 (`c.py`,7), 신뢰도 0.9. 2·3행 발견 없음. |
| AC-9 | 후보가 여럿이거나 기본값 인자로만 정해지면 모든 후보를 신뢰도 0.6 으로 기록한다. | `T/d.py` = `import hashlib⏎def digest(data, alg="md5"):⏎    return hashlib.new(alg, data)⏎MODE = "sha256"⏎if cond:⏎    MODE = "sha1"⏎hashlib.new(MODE, b"")⏎`. 기본 스캔 → `MD5` 발견 (`d.py`,3), `SHA-256` 발견 (`d.py`,7), `SHA-1` 발견 (`d.py`,7). 세 구성요소 모두 근거 [AST 0.6] 만, 신뢰도 0.6. |
| AC-10 | 해석할 수 없는 인자는 기록하지 않고 오류도 내지 않는다(확인 필요 9 추천안). | `T/u.py` = `import hashlib⏎hashlib.new(user_input, b"")⏎hashlib.new(get_alg(), b"")⏎hashlib.new(f"sha{n}", b"")⏎`. 기본 스캔 → 종료 코드 0, `algorithm` 구성요소 0개, stderr 에 `Traceback` 없음. |
| AC-11 | `Cipher(algorithms.X(…), modes.Y(…))` 는 하나의 `X-Y` 로 기록한다. | `T/e.py` = `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes⏎c1 = Cipher(algorithms.TripleDES(k), modes.ECB())⏎c2 = Cipher(algorithms.AES(k), modes.CBC(iv))⏎`. 기본 스캔 → 구성요소 `3DES-ECB`(`e.py`,2, `status=broken`), `AES-CBC`(`e.py`,3). 이름이 `AES-ECB`, `AES`, `3DES` 인 구성요소 없음. |
| AC-12 | 기존 Python 규칙이 잡던 한 줄 리터럴 호출은 AST 엔진도 모두 같은 이름으로 잡는다. | `T/all.py` = `hashlib.md5(b"")⏎hashlib.new('sha512')⏎hashes.SHA384()⏎rsa.generate_private_key(public_exponent=65537, key_size=2048)⏎RSA.generate(3072)⏎dsa.generate_private_key(key_size=1024)⏎dh.generate_parameters(generator=2, key_size=2048)⏎ec.generate_private_key(ec.SECP384R1())⏎ec.ECDSA(hashes.SHA256())⏎Ed25519PrivateKey.generate()⏎AESGCM(k)⏎ChaCha20Poly1305(k)⏎DES3.new(k, DES3.MODE_CBC)⏎ARC4.new(k)⏎` (import 없음). 기본 스캔과 `--engine regex` 스캔의 `algorithm` 구성요소 이름 집합이 같다. |
| AC-13 | Python API 지식이 데이터로 분리돼 있다. | (1) `src/cbom_scout/` 아래에 Python API 지식 베이스 데이터 파일(JSON 등, 경로는 README 또는 해당 모듈 docstring 에 적힘)이 있고, AC-12 의 각 API(`hashlib.md5`, `hashlib.new`, `hashes.SHA384`, `rsa.generate_private_key`, `RSA.generate`, `dsa.generate_private_key`, `dh.generate_parameters`, `ec.generate_private_key`, `ec.ECDSA`, `Ed25519PrivateKey`, `AESGCM`, `ChaCha20Poly1305`, `DES3.new`, `ARC4.new`)에 해당하는 항목이 있다. (2) `src/cbom_scout/` 아래 `.py` 파일 중 `import ast` 또는 `from ast` 를 포함하는 파일에는 문자열 `generate_private_key`, `generate_parameters`, `ChaCha20Poly1305` 이 없다. |

### 1a-A. Python — 대체·인코딩

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-14 | 구문 오류 파일은 정규식으로 대체하되 줄 전체가 `#` 주석인 줄은 제외한다. 다른 파일 분석은 영향이 없다. | `T/legacy.py` = `print "hello"⏎import hashlib⏎# hashlib.sha1(x)⏎hashlib.md5(x)⏎`, `T/ok.py` = `import hashlib⏎hashlib.sha384(b"")⏎`. 기본 스캔에 `-v` 추가 → `MD5` 발견 (`legacy.py`,4), 근거 [SRC 0.6] 만. `SHA-1` 없음. `SHA-384` 는 근거 [AST 0.9]. stderr 에 `구문 분석 실패` 와 `legacy.py` 가 한 줄에 함께 나온다. `-v` 없이는 그 문구가 없다. |
| AC-15 | UTF-8 BOM 이 있는 파일도 AST 로 분석한다. | `T/bom.py` 바이트 = `EF BB BF` + `import hashlib⏎hashlib.md5(b'')⏎`. 기본 스캔 → `MD5` 발견 (`bom.py`,2), 근거 [AST 0.9]. |
| AC-16 | 실행 중인 Python 이 모르는 새 문법이 있어도 중단하지 않는다. | `T/new.py` = `import hashlib⏎type Alias = int⏎hashlib.md5(b"")⏎`. Python 3.10·3.11 에서는 `MD5` 발견 (`new.py`,3) 근거 [SRC 0.6]; 3.12 이상에서는 근거 [AST 0.9]. 어느 버전이든 종료 코드 0, `Traceback` 없음. |

### 1a-B. 그 밖의 언어 — 주석·문자열 문맥

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-17 | Java 주석(줄·블록·Javadoc·같은 줄 꼬리 주석) 속 API 는 기록하지 않는다. | `T/A.java` = `import javax.crypto.Cipher;⏎public class A {⏎  // Cipher c = Cipher.getInstance("DES");⏎  /* MessageDigest.getInstance("MD5");⏎     Signature.getInstance("SHA1withRSA"); */⏎  /** Cipher.getInstance("RC4") */⏎  Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // 예전: Cipher.getInstance("DESede")⏎}⏎`. 기본 스캔 → `algorithm` 구성요소는 `AES-GCM` 하나뿐, 발견 (`A.java`,7, `symbol == "Cipher.getInstance"`), 근거 [SRC 0.9] 만. |
| AC-18 | Java 문자열·텍스트 블록 속 API 는 기록하지 않고, 문자열 안의 `//` 를 주석으로 오인하지 않는다. | `T/B.java` = `class B {⏎  String doc = "Cipher.getInstance(\"DES\") 금지";⏎  String tb = """⏎    MessageDigest.getInstance("MD5")⏎    """;⏎  String u = "http://x"; MessageDigest md = MessageDigest.getInstance("SHA-256");⏎}⏎`. 기본 스캔 → `algorithm` 구성요소는 `SHA-256` 하나뿐, 발견 (`B.java`,6). |
| AC-19 | 앞보기(`_lookahead`)는 주석 줄을 읽지 않는다. | `T/K.java` = `class K { void k() throws Exception {⏎  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");⏎  // g.initialize(1024);⏎  g.initialize(3072);⏎}}⏎`. 기본 스캔 → 구성요소 `RSA-3072` 있음, `RSA-1024` 없음. |
| AC-20 | Go 주석과 원시 문자열 속 API 는 기록하지 않는다. | `T/g.go` = `package main⏎import ("crypto/sha1"; "crypto/sha256")⏎// sha1.Sum(x)⏎var s = \`md5.New()\`⏎func f(b []byte) { _ = sha256.Sum256(b) }⏎`. 기본 스캔 → `algorithm` 구성요소는 `SHA-256` 하나뿐. |
| AC-21 | JS/TS 주석·문자열·템플릿 리터럴(보간 없음) 속 API 는 기록하지 않는다. | `T/w.ts` = `import { createHash, createCipheriv } from "crypto";⏎// createHash('md5')⏎/* createCipheriv('des-ede3-cbc', k, iv) */⏎const s = "createHash('sha1')";⏎const t = \`createHash('sha1')\`;⏎export const h = createHash('sha512');⏎`. 기본 스캔 → `algorithm` 구성요소는 `SHA-512` 하나뿐, 발견 (`w.ts`,6). |
| AC-22 | C·C# 주석과 C# verbatim 문자열을 구분한다. 같은 줄의 주석 뒤 코드는 기록한다. | `T/x.c` = `#include <openssl/evp.h>⏎/* EVP_md5() */ EVP_DigestInit(ctx, EVP_sha256());⏎`, `T/y.cs` = `// MD5.Create()⏎var s = @"SHA1.Create() ""q""";⏎var h = SHA256.Create();⏎`. 기본 스캔 → `algorithm` 구성요소 이름 집합 = `{SHA-256}`, 발견 (`x.c`,2) 와 (`y.cs`,3). |
| AC-23 | 다른 언어의 PQC 문자열도 주석 밖이면 신뢰도 0.3, 주석이면 제외. | `T/P.java` = `class P { void p() { log.info("ML-KEM-768 준비 중"); } }⏎// "ML-DSA-65"⏎`. 기본 스캔 → `ML-KEM-768` 발견 (`P.java`,1), 근거 [SRC 0.3] 만. `ML-DSA-65` 없음. |
| AC-24 | 닫히지 않은 주석·문자열에서 중단하지 않는다. | `T/o1.js` = `/* 열린 주석⏎createHash('md5')⏎`, `T/o2.js` = `const s = "abc⏎createHash('md5')⏎`. 기본 스캔 → 종료 코드 0, `Traceback` 없음. `MD5` 구성요소의 발견은 (`o2.js`,2) 하나뿐이다. |
| AC-25 | 비밀키 헤더는 주석·문자열·docstring 안에서도 계속 탐지한다. | `T/s.java` = `// -----BEGIN RSA PRIVATE KEY-----⏎`, `T/s.py` = `"""⏎-----BEGIN EC PRIVATE KEY-----⏎"""⏎`. 기본 스캔 → `assetType == "related-crypto-material"` 이고 `relatedCryptoMaterialProperties.type == "private-key"` 인 구성요소가 두 위치(`s.java`, `s.py`) 모두에 있고 속성 `status=broken`. |
| AC-26 | 설정 파일 동작은 그대로다. | `T/sshd_config` = `# KexAlgorithms diffie-hellman-group1-sha1⏎KexAlgorithms curve25519-sha256⏎`, `T/nginx.conf` = `ssl_protocols TLSv1.2 TLSv1.3; # TLSv1⏎`. 기본 스캔 → `DH-1024` 없음, `X25519` 있음(근거 [SRC 0.9]), 프로토콜 구성요소 `status=ok`. |

### 1a-C. 신뢰도 표준 필드·정책 옵션

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-27 | 여러 방식으로 발견된 구성요소는 방식별 최댓값과 전체 최댓값을 표준 필드에 기록한다. | `T/p.py` = `print("ML-KEM-768")⏎`, `T/B.java` = `class B { void b() throws Exception { KEM k = KEM.getInstance("ML-KEM-768"); } }⏎`. 기본 스캔 → 구성요소 `ML-KEM-768` 의 `evidence.identity` 는 길이 1 배열, 원소 = `{"field": "name", "concludedValue": "ML-KEM-768", "confidence": 0.9, "methods": [{"technique": "ast-fingerprint", "confidence": 0.3}, {"technique": "source-code-analysis", "confidence": 0.9}]}` (키 순서 무관, `methods` 는 이 순서). |
| AC-28 | 신뢰도·탐지 방식용 자체 속성이 없고, 코드 스캐너 구성요소에는 모두 표준 identity 가 있다. | AC-1~AC-26 의 모든 기본 스캔 `out.json` 에서: (1) 어떤 구성요소의 `properties[].name` 에도 `confidence`·`detection`·`technique` 문자열이 들어간 것이 없다. (2) `cbom-scout:scanners` 에 `code` 가 들어 있는 구성요소는 모두 `evidence.identity` 가 배열이고 `field == "name"` 원소가 정확히 하나, 그 `confidence` 와 모든 `methods[].confidence` 가 0 이상 1 이하, `methods[].technique` 가 `ast-fingerprint`·`source-code-analysis` 중 하나다. |
| AC-29 | 인증서·TLS 스캐너로만 나온 구성요소에는 identity 를 넣지 않는다. | 저장소 루트에서 `cbom-scout scan examples/demo-app/certs -o out.json --fail-on never --no-github-summary` → `cbom-scout:scanners` 가 `certs` 뿐인 구성요소에는 `evidence.identity` 가 없다. |
| AC-30 | 출력 CBOM 은 CycloneDX 1.6 스키마를 통과한다. | AC-1~AC-50 에서 만든 모든 `out.json`·`m.json`, 그리고 저장소 루트에서 `cbom-scout scan examples/demo-app -o demo.json --fail-on never` 의 `demo.json` 을 `tests/schemas/bom-1.6.schema.json` 으로 검증 → 오류 0건 (`test_cbom_schema_valid` 와 같은 검증기). |
| AC-31 | 상수 해석 결과에 알고리즘 이름 외의 값은 기록하지 않는다. | `T/z.py` = `import hashlib⏎SECRET_KEY = "s3cr3t-Pa55w0rd-XYZ"⏎ALG = "sha1"⏎hashlib.new(ALG, SECRET_KEY.encode())⏎`. 기본 스캔에 `-v` → `out.json`, `r.md`, `r.html`, stdout, stderr 어디에도 `s3cr3t-Pa55w0rd-XYZ` 가 없다. `SHA-1` 발견 (`z.py`,4). |
| AC-32 | 정책 `min_confidence` 미만인 자산은 조치가 `info` 로 제한되고 메시지에 표시된다. 키가 없으면 기존과 같다. | AC-9 의 `T/d.py` 트리. `T/p.json` = `src/cbom_scout/policies/nist-ir8547.json` 내용에 최상위 `"min_confidence": 0.7` 을 더한 것. (1) `cbom-scout scan . -o out.json --markdown r.md --no-github-summary` (기본 정책, `--fail-on fail`) → 종료 코드 1, `MD5` 속성 `policy-action=fail`. (2) 같은 명령에 `--policy p.json` → 종료 코드 0, `MD5`·`SHA-1` 속성 `policy-action=info`, `r.md` 의 `MD5` 행에 `(탐지 신뢰도 낮음 — 판정 보류)` 가 있다. (3) `"min_confidence": 0.5` 로 바꾸면 (1) 과 같은 종료 코드 1. |
| AC-33 | identity 가 없는 구성요소는 `min_confidence` 로 낮추지 않고, 잘못된 값은 오류다. 내장 정책은 바뀌지 않는다. | (1) `cbom-scout check docs/sample-cbom.json --policy p.json --fail-on never --no-github-summary` (AC-32 의 `p.json`, 값 0.7) 의 stderr 요약 줄이 `--policy nist-ir8547` 로 돌린 요약 줄과 같다. (2) `"min_confidence": "high"` 와 `1.5` 인 정책 파일로 각각 스캔 → 종료 코드 2, stderr 에 `min_confidence` 가 있다, `Traceback` 없음. (3) `git diff 5bbfbeb -- src/cbom_scout/policies/` 가 비어 있다. |

### 1a-D. 테스트·예제 범위

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-34 | 발견 위치에 따라 `scope` 속성을 단다. | `T/src/app.py` = `import hashlib⏎hashlib.md5(b"")⏎`, `T/tests/test_app.py` = `import hashlib⏎hashlib.md5(b"")⏎hashlib.sha1(b"")⏎`, `T/examples/demo.py` = `import hashlib⏎hashlib.sha384(b"")⏎`, `T/pkg/util_test.go` = `package pkg⏎import "crypto/sha512"⏎var _ = sha512.Sum512(nil)⏎`. 기본 스캔 → `MD5` `scope=production,test`, `SHA-1` `scope=test`, `SHA-384` `scope=example`, `SHA-512` `scope=test`. |
| AC-35 | 파일 이름 패턴과 대소문자 무시 디렉터리를 인식한다(확인 필요 5 추천 목록 기준). | `T/a/conftest.py`(`import hashlib⏎hashlib.md5(b"")`), `T/a/FooTest.java`(`class FooTest { Object m = MessageDigest.getInstance("SHA-1"); }`), `T/a/x.spec.ts`(`createHash('sha384')`), `T/Tests/Bar.cs`(`var h = SHA512.Create();`), `T/Samples/s.go`(`package s⏎import "crypto/sha256"⏎var _ = sha256.Sum256(nil)`). 기본 스캔 → `MD5`·`SHA-1`·`SHA-384`·`SHA-512` 는 `scope=test`, `SHA-256` 은 `scope=example`. |
| AC-36 | 범위는 스캔 루트 기준으로 판정한다(확인 필요 6 추천안). | 저장소 루트에서 `cbom-scout scan examples/demo-app -o demo.json --fail-on never --no-github-summary` → `src/` 코드에서 나온 구성요소는 모두 `scope=production`. (위치 문자열은 기존처럼 `examples/demo-app/src/payment.py`.) |
| AC-37 | 리포트에 테스트·예제 전용과 신뢰도 낮음(identity `confidence` < 0.5)을 표시한다. | AC-34 트리에 `T/src/p.py` = `print("ML-KEM-768")⏎` 를 더해 기본 스캔 → `r.md` 의 "조치가 필요한 자산" 표에서 `SHA-1` 행의 자산 칸에 `**SHA-1** (테스트·예제 전용)` 이 있고, `MD5` 행에는 `(테스트·예제 전용)` 이 없다. "정책 결과:" 줄 바로 다음 비지 않은 줄이 `탐지 참고: 테스트·예제 경로에서만 발견 3개 · 신뢰도 낮음 1개` 이다. "통과한 자산" 목록에서 `ML-KEM-768` 으로 시작하는 줄에 `(신뢰도 낮음)` 이 있다. `r.html` 에도 `(테스트·예제 전용)` 과 `탐지 참고:` 가 있다. 두 수가 모두 0 이면 `탐지 참고:` 줄은 없다(AC-1 트리로 확인). |
| AC-38 | 기준선 모드 리포트에도 같은 표시가 붙는다. | AC-37 트리를 `--fail-on never -o base.json` 으로 스캔해 기준선을 만들고, `T/tests/test_app.py` 끝에 `hashlib.sha224(b"")⏎` 를 추가한 뒤 `cbom-scout scan . --baseline base.json --markdown r2.md --fail-on never --no-github-summary` → `r2.md` 의 "신규 위반 (기준선 대비)" 표의 `SHA-224` 행에 `(테스트·예제 전용)` 이 있다. |
| AC-39 | 범위는 정책 판정·종료 코드·GitHub 주석을 바꾸지 않는다. | AC-34 트리에서 `--fail-on fail` 로 스캔 → 종료 코드 1, `SHA-1` 의 `policy-action=fail`. `GITHUB_ACTIONS=true` 로 같은 스캔 → stdout 에 `::error file=tests/test_app.py,line=3,title=cbom-scout SHA-1::` 로 시작하는 줄이 있다. |

### 1b-E. 암호 라이브러리 식별

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-40 | `requirements*.txt` 에서 암호 라이브러리의 이름·버전·선언 위치를 기록한다. 주석·비암호 패키지·옵션 줄은 무시한다. | `T/requirements.txt` = `cryptography[ssh]==42.0.5 ; python_version > "3.8"⏎PyCryptodome>=3.20⏎# pyopenssl==24.0.0⏎requests==2.31.0⏎-r other.txt⏎PyNaCl==1.5.0⏎`. 기본 스캔 → `type == "library"` 구성요소가 정확히 셋: (1) `name=cryptography`, `version=42.0.5`, `purl=pkg:pypi/cryptography@42.0.5`, `bom-ref` = purl, 발견 (`requirements.txt`,1); (2) `name=pycryptodome`, `version` 필드 없음, `purl=pkg:pypi/pycryptodome`, 속성 `version-spec=>=3.20`, 발견 (`requirements.txt`,2); (3) `name=pynacl`, `purl=pkg:pypi/pynacl@1.5.0`, 발견 (`requirements.txt`,6). 셋 다 속성 `scanners=deps`, `scope=production`, `evidence.identity` = `[{"field": "purl", "concludedValue": <purl>, "confidence": 0.9, "methods": [{"technique": "manifest-analysis", "confidence": 0.9}]}]`. `other.txt` 가 없어도 오류 없음. |
| AC-41 | 식별까지만 한다: 라이브러리는 판정·알고리즘·연결을 만들지 않는다. | AC-40 트리의 `out.json` 에서: `library` 구성요소에 `cryptoProperties` 키가 없고, `properties[].name` 이 `cbom-scout:scanners`, `cbom-scout:scope`, `cbom-scout:version-spec` 외의 것이 없다(즉 `status`·`policy-action`·`note` 없음). `cryptographic-asset` 구성요소 0개. `dependencies` 배열에 라이브러리 `bom-ref` 가 `ref` 나 `dependsOn` 으로 나오지 않는다. |
| AC-42 | `pyproject.toml` (PEP 621·Poetry) 을 읽는다. | `T/pyproject.toml` = `[project]⏎name = "x"⏎dependencies = ["cryptography>=41", "click"]⏎[project.optional-dependencies]⏎dev = ["pytest", "pynacl==1.5.0"]⏎[tool.poetry.dependencies]⏎pycryptodome = "^3.20"⏎`. 기본 스캔 → `cryptography`(`version-spec=>=41`, 발견 (`pyproject.toml`,3)), `pynacl`(`version=1.5.0`, 발견 (`pyproject.toml`,5)), `pycryptodome`(`version-spec=^3.20`, 발견 (`pyproject.toml`,7)). `click`·`pytest` 없음. Python 3.10 과 3.13 에서 결과가 같다. |
| AC-43 | `package.json` 을 읽고, npm 범위 패키지를 purl 규격대로 쓴다. 다른 `.json` 은 여전히 보지 않는다. | `T/package.json` = `{"name":"w","dependencies":{"node-forge":"1.3.1","express":"^4","@noble/curves":"1.4.0"},"devDependencies":{"jsonwebtoken":"^9.0.0"}}`, `T/data.json` = `{"ctx": "hashlib.md5(x)"}`. 기본 스캔 → `node-forge`(`purl=pkg:npm/node-forge@1.3.1`), `@noble/curves`(`purl=pkg:npm/%40noble/curves@1.4.0`), `jsonwebtoken`(`version-spec=^9.0.0`). `express` 없음. `cryptographic-asset` 구성요소 0개. 발견 줄 번호는 1(한 줄 파일). |
| AC-44 | 깨진 매니페스트는 건너뛰고 경고만 낸다. `node_modules` 안 매니페스트는 읽지 않는다. | `T/package.json` = `{"dependencies": {`, `T/node_modules/x/package.json` = `{"dependencies":{"node-forge":"1.3.1"}}`, `T/app/a.py` = `import hashlib⏎hashlib.md5(b"")⏎`. 기본 스캔에 `-v` → 종료 코드 0, `library` 구성요소 0개, `MD5` 는 있음, stderr 에 `매니페스트를 읽을 수 없음` 과 `package.json` 이 한 줄에 함께 나온다. |
| AC-45 | `pom.xml` 을 읽는다. 주석 처리된 의존성·비암호 의존성은 무시한다. | `T/pom.xml` = `<project xmlns="http://maven.apache.org/POM/4.0.0">⏎<dependencies>⏎<dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency>⏎<dependency><groupId>com.google.crypto.tink</groupId><artifactId>tink</artifactId><version>${tink.version}</version><scope>test</scope></dependency>⏎<!-- <dependency><groupId>org.conscrypt</groupId><artifactId>conscrypt-openjdk</artifactId><version>2.5.2</version></dependency> -->⏎<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version></dependency>⏎</dependencies>⏎</project>⏎`. 기본 스캔 → `bcprov-jdk18on`(`group=org.bouncycastle`, `version=1.78`, `purl=pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78`, 발견 (`pom.xml`,3)), `tink`(`version` 없음, `version-spec=${tink.version}`, 발견 (`pom.xml`,4)). `conscrypt-openjdk`·`junit` 없음. |
| AC-46 | `pom.xml` 의 DOCTYPE·엔티티를 확장하지 않는다. | `T/secret.txt` = `TOPSECRET-123`, `T/pom.xml` = `<?xml version="1.0"?>⏎<!DOCTYPE p [<!ENTITY x SYSTEM "secret.txt">]>⏎<project><dependencies><dependency><groupId>org.bouncycastle</groupId><artifactId>&x;</artifactId><version>1.78</version></dependency></dependencies></project>⏎`. 기본 스캔 → 종료 코드 0, 10초 안에 끝남, `out.json`·`r.md`·stderr 에 `TOPSECRET-123` 없음. |
| AC-47 | `go.mod` 의 `require` 블록·단일 줄을 읽는다. | `T/go.mod` = `module example.com/app⏎⏎go 1.24⏎⏎require (⏎\tgolang.org/x/crypto v0.31.0⏎\tgithub.com/cloudflare/circl v1.5.0 // indirect⏎\tgithub.com/gin-gonic/gin v1.10.0⏎)⏎require filippo.io/edwards25519 v1.1.0⏎`. 기본 스캔 → `golang.org/x/crypto`(`version=v0.31.0`, `purl=pkg:golang/golang.org/x/crypto@v0.31.0`, 발견 (`go.mod`,6)), `circl`(발견 (`go.mod`,7)), `edwards25519`(발견 (`go.mod`,10)). `gin` 없음. purl 의 namespace/name 분리는 purl 규격을 따른다. |
| AC-48 | 라이브러리는 정책·요약·종료 코드에 영향이 없고, 리포트에 별도 절로 나온다. 제외 패턴이 적용된다. | `T/requirements.txt` = `cryptography==42.0.5⏎`, `T/tests/requirements.txt` = `pynacl==1.5.0⏎`, `T/.cbomignore` = `tests/⏎`. `cbom-scout scan . -o out.json --markdown r.md --no-github-summary` (기본 `--fail-on fail`) → 종료 코드 0. stderr 요약이 `cbom-scout: 자산 0개` 로 시작. `r.md` 에 `## 암호 라이브러리 의존성` 절이 있고 그 표에 `cryptography`, `42.0.5`, `requirements.txt:1` 이 한 행에 있다. `pynacl` 은 없다. 라이브러리가 하나도 없는 스캔(AC-1 트리)의 `r.md` 에는 이 절이 없다. |
| AC-49 | `--no-deps` 로 매니페스트 분석을 끈다(이름은 확인 필요 8). `--no-code` 는 매니페스트 분석을 끄지 않는다. | AC-40 트리에서 `--no-deps` 추가 → `library` 구성요소 0개. `--no-code` 만 추가 → `library` 구성요소 3개. |

### 1a·1b 공통 — 병합·하위 호환

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-50 | `merge`·`check` 가 라이브러리 구성요소를 보존하고 identity·범위를 규칙대로 합친다. | `a.json`: 작업 디렉터리 `T1`, `T1/app1/requirements.txt` = `cryptography==42.0.5⏎`, `T1/app1/x.py` = `import hashlib⏎hashlib.md5(b"")⏎`, `cbom-scout scan . -o a.json --fail-on never`. `b.json`: 작업 디렉터리 `T2`, `T2/app2/requirements.txt` = 같은 내용, `T2/tests/t.py` = `print "x"⏎hashlib.md5(b"")⏎`(구문 오류 → [SRC 0.6], 범위 `test`), 같은 방법으로 스캔. `cbom-scout merge a.json b.json -o m.json` → `bom-ref == "pkg:pypi/cryptography@42.0.5"` 구성요소가 하나, 발견 (`app1/requirements.txt`,1)·(`app2/requirements.txt`,1) 둘, identity 원소 하나(`field == "purl"`). `MD5` 는 `scope=production,test`, 근거 [AST 0.9] 와 [SRC 0.6], 신뢰도 0.9, `field == "name"` 원소 하나. `cbom-scout check m.json --markdown r.md --fail-on never --no-github-summary` → `r.md` 에 `## 암호 라이브러리 의존성` 절이 있다. |
| AC-51 | `--engine regex` 는 기존 동작과 같은 탐지를 낸다. | 저장소 루트에서 `cbom-scout scan examples/demo-app --engine regex -o r.json --fail-on never --no-github-summary` 와 main 결과(`… -o m.json`)를 비교 → `cryptographic-asset` 구성요소의 (`name`, 발견 (location,line) 집합) 쌍이 완전히 같다. `r.json` 의 코드 스캐너 구성요소는 모두 근거 [SRC 0.6] 만이고 occurrence 에 `symbol` 이 없다. `--engine foo` → 종료 코드 2. |
| AC-52 | 기본 엔진의 데모 결과 변화는 중복 `AES` 제거뿐이고, README 의 데모 출력 줄을 실제와 맞춘다. | 저장소 루트에서 `cbom-scout scan examples/demo-app -v -o d.json` → 종료 코드 1. `d.json` 의 `cryptographic-asset` 이름 집합 = main 결과 이름 집합 − `{"AES"}`. `d.json` 의 모든 발견 (location,line) 은 main 결과에도 있다. stderr 첫 요약 줄이 README "데모 앱으로 바로 확인" 블록의 `# cbom-scout: 자산 …` 줄(앞의 `# ` 제외)과 정확히 같다. |
| AC-53 | 기존 테스트를 고치지 않고 전체 테스트가 통과한다. | `python -m pytest -q` 통과. `git diff 5bbfbeb -- tests/test_code_scanner.py tests/test_policy_cli.py tests/test_baseline.py tests/test_catalog.py tests/test_certs_tls.py tests/acceptance/test_baseline.py` 가 비어 있다. |
| AC-54 | 이전 버전 기준선과 비교하면 사라진 주석 오탐은 "해결됨"으로 나오고 신규 위반은 없다. 새 버전끼리는 identity 때문에 차이가 생기지 않는다. | `T/app/a.py` = `import hashlib⏎# hashlib.md5(x)⏎hashlib.sha1(b"")⏎`. main 코드로 `cbom-scout scan . -o old.json --fail-on never` → `old.json` 에 `MD5` 있음. 새 코드로 `cbom-scout scan . --baseline old.json --markdown r.md --no-github-summary` (기본 `--fail-on fail`) → 종료 코드 0, stderr 기준선 요약 줄에 `신규 실패 0` 과 `해결 1건`, `r.md` "해결된 위반" 절에 `MD5` 와 `app/a.py` 가 한 줄에 함께 있고 `SHA-1` 은 "기존 위반"에 있다. 이어서 새 코드로 `cbom-scout scan . -o new.json --fail-on never` 를 만들고 같은 트리를 `--baseline new.json` 으로 다시 스캔 → 기준선 요약 줄에 `신규 실패 0 / 신규 경고 0 / 신규 참고 0` 과 `해결 0건`. |
| AC-55 | 새 필드가 없는 이전 CBOM 도 그대로 평가된다. | `cbom-scout check docs/sample-cbom.json --markdown r.md --fail-on never --no-github-summary` → 종료 코드 0, stderr 요약 줄이 main 결과와 같다, `r.md` 에 `(테스트·예제 전용)`·`(신뢰도 낮음)`·`탐지 참고:` 없음, `Traceback` 없음. |
| AC-56 | 같은 트리를 두 번 스캔하면 `serialNumber`·`metadata.timestamp` 외에는 출력이 같다. | AC-34 + AC-40 파일을 합친 트리를 두 번 기본 스캔 → 두 `out.json` 에서 그 두 필드를 지우면 바이트 단위로 같다. |

### Windows / Linux

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-57 | 이 명세의 인수 테스트 전체가 Windows 11 과 Ubuntu 에서, Python 3.10 과 3.13 에서 통과한다. | 네 조합에서 `python -m pytest -q` 통과. (CI 에 Windows 를 넣을지는 확인 필요 13.) |
| AC-58 | CRLF 파일의 결과(구성요소·발견 줄 번호·범위·identity)는 LF 파일과 같다. | AC-8, AC-9, AC-17(여러 줄 블록 주석), AC-40, AC-47 의 입력을 테스트 실행 중에 CRLF 로 바꿔 쓴 트리와 LF 트리를 각각 스캔 → `cryptographic-asset`·`library` 구성요소의 (`name`, 발견 집합, `scope`, `evidence.identity`) 가 같다. (저장소에 CRLF 파일을 커밋하지 않는다.) |
| AC-59 | Windows 에서도 위치는 `/` 구분이고 범위 판정이 맞다. 공백·한글 경로를 처리한다. | Windows 에서 AC-34 실행 → 발견 위치가 `tests/test_app.py` (`\` 없음), `SHA-1` `scope=test`. `T/한글 폴더/tests/a.py` = `import hashlib⏎hashlib.md5(b"")⏎` → 발견 (`한글 폴더/tests/a.py`, 2), `scope=test`. |

### 1a-G. 평가용 말뭉치

| ID | 기준 | 검증 방법 |
|---|---|---|
| AC-60 | 말뭉치와 정답 라벨이 `tests/` 아래에 있고 최소 규모를 만족한다. | 라벨 파일을 읽어 센다: 양성 라벨(있어야 할 발견) 80개 이상, 음성 라벨(없어야 할 발견이 있는 줄) 40개 이상. 언어 Python·Java·Go·JS/TS·C/C++·C#·설정 파일 각각 양성 5개 이상. `phase: 1` 범주별 최소: `direct` 20, `comment` 10(Python 3·그 밖 7 이상), `docstring` 5, `string-literal` 10, `lookalike`(암호처럼 보이지만 암호가 아닌 코드, 예: 변수명 `md5sum`, 문자열 `"aes"` 를 쓰는 비암호 함수) 5, `alias` 5, `multiline` 5, `indirect-const` 8, `indirect-default` 3, `test-path` 5, `manifest` 10. `phase: later` 범주 `cross-function`(함수 경계를 넘는 전달) 5 이상. |
| AC-61 | 라벨 형식이 정해져 있고 닫힌 세계로 채점한다. 라벨은 사람이 검수한다. | 라벨 한 건은 최소 `file`(말뭉치 루트 기준 `/` 경로), `line`, `name`(CBOM 구성요소 이름, 라이브러리는 purl), `label`(`positive`/`negative`), `category`, `phase`(`1`/`later`), `source`(`handwritten` 또는 참고한 벤치마크 이름, 예: `CryptoAPI-Bench`), `reviewed`(사람 검수 여부, 모든 라벨이 `true`)를 가진다. 말뭉치 파일 안의 탐지 중 양성 라벨과 (file, line, name) 이 맞지 않는 것은 모두 오탐(FP)으로 센다. 없는 파일이나 범위를 벗어난 줄을 가리키는 라벨, `reviewed` 가 `true` 가 아닌 라벨이 있으면 평가 도구가 종료 코드 2 와 그 라벨 위치를 출력한다. |
| AC-62 | 평가 도구는 엔진별(`auto`, `regex`) 지표를 범주별로 결정적으로 낸다. | 평가 도구(위치·명령은 확인 필요 12)를 두 번 실행 → 전체·언어별·범주별 TP/FP/FN/정밀도/재현율 표(마크다운)와 같은 내용의 JSON 이 나오고 두 실행 결과가 같다. `phase: later` 라벨은 별도 줄로 집계된다. |
| AC-63 | 1차 개선 목표를 수치로 만족한다(기준치는 확인 필요 12). | 말뭉치(테스터가 추가한 비공개 사례 포함)에서 `auto` 엔진: `comment`·`docstring`·`string-literal`·`lookalike` 범주 FP = 0; 전체와 언어별 재현율이 `regex` 엔진 이상; `alias`·`multiline`·`indirect-const` 범주 재현율 ≥ 0.9; 전체 정밀도가 `regex` 엔진 이상. |
| AC-64 | 성능 저하가 허용 범위 안이다. | 테스트 중에 생성한 합성 트리(Python 300개·Java 300개·JS 300개 파일, 각 200줄, 암호 호출 섞음)를 같은 기계에서 `--engine regex` 와 기본 엔진으로 각각 스캔 → 기본 엔진 소요 시간 ≤ regex 엔진의 3배 (각 3회 중앙값). |

## 설계 메모

- **바뀌는 모듈**
  - `scanners/code.py`: 언어별 문맥 판정(Python AST, 그 밖 토크나이저)을 규칙 적용 앞단에 둔다. 이름 해석기(`parse_cipher_spec` 등)와 `catalog.py` 는 재사용해 판정 기준이 두 곳으로 갈라지지 않게 한다. Python AST 분석은 별도 모듈로 분리해도 좋다.
  - Python API 지식 베이스 데이터 파일(API 정규 이름 → 인자 위치·키워드 → 알고리즘/키 길이/곡선/모드, `cryptoFunctions`). 신뢰도 수치표와 테스트·예제 패턴도 데이터로 둔다.
  - 새 매니페스트 스캐너(예: `scanners/deps.py`)와 암호 라이브러리 목록 데이터(이름·생태계만).
  - `inventory.py`: 발견별 (technique, 신뢰도, symbol) 를 받아 `evidence.identity`·`occurrence.symbol` 에 반영, `cbom-scout:scope`, `library` 구성요소, `merge_component` 의 identity·scope 병합.
  - `cbom.py`: `inventory_from_boms` 가 `library` 구성요소를 보존.
  - `policy.py`: 선택 키 `min_confidence` 처리. `report.py`: 표시 문구, 라이브러리 절. `Finding.locations` 문자열 형식은 바꾸지 않는다(GitHub 주석이 `path:line` 을 파싱한다).
  - `cli.py`: `--engine {auto,regex}`, `--no-deps`, `-v` 경고 출력.
  - `baseline.py`: 바꿀 필요 없음(`_component_problem` 은 `cryptographic-asset` 이 아닌 구성요소를 검사하지 않고, 비교는 위치만 본다). AC-54 로 확인.
- **CLI·Action 입력:** 새 옵션 2개. Action 입력 추가는 확인 필요 8(추천: 1차는 추가하지 않음).
- **정책 파일:** 선택 키 `min_confidence` 하나 추가. 내장 정책 파일은 바꾸지 않는다. README 정책 예시에 사용법을 적는다.
- **하위 호환**
  - 출력 CBOM 은 `evidence.identity`, `occurrence.symbol`, `cbom-scout:scope`, `library` 구성요소가 늘어날 뿐 기존 필드는 그대로다. 모두 CycloneDX 1.6 표준 필드이거나 기존 `properties` 관례다.
  - 오탐이 줄어 기존 사용자의 위반 수가 **줄 수 있다**(주석·docstring·문자열 속 API, 데모의 중복 `AES`). 이전 버전 기준선과 비교하면 "해결됨"으로 나온다(AC-54). 릴리스 노트에 적는다.
  - 여러 줄 호출 해석으로 심각도가 **올라갈 수 있다**(`RSA` → `RSA-1024`). 기준선 비교에서는 이름이 바뀌므로 신규 위반으로 나온다. 릴리스 노트에 적는다.
  - `--engine regex` 는 기존 탐지를 그대로 재현하는 비상구다(AC-51).
- **보안:** 상수 해석에서 얻은 값은 알고리즘 이름·키 길이로만 쓰고 기록하지 않는다. `symbol` 에는 API 이름만 넣는다. XML 은 외부 엔티티·DTD 를 처리하지 않는다([Python XML 취약점 안내](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)). `additionalContext` 원문 기록 문제는 확인 필요 14.
- **외부 의존성:** 1차 추천안은 표준 라이브러리만(`ast`, `tokenize` 등). `tomllib` 은 Python 3.11+ 에만 있으므로([tomllib](https://docs.python.org/3/library/tomllib.html)) 3.10 지원 방법이 필요하다(확인 필요 1).
- **참고 근거:** [CycloneDX 1.6 JSON 참조](https://cyclonedx.org/docs/1.6/json/), [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), [purl spec](https://github.com/package-url/purl-spec), [Python ast](https://docs.python.org/3/library/ast.html), [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd), [tree-sitter](https://tree-sitter.github.io/tree-sitter/), 업계 조사 문서 `docs/research/crypto-detection-survey.md` 와 그 출처(위 "업계 동향" 표).

## 결정 (2026-11-27 사용자 승인)

아래 "확인 필요" 1~18 은 모두 **[추천]** 안으로 결정했다. 14(`additionalContext`)는 이 기능과 별도로 PR #3 에서 처리한다.

15(1a·1b 분할)에 따른 완료 기준 배정:

| PR | 완료 기준 |
|---|---|
| 1a | AC-1 ~ AC-39, AC-51 ~ AC-64. 단, 아래 1b 로 넘기는 부분은 제외 |
| 1b | AC-40 ~ AC-50, 그리고 AC-30 의 `m.json`(AC-50) 검증, AC-56 의 AC-40 입력, AC-58 의 AC-40·AC-47 입력, AC-60 의 `manifest` 범주 10건 |

1a 에서 AC-56 은 AC-34 트리만, AC-58 은 AC-8·AC-9·AC-17 입력만으로 검증한다.

## 확인 필요 (사용자 결정)

이번 개정에서 정리된 결정: **신뢰도는 CycloneDX 1.6 표준 필드(`evidence.identity[].confidence`, `methods[].technique`/`confidence`, `occurrence.symbol`)로 표현하고 자체 속성은 쓰지 않는다**(이전 "신뢰도 표현"·"신뢰도 단계" 항목 대체). **의존성 분석은 라이브러리 식별까지**(이전 "라이브러리 판정" 질문 제거).

- [ ] **1. 외부 의존성.** (a) 표준 라이브러리만 — Python 은 `ast`, 다른 언어는 직접 만든 토크나이저 **[추천: 1차, 조사 문서도 `ast` 로 외부 의존성 없이 가능하다고 봄]**. (b) tree-sitter 를 선택 설치(`pip install cbom-scout[parse]`)로. (c) tree-sitter 필수. 함께 결정: Python 3.10 의 TOML — (가) `tomli; python_version<"3.11"` 조건부 의존성 **[추천]**, (나) 자체 파서, (다) 3.10 에서는 `pyproject.toml` 생략. XML — (가) 표준 `xml.etree` + DOCTYPE 거부 **[추천]**, (나) `defusedxml`.
- [ ] **2. 주석·docstring 속 탐지.** (a) 기록하지 않음 **[추천]**. (b) 신뢰도 0.3 으로 기록(그러면 `min_confidence` 로 걸러낼 수 있음).
- [ ] **3. 신뢰도 수치표와 위치별 신뢰도.** (a) 위 표의 0.9 / 0.6 / 0.3 과 "낮음" 표시 기준 0.5 를 승인 **[추천]**. (b) 수치 조정. 함께 결정: 표준에는 occurrence 수준 신뢰도 필드가 없으므로 위치별 신뢰도는 남기지 않는다 **[추천: 사용자 지시 "자체 속성 대신 표준 필드" 를 따름]** vs 조사 문서 1번처럼 "표준 필드 기본 + 전용 속성 보조"로 위치별 값을 `cbom-scout:` 속성에 덧붙임. (조사 문서와 사용자 지시가 갈리는 지점)
- [ ] **4. AST 기법 이름.** Python AST 탐지의 `technique` 값을 (a) `ast-fingerprint` **[추천: 구문 트리에서 API 호출 모양을 맞추는 방식이라 가장 가까움, 조사 문서도 이 값을 언급]**, (b) 정규식과 같은 `source-code-analysis` 로 하고 구분하지 않음.
- [ ] **5. 테스트·예제 기본 패턴.** 위 "범위" 절의 목록 **[추천]** 을 승인하거나 수정. `spec`·`demo` 처럼 운영 코드 폴더 이름과 겹칠 수 있는 항목을 뺄지. 사용자 정의 패턴은 후속 **[추천]** vs 1차에 `--test-path GLOB` 추가.
- [ ] **6. 범위 판정 기준 경로.** (a) 스캔 루트 기준 **[추천, `.cbomignore` 의 "직접 지정하면 스캔" 동작과 일관]**. (b) 작업 디렉터리 기준.
- [ ] **7. 신뢰도 정책 옵션(조사 문서 2번 반영).** (a) 1차에 선택 키 `min_confidence`(미만이면 조치 상한 `info`), 내장 정책에는 넣지 않음 **[추천]**. (b) 키 이름·동작 변경(예: `low_confidence: {"below": 0.5, "max_action": "info"}`). (c) 1차는 기록만, 정책 연동은 후속. 내장 정책 기본값에 넣을지도 결정(추천: 넣지 않음 — 하위 호환).
- [ ] **8. CLI·Action 이름.** `--engine {auto,regex}` **[추천]** (대안 `--analysis`, `--legacy-regex`). `--no-deps` **[추천]** (대안 `--no-manifests`). Action 입력은 1차에 추가하지 않음 **[추천]**.
- [ ] **9. 해석 못 한 변수 인자.** (a) 기록하지 않음 **[추천: 자산 수가 늘지 않아 하위 호환]**. (b) 조사 문서 2번 취지대로 "해석 실패 = 낮은 신뢰도"로 `unknown` 구성요소(예: `hashlib.new` 의 알 수 없는 해시)를 신뢰도 0.3 으로 기록 — `min_confidence` 와 함께 쓰면 빌드는 막지 않으면서 감사 대상으로 남김.
- [ ] **10. Python 외 언어의 같은 파일 상수 전파.** (a) 후속 1순위 **[추천]**. (b) 1차에 Java 만. (c) 1차에 Java·Go·JS.
- [ ] **11. 암호 라이브러리 초기 목록(식별용).** 추천안 — PyPI: `cryptography`, `pycryptodome`, `pycryptodomex`, `pycrypto`, `pyopenssl`, `pynacl`, `bcrypt`, `paramiko`, `pyjwt`, `python-jose`, `rsa`, `ecdsa`, `passlib`, `liboqs-python`. npm: `node-forge`, `crypto-js`, `jsrsasign`, `tweetnacl`, `libsodium-wrappers`, `jose`, `jsonwebtoken`, `bcrypt`, `elliptic`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `openpgp`. Maven: `org.bouncycastle:*`, `com.google.crypto.tink:*`, `org.conscrypt:*`, `com.nimbusds:nimbus-jose-jwt`, `io.jsonwebtoken:*`, `org.openquantumsafe:*`. Go: `golang.org/x/crypto`, `github.com/cloudflare/circl`, `github.com/open-quantum-safe/liboqs-go`, `filippo.io/edwards25519`, `github.com/golang-jwt/jwt*`.
- [ ] **12. 수치 기준과 평가 도구 위치.** (a) AC-63 기준치(주석·docstring·문자열·유사 코드 FP 0, 간접·별칭·여러 줄 재현율 ≥ 0.9, 재현율·정밀도 비퇴행)와 AC-64 의 3배 성능 한도 승인 **[추천 — 조사 문서의 Cryptoscope 보고치(재현율 92%, 정밀도 97%)와 비슷한 수준]**. (b) 위치: 말뭉치·평가 스크립트 모두 `tests/corpus/` 아래, `python tests/corpus/evaluate.py` **[추천]** vs `cbom-scout eval` 하위 명령. 기존 벤치마크(CryptoAPI-Bench, CamBench)는 사례 출처로만 쓰고 코드를 복사하지 않는다 **[추천: 라이선스·정답 품질]**.
- [ ] **13. Windows CI.** (a) `ci.yml` 매트릭스에 `windows-latest` 추가 **[추천]**. (b) 수동 검증만.
- [ ] **14. `additionalContext` 원문 기록(하드코딩 키 노출 위험).** (a) 이번 기능과 별개로 작은 수정으로 먼저 처리 **[추천]**. (b) 이번 1차에 포함. (c) 현행 유지.
- [ ] **15. 1차 분할.** (a) 1a(A·A'·B·C·C'·D·F·G)와 1b(E 라이브러리 식별)를 각각 파이프라인·PR 로 **[추천]**. (b) 하나의 PR.
- [ ] **16. CBOMkit 연동(조사 문서 7번).** (a) 후속 — 지금처럼 사용자가 CBOMkit 결과를 `merge` **[추천]**. (b) 1차에 CBOMkit CBOM 경로를 받아 자동 병합하는 편의 옵션 추가.
- [ ] **17. 알려진 라이브러리 참고 정보(조사 문서 5번).** 조사 문서는 "liboqs·BouncyCastle PQC 지원 버전 같은 알려진 라이브러리에 참고 정보를 붙인다"까지를 완료 기준으로 제안하지만, 사용자 지시는 "라이브러리 식별까지". (a) 후속으로 미룸 **[추천: 사용자 지시 우선]**. (b) 1차에 데이터 기반 `cbom-scout:note` 참고 문구만 추가(정책 판정 없음).
- [ ] **18. API 지식 데이터화 범위(조사 문서 3번).** (a) 1차는 Python AST 엔진만 데이터화, 다른 언어 정규식 규칙은 후속 **[추천: 범위 억제]**. (b) 1차에 모든 언어 규칙을 데이터 파일로 이전.

## 작업 단위

1. 평가 말뭉치 골격·라벨 형식·평가 도구 — 현재(`regex`) 엔진 지표를 먼저 기록해 기준점을 만든다 (AC-60~62).
2. 표준 근거 기록 경로: `Inventory` 의 `evidence.identity`·`occurrence.symbol`·병합 규칙, `--engine regex` (AC-27~30, 51, 56).
3. 그 밖의 언어 토크나이저와 문맥 필터, `_lookahead` 코드 전용화 (AC-17~26).
4. Python API 지식 베이스 데이터와 AST 엔진: 문맥 구분 → import 별칭 → 여러 줄·`Cipher` 결합 → 같은 파일 상수 전파 → 구문 오류 대체 (AC-1~16, 31).
5. 정책 `min_confidence` (AC-32~33).
6. 테스트·예제 범위 판정과 리포트 표시 (AC-34~39).
7. 하위 호환·플랫폼 확인, README "한계와 보완 방법"·데모 출력 줄·정책 예시·CLI 도움말 갱신, 말뭉치 지표 재측정 (AC-52~59, 63~64).
8. (1b) 매니페스트 스캐너와 라이브러리 목록 데이터, 리포트 절, `merge`/`check` 보존 (AC-40~50).
