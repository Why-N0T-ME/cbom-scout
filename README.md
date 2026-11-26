# cbom-scout 🔐

**우리 회사가 어떤 암호를 어디에 쓰는지 자동으로 찾아내는 도구.**
소스코드·설정 파일·인증서·TLS 엔드포인트를 스캔해 **CycloneDX 1.6 CBOM**(Cryptography Bill of Materials)을 만들고,
NIST PQC 전환 일정(IR 8547) 기준으로 무엇을 언제 바꿔야 하는지 판정합니다.
CI에 붙이면 배포할 때마다 암호 목록이 갱신되고, 금지된 알고리즘이 새로 들어오면 빌드를 막습니다.

> 보이지 않으면 바꿀 수 없다. 암호 민첩성(crypto agility)의 출발점은 살아 있는 암호 인벤토리다.

## 무엇을 찾나

| 계층 | 대상 | 예 |
|---|---|---|
| 소스코드 | Python, Java/Kotlin, Go, JS/TS, C/C++(OpenSSL), C# | `rsa.generate_private_key(key_size=2048)`, `Cipher.getInstance("DESede/CBC/...")`, `mlkem.GenerateKey768()` |
| 설정 파일 | nginx, Apache, sshd/ssh, OpenSSL 설정 | `ssl_protocols TLSv1 TLSv1.1`, `KexAlgorithms mlkem768x25519-sha256,...`, `ssl_ecdh_curve X25519` |
| 인증서·키 | PEM/DER 인증서, 공개키·비밀키, SSH 공개키 | 키 알고리즘·길이, 서명 해시, 만료일. **키 값은 기록하지 않음** |
| 저장소 내 비밀키 | 모든 텍스트 파일 | `-----BEGIN RSA PRIVATE KEY-----` 가 커밋돼 있으면 즉시 실패 |
| TLS 엔드포인트 | `host:port` 목록 | 협상된 TLS 버전·암호 스위트·서버 인증서, (OpenSSL 3.5+ 있으면) **하이브리드 PQC 키 교환(X25519MLKEM768) 협상 여부** |
| 외부 CBOM | 다른 도구 결과 | CBOMkit(sonar-cryptography) 등이 만든 CBOM 을 `merge` 로 합쳐 같은 정책으로 평가 |

## 판정 기준

| 상태 | 의미 | 기본 정책 (`nist-ir8547`) |
|---|---|---|
| `broken` | 고전 컴퓨터로도 취약 (MD5, SHA-1, DES/3DES, RC4, RSA-1024, ECB, TLS 1.0/1.1, 커밋된 비밀키) | 🔴 즉시 실패 |
| `quantum-vulnerable` | Shor 알고리즘에 깨지는 공개키 (RSA, ECDSA, ECDH, Ed25519, X25519, DH) | 🟠 경고 → **2031-01-01부터 자동 실패** |
| `symmetric-weak` | AES-128, SHA-256 등 양자 여유가 작은 대칭키·해시 | 🔵 참고 |
| `hybrid` | X25519MLKEM768 등 고전+PQC 하이브리드 | 🟢 통과 |
| `pqc` | ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS, **KpqC(SMAUG-T, NTRU+, HAETAE, AIMer)** | 🟢 통과 |
| `pqc-draft` | FN-DSA(FIPS 206 초안), HQC | 🔵 참고 |

`quantum-vulnerable` 의 실패 전환 날짜는 NIST IR 8547 최종본(2026.10)의 "2030년 이후 비권고, 2035년 이후 금지"와 국내 중요시스템 전환 목표(2031년)를 반영한 기본값입니다. 정책 파일에서 바꿀 수 있습니다.

## 빠른 시작

```bash
pip install git+https://github.com/OWNER/cbom-scout.git     # 또는 저장소를 받아 pip install -e .

# 현재 저장소 스캔 → cbom.json + 리포트
cbom-scout scan . --markdown report.md --html report.html -v

# 외부 엔드포인트까지 함께
cbom-scout scan . --tls api.example.com:443 --tls www.example.com

# 엔드포인트 목록 파일
cbom-scout scan --tls-file endpoints.txt -o tls-cbom.json

# 신규 서비스용 엄격 정책 (양자 취약 공개키도 즉시 실패)
cbom-scout scan . --policy strict

# 테스트·생성물 제외 (저장소 루트의 .cbomignore 도 자동으로 읽음)
cbom-scout scan . --exclude tests/ --exclude "*.min.js"

# 여러 CBOM 합치기 → 전사 인벤토리
cbom-scout merge team-a.json team-b.json cbomkit-output.json -o company.json
cbom-scout check company.json --html company-report.html --fail-on never
```

`.cbomignore` 예시 (한 줄에 하나, 저장소 루트 기준):

```
tests/
examples/
third_party/
*.min.js
```

제외된 폴더라도 `cbom-scout scan examples/demo-app` 처럼 직접 지정하면 스캔합니다.

종료 코드: `0` 통과, `1` 정책 위반(`--fail-on` 기준), `2` 사용법 오류(기준선 파일이 없거나 깨진 경우 포함).
`--baseline` 을 주면 `1` 은 **기준선 대비 새로 생긴 위반**이 `--fail-on` 수준 이상일 때만 납니다.

### 기준선 비교 — PR 에서는 새로 생긴 취약 암호만 막기

레거시 MD5·RSA 가 이미 있는 저장소에서도 PR 이 **새로 들여오는** 취약 암호만 실패로 처리할 수 있습니다.

```bash
# main 에서 기준선을 만들어 보관 (아티팩트 등)
cbom-scout scan . -o baseline.json --fail-on never

# PR 에서: 기준선 대비 신규 위반만 종료 코드 1
cbom-scout scan . --baseline baseline.json --markdown report.md -v
# cbom-scout: 자산 … → 실패
# 기준선 대비: 신규 실패 1 / 신규 경고 0 / 신규 참고 0 · 기존 4건 · 해결 1건 → 실패
```

- 같은 발견인지는 **(자산, 파일 경로)** 로 판단하고 줄 번호는 보지 않습니다. 코드가 위아래로 움직여도 기존으로 봅니다.
  같은 파일 안에서 같은 알고리즘을 한 번 더 쓰는 것도 기존으로 봅니다.
- 기존 위반은 정책이 엄격해지거나 `fail_after` 날짜가 지나 실패로 올라가도 PR 을 실패시키지 않습니다. 리포트에는 현재 판정으로 계속 나옵니다.
- 파일 이름을 바꾸거나 옮기면 신규로 봅니다(이전 위치는 "해결됨").
- 리포트는 신규 위반 → 기존 위반(접힘) → 해결된 위반 순서로 나오고, GitHub 주석은 신규 위치에만 달립니다.
  출력 CBOM 의 위반 구성요소에는 `cbom-scout:baseline` = `new`/`existing` 속성이 붙습니다.
- 기준선과 현재 스캔은 **같은 작업 디렉터리 기준**으로 만들어야 경로가 맞습니다. 하나도 겹치지 않으면 경고가 나옵니다.
- 기준선은 cbom-scout 출력이 아니어도 CycloneDX JSON 이면 됩니다(알고리즘은 이름 대소문자 무시). `check` 명령에도 `--baseline` 을 쓸 수 있습니다.

데모 앱으로 바로 확인해 볼 수 있습니다:

```bash
cbom-scout scan examples/demo-app -v
# cbom-scout: 자산 28개 (알고리즘 23, 취약 15, PQC·하이브리드 3) · 실패 5 / 경고 14 / 참고 2 / 통과 7 → 실패
```

결과 예시: [docs/sample-report.md](docs/sample-report.md) · [docs/sample-cbom.json](docs/sample-cbom.json)

## GitHub Action 으로 자동화

```yaml
# .github/workflows/cbom.yml
name: Crypto inventory
on: [pull_request, push]
jobs:
  cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWNER/cbom-scout@v0.1.0
        with:
          path: .
          tls-targets: api.example.com:443
          policy: nist-ir8547
          fail-on: fail
```

- PR 화면의 **작업 요약(Job summary)** 에 리포트 표가 붙고, 문제가 된 코드 줄에 **주석(annotation)** 이 달립니다.
- `cbom.json`, `cbom-report.md`, `cbom-report.html` 이 아티팩트로 올라갑니다.
- `baseline: baseline.json` 입력을 주면 기준선 대비 새로 생긴 위반만 실패로 처리합니다. 기준선 파일은 워크플로에서 미리 준비합니다
  (예: main 푸시 때 만든 `cbom.json` 아티팩트를 내려받기). 파일이 있을 때만 넘기세요 — 지정했는데 없으면 오류로 멈춥니다.
- 주간 `schedule` 트리거를 걸면 외부 TLS 엔드포인트의 PQC 적용 현황을 계속 추적할 수 있습니다.
  전체 예시: [examples/workflows/cbom-scan.yml](examples/workflows/cbom-scan.yml)

## 정책 = 코드 밖의 설정 (암호 민첩성)

판정 기준은 [src/cbom_scout/policies/](src/cbom_scout/policies/) 의 JSON 파일입니다. 기준이 바뀌면 코드를 고치지 않고 정책만 바꿉니다.

```json
{
  "name": "my-company",
  "status": {
    "broken":             {"action": "fail"},
    "quantum-vulnerable": {"action": "warn", "fail_after": "2029-01-01"},
    "symmetric-weak":     {"action": "warn"},
    "pqc":                {"action": "pass"}
  },
  "overrides": [
    {"name": "MD5", "action": "info", "message": "레거시 파일 체크섬 — 보안팀 예외 승인 #123"}
  ]
}
```

```bash
cbom-scout scan . --policy my-company.json
```

도입 초기에는 `"min_confidence": 0.7` 처럼 **탐지 신뢰도 기준**을 넣을 수 있습니다. 신뢰도가 기준 미만인 자산
(예: 후보 값이 여럿인 변수, 로그 문자열 속 PQC 이름)은 CBOM·리포트에 남기되 조치를 `info` 까지만 올려 빌드를 막지 않고,
메시지 끝에 `(탐지 신뢰도 낮음 — 판정 보류)` 가 붙습니다. 내장 정책에는 이 키가 없어 기본 동작은 그대로입니다.

## CBOM 출력 형식

[CycloneDX 1.6](https://cyclonedx.org/) 스키마를 따르며, 테스트에서 공식 JSON 스키마로 검증합니다.

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto/algorithm/RSA-2048",
  "name": "RSA-2048",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "2048",
                            "nistQuantumSecurityLevel": 0, "cryptoFunctions": ["keygen"]},
    "oid": "1.2.840.113549.1.1.1"
  },
  "evidence": {
    "identity": [{"field": "name", "confidence": 0.9, "concludedValue": "RSA-2048",
                  "methods": [{"technique": "ast-fingerprint", "confidence": 0.9}]}],
    "occurrences": [{"location": "src/payment.py", "line": 10, "symbol": "rsa.generate_private_key"}]
  },
  "properties": [{"name": "cbom-scout:status", "value": "quantum-vulnerable"},
                 {"name": "cbom-scout:scope", "value": "production"},
                 {"name": "cbom-scout:policy-action", "value": "warn"}]
}
```

**탐지 근거는 CycloneDX 표준 필드**에 남겨 Dependency-Track 같은 다른 도구도 읽을 수 있습니다.

| 필드 | 뜻 |
|---|---|
| `evidence.identity[].methods[].technique` | 탐지 방식. `ast-fingerprint`(Python 구문 트리), `source-code-analysis`(정규식·설정 파일) |
| `evidence.identity[].confidence`, `methods[].confidence` | 탐지 신뢰도 0~1. 방식별 최댓값과 전체 최댓값 |
| `evidence.occurrences[].symbol` | 근거가 된 API 이름 (별칭을 푼 이름. 예: `from hashlib import md5` → `hashlib.md5`) |
| `cbom-scout:scope` 속성 | 발견 위치 분류 `production` / `test` / `example` (스캔 루트 기준). 판정·종료 코드는 바꾸지 않음 |

신뢰도 기준표와 테스트·예제 경로 패턴은 [src/cbom_scout/data/detection.json](src/cbom_scout/data/detection.json) 에 있습니다.
인증서·TLS 스캐너로만 나온 자산에는 `identity` 를 달지 않습니다.

알고리즘·인증서·키 자료·프로토콜이 `dependencies` 로 연결되어, "이 인증서는 어떤 키 알고리즘과 서명 알고리즘을 쓰는가"를 따라갈 수 있습니다.

## 구조

```
src/cbom_scout/
├── catalog.py          알고리즘 지식 베이스 (상태·primitive·양자 보안 수준·KpqC 포함)
├── inventory.py        발견 결과 → CycloneDX 구성요소, 중복 제거·병합
├── scanners/
│   ├── code.py         언어별 규칙 + 설정 파일 + 커밋된 비밀키 (엔진 선택)
│   ├── pyast.py        Python 구문 트리 분석 (API 지식은 data/python_api.json)
│   ├── context.py      C 계열 언어의 주석·문자열 문맥 판정
│   ├── certs.py        인증서·키 파일 (cryptography 라이브러리)
│   └── tls.py          TLS 엔드포인트 (ssl + OpenSSL 3.5 s_client)
├── cbom.py             CBOM 직렬화·병합
├── detection.py        탐지 신뢰도·테스트/예제 범위 (기준값은 data/detection.json)
├── policy.py           정책 평가 (fail_after 날짜 승격, overrides, min_confidence)
├── report.py           마크다운·HTML 리포트
└── cli.py              scan / check / merge
```

## 한계와 보완 방법

- **코드 분석 방식** (기본 `--engine auto`)
  - **Python** 은 구문 트리(AST)로 분석합니다. 주석·docstring·문자열 속 API 는 무시하고, import 별칭
    (`import hashlib as hl`, `from hashlib import md5`), 여러 줄 호출, `Cipher(algorithms.X, modes.Y)` 결합,
    **같은 파일 안**의 상수·변수·기본값 인자(`HASH = "sha1"; hashlib.new(HASH)`)를 해석합니다.
    후보 값이 여럿이거나 기본값 인자로만 정해지면 신뢰도 0.6 으로 모든 후보를 기록합니다.
    구문 오류 파일(예: Python 2)은 정규식으로 대체하고 `-v` 에서 경고합니다.
  - **Java/Kotlin·Go·JS/TS·C/C++·C#** 은 정규식 규칙을 쓰되 주석(`//`, `/* */`)과 문자열 리터럴 안의 매치는 버립니다.
    변수로 넘긴 알고리즘 이름은 아직 해석하지 못합니다.
  - 문자열 속 PQC 이름(`"ML-KEM-768 지원 예정"`)은 신뢰도 0.3 으로 기록합니다. 커밋된 비밀키 헤더는 주석 안에 있어도 탐지합니다.
  - `--engine regex` 로 예전 줄 단위 정규식 동작으로 되돌릴 수 있습니다(비교·비상용).
- **아직 못 하는 것**: 파일·함수 경계를 넘는 데이터 흐름(다른 모듈의 상수, 함수 인자로 전달), 클래스 속성(`self.ALG`),
  f-string·문자열 연결, 외부 라이브러리 **내부**의 암호 호출. 문맥 판정이 다루지 않는 문법: JS 템플릿 `${}` 보간 안쪽,
  JS 정규식 리터럴, C++ 원시 문자열 `R"(…)"`, Kotlin·Scala 중첩 블록 주석, C 전처리기 `#if 0`.
  언어별 정밀 분석은 [CBOMkit](https://github.com/cbomkit) 결과를 `merge` 로 합치세요.
- **탐지 품질 측정**: [tests/corpus/](tests/corpus/) 에 정답 라벨이 달린 평가 말뭉치가 있습니다.
  `python tests/corpus/evaluate.py` 가 엔진별(`auto`, `regex`)·언어별·범주별(주석, 문자열, 별칭, 간접 상수 등) 정밀도·재현율을 냅니다.
  결과에는 사람이 검수한(`reviewed: true`) 라벨 수와 미검수 수가 함께 나옵니다.
- 설정으로만 정해지는 암호(런타임 협상)는 **TLS 스캔**으로, 저장소 밖의 키는 **HSM·KMS 조회**(로드맵)로 보완해야 합니다.
- 망분리 구간·SaaS·벤더 제품은 자동 스캔이 닿지 않습니다. 공급사에 CBOM 제공을 요구하고 `merge` 로 합치세요.
- TLS 하이브리드 키 교환 확인은 실행 환경에 **OpenSSL 3.5 이상**이 필요합니다. 없으면 `key-exchange-source: unavailable` 로 표시됩니다.

## 로드맵

- [ ] 클라우드 KMS(AWS/GCP/Azure) 키 목록 수집기
- [ ] SSH 엔드포인트 스캐너 (KEX·호스트키 협상)
- [ ] 컨테이너 이미지 스캔 (패키지된 OpenSSL 버전·인증서)
- [ ] SARIF 출력 → GitHub Code Scanning 연동
- [ ] KCMVP 검증 모듈 목록과 대조

## Claude Code 에이전트 파이프라인

이 저장소는 Claude Code 로 기능을 개발할 때 역할을 나눠 서로 검증하도록 설정돼 있습니다.

| 역할 | 정의 | 수정 가능 경로 |
|---|---|---|
| PM — 명세·완료 기준 | `.claude/agents/pm.md` | `docs/specs/` |
| 개발 — 구현 | 메인 세션 (`CLAUDE.md`) | 제한 없음 |
| 테스터 — 독립 검증 | `.claude/agents/tester.md` | `tests/`, `docs/test-reports/` |
| 보고 — 최종 보고서 | `.claude/agents/reporter.md` | `docs/reports/` |

역할별 수정 가능 경로는 훅(`.claude/hooks/guard_paths.py`)이 강제합니다. 흐름과 관문은 [docs/pipeline.md](docs/pipeline.md).
저장소 폴더에서 `claude` 를 실행하고 "기준선 비교 기능을 파이프라인으로 진행해줘"처럼 요청하면 됩니다.
처음 열 때 폴더를 신뢰(trust)해야 훅이 동작하며, 훅은 `python` 명령을 씁니다.

## 릴리스 만들기 (관리자용)

1. `docs/releases/vX.Y.Z.md` 에 릴리스 설명을 쓰고 커밋합니다.
2. GitHub **Actions → Release → Run workflow** 에서 버전(`v0.1.0` 등)을 입력해 실행합니다.
3. 워크플로가 테스트를 돌린 뒤 태그와 릴리스를 만들고, 다른 저장소가 쓰는 `v0` 같은 주 버전 태그도 최신 릴리스로 옮깁니다.

## 개발

```bash
pip install -e ".[dev]"
pytest -q
```

## 라이선스

Apache License 2.0. `tests/schemas/` 의 CycloneDX 스키마는 OWASP CycloneDX 프로젝트의 것입니다(Apache-2.0).
