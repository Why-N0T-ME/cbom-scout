# 암호 탐지 도구 업계 조사 — 정규식 스캔 보완 명세 참고

Nov 26, 2026 · @Topiaryy

비슷한 도구들은 오픈소스 쪽은 구문 트리와 데이터 흐름 분석으로 정확도를 높이고, 상용 쪽은 정적 분석에 실행 중 추적과 파일·네트워크 스캔을 더해 빈틈을 메운다. cbom-scout PM 명세의 방향은 업계 흐름과 대체로 맞지만, **신뢰도 기록 위치**와 **의존성 분석에 대한 기대치**는 조정이 필요하다.

## 주요 도구 비교

| 도구 | 탐지 방식 | 신뢰도·근거 표시 | 의존성·기타 |
| --- | --- | --- | --- |
| [CBOMkit / sonar-cryptography](https://github.com/PQCA/sonar-cryptography) (IBM → PQCA) | SonarQube 파서 기반. 규칙마다 `Cipher#getInstance` 같은 특정 API를 겨냥하고, 어느 매개변수에 암호 값이 있는지와 추출 방법을 정의 | 발견 위치를 CBOM에 기록 | 인증서·키·설정·컨테이너는 별도 도구 Theia가 담당 |
| [Cryptoscope](https://arxiv.org/pdf/2503.19531) (IBM 연구) | ANTLR 구문 트리 → 데이터 흐름·제어 흐름·호출 그래프. `Cipher.doFinal()` 같은 호출에서 거꾸로 영향을 준 문장을 모음 | 파일·줄·API 호출을 근거로 기록 | 의존 라이브러리 내부는 분석 안 함, Java만 지원 |
| [GitHub CodeQL](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/) (GitHub·Santander·Microsoft) | 사용자 정의 CodeQL 질의로 CBOM 생성, 여러 저장소 일괄 분석(MRVA) | — | 큰 프로그램에서는 함수 경계를 넘는 데이터 흐름 분석이 필요하다고 봄 |
| [cdxgen](https://github.com/cdxgen/cdxgen) (OWASP CycloneDX) | 정적 분석 엔진 기반 | 알고리즘을 구현하는 패키지까지 식별, 발생 위치와 호출 스택 근거 기록 | `tracebom`으로 실행 중 앱을 추적해 협상된 TLS 스위트·암호 라이브러리 수집 |
| [OPSWAT MetaDefender CBOM](https://www.opswat.com/docs/mdcore/software-bill-of-materials/cbom) | 소스코드의 암호 API 호출과 import 탐지 | 의존성 선언 줄을 근거로 제시 | `pom.xml`, `requirements.txt`, `package.json`, `go.mod` 등에서 암호 라이브러리(BouncyCastle, Tink 등) 보고. 라이브러리에서 알고리즘을 추론한다는 설명은 없음 |
| [SandboxAQ AQtive Guard](https://sandboxaq.com/products) (상용) | 파일 분석기, 네트워크 분석기, 실행 중 분석기 3종 | — | 실행 중 암호 라이브러리와의 상호작용을 기록 |
| [Semgrep](https://docs.semgrep.dev/kb/rules/understand-severities) (범용 SAST) | 구문 트리 패턴 규칙 | 규칙 작성자가 신뢰도를 직접 정함. 취약점이 아니라 규칙이 오탐 없이 잡는 정도를 뜻함 | 신뢰도 낮은 규칙은 코드 감사자용으로 둠 |

## PM 명세에 반영할 점

완료 기준 문구가 바뀌는 1번(표준 필드)과 5번(의존성 기대치)은 승인 전에 반영하는 것이 좋다.

1. **신뢰도는 표준 필드에 기록한다.** CycloneDX 1.6 구성요소의 `evidence.identity[].methods[]`에 탐지 방식(`technique`)과 0\~1 신뢰도(`confidence`)를 넣을 수 있다(공식 스키마로 확인). 탐지 방식 값에는 `source-code-analysis`, `ast-fingerprint`, `manifest-analysis`, `dynamic-analysis` 등이 있다. `cbom-scout:` 전용 속성만 쓰면 다른 도구가 읽지 못하므로, 표준 필드를 기본으로 하고 전용 속성은 보조로 둔다.
2. **신뢰도를 CI 판정과 연결한다.** 낮은 신뢰도의 탐지는 기록하되 빌드를 실패시키지 않는 정책 옵션을 둔다(Semgrep의 감사용 규칙 방식). 변수 값을 끝내 해석하지 못하면 신뢰도를 낮추는 규칙이 고정 신뢰도보다 정확하다.
3. **API 지식 베이스를 데이터로 분리한다.** “어떤 API의 몇 번째 인자가 알고리즘·키 길이인가”를 데이터 파일로 빼면 라이브러리 추가가 코드 수정이 아니라 데이터 추가가 된다. Cryptoscope 논문의 교훈이자 저장소 원칙 “판정 기준은 데이터로”와도 맞다.
4. **Python 구문 트리 분석의 범위를 정한다.** 표준 `ast` 모듈로 외부 의존성 없이 가능하다. 같은 함수·모듈 안의 상수 추적은 1차, 함수를 넘나드는 추적은 후속으로 둔다. 참고로 Cryptoscope는 Java 프로젝트 7개·기준 자산 97개에서 재현율 92%(부분 일치 포함 98%), 정밀도 97%를 보고했다.
5. **의존성 분석의 기대치를 낮춘다.** 매니페스트로 알 수 있는 것은 “이 암호 라이브러리를 쓴다”까지다. 완료 기준은 “라이브러리 이름·버전·선언 위치를 `manifest-analysis`로 기록하고, liboqs나 BouncyCastle PQC 지원 버전 같은 알려진 라이브러리에는 참고 정보를 붙인다” 수준이 정확하다.
6. **평가용 예제 묶음은 기존 벤치마크 방식을 따른다.** CryptoAPI-Bench처럼 안전한 사용 사례를 함께 넣어 오탐률을 잴다. 주석·문자열·변수 전달·함수 경계 같은 범주별로 정답 표시를 달고 정밀도·재현율을 범주별로 낸다. 기존 벤치마크는 “오용 탐지”용이라 사례 출처로만 참고하고, 정답은 사람이 확인한다(Cryptoscope도 LLM으로 만든 정답을 대대적으로 수정해야 했다).
7. **직접 만들기와 연동을 함께 검토한다.** Java·Go는 이미 CBOMkit이 라이브러리별로 정밀하게 다룬다. tree-sitter 도입과 별개로 “CBOMkit 결과 자동 병합”도 선택지로 올린다. `merge` 기능이 있어 비용이 작다.
8. **실행 중 추적은 이번 범위 밖으로 명시한다.** 상용 제품과 cdxgen은 정적 분석의 한계를 실행 중 추적으로 보완한다. 명세의 “하지 않는 것”에 후속 후보로 적는다.

## 출처

- [sonar-cryptography (CBOMkit)](https://github.com/PQCA/sonar-cryptography)
- [Cryptoscope 논문 (arXiv 2503.19531)](https://arxiv.org/pdf/2503.19531)
- [GitHub 블로그: CodeQL로 PQC 대응](https://github.blog/security/vulnerability-research/addressing-post-quantum-cryptography-with-codeql/)
- [cdxgen](https://github.com/cdxgen/cdxgen)
- [OPSWAT CBOM 문서](https://www.opswat.com/docs/mdcore/software-bill-of-materials/cbom)
- [SandboxAQ AQtive Guard](https://sandboxaq.com/products)
- [Semgrep 규칙 신뢰도 기준](https://docs.semgrep.dev/kb/rules/understand-severities)
- [CryptoAPI-Bench](https://yaogroup.cs.vt.edu/papers/IEEE_SecDev19_CryptoAPI-Bench.pdf)
- [CamBench](https://arxiv.org/pdf/2204.06447)
