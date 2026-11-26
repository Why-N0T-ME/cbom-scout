# 평가 말뭉치

탐지 엔진의 오탐·미탐을 범주별로 재는 예제 모음이다. 의도적으로 취약한 암호 코드가 들어 있다(`.cbomignore` 의 `tests/` 로 자체 스캔에서 제외).

- `files/` — 스캔 대상 예제 (Python·Java·Go·JS/TS·C·C#·설정 파일)
- `labels.json` — 정답 라벨. 필드: `file`, `line`, `name`, `label`(positive/negative), `category`, `phase`(1/later), `source`, `reviewed`, 선택 `scope`
- `evaluate.py` — 채점 도구. `python tests/corpus/evaluate.py [--json r.json] [--markdown r.md]`

## 출처와 라이선스

모든 예제와 라벨은 이 저장소에서 **직접 작성**했다(`source: "handwritten"`). 외부 벤치마크(CryptoAPI-Bench, CamBench 등),
Semgrep 규칙, 외부 문서의 코드나 문구를 복사하거나 바꿔 쓴 것은 없다. 따라서 `third_party.json` 에 등록할 외부 파일이 없다.

| 파일 | 출처 |
|---|---|
| `python/comments.py`, `docstrings.py`, `strings.py`, `alias.py`, `multiline.py`, `indirect_const.py`, `indirect_default.py`, `java/Crypto.java`, `go/main.go`, `js/crypto.ts`, `c/crypto.c`, `csharp/Crypto.cs`, `config/sshd_config` | 직접 작성. 이 저장소 명세 `docs/specs/context-aware-detection.md` 의 완료 기준 예시(AC-1~AC-26)를 바탕으로 다시 씀 |
| `python/direct.py`, `lookalike.py`, `tests/test_crypto.py`, `pkg/*`, `java/src/test/java/CryptoTest.java`, `go/util_test.go`, `js/crypto.test.js`, `config/nginx.conf` | 직접 작성 |

- 예제 속 API 이름(`hashlib.md5`, `Cipher.getInstance` 등)은 각 라이브러리의 공개 API 이름이다.
- 빈 입력의 MD5·SHA-1 해시값(`d41d8cd9…`, `da39a3ee…`)은 계산 결과인 사실이다.
- 새 사례를 외부 자료에서 가져오려면 CLAUDE.md "외부 코드·데이터" 규칙을 따른다. Semgrep 규칙은 복사하지 않고 사실·아이디어만 참고해 새로 쓴다.
