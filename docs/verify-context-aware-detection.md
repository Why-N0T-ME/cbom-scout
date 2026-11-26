# 직접 검증 가이드 — 문맥 인식 탐지 (1a)

브랜치 `feature/context-aware-detection`, 명세 [docs/specs/context-aware-detection.md](specs/context-aware-detection.md).
명령은 모두 **Windows PowerShell**, 저장소 루트 기준이다.

```powershell
git checkout feature/context-aware-detection
python -m pip install -e ".[dev]"
```

## 1. 전체 테스트

```powershell
python -m pytest -q
```

- 정상: `203 passed` (2026-11-27 기준).
- 작업 트리에 테스터 1회차 산출물 `tests/acceptance/test_context_aware_detection.py` 가 남아 있으면(커밋 안 됨) 옛 라벨 기준이라
  `test_ac61_labels_are_human_reviewed` 1개가 실패한다. 그 파일을 빼고 돌리려면:

```powershell
python -m pytest -q --ignore=tests/acceptance/test_context_aware_detection.py
```

## 2. 평가 도구 (탐지 품질)

```powershell
python tests/corpus/evaluate.py                                  # 신뢰도 기준: 전체, 0.5 이상 (기본)
python tests/corpus/evaluate.py --thresholds 0,0.5,0.9           # 기준 바꾸기
python tests/corpus/evaluate.py --json result.json --markdown result.md
```

결과 읽는 법:

| 절 | 뜻 |
|---|---|
| `사람 검수: 검수 N개 · 미검수 M개` | `reviewed: true` 인 라벨 수. 미검수 라벨도 채점에 들어간다 |
| `전체 (phase 1)` | 엔진별 TP(맞게 찾음)·FP(오탐)·FN(미탐)·정밀도·재현율. 닫힌 세계 채점이라 라벨에 없는 탐지는 모두 FP |
| `신뢰도 기준별` | 기준 미만 신뢰도로 기록된 탐지를 없는 것으로 보고 다시 채점. `auto` 의 로그 문자열 속 PQC 이름(0.3)은 0.5 이상에서 빠진다 |
| `언어별`, `범주별` | 어디서 틀리는지. `comment`·`docstring`·`string-literal`·`lookalike` 의 `auto` FP 는 0 이어야 한다(AC-63). `pqc-string` FP 2건은 엔진 설계(신뢰도 0.3 기록)와 정답 기준(❌)의 차이로 그대로 보이게 둔 것 |
| `후속 단계 목표 (phase later)` | 함수·파일 경계를 넘는 사례. 1차 지표와 분리 집계. 현재 두 엔진 모두 0/5 |

2026-11-27 기준 값(라벨 141개, 검수 68개):

| 엔진 | 기준 | TP | FP | FN | 정밀도 | 재현율 |
|---|---|---:|---:|---:|---:|---:|
| auto | 전체 | 82 | 4 | 2 | 0.953 | 0.976 |
| auto | 0.5 이상 | 82 | 2 | 2 | 0.976 | 0.976 |
| regex | 전체 | 59 | 45 | 25 | 0.567 | 0.702 |

- `auto` 미탐 2건: `md5sum` 외부 실행(`python/lookalike.py:5`), `RSA_generate_key_ex(…, 2048)` 의 키 길이(`c/crypto.c:14`).
- 말뭉치는 구현과 함께 작성해 실제보다 좋게 나올 수 있다. 독립 사례로 다시 재는 것이 테스터 재실행의 목적이다.
- 결과에서 FP·FN 목록은 `--json` 출력의 `false_positives`, `false_negatives` 에 있다.

## 3. 데모 스캔

```powershell
cbom-scout scan examples/demo-app -v
echo $LASTEXITCODE
```

정상이면 stderr 첫 줄이 아래와 같고 종료 코드는 **1** 이다(데모는 의도적으로 취약하다).

```
cbom-scout: 자산 28개 (알고리즘 23, 취약 15, PQC·하이브리드 3) · 실패 5 / 경고 14 / 참고 2 / 통과 7 → 실패
```

예전 엔진과 비교:

```powershell
cbom-scout scan examples/demo-app --engine regex -o regex.json
```

- `자산 29개 (알고리즘 24, … 참고 3 / 통과 7)` 가 나오면 정상. 차이는 `Cipher(algorithms.AES(key), modes.ECB())` 에서 생기던 중복 `AES` 1개뿐이다.
- `cbom.json` 의 구성요소에 `evidence.identity`(탐지 방식·신뢰도), `occurrences[].symbol`(API 이름), `cbom-scout:scope` 속성이 붙는다.

## 4. 남은 일

- [ ] **2부 무작위 20개 검수** — #2, #4, #5, #10, #13, #15, #20, #37, #40, #59, #78, #82, #84, #102, #105, #113, #115, #124, #125, #127.
      2개 이상 틀리면 나머지 50개 전수 검토.
- [ ] **새 라벨 4건 검수** — #137·#138(보안 용도가 아닌 MD5, ✅), #139 `aes_theme`·#140 `des = "description"`(❌).
- [ ] 검수한 라벨을 `tests/corpus/labels.json` 에서 `"reviewed": true` 로 바꾸기 (번호는 `labels` 배열의 순서, 0부터).
- [ ] **테스터 재실행(2회차)** — 위 검수가 끝난 뒤. 1회차 결과는 옛 라벨 기준이라 판정에 쓰지 않는다.
- [ ] PR #3(`additionalContext` 제거) 병합 — 이 브랜치는 그 위에 쌓여 있다.
- [ ] 1b(의존성 매니페스트에서 암호 라이브러리 식별)는 별도 PR.
- [ ] (선택) 깨진 JSON 을 `check`·`merge`·`--policy` 에 넘기면 Traceback 이 나는 기존 문제 — 이번 기능과 무관, 별도 수정 여부 결정.
