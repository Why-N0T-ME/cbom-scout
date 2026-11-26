# 🔐 cbom-scout 암호자산 리포트

**판정: 🔴 실패** · 정책 `nist-ir8547-default`

| 전체 자산 | 알고리즘 | 취약 알고리즘 | PQC·하이브리드 | 발견 위치 |
|---:|---:|---:|---:|---:|
| 29 | 24 | 15 | 3 | 40 |

정책 결과: 🔴 실패 5 · 🟠 경고 14 · 🔵 참고 3 · 🟢 통과 7

## 조치가 필요한 자산

| 판정 | 자산 | 유형 | 상태 | 조치 | 위치 |
|---|---|---|---|---|---|
| 🔴 실패 | **3DES-CBC** | 알고리즘 | 즉시 교체 (취약) | 즉시 교체: 고전 컴퓨터로도 안전하지 않음 — NIST 사용 금지 (SP 800-131A) | `examples/demo-app/src/AuthService.java:20` |
| 🔴 실패 | **AES-ECB** | 알고리즘 | 즉시 교체 (취약) | 즉시 교체: 고전 컴퓨터로도 안전하지 않음 — ECB 모드 — 패턴이 드러남, 사용 금지 | `examples/demo-app/src/payment.py:26` |
| 🔴 실패 | **MD5** | 알고리즘 | 즉시 교체 (취약) | 즉시 교체: 고전 컴퓨터로도 안전하지 않음 — 충돌 공격 가능 — 고전적으로도 취약 | `examples/demo-app/src/payment.py:18` |
| 🔴 실패 | **RSA-1024** | 알고리즘 | 즉시 교체 (취약) | 즉시 교체: 고전 컴퓨터로도 안전하지 않음 — 1024비트 — 고전적으로도 취약 (최소 2048비트) | `examples/demo-app/src/AuthService.java:7` |
| 🔴 실패 | **SHA-1** | 알고리즘 | 즉시 교체 (취약) | 즉시 교체: 고전 컴퓨터로도 안전하지 않음 — 충돌 공격 가능 — 서명·무결성 용도 금지 | `examples/demo-app/config/sshd_config:2`, `examples/demo-app/src/server.go:22`, `examples/demo-app/src/web.ts:9` |
| 🟠 경고 | **DH-2048** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/config/sshd_config:1` |
| 🟠 경고 | **EC-P-256** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 — 타원곡선 키 | `examples/demo-app/certs/device.pem`, `examples/demo-app/src/payment.py:14` |
| 🟠 경고 | **ECDH-P-384** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/config/nginx.conf:4` |
| 🟠 경고 | **ECDSA** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/certs/device.pem`, `examples/demo-app/src/AuthService.java:13` |
| 🟠 경고 | **ECDSA-P-384** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/src/server.go:20` |
| 🟠 경고 | **Ed25519** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/config/sshd_config:2` |
| 🟠 경고 | **O=Demo Corp,CN=api.demo.example** | 인증서 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 — RSA 키 인증서 — PQC(ML-DSA) 인증서로 교체 계획 필요 | `examples/demo-app/certs/api.crt` |
| 🟠 경고 | **O=Demo Corp,CN=device.demo.example** | 인증서 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 — EC 키 인증서 — PQC(ML-DSA) 인증서로 교체 계획 필요 | `examples/demo-app/certs/device.pem` |
| 🟠 경고 | **RSA** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/certs/api.crt`, `examples/demo-app/config/sshd_config:2` |
| 🟠 경고 | **RSA-2048** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/certs/api.crt`, `examples/demo-app/src/payment.py:10` |
| 🟠 경고 | **RSA-3072** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/src/web.ts:4` |
| 🟠 경고 | **X25519** | 알고리즘 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/config/nginx.conf:4`, `examples/demo-app/config/sshd_config:1`, `examples/demo-app/src/server.go:15` |
| 🟠 경고 | **public-key:79cad0ab282df80a** | 키 자료 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/certs/api.crt` |
| 🟠 경고 | **public-key:8a8b4adb24ad816b** | 키 자료 | 양자 취약 공개키 | 양자 취약 공개키: NIST IR 8547 기준 2030년 이후 비권고, 2035년 이후 금지 → ML-KEM/ML-DSA 또는 하이브리드로 전환 | `examples/demo-app/certs/device.pem` |
| 🔵 참고 | **AES** | 알고리즘 | 대칭키·해시 상향 권장 | 대칭키·해시 상향 권장 (AES-256, SHA-384 이상) — 키 길이 미확인 → AES-256 확인 필요 | `examples/demo-app/src/payment.py:26` |
| 🔵 참고 | **AES-GCM** | 알고리즘 | 대칭키·해시 상향 권장 | 대칭키·해시 상향 권장 (AES-256, SHA-384 이상) — 키 길이 미확인 → AES-256 확인 필요 | `examples/demo-app/src/payment.py:31` |
| 🔵 참고 | **SHA-256** | 알고리즘 | 대칭키·해시 상향 권장 | 대칭키·해시 상향 권장 (AES-256, SHA-384 이상) — 현재 허용, 장기적으로 SHA-384 이상 권장 | `examples/demo-app/certs/api.crt`, `examples/demo-app/src/AuthService.java:13`, `examples/demo-app/src/payment.py:22` |

<details><summary>통과한 자산 7개</summary>

- AES-256-GCM (대칭키·해시 충분)
- ML-KEM (양자내성)
- ML-KEM-768 (양자내성)
- SHA-384 (대칭키·해시 충분)
- SHA-512 (대칭키·해시 충분)
- TLS examples/demo-app/config/nginx.conf:3 (기준 충족)
- X25519MLKEM768 (하이브리드 (전환기 권장))

</details>

> CycloneDX 1.6 CBOM 원본은 워크플로 아티팩트로 내려받을 수 있습니다.
