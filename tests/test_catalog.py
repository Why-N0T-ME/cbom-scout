from cbom_scout.catalog import BROKEN, HYBRID, PQC, PQC_DRAFT, QV, SYM_OK, SYM_WEAK, classify, normalize


def test_rsa_key_sizes():
    assert classify("RSA", size=1024).status == BROKEN
    c = classify("rsa", size=2048)
    assert c.status == QV and c.key == "RSA-2048" and c.nist_qsl == 0


def test_symmetric():
    assert classify("AES", size=256).status == SYM_OK
    assert classify("AES", size=128).status == SYM_WEAK
    assert classify("AES", size=256, mode="ecb").status == BROKEN
    assert classify("DESede").status == BROKEN
    assert classify("MD5").status == BROKEN
    assert classify("sha384").status == SYM_OK


def test_pqc_and_hybrid():
    assert classify("ML-KEM-768").status == PQC
    assert classify("ML-KEM-768").nist_qsl == 3
    assert classify("x25519mlkem768").status == HYBRID
    assert classify("Falcon").status == PQC_DRAFT
    for kpqc in ("SMAUG-T", "NTRU+", "HAETAE", "AIMer"):
        assert classify(kpqc).status == PQC


def test_normalize_aliases():
    assert normalize("SHA-256") == "SHA-256"
    assert normalize("sha3_384") == "SHA3-384"
    assert normalize("ECDHE") == "ECDH"
    assert normalize("Kyber") == "ML-KEM"
    assert normalize("nonexistent") is None
    assert classify("nonexistent").status == "unknown"


def test_curve_naming():
    assert classify("EC", curve="secp256r1").key == "EC-P-256"
    assert classify("ECDSA", curve="P384").key == "ECDSA-P-384"
