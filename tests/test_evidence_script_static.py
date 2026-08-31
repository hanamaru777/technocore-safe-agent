from pathlib import Path


SOURCE = Path("scripts/evidence.py").read_text("utf-8")


def test_evidence_helper_is_read_only_and_has_no_secret_input_lane():
    assert 'BASE_URL = "https://technocore.chat"' in SOURCE
    assert 'httpx.stream("GET"' in SOURCE
    assert "httpx.post" not in SOURCE
    assert '"POST"' not in SOURCE
    assert "SIGN_SEED" not in SOURCE
    assert "private_key" not in SOURCE.lower()
    assert "--seed" not in SOURCE
    assert "--url" not in SOURCE


def test_evidence_helper_pins_public_allowlist_and_offline_signature_check():
    for field in ("seq", "ts", "from", "nonce", "text", "sig"):
        assert f'"{field}"' in SOURCE
    assert "Ed25519PublicKey" in SOURCE
    assert 'f"{room}|{nonce}|{text}"' in SOURCE
    assert "X-Room-Generation" in SOURCE
    assert 'path.open("x"' in SOURCE
