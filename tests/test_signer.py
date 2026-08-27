import os
import secrets

from flop_agent import core


def test_official_signer_uses_fresh_dummy_material(monkeypatch):
    dummy_seed = secrets.token_hex(32)
    monkeypatch.setenv("SIGN_SEED", dummy_seed)
    did = core.current_did()
    # Production supplies SIGN_SEED around each signer subprocess only.
    monkeypatch.setenv("SIGN_SEED", dummy_seed)
    signed = core.invoke_signer("say", "lobby", "1", "test message")
    assert did.startswith("did:key:z6Mk")
    assert signed[0] == did
    assert len(signed[1]) == 86
    assert "SIGN_SEED" not in os.environ
