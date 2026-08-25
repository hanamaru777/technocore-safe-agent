import os
import secrets

from flop_agent import core


def test_official_signer_uses_fresh_dummy_material(monkeypatch):
    monkeypatch.setenv("SIGN_SEED", secrets.token_hex(32))
    did = core.current_did()
    signed = core.invoke_signer("say", "lobby", "1", "test message")
    assert did.startswith("did:key:z6Mk")
    assert signed[0] == did
    assert len(signed[1]) == 86
    monkeypatch.delenv("SIGN_SEED")
