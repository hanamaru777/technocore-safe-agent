import os
import secrets
import sys

import pytest

from flop_agent import cli, core


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


def test_show_did_uses_one_ephemeral_signer_child(monkeypatch, capsys):
    monkeypatch.setenv("SIGN_SEED", secrets.token_hex(32))
    monkeypatch.setattr(sys, "argv", ["flop", "show-did"])
    cli.main()
    assert '"did": "did:key:z6Mk' in capsys.readouterr().out
    assert "SIGN_SEED" not in os.environ


def test_manual_post_reuses_preflight_did_and_rejects_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    dummy_seed = secrets.token_hex(32)
    monkeypatch.setenv("SIGN_SEED", dummy_seed)
    did = core.current_did()
    assert "SIGN_SEED" not in os.environ
    monkeypatch.setenv("SIGN_SEED", dummy_seed)  # separate CLI child in the Windows flow
    monkeypatch.setattr(core, "make_nonce", lambda *_: "1")
    # Return the real signer result captured by the HTTP fake without a second
    # signer invocation, preserving the one-child manual-post invariant.
    signed = []
    real_invoke = core.invoke_signer
    def invoke(*args):
        result = real_invoke(*args); signed[:] = result; return result
    monkeypatch.setattr(core, "invoke_signer", invoke)
    class Receipt:
        def raise_for_status(self): pass
        def json(self): return {"posted": {"from": did, "nonce": "1", "text": "manual test", "sig": signed[1], "seq": 1, "ts": "2026-08-30T00:00:00Z"}}
    monkeypatch.setattr(core.httpx, "post", lambda *args, **kwargs: Receipt())
    monkeypatch.setattr(core, "read_room", lambda room: pytest.fail("manual signed post must use the POST receipt"))
    assert core.post_signed("lobby", "manual test", True, did=did)["did"] == did
    assert "SIGN_SEED" not in os.environ
    monkeypatch.setenv("SIGN_SEED", dummy_seed)
    with pytest.raises(RuntimeError, match="signer の出力"):
        core.post_signed("lobby", "manual test", True, did="did:key:z6MkWrong")
    assert "SIGN_SEED" not in os.environ
    assert "--did $preflightDid" in (core.ROOT / "flop.ps1").read_text("utf-8")
