"""R1128 synthetic-only encrypted source bounded preseed tests.

The test never authenticates to Oracle, AWS, TradeBot or external services.
"""
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/migration/r1128_provisional_preseed.py"
spec = importlib.util.spec_from_file_location("r1128_test_source", SCRIPT)
P = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = P
spec.loader.exec_module(P)


def fixture_roots(tmp_path, monkeypatch):
    app, state = tmp_path / "flop-app", tmp_path / "flop-state"
    app.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    (state / "signer").mkdir(mode=0o700)
    (state / "verified-did.json").write_bytes(b'{"did":"example-only-not-real"}')
    (state / "nonces.json").write_bytes(b'{"nonce":"fixture"}')
    (state / "signer/oracle-signer-receipts.json").write_bytes(
        b'{"receipts":{"test-only":{"state":"quarantined"}}}')
    monkeypatch.setattr(P, "APP", app)
    monkeypatch.setattr(P, "STATE", state)
    monkeypatch.setattr(P, "_original_host", lambda scope: None)
    monkeypatch.setattr(P, "pressure", lambda: None)
    monkeypatch.setattr(P, "_mount_guard", lambda: None)
    return app, state


def test_real_r1084_aead_provisional_ciphertext_not_plaintext(tmp_path, monkeypatch):
    app, state = fixture_roots(tmp_path, monkeypatch)
    recovery = b"offline-test-only-independent-code-32-bytes-long"
    stream = io.BytesIO()
    result = P.preseed_live_to_stream({}, recovery, stream)
    cipher = stream.getvalue()
    assert result["mode"] == P.PROVISIONAL_EPOCH
    assert result["source_complete"] is False
    assert result["history_finality"] == "UNKNOWN"
    assert result["cutover"] == "NO_GO"
    assert cipher.startswith(b"FLOPST01")
    assert b"example-only-not-real" not in cipher
    assert b"fixture" not in cipher

    W = P.load("r1084_offhost_ciphertext_stream.py", "r1128_verify")
    T = P.load("r1066_transfer.py", "r1128_decode")
    parent = tmp_path / "secret-sink"
    parent.mkdir(mode=0o700)
    archive = parent / "preseed"
    receipt = W.receive_offhost_ciphertext(io.BytesIO(cipher), archive,
                                            quota_bytes=20 * 1024**2)
    assert receipt["ciphertext_files"] >= 3
    assert receipt["aead_verified"] is False
    raw = b"".join(T.decrypt(archive, recovery))
    assert b"example-only-not-real" in raw
    assert b"fixture" in raw

    tampered = bytearray(cipher)
    tampered[len(tampered) // 2] ^= 0x80
    with pytest.raises(Exception):
        W.receive_offhost_ciphertext(io.BytesIO(tampered),
                                     parent / "tampered", quota_bytes=20 * 1024**2)


def test_no_automatic_cli_or_full_live_export():
    source = SCRIPT.read_text(encoding="utf8")
    assert "if __name__" not in source
    assert "argparse.ArgumentParser" not in source
    assert 'PROVISIONAL_LIVE_UNFENCED_NO_REPLAY' in source
    assert "from cryptography" not in source  # reuse audited R1084 dependencies
    assert "os.unlink" not in source and "subprocess.Popen" not in source
    assert "source_complete" in source


def test_symlinks_and_hardlinked_finance_state_stop(tmp_path, monkeypatch):
    app, state = fixture_roots(tmp_path, monkeypatch)
    T = P.load("r1066_transfer.py", "r1128_offline_test_t1")
    p = state / "nonces.json"
    p.unlink()
    target = tmp_path / "outside-nonces"
    target.write_bytes(b"fixture")
    p.symlink_to(target)
    with pytest.raises(P.Stop, match="SOURCE_OBJECT_STOP"):
        P.selected_manifest({"app": app, "state": state}, T)
    p.unlink()
    p.write_bytes(b"fixture")
    os.link(p, state / "nonces-link")
    with pytest.raises(P.Stop, match="SOURCE_OBJECT_STOP"):
        P.selected_manifest({"app": app, "state": state}, T)


def test_missing_and_large_file_fail_closed(tmp_path, monkeypatch):
    app, state = fixture_roots(tmp_path, monkeypatch)
    T = P.load("r1066_transfer.py", "r1128_offline_test_t2")
    (state / "nonces.json").unlink()
    with pytest.raises(FileNotFoundError):
        P.selected_manifest({"app": app, "state": state}, T)
    (state / "nonces.json").write_bytes(b"X" * (1024 * 1024 + 1))
    with pytest.raises(P.Stop, match="SOURCE_OBJECT_STOP"):
        P.selected_manifest({"app": app, "state": state}, T)


def test_source_head_original_and_owner_admission_are_fixed():
    assert len(P.SELECTED) == 3
    assert P.SELECTED[0][0] == "state/verified-did.json"
    assert "state/nonces.json" in [x[0] for x in P.SELECTED]
    assert P.HEAD == "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    with pytest.raises(P.Stop, match="ORIGINAL_HOST_STOP"):
        # unittest/CI are non-root and not on the OCI original.
        P._original_host({})


def test_output_failure_does_not_create_source_backup(tmp_path, monkeypatch):
    fixture_roots(tmp_path, monkeypatch)
    class BreakOutput:
        def isatty(self): return False
        def write(self, data): raise RuntimeError("synthetic destination disconnect")
    with pytest.raises(RuntimeError, match="synthetic destination disconnect"):
        P.preseed_live_to_stream({}, b"not-a-production-secret-test-only-32+bytes",
                                 BreakOutput())
    assert sorted(x.name for x in tmp_path.iterdir()) == ["flop-app", "flop-state"]


def test_independent_ed25519_owner_approval_binds_exact_preseed_scope(monkeypatch):
    # Synthetic, non-network proof of R1063 signed owner admission. A forged
    # boolean or altered source/destination must not release the source.
    if sys.platform != "linux":
        pytest.skip("Linux-only original-host source admission")
    import hashlib
    from types import SimpleNamespace
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    G = P.load("r1063_release_gates.py", "r1128_test_independent_gates")
    signing_key = Ed25519PrivateKey.generate()
    pub = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = hashlib.sha256(pub).hexdigest()
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    destination = "f" * 64 if host != "f" * 64 else "e" * 64
    context = {
        "campaign": "1" * 64,
        "host": host,
        "destination": destination,
        "did": "2" * 64,
        "source_head": P.HEAD,
        "generation": 1,
    }
    enrolled_elsewhere = G.Trust(context, {
        kid: (pub, frozenset({"owner"}))}, frozenset())
    binding = G.sha({
        "purpose": "provisional_preseed_ciphertext_only",
        "source": host,
        "destination": destination,
        "source_head": P.HEAD,
        "files": [x[0] for x in P.SELECTED],
        "max_plaintext_bytes": P.MAX_TOTAL,
        "non_authoritative": True,
    })
    import time
    stamp = int(time.time())
    body = {
        "action": "provisional_preseed_offhost",
        "context": context,
        "binding": binding,
        "approved_at": stamp - 2,
        "expires_at": stamp + 240,
    }
    packet = {
        "signer": kid,
        "body": body,
        "signature": signing_key.sign(G.DOMAIN + G.canonical(body)).hex(),
    }
    scope = {
        "expected_machine_sha256": host,
        "destination_machine_sha256": destination,
        "independent_trust": enrolled_elsewhere,
        "signed_owner_approval": packet,
    }
    monkeypatch.setattr(P.os, "geteuid", lambda: 0)
    monkeypatch.setattr(P, "_mount_guard", lambda: None)
    monkeypatch.setattr(P.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=0,
                            stdout=(P.HEAD + "\n").encode()))
    P._original_host(scope)
    altered = dict(scope, destination_machine_sha256="a" * 64)
    with pytest.raises(P.Stop, match="OWNER_AUTH_REQUIRED"):
        P._original_host(altered)
    unsigned = dict(scope, signed_owner_approval={
        **packet, "signature": "0" * 128})
    with pytest.raises(Exception):
        P._original_host(unsigned)
    with pytest.raises(P.Stop, match="OWNER_AUTH_REQUIRED"):
        P._original_host({"owner_provisional_authorization": True})
