"""Read-only FLOP OCI signer cutover count-only assessment tests."""
import importlib.util
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-signer-cutover-gate.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_retirement_signer_cutover", SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def state(receipts=None, outbox=None):
    did = "did:key:z" + "a" * 50
    return (
        {"schema_version": 1, "receipts": receipts or {}},
        {"schema_version": 1, "enabled": True, "paused": False,
         "outbox": outbox or {}, "receipts": {}},
        {"nonce-key": 5}, {"did": did},
    )

def test_only_counters_no_private_values():
    m = load()
    did = "did:key:z" + "a" * 50
    vals = state(
        {"abc": {"state": "prepared", "did": did, "nonce": "secret"}},
        {"def": {"status": "queued", "text": "private-secret"}}
    )
    summary = m.report(*vals)
    assert summary["signer_prepared"] == 1
    assert summary["outbox_queued"] == 1
    assert summary["nonce_entries"] == 1
    assert "private-secret" not in str(summary)
    assert did not in str(summary)
    assert "nonce-key" not in str(summary)

def test_only_accepted_lifecycle_states():
    m = load()
    for s in ("prepared", "posted", "acknowledged"):
        did = "did:key:z" + "a" * 50
        rows = state(receipts={"x": {"state": s, "did": did}})
        assert m.report(*rows)["signer_" + s] == 1
    for s in ("queued", "posted", "acknowledged", "ambiguous", "quarantined", "expired"):
        rows = state(outbox={"x": {"status": s}})
        assert m.report(*rows)["outbox_" + s] == 1

def test_cross_did_receipts_fail_closed():
    m = load()
    rows = state(receipts={"x": {"state": "posted", "did": "did:key:z" + "b" * 50}})
    with pytest.raises(m.Stop, match="RECEIPT_VALUE_STOP"):
        m.report(*rows)

def test_unknown_outbox_status_not_silently_ignored():
    m = load()
    rows = state(outbox={"x": {"status": "unknown_or_sent"}})
    with pytest.raises(m.Stop, match="OUTBOX_UNEXPECTED_STATUS_STOP"):
        m.report(*rows)

def test_unsafe_path_and_symlink_rejected(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m, "ROOT", tmp_path)
    with pytest.raises(m.Stop, match="NOT_ALLOWLISTED_STOP"):
        m.read_small("../../etc/shadow")
    (tmp_path / "signer").symlink_to("/etc")
    with pytest.raises(m.Stop, match="INPUT_PARENT_INVALID_STOP"):
        m.read_small("signer/oracle-signer-receipts.json")

def test_read_only_file_has_strict_max_size(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m, "ROOT", tmp_path)
    (tmp_path / "signer").mkdir()
    p = tmp_path / "signer/oracle-signer-receipts.json"
    p.write_bytes(b"z" * (m.MAX_JSON + 1))
    with pytest.raises(m.Stop, match="INPUT_SIZE_TYPE_PERM_STOP"):
        m.read_small("signer/oracle-signer-receipts.json")

def test_no_state_or_service_mutation_surface():
    s = SRC.read_text()
    compile(s, str(SRC), "exec")
    for bad in ("sqlite3.connect", ".read_bytes(", "rglob(", "os.walk(",
                "httpx", "urllib", "open(", "subprocess.Popen",
                "systemctl stop", "systemctl start", "systemctl restart",
                "systemctl enable", "systemctl disable", "SIGTERM",
                "os.kill(", "os.rename", "write_text(", "write_bytes(",
                "unlink(", "chmod(", "chown(", "SIGN_SEED",
                "OCI_VAULT_SECRET_OCID", "/etc/technocore-safe-agent/env"):
        assert bad not in s
    assert "FLOP_OCI_SIGNER_CUTOVER_NOT_AUTHORIZED_WHILE_LIVE" in s
    assert "FLOP_OCI_SIGNER_GATE_READ_ONLY_PASS" in s
