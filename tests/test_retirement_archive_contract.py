"""R861: fully synthetic offline archive metadata contract tests."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/retirement_archive_contract.py"

def module():
    spec = importlib.util.spec_from_file_location("flop_r861", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def fixtures(m):
    capture = {
        "kind": "preliminary_capture_only", "source_commit": m.SOURCE,
        "capture_unit_remained_inactive": True,
        "signer_autopilot_and_nonce_not_archived": True,
        "off_host_restored": False,
        "sqlite_integrity_off_host_pending": True,
        "files": [
            {"source_relative": src, "source_size_at_preflight": 2000,
             "archive_file": name, "archive_size": 1600, "backup_steps": 1}
            for src, name, _ in m.DBS
        ],
    }
    state = {"source_commit":m.SOURCE,
             "files":[{"path": p, "type": "regular", "size": 100}
                      for p in sorted(m.REQUIRED)]}
    return capture, state

def add(state, *names):
    for name in names:
        state["files"].append({"path": name, "type": "regular", "size": 1})

def test_real_preliminary_names_map_exactly_to_offhost_canonical():
    m = module()
    captures, states = m.plan(*fixtures(m))
    assert captures == [
        ("capture-0.sqlite3", "capture/lobby-capture.sqlite3"),
        ("capture-1.sqlite3", "capture/lobby-capture-service.sqlite3"),
    ]
    assert "state/autopilot/autopilot-audit.jsonl" in dict(states)
    assert len(states) == len(m.REQUIRED)

def test_missing_outbox_nonce_audit_and_config_all_stop():
    m = module()
    for missing in ("nonces.json", "autopilot/autopilot-audit.jsonl",
                    "observer/observer-config.json", "signer/oracle-signer-receipts.json"):
        c, s = fixtures(m)
        s["files"] = [r for r in s["files"] if r["path"] != missing]
        with pytest.raises(m.Stop, match="REQUIRED_STATE_MISSING"):
            m.plan(c, s)

def test_rotated_audits_preserved_only_if_contiguous():
    m = module()
    c, s = fixtures(m)
    add(s, "autopilot/autopilot-audit.jsonl.1",
        "autopilot/autopilot-audit.jsonl.2")
    _, states = m.plan(c, s)
    assert "state/autopilot/autopilot-audit.jsonl.2" in dict(states)
    s["files"] = [row for row in s["files"] if not row["path"].endswith(".1")]
    with pytest.raises(m.Stop, match="AUDIT_ROTATION_GAP"):
        m.plan(c, s)

def test_legacy_and_unclassified_paths_fail_closed():
    m = module()
    for path, why in [
        ("observer/autopilot-outbox.json", "LEGACY_AUTOPILOT"),
        ("close1/unchecked.json", "UNCLASSIFIED_STATE"),
        ("public-proofs/unclassified.bin", "UNCLASSIFIED_STATE"),
        ("signer.env", "UNCLASSIFIED_STATE"),
    ]:
        c, s = fixtures(m)
        add(s, path)
        with pytest.raises(m.Stop, match=why):
            m.plan(c, s)

def test_capture_origins_never_directly_copied_with_sidecars():
    m = module()
    c, s = fixtures(m)
    add(s, *[x[0] for x in m.DBS],
        "observer/lobby-capture.sqlite3-wal",
        "observer/lobby-capture.sqlite3-shm")
    cap, rows = m.plan(c, s)
    assert len(cap) == 2 and len(rows) == len(m.REQUIRED)

def test_proof_plan_and_cursors_covered_from_inventory():
    m = module()
    c, s = fixtures(m)
    add(s, "proof-plans/0123456789abcdef.json",
        "cursor-public-room.json")
    _, rows = m.plan(c, s)
    assert "state/proof-plans/0123456789abcdef.json" in dict(rows)
    assert "state/cursor-public-room.json" in dict(rows)

def test_reversed_capture_mapping_rejected():
    m = module()
    c, s = fixtures(m)
    c["files"].reverse()
    with pytest.raises(m.Stop, match="CAPTURE_MAPPING_MISMATCH"):
        m.plan(c, s)

def test_unsafe_traversal_and_symlink_file_type_rejected():
    m = module()
    for path, ty, why in [
        ("../etc/shadow", "regular", "PATH_UNSAFE"),
        ("signer/signer-health.json", "symlink", "STATE_FILE_TYPE_OR_SIZE"),
    ]:
        c, s = fixtures(m)
        if path.startswith(".."):
            add(s, path)
        else:
            for row in s["files"]:
                if row["path"] == path:
                    row["type"] = ty
        with pytest.raises(m.Stop, match=why):
            m.plan(c, s)

def test_duplicate_empty_or_negative_size_rejected():
    m = module()
    c, s = fixtures(m)
    add(s, "nonces.json")
    with pytest.raises(m.Stop, match="STATE_DUPLICATE_PATH"):
        m.plan(c, s)
    c, s = fixtures(m)
    s["files"][0]["size"] = -1
    with pytest.raises(m.Stop, match="STATE_FILE_TYPE_OR_SIZE"):
        m.plan(c, s)

def test_invalid_capture_flags_and_source_commit():
    m = module()
    c, s = fixtures(m)
    c["off_host_restored"] = True
    with pytest.raises(m.Stop, match="CAPTURE_PROVENANCE_INVALID"):
        m.plan(c, s)
    c, s = fixtures(m)
    s["source_commit"] = "0" * 40
    with pytest.raises(m.Stop, match="STATE_INVENTORY_SCHEMA"):
        m.plan(c, s)

def test_source_never_accesses_live_data_network_or_mutates():
    source = SCRIPT.read_text()
    compile(source, str(SCRIPT), "exec")
    for token in ("import sqlite3", "import subprocess", "import requests",
                  "os.system(", "urllib", "shutil.copy", "os.remove(",
                  "Path.write_bytes", "Path.write_text", "systemctl",
                  "BucketCreate", "PutObject"):
        assert token not in source
    assert "FLOP_R861_ORACLE_DELETION_NOT_AUTHORIZED" in source

def test_main_accepts_metadata_offline_only(tmp_path, monkeypatch, capsys):
    m = module()
    c, s = fixtures(m)
    a = tmp_path / "cap.json"
    b = tmp_path / "inventory.json"
    a.write_text(json.dumps(c))
    b.write_text(json.dumps(s))
    monkeypatch.setattr(m.sys, "argv",
                        ["script", "--capture-metadata", str(a),
                         "--state-inventory", str(b)])
    m.main()
    output = capsys.readouterr().out
    assert "FLOP_R861_OFFLINE_METADATA_PLAN_PASS" in output
    assert "FLOP_R861_NO_ARCHIVE_NO_UPLOAD_NO_WRITER_EPOCH_PROOF" in output
