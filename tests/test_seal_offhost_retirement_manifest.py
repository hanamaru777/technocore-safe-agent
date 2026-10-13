"""R864 only isolated synthetic stage tests. No OCI data and no network."""
import hashlib
import importlib.util
import json
from pathlib import Path
import os

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] / "packaging" / "archive"
          / "seal_offhost_retirement_manifest.py")


def module():
    spec = importlib.util.spec_from_file_location("flop_r864", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def prepare(tmp_path, m):
    c = m.contract()
    capture = {"kind": "preliminary_capture_only", "source_commit": c.SOURCE,
               "capture_unit_remained_inactive": True,
               "signer_autopilot_and_nonce_not_archived": True,
               "off_host_restored": False,
               "sqlite_integrity_off_host_pending": True,
               "files": [{"source_relative": origin,
                          "source_size_at_preflight": 128,
                          "archive_file": image, "archive_size": 128,
                          "backup_steps": 1} for origin, image, _ in c.DBS]}
    state = {"source_commit": c.SOURCE,
             "files": [{"path": p, "type": "regular", "size": 16}
                       for p in sorted(c.REQUIRED)]}
    stage = tmp_path / "stage"
    stage.mkdir(parents=True)
    for name in sorted(c.REQUIRED):
        target = stage / "state" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"s" * 16)
    for _, _, target in c.DBS:
        dest = stage / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"d" * 128)
    return stage, capture, state


def test_can_seal_exact_canonical_staged_tree_and_external_hash(tmp_path):
    m = module()
    stage, capture, state = prepare(tmp_path, m)
    count, digest = m.seal(stage, capture, state)
    assert count == len(state["files"]) + 2
    assert len(digest) == 64
    manifest = stage / m.MANIFEST
    raw = manifest.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    assert manifest.stat().st_mode & 0o777 == 0o600
    doc = json.loads(raw)
    assert doc["schema"] == 1
    assert doc["kind"] == "flop-retirement-offhost-v1"
    assert doc["source_commit"] == m.contract().SOURCE
    assert {x["path"] for x in doc["files"]} == {
        "state/" + row["path"] for row in state["files"]
    } | {db[2] for db in m.contract().DBS}
    assert all(len(x["sha256"]) == 64 for x in doc["files"])


def test_manifest_creation_is_one_shot_without_overwrite(tmp_path):
    m = module()
    stage, c, s = prepare(tmp_path, m)
    m.seal(stage, c, s)
    original = (stage / m.MANIFEST).read_bytes()
    with pytest.raises(m.Stop, match="MANIFEST_ALREADY_PRESENT"):
        m.seal(stage, c, s)
    assert (stage / m.MANIFEST).read_bytes() == original


def test_missing_file_or_extra_file_fails_closed(tmp_path):
    m = module()
    stage, c, s = prepare(tmp_path, m)
    (stage / "state" / s["files"][0]["path"]).unlink()
    with pytest.raises(m.Stop, match="STAGE_FILES_NOT_EXACTLY_MANIFESTED"):
        m.seal(stage, c, s)
    assert not (stage / m.MANIFEST).exists()
    stage, c, s = prepare(tmp_path / "extra", m)
    (stage / "state" / "unexpected.txt").write_text("unexpected")
    with pytest.raises(m.Stop, match="STAGE_FILES_NOT_EXACTLY_MANIFESTED"):
        m.seal(stage, c, s)


def test_staged_size_drift_rejects(tmp_path):
    m = module()
    stage, c, s = prepare(tmp_path, m)
    (stage / "capture" / "lobby-capture.sqlite3").write_bytes(b"1" * 127)
    with pytest.raises(m.Stop, match="STAGED_SIZE_MISMATCH"):
        m.seal(stage, c, s)


def test_symlinked_extra_and_required_staged_files_rejected(tmp_path):
    m = module()
    stage, c, s = prepare(tmp_path, m)
    (stage / "state" / "unsafe.txt").symlink_to("/etc/passwd")
    with pytest.raises(m.Stop, match="STAGE_SYMLINK_STOP"):
        m.seal(stage, c, s)
    (stage / "state" / "unsafe.txt").unlink()
    expected = stage / "state" / "nonces.json"
    expected.unlink()
    expected.symlink_to("/etc/passwd")
    with pytest.raises(m.Stop, match="STAGE_SYMLINK_STOP"):
        m.seal(stage, c, s)


def test_hardlink_and_unclassified_state_are_rejected(tmp_path):
    m = module()
    stage, c, s = prepare(tmp_path, m)
    (stage / "state" / "extra-hardlink").hardlink_to(stage / "state" / "nonces.json")
    with pytest.raises(m.Stop, match="STAGE_NONREGULAR_STOP"):
        m.seal(stage, c, s)
    (stage / "state" / "extra-hardlink").unlink()
    s["files"].append({"path": "unknown-file.json", "type":"regular", "size":3})
    with pytest.raises(m.Stop, match="CONTRACT_UNCLASSIFIED_STATE_FILE_STOP"):
        m.seal(stage, c, s)


def test_does_not_read_from_live_app_or_perform_cloud_mutations():
    code = SCRIPT.read_text()
    compile(code, str(SCRIPT), "exec")
    assert "FLOP_R864_NO_UPLOAD_NO_RESTORE_NO_WRITER_EPOCH_PROOF" in code
    for forbidden in ("import oci", "import requests", "import httpx",
                      "subprocess", "systemctl", "sqlite3.connect", "urlopen(",
                      "SecretsClient", "SIGN_SEED", "copyfile(", "shutil.copy",
                      "os.remove(", "unlink(", "os.system("):
        assert forbidden not in code
    assert "O_EXCL" in code and "os.fsync" in code
