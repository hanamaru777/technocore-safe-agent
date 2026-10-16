"""R953 metadata-only synthetic tests. Never connect to any cloud endpoint."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/oracle/r953_readonly_source_gap_probe.py"


def mod():
    spec = importlib.util.spec_from_file_location("r953", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_old_r938_omitted_newly_source_proven_radar():
    m = mod()
    assert "airdrop-radar" not in m.PREVIOUS_GROUPS
    assert "airdrop-radar" in m.KNOWN
    root = m.__name__
    assert root == "r953"


def test_radar_state_counted_not_mistaken_for_complete_archive(tmp_path):
    m = mod()
    x = tmp_path / "airdrop-radar" / "challenges" / "contest_2026" / "artifacts"
    x.mkdir(parents=True)
    (tmp_path / "airdrop-radar" / "state.json").write_bytes(b"NOT_READ")
    (x / "rules.txt").write_bytes(b"DO_NOT_ECHO")
    report = m.profile(tmp_path)
    assert report["metadata_walk_complete"]
    assert report["archive_complete"] is False
    assert report["writer_epoch_proven"] is False
    assert report["radar"]["radar_fixed_ledger"]["files"] == 1
    assert report["radar"]["challenge_artifact_payload"]["files"] == 1
    assert report["known_bytes"] == len(b"NOT_READDO_NOT_ECHO")
    assert "rules.txt" not in str(report)
    assert "DO_NOT_ECHO" not in str(report)


def test_unknown_root_one_level_categorized_without_descent(tmp_path):
    m = mod()
    p = tmp_path / "secret-root"
    (p / "nested").mkdir(parents=True)
    (p / "private.txt").write_bytes(b"PRIVATE_DO_NOT_ECHO")
    (p / "nested" / "deeper.json").write_bytes(b"MORE_SECRETS")
    report = m.profile(tmp_path)
    assert not report["metadata_walk_complete"]
    assert len(report["unknown_roots"]) == 1
    assert report["unknown_roots"][0]["root_hash12"] == m.token("secret-root")
    assert report["unknown_roots"][0]["regular_bytes"] == len(b"PRIVATE_DO_NOT_ECHO")
    assert report["unknown_roots"][0]["dirs_not_traversed"] == 1
    assert report["known_bytes"] == 0
    assert "secret-root" not in str(report)
    assert "MORE_SECRETS" not in str(report)


def test_link_external_target_not_dereferenced_or_printed(tmp_path):
    m = mod()
    p = tmp_path / "observer"
    p.mkdir()
    (p / "unsafe").symlink_to("/private/signer/seed.txt")
    report = m.profile(tmp_path)
    assert report["symlinks"] == 1
    assert report["symlink_classes"]["outside"] == 1
    assert not report["metadata_walk_complete"]
    assert "/private/signer" not in str(report)


def test_link_relative_internal_not_claimed_verified(tmp_path):
    m = mod()
    root = tmp_path / "airdrop-radar"
    root.mkdir()
    (root / "alias").symlink_to("events.jsonl")
    report = m.profile(tmp_path)
    assert report["symlink_classes"]["relative_inside_lexical_only"] == 1
    assert not report["metadata_walk_complete"]


def test_depth_limit_fails_closed_without_reading_file(tmp_path, monkeypatch):
    m = mod()
    p = tmp_path / "airdrop-radar"
    for i in range(8):
        p = p / str(i)
        p.mkdir(parents=True)
    monkeypatch.setattr(m, "MAX_DEPTH", 2)
    report = m.profile(tmp_path)
    assert report["reason"] == "DEPTH_LIMIT"
    assert not report["metadata_walk_complete"]


def test_known_fixed_unit_status_identity_not_only_aggregate(monkeypatch):
    m = mod()
    from subprocess import CompletedProcess
    response = "\n\n".join(
        f"Id={name}\nActiveState={'inactive' if idx == 2 else 'active'}"
        for idx, name in enumerate(m.UNITS))
    def fake_run(args, **kwargs):
        assert args[:4] == [
            "systemctl", "show", "--no-pager", "--property=Id,ActiveState"]
        return CompletedProcess(args, 0, response, "")
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    data = m.fixed_units()
    assert data["status"] == "READONLY_FIXED_UNITS"
    assert data["states"][m.UNITS[2]] == "inactive"


def test_unit_missing_or_duplicate_is_never_marked_complete(monkeypatch):
    m = mod()
    from subprocess import CompletedProcess
    monkeypatch.setattr(m.subprocess, "run", lambda args, **kw:
                        CompletedProcess(args, 0, "Id=" + m.UNITS[0] + "\nActiveState=active", ""))
    assert m.fixed_units()["status"] == "INCOMPLETE_STOP"


def test_probe_contains_no_content_read_proc_or_file_mutation():
    text = SCRIPT.read_text(encoding="utf-8")
    compile(text, str(SCRIPT), "exec")
    for forbidden in (
        "read_bytes(", "read_text(", "unlink(", "rmtree(", "/proc/",
        "get_secret_bundle(", "import oci", "import sqlite3",
        "systemctl start", "systemctl stop", "open('wb'", 'open("wb"',
        "open('rb'", 'open("rb"', "eval(", "exec(",
    ):
        assert forbidden not in text
    assert "NO_FILE_CONTENT_NO_SECRET_NO_PROC_NO_WRITE_NO_ARCHIVE_NO_DELETE" in text


def test_source_gate_rejects_unprivileged_user(monkeypatch):
    m = mod()
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    with pytest.raises(m.Stop, match="ORIGINAL_SOURCE_ROOT_REQUIRED"):
        m.source_pin()
