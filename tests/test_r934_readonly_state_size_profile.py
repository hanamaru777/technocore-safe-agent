"""R934 synthetic offline metadata-only regression tests."""
import importlib.util
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / (
    "packaging/oracle/r934_readonly_state_size_profile.py"
)

def mod():
    spec = importlib.util.spec_from_file_location("r934", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_large_file_categories_never_echo_names_or_content(tmp_path):
    m = mod()
    observer = tmp_path / "observer"
    observer.mkdir()
    (observer / "observer-state.json.backup-20261001").write_bytes(b"X" * 100)
    (observer / "lobby-capture.sqlite3").write_bytes(b"Y" * 7)
    autopilot = tmp_path / "autopilot"
    autopilot.mkdir()
    (autopilot / "autopilot-outbox.json").write_bytes(b"Z" * 200)
    report = m.profile(tmp_path)
    assert report["stats"]["bytes"] == 307
    assert report["classes"]["observer_compaction_backup"]["bytes"] == 100
    assert report["classes"]["autopilot_current_outbox"]["bytes"] == 200
    assert not report["stats"]["incomplete"]
    assert "backup-20261001" not in str(report)
    assert "X" * 20 not in str(report)

def test_symlink_and_unknown_root_are_not_followed(tmp_path):
    m = mod()
    (tmp_path / "observer").mkdir()
    (tmp_path / "observer" / "bad").symlink_to("/etc/shadow")
    (tmp_path / "secret-other").mkdir()
    (tmp_path / "secret-other" / "data").write_bytes(b"PRIVATE" * 10)
    report = m.profile(tmp_path)
    assert report["stats"]["incomplete"]
    assert report["stats"]["symlinks"] == 1
    assert report["stats"]["unknown_root_dirs"] == 1
    assert report["stats"]["bytes"] == 0
    assert "secret-other" not in str(report)

def test_largest_is_bounded_and_hashed(tmp_path):
    m = mod()
    (tmp_path / "autopilot").mkdir()
    for i in range(40):
        (tmp_path / "autopilot" / f"{i}.json").write_bytes(b"12345")
    report = m.profile(tmp_path)
    assert report["stats"]["files"] == 40
    assert report["stats"]["bytes"] == 200
    assert len(report["largest"]) == m.MAX_TOP
    assert all(len(i["id_hash12"]) == 12 for i in report["largest"])

def test_deep_paths_stop_safely(tmp_path, monkeypatch):
    m = mod()
    monkeypatch.setattr(m, "MAX_DEPTH", 3)
    path = tmp_path / "autopilot"
    for i in range(5):
        path = path / str(i)
        path.mkdir(parents=True)
    report = m.profile(tmp_path)
    assert report["stats"]["incomplete"]
    assert report["stats"]["reason"] == "DEPTH_LIMIT"

def test_hardlink_skipped(tmp_path):
    m = mod()
    directory = tmp_path / "signer"
    directory.mkdir()
    (directory / "a").write_bytes(b"important")
    os.link(directory / "a", directory / "b")
    report = m.profile(tmp_path)
    assert report["stats"]["hardlinks"] == 2
    assert report["stats"]["bytes"] == 0
    assert report["stats"]["incomplete"]

def test_read_only_no_service_write_or_private_access():
    s = SCRIPT.read_text(encoding="utf-8")
    compile(s, str(SCRIPT), "exec")
    for forbidden in (
        "read_bytes(", "read_text(", "unlink(", "rmtree(",
        "systemctl stop", "systemctl start", "import oci", "import sqlite3",
        "import requests", "get_secret_bundle(", "open('wb'", 'open("wb"',
    ):
        assert forbidden not in s
    assert "NO_SOURCE_MUTATION_NO_BACKUP_NO_DELETION" in s

def test_source_guard_rejects_unprivileged_user(monkeypatch):
    m = mod()
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    with pytest.raises(m.Stop, match="SOURCE_ROOT_REQUIRED"):
        m.original_source_gate()


def test_r938_atomic_observer_candidates_are_narrowly_named():
    m = mod()
    assert m.classify("observer/.observer-state.json.abcd.tmp") == (
        "observer", "observer_atomic_tmp_candidate")
    assert m.classify("observer/.resident-state.json.abcd.tmp") == (
        "observer", "observer_atomic_tmp_candidate")
    assert m.classify("observer/.compact-estimate.abcd.tmp") == (
        "observer", "observer_compaction_tmp_candidate")
    assert m.classify("observer/other.tmp") == (
        "observer", "observer_other_tmp_unclassified")
    assert m.classify("observer/history/subfolder/.observer-state.json.abcd.tmp") == (
        "observer", "observer_other_tmp_unclassified")


def test_r938_disk_block_allocations_and_age_buckets(tmp_path):
    import time
    m = mod()
    ob = tmp_path / "observer"
    ob.mkdir()
    name = ob / ".observer-state.json.unique.tmp"
    name.write_bytes(b"test" * 3)
    os.utime(name, (time.time() - 700_000, time.time() - 700_000))
    result = m.profile(tmp_path)
    key = "observer_atomic_tmp_candidate"
    assert result["classes"][key]["bytes"] == 12
    assert result["classes"][key]["allocated_bytes"] >= 0
    assert result["stats"]["allocated_bytes"] >= 0
    age = key + ":older_than_week"
    assert result["age_bands"][age]["files"] == 1
    assert result["largest"][0]["age_band"] == "older_than_week"
    assert result["largest"][0]["kind"] == "tmp"


def test_r938_age_buckets_exact_semantics():
    m = mod()
    assert m.age_bucket(-1) == "future_or_clock_skew"
    assert m.age_bucket(0) == "lt_1hour"
    assert m.age_bucket(3600) == "hour_to_day"
    assert m.age_bucket(86400) == "day_to_week"
    assert m.age_bucket(7 * 86400) == "older_than_week"


def test_r938_unclassified_huge_autopilot_file_is_not_false_archive():
    m = mod()
    assert m.classify("autopilot/unknown.largeblob") == (
        "autopilot", "autopilot_other_unclassified")
    assert m.classify("autopilot/autopilot-audit.jsonl") == (
        "autopilot", "autopilot_audit")
    assert m.classify("autopilot/autopilot-outbox.json") == (
        "autopilot", "autopilot_current_outbox")


def test_r938_no_data_reads_deletes_or_chmod():
    text = SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "read_bytes(", "read_text(", "unlink(", "rmtree(", "chmod(",
        "os.remove(", "shutil.copy", "open('wb'", 'open("wb"',
        "os.kill(", "systemctl stop", "systemctl start",
    ):
        assert forbidden not in text
