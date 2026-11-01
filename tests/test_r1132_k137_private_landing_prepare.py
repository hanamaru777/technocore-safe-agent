"""R1132 targeted offline tests for K137 exact-scope private directory init."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/migration/r1132_k137_private_landing_prepare.py"
spec=importlib.util.spec_from_file_location("r1132_private_landing", SOURCE)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def fixture(tmp_path, monkeypatch):
    private = tmp_path / "k137-var-lib"
    private.mkdir(mode=0o700)
    monkeypatch.setattr(M, "BASE", private)
    monkeypatch.setattr(M, "base_fd",
                        lambda: os.open(private, M.OPEN_FLAGS))
    monkeypatch.setattr(M, "identity",
                        lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(M, "check_machine", lambda _: None)
    monkeypatch.setattr(M, "ROOT_UID", os.getuid())
    monkeypatch.setattr(M.os, "fchown", lambda fd, uid, gid: None)
    monkeypatch.setattr(M.os, "geteuid", lambda: 0)
    monkeypatch.setattr(M.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=60 * 1024**3))
    return private


def test_missing_private_parent_is_plan_only_no_mutation(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    result = M.provision("f" * 64, apply=False)
    assert result["result"] == "PLAN_NEW_PRIVATE_PARENT_AND_CHILD"
    assert result["files_written"] == 0
    assert list(base.iterdir()) == []


def test_apply_creates_two_exact_private_dirs_only(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    result = M.provision("f" * 64, apply=True)
    assert result["result"] == "PRIVATE_CIPHERTEXT_LANDING_READY"
    assert result["created_parent"] is True
    assert result["created_child"] is True
    assert result["source_bytes_transferred"] == 0
    assert result["services_touched"] == 0
    assert result["cutover"] == "NO_GO"
    parent = base / M.PARENT_NAME
    child = parent / M.CHILD_NAME
    assert parent.is_dir() and child.is_dir()
    assert parent.stat().st_mode & 0o777 == 0o700
    assert child.stat().st_mode & 0o777 == 0o700
    assert [x.name for x in base.iterdir()] == [M.PARENT_NAME]
    assert [x.name for x in parent.iterdir()] == [M.CHILD_NAME]
    again = M.provision("f" * 64, apply=False)
    assert again["ready"] is True and again["apply"] is False


def test_existing_parent_without_child_preserves_sibling(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    parent = base / M.PARENT_NAME
    parent.mkdir(mode=0o700)
    sentinel = parent / "existing"
    sentinel.write_bytes(b"keep")
    result = M.provision("f" * 64, apply=True)
    assert result["created_parent"] is False
    assert result["created_child"] is True
    assert sentinel.read_bytes() == b"keep"


def test_existing_wrong_mode_never_chmod_or_chown(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    parent = base / M.PARENT_NAME
    parent.mkdir(mode=0o755)
    with pytest.raises(M.Stop, match="EXISTING_PATH_MISMATCH_STOP"):
        M.provision("f" * 64, apply=True)
    assert parent.stat().st_mode & 0o777 == 0o755
    assert not (parent / M.CHILD_NAME).exists()


def test_symlink_parent_not_followed(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    (base / M.PARENT_NAME).symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(M.Stop, match="EXISTING_PATH_MISMATCH_STOP"):
        M.provision("f" * 64, apply=True)
    assert not (tmp_path / M.CHILD_NAME).exists()


def test_no_disk_headroom_refuses_before_any_creation(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(M.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=20 * 1024**3))
    with pytest.raises(M.Stop, match="TRADEBOT_DISK_RESERVE_STOP"):
        M.provision("f" * 64, apply=True)
    assert list(base.iterdir()) == []


def test_machine_id_not_a_hint_and_exact_root_required():
    with pytest.raises(M.Stop, match="MACHINE_PIN_STOP"):
        M.check_machine("not-a-hash")
    actual = Path("/etc/machine-id")
    if actual.exists():
        with pytest.raises(M.Stop, match="MACHINE_PIN_STOP"):
            M.check_machine("f" * 64)
    assert M.PARENT_NAME == "flop-migration-r1066"
    assert M.CHILD_NAME == "disarmed"
    assert M.ROOT_UID == 0 and M.TARGET_UID == 1000
    assert M.MIN_FREE_BYTES >= 20 * 1024**3


def test_unauthorized_user_cannot_apply(tmp_path, monkeypatch):
    base = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(M.os, "geteuid", lambda: 1000)
    with pytest.raises(M.Stop, match="ROOT_REQUIRED"):
        M.provision("f" * 64, apply=True)
    assert list(base.iterdir()) == []
