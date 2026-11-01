"""R1126 scoped mount witness offline tests; never connect to OCI."""
import importlib.util
import io
import json
from pathlib import Path
from contextlib import redirect_stdout

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging" / "oracle" / "r1126_original_root_mount_readonly.py"
WINDOWS = ROOT / "packaging" / "windows" / "r1126_original_root_mount_readonly.ps1"

spec = importlib.util.spec_from_file_location("r1126_guest", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

ROOT_LINE = "31 22 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
CHILD_LINE = "32 31 8:1 / /var/lib/technocore-safe-agent rw - ext4 /dev/sda1 rw\n"


def test_plain_single_oci_root_device_bound():
    mounts = mod.parse_mounts(ROOT_LINE.encode("ascii"))
    assert mod.mount_scope(mounts, (mod.APP, mod.STATE)) is True


def test_nested_mount_cannot_falsely_pass():
    mounts = mod.parse_mounts((ROOT_LINE + CHILD_LINE).encode("ascii"))
    with pytest.raises(mod.Stop, match="NONROOT_MOUNT_STOP|NESTED_MOUNT_STOP"):
        mod.mount_scope(mounts, (mod.APP, mod.STATE))


def test_nfs_root_fails_closed():
    m = mod.parse_mounts(
        b"31 22 8:1 / / rw - nfs4 10.0.0.1:/mnt rw\n"
    )
    with pytest.raises(mod.Stop, match="ROOT_FILESYSTEM_STOP"):
        mod.mount_scope(m, (mod.APP, mod.STATE))


def test_bad_mountinfo_and_duplicate_root_stop():
    with pytest.raises(mod.Stop, match="MOUNT_FORMAT_STOP"):
        mod.parse_mounts(b"not-mountinfo\n")
    stacked = mod.parse_mounts((ROOT_LINE + ROOT_LINE).encode("ascii"))
    with pytest.raises(mod.Stop, match="ROOT_MOUNT_ALIAS_STOP"):
        mod.mount_scope(stacked, (mod.APP, mod.STATE))


def test_unrelated_duplicate_mount_allowed_but_nested_still_fails():
    # Real Linux may expose duplicate mountpoints in unrelated subtrees.
    unrelated = "33 31 0:12 / /proc rw - proc proc rw\n"
    mounts = mod.parse_mounts(
        (ROOT_LINE + unrelated + unrelated).encode("ascii")
    )
    assert mod.mount_scope(mounts, (mod.APP, mod.STATE)) is True

    relevant = (
        "34 31 0:13 / /var/lib/technocore-safe-agent rw - tmpfs tmpfs rw\n"
    )
    mounts2 = mod.parse_mounts(
        (ROOT_LINE + unrelated + unrelated + relevant).encode("ascii")
    )
    with pytest.raises(mod.Stop, match="NONROOT_MOUNT_STOP|NESTED_MOUNT_STOP"):
        mod.mount_scope(mounts2, (mod.APP, mod.STATE))


def test_mountinfo_escape_and_secret_free_result(monkeypatch):
    mounts = mod.parse_mounts(
        ROOT_LINE.encode("ascii") + b"33 22 8:2 / /media/some\\040path rw - ext4 /dev/sdb1 rw\n"
    )
    assert any(p == "/media/some path" for p, _, _ in mounts)
    monkeypatch.setattr(mod, "run", lambda: (_ for _ in ()).throw(mod.Stop("ROOT_PATH_STOP")))
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert mod.main() == 42
    assert json.loads(buf.getvalue()) == {
        "phase": "R1126", "result": "STOP", "reason": "ROOT_PATH_STOP",
        "source_archive": "NO_GO", "cutover": "NO_GO",
        "oci_retirement": "STRICT_NO_GO",
    }


def test_windows_carrier_is_distinct_from_consumed_r1112():
    code = WINDOWS.read_text(encoding="utf-8")
    assert "r1126_original_root_mount_readonly.py" in code
    assert "PRIVATE_ROOT_MOUNT_WITNESS_ONLY" in code
    assert "efcd3fc6d58211167be76d91875296b24fb6b451" in code
    assert "R1112" not in code and "r1112" not in code
    assert "StrictHostKeyChecking=yes" in code
    assert "R987 V2 local recovery code" in code
    assert "Remove-R1027Custody" in code
