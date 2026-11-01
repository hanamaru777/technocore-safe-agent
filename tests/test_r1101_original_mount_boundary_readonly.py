"""R1101 G4 private RO mount namespace bypass regression, no production IO."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"packaging/migration/r1101_original_mount_boundary_readonly.py"
spec=importlib.util.spec_from_file_location("r1101_mount",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def fake_osi(init_id=77,self_id=77,fail=False):
    def get_stat(path):
        if fail and path==m.PROC_INIT:raise PermissionError("unreadable")
        return SimpleNamespace(st_dev=4,st_ino=init_id if path==m.PROC_INIT else self_id)
    return SimpleNamespace(stat=get_stat,geteuid=lambda:0,ST_RDONLY=1,
                           statvfs=lambda path:SimpleNamespace(f_flag=1))

def test_private_ro_bind_view_denied_even_when_visible_ro():
    with pytest.raises(m.Stop,match="G4_MOUNT_VIEW_STOP"):
        m.mount_namespace_identity(fake_osi(init_id=1,self_id=2))

def test_missing_or_uninspectable_original_namespace_denied():
    with pytest.raises(m.Stop,match="G4_MOUNT_VIEW_STOP"):
        m.mount_namespace_identity(fake_osi(fail=True))

def test_same_namespace_does_not_equate_to_signed_fence():
    assert m.mount_namespace_identity(fake_osi())==(4,77)
    assert "no G4/G5" in m.inspect_original_ro_view.__doc__
    assert m.ROOTS==(Path("/opt/technocore-safe-agent"),
                     Path("/var/lib/technocore-safe-agent"))

def test_no_mutation_operations_or_fake_release():
    s=FILE.read_text(encoding="utf-8")
    for bad in ("subprocess","os.unlink","systemctl","umount","ssh ","mount("):
        assert bad not in s
    assert '"source_archival_authorized":False' in s
