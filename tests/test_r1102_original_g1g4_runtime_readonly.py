"""R1102 original G1/G4 source-pinned runtime survey, no host operation."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"packaging/oracle/r1102_original_g1g4_runtime_readonly.py"
sp=importlib.util.spec_from_file_location("r1102",P)
m=importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)

def test_fixed_original_names_and_no_false_attestation():
    assert len(m.EXPECTED)==27
    assert len(m.SPECIAL)==4
    assert m.HEAD=="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    assert m.APP==Path("/opt/technocore-safe-agent")
    assert m.STATE==Path("/var/lib/technocore-safe-agent")
    assert m.MAX_FD==65536
    assert m.MAX_SECONDS==48
    assert m.MATCH.search("technocore-safe-agent-tclk-accept@nonce.service")
    assert "NO_GO" in P.read_text()
    assert "NOT_PROVEN" in P.read_text()

def test_namespace_visible_does_not_prove_global_fence(monkeypatch):
    original=m.os.stat
    def stat_fake(path,*args,**kwargs):
        if path=="/proc/self/ns/mnt":return SimpleNamespace(st_dev=1,st_ino=2)
        if path=="/proc/1/ns/mnt":return SimpleNamespace(st_dev=1,st_ino=1)
        return original(path,*args,**kwargs)
    monkeypatch.setattr(m.os,"stat",stat_fake)
    assert m.namespaces()["pid1_mount_namespace_matches"] is False
    assert m.namespaces()["all_original_mount_aliases_fenced"] is False

def test_no_deletion_or_service_commands():
    s=P.read_text(encoding="utf-8")
    for bad in ("os.unlink(", "shutil.rmtree(", "systemctl stop","systemctl disable",
       "systemctl mask","systemctl restart", "mount -o", "chmod(", "chown(", "get_secret_bundle"):
        assert bad not in s
    assert "list-units" in s
    assert "source_archive" in s
    assert '"NOT_AUTHORIZED"' in s
