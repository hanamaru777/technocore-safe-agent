"""R1139 original file metadata read-only guard, synthetic paths only."""
import importlib.util
import os
from pathlib import Path
import sys

import pytest

SRC=Path(__file__).resolve().parents[1]/"packaging/oracle/r1139_source_preseed_metadata_readonly.py"
spec=importlib.util.spec_from_file_location("r1139_source_preflight_tests",SRC)
M=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=M
spec.loader.exec_module(M)

def fixture(tmp_path, monkeypatch):
    state=tmp_path/"flop-state"
    state.mkdir()
    (state/"signer").mkdir()
    (state/"verified-did.json").write_bytes(b"TEST-DID-ONLY")
    (state/"nonces.json").write_bytes(b"TEST-COUNT-ONLY")
    (state/"signer/oracle-signer-receipts.json").write_bytes(b"TEST-RECEIPTS-ONLY")
    monkeypatch.setattr(M,"STATE",state)
    return state

def test_exact_three_names_and_sizes(tmp_path,monkeypatch):
    state=fixture(tmp_path,monkeypatch)
    assert len(M.FILES)==3
    results={key:M.file_metadata(key,segments,cap)
             for key,segments,cap in M.FILES}
    assert set(results)=={"verified-did","nonces","signer-receipts"}
    assert all(x["within_limit"] and x["single_link"] for x in results.values())
    assert all(0<x["size_bytes"]<=limit for key,segments,limit in M.FILES
               for x in [results[key]])

def test_missing_and_oversize_fail_metadata_ready(tmp_path,monkeypatch):
    state=fixture(tmp_path,monkeypatch)
    (state/"nonces.json").unlink()
    assert M.file_metadata("nonces",("nonces.json",),1048576)["exists"] is False
    (state/"nonces.json").write_bytes(b"X"*(1048576+1))
    x=M.file_metadata("nonces",("nonces.json",),1048576)
    assert x["exists"] and not x["within_limit"] and x["size_bytes"]==0

def test_symlinks_and_hardlinks_stop(tmp_path,monkeypatch):
    state=fixture(tmp_path,monkeypatch)
    f=state/"nonces.json"
    f.unlink()
    f.symlink_to(state/"verified-did.json")
    with pytest.raises(M.Stop,match="SOURCE_FILE_LINK_STOP"):
        M.file_metadata("nonces",("nonces.json",),1048576)
    f.unlink()
    f.write_bytes(b"X")
    os.link(f,state/"extra-hardlink")
    x=M.file_metadata("nonces",("nonces.json",),1048576)
    assert x["single_link"] is False and x["within_limit"] is False

def test_nested_symlink_parent_stop(tmp_path,monkeypatch):
    state=fixture(tmp_path,monkeypatch)
    (state/"signer/oracle-signer-receipts.json").unlink()
    (state/"signer").rmdir()
    (state/"signer").symlink_to(tmp_path,target_is_directory=True)
    with pytest.raises(M.Stop,match="SOURCE_FILE_LINK_STOP"):
        M.file_metadata("signer-receipts",
                        ("signer","oracle-signer-receipts.json"),8388608)

def test_unrelated_mount_alias_permitted_protected_child_stops(tmp_path,monkeypatch):
    app=tmp_path/"app"; app.mkdir()
    state=fixture(tmp_path,monkeypatch)
    monkeypatch.setattr(M,"APP",app)
    root="1 0 8:1 / / rw - ext4 /dev/root rw\n"
    unrelated="2 1 0:1 / /proc rw - proc proc rw\n"
    data=M.parse_mounts((root+unrelated+unrelated).encode())
    M.mount_guard(data)
    child="3 1 0:2 / "+str(state)+"/signer rw - tmpfs tmpfs rw\n"
    with pytest.raises(M.Stop,match="SOURCE_MOUNT_STOP"):
        M.mount_guard(M.parse_mounts((root+child).encode()))

def test_original_constraints_and_no_archive_or_key_copy():
    source=SRC.read_text()
    assert M.HEAD=="ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    assert "source_archive" in source and '"NO_GO"' in source
    assert "vault_seed" not in source and "SIGN_SEED" not in source
    assert "httpx" not in source and "requests." not in source
    assert "unlink(" not in source and "mkdir(" not in source
    assert "read_bytes()" not in source[source.index("def file_metadata"):source.index("def inventory")]
