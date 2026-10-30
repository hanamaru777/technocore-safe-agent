"""R1112 original G1 detail witness: all synthetic, NO actual original probe."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"packaging/oracle/r1112_original_identity_readonly.py"
WINDOWS=ROOT/"packaging/windows/r1112_original_identity_readonly.ps1"
spec=importlib.util.spec_from_file_location("r1112_original",SOURCE)
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)


def fake_host(monkeypatch,tmp_path):
    app=tmp_path/"app";state=tmp_path/"state"
    app.mkdir();state.mkdir()
    monkeypatch.setattr(M,"APP",app)
    monkeypatch.setattr(M,"STATE",state)
    monkeypatch.setattr(M.os,"geteuid",lambda:0)
    recognized=sorted(M.EXPECTED)[:19]
    extra=[f"technocore-safe-agent-extra{i}.service" for i in range(11)]
    present=sorted(recognized+extra)
    loaded=sorted(present)[:22]
    calls=[]
    def command(argv,deadline):
        calls.append(tuple(argv))
        assert argv[0] in ("/usr/bin/git","/usr/bin/systemctl")
        assert "-c" not in argv or argv[0]=="/usr/bin/git"
        assert "stop" not in argv and "kill" not in argv and "restart" not in argv
        if argv[0]=="/usr/bin/git":
            return (M.HEAD+"\n").encode()
        if "list-unit-files" in argv:
            return "\n".join(f"{n} enabled enabled" for n in present).encode()
        if "list-units" in argv:
            return "\n".join(f"{n} loaded active running" for n in loaded).encode()
        if "show" in argv:
            name=argv[-1]
            p={k:"" for k in M.PROPS}
            p.update({"Id":name,"Names":name,"LoadState":"loaded" if name in present else "not-found",
                      "FragmentPath":"/etc/systemd/system/"+name if name in present else "",
                      "ActiveState":"inactive"})
            return "\n".join(f"{k}={v}" for k,v in p.items()).encode()
        raise AssertionError("UNKNOWN_CALL")
    monkeypatch.setattr(M,"read_command",command)
    return calls


def test_private_detail_count_and_effective_hash_no_names(monkeypatch,tmp_path):
    calls=fake_host(monkeypatch,tmp_path)
    value=M.witness()
    assert value["expected"]==27
    assert value["recognized"]==19
    assert value["missing"]==8
    assert value["extras"]==11
    assert value["loaded"]==22
    assert len(value["unit_identity_sha256"])==64
    assert len(value["effective_config_sha256"])==64
    assert value["all_launchers_proven"] is False
    assert value["all_writers_fenced"] is False
    assert value["source_archive"]=="NO_GO"
    assert value["oci_retirement"]=="STRICT_NO_GO"
    assert "extra1" not in json.dumps(value)
    assert "ExecStart" not in json.dumps(value)
    assert sum("show" in x for x in calls)>=2*(27+11)


def test_source_head_drift_fails_closed(monkeypatch,tmp_path):
    fake_host(monkeypatch,tmp_path)
    monkeypatch.setattr(M,"read_command",lambda *a,**k:b"not-the-original-head\n")
    with pytest.raises(M.Stop):M.witness()


def test_outside_original_or_untrusted_username_cannot_run(monkeypatch,tmp_path):
    fake_host(monkeypatch,tmp_path)
    monkeypatch.setattr(M.os,"geteuid",lambda:1000)
    with pytest.raises(M.Stop):M.witness()


def test_invalid_systemctl_or_race_fails(monkeypatch,tmp_path):
    fake_host(monkeypatch,tmp_path)
    original=M.read_command
    n=[0]
    def race(argv,deadline):
        if "list-unit-files" in argv:
            n[0]+=1
            if n[0]==2:return b"[]"
        return original(argv,deadline)
    monkeypatch.setattr(M,"read_command",race)
    with pytest.raises(M.Stop):M.witness()


def test_r1112_has_no_original_writer_or_external_post_side_effect():
    source=SOURCE.read_text("utf-8")
    forbidden=["os.system(","Popen(","shell=True","requests.post","urllib.request.urlopen",
        "os.remove(",".unlink(","shutil.rmtree","subprocess.check_call","systemctl stop",
        "systemctl disable","seed","private_key","--delete","--write"]
    assert all(x not in source for x in forbidden)
    assert "HEAD=" in source and "g5_finality" in source
    assert "STRICT_NO_GO" in source
    assert "R1102" not in source or "previously proven R1102" in source
    assert '"--output=json"' not in source
    assert '"--all","show"' in source


def test_windows_wrapper_reuses_existing_strict_r987_readonly_transport():
    ps=WINDOWS.read_text("utf-8")
    assert "param()" in ps
    assert "StrictHostKeyChecking=yes" in ps
    assert "IdentitiesOnly=yes" in ps
    assert "PasswordAuthentication=no" in ps
    assert "HostKeyAlgorithms=ecdsa-sha2-nistp256" in ps
    assert "Read-R1027Backup" in ps and "Unprotect-R1027" in ps
    assert "Remove-R1027Custody" in ps
    assert "r1112_original_identity_readonly.py" in ps
    assert "Read-R1112Report" in ps
    assert "source_archive='NO_GO'" in ps
    assert "oci_retirement='STRICT_NO_GO'" in ps
    assert "PRIVATE_G1_IDENTITY_WITNESS_ONLY" in ps
    assert "r1102_original_g1g4_runtime_readonly.ps1" not in ps


def test_windows_wrapper_pins_exact_guest_git_blob():
    ps=WINDOWS.read_text("utf-8")
    raw=SOURCE.read_bytes()
    actual=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    assert re.search(r"blob='"+re.escape(actual)+r"'",ps)
    assert "commit='0d67aae27a6ddec936db226e4a69afcb854410e1'" in ps
    assert "r1062_writer_attribution_one_shot_readonly.ps1" in ps
    assert "$script:SourcesCommit='b46d766bb165477a16d5a77ee204fc7bb5982725'" in ps


def test_unrelated_linux_device_units_do_not_invalidate_flop_census(monkeypatch,tmp_path):
    fake_host(monkeypatch,tmp_path)
    original=M.read_command
    def with_unrelated(argv,deadline):
        raw=original(argv,deadline)
        if "list-unit-files" in argv:
            return raw+b"\nsys-devices-virtual-block-loop0.device loaded\nsys-kernel-debug.mount loaded"
        return raw
    monkeypatch.setattr(M,"read_command",with_unrelated)
    result=M.witness()
    assert result["expected"]==27
    assert result["recognized"]==19
    assert result["extras"]==11


def test_unrecognized_source_scoped_unit_extension_fails_closed(monkeypatch,tmp_path):
    fake_host(monkeypatch,tmp_path)
    original=M.read_command
    def with_unknown(argv,deadline):
        raw=original(argv,deadline)
        if "list-unit-files" in argv:
            return raw+b"\ntechnocore-safe-agent-unknown.device loaded"
        return raw
    monkeypatch.setattr(M,"read_command",with_unknown)
    with pytest.raises(M.Stop):
        M.witness()
