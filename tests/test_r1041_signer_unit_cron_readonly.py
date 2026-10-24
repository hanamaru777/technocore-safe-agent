"""R1041 synthetic only, never calls original OCI network or services."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/oracle/r1041_signer_unit_cron_readonly.py"
spec = importlib.util.spec_from_file_location("r1041", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def unit_data(name):
    return ("\n".join((
        "Id=" + name, "LoadState=loaded", "ActiveState=inactive",
        "UnitFileState=enabled", "FragmentPath=/etc/systemd/system/" + name,
        "ExecStart={ path=/usr/bin/bash ; argv[]=/bin/bash /opt/my-private-file SECRET; }",
        "ExecStartPre=", "ExecStartPost=", "User=root", "Type=oneshot",
        "ReadWritePaths=/var/lib/technocore-safe-agent/autopilot",
        "Requires=", "Wants=technocore-safe-agent-resident.service",
    )) + "\n").encode()

def test_only_two_original_unknown_service_queries_and_no_command_leak(monkeypatch):
    queries = []
    def subprocess_mock(argv, **kwargs):
        queries.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=unit_data(argv[-1]))
    monkeypatch.setattr(m.subprocess, "run", subprocess_mock)
    result = [m.show_fixed_unit(n) for n in m.SYSTEMD_UNKNOWNS]
    assert len(queries) == 2
    assert all(call[0][0:2] == ("systemctl", "show") for call in queries)
    assert all(k["command_kind"] == "SHELL_WRAPPER" for k in result)
    assert all(k["declared_write_scope"] == "FLOP_STATE_DECLARED" for k in result)
    assert result[0]["dependency_kind"] == "FLOP_SERVICE_REFERENCE"
    assert "SECRET" not in str(result)
    assert "argv[]" not in str(result)

@pytest.mark.parametrize("bad", (
    "Id=UNEXPECTED", "ExecStart=SECRETS\nPrivileged=oops",
    "LoadState=unexpected", "ActiveState=unknown",
))
def test_unit_show_data_cannot_weaken_identity_or_schema(monkeypatch, bad):
    def fake(argv, **kwargs):
        raw = unit_data(argv[-1]).decode()
        key = bad.split("=", 1)[0]
        raw = "\n".join(
            bad if ln.startswith(key+"=") else ln for ln in raw.splitlines()
        ) + "\n"
        return SimpleNamespace(returncode=0, stdout=raw.encode())
    monkeypatch.setattr(m.subprocess, "run", fake)
    with pytest.raises(m.Stop):
        m.show_fixed_unit(m.SYSTEMD_UNKNOWNS[0])

def test_other_service_cannot_be_queried(monkeypatch):
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: pytest.fail("query leaked"))
    with pytest.raises(m.Stop, match="UNIT_ALLOWLIST_STOP"):
        m.show_fixed_unit("technocore-safe-agent-signer.service")

def test_cron_aggregate_non_follow_and_reason_counts(tmp_path, monkeypatch):
    base=tmp_path/"etc"
    base.mkdir()
    primary=base/"crontab"
    primary.write_text("MAILTO=SECRET_ADDRESS\n", encoding="utf-8")
    cron=base/"cron.d"
    cron.mkdir()
    (cron/"legit").write_text("* * * * * root hidden SECRET\n")
    (cron/"private").write_text("secret")
    (cron/"private-symlink").symlink_to(cron/"private")
    (cron/"large").write_bytes(b"x"*65537)
    (cron/"folder").mkdir()
    monkeypatch.setattr(m, "CRON_PATHS", (primary,cron))
    result = m.cron_metadata_reason()
    assert result["regular_size_bounded"]==3
    assert result["symlink"]==1
    assert result["oversized"]==1
    assert result["nonregular"]==1
    assert "SECRET" not in str(result)

def test_r1041_combined_structure_when_signer_pass_or_guard(monkeypatch,capsys):
    def fake_show(name):
        return dict(identity=name,active="inactive",command_kind="SHELL_WRAPPER",
                    declared_write_scope="NO_EXPLICIT_READWRITE",
                    dependency_kind="NO_FLOP_DEPENDENCY_REFERENCE",
                    fragment_origin="ETC_SYSTEMD",pre_exec_configured=False,
                    post_exec_configured=False,service_type="oneshot")
    monkeypatch.setattr(m, "show_fixed_unit", fake_show)
    monkeypatch.setattr(m, "cron_metadata_reason", lambda: {
        k:0 for k in ("regular_size_bounded","symlink","oversized","nonregular",
                      "multiple_links","raced")})
    monkeypatch.setattr(m.os, "geteuid", lambda:0)
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.sys, "argv", ["-"])
    good = dict(prepared_total=2,quarantined_total=2,recognized_quarantined_e2e=2,
                unreconciled_prepared=0,unreconciled_quarantined=0,
                ack_ids_consistent=True,nonce_binding_consistent=True,
                active_or_ambiguous_outbox=0,autopilot_enabled=False,autopilot_paused=True)
    monkeypatch.setattr(m,"signer_main",lambda:good)
    m.run_combined()
    printed=capsys.readouterr().out
    assert printed==json.dumps(json.loads(printed),sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n"
    response=json.loads(printed)
    assert response["signer"]==dict(validation="PASS",result=good)
    assert response["flags"]["oci_retirement"]=="STRICT_NO_GO"
    assert response["flags"]["all_writers_fenced"]=="NO"
    def stop():
        raise m.Stop("SENSITIVE_PRIVATE_PATH")
    monkeypatch.setattr(m,"signer_main",stop)
    m.run_combined()
    failed=capsys.readouterr().out
    obj=json.loads(failed)
    assert obj["signer"] == {"validation":"GUARD_STOP","result":None}
    assert "SENSITIVE_PRIVATE_PATH" not in failed
    assert len(obj["units"])==2

def test_original_signer_reconciliation_remains_reusable_and_never_claims_post_proof():
    receipts={"schema_version":1,"receipts":{}}
    outbox={"schema_version":1,"enabled":False,"paused":True,"outbox":{},"receipts":{}}
    nonces={}
    did={"did":"did:key:z"+"q"*45}
    report=m.pairing(receipts,outbox,nonces,did)
    assert report["unreconciled_prepared"]==0
    assert report["nonce_binding_consistent"] is False
    assert report["active_or_ambiguous_outbox"]==0

def test_source_contains_no_write_or_signer_submit_or_network_primitive():
    src=SOURCE.read_text(encoding="utf8")
    for prohibited in ("systemctl stop","systemctl start","systemctl restart",
                       "systemctl disable","systemctl mask","sqlite3",
                       "os.environ","urlopen(","requests.","socket.",
                       "subprocess.Popen(","open(leaf, os.O_WRONLY",
                       "unittest.mock.patch.object", "eval(", "exec("):
        assert prohibited not in src
