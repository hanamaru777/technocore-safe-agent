"""R1069 owner-authorized K137 preparation checks; 100% synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"packaging/migration/r1069_aws_cloudshell_k137_private_landing.sh"
OTHER=ROOT/"tests/test_r1067_aws_cloudshell.py"
spec=importlib.util.spec_from_file_location("fixture_r1067_k137",OTHER)
other=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=other
spec.loader.exec_module(other)


def mock_env(tmp_path, *, tamper=False):
    env=other.mock_env(tmp_path,tamper=tamper)
    ssh=tmp_path/"commands"/"ssh"
    text=ssh.read_text()
    before="assert a[-1]=='/usr/bin/python3 -I -B -'"
    after="assert a[-1]=='sudo -n /usr/bin/python3 -I -B -'"
    assert before in text
    ssh.write_text(text.replace(before,after).replace(
        "'phase':'R1067_K137_READONLY'",
        "'phase':'R1069_K137_LANDING_PREPARE'").replace(
        "'result':'HOST_AUTHENTICATED'","'result':'PREPARED'"))
    return env


def test_script_parses_and_requires_explicit_owner_use():
    p=subprocess.run(["bash","-n",str(SCRIPT)],capture_output=True)
    assert p.returncode==0,p.stderr.decode(errors="replace")
    text=SCRIPT.read_text()
    assert "sudo -n /usr/bin/python3 -I -B -" in text
    assert 'StrictHostKeyChecking=yes' in text
    assert "fingerprintSHA256" in text
    assert "ssh-keyscan" not in text
    assert "/var/lib/flop-migration-r1066" in text
    assert "cgroup" in text
    assert 'OCI_RETIREMENT=YES' not in text
    assert 'instance stop' not in text


def test_synthetic_aws_ssh_controller_uses_ephemeral_identity(tmp_path):
    env=mock_env(tmp_path)
    p=subprocess.run(["bash",str(SCRIPT),"--allow-one-private-landing-create"],env=env,
                     capture_output=True,timeout=20)
    assert p.returncode==0,(p.stdout,p.stderr)
    out=json.loads(p.stdout)
    assert out["phase"]=="R1069_K137_LANDING_PREPARE"
    assert out["result"]=="PREPARED"
    assert out["oci_retirement"]=="STRICT_NO_GO"
    assert b"PRIVATE KEY" not in p.stdout+p.stderr


def test_invalid_aws_host_key_stops_before_remote_preparation(tmp_path):
    env=mock_env(tmp_path,tamper=True)
    p=subprocess.run(["bash",str(SCRIPT),"--allow-one-private-landing-create"],env=env,
                     capture_output=True,timeout=20)
    assert p.returncode==42
    assert json.loads(p.stdout)["code"]=="HOSTKEY_FINGERPRINT_STOP"


def guest_code():
    text=SCRIPT.read_text()
    begin="import json,os,pathlib,pwd,stat,subprocess,sys\n# This guest"
    end="\nPY\nthen\n    die SSH_OR_REMOTE_PREPARE_STOP"
    assert text.count(begin)==1 and text.count(end)==1
    return text.split(begin,1)[1].split(end,1)[0]


def test_remote_guest_owns_exact_single_directory_only():
    source=guest_code()
    assert source.count("os.mkdir(D,0o700)")==1
    assert source.count("os.chown(D,who.pw_uid,who.pw_gid,follow_symlinks=False)")==1
    assert 'check(not os.path.lexists(D)' not in source
    assert "LANDING_PREEXISTS_UNTRUSTED_STOP" in source
    assert "ALREADY_PREPARED" in source
    assert "free>=20*1024**3" in source
    assert "stage_git_head" in source
    for forbidden in ("os.unlink(", "os.rmdir(", "shutil.rmtree",
                      "os.rename(", "systemctl", "os.system(",
                      "subprocess.Popen", "os.chmod(", "os.remove(",
                      "os.symlink(", "os.link("):
        assert forbidden not in source
    assert "tradebot_paths" in source
    assert '"cutover":"NO_GO"' in source
    assert '"oci_retirement":"STRICT_NO_GO"' in source


def test_no_writes_to_tradebot_or_shadow_routes():
    source=guest_code()
    assert 'PROTECTED=("/opt/flop-shadow","/opt/tradebot-k137","/opt/tradebot-k137-private")' in source
    assert "entry(part)" in source
    assert "s.st_uid!=who.pw_uid" in source
    assert "os.path.lexists(D)" in source
    assert "os.mkdir(D,0o700)" in source
    for path in ("/opt/tradebot-k137","/opt/tradebot-k137-private","/opt/flop-shadow"):
        for line in source.splitlines():
            if any(verb in line for verb in ("os.mkdir(","os.chown(","os.chmod(")):
                assert path not in line



def test_no_owner_optin_stops_before_any_aws_or_ssh(tmp_path):
    env=mock_env(tmp_path)
    result=subprocess.run(["bash",str(SCRIPT)],env=env,
                          capture_output=True,timeout=20)
    assert result.returncode==42
    assert json.loads(result.stdout)["code"]=="OWNER_OPT_IN_REQUIRED"
    assert b"PRIVATE KEY" not in result.stdout+result.stderr
