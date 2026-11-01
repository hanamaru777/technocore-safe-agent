"""R1071 ephemeral bounded K137 scope, synthetic only: no host, no AWS."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parents[1]
SOURCE=HERE/"packaging/migration/r1071_aws_cloudshell_bounded_scope_readonly.sh"
R1067=HERE/"tests/test_r1067_aws_cloudshell.py"
spec=importlib.util.spec_from_file_location("r1071_fixture_r1067",R1067)
fixture=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=fixture
spec.loader.exec_module(fixture)


def env_with_mock(tmp_path, *, bad_fingerprint=False):
    env=fixture.mock_env(tmp_path,tamper=bad_fingerprint)
    ssh=tmp_path/"commands"/"ssh"
    source=ssh.read_text()
    previous="assert a[-1]=='/usr/bin/python3 -I -B -'"
    expected="assert a[-1].startswith('sudo -n /usr/bin/systemd-run --system --quiet --pipe --collect ')" + "\n" + (
        "assert '--property=User=ubuntu' in a[-1]\n"
        "assert '--property=MemoryMax=256M' in a[-1]\n"
        "assert '--property=TasksMax=64' in a[-1]\n"
        "assert '--property=CPUQuota=50%' in a[-1]\n"
        "assert '--property=ProtectSystem=strict' in a[-1]\n"
        "assert a[-1].endswith(' /usr/bin/python3 -I -B -')")
    assert previous in source
    source=source.replace(previous,expected)
    source=source.replace("'phase':'R1067_K137_READONLY'",
        "'phase':'R1071_K137_BOUNDED_SCOPE'")
    source=source.replace("'result':'HOST_AUTHENTICATED'",
        "'result':'BOUNDED_SCOPE_OBSERVED'")
    ssh.write_text(source)
    return env


def test_bash_parses_and_has_strict_ssh_and_cgroup():
    p=subprocess.run(["bash","-n",str(SOURCE)],capture_output=True)
    assert p.returncode==0,p.stderr.decode(errors="replace")
    source=SOURCE.read_text()
    assert "StrictHostKeyChecking=yes" in source
    assert "fingerprintSHA256" in source
    assert "ssh-keyscan" not in source
    assert "sudo -n /usr/bin/systemd-run" in source
    for required in ("--pipe","--collect","--property=User=ubuntu",
                     "--property=Group=ubuntu","--property=MemoryMax=256M",
                     "--property=TasksMax=64","--property=CPUQuota=50%",
                     "--property=ProtectSystem=strict",
                     "--property=NoNewPrivileges=yes","--property=PrivateTmp=yes"):
        assert required in source
    for forbidden in ("rm -rf","systemctl stop","systemctl restart",
                      "delete-instance","chmod 777","mkdir /var/lib",
                      "User=root", "AuthorizedKeysFile", "ssh-keygen -A"):
        assert forbidden not in source


def test_mock_success_authenticates_aws_pinned_host_before_bounded_ssh(tmp_path):
    env=env_with_mock(tmp_path)
    p=subprocess.run(["bash",str(SOURCE)],env=env,capture_output=True,timeout=20)
    assert p.returncode==0,(p.stdout,p.stderr)
    row=json.loads(p.stdout)
    assert row["result"]=="BOUNDED_SCOPE_OBSERVED"
    assert row["oci_retirement"]=="STRICT_NO_GO"
    assert b"EC PRIVATE KEY" not in p.stdout+p.stderr


def test_mismatched_host_fingerprint_fails_before_systemd(tmp_path):
    env=env_with_mock(tmp_path,bad_fingerprint=True)
    p=subprocess.run(["bash",str(SOURCE)],env=env,capture_output=True,timeout=20)
    assert p.returncode==42
    assert json.loads(p.stdout)["code"]=="HOSTKEY_FINGERPRINT_STOP"


def test_remote_guest_only_reads_scope_and_landing_metadata():
    src=SOURCE.read_text()
    anchor="import hashlib,json,os,pathlib,re,stat,sys\n"
    assert src.count(anchor)==1
    guest=src.split(anchor,1)[1].split("\nPY\nthen\n",1)[0]
    assert '"/proc/self/cgroup"' in guest
    assert '"memory.max"' in guest and '"pids.max"' in guest and '"cpu.max"' in guest
    assert "268435456" in guest
    assert 'stat.S_IMODE(a.st_mode)==0o700' in guest
    assert "cgroup_sha256" in guest
    for forbidden in ("subprocess", "os.mkdir(", "os.chown(", "os.remove(",
                      "os.rename(", "os.system(", "os.environ", "exec(", "open("):
        assert forbidden not in guest
