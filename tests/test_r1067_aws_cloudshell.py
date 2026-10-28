"""R1067: actual shell syntax and synthetic AWS temporary-key flow, NO cloud calls."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import struct

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] /
          "packaging/migration/r1067_aws_cloudshell_k137_readonly.sh")

def test_bash_source_parses():
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")

def test_cannot_delete_tradebot_original_or_wallet_from_source():
    text = SCRIPT.read_text()
    assert "lightsail get-instance-access-details" in text
    assert "StrictHostKeyChecking=yes" in text
    assert "CertificateFile=" in text
    assert "ssh-ed25519" in text
    assert "oci_retirement" in text
    assert "rm -rf" not in text
    assert "ssh-keyscan" not in text
    for forbidden in ["systemctl stop","systemctl restart","oracle_signer",
                      "delete-instance","delete-disk","rm -r /opt",
                      "mkdir /var/lib","git checkout","chmod 777"]:
        assert forbidden not in text

def mock_env(tmp_path, *, tamper=False, algorithm="ssh-ed25519"):
    cmd = tmp_path / "commands"
    cmd.mkdir()
    def wire(s):
        return struct.pack(">I",len(s)) + s
    if algorithm == "ssh-ed25519":
        keydata=wire(b"ssh-ed25519") + wire(b"A" * 32)
    elif algorithm == "ecdsa-sha2-nistp256":
        keydata=(wire(b"ecdsa-sha2-nistp256") + wire(b"nistp256")
                 + wire(b"\x04" + b"B" * 64))
    else:
        keydata=wire(b"ssh-rsa") + wire(b"unsupported")
    fingerprint = base64.b64encode(hashlib.sha256(keydata).digest()).decode().rstrip("=")
    host = {
        "algorithm":algorithm,
        "publicKey":base64.b64encode(keydata).decode(),
        "fingerprintSHA256":"SHA256:"+("BAD" if tamper else fingerprint),
    }
    # A real ephemeral valid OpenSSH-read RSA/EC PEM key avoids a fake-header
    # fixture passing the test while the owner credential would fail.
    seed=tmp_path/"synthetic-ssh-key"
    subprocess.run(["ssh-keygen","-q","-t","ecdsa","-b","256","-m","PEM",
                    "-N","","-f",str(seed)],check=True,
                   stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
    private=seed.read_text(encoding="ascii")
    assert private.startswith("-----BEGIN EC PRIVATE KEY-----")
    mock = {"accessDetails":{
        "instanceName":"tradebot-k137","protocol":"ssh",
        "ipAddress":"8.8.8.8","username":"ubuntu",
        "expiresAt":"2099-01-01T00:00:00Z",
        "privateKey":private,
        "certKey":"ssh-rsa-cert-v01@openssh.com SYNTHETIC_PUBLIC_CERT",
        "hostKeys":[host]}}
    aws = cmd / "aws"
    aws.write_text("#!"+sys.executable+"\n"
                   "import os,sys\n"
                   "sys.stdout.write(os.environ['SYNTHETIC_AWS_DETAILS'])\n")
    aws.chmod(0o700)
    ssh = cmd / "ssh"
    ssh.write_text("#!"+sys.executable+"\n"
                   "import os,sys,json,pathlib\n"
                   "a=sys.argv\n"
                   "assert '-o' in a\n"
                   "cert=[x.split('=',1)[1] for x in a if x.startswith('CertificateFile=')]\n"
                   "assert len(cert)==1 and pathlib.Path(cert[0]).exists()\n"
                   "assert pathlib.Path(a[a.index('-i')+1]).exists()\n"
                   "assert 'StrictHostKeyChecking=yes' in a\n"
                   "assert 'HostKeyAlgorithms='+os.environ['R1067_EXPECT_ALGO'] in a\n"
                   "assert a[-2]=='ubuntu@8.8.8.8'\n"
                   "assert a[-1]=='/usr/bin/python3 -I -B -'\n"
                   "assert len(sys.stdin.buffer.read())>100\n"
                   "print(json.dumps({'phase':'R1067_K137_READONLY','result':'HOST_AUTHENTICATED',"
                   "'cutover':'NO_GO','oci_retirement':'STRICT_NO_GO'}))\n")
    ssh.chmod(0o700)
    env = os.environ.copy()
    env["PATH"] = str(cmd) + os.pathsep + env["PATH"]
    env["SYNTHETIC_AWS_DETAILS"] = json.dumps(mock)
    env["R1067_EXPECT_ALGO"] = algorithm
    return env

def test_synthetic_ephemeral_aws_key_trust_and_ssh_command(tmp_path):
    env = mock_env(tmp_path)
    run = subprocess.run(["bash", str(SCRIPT)], env=env,
                         capture_output=True, timeout=20)
    assert run.returncode == 0, (run.stdout, run.stderr)
    response = json.loads(run.stdout)
    assert response == {
        "phase":"R1067_K137_READONLY","result":"HOST_AUTHENTICATED",
        "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
    assert b"SYNTHETIC_CANARY" not in run.stdout + run.stderr
    assert b"BEGIN EC PRIVATE KEY" not in run.stdout + run.stderr

def test_wrong_aws_host_key_fingerprint_rejected_before_ssh(tmp_path):
    env = mock_env(tmp_path, tamper=True)
    run = subprocess.run(["bash", str(SCRIPT)], env=env,
                         capture_output=True, timeout=20)
    assert run.returncode == 42
    response = json.loads(run.stdout)
    assert response["code"] == "HOSTKEY_FINGERPRINT_STOP"
    assert response["oci_retirement"] == "STRICT_NO_GO"
    assert b"SYNTHETIC_CANARY" not in run.stdout + run.stderr

def test_aws_authenticated_nistp256_ecdsa_host_key_supported(tmp_path):
    env = mock_env(tmp_path, algorithm="ecdsa-sha2-nistp256")
    run = subprocess.run(["bash", str(SCRIPT)], env=env,
                         capture_output=True, timeout=20)
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert json.loads(run.stdout)["result"] == "HOST_AUTHENTICATED"
    assert b"SYNTHETIC_CANARY" not in run.stdout + run.stderr


def test_absent_strong_host_key_is_redacted_specific_stop(tmp_path):
    env = mock_env(tmp_path, algorithm="ssh-rsa")
    run = subprocess.run(["bash", str(SCRIPT)], env=env,
                         capture_output=True, timeout=20)
    assert run.returncode == 42
    assert json.loads(run.stdout)["code"] == "HOSTKEY_SUPPORTED_ALGORITHM_MISSING"
    assert b"SYNTHETIC_CANARY" not in run.stdout + run.stderr


def test_bad_ecdsa_host_fingerprint_cannot_fallback_to_ssh_rsa(tmp_path):
    env = mock_env(tmp_path, tamper=True, algorithm="ecdsa-sha2-nistp256")
    run = subprocess.run(["bash", str(SCRIPT)], env=env,
                         capture_output=True, timeout=20)
    assert run.returncode == 42
    assert json.loads(run.stdout)["code"] == "HOSTKEY_FINGERPRINT_STOP"
    assert b"SYNTHETIC_CANARY" not in run.stdout + run.stderr

def test_missing_temporary_credential_is_explicit_and_no_ssh(tmp_path):
    env=mock_env(tmp_path)
    details=json.loads(env["SYNTHETIC_AWS_DETAILS"])
    details["accessDetails"]["privateKey"]=""
    env["SYNTHETIC_AWS_DETAILS"]=json.dumps(details)
    done=subprocess.run(["bash",str(SCRIPT)],env=env,capture_output=True,timeout=20)
    assert done.returncode==42
    assert json.loads(done.stdout)["code"]=="TEMP_PRIVATE_KEY_MISSING_STOP"
    assert b"PRIVATE KEY" not in done.stdout+done.stderr


def test_malformed_temporary_credential_is_rejected_by_real_openssh(tmp_path):
    env=mock_env(tmp_path)
    details=json.loads(env["SYNTHETIC_AWS_DETAILS"])
    details["accessDetails"]["privateKey"]="-----BEGIN EC PRIVATE KEY-----\\nBAD\\n-----END EC PRIVATE KEY-----"
    env["SYNTHETIC_AWS_DETAILS"]=json.dumps(details)
    done=subprocess.run(["bash",str(SCRIPT)],env=env,capture_output=True,timeout=20)
    assert done.returncode==42
    assert json.loads(done.stdout)["code"]=="TEMP_PRIVATE_KEY_PARSE_STOP"
    assert b"BAD" not in done.stdout+done.stderr


def test_leading_whitespace_valid_pem_is_accepted_after_private_trim(tmp_path):
    env=mock_env(tmp_path)
    details=json.loads(env["SYNTHETIC_AWS_DETAILS"])
    details["accessDetails"]["privateKey"]="  \\n"+details["accessDetails"]["privateKey"]
    env["SYNTHETIC_AWS_DETAILS"]=json.dumps(details)
    done=subprocess.run(["bash",str(SCRIPT)],env=env,capture_output=True,timeout=20)
    assert done.returncode==0, (done.stdout,done.stderr)
    assert json.loads(done.stdout)["result"]=="HOST_AUTHENTICATED"
