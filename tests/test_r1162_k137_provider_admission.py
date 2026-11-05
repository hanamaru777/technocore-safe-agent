"""Synthetic provider/guest tests only. No AWS CLI, SSH connection, or unit start."""
import ast
import base64
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, SSHCertificateBuilder, SSHCertificateType)

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "packaging/migration/r1162_k137_provider_admission.py"
GUEST = ROOT / "packaging/migration/r1162_k137_bounded_guest.py"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("r1162_test", ENTRY)
g = load("r1162_guest_test", GUEST)
old = load("r1162_frozen_public", ROOT / "packaging/migration/r1159_m2_bootstrap.py")
POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX-only credential custody and process groups")


def cert(key, ca, now, *, principals=None, start=None, end=None, host=False, critical=False):
    builder = (SSHCertificateBuilder().public_key(key.public_key()).serial(1).key_id(b"synthetic")
               .type(SSHCertificateType.HOST if host else SSHCertificateType.USER)
               .valid_principals(principals or [b"ubuntu"])
               .valid_after(now - 30 if start is None else start)
               .valid_before(now + 600 if end is None else end))
    if critical:
        builder = builder.add_critical_option(b"force-command", b"untrusted")
    return builder.sign(ca).public_bytes().decode()


@pytest.fixture
def provider():
    now = int(time.time())
    key, ca = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    wire = base64.b64decode(old.K137_KEY.split()[1])
    a = dict(instanceName=m.INSTANCE, protocol="ssh", ipAddress=m.HOST, username="ubuntu",
             certKey=cert(key, ca, now), expiresAt=now + 600,
             hostKeys=[dict(algorithm="ssh-ed25519", publicKey=old.K137_KEY.split()[1],
                            fingerprintSHA256="SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip("="),
                            witnessedAt=now - 1000)])
    a["privateKey"] = key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode()
    return SimpleNamespace(now=now, key=key, ca=ca, public=public,
                           response=dict(accessDetails=a), data=a)


def fake_custody(monkeypatch, provider, reject_parser=False):
    written, commands = {}, []
    monkeypatch.setattr(m, "put", lambda folder, name, raw: written.setdefault(name, bytes(raw)))
    def parser(argv, *args, **kwargs):
        commands.append(argv)
        if "-y" in argv:
            return bytearray(provider.public)
        if reject_parser:
            raise m.Stop("PROCESS_REJECTED_NO_RETRY")
        return bytearray(b"synthetic certificate parsed")
    monkeypatch.setattr(m, "bounded", parser)
    return written, commands


def test_frozen_sources_verified_without_running_r1071(monkeypatch):
    pins = m.sources()
    assert g.MACHINE_SHA256 == old.K137_MACHINE and g.TRADEBOT == old.TRADEBOT
    assert pins["base"] == m.BASE and pins["reference"] == m.REFERENCE
    assert pins["frozen"]["packaging/migration/r1071_aws_cloudshell_bounded_scope_readonly.sh"] == "9d8dcaef816c2d5662d0a2d4038e0f65643b57d9"
    source = m.source
    monkeypatch.setattr(m, "source", lambda p: source(p) + b"\n" if p.endswith("r1066_preflight_readonly.py") else source(p))
    with pytest.raises(m.Stop, match="SOURCE_PIN"): m.sources()


def test_valid_provider_packet_is_not_emitted_or_written_as_json(provider, monkeypatch, tmp_path, capsys):
    written, commands = fake_custody(monkeypatch, provider)
    result = m.credentials(m.canonical(provider.response), tmp_path, "/fixed/keygen", old.K137_KEY, provider.now)
    assert result["operation"] == "Lightsail.GetInstanceAccessDetails"
    assert set(written) == {"identity", "identity-cert.pub", "known_hosts"}
    assert commands[0][1:4] == ["-y", "-P", ""]
    assert commands[1][1] == "-L"
    assert "privateKey" not in result and "certKey" not in result
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["iso8601", "naive", "future_witness"])
def test_aws_cli_v2_timestamp_formats(provider, monkeypatch, tmp_path, fault):
    fake_custody(monkeypatch,provider)
    a=provider.data
    a["expiresAt"]=datetime.datetime.fromtimestamp(provider.now+600,datetime.timezone.utc).isoformat()
    value=provider.now+10 if fault=="future_witness" else provider.now-1000
    a["hostKeys"][0]["witnessedAt"]=datetime.datetime.fromtimestamp(value,datetime.timezone.utc).isoformat()
    if fault=="naive": a["hostKeys"][0]["witnessedAt"]=a["hostKeys"][0]["witnessedAt"][:-6]
    if fault=="iso8601":
        assert m.credentials(m.canonical(provider.response),tmp_path,"/keygen",old.K137_KEY,provider.now)["witnessed_at"]==provider.now-1000
    else:
        with pytest.raises(m.Stop,match="PROVENANCE"): m.credentials(m.canonical(provider.response),tmp_path,"/keygen",old.K137_KEY,provider.now)


@pytest.mark.parametrize("fault", ["instance", "ip", "user", "protocol", "fingerprint", "host_key", "duplicate_host",
    "no_ed25519", "missing_private", "expired", "naive_expiry", "wrong_principal", "host_cert", "critical", "long_cert", "future_cert"])
def test_provider_and_certificate_failures_never_reach_ssh(provider, monkeypatch, tmp_path, fault):
    written, calls = fake_custody(monkeypatch, provider)
    a = copy.deepcopy(provider.data)
    if fault == "instance": a["instanceName"] = "other"
    if fault == "ip": a["ipAddress"] = "52.198.96.244"
    if fault == "user": a["username"] = "ubuntu -o ProxyCommand=bad"
    if fault == "protocol": a["protocol"] = "rdp"
    if fault == "fingerprint": a["hostKeys"][0]["fingerprintSHA256"] = "SHA256:forged"
    if fault == "host_key": a["hostKeys"][0]["publicKey"] = provider.public.decode()
    if fault == "duplicate_host": a["hostKeys"] *= 2
    if fault == "no_ed25519": a["hostKeys"][0]["algorithm"] = "ssh-rsa"
    if fault == "missing_private": a["privateKey"] = ""
    if fault == "expired": a["expiresAt"] = provider.now - 1
    if fault == "naive_expiry": a["expiresAt"] = "2026-11-05T00:00:00"
    if fault == "wrong_principal": a["certKey"] = cert(provider.key, provider.ca, provider.now, principals=[b"root"])
    if fault == "host_cert": a["certKey"] = cert(provider.key, provider.ca, provider.now, host=True)
    if fault == "critical": a["certKey"] = cert(provider.key, provider.ca, provider.now, critical=True)
    if fault == "long_cert": a["certKey"] = cert(provider.key, provider.ca, provider.now, end=provider.now+86400)
    if fault == "future_cert": a["certKey"] = cert(provider.key, provider.ca, provider.now, start=provider.now+1)
    with pytest.raises((m.Stop, ValueError)):
        m.credentials(m.canonical(dict(accessDetails=a)), tmp_path, "/fixed/keygen", old.K137_KEY, provider.now)
    assert not calls  # Every above failure precedes the local key parser too.


def test_certificate_private_key_mismatch_and_parser_failure(provider, monkeypatch, tmp_path):
    _, calls = fake_custody(monkeypatch, provider, reject_parser=True)
    with pytest.raises(m.Stop, match="REJECTED"):
        m.credentials(m.canonical(provider.response), tmp_path, "/keygen", old.K137_KEY, provider.now)
    different = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    monkeypatch.setattr(m, "bounded", lambda *a, **k: bytearray(different))
    with pytest.raises(m.Stop, match="KEY_MISMATCH"):
        m.credentials(m.canonical(provider.response), tmp_path, "/keygen", old.K137_KEY, provider.now)


@pytest.mark.parametrize("algorithm", ["rsa", "ecdsa"])
def test_provider_certificate_subject_formats(provider, monkeypatch, tmp_path, algorithm):
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048) if algorithm=="rsa" else ec.generate_private_key(ec.SECP256R1())
    provider.key = key
    provider.public = key.public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH)
    provider.data["privateKey"] = key.private_bytes(Encoding.PEM,PrivateFormat.TraditionalOpenSSL,NoEncryption()).decode()
    provider.data["certKey"] = cert(key,provider.ca,provider.now)
    fake_custody(monkeypatch,provider)
    assert m.credentials(m.canonical(provider.response),tmp_path,"/keygen",old.K137_KEY,provider.now)["expires_at"]>provider.now


def test_installed_openssh_certificate_signature_validation(provider,tmp_path):
    keygen = r"C:\Windows\System32\OpenSSH\ssh-keygen.exe" if os.name=="nt" else "/usr/bin/ssh-keygen"
    path=tmp_path/"synthetic-public-cert.pub"
    path.write_text(provider.data["certKey"]+"\n",encoding="ascii")
    def parsed():
        return subprocess.run([keygen,"-L","-f",str(path)],stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode
    assert parsed()==0
    algorithm,wire=m.public_line(provider.data["certKey"])
    path.write_text(algorithm+" "+base64.b64encode(wire[:-1]+bytes([wire[-1]^1])).decode()+"\n",encoding="ascii")
    assert parsed()!=0


def test_fixed_provider_and_ssh_arguments():
    args = m.provider_args("/root-owned/aws")
    assert args[args.index("--instance-name")+1] == "tradebot-k137"
    assert args[args.index("--region")+1] == "ap-northeast-1"
    assert args[args.index("--endpoint-url")+1] == m.ENDPOINT
    assert "--no-verify-ssl" not in args and "--no-sign-request" not in args
    ssh = m.ssh_args("/usr/bin/ssh", Path("/tmp/synthetic"))
    assert ssh[-2] == "ubuntu@52.198.96.243" and ssh[-1] == m.REMOTE
    assert "StrictHostKeyChecking=yes" in ssh and "HostKeyAlgorithms=ssh-ed25519" in ssh
    accepted = next(x for x in ssh if x.startswith("PubkeyAcceptedAlgorithms="))
    assert all("-cert-v01@openssh.com" in x for x in accepted.split("=", 1)[1].split(","))
    assert m.REMOTE.startswith("sudo -n /usr/bin/systemd-run --system ")
    assert m.REMOTE.count("sudo") == 1 and "--scope" not in m.REMOTE and "--replace" not in m.REMOTE
    for prop in ("User=ubuntu", "Group=ubuntu", "MemoryMax=256M", "TasksMax=64", "CPUQuota=50%",
                 "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "NoNewPrivileges=yes",
                 "RuntimeMaxSec=45s", "KillMode=control-group", "Restart=no"):
        assert m.REMOTE.index("--property="+prop) < m.REMOTE.index("/usr/bin/python3")
    assert m.REMOTE.endswith("/usr/bin/python3 -I -B -")


@pytest.fixture
def guest(monkeypatch):
    now = int(time.time())
    root = "/sys/fs/cgroup/system.slice/" + g.UNIT
    data = {"/proc/self/cgroup": ("0::/system.slice/" + g.UNIT + "\n").encode(),
            root + "/cgroup.procs": str(os.getpid()).encode(),
            root + "/memory.max": b"268435456", root + "/pids.max": b"64",
            root + "/cpu.max": b"50000 100000", root + "/memory.swap.max": b"0",
            "/etc/machine-id": b"a"*32, "/proc/sys/kernel/random/boot_id": b"12345678-1234-1234-1234-123456789abc\n"}
    properties = dict(User="ubuntu", Group="ubuntu", NoNewPrivileges="yes", ProtectSystem="strict",
                      ProtectHome="yes", PrivateTmp="yes", ControlGroup="/system.slice/"+g.UNIT,
                      KillMode="control-group", Restart="no")
    target = dict(LoadState="loaded", ActiveState="active", MemoryHigh="1048576000",
                  MemoryMax="1258291200", ControlGroup="/system.slice/"+g.TRADEBOT)
    data["/sys/fs/cgroup"+target["ControlGroup"]+"/memory.max"] = b"1258291200"
    def command(argv, **kwargs):
        assert argv[:2] == ["/usr/bin/systemctl", "show"] and kwargs["env"] == {"PATH":"/usr/bin:/bin", "LANG":"C"}
        values = target if argv[-1] == g.TRADEBOT else properties
        return SimpleNamespace(returncode=0, stdout=("\n".join(k+"="+v for k,v in values.items())+"\n").encode(), stderr=b"")
    R = SimpleNamespace(LANDING="/synthetic-landing", K137_STAGE="/synthetic-stage",
        K137_STAGE_SHA="3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e", PROTECTED=("/synthetic-tradebot",),
        read_small=lambda p, *a: data[p], git_head=lambda p:"3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e",
        directory=lambda p:SimpleNamespace(st_uid=1000 if p=="/synthetic-landing" else 0, st_mode=stat.S_IFDIR|0o700),
        subprocess=SimpleNamespace(run=command, DEVNULL=subprocess.DEVNULL))
    monkeypatch.setattr(g, "R", R, raising=False)
    text = (ROOT/"packaging/migration/r1159_m2_bootstrap.py").read_text()
    node = next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=="tradebot_evidence")
    exec(ast.get_source_segment(text,node), g.__dict__)
    monkeypatch.setattr(g, "MACHINE_SHA256", m.sha(b"a"*32))
    monkeypatch.setattr(g, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(g.os, "geteuid", lambda:1000, raising=False)
    monkeypatch.setattr(g.os, "getegid", lambda:1000, raising=False)
    monkeypatch.setattr(g.os, "access", lambda p, mode: p==R.LANDING and mode==os.R_OK|os.X_OK)
    monkeypatch.setattr(g.os, "statvfs", lambda p:SimpleNamespace(f_bavail=21*1024**3, f_frsize=1), raising=False)
    request = dict(challenge=m.sha(os.urandom(32)), expires_at=now+180, source_blobs={"guest":m.blob(GUEST.read_bytes().replace(b"\r\n",b"\n"))}, provider_sha256=m.sha(b"synthetic provider"))
    return SimpleNamespace(R=R, data=data, root=root, properties=properties, target=target, request=request, now=now)


def test_guest_and_strict_report_admit_payload_only(guest):
    v = g.probe(guest.request)
    assert m.validate_report(m.canonical(v), guest.request, guest.now, m.sha(b"a"*32), guest.R.K137_STAGE_SHA) == v
    assert v["ssh_login_prebounded"] is False and v["m2"] == "NO_GO"


@pytest.mark.parametrize("fault", ["memory", "pids", "cpu", "swap", "scope", "extra_pids", "membership",
    "uid", "gid", "machine", "boot_change", "scope_change", "sandbox", "tradebot", "tradebot_change", "space", "head", "landing_write"])
def test_guest_fails_closed_on_missing_bounds_or_changed_identity(guest, monkeypatch, fault):
    d, R = guest.data, guest.R
    if fault=="memory": d[guest.root+"/memory.max"]=b"max"
    if fault=="pids": d[guest.root+"/pids.max"]=b"65"
    if fault=="cpu": d[guest.root+"/cpu.max"]=b"50001 100000"
    if fault=="swap": d[guest.root+"/memory.swap.max"]=b"max"
    if fault=="scope": d["/proc/self/cgroup"]=b"0::/session.scope\n"
    if fault=="extra_pids": d[guest.root+"/cgroup.procs"]=b"\n".join(str(x).encode() for x in range(65))+b"\n"+str(os.getpid()).encode()
    if fault=="membership": d[guest.root+"/cgroup.procs"]=b"99999999"
    if fault=="uid": monkeypatch.setattr(g.os,"geteuid",lambda:1001)
    if fault=="gid": monkeypatch.setattr(g.os,"getegid",lambda:1001)
    if fault=="machine": d["/etc/machine-id"]=b"b"*32
    if fault=="sandbox": guest.properties["NoNewPrivileges"]="no"
    if fault=="tradebot": guest.target["MemoryHigh"]="1"
    if fault=="space": monkeypatch.setattr(g.os,"statvfs",lambda p:SimpleNamespace(f_bavail=21*1024**3-1,f_frsize=1))
    if fault=="head": R.git_head=lambda p:"f"*40
    if fault=="landing_write": monkeypatch.setattr(g.os,"access",lambda p, mode:p==R.LANDING)
    if fault in ("boot_change","scope_change","tradebot_change"):
        original=R.git_head
        def changed(path):
            if fault=="boot_change": d["/proc/sys/kernel/random/boot_id"]=b"changed"
            if fault=="scope_change": d["/proc/self/cgroup"]=b"0::/other.service\n"
            if fault=="tradebot_change":
                # Mutation after the first TradeBot snapshot.
                original_call=R.subprocess.run
                calls=[]
                def run(argv,**kw):
                    if argv[-1]==g.TRADEBOT:
                        calls.append(1)
                        if len(calls)>1: guest.target["ControlGroup"]="/changed"
                    return original_call(argv,**kw)
                R.subprocess.run=run
            return original(path)
        R.git_head=changed
    with pytest.raises((ValueError,KeyError)): g.probe(guest.request)


def test_generated_payload_has_only_fixed_readers(guest):
    manifest=m.sources()
    payload=m.guest_source(guest.request)
    compile(payload,"<synthetic>","exec")
    assert len(payload)<=32768
    executable=ast.unparse(ast.parse(payload)).encode()
    for forbidden in (b"sudo ",b"systemd-run ",b"os.mkdir(",b"os.unlink(",b"os.rename(",b"httpx",b"vault_seed"):
        assert forbidden not in executable
    assert "packaging/migration/r1071_aws_cloudshell_bounded_scope_readonly.sh" in manifest["frozen"]


def test_replayed_or_leaked_guest_output_is_never_forwarded(guest):
    v=g.probe(guest.request)
    for wrong in (dict(v,challenge="0"*64), dict(v,ssh_login_prebounded=True), dict(v,privateKey="SYNTHETIC_PRIVATE_CANARY"),
                  dict(v,expires_at=guest.now-1)):
        with pytest.raises(m.Stop):
            m.validate_report(m.canonical(wrong),guest.request,guest.now,m.sha(b"a"*32),guest.R.K137_STAGE_SHA)
    with pytest.raises(m.Stop): m.strict(b'{"value":1,"value":2}')


@pytest.mark.parametrize("scenario",["pass","aws_error","ssh_ambiguous","cleanup_error","interrupt"])
def test_one_shot_order_redaction_and_cleanup(provider, guest, tmp_path, monkeypatch, capsys, scenario):
    events=[]
    saved={}
    state=tmp_path/"state"
    for key in ("PATH","AWS_MAX_ATTEMPTS","AWS_RETRY_MODE","AWS_PAGER","AWS_CLI_AUTO_PROMPT",
                "AWS_CONFIG_FILE","AWS_SHARED_CREDENTIALS_FILE","AWS_EC2_METADATA_DISABLED"):
        monkeypatch.setenv(key,"synthetic-previous-value")
    monkeypatch.setattr(m,"new_attempt",lambda *a:events.append("marker"))
    monkeypatch.setattr(m.tempfile,"mkdtemp",lambda **kw: str(tmp_path))
    monkeypatch.setattr(m.stat,"S_IMODE",lambda value:0o700)
    monkeypatch.setattr(m,"credentials",lambda raw,*a:dict(operation="Lightsail.GetInstanceAccessDetails",expires_at=provider.now+600,witnessed_at=provider.now-1000,host_key_sha256=m.sha(b"host")))
    original_guest=m.guest_source
    def payload(request):
        saved["request"]=request
        return original_guest(request)
    monkeypatch.setattr(m,"guest_source",payload)
    def invoke(argv,data=b"",**kw):
        is_aws="get-instance-access-details" in argv
        events.append("aws" if is_aws else "ssh")
        if is_aws:
            if scenario=="aws_error": raise m.Stop("PROCESS_REJECTED_NO_RETRY")
            return bytearray(b"SYNTHETIC_PRIVATE_CANARY")
        assert kw.get("provider") is None
        if scenario=="ssh_ambiguous": raise m.Stop("PROCESS_AMBIGUOUS_NO_RETRY")
        if scenario=="interrupt": raise KeyboardInterrupt()
        request=saved["request"]
        v=g.probe(guest.request)
        v.update(request, machine_sha256=old.K137_MACHINE)
        return bytearray(m.canonical(v))
    monkeypatch.setattr(m,"bounded",invoke)
    def clean(folder):
        events.append("cleanup")
        if scenario=="cleanup_error": raise OSError("SYNTHETIC_PRIVATE_CANARY")
    monkeypatch.setattr(m,"cleanup",clean)
    manifest=m.sources()
    if scenario=="pass":
        result=m.owner_run(manifest,"/aws","/ssh","/keygen",state)
        assert result["body"]["verdict"]=="K137_PAYLOAD_BOUNDED"
        assert result["body"]["ssh_login_prebounded"] is False
        assert result["sha256"]==m.sha(m.canonical(result["body"]))
        text=m.canonical(result)
        for forbidden in (b"SYNTHETIC_PRIVATE_CANARY",m.INSTANCE.encode(),m.HOST.encode(),b"ubuntu",b"privateKey",str(tmp_path).encode()):
            assert forbidden not in text
    else:
        with pytest.raises(m.Stop): m.owner_run(manifest,"/aws","/ssh","/keygen",state)
    assert events[0]=="marker" and events[-1]=="cleanup"
    assert events.count("aws")==1 and events.count("ssh")<=1
    assert capsys.readouterr()==("","")


def test_default_cli_never_contacts_provider_or_reads_custody():
    r=subprocess.run([sys.executable,"-I","-B",str(ENTRY)],capture_output=True,timeout=10)
    assert r.returncode==42 and json.loads(r.stdout)["code"]=="EXPLICIT_OWNER_EXECUTION_REQUIRED" and not r.stderr


@POSIX
def test_temporary_files_are_0600_and_duplicate_marker_is_terminal(tmp_path,monkeypatch):
    # pytest's temporary ancestor stands in for the owner's private HOME.
    original=Path.lstat
    def local_metadata(p,*a,**kw):
        if p==Path("/tmp"):
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        return original(p,*a,**kw)
    monkeypatch.setattr(Path,"lstat",local_metadata)
    folder=tmp_path/"attempt"
    m.new_attempt(folder,"a"*64,int(time.time()))
    assert stat.S_IMODE((folder/"ATTEMPTED.json").stat().st_mode)==0o600
    with pytest.raises(m.Stop,match="CONSUMED"): m.new_attempt(folder,"b"*64,int(time.time()))
    target=tmp_path/"custody";target.mkdir(mode=0o700)
    m.put(target,"identity",b"fresh synthetic dummy")
    assert stat.S_IMODE((target/"identity").stat().st_mode)==0o600
    with pytest.raises(FileExistsError):m.put(target,"identity",b"must not replace")
    m.cleanup(target)
    assert not target.exists()


@POSIX
def test_real_openssh_parses_only_fresh_dummy_cert_and_rejects_signature_tampering(provider,tmp_path):
    parsed=m.credentials(m.canonical(provider.response),tmp_path,"/usr/bin/ssh-keygen",old.K137_KEY,provider.now)
    assert parsed["expires_at"]>provider.now+75
    for p in tmp_path.iterdir(): p.unlink()
    a=copy.deepcopy(provider.data)
    alg,wire=m.public_line(a["certKey"])
    wire=wire[:-1]+bytes([wire[-1]^1])
    a["certKey"]=alg+" "+base64.b64encode(wire).decode()
    with pytest.raises(m.Stop,match="REJECTED"):
        m.credentials(m.canonical(dict(accessDetails=a)),tmp_path,"/usr/bin/ssh-keygen",old.K137_KEY,provider.now)


@pytest.mark.parametrize("scenario",["overflow","timeout","error"])
def test_local_carrier_bounds_and_never_prints_diagnostics(scenario,capsys):
    code={"overflow":"import sys;sys.stdout.write('SYNTHETIC_PRIVATE_CANARY'*1000)",
          "timeout":"import time;time.sleep(10)",
          "error":"import sys;sys.stderr.write('SYNTHETIC_PRIVATE_CANARY');sys.exit(1)"}[scenario]
    with pytest.raises(m.Stop):
        m.bounded([sys.executable,"-I","-B","-c",code],limit=64,timeout=1)
    assert capsys.readouterr()==("","")
