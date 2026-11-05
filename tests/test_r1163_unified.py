"""R1163 synthetic public contracts; never production accounts or hosts."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT/"packaging/migration"


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, PKG/leaf)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


U = load("r1163_test_unified", "r1163_unified.py")
K = U.K
P = load("r1163_test_pipeline", "r1163_pipeline.py")
NOW = 2000000000
h = lambda x: K.sha(x.encode())


def test_fixed_sources_interfaces_and_no_legacy_changes():
    pins = K.source_map()
    assert len(pins["files"]) == 122
    assert len([r for r in pins["files"].values() if r["origin"] == K.T1150]) == 8
    assert K.ORIGINAL_AUTHORITIES == {}
    for name in pins["files"]:
        assert not name.endswith("r1163_contract.py")
    p = subprocess.run(["git", "diff", K.BASE, "--", *[n for n in pins["files"] if n.startswith("packaging/migration/")]],
                       cwd=ROOT, capture_output=True, timeout=20)
    assert p.returncode == 0 and p.stdout == b""


def test_budget_does_not_waive_limits_using_low_current_rss():
    value = K.resource_plan()
    assert value["flop_total_mib"] == 864
    assert value["minimum_required_mib"] == 2320 and value["overcommit_mib"] == 414
    assert value["state"] == "NO_GO" and value["tradebot_max_mib"] == 1200


def anchor():
    signer, guest = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    public = guest.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    body = dict(version=1, kind="INDEPENDENT_ORIGINAL_OCI_GUEST_SSHD", authority="synthetic-independent",
                challenge=h("fresh-challenge"), observed_at=NOW, expires_at=NOW+120,
                host="140.238.55.171", instance="ORIGINAL_ORACLE", machine_sha256=h("original-host"),
                boot_sha256=h("fresh-boot"), scope_sha256=h("fresh-scope"), guest_host_key=public,
                key_sha256=K.sha(base64.b64decode(public.split()[1])), evidence_sha256=h("independent-archive"))
    packet = dict(body=body, signature=signer.sign(K.DOMAIN+K.canonical(body)).hex())
    roots = {body["authority"]: signer.public_key().public_bytes_raw().hex()}
    return packet, roots, signer


def test_original_import_default_rejects_self_signed_user_root_and_override():
    packet, roots, _ = anchor()
    with pytest.raises(K.Stop, match="INDEPENDENT_AUTHORITY_REQUIRED"):
        K.original_anchor(packet, h("fresh-challenge"), now=NOW)
    with pytest.raises(K.Stop, match="TRUST_OVERRIDE"):
        K.original_anchor(packet, h("fresh-challenge"), now=NOW, authorities=roots)


@pytest.mark.parametrize("kind", ["known_hosts", "ssh-keyscan", "authorized_keys", "serial_proxy", "AWS_PROVIDER_KEY", "USER_DIGEST"])
def test_original_anchor_rejects_untrusted_provenance(kind):
    packet, roots, _ = anchor(); packet["body"]["kind"] = kind
    with pytest.raises(K.Stop, match="PROVENANCE"):
        K.original_anchor(packet, h("fresh-challenge"), now=NOW, authorities=roots, trial=True)


@pytest.mark.parametrize("fault", [None, "signature", "host", "boot", "challenge", "expiry", "key", "extra"])
def test_challenge_bound_anchor_synthetic_only(monkeypatch, fault):
    packet, roots, signer = anchor()
    original = K.legacy("r1161_readonly_admission.py")
    monkeypatch.setattr(original, "ORIGINAL_ED25519_SHA256", packet["body"]["key_sha256"])
    if fault == "signature": packet["signature"] = "00"*64
    if fault == "host": packet["body"]["host"] = "52.198.96.243"
    if fault == "boot": packet["body"]["boot_sha256"] = h("other-boot")  # unsigned tamper
    if fault == "challenge": packet["body"]["challenge"] = h("old-challenge")
    if fault == "expiry": packet["body"]["expires_at"] = NOW-1
    if fault == "key": packet["body"]["key_sha256"] = h("other-key")
    if fault == "extra": packet["body"]["trusted"] = True
    if fault:
        with pytest.raises((K.Stop, ValueError)):
            K.original_anchor(packet, h("fresh-challenge"), now=NOW, authorities=roots, trial=True)
    else:
        value = K.original_anchor(packet, h("fresh-challenge"), now=NOW, authorities=roots, trial=True)
        assert value["scope"] == "OFFLINE_TRIAL" and value["migration"] == "NO_GO"


def receipt():
    m = K.legacy("r1162_k137_provider_admission.py"); old = K.legacy("r1159_m2_bootstrap.py")
    manifest = m.sources()
    pins = {**manifest["frozen"], **manifest["guest"], "packaging/migration/r1162_k137_provider_admission.py":
            m.blob(m.source("packaging/migration/r1162_k137_provider_admission.py"))}
    b = dict(task="R1162", verdict="K137_PAYLOAD_BOUNDED", ssh_login_prebounded=False,
             challenge=h("k137-challenge"), observed_at=NOW, expires_at=NOW+120, source_base=m.BASE,
             reference_commit=m.REFERENCE, source_blobs=pins, provider_operation="Lightsail.GetInstanceAccessDetails",
             provider_sha256=h("provider"), provider_witnessed_at=NOW-10, credential_expires_at=NOW+600,
             host_key_sha256=old.host_key(old.K137_KEY, "ssh-ed25519"), head="3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e",
             guest_sha256=h("guest"), report_sha256=h("report"), boot_sha256=h("boot"), scope_sha256=h("scope"),
             tradebot_sha256=h("protected-tradebot"), caps=dict(scope_sha256=h("scope"), memory_max=256*K.MIB,
             pids_max=64, cpu_quota=50000, cpu_period=100000, swap_max=0), m2="NO_GO", cutover="NO_GO", oci_retirement="STRICT_NO_GO")
    return dict(body=b, sha256=K.sha(K.canonical(b)))


@pytest.mark.parametrize("fault", [None, "hash", "host", "boot", "scope", "challenge", "source", "memory", "cpu", "swap", "login", "provider", "expiry", "extra"])
def test_receipt_never_self_authenticates_even_with_recomputed_hash(fault):
    packet = receipt(); b = packet["body"]
    if fault == "host": b["host_key_sha256"] = h("Oracle-key-misused")
    if fault == "boot": b["boot_sha256"] = h("other-boot")
    if fault == "scope": b["caps"]["scope_sha256"] = h("other-cgroup")
    if fault == "challenge": b["challenge"] = h("stale")
    if fault == "source": b["source_blobs"] = {}
    if fault == "memory": b["caps"]["memory_max"] += 1
    if fault == "cpu": b["caps"]["cpu_quota"] += 1
    if fault == "swap": b["caps"]["swap_max"] = 1
    if fault == "login": b["ssh_login_prebounded"] = True
    if fault == "provider": b["provider_operation"] = "OCI.GetInstance"
    if fault == "expiry": b["expires_at"] = NOW-1
    if fault == "extra": b["production_pass"] = True
    packet["sha256"] = K.sha(K.canonical(b)) if fault != "hash" else "0"*64
    args = dict(now=NOW, expected_boot=h("boot"), expected_scope=h("scope"))
    if fault:
        with pytest.raises(Exception): K.k137_receipt(packet, h("k137-challenge"), **args)
    else:
        result = K.k137_receipt(packet, h("k137-challenge"), **args)
        assert result["consistency"] == "PASS" and result["state"] == "UNKNOWN" and result["migration"] == "NO_GO"


def test_future_one_operation_delegates_exact_runner_once_without_releasing_migration(monkeypatch):
    m = U.K.legacy("r1162_k137_provider_admission.py"); packet = receipt(); calls = []
    def fake():
        calls.append(sys.argv[:]); print(K.canonical(packet).decode()); return 0
    monkeypatch.setattr(m, "main", fake)
    monkeypatch.setattr(U.time, "time", lambda: NOW)
    result = U.admission_operation()
    assert len(calls) == 1 and calls[0][1:] == ["--execute"]
    assert result["state"] == "UNKNOWN" and result["next_action"] == "INDEPENDENT_REVIEW_ONLY"


def test_failed_operation_redacts_output_and_does_not_retry(monkeypatch):
    m = U.K.legacy("r1162_k137_provider_admission.py"); calls = []
    def fake():
        calls.append(1); print('{"untrusted":"SYNTHETIC_PRIVATE_DIAGNOSTIC"}'); return 42
    monkeypatch.setattr(m, "main", fake)
    result = U.admission_operation()
    assert calls == [1] and "SYNTHETIC_PRIVATE" not in str(result) and result["state"] == "NO_GO"


def test_offline_entrypoint_never_calls_provider_and_returns_one_redacted_bundle(monkeypatch,capsys):
    monkeypatch.setattr(U, "admission_operation", lambda: pytest.fail("production action"))
    assert U.main([]) == 42
    packet = json.loads(capsys.readouterr().out); body = packet["body"]
    assert packet["sha256"] == K.sha(K.canonical(body))
    assert body["mode"] == "OFFLINE_NO_PROD" and body["post"] == "DISABLED"
    assert body["testnet"]["plan"]["genesis_sha256"] is None and body["testnet"]["spend"] == 0
    assert U.main(["admit-k137"]) == 42
    assert "UNVERIFIED_STOP" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["status","--execute"], ["status","--capsule-path","SYNTHETIC_PRIVATE"], ["oracle-import"]])
def test_invalid_cli_does_not_reflect_input(args,capsys):
    assert U.main(args) == 42
    value = capsys.readouterr().out
    assert "SYNTHETIC_PRIVATE" not in value and "NO_GO" in value


def test_public_packet_duplicate_json_and_sensitive_path_refused(tmp_path):
    path = tmp_path/"public-packet.json"; path.write_text('{"a":1,"a":2}')
    with pytest.raises(ValueError): U.public_input(path)
    with pytest.raises(ValueError): U.public_input(tmp_path/"credentials.sealed.json")


def test_production_boundary_stops_before_reading_source_or_owner_key():
    with pytest.raises(K.Stop, match="LIVE_AUTHORITIES_REQUIRED"):
        K.production_migration(object(), production_pass=True, owner_approved=True)
    with pytest.raises(P.K.Stop, match="PRODUCTION_MIGRATION_NOT_ADMITTED"):
        P.Trial(None, None, None, mode="PRODUCTION")


def test_blocksio_small_reads_eof_and_bounds():
    data = P.BlocksIO(iter([b"ab", b"cdef"]))
    assert data.read(3) == b"abc" and data.read(9) == b"def" and data.read(1) == b""
    with pytest.raises(ValueError): data.read(-1)


@pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell 5.1")
def test_ps51_consolidated_entrypoint_offline_no_cloud():
    script = "$PSVersionTable.PSVersion.ToString(); & 'PYTHON' -I -B 'ENTRY' status; exit $LASTEXITCODE"
    script = script.replace("PYTHON",sys.executable.replace("'","''")).replace("ENTRY",str(PKG/"r1163_unified.py").replace("'","''"))
    p = subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],capture_output=True,timeout=30)
    lines = p.stdout.decode().splitlines()
    assert p.returncode == 42 and p.stderr == b"" and lines[0].startswith("5.1.")
    body = json.loads(lines[1])["body"]
    assert body["source_files_checked"] == 122 and body["state"] == "NO_GO"
