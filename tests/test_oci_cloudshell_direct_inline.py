"""Direct OCI Cloud Shell survey is tested offline; no OCI client / remote mutation."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-cloudshell-direct-inline.py"

def module():
    spec = importlib.util.spec_from_file_location("flop_cloudshell_direct", SRC)
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item

def baseline(monkeypatch, m):
    monkeypatch.setattr(sys, "argv", [str(SRC)])
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(m.socket, "gethostname", lambda: "cloudshell")
    monkeypatch.setattr(m.shutil, "which", lambda exe: "/usr/local/bin/oci")
    monkeypatch.setenv("OCI_CLI_AUTH", "instance_obo_user")
    monkeypatch.setenv("OCI_CLI_CONFIG_FILE", "/etc/oci/config")
    monkeypatch.setenv("OCI_CLI_PROFILE", "ap-tokyo-1")
    monkeypatch.setattr(m, "tenancy_from_config", lambda path, profile: "ocid1.tenancy.oc1..fake987654321")

def test_syntax_allowlist_and_no_mutation_tokens():
    data = SRC.read_text()
    compile(data, str(SRC), "exec")
    assert "ALLOWED = " in data and '("os", "bucket", "list")' in data
    assert "shell=True" not in data
    assert "stderr=subprocess.DEVNULL" in data
    assert "FLOP_STORAGE_QUOTA_CREDITS_BILLING_UNCONFIRMED" in data

def test_no_oci_if_wrong_host(monkeypatch):
    m = module()
    baseline(monkeypatch, m)
    monkeypatch.setattr(m.socket, "gethostname", lambda: "technocore-resident")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not call OCI"))
    with pytest.raises(m.Stop, match="WRONG_HOST"):
        m.run()

def test_no_oci_without_cloudshell_auth(monkeypatch):
    m = module()
    baseline(monkeypatch, m)
    monkeypatch.delenv("OCI_CLI_AUTH")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not call OCI"))
    with pytest.raises(m.Stop, match="AUTH_ABSENT"):
        m.run()

def test_cloud_shell_tenancy_config_parser(tmp_path):
    m = module()
    cfg = tmp_path / "config"
    cfg.write_text("[ap-tokyo-1]\ntenancy=ocid1.tenancy.oc1..abcdefghi0123\n")
    assert m.tenancy_from_config(cfg, "ap-tokyo-1") == "ocid1.tenancy.oc1..abcdefghi0123"
    with pytest.raises(m.Stop, match="TENANCY_PROFILE"):
        m.tenancy_from_config(cfg, "nonexistent")

def test_reject_unlisted_method_before_execution(monkeypatch):
    m = module()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not call OCI"))
    with pytest.raises(m.Stop, match="NON_READ_ONLY"):
        m.cli("os", "object", "put", "--name", "forbidden")

def test_success_one_private_bucket_no_identifier_disclosure(monkeypatch, capsys):
    m = module()
    baseline(monkeypatch, m)
    namespace = "secret-ns"
    bucket = "secret-bucket"
    def fake(*args):
        if args[:3] == ("os", "ns", "get"):
            return {"data": namespace}
        if args[:3] == ("os", "bucket", "list"):
            return {"data": [{"name":bucket}]}
        if args[:3] == ("os", "bucket", "get"):
            if "--fields" in args:
                return {"data":{"approximate-size":12345}}
            return {"data":{"public-access-type":"NoPublicAccess"}}
        pytest.fail("unexpected method")
    monkeypatch.setattr(m, "cli", fake)
    m.run()
    out = capsys.readouterr().out
    assert "FLOP_STORAGE_DIRECT_CLOUDSHELL_READONLY_PASS" in out
    assert "FLOP_STORAGE_ROOT_APPROX_BYTES=12345" in out
    for sensitive in (namespace,bucket,"ocid1.tenancy"):
        assert sensitive not in out

def test_more_than_three_is_partial_and_skips_bucket_get(monkeypatch,capsys):
    m = module()
    baseline(monkeypatch, m)
    def fake(*args):
        if args[:3] == ("os", "ns", "get"):
            return {"data":"secret-ns"}
        if args[:3] == ("os", "bucket", "list"):
            return {"data":[{"name":str(i)} for i in range(4)]}
        pytest.fail("should not fetch details for partial list")
    monkeypatch.setattr(m,"cli",fake)
    m.run()
    out=capsys.readouterr().out
    assert "FLOP_STORAGE_ROOT_LIST_PARTIAL" in out
    assert "FLOP_STORAGE_ROOT_APPROX_BYTES" not in out
