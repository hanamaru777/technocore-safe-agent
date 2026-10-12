"""R860 OCI Cloud Shell survey: offline security and host-identity regression tests."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-cloudshell-auth-survey.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_r860", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def valid(monkeypatch, tmp_path, m):
    config = tmp_path / "config"
    config.write_text("[ap-tokyo-1]\ntenancy=ocid1.tenancy.oc1..valid123456789\n")
    token = tmp_path / "delegation_token"
    token.write_text("dummy-test-token")
    monkeypatch.setattr(m, "CONFIG", config)
    monkeypatch.setattr(m, "TOKEN", token)
    monkeypatch.setattr(m, "REGION", "ap-tokyo-1")
    monkeypatch.setattr(sys, "argv", ["-"])
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("OCI_CLI_AUTH", "instance_obo_user")
    monkeypatch.setenv("OCI_CLI_CONFIG_FILE", str(config))
    monkeypatch.setenv("OCI_CLI_PROFILE", "ap-tokyo-1")
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/local/bin/oci")
    return config, token

def test_source_syntax_scope_and_no_hostname_dependency():
    source = SCRIPT.read_text()
    compile(source, str(SCRIPT), "exec")
    assert "gethostname" not in source and "socket" not in source
    assert "CLOUD_SHELL_DELEGATION_TOKEN_ABSENT" in source
    assert "FLOP_R860_NO_CLOUD_MUTATION" in source
    assert "stderr=subprocess.DEVNULL" in source
    for token in ('"object", "put"', '"object", "delete"', '"bucket", "create"',
                  '"iam", "policy"', "shell=True", "sudo"):
        assert token not in source

def test_realistic_cloudshell_hostname_is_not_used(monkeypatch, tmp_path):
    m = load()
    valid(monkeypatch, tmp_path, m)
    # Actual inner hostname is not observed. Prove no dependence on its form.
    assert m.admission() == "ocid1.tenancy.oc1..valid123456789"

def test_missing_delegation_token_stops_before_cli(monkeypatch, tmp_path):
    m = load()
    _, token = valid(monkeypatch, tmp_path, m)
    token.unlink()
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: pytest.fail("must not query storage"))
    with pytest.raises(m.Stop, match="DELEGATION_TOKEN_ABSENT"):
        m.run()

def test_wrong_auth_stops_before_cli(monkeypatch, tmp_path):
    m = load()
    valid(monkeypatch, tmp_path, m)
    monkeypatch.delenv("OCI_CLI_AUTH")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: pytest.fail("must not query storage"))
    with pytest.raises(m.Stop, match="AUTH_ABSENT"):
        m.run()

def test_profile_path_symlink_rejected(monkeypatch, tmp_path):
    m = load()
    config, _ = valid(monkeypatch, tmp_path, m)
    config.unlink()
    outside = tmp_path / "outside"
    outside.write_text("[ap-tokyo-1]\ntenancy=ocid1.tenancy.oc1..valid123456789\n")
    config.symlink_to(outside)
    with pytest.raises(m.Stop, match="CONFIG_ABSENT"):
        m.admission()

def test_mutating_cli_method_is_rejected_without_subprocess(monkeypatch):
    m = load()
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: pytest.fail("no mutation"))
    with pytest.raises(m.Stop, match="UNAPPROVED_METHOD"):
        m.cli("os", "bucket", "delete", "--bucket-name", "bad")

def test_success_no_secret_print(monkeypatch, tmp_path, capsys):
    m = load()
    valid(monkeypatch, tmp_path, m)
    def fake(*args):
        if args[:3] == ("os", "ns", "get"):
            return {"data":"private-ns"}
        if args[:3] == ("os", "bucket", "list"):
            return {"data":[{"name":"classified-bucket"}]}
        if args[:3] == ("os", "bucket", "get"):
            return {"data":{"approximate-size":12345}} if "--fields" in args else {
                "data":{"public-access-type":"NoPublicAccess"}}
        pytest.fail("unknown call")
    monkeypatch.setattr(m, "cli", fake)
    m.run()
    output = capsys.readouterr().out
    assert "FLOP_R860_READ_ONLY_SURVEY_PASS" in output
    assert "FLOP_R860_ROOT_APPROX_BYTES=12345" in output
    for word in ("private-ns", "classified-bucket", "ocid1.tenancy", "dummy-test-token"):
        assert word not in output

def test_four_buckets_partial_no_detail_calls(monkeypatch, tmp_path, capsys):
    m = load()
    valid(monkeypatch, tmp_path, m)
    def fake(*args):
        if args[:3] == ("os", "ns", "get"):
            return {"data":"secret-ns"}
        if args[:3] == ("os", "bucket", "list"):
            return {"data":[{"name":str(i)} for i in range(4)]}
        pytest.fail("no detail query after truncated list")
    monkeypatch.setattr(m, "cli", fake)
    m.run()
    output = capsys.readouterr().out
    assert "FLOP_R860_ROOT_LIST_PARTIAL" in output
    assert "FLOP_R860_ROOT_APPROX_BYTES" not in output
