"""OCI Cloud Shell feasibility probe offline stubs; no live OCI API calls."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging/oracle/retirement-objectstorage-readonly-feasibility.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_oci_cloudshell_storage", SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_source_compiles_and_denies_all_mutating_method_names():
    content = SRC.read_text()
    compile(content, str(SRC), "exec")
    for token in (
        '"object", "put"', '"object", "delete"', '"bucket", "create"',
        '"bucket", "delete"', '"bucket", "update"', '"iam", "policy"',
        "sys.stdin.read", "open('/etc", "sudo", "oci setup",
    ):
        assert token not in content
    assert "FLOP_OFFVM_BUCKET_CREATE_UPLOAD_DELETE_NOT_ATTEMPTED" in content
    assert "FLOP_OFFVM_FREE_TIER_CREDIT_BILLING_UNCONFIRMED" in content
    assert "FLOP_OFFVM_ROOT_COMPARTMENT_ONLY_NOT_ALL_TENANCY" in content

def test_unapproved_oci_cli_method_fails_without_subprocess(monkeypatch):
    m = load()
    def bad(*args, **kwargs):
        raise AssertionError("must not execute any program")
    monkeypatch.setattr(m.subprocess, "run", bad)
    with pytest.raises(m.Stop, match="UNAPPROVED_CLI_METHOD"):
        m.cli("os", "object", "delete", "--bucket-name", "bad")

def test_zero_root_buckets_is_only_partial_scope(monkeypatch, capsys):
    m = load()
    monkeypatch.setattr(m.sys, "argv", ["objectstorage-readonly-feasibility.py"])
    monkeypatch.setattr(m, "tenancy_id", lambda: "ocid1.tenancy.oc1..fakebutnotprinted")
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/local/bin/oci")
    hits = []
    def fake(*parts):
        hits.append(parts)
        if parts[:3] == ("os", "ns", "get"):
            return {"data": "private-namespace-not-for-stdout"}
        if parts[:3] == ("os", "bucket", "list"):
            return {"data": []}
        if parts[:3] == ("limits", "value", "list"):
            return {"data": [{"name":"example"}]}
        raise AssertionError(parts)
    monkeypatch.setattr(m, "cli", fake)
    m.run()
    output = capsys.readouterr().out
    assert "FLOP_OFFVM_READ_ONLY_STORAGE_FEASIBILITY_PASS" in output
    assert "FLOP_OFFVM_ROOT_BUCKET_COUNT_OBSERVED=0" in output
    assert "FLOP_OFFVM_ROOT_COMPARTMENT_ONLY_NOT_ALL_TENANCY" in output
    assert "private-namespace" not in output
    assert "fakebutnotprinted" not in output
    assert len(hits) == 3

def test_existing_bucket_size_aggregation_does_not_disclose_name(monkeypatch, capsys):
    m = load()
    monkeypatch.setattr(m.sys, "argv", ["objectstorage-readonly-feasibility.py"])
    monkeypatch.setattr(m, "tenancy_id", lambda: "ocid1.tenancy.oc1..fakebutnotprinted")
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/local/bin/oci")
    def fake(*parts):
        if parts[:3] == ("os", "ns", "get"):
            return {"data":"storage-namespace-do-not-leak"}
        if parts[:3] == ("os", "bucket", "list"):
            return {"data":[{"name":"company-private-archive"}]}
        if parts[:3] == ("os", "bucket", "get"):
            return {"data":{"approximate-size":456789,"public-access-type":"NoPublicAccess"}}
        if parts[:3] == ("limits", "value", "list"):
            raise m.Stop("insufficient permissions")
        raise AssertionError(parts)
    monkeypatch.setattr(m, "cli", fake)
    m.run()
    output = capsys.readouterr().out
    assert "FLOP_OFFVM_ROOT_APPROX_SIZE_KNOWN=true" in output
    assert "FLOP_OFFVM_ROOT_APPROX_BYTES=456789" in output
    assert "FLOP_OFFVM_ROOT_PRIVATE_STATUS=VERIFIED" in output
    assert "FLOP_OFFVM_STORAGE_LIMIT_QUERY_UNCONFIRMED" in output
    assert "company-private-archive" not in output
    assert "storage-namespace" not in output

def test_truncated_list_must_not_be_tenancy_total(monkeypatch, capsys):
    m = load()
    monkeypatch.setattr(m.sys, "argv", ["objectstorage-readonly-feasibility.py"])
    monkeypatch.setattr(m, "tenancy_id", lambda: "ocid1.tenancy.oc1..fakebutnotprinted")
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/local/bin/oci")
    def fake(*parts):
        if parts[:3] == ("os", "ns", "get"):
            return {"data":"private"}
        if parts[:3] == ("os", "bucket", "list"):
            return {"data":[{"name":str(i)} for i in range(4)]}
        if parts[:3] == ("limits", "value", "list"):
            return {"data":[]}
        raise AssertionError("no per-bucket fetch on truncated list")
    monkeypatch.setattr(m,"cli",fake)
    m.run()
    o = capsys.readouterr().out
    assert "FLOP_OFFVM_ROOT_BUCKET_REVIEW_PARTIAL" in o
    assert "FLOP_OFFVM_ROOT_APPROX_BYTES=" not in o

def test_missing_tenancy_auth_metadata_fails_closed(monkeypatch, tmp_path):
    m = load()
    monkeypatch.delenv("OCI_CLI_TENANCY", raising=False)
    monkeypatch.setenv("OCI_CLI_PROFILE", "DEFAULT")
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(m.Stop, match="CLOUDSHELL_CLI_PROFILE_ABSENT"):
        m.tenancy_id()
