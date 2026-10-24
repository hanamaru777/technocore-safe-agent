"""R1052 real repository original template-pin audit + synthetic negative gates.

Never accesses OCI, AWS, secrets, state, network, systemd, or a running service.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "packaging/archive/r1052_offline_writer_route_contract.py"
spec = importlib.util.spec_from_file_location("flop_r1052_offline", MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.fixture
def snapshot():
    path = ROOT / "packaging/oracle"
    return {name: (path / name).read_bytes()
            for name in sorted(audit.ORIGINAL_TEMPLATE_GIT_BLOBS)}


def test_exact_current_checkout_original_27_template_pins(snapshot):
    result = audit.audit_offline_original_templates(snapshot)
    assert result["schema_version"] == 1
    assert result["template_sources_pinned"] == 27
    assert result["service_templates"] == 19
    assert result["timer_templates"] == 8
    assert result["sign_and_post_entrypoint_templates"] == 5
    assert result["original_source_head"] == "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
    assert result["r1034_unexpected_installed"] == 4
    assert result["r1034_known_source_missing_installed"] == 1
    assert result["oci_retirement"] == "STRICT_NO_GO"
    assert result["all_writers_fenced"] == "NO"
    assert result["signer_inflight_post_resolved"] == "NO"
    assert result["full_state_common_epoch"] == "NOT_PROVEN"
    assert result["dynamic_template_instance_enumeration"] == "NOT_PROVEN"
    assert result["no_files_or_services_touched"] == "YES"


def test_exact_source_git_blobs_are_pinned(snapshot):
    assert all(audit.git_blob_sha1(content) == audit.ORIGINAL_TEMPLATE_GIT_BLOBS[name]
               for name, content in snapshot.items())


def test_new_unknown_unit_is_rejected_without_implicitly_fencing(snapshot):
    snapshot["unexpected-writer.timer"] = b"[Timer]\nOnBootSec=1\n"
    with pytest.raises(audit.CoverageStop, match="TEMPLATE_EXACT_SET_STOP"):
        audit.audit_offline_original_templates(snapshot)


def test_missing_dynamic_template_rejected(snapshot):
    del snapshot["technocore-safe-agent-tclk-reveal@.service"]
    with pytest.raises(audit.CoverageStop, match="TEMPLATE_EXACT_SET_STOP"):
        audit.audit_offline_original_templates(snapshot)


def test_tampered_exact_template_rejected_without_leaking_contents(snapshot):
    name = "technocore-safe-agent-signer.service"
    snapshot[name] += b"\nEnvironment=SIGN_SEED=NEVER_ECHO_THIS\n"
    with pytest.raises(audit.CoverageStop, match="^TEMPLATE_PIN_MISMATCH_STOP$") as e:
        audit.audit_offline_original_templates(snapshot)
    assert "NEVER_ECHO_THIS" not in str(e.value)


def test_nonbytes_rejected_without_interpreting_source(snapshot):
    snapshot["resident.service"] = "this is not bytes"
    with pytest.raises(audit.CoverageStop, match="SOURCE_TYPE_OR_SIZE_STOP"):
        audit.audit_offline_original_templates(snapshot)


def test_oversized_template_rejected_bounded(snapshot):
    snapshot["resident.service"] = b"X" * (audit.MAX_SOURCE_BYTES + 1)
    with pytest.raises(audit.CoverageStop, match="SOURCE_TYPE_OR_SIZE_STOP"):
        audit.audit_offline_original_templates(snapshot)


def test_route_execstart_mismatch_even_if_test_pin_is_rebased(snapshot, monkeypatch):
    """Defence-in-depth: trusted pin plus exact route mapping, no shell parsing."""
    name = "technocore-safe-agent-tclk-accept@.service"
    mutated = snapshot[name].replace(
        b"flop_agent.tclk_pilot_accept %i",
        b"flop_agent.fake_unreviewed_writer %i")
    assert mutated != snapshot[name]
    snapshot[name] = mutated
    replacement = dict(audit.ORIGINAL_TEMPLATE_GIT_BLOBS)
    replacement[name] = audit.git_blob_sha1(mutated)
    monkeypatch.setattr(audit, "ORIGINAL_TEMPLATE_GIT_BLOBS", replacement)
    with pytest.raises(audit.CoverageStop, match="SIGN_ROUTE_MODULE_DRIFT_STOP"):
        audit.audit_offline_original_templates(snapshot)


def test_private_preview_writers_not_misclassified_as_post_authority():
    assert "flop_agent.tclk_pilot_signer" not in audit.SIGN_POST_ROUTES.values()
    assert "flop_agent.tclk_pilot_reveal" not in audit.SIGN_POST_ROUTES.values()
    assert "technocore-safe-agent-tclk-accept@.service" in audit.SIGN_POST_ROUTES
    assert "technocore-safe-agent-tclk-reveal@.service" in audit.SIGN_POST_ROUTES


def test_unknown_units_and_cron_cannot_be_silently_called_covered(snapshot):
    result = audit.audit_offline_original_templates(snapshot)
    assert len(result["all_unproven_categories"]) >= 10
    assert "all_cron_entries_and_effective_interpreters" in result["all_unproven_categories"]
    assert "full_dynamic_tclk_instance_census" in result["all_unproven_categories"]
    assert "all_signer_close1_tclk_external_post_acceptance" in result["all_unproven_categories"]
    assert result["oci_retirement"] == "STRICT_NO_GO"


def test_pure_module_no_prod_entrypoint_or_write_operations():
    source = MODULE.read_text(encoding="utf-8")
    for blocked in (
        "subprocess.run", "subprocess.Popen", "os.system(",
        "os.kill(", "systemctl start", "systemctl stop", "systemctl mask",
        "sqlite3.connect", "socket.socket", "requests.post",
        "httpx.post", "urllib.request", "oci.secrets",
        "Path.write_text(", "Path.write_bytes(", "open(", "__main__",
    ):
        assert blocked not in source
