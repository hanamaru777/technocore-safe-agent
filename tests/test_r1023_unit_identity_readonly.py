"""Synthetic metadata only: never invokes the host or network."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/oracle/r1023_unit_identity_readonly.py"
spec = importlib.util.spec_from_file_location("r1023", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_original_static_names_match_r1016():
    other = importlib.util.spec_from_file_location("r1016", ROOT / "packaging/oracle/r1016_writer_inventory_readonly.py")
    original = importlib.util.module_from_spec(other)
    other.loader.exec_module(original)
    assert m.EXPECTED == original.EXPECTED
    assert len(m.EXPECTED) == 27


def test_missing_active_signer_enabled_and_normalized_instances():
    signer = m.PREFIX + "signer.service"
    template = m.PREFIX + "tclk-accept@.service"
    instance = m.PREFIX + "tclk-accept@private-instance.service"
    timer = m.PREFIX + "tclk-stager.timer"
    installed = m.metadata_names(f"{signer} enabled enabled\n{template} static -\n{timer} enabled enabled\n")
    live = m.metadata_names(f"{signer} loaded active running hidden description\n{instance} loaded activating start hidden\n", live=True)
    result = m.analyze_units(installed, live)
    assert len(result["missing_known"]) == 24
    assert signer not in result["missing_known"]
    assert result["active_signer_candidates"] == sorted((signer, template))
    assert template in result["active_known"]
    assert "private-instance" not in m.render(result)
    assert next(row for row in result["units"] if row["identity"] == timer)["installed_states"] == ["enabled"]
    assert result["flags"] == m.FLAGS
    assert result["flags"]["all_writers_fenced"] == "NO"
    assert result["flags"]["oci_retirement"] == "STRICT_NO_GO"


def test_unknown_identity_safe_allowlist_or_digest():
    safe = m.PREFIX + "extra-writer.service"
    unsafe = m.PREFIX + "secret@synthetic-token.service"
    result = m.analyze_units(m.metadata_names(f"{safe} enabled\n{unsafe} disabled\n"),
                             m.metadata_names(f"{safe} loaded active running\n", live=True))
    text = m.render(result)
    assert safe in text
    assert unsafe not in text
    assert "synthetic-token" not in text
    assert "redacted-sha256-" in text
    assert next(row for row in result["units"] if row["identity"] == safe)["active_states"] == ["active"]


@pytest.mark.parametrize("raw", [
    "x.service enabled\nx.service disabled\n", "x.service unexpected\n",
    "x.service\n", "not-unit enabled\n", "x" * (m.MAX_INPUT + 1),
    "x.service enabled\n" * (m.MAX_LINES + 1),
], ids=["duplicate", "bad-state", "missing-state", "bad-name", "byte-bound", "line-bound"])
def test_malformed_duplicate_and_oversized_metadata_rejected(raw):
    with pytest.raises(m.Stop):
        m.metadata_names(raw)


def test_guest_scope_pin_rejected_before_systemd(monkeypatch, tmp_path):
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(m, "ROOT", tmp_path)
    monkeypatch.setattr(m, "STATE", tmp_path)
    calls = []
    monkeypatch.setattr(m, "read_command", lambda args: calls.append(args) or "wrong")
    with pytest.raises(m.Stop, match="ORIGINAL_HEAD_MISMATCH_STOP"):
        m.guest_preflight()
    assert len(calls) == 1 and calls[0][0] == "git"


def test_run_only_fixed_metadata_commands(monkeypatch, capsys):
    monkeypatch.setattr(m, "guest_preflight", lambda: None)
    calls = []
    monkeypatch.setattr(m, "read_command", lambda args: calls.append(args) or "")
    m.run()
    output = capsys.readouterr().out
    assert len(calls) == 2
    assert all(args[:2] in (("systemctl", "list-unit-files"), ("systemctl", "list-units")) for args in calls)
    assert "STRICT_NO_GO" in output and "process_enumeration_complete" in output


def test_no_mutation_or_sensitive_read_primitives():
    raw = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("systemctl stop", "systemctl start", "systemctl restart",
                      "systemctl disable", "systemctl mask", "sqlite3", "journalctl",
                      "os.environ", "/proc/", ".write_text(", ".write_bytes(", "urlopen"):
        assert forbidden not in raw

