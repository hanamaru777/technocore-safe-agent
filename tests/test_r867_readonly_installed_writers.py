"""R867: fake state only, never connect to cloud or operate real systemd."""
import importlib.util
import json
from pathlib import Path

import pytest

SOURCE = (Path(__file__).resolve().parents[1] / "packaging" / "oracle"
          / "r867_readonly_installed_writers.py")


def module():
    spec = importlib.util.spec_from_file_location("r867", SOURCE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_known_27_source_unit_names_and_installed_aliases():
    m = module()
    assert len(m.SOURCE_UNITS) == 27
    assert m.installed_name("resident.service") == "technocore-safe-agent-resident.service"
    assert m.installed_name("airdrop-monitor.timer") == "technocore-safe-agent-airdrop-monitor.timer"
    assert m.installed_name("technocore-safe-agent-signer.service") == "technocore-safe-agent-signer.service"


def test_installed_active_failed_units_are_summarized_without_process_details():
    m = module()
    installed = m.unit_file_names(
        "technocore-safe-agent-resident.service enabled enabled\n"
        "technocore-safe-agent-signer.service enabled enabled\n"
        "an-unrelated-bot.service enabled enabled\n")
    assert len(installed) == 2
    loaded = m.loaded_states(
        "technocore-safe-agent-resident.service loaded active running live\n"
        "● technocore-safe-agent-signer.service loaded failed failed broken\n"
        "another.service loaded active running different\n")
    assert loaded == {
        "technocore-safe-agent-resident.service": "active",
        "technocore-safe-agent-signer.service": "failed",
    }
    report = m.compare(installed, loaded)
    assert report["source_units_expected"] == 27
    assert report["loaded_active_count"] == 1
    assert report["loaded_failed_count"] == 1
    assert report["missing_count"] == 25
    assert report["unknown_count"] == 0


def test_template_instance_accepted_as_observation_but_not_a_writer_freeze():
    m = module()
    installed = {m.installed_name(x) for x in m.SOURCE_UNITS}
    states = {n: "inactive" for n in installed}
    states["technocore-safe-agent-tclk-accept@stage42.service"] = "active"
    info = m.compare(installed, states)
    assert info["template_instance_count"] == 1
    assert info["loaded_active_count"] == 1
    assert info["unknown_count"] == 0


def test_unrecognized_service_stays_digested_not_printed():
    m = module()
    name = "technocore-safe-agent-unexpected-finance-writer.service"
    info = m.compare(set(), {name: "active"})
    assert info["unknown_count"] == 1
    assert name not in json.dumps(info)
    assert len(info["unknown_digests"][0]) == 16


def test_malicious_template_instance_rejected():
    m = module()
    with pytest.raises(m.Stop, match="TEMPLATE_INSTANCE_INVALID"):
        m.compare(set(), {"technocore-safe-agent-tclk-reveal@../evil.service":"active"})


def test_output_limits_fail_closed():
    m = module()
    with pytest.raises(m.Stop, match="UNIT_FILE_LIST_INVALID"):
        m.unit_file_names("x" * m.MAX_OUTPUT)


def test_subprocess_is_strictly_read_only_no_shell_or_stderr(monkeypatch):
    m = module()
    class R:
        returncode = 0
        stdout = "sample\n"
    calls = []
    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return R()
    monkeypatch.setattr(m.subprocess, "run", fake)
    assert m.command(["systemctl", "list-unit-files"]).strip() == "sample"
    assert calls[0][1]["timeout"] == 6
    assert calls[0][1]["stderr"] == m.subprocess.DEVNULL
    assert calls[0][0][0] == ["systemctl", "list-unit-files"]


def test_timeout_is_not_retried(monkeypatch):
    m = module()
    called = []
    def fail(*args, **kwargs):
        called.append(1)
        raise m.subprocess.TimeoutExpired("systemctl", 6)
    monkeypatch.setattr(m.subprocess, "run", fail)
    with pytest.raises(m.Stop, match="READONLY_COMMAND_UNAVAILABLE"):
        m.command(["systemctl", "list-unit-files"])
    assert len(called) == 1


def test_source_cannot_mutate_services_secrets_or_cloud():
    text = SOURCE.read_text()
    compile(text, str(SOURCE), "exec")
    for snippet in ("systemctl stop", "systemctl restart", "systemctl disable",
                    "os.system(", "shell=True", "subprocess.Popen",
                    "shutil.copy(", "delete-instance", "SIGN_SEED",
                    ".environ", "write_bytes(", "write_text(",
                    "httpx.", "requests.", "import oci"):
        assert snippet not in text
    assert '"safe_to_snapshot": False' in text
    assert '"safe_to_delete_oracle": False' in text


def test_process_count_only_boolean_match(monkeypatch, tmp_path):
    m = module()
    a = tmp_path / "201"; a.mkdir()
    (a / "cmdline").write_bytes(b"python\0-m\0flop_agent.oracle_signer\0SENSITIVE\0")
    b = tmp_path / "202"; b.mkdir()
    (b / "cmdline").write_bytes(b"python\0-m\0unrelated\0")
    monkeypatch.setattr(m, "Path", lambda value: tmp_path if value == "/proc" else Path(value))
    assert m.process_count() == 1
