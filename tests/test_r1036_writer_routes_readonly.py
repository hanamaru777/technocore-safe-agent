"""R1036 synthetic source-only tests: no original Oracle/credentials or network."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/oracle/r1036_writer_routes_readonly.py"
spec = importlib.util.spec_from_file_location("r1036", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixed_unit_output(name, *, command="", state="inactive", installed="static"):
    return ("\n".join((
        "Id=" + name, "LoadState=loaded", "ActiveState=" + state,
        "UnitFileState=" + installed,
        "FragmentPath=/etc/systemd/system/" + name,
        "ExecStart=" + command,
    )) + "\n")


def test_unknown_fixed_units_only_and_no_raw_commands(monkeypatch):
    calls = []

    def fake_execute(argv, stage):
        calls.append((argv, stage))
        name = argv[-1]
        if name.endswith(".timer"):
            return fixed_unit_output(name, installed="disabled")
        return fixed_unit_output(name, command=(
            "{ path=/opt/technocore-safe-agent/.venv/bin/python ; "
            "argv[]=/opt/technocore-safe-agent/.venv/bin/python -m "
            "flop_agent.close1_standalone_watch PRIVATE_TEST_MARKER ; }"))
    monkeypatch.setattr(m, "execute", fake_execute)
    result = m.unit_rows()
    assert len(result) == 4 and len(calls) == 4
    assert all(stage == "SHOW" and args[:2] == ("systemctl", "show")
               and "--no-pager" in args for args, stage in calls)
    assert all(row["identity"].startswith(m.PREFIX) for row in result)
    assert result[0]["command_kind"] == "FLOP_PYTHON"
    assert "PRIVATE_TEST_MARKER" not in str(result)
    assert result[1]["command_kind"] == "NO_EXEC"
    assert result[3]["active"] == "inactive"


@pytest.mark.parametrize(("bad", "reason"), (
    ("Id=WRONG", "UNIT_ID_STOP"),
    ("UnitFileState=UNEXPECTED", "UNIT_STATE_STOP"),
    ("ActiveState=UNKNOWN", "UNIT_STATE_STOP"),
    ("ExecStart=" + "a" * 8193, "UNIT_COMMAND_BOUND_STOP"),
    ("UntrustedField=secret", "UNIT_SCHEMA_STOP"),
))
def test_show_guard_rejects_drift_or_untrusted_output(monkeypatch, bad, reason):
    name = m.PREFIX + m.SUFFIXES[0]
    original = fixed_unit_output(name)
    key = bad.split("=", 1)[0]
    if key == "UntrustedField":
        text = original + bad + "\n"
    else:
        text = "\n".join(bad if line.startswith(key + "=") else line
                         for line in original.splitlines()) + "\n"
    monkeypatch.setattr(m, "execute", lambda *args: text)
    with pytest.raises(m.Stop, match=reason):
        m.unit_rows()


def test_cron_metadata_aggregates_without_printing_contents(tmp_path):
    cronfile = tmp_path / "crontab"
    cronfile.write_text(
        "# ignored /opt/technocore-safe-agent\n"
        "* * * * * root /opt/technocore-safe-agent/.venv/bin/python "
        "-m flop_agent.resident_daemon SENSITIVE_VALUE\n"
        "MAILTO=PRIVATE_ADDRESS\n",
        encoding="utf-8",
    )
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    (cron_dir / "regular").write_text("0 0 * * * python unrelated\n", encoding="utf-8")
    result = m.bounded_cron(primary=cronfile, directories=(cron_dir,))
    assert result["cron_regular_files_read"] == 2
    assert result["cron_flop_matching_lines"] == 1
    assert result["cron_unverified_entries"] == 0
    assert result["cron_scan_complete"] is False
    assert "SENSITIVE_VALUE" not in str(result)
    assert "PRIVATE_ADDRESS" not in str(result)


def test_cron_rejects_symlink_and_oversized_without_following(tmp_path):
    private = tmp_path / "private"
    private.write_text("sensitive", encoding="utf-8")
    directory = tmp_path / "cron.d"
    directory.mkdir()
    (directory / "symbolic").symlink_to(private)
    (directory / "oversize").write_bytes(b"x" * (m.MAX_CRON_FILE + 1))
    primary = tmp_path / "absent"
    result = m.bounded_cron(primary=primary, directories=(directory,))
    assert result["cron_regular_files_read"] == 0
    assert result["cron_unverified_entries"] == 2


def test_process_witness_aggregates_without_pids_or_arguments(tmp_path):
    first = tmp_path / "1001"
    first.mkdir()
    (first / "cmdline").write_bytes(b"python\0-m\0flop_agent.oracle_signer\0PRIVATE\0")
    (first / "cgroup").write_bytes(b"0::/system.slice/technocore-safe-agent-signer.service\n")
    second = tmp_path / "1002"
    second.mkdir()
    (second / "cmdline").write_bytes(b"unrelated")
    third = tmp_path / "1003"
    third.mkdir()
    (third / "cmdline").write_bytes(b"flop_agent.anything")
    (third / "cgroup").write_bytes(b"0::/unknown.slice\n")
    report = m.bounded_processes(proc=tmp_path)
    assert report["matching_processes"] == 2
    assert report["cgroup_inspected_candidates"] == 2
    assert report["unknown_or_raced_processes"] == 1
    assert report["process_scan_complete"] is False
    assert "PRIVATE" not in str(report) and "1001" not in str(report)


@pytest.mark.parametrize("stage", ["HEAD", "SHOW"])
def test_command_failure_discards_stderr(monkeypatch, stage):
    def fail(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, timeout=1, stderr=b"SENSITIVE")
    monkeypatch.setattr(m.subprocess, "run", fail)
    with pytest.raises(m.Stop, match=stage + "_EXEC_STOP") as caught:
        m.execute(("systemctl", "show"), stage)
    assert "SENSITIVE" not in str(caught.value)


def test_full_report_is_bounded_canonical_and_disarmed(monkeypatch, capsys):
    monkeypatch.setattr(m, "preflight", lambda: None)
    monkeypatch.setattr(m, "unit_rows", lambda: [])
    monkeypatch.setattr(m, "bounded_cron", lambda: {
        "cron_regular_files_read": 0, "cron_flop_matching_lines": 0,
        "cron_unverified_entries": 0, "cron_scan_complete": False})
    monkeypatch.setattr(m, "bounded_processes", lambda: {
        "matching_processes": 0, "cgroup_inspected_candidates": 0,
        "unknown_or_raced_processes": 0, "process_scan_complete": False})
    m.run()
    import json
    text = capsys.readouterr().out
    obj = json.loads(text)
    assert text == json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    assert obj["flags"]["all_writers_fenced"] == "NO"
    assert obj["flags"]["oci_retirement"] == "STRICT_NO_GO"
    assert obj["flags"]["process_and_cron_discovery_complete"] == "NO"


def test_readonly_source_has_no_unsafe_primitives():
    raw = SCRIPT.read_text(encoding="utf-8")
    for bad in ("systemctl stop", "systemctl start", "systemctl restart",
                "systemctl disable", "systemctl mask", "sudo ", "sqlite3",
                "journalctl", "requests.", "urlopen", "os.environ",
                "stdout=subprocess.PIPE, stderr=subprocess.PIPE",
                "open(", "write_text(", "write_bytes("):
        if bad == "open(":
            assert "open(path, flags)" in raw
            continue
        if bad in ("write_text(", "write_bytes("):
            assert bad not in raw
        else:
            assert bad not in raw


def test_timer_without_service_only_exec_property(monkeypatch):
    def fake(argv, stage):
        name = argv[-1]
        response = fixed_unit_output(name, installed="disabled")
        if name.endswith(".timer"):
            response = response.replace("ExecStart=\n", "")
        return response
    monkeypatch.setattr(m, "execute", fake)
    report = m.unit_rows()
    assert len(report) == 4
    assert report[1]["command_kind"] == "NO_EXEC"
    assert report[2]["command_kind"] == "NO_EXEC"
    assert report[0]["command_kind"] == "NO_EXEC"
