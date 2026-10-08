from __future__ import annotations

import inspect
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from flop_agent import observer_lobby_capture as capture
from flop_agent import observer_lobby_capture_service as service


def test_bootstrap_copies_live_legacy_spool_once(tmp_path):
    legacy = tmp_path / "legacy.sqlite3"
    target = tmp_path / "service.sqlite3"
    connection = capture._connect(legacy)
    try:
        assert capture.initialize_cursor(connection, 10) == 10
        rows = [
            {"seq": 11, "text": "a"},
            {"seq": 12, "text": "b"},
            {"seq": 13, "text": "c"},
        ]
        assert capture.store_rows(connection, rows) == 3
        assert capture._advance_contiguous(connection, 10) == 13
        capture._meta_set(connection, "last_success_at", "2026-09-08T10:00:00+00:00")
        connection.commit()
    finally:
        connection.close()

    assert service.bootstrap_from_legacy(source=legacy, target=target)
    copied = capture.status(target)
    assert copied["capture_cursor"] == 13
    assert copied["rows"] == 3
    assert copied["last_success_at"] == "2026-09-08T10:00:00+00:00"
    assert not service.bootstrap_from_legacy(source=legacy, target=target)


def test_install_reader_switches_capture_helpers_to_service_spool(monkeypatch):
    monkeypatch.setattr(capture, "DB_NAME", service.LEGACY_DB_NAME)
    service.install_reader()
    assert capture.DB_NAME == service.SERVICE_DB_NAME


def test_service_module_has_no_write_signing_or_shell_surface():
    source = inspect.getsource(service)
    assert "subprocess" not in source
    assert ".post(" not in source
    assert "post_signed(" not in source
    assert "SIGN_SEED" not in source
    assert "source_conn.backup(destination)" in source
    assert "capture.capture_process(stop)" in source


def test_oracle_units_keep_capture_independent_from_resident_restart():
    root = Path(__file__).resolve().parents[1]
    capture_unit = (root / "packaging/oracle/lobby-capture.service").read_text()
    resident_unit = (root / "packaging/oracle/resident.service").read_text()
    installer = (root / "packaging/oracle/install.sh").read_text()

    assert "ExecStart=/opt/technocore-safe-agent/.venv/bin/python -m flop_agent.observer_lobby_capture_service" in capture_unit
    assert "Restart=on-failure" in capture_unit
    assert "Before=technocore-safe-agent-resident.service" in capture_unit
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/observer" in capture_unit
    assert "Wants=network-online.target technocore-safe-agent-lobby-capture.service" in resident_unit
    assert "After=network-online.target technocore-safe-agent-metadata-block.service technocore-safe-agent-lobby-capture.service" in resident_unit
    assert "packaging/oracle/lobby-capture.service /etc/systemd/system/technocore-safe-agent-lobby-capture.service" in installer


def test_capture_lightweight_paths_match_observer_contract(monkeypatch, tmp_path):
    monkeypatch.setattr(capture.core, "STATE", tmp_path)
    assert capture.observer_dir() == tmp_path / "observer"
    assert capture.capture_path() == tmp_path / "observer" / capture.DB_NAME
    assert capture.heartbeat_path() == tmp_path / "observer" / "observer-heartbeat.json"
    assert capture.observer_cursor_bootstrap_path() == (
        tmp_path / "observer" / capture.OBSERVER_CURSOR_BOOTSTRAP_NAME
    )


def test_capture_timestamp_remains_utc_iso8601():
    stamp = datetime.fromisoformat(capture._now())
    assert stamp.tzinfo is not None
    assert stamp.utcoffset() == UTC.utcoffset(stamp)


def test_standalone_capture_import_does_not_load_rich_observer():
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    code = (
        "import sys; "
        "import flop_agent.observer_lobby_capture_service; "
        "print('flop_agent.observer' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == "False"
