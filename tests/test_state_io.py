from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from flop_agent import observer, state_io


def test_atomic_json_write_matches_observer_bytes_normal_and_compact(tmp_path):
    value = {
        "schema_version": 1,
        "z": "日本語",
        "a": {"b": True, "n": 3},
    }
    for compact in (False, True):
        old = tmp_path / f"observer-{compact}.json"
        new = tmp_path / f"state-io-{compact}.json"
        observer.atomic_json_write(old, value, compact=compact, mode=0o600)
        state_io.atomic_json_write(new, value, compact=compact, mode=0o600)
        assert new.read_bytes() == old.read_bytes()


def test_atomic_json_write_preserves_explicit_0600_and_cleans_temp(tmp_path):
    path = tmp_path / "nested" / "state.json"
    state_io.atomic_json_write(path, {"schema_version": 1}, mode=0o600)
    assert json.loads(path.read_text("utf-8")) == {"schema_version": 1}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(path.parent.glob(f".{path.name}.*.tmp")) == []


def test_parse_time_matches_observer_contract():
    samples = [
        None,
        "",
        "2026-10-08T07:00:00+00:00",
        "2026-10-08T16:00:00+09:00",
        "2026-10-08T07:00:00",
        "not-a-time",
    ]
    for value in samples:
        assert state_io.parse_time(value) == observer.parse_time(value)


def _fresh_import_probe(module: str, tmp_path: Path) -> str:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["FLOP_STATE_DIR"] = str(tmp_path / "state")
    code = (
        "import sys; "
        f"import {module}; "
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
    return result.stdout.strip()


def test_fresh_autopilot_transport_import_does_not_load_observer(tmp_path):
    assert _fresh_import_probe(
        "flop_agent.autopilot_transport",
        tmp_path,
    ) == "False"


def test_fresh_oracle_signer_import_does_not_load_observer(tmp_path):
    assert _fresh_import_probe(
        "flop_agent.oracle_signer",
        tmp_path,
    ) == "False"
