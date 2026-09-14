from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEALTHCHECK = ROOT / "packaging" / "oracle" / "healthcheck.sh"


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fake_systemctl(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "systemctl"
    script.write_text(
        """#!/usr/bin/env bash
set -eu
if [[ ${1:-} == is-active && ${2:-} == --quiet ]]; then
  case ${3:-} in
    technocore-safe-agent-metadata-block.service|technocore-safe-agent-resident.service)
      exit 0
      ;;
    technocore-safe-agent-signer.service)
      exit 1
      ;;
  esac
fi
exit 1
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return bindir


def _run_healthcheck(tmp_path: Path, resident_heartbeat: dict) -> subprocess.CompletedProcess[str]:
    now = datetime.now(UTC).isoformat()
    state = tmp_path / "state"
    observer = state / "observer"
    _write_json(
        observer / "observer-heartbeat.json",
        {"schema_version": 1, "updated_at": now, "status": "ok"},
    )
    _write_json(observer / "resident-heartbeat.json", resident_heartbeat)
    bindir = _fake_systemctl(tmp_path)
    env = dict(os.environ)
    env["FLOP_STATE_DIR"] = str(state)
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        ["bash", str(HEALTHCHECK)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.skipif(os.name == "nt", reason="Oracle healthcheck is a Linux shell script")
def test_healthcheck_accepts_current_nested_resident_status(tmp_path: Path) -> None:
    now = datetime.now(UTC).isoformat()
    result = _run_healthcheck(
        tmp_path,
        {
            "schema_version": 1,
            "updated_at": now,
            "status": "ok",
            "resident_status": {
                "read_only": True,
                "last_refresh_at": now,
            },
        },
    )

    assert result.returncode == 0, result.stderr
    assert "resident healthcheck ok" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="Oracle healthcheck is a Linux shell script")
def test_healthcheck_rejects_legacy_top_level_refresh_without_resident_status(tmp_path: Path) -> None:
    now = datetime.now(UTC).isoformat()
    result = _run_healthcheck(
        tmp_path,
        {
            "schema_version": 1,
            "updated_at": now,
            "status": "ok",
            "last_refresh_at": now,
        },
    )

    assert result.returncode != 0
    assert "resident heartbeat status is invalid" in result.stderr
