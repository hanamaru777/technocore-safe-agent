#!/usr/bin/env python3
"""Collect ONE Flop-only, read-only 60s proof for issue813-lobby-recovery-gate.

No networking, credentials, production source changes, SQLite connections,
service control, shell evaluation, or output of raw state/agent/DID records.
The policy evaluator, not this collector, renders a safety verdict; neither
authorizes a restart. Requires local jq for bounded Rich JSON streaming.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

HOST = "technocore-resident"
REPO = Path("/opt/technocore-safe-agent")
ROOT = Path("/var/lib/technocore-safe-agent")
OBSERVER = ROOT / "observer"
OLD_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"
TARGET_HEAD = "a1b3517a1092fb4c7e4e730ac75d42d1f0075167"
UNITS = ("resident", "lobby-capture", "signer", "discord")
SAMPLES = 7
INTERVAL_SECONDS = 10.0
MAX_RICH_BYTES = 32 * 1024 * 1024
MAX_SAFETY_BYTES = 4096
MAX_STREAM_OUTPUT = 16384
EXPECTED_ERROR = "startup_lobby_capture_protected_backlog_capacity"
RICH_FILTER = r"""
select(length == 2) | .[0] as $p | .[1] as $v
| if $p == ["updated_at"] then ["at",$v]
  elif $p == ["cursors","lobby"] then ["lobby_cursor",$v]
  elif $p == ["health","current"] then ["health",$v]
  elif $p == ["metrics","unrecoverable_core_gap_events"] then ["core_gap_events",$v]
  elif $p == ["metrics","unrecoverable_core_gap_messages"] then ["core_gap_messages",$v]
  elif $p == ["metrics","lobby_startup_bridge_unrecoverable_events"] then ["bridge_gap_events",$v]
  elif $p == ["metrics","lobby_startup_bridge_unrecoverable_messages"] then ["bridge_gap_messages",$v]
  elif $p == ["health","rooms","lobby","kind"] then
    ["lobby_kind",(if $v=="startup_lobby_capture_protected_backlog_capacity" then $v else "OTHER" end)]
  elif ($p|length)==4 and $p[0]=="health" and $p[1]=="rooms"
       and $p[3]=="status" and $v=="error" then
    ["error_room",(if $p[2]=="lobby" then "lobby" else "other" end)]
  else empty end
"""


def _run(command: list[str], *, timeout: int = 4) -> str:
    # Argument array only, never shell=True; external executables read only.
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=timeout, env=env
    )
    if result.returncode != 0:
        raise ValueError("read_only_command_failed")
    if len(result.stdout) > MAX_STREAM_OUTPUT:
        raise ValueError("command_output_too_large")
    return result.stdout.strip()


def _repo_status() -> tuple[str, bool]:
    head = _run(["git", "-C", str(REPO), "rev-parse", "HEAD"])
    if head != OLD_HEAD:
        raise ValueError("unexpected_production_head")
    branch = _run(["git", "-C", str(REPO), "symbolic-ref", "--short", "HEAD"])
    if branch != "main":
        raise ValueError("unexpected_branch")
    clean = _run(["git", "-C", str(REPO), "status", "--porcelain"])
    if clean:
        raise ValueError("dirty_worktree")
    return head, True


def _unit(name: str) -> dict:
    if name not in UNITS:
        raise ValueError("unit_not_allowlisted")
    unit = f"technocore-safe-agent-{name}.service"
    output = _run(
        ["systemctl", "show", unit, "-p", "MainPID", "-p", "NRestarts",
         "-p", "ActiveState", "--no-pager"],
        timeout=4,
    )
    props = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if set(props) != {"MainPID", "NRestarts", "ActiveState"}:
        raise ValueError("incomplete_unit_snapshot")
    if not re.fullmatch(r"[1-9][0-9]*", props["MainPID"]):
        raise ValueError("invalid_pid")
    if not re.fullmatch(r"0|[1-9][0-9]*", props["NRestarts"]):
        raise ValueError("invalid_n_restarts")
    return {
        "pid": int(props["MainPID"]),
        "n_restarts": int(props["NRestarts"]),
        "active_state": props["ActiveState"] if props["ActiveState"] == "active" else "OTHER",
    }


def _memory_available() -> int:
    for line in Path("/proc/meminfo").read_text("ascii").splitlines():
        match = re.fullmatch(r"MemAvailable:\s+([0-9]+) kB", line)
        if match:
            return int(match.group(1))
    raise ValueError("missing_mem_available")


def _psi(name: str) -> float:
    if name not in ("memory", "io"):
        raise ValueError("bad_psi_name")
    for line in (Path("/proc/pressure") / name).read_text("ascii").splitlines():
        match = re.search(r"^full\s+avg10=([0-9]+(?:\.[0-9]+)?)\b", line)
        if match:
            return float(match.group(1))
    raise ValueError("missing_full_psi")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sample() -> dict:
    return {
        "at": _now(),
        "mem_available_kib": _memory_available(),
        "mem_psi_full_avg10": _psi("memory"),
        "io_psi_full_avg10": _psi("io"),
        "units": {name: _unit(name) for name in UNITS},
    }


def _rich() -> dict:
    state = OBSERVER / "observer-state.json"
    size = state.stat().st_size
    if not 0 < size <= MAX_RICH_BYTES:
        raise ValueError("unsafe_rich_size")
    # Streaming JSON: no full 20MiB Observer state is loaded into this process.
    output = _run(["nice", "-n", "19", "timeout", "25s", "jq", "--stream",
                   "-c", RICH_FILTER, str(state)], timeout=29)
    record: dict = {"error_rooms": [], "lobby_kind": None}
    seen: set[str] = set()
    for line in output.splitlines():
        item = json.loads(line)
        if not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str):
            raise ValueError("malformed_rich_stream")
        key, value = item
        if key == "error_room":
            if value not in ("lobby", "other"):
                raise ValueError("untrusted_error_room")
            if value not in record["error_rooms"]:
                record["error_rooms"].append(value)
        else:
            if key in seen:
                raise ValueError("duplicate_rich_field")
            record[key] = value
            seen.add(key)
    required = {"at", "lobby_cursor", "health", "core_gap_events",
                "core_gap_messages", "bridge_gap_events", "bridge_gap_messages"}
    if not required.issubset(seen):
        raise ValueError("missing_rich_fields")
    record["error_rooms"].sort()
    return record


def _safety() -> dict:
    path = ROOT / "observer-safety.json"
    size = path.stat().st_size
    if not 0 < size <= MAX_SAFETY_BYTES:
        raise ValueError("unsafe_safety_size")
    data = json.loads(path.read_text("utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("invalid_safety_schema")
    return {
        "at": data.get("updated_at"),
        "health": data.get("health"),
        "core_gap_events": data.get("unrecoverable_core_gap_events"),
        "core_gap_messages": data.get("unrecoverable_core_gap_messages"),
    }


def collect() -> dict:
    if socket.gethostname().split(".")[0] != HOST:
        raise ValueError("unexpected_host")
    head, clean = _repo_status()
    began = time.monotonic()
    samples = []
    for i in range(SAMPLES):
        if i:
            time.sleep(max(0.0, began + i * INTERVAL_SECONDS - time.monotonic()))
        samples.append(_sample())
    proof = {
        "schema_version": 1,
        "source_head": head,
        "target_head": TARGET_HEAD,
        "worktree_clean": clean,
        "samples": samples,
        "rich": _rich(),
        "safety": _safety(),
    }
    # If the observational window was interrupted, fail without emitting a
    # possibly convincing-looking partial proof.
    start = datetime.fromisoformat(samples[0]["at"])
    end = datetime.fromisoformat(samples[-1]["at"])
    if (end - start).total_seconds() < 60:
        raise ValueError("short_observation_window")
    return proof


def main() -> int:
    try:
        proof = collect()
        encoded = json.dumps(proof, separators=(",", ":"), ensure_ascii=True)
        if len(encoded) > 65536:
            raise ValueError("oversized_proof")
        print(encoded)
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        # Never output raw command stderr, process environment or untrusted state.
        print(json.dumps({"decision":"NO_GO","restart_authorized":False,
                          "reasons":[type(error).__name__]}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
