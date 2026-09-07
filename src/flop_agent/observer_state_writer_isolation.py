"""Keep full Observer state persistence off the hot network event loop.

The Observer state is intentionally rich and can be many megabytes at the 5,000
Agent bound.  The base ``StateWriter.flush()`` serializes, writes, fsyncs and
periodically sweeps that whole state synchronously on the same asyncio thread that
must keep lobby/events reads moving.

This overlay preserves the single in-memory writer.  It performs only a bounded,
non-yielding serialization step on the event-loop thread to obtain a consistent
snapshot, then moves filesystem write/fsync work to a worker thread.  New mutations
that arrive while I/O is in flight are tracked by a generation counter and remain
dirty for the next flush.  Expensive whole-state compaction runs only when an
actual configured bound is exceeded; per-message retention is already bounded at
mutation time by Observer.

No network, signing, shell, URL following, or Technocore write is added here.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile

from . import observer

_INSTALLED = False
_BASE_MARK_DIRTY = observer.StateWriter.mark_dirty
_BASE_RUN = observer.StateWriter.run


def mark_dirty(writer) -> None:
    writer.dirty = True
    writer._dirty_generation = int(getattr(writer, "_dirty_generation", 0)) + 1


def _atomic_text_write(path, encoded: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _persist_serialized(state_text: str, heartbeat_text: str) -> None:
    _atomic_text_write(observer.state_path(), state_text)
    _atomic_text_write(observer.heartbeat_path(), heartbeat_text)


def _serialize_snapshot(writer) -> tuple[int, str, str]:
    """Capture one consistent snapshot without yielding to mutating tasks."""
    config = writer.config or observer.load_config()
    over_bound = (
        len(writer.state.get("agents", {})) > config["max_agents"]
        or len(writer.state.get("rooms", {})) > config["max_rooms"]
        or len(writer.state.get("discovered_rooms", {})) > config["max_discovered_rooms"]
        or len(writer.state.get("returning_dids", [])) > 1000
    )
    if over_bound:
        observer.compact_state(
            writer.state,
            config["memory_retention"],
            max_agents=config["max_agents"],
            max_rooms=config["max_rooms"],
            max_discovered_rooms=config["max_discovered_rooms"],
            evict=bool(writer.state.get("compaction_acknowledged")),
        )

    generation = int(getattr(writer, "_dirty_generation", 0))
    writer.state["updated_at"] = observer.now()
    metrics = writer.state.get("metrics", {})
    heartbeat = {
        "schema_version": 1,
        "updated_at": writer.state["updated_at"],
        "status": writer.state.get("health", {}).get("current", "degraded"),
        "agent_count": len(writer.state.get("agents", {})),
        "metrics": {
            "unique_dids_discovered": int(metrics.get("unique_dids_discovered", 0)),
            "returning_did_encounters": int(metrics.get("returning_did_encounters", 0)),
            "message_gaps": int(metrics.get("message_gaps", 0)),
        },
    }
    # State files are data stores, not canonical signed artifacts.  Avoid recursive
    # key sorting so serialization time stays bounded as the Agent map grows.
    state_text = json.dumps(
        writer.state,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ) + "\n"
    heartbeat_text = json.dumps(
        heartbeat,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ) + "\n"
    return generation, state_text, heartbeat_text


async def flush_async(writer) -> None:
    if not writer.dirty:
        return
    generation, state_text, heartbeat_text = _serialize_snapshot(writer)
    await asyncio.to_thread(_persist_serialized, state_text, heartbeat_text)
    writer.write_count += 1
    if int(getattr(writer, "_dirty_generation", 0)) == generation:
        writer.dirty = False


async def run(writer, stop: asyncio.Event) -> None:
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=writer.interval_seconds)
            except TimeoutError:
                pass
            await flush_async(writer)
        await flush_async(writer)
    except BaseException:
        stop.set()
        raise


def install() -> None:
    """Install generation-safe asynchronous persistence exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return
    observer.StateWriter.mark_dirty = mark_dirty
    observer.StateWriter.run = run
    _INSTALLED = True
