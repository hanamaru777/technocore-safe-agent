"""Tiny local-state primitives for isolated runtime processes.

Keep this module dependency-free from Observer/Resident layers. The semantics are
intentionally byte-compatible with the long-standing Observer helpers.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path


def atomic_json_write(
    path: Path,
    value: dict,
    *,
    compact: bool = False,
    mode: int | None = None,
) -> None:
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
            json.dump(
                value,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                **({"separators": (",", ":")} if compact else {"indent": 2}),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
        if mode is not None:
            os.chmod(path, mode)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def parse_time(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None
