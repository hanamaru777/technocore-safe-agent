#!/usr/bin/env python3
"""Validate and atomically install only the documented Resident public-state export."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ALLOWED = {"verified-did.json", "observer/observer-state.json", "observer/observer-config.json", "observer/resident-state.json", "observer/resident-config.json"}


def reject(message: str) -> None: raise SystemExit(message)


def valid_json(name: str, data: bytes) -> None:
    try: value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): reject(f"invalid JSON: {name}")
    if not isinstance(value, dict): reject(f"invalid JSON object: {name}")
    if name != "verified-did.json" and not isinstance(value.get("schema_version"), int): reject(f"missing schema version: {name}")
    if name == "verified-did.json" and not isinstance(value.get("did"), str): reject("invalid verified DID")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".import-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); os.chmod(path, 0o640)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main() -> None:
    if len(sys.argv) != 3: reject("usage: import-state.py EXPORT.zip STATE_DIRECTORY")
    archive, target = Path(sys.argv[1]), Path(sys.argv[2])
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist(); names = [info.filename for info in infos]
        if len(names) != len(set(names)): reject("duplicate archive entries are not allowed")
        if any(name.startswith("/") or ".." in Path(name).parts or "\\" in name for name in names): reject("unsafe archive path")
        if "manifest.json" not in names: reject("manifest is missing")
        try: manifest = json.loads(bundle.read("manifest.json"))
        except (UnicodeDecodeError, json.JSONDecodeError): reject("manifest is invalid")
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, list): reject("manifest files are invalid")
        manifest_names = [item.get("name") for item in files if isinstance(item, dict)]
        if len(manifest_names) != len(files) or len(manifest_names) != len(set(manifest_names)): reject("manifest has duplicate or invalid names")
        if set(manifest_names) != set(names) - {"manifest.json"}: reject("manifest and archive entries differ")
        if not set(manifest_names) <= ALLOWED: reject("unsupported or legacy flat export layout")
        payloads = {}
        for item in files:
            name = item["name"]; data = bundle.read(name)
            if hashlib.sha256(data).hexdigest() != item.get("sha256"): reject(f"hash mismatch: {name}")
            valid_json(name, data); payloads[name] = data
    backup = target.with_name(f"{target.name}.backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
    if target.exists(): shutil.copytree(target, backup)
    try:
        for name, data in payloads.items(): atomic_write(target / name, data)
        os.chmod(target, 0o750)
        (target / "observer").mkdir(parents=True, exist_ok=True); os.chmod(target / "observer", 0o750)
    except Exception:
        if backup.exists():
            shutil.rmtree(target, ignore_errors=True); shutil.move(str(backup), str(target))
        raise


if __name__ == "__main__": main()
