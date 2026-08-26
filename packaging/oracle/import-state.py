#!/usr/bin/env python3
"""Validate and install a Resident state export without accepting arbitrary files."""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

ALLOWED = {"observer-state.json", "observer-config.json", "resident-state.json", "resident-config.json", "verified-did.json"}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: import-state.py EXPORT.zip STATE_DIRECTORY")
    archive, target = Path(sys.argv[1]), Path(sys.argv[2])
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        if "manifest.json" not in names or not names <= ALLOWED | {"manifest.json"}:
            raise SystemExit("export contains files outside the Resident allowlist")
        manifest = json.loads(bundle.read("manifest.json"))
        files = manifest.get("files")
        if not isinstance(files, list):
            raise SystemExit("export manifest is invalid")
        for entry in files:
            name = entry.get("name")
            if name not in ALLOWED or name not in names:
                raise SystemExit("export manifest allowlist validation failed")
            data = bundle.read(name)
            if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                raise SystemExit("export manifest hash validation failed")
            json.loads(data.decode("utf-8"))
        target.mkdir(parents=True, exist_ok=True)
        for entry in files:
            (target / entry["name"]).write_bytes(bundle.read(entry["name"]))


if __name__ == "__main__":
    main()
