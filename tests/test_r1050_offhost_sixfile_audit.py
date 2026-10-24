"""R1050 six-file forensic offhost tests, entirely synthetic temporary SQLite."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/archive/r1050_offhost_sixfile_audit.py"


def load():
    spec = importlib.util.spec_from_file_location("r1050", SOURCE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def bundle(tmp_path):
    m = load()
    directory = tmp_path / "offhost-private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    for name in m.SQLITE:
        path = directory / name
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO messages VALUES(?,?)", (1, '{"private":"never-output"}'))
            db.commit()
        path.chmod(0o600)
    for name in m.LEDGER:
        path = directory / name
        path.write_text('{"private":"never-output"}', encoding="utf8")
        path.chmod(0o600)
    return directory


def pins_for(bundle):
    return {p.name: sha(p) for p in bundle.iterdir()}


def test_positive_exact_six_returns_only_sizes_and_requires_no_epoch(bundle):
    m = load()
    result = m.audit_offhost(bundle, pins_for(bundle))
    assert set(result) == m.EXPECTED
    assert all(isinstance(v, int) and v > 0 for v in result.values())
    assert "private" not in str(result)
    assert sum(result.values()) > 200


def test_offhost_contract_retirement_is_always_strict_no_go():
    source = SOURCE.read_text(encoding="utf8")
    assert "FLOP_R1050_OCI_RETIREMENT=STRICT_NO_GO" in source
    assert "FLOP_R1050_COMMON_WRITER_EPOCH=NOT_PROVEN" in source
    assert "FLOP_R1050_PIN_MAP_SOURCE_AUTHENTICITY=NOT_PROVEN" in source
    assert "FLOP_R1050_EXTERNAL_SIGNER_POST_AND_NONCE=NOT_PROVEN" in source
    assert "FLOP_R1050_ALL_WRITERS_FENCED=NO" in source
    assert "FLOP_R1050_PRIVATE_LEDGER_SCHEMA=NOT_VERIFIED" in source
    assert "FLOP_R1050_NO_EXPLICIT_FILE_WRITES=YES" in source
    assert "FLOP_R1050_ARCHIVE_ATIME_UNCHANGED=NOT_PROVEN" in source
    assert "systemctl start" not in source
    assert "core.post_signed" not in source


def test_pin_map_requires_exact_six_and_duplicate_key_rejected(bundle):
    m = load()
    pins = pins_for(bundle)
    payload = {"schema_version": 1, "pins": pins}
    assert m.pin_map(json.dumps(payload).encode()) == pins
    with pytest.raises(m.Stop, match="SIX_NAMES"):
        m.pin_map(json.dumps({"schema_version": 1, "pins": {"x": "0"*64}}).encode())
    with pytest.raises(m.Stop, match="DUPLICATE_JSON_KEY"):
        m.pin_map(b'{"schema_version":1,"schema_version":1,"pins":{}}')
    with pytest.raises(m.Stop, match="PIN_MAP_HASH"):
        m.pin_map(json.dumps({"schema_version": 1,
                              "pins": {**pins, m.SQLITE[0]: "not-a-hash"}}).encode())
    with pytest.raises(m.Stop, match="PIN_MAP_SCHEMA"):
        m.pin_map(json.dumps({"schema_version": True, "pins": pins}).encode())


def test_private_pin_map_permissions_and_symlink_refused(tmp_path, bundle):
    m = load()
    p = tmp_path / "external-pins.json"
    p.write_text(json.dumps({"schema_version": 1, "pins": pins_for(bundle)}))
    p.chmod(0o600)
    assert m.read_private_pin_map(p) == pins_for(bundle)
    p.chmod(0o644)
    with pytest.raises(m.Stop, match="PIN_MAP_CUSTODY_STOP"):
        m.read_private_pin_map(p)
    p.chmod(0o600)
    link = tmp_path / "pins-link.json"
    link.symlink_to(p)
    with pytest.raises(OSError):
        m.read_private_pin_map(link)
    # A real leaf behind a symlinked parent is still untrusted: leaf-only
    # O_NOFOLLOW is insufficient unless every parent was pinned by dir-fd.
    alias = tmp_path / "pin-dir-symlink"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        m.read_private_pin_map(alias / p.name)


def test_wrong_ledger_pin_rejected_with_no_content_logged(bundle):
    m = load()
    pins = pins_for(bundle)
    pins[m.LEDGER[0]] = "0" * 64
    with pytest.raises(m.Stop, match="LEDGER_SHA256_STOP") as error:
        m.audit_offhost(bundle, pins)
    assert "never-output" not in str(error.value)


def test_group_or_world_readable_ledger_denied(bundle):
    m = load()
    path = bundle / m.LEDGER[1]
    path.chmod(0o640)
    with pytest.raises(m.Stop, match="CUSTODY"):
        m.audit_offhost(bundle, pins_for(bundle))


def test_extra_file_or_sqlite_sidecar_refused(bundle):
    m = load()
    pins = pins_for(bundle)
    extra = bundle / "unexpected-private.tar"
    extra.write_bytes(b"private")
    with pytest.raises(m.Stop, match="ARCHIVE_EXACT_SIX_FILES_STOP"):
        m.audit_offhost(bundle, pins)
    extra.unlink()
    sidecar = bundle / (m.SQLITE[0] + "-wal")
    sidecar.write_bytes(b"")
    with pytest.raises(m.Stop, match="ARCHIVE_EXACT_SIX_FILES_STOP"):
        m.audit_offhost(bundle, pins)


def test_symlink_or_hardlink_ledger_refused(bundle):
    m = load()
    a = bundle / m.LEDGER[0]
    pins = pins_for(bundle)
    sibling = a.with_name("outside-alias")
    os.link(a, sibling)
    # Extra sibling is independently a STOP before file ownership checks.
    with pytest.raises(m.Stop, match="ARCHIVE_EXACT_SIX_FILES_STOP"):
        m.audit_offhost(bundle, pins)
    sibling.unlink()
    a.unlink()
    a.symlink_to(bundle / m.LEDGER[1])
    with pytest.raises(OSError):
        m.audit_offhost(bundle, pins)


def test_missing_ledger_never_accepted(bundle):
    m = load()
    pins = pins_for(bundle)
    (bundle / m.LEDGER[-1]).unlink()
    with pytest.raises(m.Stop, match="ARCHIVE_EXACT_SIX_FILES_STOP"):
        m.audit_offhost(bundle, pins)


def test_untrusted_pins_can_match_tampered_bytes_so_provenance_is_never_claimed(bundle):
    m = load()
    path = bundle / m.LEDGER[1]
    path.write_bytes(b'{"tampered":"untrusted but hash-pinned"}')
    pins = pins_for(bundle)
    assert m.audit_offhost(bundle, pins)[m.LEDGER[1]] == len(path.read_bytes())
    assert "PIN_MAP_SOURCE_AUTHENTICITY=NOT_PROVEN" in SOURCE.read_text()
    # Both matching manifest and filesystem may be wrong about true original.
    assert "COMMON_WRITER_EPOCH=NOT_PROVEN" in SOURCE.read_text()


def test_no_live_host_and_no_root_guards_can_be_bypassed_by_cli(monkeypatch):
    m = load()
    if os.geteuid() == 0:
        with pytest.raises(m.R1005.Stop, match="OFFHOST_NONROOT"):
            m.R1005.live_host_refusal()
    monkeypatch.setattr(m.R1005.os, "geteuid", lambda: 10001)
    for live in ("/opt/flop-shadow", "/opt/tradebot-k137-private",
                 "/opt/technocore-safe-agent"):
        with monkeypatch.context() as patch:
            patch.setattr(m.R1005.Path, "exists", lambda self: str(self) == live)
            with pytest.raises(m.R1005.Stop, match="LIVE_HOST_FORBIDDEN"):
                m.R1005.live_host_refusal()


def test_script_syntax():
    compile(SOURCE.read_text(encoding="utf8"), str(SOURCE), "exec")
