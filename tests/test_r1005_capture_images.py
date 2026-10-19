"""R1005 real SQLite image fixtures; no Oracle source or sensitive data."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "packaging/archive/verify-capture-backup-images.py"


def load():
    spec = importlib.util.spec_from_file_location("r1005", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def images(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    for name in ("lobby-capture.sqlite3", "lobby-capture-service.sqlite3"):
        path = root / name
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE messages (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO messages(seq,payload) VALUES (?,?)",
                       (23, '{"fake":"secret"}'))
            db.execute("INSERT INTO messages(seq,payload) VALUES (?,?)",
                       (27, '{"fake":"value"}'))
            db.commit()
        path.chmod(0o600)
    return root


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_two_images_readonly_and_message_counts(images):
    m = load()
    fd = m.opened_dir(images)
    try:
        for name in m.EXPECTED:
            result = m.verify_image(fd, name, sha(images / name))
            assert result["messages"] == 2
            assert result["bytes"] > 100
    finally:
        os.close(fd)


def test_wrong_hash_fails(images):
    m = load()
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop, match="HASH_PIN_MISMATCH"):
            m.verify_image(fd, m.EXPECTED[0], "0" * 64)
    finally:
        os.close(fd)


def test_truncation_fails(images):
    m = load()
    name = m.EXPECTED[0]
    path = images / name
    digest = sha(path)
    with open(path, "r+b") as stream:
        stream.truncate(128)
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop):
            m.verify_image(fd, name, digest)
    finally:
        os.close(fd)


def test_hardlink_and_symlink_fail(images):
    m = load()
    name = m.EXPECTED[0]
    path = images / name
    alias = images / "alias"
    os.link(path, alias)
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop, match="DATABASE_CUSTODY"):
            m.verify_image(fd, name, sha(path))
    finally:
        os.close(fd)
    alias.unlink()
    path.unlink()
    path.symlink_to(images / m.EXPECTED[1])
    fd = m.opened_dir(images)
    try:
        with pytest.raises(OSError):
            m.verify_image(fd, name, sha(images / m.EXPECTED[1]))
    finally:
        os.close(fd)


def test_sidecar_even_empty_is_refused(images):
    m = load()
    name = m.EXPECTED[0]
    (images / (name + "-wal")).touch()
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop, match="SIDECAR"):
            m.verify_image(fd, name, sha(images / name))
    finally:
        os.close(fd)


def test_missing_table_rejected_with_matching_hash(images):
    m = load()
    name = m.EXPECTED[0]
    path = images / name
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE meta")
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop, match="SCHEMA"):
            m.verify_image(fd, name, sha(path))
    finally:
        os.close(fd)


def test_page_corruption_rejected_with_matching_hash(images):
    m = load()
    name = m.EXPECTED[0]
    path = images / name
    with open(path, "r+b") as stream:
        stream.seek(8192)
        stream.write(bytes(range(200)))
    fd = m.opened_dir(images)
    try:
        with pytest.raises((m.Stop, sqlite3.Error)):
            m.verify_image(fd, name, sha(path))
    finally:
        os.close(fd)


def test_group_readable_file_rejected(images):
    m = load()
    name = m.EXPECTED[0]
    path = images / name
    path.chmod(0o640)
    fd = m.opened_dir(images)
    try:
        with pytest.raises(m.Stop, match="CUSTODY"):
            m.verify_image(fd, name, sha(path))
    finally:
        os.close(fd)


def test_world_readable_directory_rejected(images):
    m = load()
    images.chmod(0o755)
    with pytest.raises(m.Stop, match="ARCHIVE_DIR_CUSTODY"):
        m.opened_dir(images)


def test_live_host_and_root_guard():
    m = load()
    if os.geteuid() == 0:
        with pytest.raises(m.Stop, match="OFFHOST_NONROOT"):
            m.live_host_refusal()


def test_no_content_value_returned(images):
    m = load()
    fd = m.opened_dir(images)
    try:
        summary = m.verify_image(fd, m.EXPECTED[0], sha(images / m.EXPECTED[0]))
        assert set(summary) == {"bytes", "messages", "sha256"}
        assert "fake" not in str(summary)
    finally:
        os.close(fd)


def test_syntax():
    compile(SOURCE.read_text(), str(SOURCE), "exec")
