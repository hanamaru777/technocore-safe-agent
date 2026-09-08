"""Independent read-only lobby shock absorber for Issue #57.

The main Observer must inspect and score public room messages, which can be CPU-heavy
under burst load.  This helper keeps a second, cheap read-only capture lane in a
separate process and stores recent raw lobby rows in a bounded local SQLite spool.
The main Observer can then recover a live-tail hole from local evidence even after
the server retained ring has already compacted past that range.

Only official Technocore GET endpoints are used.  Captured text is untrusted data;
it is never executed, followed as a URL, signed, or posted.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from . import core, observer

ROOM = "lobby"
DB_NAME = "lobby-capture.sqlite3"
LIVE_LIMIT = 200
CAPTURE_READS_PER_MINUTE = 250
CAPTURE_INTERVAL_SECONDS = 60.0 / CAPTURE_READS_PER_MINUTE
MAX_ROWS = 300_000
PRUNE_EVERY_INSERTS = 5_000
MAX_EXPORT_BYTES = 12 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 5.0


def capture_path() -> Path:
    return observer.observer_dir() / DB_NAME


def _connect(path: Path | None = None) -> sqlite3.Connection:
    target = path or capture_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target), timeout=2.0)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.commit()
    return connection


def _meta_get(connection: sqlite3.Connection, key: str) -> str | None:
    row = connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else None


def _meta_set(connection: sqlite3.Connection, key: str, value: object) -> None:
    connection.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def _observer_cursor() -> int:
    try:
        raw = json.loads(observer.state_path().read_text("utf-8"))
        return int(raw.get("cursors", {}).get(ROOM, 0) or 0)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def initialize_cursor(connection: sqlite3.Connection, observer_cursor: int | None = None) -> int:
    observed = _observer_cursor() if observer_cursor is None else int(observer_cursor)
    stored = _meta_get(connection, "capture_cursor")
    cursor = max(observed, int(stored or 0))
    _meta_set(connection, "capture_cursor", cursor)
    connection.commit()
    return cursor


def _valid_rows(payload: dict | list) -> list[dict]:
    messages = payload.get("messages", payload if isinstance(payload, list) else [])
    if not isinstance(messages, list):
        return []
    return sorted(
        (
            item
            for item in messages
            if isinstance(item, dict)
            and isinstance(item.get("seq"), int)
            and item["seq"] >= 0
            and isinstance(item.get("text"), str)
        ),
        key=lambda item: item["seq"],
    )


def store_rows(connection: sqlite3.Connection, rows: list[dict]) -> int:
    encoded: list[tuple[int, str]] = []
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("seq"), int):
            continue
        if not isinstance(item.get("text"), str):
            continue
        encoded.append(
            (
                item["seq"],
                json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=False),
            )
        )
    if not encoded:
        return 0
    before = connection.total_changes
    connection.executemany(
        "INSERT OR IGNORE INTO messages(seq,payload) VALUES(?,?)",
        encoded,
    )
    connection.commit()
    return connection.total_changes - before


def _advance_contiguous(connection: sqlite3.Connection, cursor: int) -> int:
    current = int(cursor)
    while True:
        rows = connection.execute(
            "SELECT seq FROM messages WHERE seq>? ORDER BY seq LIMIT 5000",
            (current,),
        ).fetchall()
        if not rows:
            break
        expected = current + 1
        advanced = current
        for row in rows:
            seq = int(row[0])
            if seq != expected:
                break
            advanced = seq
            expected += 1
        if advanced == current:
            break
        current = advanced
        if len(rows) < 5000 or int(rows[-1][0]) != current:
            break
    _meta_set(connection, "capture_cursor", current)
    connection.commit()
    return current


def _skip_permanent_capture_hole(connection: sqlite3.Connection, cursor: int) -> int:
    row = connection.execute(
        "SELECT MIN(seq) FROM messages WHERE seq>?",
        (cursor,),
    ).fetchone()
    first = int(row[0]) if row and row[0] is not None else None
    if first is None or first <= cursor + 1:
        return cursor
    _meta_set(
        connection,
        "last_capture_hole",
        json.dumps(
            {"missing_from": cursor + 1, "missing_to": first - 1},
            separators=(",", ":"),
        ),
    )
    _meta_set(connection, "capture_cursor", first - 1)
    connection.commit()
    return first - 1


def _prune(connection: sqlite3.Connection) -> None:
    row = connection.execute("SELECT COUNT(*) FROM messages").fetchone()
    count = int(row[0]) if row else 0
    if count <= MAX_ROWS:
        return
    cutoff = connection.execute(
        "SELECT seq FROM messages ORDER BY seq DESC LIMIT 1 OFFSET ?",
        (MAX_ROWS - 1,),
    ).fetchone()
    if cutoff:
        connection.execute("DELETE FROM messages WHERE seq<?", (int(cutoff[0]),))
        connection.commit()


def range_complete(start: int, end: int, path: Path | None = None) -> bool:
    if end < start:
        return True
    connection = _connect(path)
    try:
        row = connection.execute(
            "SELECT COUNT(*), MIN(seq), MAX(seq) FROM messages WHERE seq BETWEEN ? AND ?",
            (int(start), int(end)),
        ).fetchone()
        expected = end - start + 1
        return bool(
            row
            and int(row[0]) == expected
            and int(row[1]) == start
            and int(row[2]) == end
        )
    finally:
        connection.close()


def read_range(start: int, end: int, path: Path | None = None) -> list[dict]:
    if end < start:
        return []
    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT seq,payload FROM messages WHERE seq BETWEEN ? AND ? ORDER BY seq",
            (int(start), int(end)),
        ).fetchall()
        result: list[dict] = []
        expected = start
        for seq, payload in rows:
            if int(seq) != expected:
                return []
            try:
                item = json.loads(payload)
            except json.JSONDecodeError:
                return []
            if not isinstance(item, dict) or item.get("seq") != expected:
                return []
            result.append(item)
            expected += 1
        return result if expected == end + 1 else []
    finally:
        connection.close()


def contiguous_end(start: int, path: Path | None = None) -> int:
    connection = _connect(path)
    try:
        expected = int(start)
        last = expected - 1
        cursor = connection.execute(
            "SELECT seq FROM messages WHERE seq>=? ORDER BY seq",
            (expected,),
        )
        for row in cursor:
            seq = int(row[0])
            if seq != expected:
                break
            last = seq
            expected += 1
        return last
    finally:
        connection.close()


def status(path: Path | None = None) -> dict:
    connection = _connect(path)
    try:
        count = int(connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0])
        return {
            "capture_cursor": int(_meta_get(connection, "capture_cursor") or 0),
            "rows": count,
            "last_success_at": _meta_get(connection, "last_success_at"),
            "last_error": _meta_get(connection, "last_error"),
            "last_capture_hole": _meta_get(connection, "last_capture_hole"),
        }
    finally:
        connection.close()


class _Pacer:
    def __init__(self) -> None:
        self.next_at = 0.0

    def wait(self, stop) -> bool:
        now = time.monotonic()
        if self.next_at > now and stop.wait(self.next_at - now):
            return False
        now = time.monotonic()
        self.next_at = max(self.next_at, now) + CAPTURE_INTERVAL_SECONDS
        return not stop.is_set()


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(
        READ_TIMEOUT_SECONDS,
        connect=CONNECT_TIMEOUT_SECONDS,
        pool=CONNECT_TIMEOUT_SECONDS,
    )


def _retry_after(response) -> float:
    try:
        return max(0.0, float(response.headers.get("Retry-After", "1")))
    except (TypeError, ValueError):
        return 1.0


def _fetch_live(client: httpx.Client, cursor: int) -> tuple[list[dict], float | None]:
    response = client.get(
        f"{core.BASE_URL}/r/{quote(ROOM, safe='')}",
        params={"format": "json", "since": cursor, "wait": 0, "limit": LIVE_LIMIT},
        timeout=_timeout(),
    )
    if response.status_code == 429:
        return [], _retry_after(response)
    response.raise_for_status()
    return _valid_rows(response.json()), None


def _fetch_export(client: httpx.Client) -> tuple[list[dict], float | None]:
    response = client.get(
        f"{core.BASE_URL}/r/{quote(ROOM, safe='')}/export",
        timeout=_timeout(),
    )
    if response.status_code == 429:
        return [], _retry_after(response)
    response.raise_for_status()
    content = response.content
    if len(content) > MAX_EXPORT_BYTES:
        raise RuntimeError("capture_export_too_large")
    rows: list[dict] = []
    for raw in content.decode("utf-8").splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("seq"), int)
            or not isinstance(item.get("text"), str)
        ):
            raise RuntimeError("capture_invalid_export")
        rows.append(item)
    return sorted(rows, key=lambda item: item["seq"]), None


def capture_process(stop) -> None:
    """Run a bounded GET-only lobby capture lane in a separate process."""
    connection = _connect()
    cursor = initialize_cursor(connection)
    pacer = _Pacer()
    inserted_since_prune = 0
    client = httpx.Client()
    try:
        while not stop.is_set():
            if not pacer.wait(stop):
                break
            try:
                live, retry = _fetch_live(client, cursor)
                if retry is not None:
                    _meta_set(connection, "last_error", "rate_limited")
                    connection.commit()
                    stop.wait(retry)
                    continue
                inserted_since_prune += store_rows(connection, live)
                new_cursor = _advance_contiguous(connection, cursor)
                first_live = live[0]["seq"] if live else None

                if first_live is not None and first_live > cursor + 1 and new_cursor == cursor:
                    if not pacer.wait(stop):
                        break
                    exported, retry = _fetch_export(client)
                    if retry is not None:
                        _meta_set(connection, "last_error", "export_rate_limited")
                        connection.commit()
                        stop.wait(retry)
                        continue
                    inserted_since_prune += store_rows(connection, exported)
                    new_cursor = _advance_contiguous(connection, cursor)
                    if new_cursor == cursor:
                        cursor = _skip_permanent_capture_hole(connection, cursor)
                        new_cursor = _advance_contiguous(connection, cursor)

                cursor = max(cursor, new_cursor)
                _meta_set(connection, "capture_cursor", cursor)
                _meta_set(connection, "last_success_at", observer.now())
                _meta_set(connection, "last_error", "")
                connection.commit()
                if inserted_since_prune >= PRUNE_EVERY_INSERTS:
                    _prune(connection)
                    inserted_since_prune = 0
            except (httpx.HTTPError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
                _meta_set(connection, "last_error", type(error).__name__)
                connection.commit()
                stop.wait(0.5)
    finally:
        client.close()
        connection.close()
