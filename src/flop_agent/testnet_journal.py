"""R1064: inert, Linux-only, durable reservation journal for future testnet Agent.

A successful reservation means "UNKNOWN_POST; never retry this intent".
It does NOT send, sign, register, spend, verify a receipt, or approve a request.
Original OCI / production paths must NEVER be provided as journal directories.
Caller creates a NEW separate 0700 empty directory before using this library.
No entrypoint and no live testnet integration.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from . import testnet_budget as budget

MAX_RECORD_BYTES = 2048
PREFIX = "intent-"
SUFFIX = ".json"


class Stop(Exception):
    """No path or underlying exception content may appear in messages."""


def _need(ok, code):
    if not ok:
        raise Stop(code)


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        _need(name not in result, "JOURNAL_DUPLICATE_JSON_KEY_STOP")
        result[name] = value
    return result


def _directory(path):
    _need(os.name == "posix" and type(path) is Path and path.is_absolute()
          and ".." not in path.parts, "JOURNAL_PLATFORM_OR_PATH_STOP")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
        s = os.fstat(fd)
        _need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o700
              and s.st_uid == os.geteuid(), "JOURNAL_DIRECTORY_CUSTODY_STOP")
        return fd
    except OSError:
        raise Stop("JOURNAL_DIRECTORY_IO_STOP") from None


def _lock(fd, exclusive):
    import fcntl
    try:
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
    except OSError:
        raise Stop("JOURNAL_LOCKED_STOP") from None


def _load(fd):
    try:
        names = os.listdir(fd)
        _need(len(names) <= budget.MAX_ITEMS, "JOURNAL_FULL_STOP")
        _need(all(name.startswith(PREFIX) and name.endswith(SUFFIX) and
                  8 <= len(name[len(PREFIX):-len(SUFFIX)]) <= 64 and
                  budget.ID.fullmatch(name[len(PREFIX):-len(SUFFIX)])
                  for name in names), "JOURNAL_UNEXPECTED_ENTRY_STOP")
        items = []
        for name in sorted(names):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                first = os.fstat(child)
                _need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1
                      and first.st_uid == os.geteuid() and
                      stat.S_IMODE(first.st_mode) == 0o600 and
                      2 <= first.st_size <= MAX_RECORD_BYTES,
                      "JOURNAL_FILE_CUSTODY_STOP")
                raw = os.read(child, MAX_RECORD_BYTES + 1)
                last = os.fstat(child)
                _need(len(raw) == first.st_size and
                      (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns,
                       first.st_ctime_ns) ==
                      (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns,
                       last.st_ctime_ns), "JOURNAL_CHANGED_OR_PARTIAL_STOP")
                row = json.loads(raw.decode("utf-8", "strict"),
                                 object_pairs_hook=_pairs)
                _need(row["intent_id"] == name[len(PREFIX):-len(SUFFIX)],
                      "JOURNAL_FILENAME_MISMATCH_STOP")
                items.append(row)
            finally:
                os.close(child)
        ledger = {"schema_version": 1, "items": items}
        budget.validate_ledger(ledger)
        _need(all(x["status"] == "UNKNOWN_POST" and
                  x["unverified_receipt_sha256"] is None for x in items),
              "JOURNAL_UNEXPECTED_STATE_STOP")
        return ledger
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, budget.Stop):
        raise Stop("JOURNAL_INVALID_OR_IO_STOP") from None


def snapshot(path: Path):
    """Return validated in-process reservation ledger. No remote evidence."""
    fd = _directory(path)
    try:
        _lock(fd, False)
        return _load(fd)
    finally:
        os.close(fd)


def reserve_unknown(path: Path, policy: dict, job: dict):
    """Permanently claim intent BEFORE any future transport attempt.

    A crash at ANY point is terminal: an existing incomplete file causes the
    next invocation to fail, never silently resend. Atomic global caps rely on
    the exclusive nonblocking directory flock. Do not remove/quarantine files
    to retry. No adapter/transport is present here.
    """
    fd = _directory(path)
    try:
        _lock(fd, True)
        ledger = _load(fd)
        try:
            new = budget.prepare(ledger, policy, job)
            committed = budget.transition(new, job["intent_id"], "MARK_ATTEMPTED")
        except (budget.Stop, KeyError, ValueError, TypeError):
            raise Stop("JOURNAL_BUDGET_OR_INTENT_STOP") from None
        row = committed["items"][-1]
        data = json.dumps(row, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii")
        _need(len(data) <= MAX_RECORD_BYTES, "JOURNAL_RECORD_BOUNDS_STOP")
        name = PREFIX + row["intent_id"] + SUFFIX
        try:
            leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                cursor = 0
                while cursor < len(data):
                    count = os.write(leaf, data[cursor:])
                    _need(count > 0, "JOURNAL_WRITE_STOP")
                    cursor += count
                os.fsync(leaf)
            finally:
                os.close(leaf)
            os.fsync(fd)
        except FileExistsError:
            raise Stop("JOURNAL_DUPLICATE_INTENT_STOP") from None
        except OSError:
            raise Stop("JOURNAL_WRITE_OR_SYNC_STOP") from None
        return {
            "schema_version": 1,
            "durable_pre_send_reservation": "UNKNOWN_POST",
            "prior_existing_entries": len(ledger["items"]),
            "original_did_signing": "NOT_PERFORMED",
            "official_faucet_or_inference_send": "NO",
            "official_receipt_or_score": "NOT_PROVEN",
            "allow_retry_without_external_reconciliation": "NO",
            "production_or_oci_mutation": "NO",
        }
    finally:
        os.close(fd)
