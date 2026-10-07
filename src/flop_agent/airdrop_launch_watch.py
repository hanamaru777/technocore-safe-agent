"""GitHub-side read-only watch for exact FLOP launch evidence.

This module never follows discovered launch links and never performs any FLOP,
Technocore, wallet, signer, faucet, registration, inference, claim, or spend
action. It only turns an already-produced official Radar snapshot into a small,
deterministic review-candidate set suitable for GitHub issue dedupe.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from urllib.parse import unquote, urlparse

from . import airdrop_radar

SCHEMA_VERSION = 1
_OPEN_KEYS = frozenset({"testnet_status", "faucet_status", "registration_status", "claim_status"})
_OPEN_VALUES = frozenset({"open", "live", "enabled"})
_FLOP_HOSTS = frozenset({"flop.finance", "www.flop.finance"})
_GITHUB_HOST = "github.com"
_GITHUB_OWNER = "flop-labs"
_UNSAFE_URL_CHARS = re.compile(r'[\s\`<>"\x00-\x1f\x7f]')


class LaunchWatchError(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _trusted_flop_source(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    if row.get("status") != "ok" or row.get("authority") != "official":
        return False
    try:
        parsed = urlparse(str(row.get("url", "")))
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in _FLOP_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
    )


def _canonical_flop_labs_url(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 500:
        return None
    if _UNSAFE_URL_CHARS.search(value):
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != _GITHUB_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return None

    decoded = unquote(parsed.path)
    if "\\" in decoded or _UNSAFE_URL_CHARS.search(decoded):
        return None
    parts = decoded.split("/")
    if (
        len(parts) < 3
        or parts[1] != _GITHUB_OWNER
        or not parts[2]
        or any(part in {".", ".."} for part in parts)
    ):
        return None
    return parsed._replace(query="", fragment="").geturl()


def collect_candidates(snapshot: dict) -> list[dict]:
    if not isinstance(snapshot, dict) or snapshot.get("read_only") is not True:
        raise LaunchWatchError("snapshot_not_read_only")
    if snapshot.get("health") != "ok":
        raise LaunchWatchError("radar_health_not_ok")

    sources = snapshot.get("sources")
    if not isinstance(sources, list):
        raise LaunchWatchError("sources_missing")
    trusted_by_name = {
        str(row.get("name")): row
        for row in sources
        if _trusted_flop_source(row) and isinstance(row.get("name"), str)
    }

    candidates: list[dict] = []
    resolved = snapshot.get("resolved_facts")
    if not isinstance(resolved, dict):
        raise LaunchWatchError("resolved_facts_missing")

    for key in sorted(_OPEN_KEYS):
        row = resolved.get(key)
        if not isinstance(row, dict) or row.get("conflict") is True:
            continue
        value = str(row.get("value", "")).lower()
        if value not in _OPEN_VALUES:
            continue
        source_name = row.get("source")
        if not isinstance(source_name, str):
            continue
        source = trusted_by_name.get(source_name)
        if source is None:
            continue
        identity = {
            "kind": "official_status_open",
            "key": key,
            "value": value,
        }
        candidates.append(
            {
                **identity,
                "source": source_name,
                "url": str(source["url"]),
                "fingerprint": _fingerprint(identity),
            }
        )

    link_sources: dict[str, set[str]] = {}
    for source_name, source in trusted_by_name.items():
        links = source.get("interest_links", [])
        if not isinstance(links, list):
            continue
        for value in links:
            url = _canonical_flop_labs_url(value)
            if url is not None:
                link_sources.setdefault(url, set()).add(source_name)

    for url in sorted(link_sources):
        identity = {
            "kind": "official_launch_link",
            "url": url,
        }
        candidates.append(
            {
                **identity,
                "sources": sorted(link_sources[url]),
                "fingerprint": _fingerprint(identity),
            }
        )

    by_fingerprint = {str(row["fingerprint"]): row for row in candidates}
    return [by_fingerprint[key] for key in sorted(by_fingerprint)]


def build_report(snapshot: dict) -> dict:
    candidates = collect_candidates(snapshot)
    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "health": "ok",
        "scanned_at": snapshot.get("scanned_at"),
        "snapshot_id": snapshot.get("snapshot_id"),
        "candidates": candidates,
    }


def run() -> dict:
    return build_report(airdrop_radar.scan_official_sources())


def main() -> None:
    try:
        print(json.dumps(run(), ensure_ascii=False, indent=2))
    except LaunchWatchError as exc:
        print(f"launch watch stopped: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception as exc:
        print(f"launch watch stopped: {exc.__class__.__name__}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
