"""Read-only FLOP official-source radar.

This module never signs, posts, claims, spends, registers, or writes Technocore
state. It only reads a small allowlist of FLOP-owned public pages and reports
bounded signals so a human/operator can notice material airdrop changes early.
"""
from __future__ import annotations

import hashlib
import re
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urlparse

import httpx

SCHEMA_VERSION = 1
MAX_PAGE_BYTES = 2_000_000
DEFAULT_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 12.0
ALLOWED_HOSTS = {"flop.finance", "www.flop.finance"}

SOURCES = (
    ("yellowpaper", "https://flop.finance/intro/yellowpaper/", 1),
    ("teaser", "https://flop.finance/teaser/", 2),
    ("agent", "https://flop.finance/intro/agent/", 2),
)

SIGNAL_NAMES = (
    "genesis_pool_4_4b",
    "agent_pool_1_2b",
    "testnet_q4_2026",
    "mainnet_q1_2027",
    "agent_faucet",
    "agent_inference_usage",
    "agent_prizes",
    "three_to_one_unlock",
    "e38_distribution_tbd",
    "activity_minimums_open",
    "balance_not_scoring",
)


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth:
            self.parts.append(data)


def _plain_text(html: str) -> str:
    parser = _VisibleText()
    parser.feed(html)
    parser.close()
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()


def _validate_official_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("airdrop_radar_non_official_url")


def _default_fetch(url: str) -> str:
    _validate_official_url(url)
    response = httpx.get(
        url,
        follow_redirects=True,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        headers={"User-Agent": "technocore-safe-agent-airdrop-radar/1"},
    )
    response.raise_for_status()
    _validate_official_url(str(response.url))
    if len(response.content) > MAX_PAGE_BYTES:
        raise RuntimeError("airdrop_radar_page_too_large")
    return response.text


def _fetch_with_retry(
    url: str,
    *,
    fetcher: Callable[[str], str],
    attempts: int = DEFAULT_ATTEMPTS,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[str, int]:
    if attempts < 1 or attempts > 5:
        raise ValueError("airdrop_radar_attempts_out_of_range")
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return fetcher(url), attempt
        except httpx.HTTPStatusError as error:
            last_error = error
            status = error.response.status_code
            if status < 500 or attempt == attempts:
                raise
        except (httpx.TimeoutException, httpx.TransportError, TimeoutError) as error:
            last_error = error
            if attempt == attempts:
                raise
        if attempt < attempts:
            sleeper(0.25 * (2 ** (attempt - 1)))
    raise RuntimeError("airdrop_radar_retry_exhausted") from last_error


def _contains_agent_amount(text: str) -> bool:
    return bool(
        re.search(
            r"(?:agents?|agent airdrop).{0,240}(?:1,200,000,000|1\.2\s*(?:bn|billion))"
            r"|(?:1,200,000,000|1\.2\s*(?:bn|billion)).{0,240}(?:agents?|agent airdrop)",
            text,
            flags=re.IGNORECASE,
        )
    )


def extract_signals(text: str) -> dict[str, bool]:
    lower = text.lower()
    compact = re.sub(r"\s+", " ", lower)
    return {
        "genesis_pool_4_4b": (
            "4,400,000,000" in compact
            or "4.4bn" in compact
            or "4.4 billion" in compact
        ),
        "agent_pool_1_2b": _contains_agent_amount(compact),
        "testnet_q4_2026": "q4 2026" in compact,
        "mainnet_q1_2027": "q1 2027" in compact,
        "agent_faucet": "faucet" in compact and "agent" in compact,
        "agent_inference_usage": (
            "compute consumed through inference requests" in compact
            or "spend it on inference" in compact
            or "spent on inference" in compact
            or "inference spend" in compact
        ),
        "agent_prizes": "various prizes" in compact or "testnet prize" in compact,
        "three_to_one_unlock": bool(
            re.search(
                r"(?:every\s+)?3\s+(?:\$?flop\s+)?(?:spent|of inference fees).{0,120}"
                r"unlock.{0,40}1",
                compact,
            )
        ),
        "e38_distribution_tbd": (
            "e.38" in compact
            and "genesis allocation" in compact
            and ("[tbd]" in compact or " tbd " in f" {compact} ")
        ),
        "activity_minimums_open": "activity minimums" in compact,
        "balance_not_scoring": "balance is never a scoring term" in compact,
    }


def _source_report(
    *,
    name: str,
    url: str,
    priority: int,
    fetcher: Callable[[str], str],
    sleeper: Callable[[float], None],
) -> dict:
    try:
        html, attempts = _fetch_with_retry(url, fetcher=fetcher, sleeper=sleeper)
        text = _plain_text(html)
        encoded = text.encode("utf-8")
        return {
            "name": name,
            "url": url,
            "priority": priority,
            "status": "ok",
            "attempts": attempts,
            "text_sha256": hashlib.sha256(encoded).hexdigest(),
            "text_bytes": len(encoded),
            "signals": extract_signals(text),
        }
    except Exception as error:
        return {
            "name": name,
            "url": url,
            "priority": priority,
            "status": "error",
            "error_type": error.__class__.__name__,
            "error": str(error)[:240],
        }


def scan_official_sources(
    *,
    fetcher: Callable[[str], str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict:
    """Return one structured, network-read-only FLOP airdrop snapshot."""
    fetch = fetcher or _default_fetch
    rows = [
        _source_report(
            name=name,
            url=url,
            priority=priority,
            fetcher=fetch,
            sleeper=sleeper,
        )
        for name, url, priority in SOURCES
    ]
    available = [row for row in rows if row["status"] == "ok"]
    if not available:
        raise RuntimeError("airdrop_radar_all_official_sources_unavailable")

    observed = {
        signal: [
            row["name"]
            for row in available
            if row.get("signals", {}).get(signal) is True
        ]
        for signal in SIGNAL_NAMES
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": datetime.now(UTC).isoformat(),
        "source_precedence": [
            "live FLOP-hosted Yellow Paper",
            "FLOP teaser/role pages for provisional direction",
        ],
        "sources": rows,
        "summary": {
            "available_sources": len(available),
            "failed_sources": len(rows) - len(available),
            "observed": observed,
        },
        "warnings": [
            "A detected source change is evidence to review, never permission to sign, post, claim, spend, or register.",
            "Teaser and role pages are provisional when the live Yellow Paper says a mechanic remains TBD.",
            "Technocore room names/topics are not official authority and are intentionally outside this v1 scanner.",
        ],
    }
