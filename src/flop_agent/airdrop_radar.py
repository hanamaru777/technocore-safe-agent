"""Official Testnet/Airdrop page extension for the read-only FLOP Radar.

The previously audited Radar implementation is preserved byte-for-byte in
``airdrop_radar_core``.  This thin layer adds the two dedicated first-party pages
that became important immediately before the Q4 Testnet launch.  It remains
strictly observational: page text can create evidence and alerts, never a
transaction candidate or permission to sign, register, claim, spend, or submit.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Callable

from . import airdrop_radar_core as _core

# Preserve the complete public/private module surface expected by existing code
# and tests.  Existing function objects continue to execute in the core module;
# only the explicitly patched source registry/extractor below changes behavior.
for _name in dir(_core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_core, _name)

_BASE_EXTRACT_FACTS = _core._extract_facts
_BASE_SCAN_OFFICIAL_SOURCES = _core.scan_official_sources
_BASE_NETWORK_FETCH = _core._network_fetch
_NEW_SOURCE_NAMES = frozenset({"testnet", "airdrop"})

_TESTNET_SOURCE = SourceSpec(
    "testnet",
    "https://flop.finance/testnet/",
    2,
    "official",
    "html",
    False,
    ("flop.finance", "www.flop.finance"),
)
_AIRDROP_SOURCE = SourceSpec(
    "airdrop",
    "https://flop.finance/airdrop/",
    2,
    "official",
    "html",
    False,
    ("flop.finance", "www.flop.finance"),
)

# Keep the long-standing source order stable and add the dedicated pages beside
# the Teaser, before narrower role-specific pages.
_sources = list(_core.SOURCES)
_insert_at = next(
    (index + 1 for index, source in enumerate(_sources) if source.name == "teaser"),
    len(_sources),
)
_sources[_insert_at:_insert_at] = [_TESTNET_SOURCE, _AIRDROP_SOURCE]
SOURCES = tuple(_sources)
_core.SOURCES = SOURCES

HIGH_KEYS = set(_core.HIGH_KEYS) | {
    "genesis_miner_airdrop",
    "genesis_validator_airdrop",
    "genesis_reserve",
    "testnet_onboarding_docs_status",
    "testnet_agent_earning_basis",
    "agent_airdrop_earning_basis",
}
_core.HIGH_KEYS = HIGH_KEYS


def _quarter_window(text: str, pattern: str) -> re.Match[str] | None:
    return re.search(pattern, text, flags=re.IGNORECASE)


def _extract_testnet(text: str, source: SourceSpec) -> list[dict]:
    """Extract only explicit launch/readiness facts from the official Testnet page."""
    facts: list[dict] = []
    lower = text.lower()

    header_status = re.search(r"\bStatus\s*(Draft|Live|Open|Enabled)\b", text, re.IGNORECASE)
    explicit_live = re.search(
        r"\btestnet\s+(?:is\s+)?(?:live|open\s+now|now\s+live)\b",
        text,
        re.IGNORECASE,
    )
    if header_status and header_status.group(1).lower() in {"live", "open", "enabled"}:
        status = header_status.group(1).lower()
        status_evidence = _context(text, *header_status.span())
    elif explicit_live:
        status = "live"
        status_evidence = _context(text, *explicit_live.span())
    elif (
        (header_status and header_status.group(1).lower() == "draft")
        or re.search(r"\bOpens\s*Q[1-4]\s*20\d{2}\b", text, re.IGNORECASE)
        or "the testnet opens when its readiness criteria are met" in lower
    ):
        status = "planned"
        anchor = header_status or re.search(r"\bOpens\s*Q[1-4]\s*20\d{2}\b", text, re.IGNORECASE)
        status_evidence = _context(text, *anchor.span()) if anchor else "official Testnet readiness language"
    else:
        status = "described"
        status_evidence = "official Testnet page"

    if "testnet" in lower:
        facts.append(
            _fact(
                key="testnet_status",
                value=status,
                source=source,
                status="official_draft",
                evidence=status_evidence,
            )
        )

    testnet_window = _quarter_window(
        text,
        r"(?:\bOpens\b|\bTestnet\s+opens\b)\s*(Q[1-4]\s*20\d{2})",
    )
    if testnet_window:
        facts.append(
            _fact(
                key="testnet_window",
                value=re.sub(r"\s+", " ", testnet_window.group(1).upper()),
                source=source,
                status="official_draft",
                evidence=_context(text, *testnet_window.span()),
            )
        )

    mainnet_window = _quarter_window(text, r"\bMainnet\b\s*(Q[1-4]\s*20\d{2})")
    if mainnet_window:
        facts.append(
            _fact(
                key="mainnet_window",
                value=re.sub(r"\s+", " ", mainnet_window.group(1).upper()),
                source=source,
                status="official_draft",
                evidence=_context(text, *mainnet_window.span()),
            )
        )

    duration = re.search(
        r"(?:\bLength\b\s*)?\b(?:About|roughly)\s+(?:90|ninety)\s+days\b",
        text,
        re.IGNORECASE,
    )
    if duration:
        facts.append(
            _fact(
                key="testnet_duration_days",
                value=90,
                unit="days",
                source=source,
                status="official_draft",
                evidence=_context(text, *duration.span()),
            )
        )

    onboarding = re.search(
        r"Onboarding documentation for each role is published when the testnet opens",
        text,
        re.IGNORECASE,
    )
    if onboarding:
        facts.append(
            _fact(
                key="testnet_onboarding_docs_status",
                value="publish_when_open",
                source=source,
                status="official_draft",
                evidence=_context(text, *onboarding.span()),
            )
        )

    minimum_activity = re.search(
        r"minimum-activity floors are published with the testnet rules",
        text,
        re.IGNORECASE,
    )
    if minimum_activity:
        facts.append(
            _fact(
                key="testnet_minimum_activity_rules_status",
                value="publish_with_testnet_rules",
                source=source,
                status="official_draft",
                evidence=_context(text, *minimum_activity.span()),
            )
        )

    faucet = re.search(
        r"(?:\bfaucet\b|test-token faucet|draw from the faucet|access to the test-token faucet)",
        text,
        re.IGNORECASE,
    )
    if faucet:
        faucet_open = re.search(
            r"\bfaucet\s+(?:is\s+)?(?:open|live)\b|\bclaim\s+(?:from\s+)?(?:the\s+)?faucet\s+now\b",
            text,
            re.IGNORECASE,
        )
        facts.append(
            _fact(
                key="faucet_status",
                value="open" if faucet_open else "planned",
                source=source,
                status="official_draft",
                evidence=_context(text, *(faucet_open or faucet).span()),
            )
        )

    agent_basis = re.search(
        r"Agents?\s*[—-]\s*compute purchased in settled sessions",
        text,
        re.IGNORECASE,
    )
    if agent_basis:
        facts.append(
            _fact(
                key="testnet_agent_earning_basis",
                value="compute_purchased_in_settled_sessions",
                source=source,
                status="official_draft",
                evidence=_context(text, *agent_basis.span()),
            )
        )

    return facts


def _allocation_fact(
    text: str,
    source: SourceSpec,
    *,
    label: str,
    key: str,
) -> dict | None:
    match = re.search(
        rf"\b{label}\b\s*(?:\|\s*)?([0-9][0-9,]{{5,}})\b",
        text,
        re.IGNORECASE,
    )
    if not match:
        return None
    return _fact(
        key=key,
        value=_parse_int(match.group(1)),
        unit="FLOP",
        source=source,
        status="official_draft",
        evidence=_context(text, *match.span()),
    )


def _extract_airdrop(text: str, source: SourceSpec) -> list[dict]:
    """Extract current draft allocation/Agent rules without treating them as final protocol law."""
    facts: list[dict] = []

    supply = re.search(
        r"genesis supply of\s+([0-9][0-9,]*)\s+\$?FLOP",
        text,
        re.IGNORECASE,
    )
    if supply:
        facts.append(
            _fact(
                key="genesis_supply",
                value=_parse_int(supply.group(1)),
                unit="FLOP",
                source=source,
                status="official_draft",
                evidence=_context(text, *supply.span()),
            )
        )

    for label, key in (
        ("Miners", "genesis_miner_airdrop"),
        ("Agents", "genesis_agent_airdrop"),
        ("Validators", "genesis_validator_airdrop"),
        ("Ecosystem reserve", "genesis_reserve"),
    ):
        row = _allocation_fact(text, source, label=label, key=key)
        if row:
            facts.append(row)

    no_sale = re.search(r"There is no token sale", text, re.IGNORECASE)
    if no_sale:
        facts.append(
            _fact(
                key="token_sale_exists",
                value=False,
                source=source,
                status="official_draft",
                evidence=_context(text, *no_sale.span()),
            )
        )

    no_investor = re.search(r"no investor allocation", text, re.IGNORECASE)
    if no_investor:
        facts.append(
            _fact(
                key="investor_allocation_exists",
                value=False,
                source=source,
                status="official_draft",
                evidence=_context(text, *no_investor.span()),
            )
        )

    agent_basis = re.search(
        r"Agents?\s*[—-]\s*supply demand\..{0,180}?compute purchased in settled sessions",
        text,
        re.IGNORECASE,
    ) or re.search(
        r"allocation is shared pro rata to compute purchased in settled sessions",
        text,
        re.IGNORECASE,
    )
    if agent_basis:
        facts.append(
            _fact(
                key="agent_airdrop_earning_basis",
                value="compute_purchased_in_settled_sessions",
                source=source,
                status="official_draft",
                evidence=_context(text, *agent_basis.span()),
            )
        )

    ratio = re.search(
        r"Every\s+(\d+)\s+\$?FLOP.{0,180}?unlock[s]?\s+(\d+)\s+\$?FLOP",
        text,
        re.IGNORECASE,
    )
    if ratio:
        facts.append(
            _fact(
                key="spend_to_unlock_ratio",
                value=f"{ratio.group(1)}:{ratio.group(2)}",
                source=source,
                status="official_draft",
                evidence=_context(text, *ratio.span()),
            )
        )

    return facts


def _extract_facts(spec: SourceSpec, body: str) -> tuple[str, list[dict], list[dict], dict]:
    if spec.name not in _NEW_SOURCE_NAMES:
        return _BASE_EXTRACT_FACTS(spec, body)

    text = _plain_text(body)
    facts = _extract_testnet(text, spec) if spec.name == "testnet" else _extract_airdrop(text, spec)
    return text, facts, _extract_deadlines(text, spec), _page_meta(text)


# Existing core source-report code resolves this global at runtime.
_core._extract_facts = _extract_facts


def _network_fetch(spec: SourceSpec) -> FetchResult:
    """Preserve legacy monkeypatch semantics for the public module surface."""
    original_stream_read = _core._stream_read
    try:
        _core._stream_read = globals()["_stream_read"]
        return _BASE_NETWORK_FETCH(spec)
    finally:
        _core._stream_read = original_stream_read


def scan_official_sources(
    *,
    fetcher: Callable[[SourceSpec], FetchResult] | None = None,
    sleeper: Callable[[float], None] = _core.time.sleep,
    now: datetime | None = None,
) -> dict:
    """Scan all official sources while preserving older injected test fetchers.

    Historical unit tests inject a dict-backed fetcher that predates the two new
    optional pages.  A missing key in such a synthetic fetcher is treated as an
    empty page, not an outage.  Real network scans always fetch both pages.
    """
    if fetcher is None:
        return _BASE_SCAN_OFFICIAL_SOURCES(sleeper=sleeper, now=now)

    def compatible_fetch(spec: SourceSpec) -> FetchResult:
        try:
            return fetcher(spec)
        except KeyError:
            if spec.name not in _NEW_SOURCE_NAMES:
                raise
            return FetchResult(body="<html><body></body></html>", final_url=spec.url, latency_ms=0)

    return _BASE_SCAN_OFFICIAL_SOURCES(fetcher=compatible_fetch, sleeper=sleeper, now=now)


# Export the enhanced functions from this public module while the existing core
# implementation keeps using the patched extractor/source registry internally.
globals()["_extract_facts"] = _extract_facts
globals()["_network_fetch"] = _network_fetch
globals()["scan_official_sources"] = scan_official_sources
