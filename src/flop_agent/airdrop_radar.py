"""FLOP airdrop radar: read-only official-source facts, conflicts, and changes.

External behavior is intentionally read-only. This module never signs, posts, spends,
claims, registers, creates Technocore rooms, or mutates protocol state.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

SCHEMA_VERSION = 2
MAX_PAGE_BYTES = 2_000_000
DEFAULT_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 12.0
SEVERITY_ORDER = {"ACTION_NOW": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


@dataclass(frozen=True)
class SourceSpec:
    name: str
    url: str
    tier: int
    authority: str
    kind: str
    critical: bool
    allowed_hosts: tuple[str, ...]


@dataclass(frozen=True)
class FetchResult:
    body: str
    final_url: str
    latency_ms: int


SOURCES = (
    SourceSpec(
        "yellowpaper",
        "https://flop.finance/intro/yellowpaper/",
        1,
        "normative",
        "html",
        True,
        ("flop.finance", "www.flop.finance"),
    ),
    SourceSpec(
        "teaser",
        "https://flop.finance/teaser/",
        2,
        "provisional",
        "html",
        True,
        ("flop.finance", "www.flop.finance"),
    ),
    SourceSpec(
        "agent",
        "https://flop.finance/intro/agent/",
        2,
        "provisional",
        "html",
        False,
        ("flop.finance", "www.flop.finance"),
    ),
    SourceSpec(
        "revenue",
        "https://flop.finance/intro/revenue/",
        2,
        "provisional",
        "html",
        False,
        ("flop.finance", "www.flop.finance"),
    ),
    SourceSpec(
        "home",
        "https://flop.finance/",
        2,
        "official",
        "html",
        False,
        ("flop.finance", "www.flop.finance"),
    ),
    SourceSpec(
        "kol_application",
        "https://flop.finance/apply/kol",
        2,
        "official",
        "html",
        False,
        ("flop.finance", "www.flop.finance", "docs.google.com"),
    ),
    SourceSpec(
        "github_org",
        "https://api.github.com/orgs/flop-labs/repos?per_page=100&sort=pushed",
        3,
        "engineering",
        "github_json",
        False,
        ("api.github.com",),
    ),
)

HIGH_KEYS = {
    "genesis_agent_airdrop",
    "genesis_supply",
    "agent_scoring_basis",
    "agent_scoring_accounting_unit",
    "activity_minimums_status",
    "sublinear_conversion_status",
    "spend_to_unlock_status",
    "spend_to_unlock_ratio",
    "airdrop_vesting_duration_blocks",
    "agent_vesting_status",
    "claim_path_status",
    "claim_status",
    "eligibility_status",
    "testnet_window",
    "testnet_status",
    "mainnet_window",
    "e38_status",
    "e40_status",
    "kol_application_status",
    "kol_compensation_guaranteed",
    "kol_program_terms_status",
}
ACTION_OPEN_KEYS = {"testnet_status", "faucet_status", "claim_status", "registration_status"}
ACTION_OPEN_VALUES = {"open", "live", "enabled"}
INTERESTING_REPO_RE = re.compile(
    r"(?:airdrop|testnet|challenge|yellowpaper|technocore|tclk|flop-core)",
    re.IGNORECASE,
)
EXACT_DEADLINE_RE = re.compile(
    r"(?i)\b(deadline|cutoff|closes?|ends?)\b.{0,100}?"
    r"(20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2}))"
)
DATE_ONLY_DEADLINE_RE = re.compile(
    r"(?i)\b(deadline|cutoff|closes?|ends?)\b.{0,100}?(20\d{2}-\d{2}-\d{2})(?!T)"
)


INTERESTING_SITE_LINK_RE = re.compile(
    r"(?:airdrop|testnet|claim|faucet|challenge|campaign|genesis|agent|kol|creator|ambassador|referral|growth)",
    re.IGNORECASE,
)


class _OfficialLinks(HTMLParser):
    def __init__(self, base_url: str, allowed_hosts: tuple[str, ...]) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.allowed_hosts = allowed_hosts
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = next((value for key, value in attrs if key.lower() == "href"), None)
        if not href:
            return
        absolute = urljoin(self.base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            return
        clean = parsed._replace(query="", fragment="").geturl()
        if INTERESTING_SITE_LINK_RE.search(parsed.path):
            self.links.add(clean)


def _official_interest_links(html: str, source: SourceSpec) -> list[str]:
    if source.kind != "html":
        return []
    parser = _OfficialLinks(source.url, source.allowed_hosts)
    parser.feed(html)
    parser.close()
    return sorted(parser.links)


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


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _deadline_identity(row: dict) -> str:
    """Stable identity independent of wording/evidence hash."""
    basis = {
        "label": row.get("label"),
        "timestamp": row.get("timestamp"),
        "date": row.get("date"),
        "source": row.get("source"),
    }
    return _sha(basis)


def _validate_url(url: str, allowed_hosts: tuple[str, ...]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise RuntimeError("airdrop_radar_non_official_url")


def _network_fetch(spec: SourceSpec) -> FetchResult:
    _validate_url(spec.url, spec.allowed_hosts)
    headers = {"User-Agent": "technocore-safe-agent-airdrop-radar/2"}
    if spec.kind == "github_json":
        headers["Accept"] = "application/vnd.github+json"
    started = time.monotonic()
    with httpx.stream(
        "GET",
        spec.url,
        follow_redirects=True,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        headers=headers,
    ) as response:
        response.raise_for_status()
        _validate_url(str(response.url), spec.allowed_hosts)
        length = response.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_PAGE_BYTES:
            raise RuntimeError("airdrop_radar_page_too_large")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_PAGE_BYTES:
                raise RuntimeError("airdrop_radar_page_too_large")
            chunks.append(chunk)
        encoding = response.encoding or "utf-8"
        body = b"".join(chunks).decode(encoding, errors="replace")
    return FetchResult(
        body=body,
        final_url=str(response.url),
        latency_ms=max(0, int((time.monotonic() - started) * 1000)),
    )


def _fetch_with_retry(
    spec: SourceSpec,
    *,
    fetcher: Callable[[SourceSpec], FetchResult],
    attempts: int = DEFAULT_ATTEMPTS,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[FetchResult, int]:
    if attempts < 1 or attempts > 5:
        raise ValueError("airdrop_radar_attempts_out_of_range")
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            result = fetcher(spec)
            _validate_url(result.final_url, spec.allowed_hosts)
            if len(result.body.encode("utf-8")) > MAX_PAGE_BYTES:
                raise RuntimeError("airdrop_radar_page_too_large")
            return result, attempt
        except httpx.HTTPStatusError as error:
            last_error = error
            status = error.response.status_code
            if status not in {429} and status < 500:
                raise
            if attempt == attempts:
                raise
        except (httpx.TimeoutException, httpx.TransportError, TimeoutError) as error:
            last_error = error
            if attempt == attempts:
                raise
        if attempt < attempts:
            sleeper(0.25 * (2 ** (attempt - 1)))
    raise RuntimeError("airdrop_radar_retry_exhausted") from last_error


def _context(text: str, start: int, end: int, radius: int = 150) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)][:420]


def _fact(
    *,
    key: str,
    value: object,
    source: SourceSpec,
    status: str,
    evidence: str,
    unit: str | None = None,
) -> dict:
    return {
        "key": key,
        "value": value,
        "unit": unit,
        "source": source.name,
        "tier": source.tier,
        "authority": source.authority,
        "status": status,
        "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        "evidence_excerpt": evidence[:420],
    }


def _parse_int(raw: str) -> int:
    return int(raw.replace(",", "").replace("_", ""))


def _param_fact(text: str, source: SourceSpec, param: str, status: str = "normative") -> dict | None:
    match = re.search(
        rf"\b{re.escape(param)}\b\s*(?:=|[:|])?\s*([0-9][0-9,_]*)\s+FLOP\b",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return _fact(
        key=param,
        value=_parse_int(match.group(1)),
        unit="FLOP",
        source=source,
        status=status,
        evidence=_context(text, *match.span()),
    )


def _status_fact(text: str, source: SourceSpec, item: str, key: str) -> dict | None:
    match = re.search(
        rf"\b{re.escape(item)}\b.{0,140}?\[(TBD|RATIFY|PARTIAL|PLANNED)\]",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return _fact(
        key=key,
        value=match.group(1).upper(),
        source=source,
        status="normative",
        evidence=_context(text, *match.span()),
    )


def _page_meta(text: str) -> dict:
    version = re.search(r"\bVersion\s*([0-9]+(?:\.[0-9]+){0,3}(?:\s*\(draft\))?)", text, re.IGNORECASE)
    updated = re.search(r"\bUpdated\s*(20\d{2}-\d{2}-\d{2})", text, re.IGNORECASE)
    return {
        "version": version.group(1).strip() if version else None,
        "updated": updated.group(1) if updated else None,
    }


def _extract_deadlines(text: str, source: SourceSpec) -> list[dict]:
    rows: list[dict] = []
    for match in EXACT_DEADLINE_RE.finditer(text):
        raw = match.group(2)
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                continue
            timestamp = parsed.astimezone(UTC).isoformat()
        except ValueError:
            continue
        rows.append(
            {
                "label": match.group(1).lower(),
                "timestamp": timestamp,
                "exact": True,
                "source": source.name,
                "tier": source.tier,
                "evidence_sha256": hashlib.sha256(_context(text, *match.span()).encode()).hexdigest(),
            }
        )
    for match in DATE_ONLY_DEADLINE_RE.finditer(text):
        rows.append(
            {
                "label": match.group(1).lower(),
                "date": match.group(2),
                "exact": False,
                "source": source.name,
                "tier": source.tier,
                "evidence_sha256": hashlib.sha256(_context(text, *match.span()).encode()).hexdigest(),
            }
        )
    deduped: dict[str, dict] = {}
    for row in rows:
        deduped[_deadline_identity(row)] = row
    return list(deduped.values())


def _extract_yellowpaper(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    for param in (
        "genesis_supply",
        "genesis_agent_airdrop",
        "genesis_reserve",
    ):
        row = _param_fact(text, source, param)
        if row:
            facts.append(row)

    vest = re.search(r"\bairdrop_vesting_duration_blocks\b\s*\|\s*([0-9][0-9,_]*)\s+blocks", text, re.IGNORECASE)
    if vest:
        facts.append(
            _fact(
                key="airdrop_vesting_duration_blocks",
                value=_parse_int(vest.group(1)),
                unit="blocks",
                source=source,
                status="normative",
                evidence=_context(text, *vest.span()),
            )
        )

    for item, key in (("E.38", "e38_status"), ("E.40", "e40_status")):
        row = _status_fact(text, source, item, key)
        if row:
            facts.append(row)

    if re.search(r"claim path (?:is|are) unspecified", text, re.IGNORECASE):
        match = re.search(r"claim path (?:is|are) unspecified", text, re.IGNORECASE)
        assert match
        facts.append(
            _fact(
                key="claim_path_status",
                value="unspecified",
                source=source,
                status="TBD",
                evidence=_context(text, *match.span()),
            )
        )
    if "whether spend-to-unlock ships" in text.lower():
        start = text.lower().index("whether spend-to-unlock ships")
        facts.append(
            _fact(
                key="spend_to_unlock_status",
                value="open",
                source=source,
                status="TBD",
                evidence=_context(text, start, start + len("whether spend-to-unlock ships")),
            )
        )
    if "activity minimums" in text.lower():
        start = text.lower().index("activity minimums")
        facts.append(
            _fact(
                key="activity_minimums_status",
                value="open",
                source=source,
                status="TBD",
                evidence=_context(text, start, start + len("activity minimums")),
            )
        )
    if "sublinear form on the conversion score" in text.lower():
        start = text.lower().index("sublinear form on the conversion score")
        facts.append(
            _fact(
                key="sublinear_conversion_status",
                value="open",
                source=source,
                status="TBD",
                evidence=_context(text, start, start + len("sublinear form on the conversion score")),
            )
        )
    verified = re.search(r"agents:\s*verified inference spend,\s*unconfirmed", text, re.IGNORECASE)
    settled = re.search(r"pro-rata by settled inference spend for the agent leg", text, re.IGNORECASE)
    scoring = verified or settled
    if scoring:
        facts.append(
            _fact(
                key="agent_scoring_basis",
                value="verified_inference_spend" if verified else "settled_inference_spend",
                source=source,
                status="unconfirmed",
                evidence=_context(text, *scoring.span()),
            )
        )
    if "balance is never a scoring term" in text.lower():
        start = text.lower().index("balance is never a scoring term")
        facts.append(
            _fact(
                key="balance_is_scoring_term",
                value=False,
                source=source,
                status="normative_placeholder",
                evidence=_context(text, start, start + len("balance is never a scoring term")),
            )
        )
    return facts


def _extract_teaser(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    supply = re.search(r"genesis airdrop of\s+([0-9][0-9,]*)\s+\$?FLOP", text, re.IGNORECASE)
    if supply:
        facts.append(
            _fact(
                key="genesis_supply",
                value=_parse_int(supply.group(1)),
                unit="FLOP",
                source=source,
                status="provisional",
                evidence=_context(text, *supply.span()),
            )
        )
    agent = re.search(r"Agents?\s*\|\s*up to\s+([0-9][0-9,]*)", text, re.IGNORECASE)
    if not agent:
        agent = re.search(r"Agents?\s+up to\s+([0-9][0-9,]*)", text, re.IGNORECASE)
    if agent:
        facts.append(
            _fact(
                key="genesis_agent_airdrop",
                value=_parse_int(agent.group(1)),
                unit="FLOP",
                source=source,
                status="provisional",
                evidence=_context(text, *agent.span()),
            )
        )
    for label, key in (("Testnet", "testnet_window"), ("Mainnet", "mainnet_window")):
        match = re.search(rf"{label}\s*(Q[1-4]\s*20\d{{2}})", text, re.IGNORECASE)
        if match:
            facts.append(
                _fact(
                    key=key,
                    value=re.sub(r"\s+", " ", match.group(1).upper()),
                    source=source,
                    status="provisional",
                    evidence=_context(text, *match.span()),
                )
            )
    duration = re.search(r"runs for roughly (?:ninety|90) days", text, re.IGNORECASE)
    if duration:
        facts.append(
            _fact(
                key="testnet_duration_days",
                value=90,
                unit="days",
                source=source,
                status="provisional",
                evidence=_context(text, *duration.span()),
            )
        )
    lower = text.lower()
    if "testnet is live" in lower or "testnet now live" in lower:
        status = "live"
    elif "testnet is planned" in lower or "testnet is planned for" in lower:
        status = "planned"
    else:
        status = "described"
    if "testnet" in lower:
        facts.append(
            _fact(
                key="testnet_status",
                value=status,
                source=source,
                status="provisional",
                evidence="official teaser testnet status language",
            )
        )
    faucet = re.search(r"claim a test-token faucet", text, re.IGNORECASE)
    if faucet:
        faucet_value = "open" if status == "live" and re.search(r"faucet.{0,50}(?:open|live|claim now)", text, re.IGNORECASE) else "planned"
        facts.append(
            _fact(
                key="faucet_status",
                value=faucet_value,
                source=source,
                status="provisional",
                evidence=_context(text, *faucet.span()),
            )
        )
    score = re.search(r"airdrop is based largely on what they spend on inference.{0,120}various prizes", text, re.IGNORECASE)
    if score:
        facts.append(
            _fact(
                key="agent_scoring_basis",
                value="inference_spend_plus_prizes",
                source=source,
                status="provisional",
                evidence=_context(text, *score.span()),
            )
        )
    ratio = re.search(r"every\s+(\d+)\s+\$?FLOP.{0,100}?unlock[s]?\s+(\d+)\s+airdropped", text, re.IGNORECASE)
    if ratio:
        facts.append(
            _fact(
                key="spend_to_unlock_ratio",
                value=f"{ratio.group(1)}:{ratio.group(2)}",
                source=source,
                status="provisional",
                evidence=_context(text, *ratio.span()),
            )
        )
    return facts


def _extract_agent(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    ratio = re.search(r"every\s+(\d+)\s+FLOP.{0,100}?unlock[s]?\s+(\d+)\s+airdropped", text, re.IGNORECASE)
    if ratio:
        facts.append(
            _fact(
                key="spend_to_unlock_ratio",
                value=f"{ratio.group(1)}:{ratio.group(2)}",
                source=source,
                status="provisional",
                evidence=_context(text, *ratio.span()),
            )
        )
    basis = re.search(r"airdrops are locked to inference spend or stake delegation", text, re.IGNORECASE)
    if basis:
        facts.append(
            _fact(
                key="agent_unlock_basis",
                value="inference_spend_or_stake_delegation",
                source=source,
                status="provisional",
                evidence=_context(text, *basis.span()),
            )
        )
    return facts


def _extract_revenue(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    match = re.search(r"(?:whole\s+)?1\.2\s*(?:bn|billion)\s+agent pool", text, re.IGNORECASE)
    if match:
        facts.append(
            _fact(
                key="genesis_agent_airdrop",
                value=1_200_000_000,
                unit="FLOP",
                source=source,
                status="provisional",
                evidence=_context(text, *match.span()),
            )
        )
    return facts


def _extract_home(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    match = re.search(r"Follow\s+@([A-Za-z0-9_]+)\s+for airdrop eligibility", text, re.IGNORECASE)
    if match:
        facts.append(
            _fact(
                key="official_airdrop_x_handle",
                value="@" + match.group(1),
                source=source,
                status="official",
                evidence=_context(text, *match.span()),
            )
        )
    return facts


def _extract_kol_application(text: str, source: SourceSpec) -> list[dict]:
    facts: list[dict] = []
    title = re.search(r"FLOP KOL Survey", text, re.IGNORECASE)
    contributing = re.search(r"Interested in contributing to the FLOP ecosystem", text, re.IGNORECASE)
    if title and contributing:
        facts.append(
            _fact(
                key="kol_application_status",
                value="form_available",
                source=source,
                status="official",
                evidence=_context(text, *title.span()),
            )
        )
    disclaimer = re.search(
        r"does not entitle me to any compensation, payment, token, token allocation, reward, benefit",
        text,
        re.IGNORECASE,
    )
    if disclaimer:
        facts.append(
            _fact(
                key="kol_compensation_guaranteed",
                value=False,
                source=source,
                status="official",
                evidence=_context(text, *disclaimer.span()),
            )
        )
    future = re.search(
        r"potential participation in future programs.{0,180}?separate eligibility requirements and terms",
        text,
        re.IGNORECASE,
    )
    if future:
        facts.append(
            _fact(
                key="kol_program_terms_status",
                value="future_programs_separate_terms",
                source=source,
                status="official",
                evidence=_context(text, *future.span()),
            )
        )
    return facts


def _extract_github_org(body: str, source: SourceSpec) -> list[dict]:
    payload = json.loads(body)
    if not isinstance(payload, list):
        raise RuntimeError("airdrop_radar_github_org_shape_invalid")
    interest = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if not isinstance(name, str) or not INTERESTING_REPO_RE.search(name):
            continue
        interest.append(
            {
                "name": name,
                "pushed_at": row.get("pushed_at") if isinstance(row.get("pushed_at"), str) else None,
                "default_branch": row.get("default_branch") if isinstance(row.get("default_branch"), str) else None,
                "archived": bool(row.get("archived")),
            }
        )
    interest.sort(key=lambda row: row["name"])
    names = [row["name"] for row in interest]
    return [
        _fact(
            key="github_interest_repo_names",
            value=names,
            source=source,
            status="engineering",
            evidence=_canonical(names),
        ),
        _fact(
            key="github_interest_repo_activity",
            value=interest,
            source=source,
            status="engineering",
            evidence=_canonical(interest),
        ),
    ]


def _extract_facts(spec: SourceSpec, body: str) -> tuple[str, list[dict], list[dict], dict]:
    if spec.kind == "github_json":
        facts = _extract_github_org(body, spec)
        normalized = _canonical(json.loads(body))
        return normalized, facts, [], {}
    text = _plain_text(body)
    if spec.name == "yellowpaper":
        facts = _extract_yellowpaper(text, spec)
    elif spec.name == "teaser":
        facts = _extract_teaser(text, spec)
    elif spec.name == "agent":
        facts = _extract_agent(text, spec)
    elif spec.name == "revenue":
        facts = _extract_revenue(text, spec)
    elif spec.name == "home":
        facts = _extract_home(text, spec)
    elif spec.name == "kol_application":
        facts = _extract_kol_application(text, spec)
    else:
        facts = []
    return text, facts, _extract_deadlines(text, spec), _page_meta(text)


def _source_report(
    spec: SourceSpec,
    *,
    fetcher: Callable[[SourceSpec], FetchResult],
    sleeper: Callable[[float], None],
) -> dict:
    try:
        result, attempts = _fetch_with_retry(spec, fetcher=fetcher, sleeper=sleeper)
        normalized, facts, deadlines, meta = _extract_facts(spec, result.body)
        return {
            "name": spec.name,
            "url": spec.url,
            "final_url": result.final_url,
            "tier": spec.tier,
            "authority": spec.authority,
            "critical": spec.critical,
            "status": "ok",
            "attempts": attempts,
            "latency_ms": result.latency_ms,
            "content_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            "content_bytes": len(normalized.encode("utf-8")),
            "meta": meta,
            "facts": facts,
            "deadlines": deadlines,
            "interest_links": _official_interest_links(result.body, spec),
        }
    except Exception as error:
        return {
            "name": spec.name,
            "url": spec.url,
            "tier": spec.tier,
            "authority": spec.authority,
            "critical": spec.critical,
            "status": "error",
            "error_type": error.__class__.__name__,
            "error": str(error)[:240],
        }


def _resolve_facts(facts: list[dict]) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = {}
    for fact in facts:
        grouped.setdefault(str(fact["key"]), []).append(fact)
    resolved: dict[str, dict] = {}
    for key, variants in grouped.items():
        ordered = sorted(variants, key=lambda row: (int(row["tier"]), str(row["source"])))
        values = {_canonical(row["value"]) for row in variants}
        winner = ordered[0]
        resolved[key] = {
            "value": winner["value"],
            "unit": winner.get("unit"),
            "source": winner["source"],
            "tier": winner["tier"],
            "authority": winner["authority"],
            "status": winner["status"],
            "conflict": len(values) > 1,
            "variants": ordered,
        }
    return resolved


def _snapshot_id(source_rows: list[dict], resolved: dict[str, dict], deadlines: list[dict]) -> str:
    basis = {
        "sources": {
            row["name"]: row.get("content_sha256")
            for row in source_rows
            if row.get("status") == "ok"
        },
        "facts": {
            key: {
                "value": row["value"],
                "source": row["source"],
                "status": row["status"],
                "conflict": row["conflict"],
            }
            for key, row in sorted(resolved.items())
        },
        "deadlines": sorted(deadlines, key=_canonical),
    }
    return _sha(basis)


def scan_official_sources(
    *,
    fetcher: Callable[[SourceSpec], FetchResult] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    now: datetime | None = None,
) -> dict:
    """Read official sources once and return a structured airdrop snapshot."""
    fetch = fetcher or _network_fetch
    if fetcher is None:
        rows_by_name: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_source_report, spec, fetcher=fetch, sleeper=sleeper): spec.name
                for spec in SOURCES
            }
            for future in as_completed(futures):
                rows_by_name[futures[future]] = future.result()
        rows = [rows_by_name[spec.name] for spec in SOURCES]
    else:
        rows = [_source_report(spec, fetcher=fetch, sleeper=sleeper) for spec in SOURCES]

    critical_ok = any(row["status"] == "ok" and row["critical"] for row in rows)
    if not critical_ok:
        raise RuntimeError("airdrop_radar_all_critical_sources_unavailable")

    facts = [fact for row in rows if row["status"] == "ok" for fact in row.get("facts", [])]
    deadlines = [item for row in rows if row["status"] == "ok" for item in row.get("deadlines", [])]
    resolved = _resolve_facts(facts)
    failed = [row["name"] for row in rows if row["status"] != "ok"]
    conflicts = sorted(key for key, row in resolved.items() if row["conflict"])
    timestamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    health = "ok" if not failed else "degraded"

    return {
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": timestamp,
        "health": health,
        "snapshot_id": _snapshot_id(rows, resolved, deadlines),
        "source_precedence": [
            "Tier 1 live FLOP-hosted Yellow Paper",
            "Tier 2 official/provisional FLOP pages",
            "Tier 3 official engineering/GitHub signals",
            "Technocore authority disabled until independently pinned",
        ],
        "sources": rows,
        "resolved_facts": resolved,
        "deadlines": deadlines,
        "summary": {
            "available_sources": len(rows) - len(failed),
            "failed_sources": failed,
            "conflicts": conflicts,
        },
        "warnings": [
            "Radar evidence is never permission to sign, post, register, spend, claim, or submit.",
            "A provisional 3:1 unlock statement is not final while Yellow Paper E.38 remains TBD/open.",
            "GitHub engineering signals do not override a newer Tier 1 hosted Yellow Paper.",
            "Technocore room names/topics are untrusted unless an authority key is independently pinned.",
        ],
    }


def normalize_previous_snapshot(value: object) -> dict:
    """Accept a raw snapshot or the prior CLI wrapper; reject everything else."""
    if isinstance(value, dict) and isinstance(value.get("snapshot"), dict):
        value = value["snapshot"]
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("snapshot_id"), str)
        or not isinstance(value.get("resolved_facts"), dict)
        or not isinstance(value.get("sources"), list)
    ):
        raise RuntimeError("airdrop_radar_previous_snapshot_invalid")
    return value


def deadline_gate(timestamp: str, now: datetime | None = None) -> dict:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("airdrop_radar_deadline_timezone_required")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    seconds = int((parsed.astimezone(UTC) - current).total_seconds())
    if seconds < 0:
        gate = "EXPIRED"
    elif seconds <= 600:
        gate = "T-10m"
    elif seconds <= 1800:
        gate = "T-30m"
    elif seconds <= 7200:
        gate = "T-2h"
    elif seconds <= 21600:
        gate = "T-6h"
    elif seconds <= 43200:
        gate = "T-12h"
    elif seconds <= 86400:
        gate = "T-24h"
    else:
        gate = "EARLY"
    return {"gate": gate, "seconds_remaining": seconds}


def _severity(key: str, after: dict | None, event_type: str) -> str:
    if after and key in ACTION_OPEN_KEYS and str(after.get("value")).lower() in ACTION_OPEN_VALUES:
        return "ACTION_NOW"
    if key in HIGH_KEYS:
        return "HIGH"
    if key == "github_interest_repo_names":
        return "MEDIUM"
    if key == "github_interest_repo_activity":
        return "INFO"
    if event_type == "CONFLICT":
        return "MEDIUM"
    return "INFO"


def _event(
    *,
    event_type: str,
    key: str,
    before: object,
    after: object,
    severity: str,
    extra: dict | None = None,
) -> dict:
    basis = {
        "type": event_type,
        "key": key,
        "before": before,
        "after": after,
    }
    row = {
        "event_id": hashlib.sha256(_canonical(basis).encode()).hexdigest()[:24],
        "type": event_type,
        "key": key,
        "severity": severity,
        "before": before,
        "after": after,
    }
    if extra:
        row.update(extra)
    return row


def compare_snapshots(
    previous: dict | None,
    current: dict,
    *,
    now: datetime | None = None,
) -> dict:
    """Return deterministic material changes; outages never masquerade as rule changes."""
    if previous is None:
        return {
            "baseline": True,
            "previous_snapshot_id": None,
            "current_snapshot_id": current["snapshot_id"],
            "events": [],
        }

    events: list[dict] = []
    before_facts = previous.get("resolved_facts", {})
    after_facts = current.get("resolved_facts", {})
    changed_sources: set[str] = set()

    before_source_rows = {
        str(row.get("name")): row
        for row in previous.get("sources", [])
        if isinstance(row, dict) and row.get("name")
    }
    after_source_rows = {
        str(row.get("name")): row
        for row in current.get("sources", [])
        if isinstance(row, dict) and row.get("name")
    }
    common_source_names = set(before_source_rows) & set(after_source_rows)
    stable_ok_sources = {
        name
        for name in common_source_names
        if before_source_rows[name].get("status") == "ok"
        and after_source_rows[name].get("status") == "ok"
    }
    newly_failed = {
        name
        for name in common_source_names
        if before_source_rows[name].get("status") == "ok"
        and after_source_rows[name].get("status") != "ok"
    }
    recovered = {
        name
        for name in common_source_names
        if before_source_rows[name].get("status") != "ok"
        and after_source_rows[name].get("status") == "ok"
    }

    for name in sorted(newly_failed):
        after_row = after_source_rows[name]
        severity = "HIGH" if after_row.get("critical") else "MEDIUM"
        events.append(
            _event(
                event_type="SOURCE_UNAVAILABLE",
                key=f"source:{name}:availability",
                before="ok",
                after=after_row.get("error_type") or "error",
                severity=severity,
            )
        )

    for name in sorted(recovered):
        after_row = after_source_rows[name]
        severity = "MEDIUM" if after_row.get("critical") else "INFO"
        events.append(
            _event(
                event_type="SOURCE_RECOVERED",
                key=f"source:{name}:availability",
                before="error",
                after="ok",
                severity=severity,
            )
        )

    def variant_sources(row: dict | None) -> set[str]:
        if not row:
            return set()
        return {
            str(item.get("source"))
            for item in row.get("variants", [])
            if isinstance(item, dict) and item.get("source")
        }

    # Compare the resolved fact only when the apparent change is not caused by
    # a source entering/leaving availability. This prevents a Tier-1 outage
    # from looking like a protocol change merely because Tier-2 becomes the
    # temporary fallback winner.
    for key in sorted(set(before_facts) | set(after_facts)):
        before = before_facts.get(key)
        after = after_facts.get(key)
        before_sources = variant_sources(before)
        after_sources = variant_sources(after)
        transition_loss = bool((before_sources - after_sources) & newly_failed)
        transition_gain = bool((after_sources - before_sources) & recovered)

        if before is None:
            if transition_gain:
                continue
            event_type = "NEW"
        elif after is None:
            if transition_loss:
                continue
            event_type = "REMOVED"
        elif (
            _canonical(before.get("value")) != _canonical(after.get("value"))
            or before.get("status") != after.get("status")
        ):
            if transition_loss or transition_gain:
                continue
            event_type = "CHANGED"
        elif bool(before.get("conflict")) != bool(after.get("conflict")):
            if transition_loss or transition_gain:
                continue
            event_type = "CONFLICT" if after.get("conflict") else "RESOLVED"
        else:
            continue

        if before:
            changed_sources.update(variant_sources(before) & stable_ok_sources)
        if after:
            changed_sources.update(variant_sources(after) & stable_ok_sources)
        events.append(
            _event(
                event_type=event_type,
                key=key,
                before=before,
                after=after,
                severity=_severity(key, after, event_type),
            )
        )

    # Compare per-source variants only across sources that were available in
    # both snapshots. A failed/recovered source is represented by its explicit
    # availability event above, never by a fake semantic change.
    for key in sorted(set(before_facts) & set(after_facts)):
        before = before_facts[key]
        after = after_facts[key]
        if any(row["key"] == key for row in events):
            continue

        def stable_variants(row: dict) -> list[dict]:
            return sorted(
                [
                    {
                        "source": item.get("source"),
                        "tier": item.get("tier"),
                        "status": item.get("status"),
                        "value": item.get("value"),
                    }
                    for item in row.get("variants", [])
                    if item.get("source") in stable_ok_sources
                ],
                key=lambda item: (str(item.get("source")), int(item.get("tier") or 999)),
            )

        before_variants = stable_variants(before)
        after_variants = stable_variants(after)
        if _canonical(before_variants) == _canonical(after_variants):
            continue
        changed_sources.update(str(row.get("source")) for row in before_variants)
        changed_sources.update(str(row.get("source")) for row in after_variants)
        events.append(
            _event(
                event_type="SOURCE_VARIANT_CHANGED",
                key=key,
                before=before_variants,
                after=after_variants,
                severity="HIGH" if key in HIGH_KEYS else "MEDIUM",
            )
        )

    previous_deadlines = {
        _deadline_identity(row): row for row in previous.get("deadlines", [])
    }
    current_deadlines = {
        _deadline_identity(row): row for row in current.get("deadlines", [])
    }
    for deadline_id, row in current_deadlines.items():
        if deadline_id in previous_deadlines:
            continue
        # A deadline reappearing only because its source recovered is not a new
        # opportunity. The source-recovery event already tells the operator to
        # refresh the snapshot.
        if row.get("source") in recovered:
            continue
        extra = {"deadline": row}
        severity = "HIGH"
        if row.get("exact") and isinstance(row.get("timestamp"), str):
            gate = deadline_gate(row["timestamp"], now=now)
            extra["deadline_gate"] = gate
            if 0 <= gate["seconds_remaining"] <= 86400:
                severity = "ACTION_NOW"
        events.append(
            _event(
                event_type="NEW_DEADLINE",
                key=f"deadline:{row.get('label', 'unknown')}",
                before=None,
                after=row,
                severity=severity,
                extra=extra,
            )
        )

    # Discover new high-signal pages linked from already trusted FLOP pages.
    # Link appearance is a review signal only; it never means the action is open.
    for name in sorted(stable_ok_sources):
        before_links = set(before_source_rows[name].get("interest_links", []))
        after_links = set(after_source_rows[name].get("interest_links", []))
        for url in sorted(after_links - before_links):
            changed_sources.add(name)
            events.append(
                _event(
                    event_type="OFFICIAL_LINK_DISCOVERED",
                    key=f"official_link:{url}",
                    before=None,
                    after={"url": url, "source": name},
                    severity="HIGH",
                )
            )

    before_ok_sources = {
        name: row
        for name, row in before_source_rows.items()
        if row.get("status") == "ok"
    }
    after_ok_sources = {
        name: row
        for name, row in after_source_rows.items()
        if row.get("status") == "ok"
    }
    for name in sorted(stable_ok_sources):
        if (
            before_ok_sources[name].get("content_sha256")
            == after_ok_sources[name].get("content_sha256")
        ):
            continue
        if name in changed_sources:
            continue
        events.append(
            _event(
                event_type="CONTENT_CHANGED",
                key=f"source:{name}",
                before=before_ok_sources[name].get("content_sha256"),
                after=after_ok_sources[name].get("content_sha256"),
                severity="INFO",
            )
        )

    events.sort(
        key=lambda row: (SEVERITY_ORDER[row["severity"]], row["key"], row["event_id"])
    )
    return {
        "baseline": False,
        "previous_snapshot_id": previous.get("snapshot_id"),
        "current_snapshot_id": current["snapshot_id"],
        "events": events,
        "counts": {
            severity: sum(1 for row in events if row["severity"] == severity)
            for severity in SEVERITY_ORDER
        },
    }

