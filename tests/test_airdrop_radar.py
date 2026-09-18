from __future__ import annotations

import httpx
import pytest

from flop_agent import airdrop_radar


YELLOW = """
<html><body>
<h1>FLOP Network Yellow Paper</h1>
<p>genesis supply 4,400,000,000 FLOP</p>
<p>Agents up to 1,200,000,000 FLOP.</p>
<p>E.38 — Genesis allocation & airdrop vesting [TBD]. Still open: activity minimums.
balance is never a scoring term.</p>
<script>ignore me</script>
</body></html>
"""

TEASER = """
<html><body>
<p>Testnet Q4 2026. Mainnet Q1 2027.</p>
<p>Agents claim a test-token faucet and spend it on inference, along with various prizes.</p>
<p>Every 3 FLOP spent on inference unlocks 1 airdropped FLOP.</p>
</body></html>
"""

AGENT = """
<html><body>
<p>Agent airdrops are locked to inference spend or stake delegation.</p>
<p>Every 3 FLOP of inference fees unlocks 1 airdropped FLOP.</p>
</body></html>
"""


def _pages() -> dict[str, str]:
    return {
        "https://flop.finance/intro/yellowpaper/": YELLOW,
        "https://flop.finance/teaser/": TEASER,
        "https://flop.finance/intro/agent/": AGENT,
    }


def test_scan_extracts_current_public_signals_without_live_network() -> None:
    pages = _pages()
    report = airdrop_radar.scan_official_sources(
        fetcher=lambda url: pages[url],
        sleeper=lambda _seconds: None,
    )
    assert report["read_only"] is True
    assert report["summary"]["available_sources"] == 3
    observed = report["summary"]["observed"]
    assert observed["genesis_pool_4_4b"] == ["yellowpaper"]
    assert observed["agent_pool_1_2b"] == ["yellowpaper"]
    assert observed["testnet_q4_2026"] == ["teaser"]
    assert observed["mainnet_q1_2027"] == ["teaser"]
    assert observed["agent_faucet"] == ["teaser"]
    assert observed["agent_prizes"] == ["teaser"]
    assert observed["three_to_one_unlock"] == ["teaser", "agent"]
    assert observed["e38_distribution_tbd"] == ["yellowpaper"]
    assert observed["activity_minimums_open"] == ["yellowpaper"]
    assert observed["balance_not_scoring"] == ["yellowpaper"]


def test_single_timeout_retries_instead_of_killing_scan() -> None:
    pages = _pages()
    calls: dict[str, int] = {}

    def fetch(url: str) -> str:
        calls[url] = calls.get(url, 0) + 1
        if url.endswith("/teaser/") and calls[url] == 1:
            raise httpx.ReadTimeout("temporary")
        return pages[url]

    report = airdrop_radar.scan_official_sources(
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )
    teaser = next(row for row in report["sources"] if row["name"] == "teaser")
    assert teaser["status"] == "ok"
    assert teaser["attempts"] == 2


def test_one_failed_source_does_not_abort_other_official_sources() -> None:
    pages = _pages()

    def fetch(url: str) -> str:
        if url.endswith("/intro/agent/"):
            raise httpx.ReadTimeout("down")
        return pages[url]

    report = airdrop_radar.scan_official_sources(
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )
    assert report["summary"]["available_sources"] == 2
    assert report["summary"]["failed_sources"] == 1
    agent = next(row for row in report["sources"] if row["name"] == "agent")
    assert agent["status"] == "error"


def test_all_failed_sources_are_visible_failure() -> None:
    def fetch(_url: str) -> str:
        raise httpx.ReadTimeout("down")

    with pytest.raises(RuntimeError, match="all_official_sources_unavailable"):
        airdrop_radar.scan_official_sources(
            fetcher=fetch,
            sleeper=lambda _seconds: None,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://flop.finance/teaser/",
        "https://evil.example/teaser/",
        "https://flop.finance.evil.example/teaser/",
    ],
)
def test_official_url_allowlist_is_strict(url: str) -> None:
    with pytest.raises(RuntimeError, match="non_official_url"):
        airdrop_radar._validate_official_url(url)
