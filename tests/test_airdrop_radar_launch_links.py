from __future__ import annotations

from datetime import UTC, datetime

from flop_agent import airdrop_adapter_readiness, airdrop_radar


def _source(name: str = "testnet") -> airdrop_radar.SourceSpec:
    return next(source for source in airdrop_radar.SOURCES if source.name == name)


def _snapshot(*, snapshot_id: str, links: list[str]) -> dict:
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": "2026-10-06T12:00:00+00:00",
        "health": "ok",
        "snapshot_id": snapshot_id,
        "source_precedence": [],
        "sources": [
            {
                "name": "testnet",
                "url": "https://flop.finance/testnet/",
                "final_url": "https://flop.finance/testnet/",
                "tier": 2,
                "authority": "official",
                "critical": False,
                "status": "ok",
                "content_sha256": snapshot_id.ljust(64, "0")[:64],
                "meta": {},
                "facts": [],
                "deadlines": [],
                "interest_links": links,
            }
        ],
        "resolved_facts": {},
        "deadlines": [],
        "summary": {"available_sources": 1, "failed_sources": [], "conflicts": []},
        "warnings": [],
    }


def test_official_flop_page_preserves_exact_flop_labs_github_link_without_following_it() -> None:
    source = _source()
    target = "https://github.com/flop-labs/flop-core/blob/main/docs/testnet/faucet.md"
    html = f'<html><body><a href="{target}?from=testnet#claim">Agent onboarding</a></body></html>'
    calls: list[str] = []

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        calls.append(spec.url)
        return airdrop_radar.FetchResult(html, spec.url, 1)

    row = airdrop_radar._source_report(
        source,
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )

    assert row["status"] == "ok"
    assert row["interest_links"] == [target]
    assert calls == ["https://flop.finance/testnet/"]


def test_external_github_discovery_is_strictly_scoped_to_flop_labs_https() -> None:
    html = """
    <html><body>
      <a href="https://github.com/flop-labs/flop-core/blob/main/docs/testnet/onboarding.md">good</a>
      <a href="https://github.com/flop-labs/testnet-client">good2</a>
      <a href="https://github.com/attacker/flop-testnet">wrong owner</a>
      <a href="https://github.com.evil.example/flop-labs/testnet">lookalike</a>
      <a href="http://github.com/flop-labs/testnet">http</a>
      <a href="https://evil@github.com/flop-labs/testnet">userinfo</a>
      <a href="https://github.com:444/flop-labs/testnet">port</a>
      <a href="https://example.com/flop-labs/testnet">external</a>
    </body></html>
    """

    assert airdrop_radar._official_interest_links(html, _source()) == [
        "https://github.com/flop-labs/flop-core/blob/main/docs/testnet/onboarding.md",
        "https://github.com/flop-labs/testnet-client",
    ]


def test_non_flop_html_source_cannot_delegate_github_discovery() -> None:
    source = airdrop_radar.SourceSpec(
        "untrusted",
        "https://example.com/testnet/",
        2,
        "official",
        "html",
        False,
        ("example.com",),
    )
    html = '<a href="https://github.com/flop-labs/testnet-client">link</a>'
    assert airdrop_radar._official_interest_links(html, source) == []


def test_new_official_github_link_generates_review_signal_only() -> None:
    target = "https://github.com/flop-labs/flop-core/blob/main/docs/testnet/faucet.md"
    before = _snapshot(snapshot_id="before", links=[])
    after = _snapshot(snapshot_id="after", links=[target])

    diff = airdrop_radar.compare_snapshots(before, after)
    matching = [event for event in diff["events"] if event["key"] == f"official_link:{target}"]

    assert len(matching) == 1
    event = matching[0]
    assert event["type"] == "OFFICIAL_LINK_DISCOVERED"
    assert event["severity"] == "HIGH"
    assert event["after"] == {"url": target, "source": "testnet"}
    assert "action_candidate" not in event


def test_link_discovery_does_not_make_adapter_implementation_ready() -> None:
    snapshot = _snapshot(snapshot_id="ready-check", links=[])
    snapshot["resolved_facts"] = {
        "testnet_status": {
            "value": "live",
            "status": "official_draft",
            "conflict": False,
            "source": "testnet",
            "tier": 2,
            "authority": "official",
            "variants": [],
        },
        "faucet_status": {
            "value": "open",
            "status": "official_draft",
            "conflict": False,
            "source": "testnet",
            "tier": 2,
            "authority": "official",
            "variants": [],
        },
    }
    report = airdrop_adapter_readiness.evaluate(
        snapshot=snapshot,
        verified_ledger={"valid": True, "count": 0, "records": []},
        now=datetime(2026, 10, 6, 12, 0, tzinfo=UTC),
    )

    assert report["overall"] == airdrop_adapter_readiness.BLOCKED
    assert report["actions"]["faucet"]["state"] == airdrop_adapter_readiness.BLOCKED
    assert "canonical_open_event_missing" in report["actions"]["faucet"]["blockers"]
    assert report["actions"]["faucet"]["candidate"] is None
