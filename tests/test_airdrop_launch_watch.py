from __future__ import annotations

import json
from pathlib import Path

import pytest

from flop_agent import airdrop_launch_watch as watch


ROOT = Path(__file__).resolve().parents[1]


def _source(
    name: str = "testnet",
    *,
    links: list[str] | None = None,
    url: str = "https://flop.finance/testnet/",
    authority: str = "official",
    status: str = "ok",
) -> dict:
    return {
        "name": name,
        "url": url,
        "final_url": url,
        "tier": 2,
        "authority": authority,
        "critical": False,
        "status": status,
        "interest_links": list(links or []),
        "facts": [],
        "deadlines": [],
        "meta": {},
    }


def _snapshot(
    *,
    facts: dict | None = None,
    sources: list[dict] | None = None,
    health: str = "ok",
) -> dict:
    return {
        "schema_version": 1,
        "read_only": True,
        "scanned_at": "2026-10-08T00:00:00+00:00",
        "health": health,
        "snapshot_id": "a" * 64,
        "sources": list(sources or [_source()]),
        "resolved_facts": dict(facts or {}),
        "deadlines": [],
        "summary": {"available_sources": 1, "failed_sources": [], "conflicts": []},
        "warnings": [],
    }


def _fact(value: str, source: str = "testnet", *, conflict: bool = False) -> dict:
    return {
        "value": value,
        "source": source,
        "tier": 2,
        "authority": "official",
        "status": "official_draft",
        "conflict": conflict,
        "variants": [],
    }


def test_planned_draft_snapshot_creates_no_candidate() -> None:
    snapshot = _snapshot(
        facts={
            "testnet_status": _fact("planned"),
            "faucet_status": _fact("planned"),
        }
    )
    assert watch.collect_candidates(snapshot) == []


def test_testnet_live_creates_deterministic_status_candidate() -> None:
    snapshot = _snapshot(facts={"testnet_status": _fact("live")})
    first = watch.collect_candidates(snapshot)
    second = watch.collect_candidates(snapshot)
    assert first == second
    assert len(first) == 1
    assert first[0]["kind"] == "official_status_open"
    assert first[0]["key"] == "testnet_status"
    assert first[0]["value"] == "live"
    assert first[0]["source"] == "testnet"
    assert first[0]["url"] == "https://flop.finance/testnet/"
    assert len(first[0]["fingerprint"]) == 64


def test_faucet_open_creates_status_candidate() -> None:
    rows = watch.collect_candidates(
        _snapshot(facts={"faucet_status": _fact("open")})
    )
    assert [(row["key"], row["value"]) for row in rows] == [
        ("faucet_status", "open")
    ]


def test_strict_flop_labs_link_creates_candidate_and_rejects_lookalikes() -> None:
    good = "https://github.com/flop-labs/flop-core/blob/main/docs/testnet/faucet.md"
    source = _source(
        links=[
            good + "?from=testnet#claim",
            "https://github.com/attacker/flop-core/blob/main/faucet.md",
            "https://github.com.evil.example/flop-labs/testnet",
            "http://github.com/flop-labs/testnet",
            "https://evil@github.com/flop-labs/testnet",
            "https://github.com:444/flop-labs/testnet",
            "https://github.com/flop-labs/testnet/%2e%2e/attacker",
            "https://github.com/flop-labs/testnet/`break",
        ]
    )
    rows = watch.collect_candidates(_snapshot(sources=[source]))
    assert len(rows) == 1
    assert rows[0]["kind"] == "official_launch_link"
    assert rows[0]["url"] == good
    assert rows[0]["sources"] == ["testnet"]


def test_duplicate_launch_link_across_sources_is_one_candidate() -> None:
    target = "https://github.com/flop-labs/flop-core/blob/main/docs/testnet/onboarding.md"
    sources = [
        _source("testnet", links=[target]),
        _source(
            "airdrop",
            links=[target, target + "#agents"],
            url="https://flop.finance/airdrop/",
        ),
    ]
    rows = watch.collect_candidates(_snapshot(sources=sources))
    assert len(rows) == 1
    assert rows[0]["sources"] == ["airdrop", "testnet"]


def test_untrusted_source_cannot_create_status_or_link_candidate() -> None:
    evil = _source(
        "testnet",
        links=["https://github.com/flop-labs/testnet-client"],
        url="https://example.com/testnet/",
    )
    snapshot = _snapshot(
        facts={"testnet_status": _fact("live")},
        sources=[evil],
    )
    assert watch.collect_candidates(snapshot) == []


def test_conflicted_open_fact_is_ignored() -> None:
    snapshot = _snapshot(
        facts={"testnet_status": _fact("live", conflict=True)}
    )
    assert watch.collect_candidates(snapshot) == []


def test_non_ok_radar_fails_closed() -> None:
    with pytest.raises(watch.LaunchWatchError, match="radar_health_not_ok"):
        watch.collect_candidates(_snapshot(health="degraded"))


def test_candidate_report_contains_no_action_candidate_or_raw_page_text() -> None:
    target = "https://github.com/flop-labs/testnet-client"
    report = watch.build_report(
        _snapshot(
            facts={"testnet_status": _fact("live")},
            sources=[_source(links=[target])],
        )
    )
    encoded = json.dumps(report, sort_keys=True)
    assert report["read_only"] is True
    assert report["health"] == "ok"
    assert "action_candidate" not in encoded
    assert "evidence" not in encoded
    assert "raw_text" not in encoded


def test_scheduled_workflow_is_main_only_minimal_and_issue_deduped() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "flop-launch-artifact-watch.yml"
    ).read_text("utf-8")
    assert 'cron: "17,47 * * * *"' in workflow
    assert "uses: actions/checkout@v5" in workflow
    assert "uses: actions/setup-python@v6" in workflow
    assert "uses: actions/github-script@v8" in workflow
    assert workflow.count("cron:") == 1
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "contents: read" in workflow
    assert "issues: write" in workflow
    assert "refs/heads/main" in workflow
    assert "python -m flop_agent.airdrop_launch_watch" in workflow
    assert 'state: "all"' in workflow
    assert "github.rest.issues.create" in workflow
    assert "github.paginate" in workflow
    assert "secrets." not in workflow
    assert "faucet claim" not in workflow.lower()
    assert "technocore" not in workflow.lower()
