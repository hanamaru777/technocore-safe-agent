from __future__ import annotations

import copy
import inspect
import json
from datetime import UTC, datetime

import httpx
import pytest

from flop_agent import airdrop_radar


YELLOW = """
<html><body>
<div>Version0.5.0 (draft) StatusImplementation spec — iterating Updated2026-09-05</div>
<p>genesis_supply = 4,400,000,000 FLOP</p>
<p>genesis_agent_airdrop = 1,200,000,000 FLOP</p>
<p>genesis_reserve = 800,000,000 FLOP</p>
<p>airdrop_vesting_duration_blocks | 7_776_000 blocks</p>
<p>E.38 — Genesis allocation & airdrop vesting [TBD]. The claim path is unspecified.
Still open: cap levels and the sublinear form on the conversion score, activity minimums,
whether spend-to-unlock ships. balance is never a scoring term.</p>
<p>E.40 — Agent & staker leg distribution [TBD]. Placeholder:
pro-rata by settled inference spend for the agent leg.</p>
<script>genesis_agent_airdrop = 9,999,999,999 FLOP</script>
<style>.fake { content: "testnet is live"; }</style>
</body></html>
"""

TEASER = """
<html><body>
<div>Version0.1 (draft) Updated2026-08-26 TestnetQ4 2026 MainnetQ1 2027</div>
<p>Flop Testnet is planned for Q4 2026 and runs for roughly ninety days.</p>
<p>The genesis airdrop of 4,400,000,000 FLOP is allocated as follows.</p>
<p>Agents | up to 1,200,000,000 | Compute consumed through inference requests</p>
<p>Agents — claim a test-token faucet and spend it on inference.
Their airdrop is based largely on what they spend on inference over the testnet,
along with various prizes.</p>
<p>Every 3 FLOP spent on inference unlocks 1 airdropped FLOP.</p>
</body></html>
"""

AGENT = """
<html><body>
<p>Agent airdrops are locked to inference spend or stake delegation.</p>
<p>Every 3 FLOP of inference fees unlocks 1 airdropped FLOP.</p>
</body></html>
"""

REVENUE = """
<html><body>
<p>The whole 1.2bn agent pool is spendable only on inference.</p>
</body></html>
"""

HOME = """
<html><body>
<p>Follow @flop_labs for airdrop eligibility</p>
</body></html>
"""

GITHUB = json.dumps(
    [
        {
            "name": "yellowpaper",
            "pushed_at": "2026-09-18T00:00:00Z",
            "default_branch": "main",
            "archived": False,
        },
        {
            "name": "technocore-chat",
            "pushed_at": "2026-09-18T01:00:00Z",
            "default_branch": "main",
            "archived": False,
        },
        {
            "name": "technocore-sonnet-challenge",
            "pushed_at": "2026-09-11T00:00:00Z",
            "default_branch": "main",
            "archived": False,
        },
        {
            "name": "unrelated-repo",
            "pushed_at": "2026-09-18T02:00:00Z",
            "default_branch": "main",
            "archived": False,
        },
    ]
)


def pages() -> dict[str, str]:
    return {
        "yellowpaper": YELLOW,
        "teaser": TEASER,
        "agent": AGENT,
        "revenue": REVENUE,
        "home": HOME,
        "github_org": GITHUB,
    }


def fetch_from(mapping: dict[str, str]):
    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        return airdrop_radar.FetchResult(
            body=mapping[spec.name],
            final_url=spec.url,
            latency_ms=7,
        )
    return fetch


def snapshot() -> dict:
    return airdrop_radar.scan_official_sources(
        fetcher=fetch_from(pages()),
        sleeper=lambda _seconds: None,
        now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )


def test_current_fact_model_preserves_authority_and_conflicts() -> None:
    report = snapshot()
    assert report["read_only"] is True
    assert report["health"] == "ok"
    assert report["resolved_facts"]["genesis_supply"]["value"] == 4_400_000_000
    assert report["resolved_facts"]["genesis_agent_airdrop"]["value"] == 1_200_000_000
    assert report["resolved_facts"]["genesis_agent_airdrop"]["source"] == "yellowpaper"
    assert report["resolved_facts"]["genesis_agent_airdrop"]["conflict"] is False

    scoring = report["resolved_facts"]["agent_scoring_basis"]
    assert scoring["value"] == "settled_inference_spend"
    assert scoring["source"] == "yellowpaper"
    assert scoring["status"] == "unconfirmed"
    assert scoring["conflict"] is True
    assert "agent_scoring_basis" in report["summary"]["conflicts"]

    assert report["resolved_facts"]["e38_status"]["value"] == "TBD"
    assert report["resolved_facts"]["e40_status"]["value"] == "TBD"
    assert report["resolved_facts"]["spend_to_unlock_status"]["value"] == "open"
    assert report["resolved_facts"]["spend_to_unlock_ratio"]["value"] == "3:1"
    assert report["resolved_facts"]["activity_minimums_status"]["value"] == "open"
    assert report["resolved_facts"]["balance_is_scoring_term"]["value"] is False
    assert report["resolved_facts"]["testnet_status"]["value"] == "planned"
    assert report["resolved_facts"]["faucet_status"]["value"] == "planned"
    assert report["resolved_facts"]["testnet_window"]["value"] == "Q4 2026"
    assert report["resolved_facts"]["mainnet_window"]["value"] == "Q1 2027"
    assert report["resolved_facts"]["official_airdrop_x_handle"]["value"] == "@flop_labs"


def test_hidden_script_and_style_text_never_becomes_fact() -> None:
    text = airdrop_radar._plain_text(
        "<p>safe</p><script>testnet is live</script><style>secret</style>"
    )
    assert text == "safe"
    report = snapshot()
    assert report["resolved_facts"]["genesis_agent_airdrop"]["value"] != 9_999_999_999


def test_generic_numeric_change_is_extracted_not_reduced_to_boolean() -> None:
    changed = pages()
    changed["yellowpaper"] = changed["yellowpaper"].replace(
        "genesis_agent_airdrop = 1,200,000,000 FLOP",
        "genesis_agent_airdrop = 1,350,000,000 FLOP",
    )
    report = airdrop_radar.scan_official_sources(
        fetcher=fetch_from(changed),
        sleeper=lambda _seconds: None,
    )
    fact = report["resolved_facts"]["genesis_agent_airdrop"]
    assert fact["value"] == 1_350_000_000
    assert fact["conflict"] is True


def test_single_timeout_retries_instead_of_killing_scan() -> None:
    mapping = pages()
    calls: dict[str, int] = {}

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        calls[spec.name] = calls.get(spec.name, 0) + 1
        if spec.name == "teaser" and calls[spec.name] == 1:
            raise httpx.ReadTimeout("temporary")
        return airdrop_radar.FetchResult(mapping[spec.name], spec.url, 5)

    report = airdrop_radar.scan_official_sources(
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )
    teaser = next(row for row in report["sources"] if row["name"] == "teaser")
    assert teaser["status"] == "ok"
    assert teaser["attempts"] == 2


def test_one_source_down_is_degraded_but_not_fatal() -> None:
    mapping = pages()

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        if spec.name == "yellowpaper":
            raise httpx.ReadTimeout("down")
        return airdrop_radar.FetchResult(mapping[spec.name], spec.url, 5)

    report = airdrop_radar.scan_official_sources(
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )
    assert report["health"] == "degraded"
    assert "yellowpaper" in report["summary"]["failed_sources"]
    assert report["resolved_facts"]["testnet_status"]["value"] == "planned"


def test_all_critical_sources_down_is_visible_failure() -> None:
    mapping = pages()

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        if spec.critical:
            raise httpx.ReadTimeout("down")
        return airdrop_radar.FetchResult(mapping[spec.name], spec.url, 5)

    with pytest.raises(RuntimeError, match="all_critical_sources_unavailable"):
        airdrop_radar.scan_official_sources(
            fetcher=fetch,
            sleeper=lambda _seconds: None,
        )


@pytest.mark.parametrize(
    ("url", "hosts"),
    [
        ("http://flop.finance/teaser/", ("flop.finance",)),
        ("https://evil.example/teaser/", ("flop.finance",)),
        ("https://flop.finance.evil.example/teaser/", ("flop.finance",)),
        ("https://github.com/flop-labs", ("api.github.com",)),
    ],
)
def test_url_allowlist_rejects_scheme_or_host_escape(url: str, hosts: tuple[str, ...]) -> None:
    with pytest.raises(RuntimeError, match="non_official_url"):
        airdrop_radar._validate_url(url, hosts)


def test_custom_fetch_is_still_subject_to_hard_body_cap() -> None:
    spec = next(spec for spec in airdrop_radar.SOURCES if spec.name == "teaser")

    def fetch(_spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        return airdrop_radar.FetchResult(
            body="x" * (airdrop_radar.MAX_PAGE_BYTES + 1),
            final_url=spec.url,
            latency_ms=1,
        )

    with pytest.raises(RuntimeError, match="page_too_large"):
        airdrop_radar._fetch_with_retry(
            spec,
            fetcher=fetch,
            sleeper=lambda _seconds: None,
        )


def test_first_snapshot_is_baseline_without_alert_storm() -> None:
    current = snapshot()
    diff = airdrop_radar.compare_snapshots(None, current)
    assert diff["baseline"] is True
    assert diff["events"] == []


def test_material_agent_pool_change_is_high_and_deterministic() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    after["resolved_facts"]["genesis_agent_airdrop"]["value"] = 1_350_000_000
    after["snapshot_id"] = "changed"

    first = airdrop_radar.compare_snapshots(before, after)
    second = airdrop_radar.compare_snapshots(before, after)
    events = [row for row in first["events"] if row["key"] == "genesis_agent_airdrop"]
    assert len(events) == 1
    assert events[0]["severity"] == "HIGH"
    assert first["events"] == second["events"]


def test_faucet_open_change_is_action_now() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    after["resolved_facts"]["faucet_status"]["value"] = "open"
    after["snapshot_id"] = "faucet-open"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "faucet_status")
    assert event["severity"] == "ACTION_NOW"


def test_content_only_change_stays_info() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    teaser = next(row for row in after["sources"] if row["name"] == "teaser")
    teaser["content_sha256"] = "content-changed"
    after["snapshot_id"] = "new-page-hash"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "source:teaser")
    assert event["type"] == "CONTENT_CHANGED"
    assert event["severity"] == "INFO"


def test_exact_deadline_gets_gate_but_date_only_never_invents_time() -> None:
    source = next(spec for spec in airdrop_radar.SOURCES if spec.name == "teaser")
    rows = airdrop_radar._extract_deadlines(
        "submission deadline 2026-09-19T01:00:00Z; claim cutoff 2026-09-30",
        source,
    )
    exact = next(row for row in rows if row["exact"])
    date_only = next(row for row in rows if not row["exact"])
    gate = airdrop_radar.deadline_gate(
        exact["timestamp"],
        now=datetime(2026, 9, 18, 20, 0, tzinfo=UTC),
    )
    assert gate["gate"] == "T-6h"
    assert "timestamp" not in date_only
    assert date_only["date"] == "2026-09-30"


def test_new_exact_deadline_within_24h_is_action_now() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    after["deadlines"] = [
        {
            "label": "deadline",
            "timestamp": "2026-09-19T00:00:00+00:00",
            "exact": True,
            "source": "teaser",
            "tier": 2,
            "evidence_sha256": "deadline-evidence",
        }
    ]
    after["snapshot_id"] = "deadline-added"
    events = airdrop_radar.compare_snapshots(
        before,
        after,
        now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )["events"]
    event = next(row for row in events if row["type"] == "NEW_DEADLINE")
    assert event["severity"] == "ACTION_NOW"
    assert event["deadline_gate"]["gate"] == "T-12h"


def test_github_interest_repo_change_is_medium_not_binding_action() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    repos = after["resolved_facts"]["github_interest_repo_names"]["value"]
    repos.append(
        {
"technocore-new-airdrop-challenge"
    )
    after["snapshot_id"] = "github-repo-added"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "github_interest_repo_names")
    assert event["severity"] == "MEDIUM"


def test_existing_github_repo_push_is_info_not_medium() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    activity = after["resolved_facts"]["github_interest_repo_activity"]["value"]
    target = next(row for row in activity if row["name"] == "technocore-chat")
    target["pushed_at"] = "2026-09-18T04:00:00Z"
    after["snapshot_id"] = "github-push"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "github_interest_repo_activity")
    assert event["severity"] == "INFO"


def test_radar_module_has_no_external_write_client_calls() -> None:
    source = inspect.getsource(airdrop_radar)
    assert "httpx.post" not in source
    assert "httpx.put" not in source
    assert "httpx.delete" not in source
