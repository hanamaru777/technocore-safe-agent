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
<p>E.40 — Agent & staker leg distribution [TBD]. Specify the pools and
the pro-rata basis (agents: verified inference spend, unconfirmed).</p>
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
<a href="/apply/kol">KOLs & creators</a>
</body></html>
"""

KOL = """
<html><body>
<h1>FLOP KOL Survey</h1>
<p>Interested in contributing to the FLOP ecosystem?</p>
<p>I understand that submitting this form does not constitute an offer, agreement, or guarantee
of selection or participation and does not entitle me to any compensation, payment, token,
token allocation, reward, benefit, or anything else of monetary value. Any future program,
if offered, may be subject to separate eligibility requirements and terms.</p>
<p>FLOP may use this form to evaluate potential participation in future programs. Any future program,
if offered, may be subject to separate eligibility requirements and terms.</p>
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
        "kol_application": KOL,
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
    assert scoring["value"] == "verified_inference_spend"
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
    assert report["resolved_facts"]["kol_application_status"]["value"] == "form_available"
    assert report["resolved_facts"]["kol_compensation_guaranteed"]["value"] is False
    assert report["resolved_facts"]["kol_program_terms_status"]["value"] == "future_programs_separate_terms"


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
    repos.append("technocore-new-airdrop-challenge")
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


def test_lower_tier_scoring_change_is_high_even_if_resolved_winner_stays_same() -> None:
    before = snapshot()
    changed = pages()
    changed["teaser"] = changed["teaser"].replace(
        "based largely on what they spend on inference over the testnet,\nalong with various prizes",
        "based largely on what they spend on inference over the testnet",
    )
    after = airdrop_radar.scan_official_sources(
        fetcher=fetch_from(changed),
        sleeper=lambda _seconds: None,
    )
    assert before["resolved_facts"]["agent_scoring_basis"]["value"] == "verified_inference_spend"
    assert after["resolved_facts"]["agent_scoring_basis"]["value"] == "verified_inference_spend"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "agent_scoring_basis")
    assert event["type"] == "SOURCE_VARIANT_CHANGED"
    assert event["severity"] == "HIGH"


def test_deadline_evidence_wording_change_does_not_create_duplicate_deadline() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    common = {
        "label": "deadline",
        "timestamp": "2026-09-19T00:00:00+00:00",
        "exact": True,
        "source": "teaser",
        "tier": 2,
    }
    before["deadlines"] = [{**common, "evidence_sha256": "old-wording"}]
    after["deadlines"] = [{**common, "evidence_sha256": "new-wording"}]
    before["snapshot_id"] = "before-deadline-wording"
    after["snapshot_id"] = "after-deadline-wording"
    events = airdrop_radar.compare_snapshots(
        before,
        after,
        now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )["events"]
    assert not any(row["type"] == "NEW_DEADLINE" for row in events)


def test_previous_snapshot_accepts_raw_or_cli_wrapper_and_rejects_invalid() -> None:
    current = snapshot()
    assert airdrop_radar.normalize_previous_snapshot(current) is current
    wrapped = {"snapshot": current, "diff": {"events": []}}
    assert airdrop_radar.normalize_previous_snapshot(wrapped) is current
    with pytest.raises(RuntimeError, match="previous_snapshot_invalid"):
        airdrop_radar.normalize_previous_snapshot({"schema_version": 999})


def test_tier1_outage_does_not_masquerade_as_rule_change() -> None:
    before = snapshot()
    mapping = pages()

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        if spec.name == "yellowpaper":
            raise httpx.ReadTimeout("temporary")
        return airdrop_radar.FetchResult(mapping[spec.name], spec.url, 5)

    after = airdrop_radar.scan_official_sources(
        fetcher=fetch,
        sleeper=lambda _seconds: None,
    )
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    unavailable = next(
        row for row in events
        if row["key"] == "source:yellowpaper:availability"
    )
    assert unavailable["type"] == "SOURCE_UNAVAILABLE"
    assert unavailable["severity"] == "HIGH"
    assert not any(
        row["key"] in {
            "genesis_supply",
            "genesis_agent_airdrop",
            "agent_scoring_basis",
            "e38_status",
            "e40_status",
        }
        and row["type"] in {"CHANGED", "REMOVED", "RESOLVED", "CONFLICT"}
        for row in events
    )


def test_recovered_source_does_not_reannounce_old_deadline_as_new() -> None:
    base = snapshot()
    down = copy.deepcopy(base)
    yellow = next(row for row in down["sources"] if row["name"] == "yellowpaper")
    yellow.update({"status": "error", "error_type": "ReadTimeout"})
    yellow.pop("content_sha256", None)
    down["deadlines"] = []
    down["snapshot_id"] = "yellowpaper-down"

    recovered = copy.deepcopy(base)
    recovered["deadlines"] = [
        {
            "label": "deadline",
            "timestamp": "2026-09-19T00:00:00+00:00",
            "exact": True,
            "source": "yellowpaper",
            "tier": 1,
            "evidence_sha256": "same-old-deadline",
        }
    ]
    recovered["snapshot_id"] = "yellowpaper-recovered"
    events = airdrop_radar.compare_snapshots(
        down,
        recovered,
        now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
    )["events"]
    assert any(
        row["type"] == "SOURCE_RECOVERED"
        and row["key"] == "source:yellowpaper:availability"
        for row in events
    )
    assert not any(row["type"] == "NEW_DEADLINE" for row in events)


def test_healthy_source_fact_removal_is_still_detected() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    fact = after["resolved_facts"]["official_airdrop_x_handle"]
    fact["variants"] = []
    del after["resolved_facts"]["official_airdrop_x_handle"]
    after["snapshot_id"] = "home-fact-removed"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "official_airdrop_x_handle")
    assert event["type"] == "REMOVED"


def test_new_official_testnet_link_is_high_review_signal_not_action() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    home_before = next(row for row in before["sources"] if row["name"] == "home")
    home_after = next(row for row in after["sources"] if row["name"] == "home")
    home_before["interest_links"] = []
    home_after["interest_links"] = ["https://flop.finance/testnet/claim/"]
    home_after["content_sha256"] = "home-with-new-link"
    after["snapshot_id"] = "new-official-link"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["type"] == "OFFICIAL_LINK_DISCOVERED")
    assert event["severity"] == "HIGH"
    assert event["severity"] != "ACTION_NOW"
    assert event["after"]["url"] == "https://flop.finance/testnet/claim/"


def test_interest_link_parser_ignores_external_and_irrelevant_links() -> None:
    source = next(spec for spec in airdrop_radar.SOURCES if spec.name == "home")
    html = """
    <a href="/testnet/">Testnet</a>
    <a href="https://evil.example/claim/">Fake claim</a>
    <a href="/about/">About</a>
    <a href="/claim/?utm_source=x#top">Claim</a>
    """
    assert airdrop_radar._official_interest_links(html, source) == [
        "https://flop.finance/claim/",
        "https://flop.finance/testnet/",
    ]


def test_kol_program_disclaimer_change_is_high_not_auto_action() -> None:
    before = snapshot()
    after = copy.deepcopy(before)
    after["resolved_facts"]["kol_compensation_guaranteed"]["value"] = True
    after["snapshot_id"] = "kol-terms-changed"
    events = airdrop_radar.compare_snapshots(before, after)["events"]
    event = next(row for row in events if row["key"] == "kol_compensation_guaranteed")
    assert event["severity"] == "HIGH"
    assert event["severity"] != "ACTION_NOW"


def test_radar_module_has_no_external_write_client_calls() -> None:
    source = inspect.getsource(airdrop_radar)
    assert "httpx.post" not in source
    assert "httpx.put" not in source
    assert "httpx.delete" not in source
