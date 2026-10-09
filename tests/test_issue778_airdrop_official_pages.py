from __future__ import annotations

from flop_agent import airdrop_launch_watch, airdrop_radar


TESTNET_DRAFT = """
<html><body>
<p>Status Draft Opens Q4 2026 Length About 90 days Mainnet Q1 2027</p>
<p>The testnet opens when its readiness criteria are met.</p>
<p>Operational rules and the minimum-activity floors are published with the testnet rules.</p>
<p>Onboarding documentation for each role is published when the testnet opens.</p>
<p>Agent — A decentralised identifier (DID) and a wallet, with access to the test-token faucet.</p>
<p>Agents — create a DID and a wallet, draw from the faucet, and begin purchasing inference.</p>
<p>Agents — compute purchased in settled sessions. Holding test tokens earns nothing.</p>
</body></html>
"""

TESTNET_LIVE = """
<html><body>
<p>Status Live Testnet is live.</p>
<p>Faucet is open. Agents can claim from the faucet now.</p>
<p>Agents — compute purchased in settled sessions.</p>
</body></html>
"""

AIRDROP = """
<html><body>
<p>Status Draft</p>
<p>There is no token sale and no investor allocation.</p>
<p>The genesis supply of 4,400,000,000 $FLOP is the testnet airdrop.</p>
<p>Miners 1,200,000,000 (6.6%) Verified compute served on the testnet</p>
<p>Agents 1,200,000,000 (6.6%) Compute purchased on the testnet</p>
<p>Validators 1,200,000,000 (6.6%) The aggregate stake that secures the network at launch</p>
<p>Ecosystem reserve 800,000,000 (4.4%) Growth programmes</p>
<p>Agents — supply demand. The allocation is shared pro rata to compute purchased in settled sessions.</p>
<p>Every 3 $FLOP of the locked balance spent in settled sessions unlocks 1 $FLOP.</p>
</body></html>
"""


def _source(name: str) -> airdrop_radar.SourceSpec:
    return next(source for source in airdrop_radar.SOURCES if source.name == name)


def _facts(name: str, body: str) -> dict[str, dict]:
    _normalized, rows, _deadlines, _meta = airdrop_radar._extract_facts(_source(name), body)
    return {row["key"]: row for row in rows}


def test_dedicated_official_pages_are_first_class_read_only_sources() -> None:
    testnet = _source("testnet")
    airdrop = _source("airdrop")

    assert testnet.url == "https://flop.finance/testnet/"
    assert airdrop.url == "https://flop.finance/airdrop/"
    assert testnet.tier == 2
    assert airdrop.tier == 2
    assert testnet.authority == "official"
    assert airdrop.authority == "official"

    yellow = _source("yellowpaper")
    assert yellow.tier == 1
    assert yellow.authority == "normative"


def test_testnet_draft_stays_planned_and_onboarding_remains_blocked() -> None:
    facts = _facts("testnet", TESTNET_DRAFT)

    assert facts["testnet_status"]["value"] == "planned"
    assert facts["testnet_window"]["value"] == "Q4 2026"
    assert facts["mainnet_window"]["value"] == "Q1 2027"
    assert facts["testnet_duration_days"]["value"] == 90
    assert facts["testnet_onboarding_docs_status"]["value"] == "publish_when_open"
    assert facts["testnet_minimum_activity_rules_status"]["value"] == "publish_with_testnet_rules"
    assert facts["faucet_status"]["value"] == "planned"
    assert facts["testnet_agent_earning_basis"]["value"] == "compute_purchased_in_settled_sessions"
    assert all("action_candidate" not in row for row in facts.values())


def test_draft_header_blocks_hypothetical_launch_and_faucet_in_watch() -> None:
    # Hypothetical onboarding prose is not a launch announcement while Draft remains.
    conditional = TESTNET_DRAFT.replace(
        "</body>", "<p>If the testnet is live, the faucet is open. Claim from the faucet now.</p></body>"
    )
    facts = _facts("testnet", conditional)

    assert facts["testnet_status"]["value"] == "planned"
    assert facts["faucet_status"]["value"] == "planned"
    assert airdrop_launch_watch.collect_candidates(
        {
            "read_only": True,
            "health": "ok",
            "sources": [
                {
                    "name": "testnet",
                    "url": "https://flop.finance/testnet/",
                    "status": "ok",
                    "authority": "official",
                    "interest_links": [],
                }
            ],
            "resolved_facts": facts,
        }
    ) == []


def test_explicit_live_language_without_status_header_is_still_detected() -> None:
    facts = _facts(
        "testnet",
        "<html><body>Testnet is live. Faucet is open.</body></html>",
    )
    assert facts["testnet_status"]["value"] == "live"
    assert facts["faucet_status"]["value"] == "open"


def test_only_explicit_live_language_opens_testnet_and_faucet_signal() -> None:
    facts = _facts("testnet", TESTNET_LIVE)

    assert facts["testnet_status"]["value"] == "live"
    assert facts["faucet_status"]["value"] == "open"
    assert airdrop_radar._severity("testnet_status", {"value": "live"}, "CHANGED") == "ACTION_NOW"
    assert airdrop_radar._severity("faucet_status", {"value": "open"}, "CHANGED") == "ACTION_NOW"


def test_airdrop_page_extracts_current_draft_allocations_and_agent_rules() -> None:
    facts = _facts("airdrop", AIRDROP)

    assert facts["genesis_supply"]["value"] == 4_400_000_000
    assert facts["genesis_miner_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_agent_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_validator_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_reserve"]["value"] == 800_000_000
    assert facts["token_sale_exists"]["value"] is False
    assert facts["investor_allocation_exists"]["value"] is False
    assert facts["agent_airdrop_earning_basis"]["value"] == "compute_purchased_in_settled_sessions"
    assert facts["spend_to_unlock_ratio"]["value"] == "3:1"
    assert all(row["status"] == "official_draft" for row in facts.values())
    assert all("action_candidate" not in row for row in facts.values())


def test_existing_custom_fetchers_without_new_fixture_keys_remain_compatible() -> None:
    legacy_pages = {
        "yellowpaper": "<html><body>genesis_supply = 4,400,000,000 FLOP</body></html>",
        "teaser": "<html><body>Flop Testnet is planned for Q4 2026.</body></html>",
        "agent": "<html><body></body></html>",
        "revenue": "<html><body></body></html>",
        "home": "<html><body></body></html>",
        "kol_application": "<html><body></body></html>",
        "github_org": "[]",
    }

    def fetch(spec: airdrop_radar.SourceSpec) -> airdrop_radar.FetchResult:
        return airdrop_radar.FetchResult(legacy_pages[spec.name], spec.url, 1)

    report = airdrop_radar.scan_official_sources(fetcher=fetch, sleeper=lambda _seconds: None)

    assert report["health"] == "ok"
    testnet_row = next(row for row in report["sources"] if row["name"] == "testnet")
    airdrop_row = next(row for row in report["sources"] if row["name"] == "airdrop")
    assert testnet_row["status"] == "ok"
    assert airdrop_row["status"] == "ok"
