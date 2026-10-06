from __future__ import annotations

from flop_agent import airdrop_radar


YELLOWPAPER_CURRENT = """
<html><body>
<p>Version 0.5.0 (draft) Updated 2026-09-24</p>
<p>E.38 — Unresolved conversion and release policy [RATIFY].</p>
<p>R8.4 — Conversion eligibility. A faucet grant MUST NOT by itself create an allocation right;
held Era-T balance and stake size MUST NOT be scoring terms. Agent scoring MUST derive from
settled compute-channel spend.</p>
<p>R8.7 — Unlock schedule. An Agent grant MUST NOT unlock any principal at its start block,
and it has no end block. It MUST unlock only against spend credit: one FLOP of principal for
each three FLOP of its locked part in the payable of a settled session.</p>
<p>R9.4 — Genesis. genesis_supply = 4,400,000,000 FLOP.
genesis_miner_airdrop = 1,200,000,000 FLOP.
genesis_validator_airdrop = 1,200,000,000 FLOP.
genesis_agent_airdrop = 1,200,000,000 FLOP.
genesis_reserve = 800,000,000 FLOP.</p>
</body></html>
"""

YELLOWPAPER_VAGUE = """
<html><body>
<p>Version 0.5.0 (draft) Updated 2026-09-24</p>
<p>Some ecosystem discussions mention a possible 3:1 unlock for Agents.</p>
<p>genesis_miner_airdrop = 1,200,000,000 FLOP.</p>
</body></html>
"""

AIRDROP_DRAFT = """
<html><body>
<p>Status Draft</p>
<p>The genesis supply of 4,400,000,000 $FLOP is the testnet airdrop.</p>
<p>Miners 1,200,000,000 (6.6%) Verified compute served on the testnet</p>
<p>Agents 1,200,000,000 (6.6%) Compute purchased on the testnet</p>
<p>Validators 1,200,000,000 (6.6%) Aggregate stake</p>
<p>Ecosystem reserve 800,000,000 (4.4%) Growth programmes</p>
<p>Every 3 $FLOP of the locked balance spent in settled sessions unlocks 1 $FLOP.</p>
</body></html>
"""


def _source(name: str) -> airdrop_radar.SourceSpec:
    return next(source for source in airdrop_radar.SOURCES if source.name == name)


def _facts(name: str, body: str) -> list[dict]:
    _text, facts, _deadlines, _meta = airdrop_radar._extract_facts(_source(name), body)
    return facts


def _by_key(rows: list[dict]) -> dict[str, dict]:
    return {row["key"]: row for row in rows}


def test_current_yellowpaper_extracts_ratified_genesis_and_agent_rules() -> None:
    facts = _by_key(_facts("yellowpaper", YELLOWPAPER_CURRENT))

    assert facts["genesis_supply"]["value"] == 4_400_000_000
    assert facts["genesis_miner_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_validator_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_agent_airdrop"]["value"] == 1_200_000_000
    assert facts["genesis_reserve"]["value"] == 800_000_000

    assert facts["agent_scoring_basis"]["value"] == "settled_compute_channel_spend"
    assert facts["agent_scoring_basis"]["status"] == "normative"
    assert facts["balance_is_scoring_term"]["value"] is False
    assert facts["balance_is_scoring_term"]["status"] == "normative"

    assert facts["spend_to_unlock_status"]["value"] == "ratified"
    assert facts["spend_to_unlock_status"]["status"] == "normative"
    assert facts["spend_to_unlock_ratio"]["value"] == "3:1"
    assert facts["spend_to_unlock_ratio"]["status"] == "normative"
    assert facts["e38_status"]["value"] == "RATIFY"

    for key in (
        "genesis_miner_airdrop",
        "genesis_validator_airdrop",
        "agent_scoring_basis",
        "balance_is_scoring_term",
        "spend_to_unlock_status",
        "spend_to_unlock_ratio",
    ):
        assert facts[key]["source"] == "yellowpaper"
        assert facts[key]["tier"] == 1


def test_vague_three_to_one_prose_cannot_fabricate_tier1_ratification() -> None:
    facts = _by_key(_facts("yellowpaper", YELLOWPAPER_VAGUE))

    assert facts["genesis_miner_airdrop"]["value"] == 1_200_000_000
    assert "spend_to_unlock_status" not in facts
    assert "spend_to_unlock_ratio" not in facts
    assert "agent_scoring_basis" not in facts
    assert "balance_is_scoring_term" not in facts


def test_tier1_yellowpaper_wins_over_same_tier2_draft_values() -> None:
    yellow = _facts("yellowpaper", YELLOWPAPER_CURRENT)
    airdrop = _facts("airdrop", AIRDROP_DRAFT)

    resolved = airdrop_radar._resolve_facts(yellow + airdrop)

    for key in (
        "genesis_supply",
        "genesis_miner_airdrop",
        "genesis_validator_airdrop",
        "genesis_agent_airdrop",
        "genesis_reserve",
        "spend_to_unlock_ratio",
    ):
        assert resolved[key]["source"] == "yellowpaper"
        assert resolved[key]["tier"] == 1
        assert resolved[key]["conflict"] is False

    assert resolved["spend_to_unlock_ratio"]["status"] == "normative"


def test_open_e38_policy_does_not_downgrade_ratified_three_to_one_mechanism() -> None:
    facts = _by_key(_facts("yellowpaper", YELLOWPAPER_CURRENT))

    assert facts["e38_status"]["value"] == "RATIFY"
    assert facts["spend_to_unlock_status"]["value"] == "ratified"
    assert facts["spend_to_unlock_ratio"]["value"] == "3:1"
