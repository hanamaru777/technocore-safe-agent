from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "SOURCES.md").read_text(encoding="utf-8")
AIRDROP_RULES = (ROOT / "AIRDROP_RULES.md").read_text(encoding="utf-8")
DOCS = SOURCES + "\n" + AIRDROP_RULES


def test_public_airdrop_docs_use_current_ratified_genesis_allocations() -> None:
    for obsolete in (
        "2,483,460,000",
        "993,384,000",
        "305,505,000",
        "596,030,400",
        "588,540,600",
        "2.48346bn",
        "596.0304m",
    ):
        assert obsolete not in DOCS

    for current in (
        "4,400,000,000",
        "1,200,000,000",
        "800,000,000",
        "settled compute-channel spend",
        "3/4",
    ):
        assert current in SOURCES
        assert current in AIRDROP_RULES


def test_public_source_docs_keep_launch_status_fail_closed() -> None:
    for url in (
        "https://flop.finance/intro/yellowpaper/",
        "https://flop.finance/testnet/",
        "https://flop.finance/airdrop/",
    ):
        assert url in SOURCES
        assert url in AIRDROP_RULES

    assert "Testnet is still **Draft**" in SOURCES
    assert "Testnet status = **Draft**" in AIRDROP_RULES
    assert "exact executable faucet procedure/endpoint" in SOURCES
    assert "#311 remains WAIT/BLOCKED" in AIRDROP_RULES
