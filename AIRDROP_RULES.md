# Airdrop rules

Checked 2026-09-10 (Asia/Tokyo).

This file separates **ratified protocol parameters**, **draft / provisional airdrop mechanics**, and **public strategy signals**. Do not collapse them into one certainty level.

## SOURCE HIERARCHY

1. FLOP Yellow Paper v0.5.0 — authoritative implementation specification, still iterating.
2. FLOP project intro / Teaser — useful public design intent, but explicitly draft and provisional where it conflicts with the Yellow Paper.
3. FLOP Labs / Arthur Hayes first-party public announcements — actionable program signals, but not protocol rules unless they are also specified in official docs.
4. Technocore / tclk official repositories and docs — protocol behavior only, not airdrop scoring unless FLOP explicitly says so.

## RATIFIED / CURRENT PROTOCOL PARAMETERS

Official Yellow Paper:
https://flop.finance/intro/yellowpaper/

Yellow Paper v0.5.0, updated 2026-09-05, currently lists these canonical genesis parameters:

- `genesis_supply` = **2,483,460,000 FLOP**.
- Miner genesis allocation = **993,384,000 FLOP (40%)**.
- Validator genesis allocation = **305,505,000 FLOP (12.3%)**.
- Agent genesis allocation = **596,030,400 FLOP (24%)**.
- Ecosystem / incentives reserve = **588,540,600 FLOP (23.7%)**.
- The reserve description explicitly includes **KOL, referral and growth incentives**.
- `airdrop_vesting_duration_blocks` = **7,776,000 blocks**, described in the parameter table as 90-day linear vesting at 1-second blocks.

Era-0 ongoing block reward parameters currently list:

- total block reward = **96 FLOP / block**.
- miners = **75%**.
- validators = **10%**.
- agents / brokers = **10%**.
- community stakers = **5%**.

Important: Yellow Paper open item **E.40** says the exact distribution mechanism for the 10% agent / broker leg is still TBD. It currently accrues in a sovereign pool and must not be treated as a live user payout rule yet.

## AIRDROP MECHANICS THAT ARE STILL OPEN

Yellow Paper open item **E.38 — Genesis allocation & airdrop vesting** says the actual distribution path is still unspecified.

Still open / not final include:

- testnet → mainnet conversion formula.
- per-user / per-cohort cap levels.
- the sublinear scoring form.
- activity minimums.
- exact validator conversion basis.
- final agent vesting horizon.
- whether the inference-spend unlock mechanic actually ships.
- final claim path.
- treatment of unallocated remainder.

Therefore, even where the parameter table contains ratified pool sizes, **individual Agent/KOL allocation formulas are not yet known**.

## TEASER TESTNET SIGNAL — HIGH VALUE, BUT PROVISIONAL

Official Teaser:
https://flop.finance/teaser/

The Teaser v0.1 (draft, updated 2026-08-26) says:

- Testnet is planned for **Q4 2026** and roughly **90 days**.
- Agents claim test tokens from a faucet and spend them on inference.
- Agent airdrop is described as based largely on inference spend over Testnet, plus various prizes.
- Agent airdrop is described as locked and usable for inference or staking.
- It describes **3 FLOP inference spend → 1 airdropped FLOP unlocked**.

However, the same Teaser still shows a **3.5bn genesis pool / up to 1.2bn Agent allocation**, while the newer Yellow Paper canonical parameter table currently ratifies **2.48346bn genesis / 596.0304m Agent**.

Conclusion: use the Teaser to prepare behavior and infrastructure, but **do not present its pool size, scoring, or spend-to-unlock path as final**.

## PRE-TESTNET TECHN0CORE SIGNAL

FLOP Labs public signal retained in project records:
https://x.com/flop_labs/status/2091830155270672521

The post asks Agents to create a unique DID and do something useful around Technocore, with a FLOP airdrop reward signal.

What is **not** published:

- exact DID score.
- posts/day score.
- receipt score.
- collaboration score.
- tclk score.
- snapshot date.
- anti-Sybil formula.

Strategy implication: keep one continuing DID and optimize for **useful, attributable, verifiable work**, not raw activity volume.

## KOL / REFERRAL TRACK

The user already submitted the FLOP KOL / Creator application before the 2026-09-09 KOL Leaderboard announcement. Do not submit the generic application again unless FLOP explicitly requires it.

2026-09-09 first-party leadership signal from Arthur Hayes (`@CryptoHayes`), retweeted by Flop Labs:

- FLOP is creating a **KOL Leaderboard**.
- KOLs are expected to receive unique referral links.
- FLOP intends to track network help / usage attributable to referrals.
- wallets created from referral links are expected to be eligible for periodic FLOP lotteries.
- program is described as open to all.
- more details are still pending.

The Yellow Paper reserve independently strengthens this track because the ratified reserve explicitly names **KOL, referral and growth incentives**.

Still unknown:

- leaderboard launch date.
- whether prior KOL application is sufficient for link issuance.
- exact referral attribution rules.
- scoring formula.
- lottery frequency / eligibility details.
- caps and anti-Sybil rules.
- reward size.

No self-referral, multi-wallet farming, fake referrals, or artificial network usage.

## TCLK / AGENT COLLABORATION

Official tclk:
https://github.com/flop-labs/tclk

- `tclk/1` is Alpha.
- the current published Alpha has no value-bearing settlement rail.
- PaperRail is appropriate for no-value rehearsal / collaboration evidence.
- genuine Agent-to-Agent collaboration + terminal receipt is strategically aligned with FLOP's stated Agent collaboration direction.
- there is **no confirmed rule** saying a tclk receipt earns a specific FLOP amount or airdrop score.

Do not manufacture self-deals, reciprocal fake work, or synthetic receipts.

## CURRENT STRATEGY — EXPECTED-VALUE ORDER

1. **Q4 Testnet Agent usage** — highest priority the moment official Faucet / Testnet / Inference interfaces are published. Use the same continuing identity where the official flow permits it, perform genuinely useful inference, and keep durable spend/result evidence.
2. **KOL referral program** — application already submitted; activate immediately when FLOP issues the official referral link / leaderboard flow. Use it only in genuine educational content and track legitimate referred usage.
3. **Pre-Testnet Agent participation** — keep the existing 24/7 Agent healthy; prioritize useful replies, repeat relationships, public technical help, and real collaboration over post count.
4. **Genuine tclk collaboration** — pursue one real no-value PaperRail collaboration with an unrelated counterparty when a suitable opportunity appears; require terminal receipt + durable evidence.
5. **Public contributions** — useful, non-duplicative public FLOP / Technocore / tclk bug reports, tests, docs, or reproducible evidence are strategically valuable, but are not claimed as confirmed airdrop points.
6. **Durable evidence** — retain public GitHub evidence and local receipts because Technocore history is ephemeral.

## DO NOT DO

- no Sybil / multi-wallet farming.
- no self-referrals.
- no wash inference or fake usage.
- no fake Agent collaboration.
- no spam posting to inflate activity.
- no speculative Testnet writes before official interfaces exist.
- no seed / private-key submission to unknown services.
- no claim that Technocore posts, receipts, GitHub PRs, or referrals equal confirmed airdrop points unless FLOP publishes that rule.

## TRIGGERS THAT REQUIRE IMMEDIATE STRATEGY UPDATE

Re-check and update this file immediately when any of these appear:

- official Testnet launch date.
- Faucet URL / claim procedure.
- Agent Inference API / CLI / RPC.
- Testnet scoring / prize rules.
- final airdrop conversion / claim rules.
- KOL referral link / leaderboard / dashboard.
- KOL attribution / lottery rules.
- Yellow Paper update changing genesis, airdrop, Agent, KOL, or reserve parameters.
- tclk production/value-bearing rail release relevant to Agent collaboration.
