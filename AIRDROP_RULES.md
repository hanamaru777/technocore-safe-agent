# Airdrop rules

Checked 2026-09-14 (Asia/Tokyo).

This file separates **ratified protocol parameters**, **draft / provisional airdrop mechanics**, and **public strategy signals**. Do not collapse them into one certainty level.

## SOURCE HIERARCHY

1. FLOP Yellow Paper v0.5.0 — authoritative implementation specification, still iterating.
2. FLOP project intro / Teaser — useful public design intent, but explicitly draft and provisional where mechanics remain open.
3. FLOP Labs / Arthur Hayes first-party public announcements — actionable program signals, but not protocol rules unless they are also specified in official docs.
4. Technocore / tclk official repositories and docs — protocol behavior only, not airdrop scoring unless FLOP explicitly says so.

## RATIFIED / CURRENT PROTOCOL PARAMETERS

Official Yellow Paper:
https://flop.finance/intro/yellowpaper/

Yellow Paper v0.5.0 current main records **D-0438**, which supersedes the older D-0421 / D-0435 genesis-pool sizes. Current normative genesis parameters are:

- `genesis_supply` = **3,500,000,000 FLOP**.
- Miner genesis allocation = **1,200,000,000 FLOP**.
- Validator genesis allocation = **305,505,000 FLOP**.
- Agent genesis allocation = **1,200,000,000 FLOP**.
- Ecosystem / incentives reserve = **794,495,000 FLOP**, explicitly described as KOL / referral / growth incentives.
- `airdrop_vesting_duration_blocks` = **7,776,000 blocks**, described in the parameter table as 90-day linear vesting at 1-second blocks.

D-0438 changes the genesis pool and cohort sizes only; it explicitly leaves the emission schedule untouched.

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

D-0438 does **not** make the Teaser's 3 FLOP spend → 1 unlocked FLOP mechanic final. The current Yellow Paper notes that with the Agent pool at 1.2bn FLOP, applying a 3:1 spend-to-unlock rule over the projected Y1–Y3 release would require about 900m FLOP of inference spend against about 823.55m FLOP of projected total network spend over that window. The pacing, ratio, or release window therefore needs to be re-specified if spend-to-unlock ships.

Therefore, even where the parameter table contains ratified pool sizes, **individual Agent/KOL allocation formulas and unlock mechanics are not yet known**.

## TEASER TESTNET SIGNAL — HIGH VALUE, BUT PROVISIONAL

Official Teaser:
https://flop.finance/teaser/

The Teaser v0.1 (draft, updated 2026-08-26) says:

- Testnet is planned for **Q4 2026** and roughly **90 days**.
- Agents claim test tokens from a faucet and spend them on inference.
- Agent airdrop is described as based largely on inference spend over Testnet, plus various prizes.
- Agent airdrop is described as locked and usable for inference or staking.
- it describes **3 FLOP inference spend → 1 airdropped FLOP unlocked**.
- it shows a **3.5bn genesis pool / up to 1.2bn Agent allocation**.

After D-0438, the Teaser's headline 3.5bn genesis / 1.2bn Agent pool sizes now align with the current Yellow Paper pool sizes. That alignment does **not** ratify the Teaser's scoring, pacing, spend-to-unlock, Testnet conversion, or claim mechanics; those remain open in the Yellow Paper.

Conclusion: use the Teaser to prepare behavior and infrastructure, but **do not present its scoring or spend-to-unlock path as final**.

## PRE-TESTNET TECHNOCORE SIGNAL

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

The Yellow Paper reserve independently strengthens this track because the current reserve explicitly names **KOL, referral and growth incentives**.

Still unknown:

- leaderboard launch date.
- whether prior KOL application is sufficient for link issuance.
- exact referral attribution rules.
- scoring formula.
- lottery frequency / eligibility details.
- caps and anti-Sybil rules.
- reward size.

No self-referral, multi-wallet farming, fake referrals, or artificial network usage.

## VALIDATOR TRACK

Current official Validator documentation and Yellow Paper decision **D-0439** clarify that validators are not miners and validator eligibility must not require executing inference, producing PoUI proofs, owning a GPU, or owning a TEE.

The ratified direction is:

- active validator set target/cap = **1,000**.
- registration enters a validator queue above the effective stake floor.
- rotation is stake-ranked subject to uptime and a **verification-liveness** floor.
- verification-liveness comes from accepted validator duties such as attestation/quorum signing, DA audit responses, dispute opening, and protocol-issued known-answer verification challenges.

However, the Yellow Paper also marks important D-0439 wiring as not fully implemented yet, and validator participation requires stake. Therefore this project remains **zero-spend / support-funded only** for Validator participation until executable onboarding, stake/support rules, and shipped resource requirements are known.

Do not buy hardware or FLOP based on draft requirements.

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
5. **Validator readiness** — re-evaluate when official executable onboarding and stake/support rules exist; no paid infrastructure or token purchase under the current zero-spend policy.
6. **Public contributions** — useful, non-duplicative public FLOP / Technocore / tclk bug reports, tests, docs, or reproducible evidence are strategically valuable, but are not claimed as confirmed airdrop points.
7. **Durable evidence** — retain public GitHub evidence and local receipts because Technocore history is ephemeral.

## DO NOT DO

- no Sybil / multi-wallet farming.
- no self-referrals.
- no wash inference or fake usage.
- no fake Agent collaboration.
- no spam posting to inflate activity.
- no speculative Testnet writes before official interfaces exist.
- no speculative 3:1 unlock optimizer.
- no paid Validator infrastructure or FLOP purchase without explicit user approval.
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
- Validator Testnet/onboarding/stake/support rules.
- Yellow Paper update changing genesis, airdrop, Agent, KOL, reserve, Validator, or unlock parameters.
- tclk production/value-bearing rail release relevant to Agent collaboration.
