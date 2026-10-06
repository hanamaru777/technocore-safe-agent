# Airdrop rules

Checked 2026-10-06 (Asia/Tokyo).

This file separates **ratified protocol parameters**, **draft / provisional launch wording**, and **public strategy signals**. Do not collapse them into one certainty level.

## SOURCE HIERARCHY

1. FLOP Yellow Paper v0.5.0 — authoritative implementation specification, still iterating.
2. Official FLOP Testnet / Airdrop / role pages / Teaser — first-party launch and participation guidance; Draft where labelled so.
3. FLOP Labs / Arthur Hayes first-party public announcements — actionable program signals, but not protocol rules unless also specified in official docs.
4. Technocore / tclk official repositories and docs — protocol behavior only, not airdrop scoring unless FLOP explicitly says so.

## RATIFIED / CURRENT PROTOCOL PARAMETERS

Official Yellow Paper:
https://flop.finance/intro/yellowpaper/

Current observed Yellow Paper v0.5.0 page is updated 2026-10-05 and normatively lists:

- `genesis_supply` = **4,400,000,000 FLOP**.
- Miner genesis airdrop = **1,200,000,000 FLOP**.
- Validator genesis airdrop = **1,200,000,000 FLOP**.
- Agent genesis airdrop = **1,200,000,000 FLOP**.
- Ecosystem / incentives reserve = **800,000,000 FLOP**.
- The reserve explicitly covers ecosystem / growth incentives, including KOL and referral programmes.

Era-0 ongoing block reward parameters currently list:

- total block reward = **96 FLOP / block**.
- miners = **75%**.
- validators = **10%**.
- agents / brokers = **10%**.
- community stakers = **5%**.

Important: Yellow Paper open item **E.40** still leaves the exact ongoing distribution policy for the 10% agent leg and 5% staker leg unresolved. Do not treat those ongoing pools as a live end-user payout rule yet.

## RATIFIED AGENT TESTNET / AIRDROP BASIS

The Yellow Paper now specifies more than the older project notes did.

### Agent scoring basis

R8.4 states that:

- a faucet grant alone does **not** create an allocation right.
- held Era-T balance and stake size are **not** scoring terms.
- completed-job count and active-day count are **not** scoring terms.
- Agent scoring MUST derive from **settled compute-channel spend**.

This means the strategy should optimize for legitimate settled inference usage, not passive faucet balance, idle wallet size, raw transaction count, or fake activity days.

### Agent spend-to-unlock

R8.7 / R8.8 now specify the core Agent unlock mechanism normatively:

- an Agent grant has **no initial principal unlock**.
- it has no fixed end block.
- eligible spend credit unlocks **1 FLOP principal for every 3 FLOP of the grant's locked part used in an eligible settled `payable`**.
- the settlement must satisfy the Yellow Paper's finality / dispute / fraud conditions before spend credit counts.
- locked Agent principal spent outside the eligible `payable` path does not create unlock credit.
- locked compute spend is capped at **3/4 of the original Agent grant principal** so the remaining quarter can be unlocked by the resulting 3:1 credit.

This 3:1 mechanism is no longer merely a Teaser hypothesis. The Yellow Paper is the authority for the exact accounting conditions.

## WHAT IS STILL OPEN / NOT FINAL

Yellow Paper item **E.38** is now `[RATIFY]`, not a blank distribution-path placeholder. The broad genesis/airdrop path and core Agent spend-to-unlock mechanism are specified, but material details still remain open, including:

- score caps and sublinear aggregation.
- exact account/cluster aggregation rules.
- verifiable-demand and maintained-duration gates.
- validator cohort activity basis.
- treatment of activity under-count appeals.
- validator grant release ordering.
- any final anti-Sybil / fraud-cluster implementation details not yet frozen in executable launch rules.

Therefore the cohort pool and scoring basis are known, but **an individual user's exact final Agent allocation cannot yet be calculated from public official information**.

## OFFICIAL TESTNET STATUS — HIGH PRIORITY, STILL NOT EXECUTABLE

Official Testnet page:
https://flop.finance/testnet/

Official Airdrop page:
https://flop.finance/airdrop/

Current official status on 2026-10-06:

- Testnet status = **Draft**.
- planned opening = **Q4 2026**.
- expected length = about **90 days**.
- Mainnet target = **Q1 2027**.
- the Testnet page says role-specific onboarding documentation is published **when the Testnet opens**.
- Agent summary expects a DID and wallet with access to the test-token faucet.
- the Airdrop page says the Testnet is the sole route to the genesis airdrop.

Still not independently confirmed as exact executable public artifacts:

- faucet claim URL / procedure / API.
- Testnet chain RPC endpoint.
- Testnet chain ID / exact chain spec required for transactions.
- Agent inference execution API / CLI / SDK flow.
- exact Agent registration / onboarding transport.

Therefore **#311 remains WAIT/BLOCKED**. Do not implement or enable speculative Testnet writes from marketing text alone.

## TEASER — DRAFT NARRATIVE, NOW ALIGNED ON GENESIS SIZE

Official Teaser:
https://flop.finance/teaser/

The Teaser v0.1 remains Draft and its page is currently updated 2026-10-05. It now aligns the genesis allocation with the Yellow Paper at:

- total genesis airdrop/reserve pool = **4.4bn FLOP**.
- miners = **1.2bn**.
- validators = **1.2bn**.
- agents = **1.2bn**.
- reserve / incentives = **0.8bn**.

The Teaser also describes Q4 2026 Testnet, faucet test tokens and Agent inference spend. Use it as launch narrative / preparation guidance, but use the Yellow Paper for normative scoring and unlock accounting.

## PRE-TESTNET TECHNOCORE SIGNAL

FLOP Labs public signal retained in project records:
https://x.com/flop_labs/status/2091830155270672521

The post asks Agents to create a unique DID and do something useful around Technocore, with a FLOP airdrop reward signal.

What is **not** published as a protocol rule:

- exact Technocore DID score.
- posts/day score.
- receipt score.
- collaboration score.
- tclk score.
- Technocore-specific snapshot date.

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

The current Yellow Paper reserve continues to support this track because the 800m ecosystem / incentives reserve includes growth programmes such as KOL and referral incentives.

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

1. **Q4 Testnet Agent settled inference usage** — highest priority when official executable Faucet / Testnet / Inference / registration interfaces are published. Use the same continuing identity where the official flow permits it, perform genuinely useful inference, and keep durable settlement/spend/result evidence.
2. **KOL referral program** — application already submitted; activate when FLOP issues the official referral link / leaderboard flow. Use it only in genuine educational content and track legitimate referred usage.
3. **Pre-Testnet Agent participation** — keep the existing Agent healthy; prioritize useful replies, repeat relationships, public technical help, and real collaboration over post count.
4. **Genuine tclk collaboration** — pursue real no-value collaboration when strategically useful; require terminal receipt + durable evidence. Do not treat it as confirmed airdrop scoring.
5. **Public contributions** — useful, non-duplicative public FLOP / Technocore / tclk bug reports, tests, docs, or reproducible evidence are strategically valuable, but are not claimed as confirmed airdrop points.
6. **Durable evidence** — retain public GitHub evidence and local receipts because Technocore history is ephemeral.

## DO NOT DO

- no Sybil / multi-wallet farming.
- no self-referrals.
- no wash inference or fake usage.
- no fake Agent collaboration.
- no spam posting to inflate activity.
- no speculative Testnet writes before exact official executable interfaces exist.
- no seed / private-key submission to unknown services.
- no claim that Technocore posts, receipts, GitHub PRs, or referrals equal confirmed airdrop points unless FLOP publishes that rule.
- no attempt to maximize faucet balance or idle wallet balance as a score; current Yellow Paper explicitly excludes held balance as an Agent scoring term.

## TRIGGERS THAT REQUIRE IMMEDIATE STRATEGY UPDATE

Re-check and update this file immediately when any of these appear:

- official Testnet launch date / status change from Draft.
- Faucet URL / claim procedure.
- chain RPC / chain ID / official chain spec.
- Agent Inference API / CLI / SDK execution path.
- exact Agent registration / onboarding transport.
- Testnet score caps / sublinear aggregation / minimum activity rules.
- final conversion / claim / snapshot rules.
- KOL referral link / leaderboard / dashboard.
- KOL attribution / lottery rules.
- Yellow Paper update changing genesis, airdrop, Agent, KOL, reserve, scoring or unlock parameters.
- tclk production/value-bearing rail release relevant to Agent collaboration.
