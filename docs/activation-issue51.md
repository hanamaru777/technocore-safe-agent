# Issue #51 — Safe autonomous first-contact activation

Production baseline on 2026-09-04 after the performance recovery:

- 5,713 pending candidates
- 0 eligible Autopilot actions
- 4,695 rejected as `reply_semantics_unsupported`
- candidate mix dominated by 4,672 `artifact_contribution` records

The prior policy had a bootstrap deadlock: normal Autopilot trust required a
previous human-approved and durably published interaction, so the bot could not
create its own first safe relationship.

## Activation policy

Cold autonomous first contact is limited to:

- explicit `specific_question`
- concrete `help_request`
- concrete public/testable `technical_collaboration`
- verified signed public direct `agent_use_case`

Bulk `artifact_contribution` and generic returning-agent candidates never cold
start. Output is deterministic and category-specific; untrusted room text is
never copied into the outbound message.

## Safety invariants

- public rooms only
- Resident anti-noise and concrete-evidence gates remain required
- no unsupported airdrop/reward/TGE claims
- no value transfer or tclk accept
- no URL following, shell execution, private credentials, or secret disclosure
- max 6 posts / 24h, max 2 per room / 24h, max 1 per DID / 6h
- at most one new queued intent per build cycle
- cold first contact also has a one-hour global spacing gate
- existing isolated Signer, pinned signer integrity, DLP, receipt and ambiguity
  handling remain unchanged
- Contribution #2 and controlled E2E are untouched

A durably acknowledged first-contact receipt bootstraps a 30-day relationship
trust window for later candidates, but every later candidate must still pass
the same content-independent safety eligibility and signer rate limits.

## Rollout

Deploy code with Autopilot paused, run a read-only production preflight against
real pending state, verify a small nonzero cold-contact set, then allow exactly
one first real autonomous action. Confirm receipt, audit behavior, CPU, Discord
gateway health, and public message quality before normal bounded operation.

## Public/X evidence to preserve

Record the 5,713 / 0 baseline, the bootstrap-deadlock correction, unchanged
security boundaries, the first real public action + receipt, and subsequent
stability. Do not claim confirmed FLOP airdrop points unless FLOP publishes that
mapping.
