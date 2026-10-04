# Close Call Pre-Contest Readiness Gate

This document is mandatory for any future short-lived-liquidity contest using the Close Call runtime or similar test-token execution.

It exists because the 2026-10-04 contest failed operationally despite observing material liquidity. The failure mode was not lack of opportunities. It was failure to convert fresh opportunities into binding execution fast enough and without human relay.

## Non-negotiable principle

A strategy is not ready until it can execute safely at the speed of the opportunity.

For short-lived offers, the winning path must not depend on:

・ChatGPT returning to chat
・the user seeing a message
・the user copying a command
・the user opening SSH
・a single external desktop connector remaining available

If any binding leg still requires that chain, the system is NOT READY.

## Mandatory GO / NO-GO gates

All gates below must PASS before contest start. Any failure means NO-GO and engineering priority becomes readiness repair, not strategy sophistication.

### 1. EXECUTION_LATENCY_GATE

Required:

・Production rehearsal proves `candidate_detected -> executor_started` <= 5 seconds.
・The measurement must be captured from real runtime timestamps, not estimated.
・The path must include fresh signed reference, exact same-snapshot maker offer, account checks, approval creation and existing fail-closed executor start.

### 2. HUMAN_INDEPENDENCE_GATE

Required:

・No user terminal command is needed to move a fresh candidate to binding execution.
・Chat remains for oversight, audit, postmortem and policy changes, not for the short-lived execution critical path.

### 3. CONTROL_PATH_REDUNDANCY_GATE

Required:

・At least two authenticated Production control paths exist before contest start.
・At least one path must be independent of the primary connector's quota/subscription failure mode.
・Credentials, sudo capability, SSH ownership and Git ownership must be tested before the contest.

### 4. SETTLEMENT_RECONCILIATION_GATE

Required end-to-end cases:

・settled
・void
・pre-POST block
・ambiguous POST
・redacted official archive
・multiple pending trade IDs where applicable

Rules:

・No blind retry.
・Any attempt fence means that trade ID becomes no-retry until authoritative reconciliation.
・Redaction never implies absence.

### 5. DEADLINE_GATE

Required:

・Runtime knows absolute trading lock and final settlement/reference deadlines.
・New binding action is fail-closed after lock.
・Deadline logic is tested before the contest.

### 6. ACTIVE_LEARNING_GATE

Required:

・The system cannot remain at zero trades solely because leader coverage or a complete victory path is unavailable.
・A bounded first learning leg is defined before contest start.
・The first settled trade must feed actual fees, clawback, settlement lag, cash and position into later sizing.

### 7. NO_LIVE_PLUMBING_GATE

Required:

・Core execution plumbing is complete before contest start.
・During the contest, new monitoring/telemetry features do not take priority over executable material opportunities.
・Live infrastructure changes are limited to safety-critical defects.

## Required runtime architecture

The production path must be resident-side and bounded:

`fresh scan -> same-snapshot exact raw capture -> policy selection -> exact approval -> existing fail-closed executor -> attempt fence -> receipt -> authoritative reconciliation`

Properties that must remain intact:

・single continuing DID only
・no Sybil / self / collusive / wash trading
・fresh offer / ref / account / expiry / signature / ±5% / funds checks
・signer and Vault isolation
・durable attempt fence before irreversible POST
・pending single-flight protection
・no stale ID reuse
・no blind retry
・authoritative reconciliation before the next binding leg

## Execution policy lessons from 2026-10-04

The following are permanent no-repeat rules:

・Do not send short-lived offers through chat/user relay before execution.
・Do not rely on Remote Desktop Commander as the sole Production path.
・Do not require complete leader coverage for every entry.
・Do not let another monitoring feature delay a live material candidate.
・Do not treat planner sophistication as a substitute for execution capability.
・Do not wait until late contest stages to obtain first realized fee/clawback evidence.
・Do not use stale approvals or historical trade IDs.
・Do not weaken safety fences to gain speed.

## Live priority order

When the contest is running:

1. Preserve safety and no-retry invariants.
2. Reconcile any existing attempt/pending state.
3. Capture and execute fresh material opportunities within the latency SLA.
4. Use realized evidence to update sizing and direction.
5. Only then improve monitoring, telemetry or strategy presentation.

## Deadline-aware opportunity policy

Before the contest, define explicit thresholds for:

・minimum meaningful quantity
・minimum price edge
・maximum cash at risk per leg
・remaining follow-up cash
・threshold relaxation as lock approaches

These thresholds may relax with time, but stale/no-retry/signature/account/deadline safety checks may never relax.

## Required metrics

Every binding opportunity must record:

・candidate_detected_at
・raw_captured_at
・approval_written_at
・executor_started_at
・attempt_fenced_at
・receipt_at
・authoritative_reconciled_at
・capture_to_executor_ms
・executor_to_receipt_ms
・receipt_to_reconcile_ms
・candidate qty / px / reference / edge / required cash
・pre/post cash
・pre/post position
・fees / clawback
・top3 and victory hurdle before/after

## 2026-10-04 failure evidence to remember

Material liquidity was observed, including a same-snapshot signed BUY 20 @ 233.92. It would have moved the continuing account from short 1 to net long 19 while using less than half the available cash. By the time the human/chat relay reached Production, the offer was gone and the executor correctly returned `offer_missing` before any attempt fence or POST.

That safety behavior was correct. The architecture that allowed the opportunity to expire was not.

Later, the only ChatGPT-accessible Production command path depended on Remote Desktop Commander and became unavailable due to its usage limit. Existing GitHub Actions, fixed RPC, Discord control and standalone watch paths intentionally had no Close Call signer/Vault binding capability. This left no autonomous fallback.

## Final rule

Do not call a future contest environment READY until every GO / NO-GO gate in this document is freshly evidenced in Production or a production-equivalent rehearsal.

Issue #667 is the permanent operational authority for this checklist.