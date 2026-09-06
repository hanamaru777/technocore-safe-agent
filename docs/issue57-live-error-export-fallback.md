# Issue #57 — live-error retained-ring export fallback

## Problem

Production evidence after PR #71 showed that core `lobby` unrecoverable loss continued during steady-state operation. The durable attribution counters proved the remaining loss is core `lobby`, with `retained_ring_start` as the latest reason.

PR #69 can recover large gaps once a successful live read reveals them, and PR #71 bounds core retry/timeout behavior, but one client-side weakness remained: when the live room GET itself fails, the worker only records the error and backs off. It does not snapshot the retained ring until a later successful live read exposes a sequence gap. On a hot room, that delay can allow the required prefix to fall out of retention before recovery starts.

## Change

For the two core rooms that need continuity protection (`lobby` and `events`):

1. A non-429 live-read failure keeps the room health degraded with the original live error.
2. The worker consumes one normal read-budget token and attempts exactly one official `/r/<room>/export` snapshot immediately.
3. If the export succeeds, rows newer than the current cursor are drained from that one snapshot in the existing bounded 2,000-message chunks.
4. Any already-missing retained prefix is accounted exactly as `retained_ring_start`; internal holes remain `not_in_retained_export`.
5. If the export fails, the cursor does not advance.
6. A live 429 never triggers the fallback; `Retry-After` remains authoritative. If the fallback export itself returns 429, its retry hint is honored by the normal worker backoff.
7. Optional `tclk-offers`, arbitrary watch rooms, discovery, and backfill do not use this fallback, preventing an export stampede outside the two protected core lanes.

## Production proof counters

The Observer now persists:

- `live_error_export_fallback_attempts`
- `live_error_export_fallback_successes`
- `live_error_export_fallback_messages`
- `live_error_export_fallback_failures`

These counters are additive diagnostics. Existing legacy gap totals and core-vs-optional attribution remain unchanged.

## Safety invariants

- GET-only Technocore behavior.
- No POST, signing, secret access, URL following, command execution, or retry of ambiguous writes.
- No Signer, Autopilot transport, Discord accounting, or tclk Phase 2 change.
- No fallback on live 429.
- No cursor advance on export failure.
- Existing exact unrecoverable accounting remains fail-closed.
- Production Autopilot remains paused through acceptance.
