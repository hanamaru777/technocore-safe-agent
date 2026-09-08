# Issue #57 — final core recovery semantics

## Production evidence before this change

Production on PR #87 (`5923f2c06492f86d7c5dd2ef77f7f5e3b8a4c83e`) remained fail-closed with Autopilot paused.

Latest attribution:

- core counters: `116 / 5,032,674`
- latest core loss: lobby `35,523,475..35,526,053` (`2,579`) with `retained_ring_start`
- that exact lobby interval later became fully present in the independent SQLite capture spool
- lobby capture remained healthy and advancing
- events startup cursor: `337,810`
- first unseen events seq: `338,385`
- exact events startup gap: `337,811..338,384` (`574`)
- events startup probe: attempts `9`, success `0`, fallback `6`, failures `3`
- events startup streaming: attempts `10`, success `4`, failures `4`, recovered `4,021`, bytes `30,914,319`

## Remaining control-flow defects

### Lobby

A fixed local-spool grace timeout is not evidence that the independent capture lane permanently missed the range. Production proved a range could be classified unrecoverable and then appear completely in SQLite later.

The rich Observer must therefore keep its cursor fixed while a fresh capture process is still behind the exact proven gap. Server fallback is allowed only after the capture lane has crossed the gap boundary without complete local evidence, or when capture is stale/erroring.

The same local-first rule applies to live-read failures: when capture is healthy but has not advanced yet, do not spend another moving retained-ring export request immediately.

On Resident startup, a fresh post-restart capture snapshot that is fully contiguous through the local capture cursor is sufficient to satisfy lobby startup continuity. Do not perform a redundant server export after the persisted spool has already proven the interval.

### Events

When a live probe proves an exact events gap and an official retained snapshot later proves part of that exact interval is no longer present, retrying the impossible target forever cannot recover information.

The safe terminal behavior is:

1. process every contiguous row that is still present;
2. account only the remaining absent suffix/internal interval as genuinely unrecoverable;
3. advance only through that exact proven missing boundary;
4. return startup health to normal and continue live observation.

Transport errors remain retryable and do not trigger unrecoverable accounting.

## Safety invariants

- GET/read-only Technocore behavior only
- no Signer changes or restart requirements
- no Technocore writes
- no tclk Phase 2 changes
- no URL following or command execution
- no secret access
- no historical counter rewrite
- no silent cursor skip
- every truly absent retained interval is counted explicitly
- Autopilot remains paused until Production acceptance passes
