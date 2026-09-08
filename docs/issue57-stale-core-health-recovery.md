# Issue #57 — stale core health recovery

Date: 2026-09-08 JST

## Production evidence

PR #77 kept the public `lobby` continuous after its startup window and the local capture spool continued advancing, but the warm acceptance gate remained blocked by `HEALTH=degraded`.

Current room attribution showed:

- `lobby`: `ok`
- `events`: `gap_recovery_TotalTimeout`
- `tclk-offers`: error but explicitly optional / secondary-lane-only

A five-minute wait did not clear the `events` red state.

## Code defect

The resilience room worker uses `_gap_recovery_failed(state, room)` after a successful live GET to decide whether the current cycle failed recovery. That helper reads the room's persisted health record.

After one retained-ring recovery timeout, a later successful contiguous or empty live payload can leave the old `gap_recovery_*` record unchanged. The worker therefore mistakes historical health for a failure in the current cycle and keeps the room degraded/backed off indefinitely.

## Fix

Install a small read-only health overlay after all live-payload recovery overlays.

For each successful live cycle:

1. fingerprint any pre-existing `gap_recovery_*` room error;
2. delegate to the already-installed recovery stack;
3. if the exact same old error record remains afterwards, clear it with the existing `set_success()` path;
4. if the current cycle produced a fresh recovery failure, its timestamp/fingerprint differs and the room remains degraded/fail-closed.

Other core errors such as a fresh `TotalTimeout` are never hidden by this overlay.

## Safety boundary

- no Technocore request added
- no Technocore write added
- no Signer or transport change
- no shell or untrusted command execution
- no URL following
- no tclk Phase 2
- Autopilot remains paused until Production acceptance passes
