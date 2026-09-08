# Issue #57 — steady-state events streaming recovery

## Production evidence after PR #82

PR #82 fixed persisted `events` startup recovery:

- core unrecoverable counters stayed `114 / 5,000,710`
- events cursor advanced `333789 -> 334469`
- streaming startup recovery succeeded `1/1/0/680`
- two-minute Autopilot-paused steady state passed

After Autopilot resumed, the ten-minute guard failed only because `events` returned to error health. Lobby remained healthy and the core unrecoverable counters did not move. The last recorded unrecoverable gap remained the optional `tclk-offers` lane.

## Remaining code path

The startup path now streams the official retained export incrementally, but the normal resilience worker still used buffered full-body export in two `events` branches:

- fallback after a non-429 live-read failure
- recovery after a successful live tail reveals a sequence hole

Either branch can reproduce the old all-or-nothing export stall after startup.

## Fix

Install a narrow overlay after lobby-spool recovery and before stale-health recovery:

- only `events` steady-state recovery uses the already-proven incremental exporter from PR #82
- live-error fallback streams the official GET export instead of buffering the whole body
- live-gap recovery streams first, then lets the existing recovery chain process the live payload once the cursor no longer has a hole
- if a clean export snapshot ends before a proven live gap is covered, the remaining range is recorded as `not_in_retained_export`; it is never silently skipped
- stream errors remain fail-closed and leave the live payload unprocessed until a later retry
- lobby continues through its local capture-spool recovery unchanged

## Safety

- GET-only Observer behavior
- exact existing unrecoverable-gap accounting remains authoritative
- no Technocore write
- no Signer or transport change
- no shell execution
- no URL following
- no secret access
- no tclk Phase 2
- Autopilot remains paused through Production acceptance
