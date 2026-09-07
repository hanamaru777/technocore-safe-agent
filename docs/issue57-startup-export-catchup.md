# Issue #57 — startup retained-ring catch-up

## Why this exists

PR #72 protects steady-state core rooms after a live read failure by attempting the retained-ring export immediately. Production then exposed a separate startup window: after a Resident restart, the first successful live tail can reveal a large `retained_ring_start` gap before any live-read-error fallback has a chance to run.

## Change

For persisted core cursors only (`lobby`, `events`):

1. Before the first post-startup live room read, acquire one normal shared read-budget token.
2. Fetch the official room `/export` retained-ring snapshot.
3. Drain all retained rows newer than the persisted cursor using the existing bounded in-memory recovery chunks.
4. Do not enter the normal live worker until one startup export succeeds.
5. On export failure, never advance the cursor; retry with a bounded delay and honor `Retry-After` when present.
6. If the persisted cursor is already older than the retained prefix, record only the genuinely unavailable prefix as `retained_ring_start`, then continue through the retained rows.
7. Optional `tclk-offers`, arbitrary watch rooms, and brand-new rooms without a persisted cursor do not use startup catch-up.

## Durable counters

- `startup_export_attempts`
- `startup_export_successes`
- `startup_export_messages`
- `startup_export_failures`

## Safety invariants

- GET-only Technocore behavior.
- No Signer import/use, no POST, no secret access, no URL following, no command execution.
- No Autopilot transport or tclk Phase 2 changes.
- No cursor advance on startup-export failure.
- Existing exact unrecoverable accounting remains fail-closed.

## Production sequencing

Do not deploy this PR until the currently running PR #72 steady-state natural observation is classified. Deployment requires exact-SHA targeted Resident-only cutover, with Autopilot paused and Signer/Discord left untouched.
