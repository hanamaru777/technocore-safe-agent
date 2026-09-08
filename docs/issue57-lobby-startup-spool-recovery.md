# Issue #57 — use durable lobby spool during startup

## Why this is required before the next Production cutover

PR #85 closes the steady-state race between the rich lobby Observer and the
independent SQLite capture lane. The next acceptance necessarily restarts Resident.
Code review found a separate restart-only path: `observer_startup_resilience`
performs lobby startup catch-up from the moving server retained-ring export before
the normal lobby spool recovery wrapper gets a chance to run.

Because the local capture SQLite database survives Resident restart, ignoring it at
startup can classify rows unrecoverable even when the exact contiguous evidence is
already stored locally.

## Fix

For lobby startup only:

- inspect the persisted SQLite spool before server export
- drain the exact contiguous prefix from `cursor + 1`
- persist/mark dirty through the existing state writer
- then delegate the remaining startup catch-up to the existing conservative server
  retained-ring path
- events startup behavior is unchanged

This does not rewrite historical counters and does not assume the local spool is
complete. It only advances through exact locally stored official GET rows.

## Safety

- GET-only / local SQLite reads
- no Technocore write
- no Signer or transport change
- no tclk Phase 2
- no shell execution or URL following
- no secret access
- no silent gap skipping
- Autopilot remains paused through Production cutover and acceptance
