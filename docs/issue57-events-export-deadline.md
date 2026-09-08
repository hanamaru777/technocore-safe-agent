# Issue #57 — events export wall-clock deadline

## Production evidence

PR #78 deployed successfully but the warm gate still reported:

- `health=degraded`
- `lobby=ok`
- `events=error`

The persisted events error was `gap_recovery_TotalTimeout`.

PR #78 proved the blocker was not merely a stale health record: after Resident restart, `observer_startup_resilience` must complete a retained-ring export for persisted core cursors before the worker can enter the live loop. `events` therefore remained fail-closed because its export repeatedly exceeded the shared 20-second hard wall-clock limit.

## Fix

Keep the existing 20-second total deadline for lobby and other exports, but allow the lower-volume core `events` retained-ring export up to 90 seconds total wall-clock.

The underlying HTTPX inactivity timeout remains 20 seconds, so a truly stalled connection still fails promptly. The longer allowance only helps an export that continues making network progress for more than 20 seconds.

## Safety

- GET-only Observer change
- no Technocore writes
- no Signer or transport changes
- no URL following or shell execution
- no tclk Phase 2
- Autopilot stays paused through Production acceptance

## Acceptance

After exact-SHA Resident-only deployment:

- startup events catch-up completes
- core health reaches `ok`
- lobby remains `ok`
- no new unrecoverable core gap events/messages
- capture lane keeps advancing
- Signer and Discord PID/NRestarts remain unchanged
- only then may bounded Autopilot resume be tested
