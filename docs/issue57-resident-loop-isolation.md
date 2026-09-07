# Issue #57 — isolate Resident maintenance from the hot-room event loop

Date: 2026-09-07 JST

## Production evidence

PR #74 correctly installed startup retained-ring catch-up and hard wall-clock request deadlines, but the first natural steady-state gate still produced two new core lobby losses totaling 7,794 messages.

The follow-up classification is important:

- new live-read errors after the PR #74 restart were `events TotalTimeout` events, not lobby live-read failures;
- the latest unrecoverable loss remained `lobby retained_ring_start`;
- Resident CPU was ~82%;
- the existing daemon still executes `resident.refresh()` and `autopilot.build_outbox()` synchronously inside the same asyncio loop that owns lobby/events network workers.

Historical Issue #49 production profiling already proved that Resident refresh can traverse thousands of agents and large local JSON state and was a major source of sustained CPU work. A successful lobby request after an event-loop starvation window can therefore reveal a retained-ring gap even though there was no lobby HTTP error to trigger the live-error fallback.

## Fix

`observer_resident_isolation` replaces only the local Resident maintenance worker.

- one daemon thread runs the existing `resident.refresh()` + `autopilot.build_outbox()` cycle;
- the thread reloads the last atomically persisted Observer snapshot and never receives or mutates Observer's live in-memory state;
- the async Observer loop only supervises the thread and remains free to schedule lobby/events reads;
- expected `RuntimeError` local refusals remain fail-closed as before;
- unexpected failures surface back to the daemon rather than silently disabling maintenance;
- shutdown does not wait for a long scoring cycle because the maintenance thread is daemonized and its local writes are atomic.

## Safety boundary

This change adds no Technocore write, signer access, secret access, shell/subprocess execution, URL following, tclk Phase 2 behavior, controlled E2E, or Contribution #2 activity.

## Acceptance

Production rollout remains Resident-only with Autopilot paused and Signer/Discord untouched.

The first acceptance baseline is the last PR #74 steady-state failure state:

- core events: 99
- core messages: 4,274,148
- latest gap: lobby `retained_ring_start` +1,690 at `2026-09-07T11:59:15.295226Z`

Acceptance requires zero new core unrecoverable events/messages after the new Resident starts, plus unchanged Signer PID/NRestarts and queue/receipt invariants. Only after continuity is stable may bounded Autopilot resume.
