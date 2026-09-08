# Issue #57 — events startup live-first continuity proof

## Production evidence

PR #79 increased the `events` retained-export total wall-clock deadline from 20s to 90s, but Production still stayed fail-closed after a Resident-only restart:

- core health `degraded`
- `lobby=ok`
- `events=error`
- Autopilot remained paused

This shows that repeatedly increasing the export timeout is not a sound fix. The startup guard currently requires a full retained-ring export for every persisted core cursor before the normal live worker may run, even when the persisted `events` cursor may already be current.

## Fix

For persisted `events` only, perform one zero-wait GET-only live probe from the persisted cursor before attempting the full export.

The probe is accepted only when:

- it returns no messages, or
- its first returned sequence is exactly `cursor + 1` (or older/duplicate), so the bounded slice proves there is no unseen startup interval.

When accepted, process that bounded slice with the existing recovery stack, mark events healthy, and enter the normal live worker.

If the probe errors or its first sequence is greater than `cursor + 1`, do not advance the cursor and do not infer continuity. Fall back to the existing retained-export startup guard unchanged.

Lobby remains export-first.

## Why this is safe

The Technocore live endpoint returns the newest bounded tail. Therefore, if more than one live-page of unseen messages exists, the first returned sequence will be greater than `cursor + 1`, which forces the existing fail-closed export path. A contiguous first sequence proves the unseen backlog fits inside the bounded response and can be processed without skipping data.

## Safety

- GET-only Observer change
- no Technocore writes
- no Signer or transport changes
- no URL following or shell execution
- no tclk Phase 2
- Autopilot remains paused through Production acceptance

## Acceptance

After exact-SHA Resident-only deployment:

- `startup_live_probe_successes` increments for events, or a proven gap safely falls back to export
- events health reaches `ok`
- lobby remains `ok`
- no new unrecoverable core gap events/messages
- lobby capture continues advancing
- Signer and Discord PID/NRestarts stay unchanged
- only then may bounded Autopilot resume be tested
