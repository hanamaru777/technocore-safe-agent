# Issue #57 — events startup live retry before retained export

## Production evidence

PR #80 passed its initial warm and 5-minute paused gates, then failed the 10-minute Autopilot guard. Post-failure evidence showed:

- core unrecoverable counters unchanged at `114 / 5,000,710`
- lobby health `ok`
- lobby capture advancing with no capture error
- Resident, Discord and Signer active with no restart drift
- Autopilot fail-closed back to paused
- `events` health repeatedly returning `startup_export_TotalTimeout` / `startup_export_ConnectTimeout`

This means the blocker is not a new core loss event. The events startup path can remain trapped in the full retained-export guard after its initial bounded live probe encounters transport uncertainty.

## Fix

For persisted `events` only:

- keep using zero-wait GET-only live probes from the persisted cursor
- when a probe transport request fails, mark current events health as `startup_live_probe_<error>`, keep the cursor unchanged, wait briefly, and retry another bounded live probe
- do **not** escalate a transport-error probe directly to full retained export
- only a successful live probe that proves an actual sequence hole may fall back to the retained-export startup guard
- a successful contiguous/empty probe marks events healthy and enters the normal worker
- lobby remains export-first

This preserves fail-closed semantics while avoiding a known-pathological export path when there is not yet evidence that an export is required.

## Acceptance correction

A Production warm gate is valid only if the current Resident restart produced a new `startup_live_probe_successes` increment for events (or a real proven gap completed through retained export). Merely reading persisted `events=ok` is not sufficient because that value can predate the current startup attempt.

## Safety

- GET-only Observer change
- no Technocore write
- no Signer/transport change
- no shell or untrusted execution
- no URL following
- no tclk Phase 2
- Autopilot remains paused until Production acceptance
