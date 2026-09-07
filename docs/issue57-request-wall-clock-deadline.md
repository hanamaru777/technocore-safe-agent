# Issue #57 — hard wall-clock deadline for Observer reads

## Production evidence

PR #72's immediate export fallback did activate in Production, but the steady-state gate still failed:

- post-startup baseline: core events `92`, core messages `3,658,645`
- later snapshot: core events `95`, core messages `4,117,534`
- steady-state delta: `+3` core events / `+458,889` core messages
- latest loss: `lobby`, `retained_ring_start`, `154,428` messages
- live-error fallback: attempts `1`, successes `1`, recovered `30,583`, failures `0`
- lobby health still carried a `ConnectTimeout` stamped `2026-09-07T08:24:54.754798Z`
- latest lobby unrecoverable loss was stamped `2026-09-07T10:37:11.276163Z`

The timing strongly indicates that a single fallback/export request could remain in flight far longer than the intended HTTP read timeout. HTTPX read timeouts bound inactivity between chunks, not the total wall-clock lifetime of the response. A slowly trickling retained-ring export can therefore keep the lobby worker occupied while the hot room continues advancing and old retained rows disappear.

## Change

Wrap the existing live-room and retained-ring export coroutines in a hard total wall-clock deadline using `asyncio.wait_for`.

- live request total deadline: 20 seconds
- export request total deadline: 20 seconds
- deadline result: `TotalTimeout`
- the existing retry/cursor safety rules then handle it exactly like another read failure
- no cursor advance occurs merely because the wall-clock deadline fired
- a cancelled slow request is retried instead of pinning the room worker indefinitely

This is layered with the startup export catch-up in the same PR so one Production cutover can cover both failure classes.

## Why this is bounded and necessary

Current Technocore room reads return a newest-tail window capped at 200 messages, while `/export` is the retained-ring recovery path. Upstream issue #481 documents that hot-room consumers can fall behind the 200-message tail in seconds. Upstream issue #775 also documents multi-megabyte exports and intermittent Service Unavailable responses. A recovery request therefore needs both retry semantics and a true total lifetime bound.

## Safety invariants

- GET-only Observer path
- no Signer import/use/restart
- no POST/write behavior
- no Autopilot transport change
- no tclk Phase 2 behavior
- no untrusted URL following or command execution
- existing exact retained-prefix/unrecoverable accounting is preserved
