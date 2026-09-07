# Issue #57 — post-restart gap observation after PR #72

Date: 2026-09-07 JST

The first post-deploy snapshot after PR #72 was captured at 2026-09-07T05:51:34Z. Resident start time was 2026-09-07T05:44:40Z, so this was only about 6 minutes 54 seconds after restart and must not be treated as a 6-hour steady-state acceptance window.

Observed after restart:

- `unrecoverable_core_gap_events`: 91 -> 92
- `unrecoverable_core_gap_messages`: 3,534,241 -> 3,658,645
- new loss: `lobby`, `retained_ring_start`, 124,404 messages
- loss observed_at: 2026-09-07T05:44:48.103480Z
- Resident started at 2026-09-07T05:44:40Z
- live-error export fallback counters all remained zero
- no new fallback attempt was triggered
- Signer/Discord stayed unchanged
- Autopilot remained paused, queue 0, receipts 2

Interpretation:

The new gap was detected roughly 8 seconds after Resident restart. Because all live-error fallback counters stayed at zero, this event did not exercise PR #72's live-read-error fallback trigger. The most likely interpretation is a restart/startup catch-up gap or a latent pre-restart hole first exposed by the initial successful live read. It is therefore not valid evidence that PR #72 failed during steady-state live-error handling.

Acceptance is split into two independent questions:

1. steady-state continuity: after this startup event baseline (core events 92 / core messages 3,658,645), does PR #72 prevent new core loss during natural running, especially when fallback counters activate?
2. restart continuity: even if steady-state passes, a separate startup/restart catch-up hardening may be needed because PR #72 only activates after a live read fails, not before the first successful post-restart live read.

No Production changes are authorized by this note. Keep current HEAD deployed, keep Autopilot paused, and do not restart Signer/Discord. Observe naturally from the post-startup baseline before deciding whether startup-specific hardening is required.