# Issue #57 — core lobby continuity hardening

Production attribution from PR #70 proved the remaining unrecoverable loss is on the core lane, not the optional tclk lane. The latest durable sample was `lobby`, `retained_ring_start`, 14,016 messages. Production also showed intermittent `ConnectTimeout` / recovery timeout errors while the published server read limit was 600 requests/min and the local Observer was capped at 300/min.

This hardening keeps Technocore access read-only and makes three bounded changes in the production resilience overlay:

1. The hot `lobby` worker never sleeps more than one second after a successful non-full slice. A full 200-message slice still drains immediately.
2. Live room reads fail connection establishment quickly (3s) while retaining a 15s read timeout so the supported `wait<=10` long-poll remains valid. Retained-ring export keeps a 20s read timeout but also uses a 3s connection timeout.
3. Non-rate-limit core read failures use a bounded 5s exponential backoff. A failed gap-recovery export remains visibly degraded and retries after 1s instead of being immediately overwritten by `set_success()` and then sleeping a normal room interval. Optional tclk failures remain isolated.

The patch does not change cursor semantics, retained-ring accounting, Signer/Autopilot/write paths, Discord notification semantics, or the configured read budget. Production should remain at 300 reads/min and Autopilot must stay paused during acceptance.

Acceptance focuses on new durable core-gap counters, not historical totals: no increase in `unrecoverable_core_gap_events/messages` over the bounded observation window, unchanged Signer/Discord continuity, queue 0 / receipts 2, and no rate-limit errors introduced by the faster lobby cadence.
