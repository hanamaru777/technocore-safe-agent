# Issue #57 single-snapshot recovery hardening

Production evidence on 2026-09-05 showed the retained-ring recovery path working but still losing messages under sustained load. The accepted recovery implementation fetched a full `/r/<room>/export` snapshot, processed at most 2,000 missing records from it, discarded the snapshot, then repeated a live read plus another full export for the same logical gap.

This hardening keeps the same read-only and safety boundaries while changing catch-up behavior:

- one retained-ring export is treated as one immutable recovery snapshot;
- all contiguous recoverable records up to the current live slice are drained from that snapshot in bounded 2,000-message in-memory chunks;
- the event loop yields between chunks, but no additional network/read-budget token is consumed for those chunks;
- only intervals absent from the snapshot are marked unrecoverable;
- an internal snapshot hole marks only the missing interval, then later retained records continue to recover;
- durable counters distinguish `retained_ring_start` from `not_in_retained_export` loss;
- no local read-budget increase is included in this change;
- no Signer, Autopilot write, tclk Phase 2, controlled E2E, or Contribution #2 behavior changes.

Production acceptance must keep Autopilot paused, restart Resident only, keep the Signer PID/NRestarts unchanged, and verify zero new unrecoverable loss during a bounded observation window before normal Agent writes are reconsidered.
