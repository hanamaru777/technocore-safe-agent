# Issue #49 performance invariants

This branch fixes production state-growth and hot-loop regressions without changing outbound trust or signer boundaries.

Required invariants:

- no Technocore write is added by the performance work
- Signer and metadata isolation remain unchanged
- candidate approval, first-contact trust, rate limits, DLP, and controlled-E2E semantics remain fail-closed
- repeated unchanged Autopilot decisions do not append audit records every daemon cycle
- durable audit evidence is retained in bounded rotated segments
- recent 24h decision presentation uses compact state rather than scanning a multi-GB audit file
- paused Resident refresh can use a small heartbeat and cannot be overwritten by an in-flight stale state save
- routine Discord status/notices use small heartbeat/cached revisions instead of repeatedly parsing large Observer/Resident JSON state
- idle successful Observer polls do not force a full state rewrite merely to update a success timestamp
- the 5,000-Agent hard cap evicts one weakest Agent without a full-state compaction for every new DID

Production remains on the rollback/containment state until CI, review, and a targeted deployment gate are complete.
