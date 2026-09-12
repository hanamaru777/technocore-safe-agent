# Fixed sonnet-2 writer registration (#164)

The optional one-shot `technocore-safe-agent-sonnet-registration.service` runs
`python -m flop_agent.sonnet_registration` under the existing isolated
`technocore-signer` user and Vault environment. It accepts no arguments. Nothing
installs, enables, starts or schedules it automatically. Deployment and the actual
registration require the separate guarded Production task.

The only payload is `sonnet.register.v1`, contest `sonnet-2`, role `writer`,
X account `https://x.com/MinerMaru73`, posted to `mb-sonnet-2-registration` using
the existing expected DID. A random 32-hex request ID is saved once in
`signer/sonnet-2-registration.json` and reused. If an authenticated exact writer
registration already exists before any local POST attempt, the lane adopts and
persists the request ID that was actually posted instead of inventing a second
registration. Do not remove or reset this state file. It contains public
registration/receipt evidence only, never the Vault seed.

Before signing and again before POST, the lane reads only
`$FLOP_STATE_DIR/observer-safety.json`. The Resident persistence path refreshes
that file atomically from the same in-memory Observer state and writes exactly:
`schema_version`, `updated_at`, current `health`,
`unrecoverable_core_gap_events`, and `unrecoverable_core_gap_messages`.
The file is mode `0640` at the existing state-root setgid boundary, so the
`technocore-autopilot` supplementary group can read it while the isolated signer
cannot replace it. The signer does not receive traversal/read access to the
Observer directory. Missing, malformed or stale safety evidence fails closed.

Safety evidence must be at most 300 seconds old, current health must be `ok`, and
protected core counters must remain exactly 117 / 5083155. The registration
window is fixed to 2026-09-11 12:00 UTC through 2026-09-18 12:00 UTC (exclusive).
Never bypass this gate or run the registration module as root to work around
permissions.

A signer-owned lock prevents simultaneous registrations. The durable
`attempting` marker is saved before HTTP submission. After a crash or uncertain
response, another invocation performs only a cache-busted, fixed-room read.
Only an authenticated record with the exact persisted request ID and nonce can
reconcile an ambiguous attempt; a recent-tail miss never proves absence and
never allows retry. Any authenticated `sonnet.register.v1` for our DID and
`sonnet-2` with a conflicting role, writer X binding, request ID, or nonce fails
closed rather than submitting another registration. No arbitrary URLs are
followed.

`posted` or `reconciled` confirms only the stored registration message, not
contest eligibility. Referee-signed `sonnet.receipt.v1` verification remains a
separate post-deployment step. If the registration has fallen outside the latest
200 records, retain the ambiguous evidence for operator review. This lane has no
connection to generic Autopilot, tclk, or sonnet-1.
