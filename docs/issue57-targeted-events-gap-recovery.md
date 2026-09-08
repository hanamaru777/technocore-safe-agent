# Issue #57 — target events export to the proven gap

## Production evidence after PR #83

PR #83 never reached its steady-state overlay during the failed warm gate.

Current Production evidence on `9535a6e68a68e17fb8ab59d8d0fc325dad4a962b`:

- core unrecoverable counters remain `114 / 5,000,710`
- events health is `startup_live_probe_gap`
- persisted events cursor is `334469`
- current live probe first unseen sequence is `335245`
- the exact proven startup gap is therefore `334470..335244` (775 messages)
- startup live probes: `4 attempts / 0 success / 4 fallback / 0 transport failure`
- startup stream exports: `2 attempts / 1 success / 0 failure / 680 recovered`
- PR #83 steady stream metrics remain all zero

Conclusion: the current blocker is still startup. The second streaming export is active but the existing helper consumes the snapshot until EOF and only flushes a sub-2,000 pending tail at EOF. That is unnecessary once the live probe has already given an exact recovery endpoint.

## Fix

Install one read-only overlay after PR #83:

- parse the existing `startup_live_probe_gap` record and derive `first_unseen - 1`
- keep the official snapshot-at-open export and existing validation, but present a clean logical EOF exactly when that sequence is reached
- if the stream passes or ends before the required endpoint, fail closed as `target_not_in_export`
- steady-state live-gap recovery uses the same exact endpoint from the first live sequence
- a steady events transport error launches no untargeted export; it keeps the cursor fixed and retries the cheap live read after normal backoff
- once a later live read proves a real gap, targeted streaming handles that exact range
- lobby behavior is unchanged

## Safety

- GET-only Observer behavior
- no Technocore write
- no Signer or transport change
- no shell execution or URL following
- no secret access
- no tclk Phase 2
- no gap is silently skipped
- Autopilot remains paused through Production acceptance
