# Issue #57 — lobby spool catch-up race

## Production evidence

After PR #83, a new core lobby gap was recorded while Autopilot was paused:

- core unrecoverable counters `114 / 5,000,710 -> 115 / 5,030,095`
- room `lobby`
- missing range `35,381,425..35,410,809`
- `29,385` messages
- reason `retained_ring_start`

A later direct read of the independent local SQLite capture spool proved:

- `range_complete(35,381,425, 35,410,809) == true`
- `contiguous_from_start == 35,483,832`
- capture healthy, no current error
- the only stored `last_capture_hole` remains the older startup hole `34,910,575..34,984,304`

This means the range now exists completely in the shock absorber even though the
main Observer already counted it unrecoverable. The existing lobby overlay checks
`range_complete()` only once at the instant a live-tail gap is discovered. If the
independent capture process is a fraction behind, the main Observer immediately
falls through to the moving server retained ring and can permanently classify the
gap before the local rows finish committing.

The evidence does not prove the spool was already complete at the exact loss
timestamp, so this is treated as a local catch-up race rather than a historical
counter rewrite.

## Fix

For an exact live-proven lobby gap:

- drain any contiguous SQLite prefix immediately instead of requiring the whole
  range to exist first
- wait at most 5 seconds for the independent capture process to finish the exact
  interval, polling locally every 250 ms
- if the range becomes complete, process the live payload without a server export
- if the grace expires, preserve all locally recovered prefix progress and delegate
  only the remaining suffix to the existing server-ring fallback
- add durable metrics for waits, successes, timeouts, and partial local recovery

The capture process runs at 250 reads/minute (~240 ms cadence), so the grace allows
multiple independent capture attempts while remaining bounded.

## Safety

- GET-only Observer/capture behavior
- no Technocore write
- no Signer or transport change
- no tclk Phase 2 change
- no shell execution or URL following
- no secret access
- no silent gap skipping
- no retroactive decrement of historical unrecoverable counters
- Autopilot remains paused through Production acceptance
