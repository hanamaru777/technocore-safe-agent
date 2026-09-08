# Issue #57 — streaming events startup export

## Production evidence

PR #81 reached the exact decision point it was designed to distinguish:

- core unrecoverable counters remained `114 / 5,000,710`
- startup live-probe attempts increased `1 -> 2`
- startup live-probe successes stayed `0`
- startup live-probe failures stayed `0`
- startup live-probe fallbacks increased `1 -> 2`
- startup full-export attempts increased `33 -> 36`
- lobby stayed healthy while events stayed red
- Autopilot remained paused

A current-run events live probe therefore completed at the transport layer but proved a real sequence hole relative to the persisted cursor. Export fallback is required. The failure is now specifically the all-or-nothing client export path: it waits for the complete retained body before processing any row, while Production repeatedly times out before that body completes.

## Upstream contract used by this fix

The official `flop-labs/technocore-chat` implementation documents and implements `/r/<room>/export` as:

- the retained room JSONL exactly as stored
- snapshotted when the file is opened
- emitted forward from the retained start
- streamed in `64 KiB` chunks
- bounded by the room retention ceiling (`10 MiB` in the referenced upstream implementation)

Because the open file descriptor keeps reading the snapshot inode even if later compaction replaces the room file, incremental client consumption does not race a moving snapshot.

## Fix

Only the persisted core `events` startup path changes after a successful live probe proves an actual gap:

- open the official export as an HTTPX streaming GET
- validate each non-empty JSONL record before use
- require strictly increasing sequence numbers from the upstream stored stream
- ignore already-processed rows at or below the current cursor
- drain new contiguous rows through the existing recovery/accounting path in bounded chunks
- advance the cursor only through validated rows actually received
- retain the existing export byte ceiling and connect/read inactivity timeouts
- if the stream fails after bounded chunks were processed, keep that safe cursor progress and retry fail-closed from there
- if retained history begins after the required cursor, the existing unrecoverable-gap accounting remains authoritative; the gap is not hidden

Lobby startup remains unchanged and export-first.

## Safety

- GET-only Observer change
- no Technocore write
- no Signer/transport change
- no shell execution
- no URL following from untrusted content
- no secret access
- no tclk Phase 2
- Autopilot remains paused until Production acceptance
