# Issue #57 — core startup transport + lobby fallback health recovery

## Production evidence

Combined PR84+85+86 Production cutover reached exact main
`2b405b6e8bf17921d2ba8ad75fa165da017bf3e8` with Autopilot still paused.
The warm gate failed without any new core loss:

- core counters remained `115 / 5,030,095`
- lobby health remained `HTTPStatusError`
- events health remained `startup_live_probe_TotalTimeout`
- independent lobby capture was healthy and advancing
- lobby startup spool attempted once, with no startup prefix available at that exact cursor
- events startup probe had repeated unsuccessful startup attempts and never reached normal steady processing

## Proven control-flow defects

### Lobby

The base room worker records the live-read error before invoking
`recover_after_live_error()`. The installed local-spool/server fallback chain can
then succeed, but the worker does not call `set_success()` on that successful
fallback result. A stale red lobby health record can therefore survive while the
independent capture path is healthy and continuity is still being maintained.

The fix clears lobby health only when the already-installed fallback chain returns
with no error. Failed or uncertain fallback remains red.

### Events

The events startup live probe intentionally retries a transient transport failure.
That policy was added before incremental streaming startup recovery existed.
Production now shows that the probe itself can remain unavailable long enough to
pin startup.

The fix keeps one cheap retry, then after two consecutive non-rate-limit transport
failures switches to the already-reviewed incremental streaming startup path.
Rate-limit responses continue to obey Retry-After and never trigger an additional
export request.

## Safety invariants

- read-only recovery paths only
- no Technocore write
- no Signer or transport change
- no tclk Phase 2 change
- no secret access
- no shell execution or URL following
- no historical counter rewrite
- no silent gap skipping
- Autopilot remains paused until Production acceptance passes
