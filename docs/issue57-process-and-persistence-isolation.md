# Issue #57 — process + persistence isolation

Date: 2026-09-08 JST

## Production evidence after PR #75

PR #75 isolated Resident maintenance onto a Python thread and passed its 120-second initial gate, but long-run Production still lost core lobby continuity before Autopilot was allowed to resume.

Accepted PR #75 cutover baseline:

- core events: 101
- core messages: 4,471,382
- Autopilot paused

Pre-resume gate at `2026-09-07T22:41:27Z`:

- core events: 112
- core messages: 4,753,073
- delta: +11 unrecoverable events / +281,691 messages
- guarded resume refused to unpause Autopilot

PR #75 therefore failed the long-run Production acceptance gate.

## Remaining local blocking surfaces

Two local mechanisms remain capable of delaying hot-room reads even without a lobby HTTP error:

1. Resident maintenance is CPU-heavy Python work. A Python thread still shares the CPython GIL with the Observer event loop, so moving work to a thread is not CPU isolation.
2. `StateWriter.flush()` still performs full Observer compaction, JSON serialization, file write and fsync synchronously on the same asyncio thread. The Production Observer state is multi-megabyte at the retained Agent bound.

The prior Issue #49 performance work already established that routine hot paths must avoid repeated whole-state work. Per-message retention and the hard Agent cap are already enforced when messages mutate the in-memory state.

## Fix

This change removes both remaining local blocking surfaces without changing any outbound policy.

### Resident process isolation

- replace the maintenance thread with one spawned Python process;
- child reloads only atomically persisted local state;
- positive niceness lowers scheduling priority relative to the Observer;
- parent supervises child exit and fails closed on unexpected termination;
- bounded shutdown prevents systemd from waiting on a long scoring cycle.

### Observer persistence isolation

- preserve one live in-memory Observer writer;
- serialize one consistent snapshot without yielding to mutating tasks;
- avoid recursive key sorting for state data because state JSON is not a canonical signed artifact;
- move file write/fsync to a worker thread after serialization;
- generation counter prevents mutations arriving during I/O from being incorrectly marked clean;
- whole-state compaction runs only when a configured bound is actually exceeded instead of every tenth write.

## Safety boundary

- read-only Technocore behavior unchanged
- no Signer import, restart, transport or write change
- no shell or untrusted command execution
- no URL following
- no tclk Phase 2
- no Controlled E2E rerun
- no Contribution #2 rerun
- Autopilot remains paused until Production continuity is accepted

## Production acceptance

After CI and merge:

1. exact-SHA Resident-only cutover;
2. Signer and Discord PID/NRestarts unchanged;
3. Autopilot remains paused;
4. capture a fresh post-cutover core baseline rather than reusing historical counters;
5. zero new core unrecoverable events/messages through the steady gate;
6. only then resume Autopilot under fail-closed guard;
7. long-run zero-gap evidence is required before Issue #57 closes and X post #4 is unblocked.
