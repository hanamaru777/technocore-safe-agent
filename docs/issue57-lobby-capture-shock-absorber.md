# Issue #57 — lobby capture shock absorber

Date: 2026-09-08 JST

## Why PR #76 still failed

PR #76 successfully separated Resident maintenance into another process and moved Observer disk/fsync off the asyncio loop. The 120-second startup gate was clean, but the following 10-minute Production window still produced one unrecoverable lobby hole of 173,907 messages while Autopilot was paused.

Production evidence:

- PRE / steady baseline: 112 core events / 4,753,073 core missing messages
- 120-second cutover delta: 0 / 0
- 10-minute steady delta: +1 event / +173,907 messages
- latest range: lobby `34,662,010..34,835,916`
- reason: `retained_ring_start`
- Observer parent remained CPU-heavy even after Resident CPU was process-isolated

This means local maintenance isolation alone cannot guarantee that the rich Observer consumes a hot public burst before the server retained ring compacts.

## Design

Add a second, cheap, read-only lobby capture lane as a shock absorber.

- runs in its own supervised Python process;
- GET-only; no signing, posting, shell, URL following or secret access;
- polls the official lobby tail with `limit=200`, `wait=0`;
- bounded to 250 reads/minute;
- current main Observer runtime budget is 300 reads/minute, so the combined local maximum remains 550/minute, below the published 600 reads/minute/IP ceiling;
- stores recent public lobby rows in a bounded local SQLite spool (300,000 rows);
- uses the official retained-ring export only when the capture lane itself sees a live-tail hole;
- if a capture-side hole is already permanently outside the retained ring, records that fact locally and continues protecting future rows.

The main Observer keeps its existing semantics. When its live tail reveals a lobby hole, it first checks whether the entire missing interval is present in the local spool. If yes, it replays that exact contiguous evidence before touching the moving server retained ring. If local coverage is incomplete, it falls through to the existing retained-ring recovery logic unchanged.

A live-read failure can likewise advance from contiguous locally captured rows before the server export fallback.

## Safety

- no Technocore write changes
- no Signer import, restart or transport changes
- no tclk Phase 2
- no Controlled E2E or Contribution #2 rerun
- public room text remains untrusted data
- capture process death is supervised and fails the Resident service closed
- Autopilot remains paused through Production acceptance

## Acceptance

After CI and merge:

1. exact-SHA Resident-only cutover;
2. Signer and Discord unchanged;
3. confirm two auxiliary child processes: low-priority maintenance + lobby capture;
4. confirm capture spool cursor/row count advances;
5. establish a fresh post-cutover core baseline after startup settle;
6. zero new core unrecoverable events/messages through a meaningful natural Production window;
7. only then resume Autopilot under fail-closed guard;
8. long-run zero-gap evidence is still required before Issue #57 closes and X post #4 is unblocked.
