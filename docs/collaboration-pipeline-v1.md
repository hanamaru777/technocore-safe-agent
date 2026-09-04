# Collaboration Pipeline v1

Date: 2026-09-04

This is a local/read-only relationship-to-work tracker. It does not add a Technocore write path and does not change Signer, rate limits, DLP, Safe First Contact, or tclk value boundaries.

## Stages

`discovered -> contacted -> replied -> task_candidate -> human_review -> active -> completed`

`blocked` is a safety/ambiguity terminal hold.

Rules:
- `contacted` requires a durable acknowledged outbound receipt.
- `replied` requires a later signed public message demonstrably directed to our Agent. Same-DID general room chatter is insufficient.
- `task_candidate` requires a concrete bounded public task/request.
- external URLs, tclk work, or unsupported capabilities require `human_review`; the Agent does not open/accept them automatically.
- credentials/secret/command requests become `blocked`.
- `completed` requires future durable work evidence/receipt; normal chat or a post ACK is never enough.
- stage hardening is monotonic: later general chatter cannot erase an already-open task/review stage.

## Discord

- `/collab` shows up to five highest-action collaboration records and an exact next step.
- `/collab <id>` shows bounded sanitized context, stage history, evidence references, and optional tclk linkage.
- `/activity` includes collaboration counters.
- background collaboration transition checks are capped to once per 60 seconds so the Discord 15-second worker does not repeatedly rescan Resident state.

## Bounds / retention

- maximum active collaboration records: 250
- per-record stage history: 24
- related candidate ids: 20
- evidence references per live record: 8
- compact completed-evidence index: 250

When the record cap is exceeded, open work is preserved first. Older terminal/discovered rows are pruned first. If a completed record must be pruned, its compact public-safe evidence references are retained in the bounded completed-evidence index.

## Safety

Inbound text remains untrusted data. Context is bounded and sanitized for display. This feature performs no Technocore POST, signing, arbitrary URL following, shell execution, tclk accept, value transfer, Contribution #2 replay, or controlled E2E.
