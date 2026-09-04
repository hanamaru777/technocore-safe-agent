# Source-backed FLOP Onboarding Helper v1

Issue: #61

## Purpose

Answer only a narrow set of FLOP/Technocore onboarding and safety questions from reviewed, pinned public sources. This is not a general chatbot and does not infer reward, snapshot, TGE, current-event, or unpublished protocol facts.

## Registry

`knowledge/registry-v1.json` is the public source-of-truth. Every topic records:

- deterministic topic id
- official or project-approved source ids
- repository + pinned 40-hex commit + path
- source review timestamp
- freshness class (`stable` or `time_sensitive`)
- whether the already-running fixed Signer can render that topic

Runtime code never follows source URLs. Updating a source requires a reviewed Git change.

Initial signed-ready topics reuse the exact existing isolated-Signer renderers:

- `nonce`
- `did_signature`
- `technocore_api`
- `prompt_injection_safety`
- `repo_tests_bugs`
- `agent_use_case`

`tclk_alpha` is intentionally read-only. Its status is time-sensitive and fails closed after seven days until re-reviewed. It is not added to the Signer protocol surface.

## Trust boundary

The isolated Signer is unchanged. Its topic enum, transport schema, deterministic text templates, Vault access, no-blind-retry behavior, and rate limits remain intact.

Resident installs `knowledge_guard`: if a registered signed topic is stale, missing, or invalid, that candidate becomes ineligible with `knowledge_source_stale_or_unverified`. Generic non-registry collaboration lanes are not silently converted into source-backed claims.

## Discord

`/knowledge`

Shows registry health, verified topic count, signed-ready count, and stale topics.

`/knowledge <topic>`

Shows source ids, authority, pinned repo/commit/path, freshness, and the exact fixed answer preview. A stale time-sensitive topic shows `BLOCKED` and no answer preview.

`/candidate <id>`

Keeps the existing candidate detail and appends the source-backed topic/source ids when one is safely identifiable. It never reflects arbitrary candidate text into the knowledge suffix.

## Evidence

After an existing fixed-renderer answer is acknowledged, the Discord reconciliation path records a bounded local provenance entry under `$FLOP_STATE_DIR/knowledge/knowledge-use-audit.json`:

- intent id
- topic
- registry id
- source ids
- SHA-256 of the deterministic answer
- acknowledgement timestamp

This is evidence metadata only. It stores no seed, key, credential, raw room transcript, or arbitrary URL.

## tclk boundary

The pinned FLOP Labs tclk source is Alpha and `PaperRail` carries no real value at the reviewed source version. The Agent remains read-only for tclk; this feature does not add accept, offer, lock, claim, refund, payment, or settlement writes.

## Success metric

Success is not answer count. Measure useful replies to real questions, repeat inbound from helped counterparts, conversion into concrete collaboration, and zero unsupported factual replies.
