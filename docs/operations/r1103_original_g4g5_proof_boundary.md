# R1103 — original OCI G4/G5 independent audit and versioned implementation contract
Date: 2026-10-30 JST. STATUS: DESIGN / SOURCE AUDIT ONLY. NO PRODUCTION AUTHORITY.

Base is PR #906 exact source HEAD 8af50b84a9a45e6a305cb9266cca9690239fa06e.
Issue #905 canonical real R1102 receipt: issuecomment-6514536165.
R1102 was executed exactly once; **never repeat R1102, old cleanup, or old resource probes.**

## Verified blockers and additional source-level findings

1. R1102 original-host LIVE count-only: 27 source unit templates; 19 recognized
   installed; 8 absent; 11 additional installed names (four historically known);
   22 loaded; 13 active; no observed dynamic TCLK instance; four cron objects,
   zero matched text; two relevant processes/four source FDs, **all four writable**,
   plus one raced/unknown descriptor. The single namespace match does NOT prove
   a global writer barrier. This is a diagnostic, not source export consent.
   The missing and extra unit names were intentionally not exported. Never
   infer exact identities from these counts or silently whitelist extras.
2. `packaging/migration/r1063_release_gates.py` G1 currently requires
   `extras_reviewed >= len(R1034_UNEXPECTED_NAMES)` = at least four. That
   synthetic metadata contract alone cannot certify the **11** extra names
   observed by R1102 or the eight missing expected templates. The R1063
   evaluator deliberately does NOT enroll production attestors or authorize
   cutover; do not upgrade its offline PASS to a production G1 proof.
3. `packaging/migration/r1089_migration.py` `SourceGuard.check` reads a
   root-owned renewal packet but tests only its own `statvfs(ST_RDONLY)`
   mount view (R1101). Its `/proc/*/fd` target-path filter cannot prove
   absence of alternate mount namespace paths or all hardlink/renamed/deleted
   writer aliases. Later census checks original hardlinks but do not establish
   all host-wide future launch denials. A read-only source-side process does
   not create the missing all-writer fence.
4. R1063 G5 `check_post_route` requires an external-role signed summary of
   `ACCEPTED` or `DEFINITELY_NOT_ACCEPTED` and a 64-hex acknowledgement
   digest. That is an **offline signed metadata contract**, not proof that
   any original real upstream endpoint issued an authoritative final verdict.
   No production upstream trust keys or authoritative receipt acquisition are
   enrolled. Do not let a source process attest its own upstream receipt.
5. Exact original source HEAD ec4bc4892d40cdd2a03e102faa44d72c89e01b99
   has five distinct signer/POST implementations:
   `src/flop_agent/oracle_signer.py`,
   `tclk_pilot_accept.py`, `tclk_pilot_reveal_publish.py`,
   `close1_approved_trade.py`, `close1_batch_trade.py`.
   Oracle signer records prepared/posted/acknowledged, and treats
   `submission_unknown` conservatively; TCLK accept/reveal validate POST
   responses and use separate read-only reconciliation; Close1 trade/batch
   create on-disk fence/receipt files and prohibit blind retries.
   These flows are **not one interchangeable upstream receipt type**.

## R1103-G4 required engineering, before any production fence is considered

A. New immutable versioned owner entrypoint only. Preserve exact R1089 owner
   workflow, source pins, four restored R1101 blobs and old test evidence.
   The old R1089 command is **not approved** for original production use.

B. Original-host authorization inventory must resolve the actual identities
   of all **11** extras and **8** missing expected units to operator-private,
   authenticated evidence, not printed to chat/GitHub. Enumerate complete
   effective systemd FragmentPath, DropInPaths, aliases, loaded and enabled
   states, ExecStart, ExecStartPre/Post, generators, timer links, Wants/Requires,
   PartOf/BindsTo, Restart and activation dependencies. Include system/user
   units, instance templates and dynamic TCLK, transient scopes/services,
   alternative schedulers, cron object type/content/interpreters, manual
   launch rights, startup/boot and all relevant external binary paths.
   The old four extras are a subset of eleven, not the eleven.

C. Implement a separately owner-approved reversible admission controller that
   first closes **all** relaunch/POST authority, then gracefully quiesces
   original writers, with rollback and recovery designed **before** stopping
   anything. A systemd stop alone is NOT proof: processes can survive,
   manual/restart paths exist, and aliases or alternative mount namespaces
   may still be writable. No general kill, mass disable or mount mutation is
   authorized by this document. The controller must not touch TradeBot.

D. Independently prove and continuously enforce zero remaining source writers,
   zero writable/directory FDs and zero unknown/raced/permission-obscured FDs,
   across mount namespaces, bind aliases, renamed/deleted-open files,
   hardlinks, relevant cgroups and unexpected launch paths. Re-check on
   each acquisition chunk and re-establish before any G6 capture. A private
   read-only view can be one necessary signal but never a sufficient one.
   If global absence or future denial cannot be independently proved,
   STOP, release no source bytes, preserve original state, require review.

E. Independent, fixed trust-root Ed25519 authority must sign exact host,
   original source HEAD, complete observed unit/launcher identity census,
   source roots, original DID, epoch/generation, barrier digest and
   fence-start. Root-owned 0700 directory / 0600 immutable packet,
   bounded lease, renewal <=30s; a source signer cannot attest its own G4.
   The owner signs a prior scoped reversible plan; any unexpected unit,
   process, new writer, lost lease, alias, evidence drift or timeout must
   fail CLOSED. Preserve original on-host recovery and isolated metadata
   guard without allowing it to publish or rewrite protected snapshot data.

## R1103-G5 required engineering

A. Freeze an exhaustive original outbox/pending/nonce/receipt/sidecar history
   for each of the five named routes, with DID and payload identity,
   multi-leg attempt identity, source epoch, and durable commit boundary.
   An empty local list is not proof of an empty upstream history.
B. For each route, independently read from the *actual authoritative upstream*
   using verified endpoint/identity, TLS/authentication and a pinned read
   interpretation for that route. Reconcile original intent/attempt/leg,
   did, room, nonce, payload/text, server-assigned seq and exact acknowledged
   result. A signed summary alone or an arbitrary acknowledgement hash cannot
   substitute for authenticated upstream evidence. Distinguish accepted,
   definitely-not-accepted, unknown and in-flight. Ambiguous timeout/HTTP
   failure, missing history or unverifiable absence is **UNKNOWN / NO_GO**.
   Never re-POST to test finality, never regenerate a nonce.
C. Independently attest five route-specific finality reconciliations to the
   same G4 barrier/epoch and state-ledger digest, excluding self-attestation.
   Validate completeness of historical ledgers as well as the five current
   upstream read windows; a single shared generic receipt cannot approve
   every route. Any pending/unresolved/duplicate attempt is NO_GO.
D. Before source export, obtain one common G6 epoch for both SQLite/WAL
   pairs and complete non-SQLite ledgers, authenticated under the renewed
   G4 barrier. A frozen-looking source without a common epoch is not G6.

## Next versioned source deliverables / fail-closed acceptance tests

1. Independently pinned G1 original-host authority identity manifest adapter.
   The R1102 counts are a blocker baseline only. Tests reject 4-of-11
   reviewed extras, missing identities, unresolved source-expected absences,
   unverified effective ExecStart/aliases, cron and transient launchers.
2. Independent G4 admission producer + renewal validator, with no source
   G4 self-signing, proof of all mount/FD/launcher boundaries, owner-approved
   reversible plan, lost lease and concurrent-writer race regressions.
   A test using private RO mounts and four live writable FDs MUST FAIL.
3. Five separate authenticated upstream G5 witness adapters and exact
   local-vs-upstream nonce/receipt reconciliation. Tests reject every
   route's unknown, missing, duplicate, timeout, hash-only acknowledgement,
   mismatched DID or generation; absolutely no outbound POST in tests/probes.
4. A new versioned Windows owner acquisition path to gate and invoke the
   unchanged R1089 encryption and K137 **DISARMED** restoration components.
   No consumed pin changes; test source acquire cannot start if any G4/G5
   input is absent, forged, stale, changing or user-self-attested.
5. Targeted local tests, then necessary PowerShell 5.1 regression and
   changed-head CI once. PR #906 remains draft. Live owner operation is
   a distinct authorization only after independent review and enrollment.

## Permanent decisions

G3=NO_GO; G4=NO_GO; G5=NO_GO; G6=NOT_PROVEN.
REAL_FULL_OFFHOST_BACKUP=NOT_CREATED; K137_DISARMED_RESTORE=NOT_PERFORMED.
CUTOVER=NO_GO; OCI_RETIREMENT=STRICT_NO_GO.

No original-host service/cron/mount, original key, AWS TradeBot, KMS/IAM,
billable resource, disk contents, owner SSH or POST action is changed
or authorized here. No new user command is requested. R1095 and R1097
production receipts and R1102 consumed survey remain accepted and
never repeated.
