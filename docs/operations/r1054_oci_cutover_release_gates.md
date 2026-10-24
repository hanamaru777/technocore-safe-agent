# R1054 — FLOP original OCI → existing AWS: finite release gates and no-delete protocol

Date: 2026-10-24 JST
Status: SOURCE/DESIGN ONLY; DRAFT; DO NOT MERGE, DEPLOY OR RUN AGAINST PRODUCTION
Parent: Issue #842; canonical Issue #765 v234 comment 6380634039.
Source baseline: original OCI observed app HEAD ec4bc4892d40cdd2a03e102faa44d72c89e01b99 (historic observation, never assumed current).
This file authorizes NO service, timer, filesystem, security, IAM, OCI, AWS, signer or TradeBot changes.

## Outcome at creation
all_writers_fenced=NO
signer_inflight_post_resolved=NO
capture_common_epoch_proven=NO
authenticated_offhost_full_restore=NO
aws_same_did_live_signing=NOT_PROVEN
k137_mixed_load_safe=NOT_PROVEN
oci_retirement=STRICT_NO_GO

Do not promote evidence produced by source-only GitHub Actions into a guest/runtime/financial gate. Old PASS/FAIL is consumed: R1034/R1039/R1041, K137 R1044–R1048, R1045 metadata, AWS Phase01/02/03C, PR #876–#881/#887/#888/#890. Never rerun them for convenience. PR #889 failed and closed; preserve its history.

## Finite dependency order

G0 — Confirm the host and scope before ANY future operation.
Evidence: independent fresh read-only identity of original Flop OCI instance versus the DIFFERENT Aerodrome/TradeBot OCI VM; inventory of Flop-owned mount/filesystem roots, original application HEAD, immutable original owner, GitHub exact source ref and branch. Attestor identity, capture clock and output digest must be retained outside the original host. STOP if host ID differs, any unknown owner boundary, missing source pin, changed code, privileged unrelated component or untrusted provenance. No cleanup on either OCI machine.

G1 — Resolve the unsafe unknown authority surface before designing a production fence.
Evidence MUST enumerate original 27 source templates (19 service, eight timer; two dynamic TCLK @ templates) AND actual installed/enabled/active/activating/transient/manual/timer/restart instances, all matching systemd cgroups/processes/open writable descriptors, system and user cron, nonregular cron objects, boot-triggered units and four R1034 unknown units. Do not infer no writer from inactive at one instant or source presence alone. Explicitly identify effects of postreboot-check.service and close1-discord-activation.service, dynamic TCLK instance count and every unknown ExecStart. Distinguish read-only proof of absence from a partial scan; ambiguous/missing permission/timeouts => STOP. Never disable metadata-block.service, host security or unrelated services. Already observed earlier: 26/27 expected installed, eight timers active, five TCLK services activating, four more installed, incomplete cron and process inventory. Not a durable fence.

G2 — Prepare a RECOVERY-CAPABLE destination BEFORE stopping source.
Evidence: a reviewed resource profile and disarmed isolated test with observed K137 public timer natural workload and prospective Flop capped CPU/RAM/PSI/disk; authenticated non-production receiver with physically measured free bytes adequate for full source plus compression worst-case, encrypted temporary bytes, both SQLite images, safety margin and rollback. K137 2vCPU/2GB/no swap with protected TradeBot public H1 gap is NOT a validated storage/compute destination. Do not write any K137 finance paths, change its timers or replay historical H1. Prior source estimate >=3017 regular files / about 19.523GB allocated with unresolved roots/links is INCOMPLETE and not an actual logical byte count. Individual shard limits of 512 records, 6GiB and 3GiB segments plus 64-shard plan must still be satisfied. Source and archive verification must not consume Cloud Shell quota or violate the >=20GiB ingress headroom rule from PR #881. STOP for insufficient verified capacity, no authenticated offsite endpoint/independent key custody, unsupported target role, missing rollback storage or any K137 public safety degradation. No implicit paid disk or host authorization.

G3 — Prove portable authentication and retained original DID outside production publication.
Five source-authored signer/POST routes: oracle_signer; tclk_pilot_accept (dynamic); tclk_pilot_reveal_publish (dynamic); close1_approved_trade; close1_batch_trade. All require an independent future ingress/drain fence. Original oracle_signer uses OCI InstancePrincipalsSecurityTokenSigner + OCI Vault CURRENT: NOT portable unchanged to AWS. AWS Lightsail iam/info HTTP200 is not IAM role or STS GetWebIdentityToken proof. AWS outbound workload federation needs regional STS, authorized IAM principal/permissions and account feature; OCI RPST JWT exchange requires separately authenticated token-exchange client (or OCI principal). Documented OAuth confidential client commonly requires a long-lived client secret. Select ONE reviewed custody boundary only after actual entitlement/credential lifecycle, issuer/subject/audience/expiry, least privilege, total cost and compromise blast radius are established. No IAM/OAuth app creation, seed export, wallet operation, live DID signing, signer dependency install or new billing from this gate. Verify exact retained DID against trusted original public DID in an independently disarmed environment, not by publishing to a live upstream. If no acceptable signer custody exists: signer migration and OCI retirement STOP; optional AWS GET-only shadow does not imply complete relocation.

G4 — Owner separately approves a one-time source authority admission FENCE, after G0–G3.
Prepare a SHA-pinned, host-identity-guarded, bounded operation with independent preflight, fixed expected unit census, denial of NEW manual/templated/cron/timer/boot/approval/POST starts, and recovery plan; use one durable fence generation ID. First protect against new ingress and manual acceptance. Do NOT kill ongoing activity before its terminal state is classified. Quiescence cannot be inferred from simply stopping signer.service or pausing autopilot. Before owner approval this remains ONLY a design; no executable stop recipe is authorized by this document. If unexpected active authority, change during admission, untrusted relaunch capability or metadata-block state drift: STOP, do not proceed to backup.

G5 — Resolve EVERY pending external POST and create a global all-writer barrier.
For each of the five entry points and every dynamic instantiation, produce independent upstream-authoritative verdict for each attempt: ACCEPTED, DEFINITELY_NOT_ACCEPTED, or AMBIGUOUS. Bind exact original DID, nonce, request/attempt ID, per-leg Close1 receipt, local receipt state and external acknowledgment. AMBIGUOUS is a hard HOLD; never resend or synthesize an answer. Original R1041 locally paired two quarantined controlled E2E records and active/ambiguous outbox0; it did NOT confirm upstream acceptance/inflight for all five routes. If any outstanding ambiguity remains, do not proceed to cutover or allow a new signer to replay it. After drain: freeze ALL mutable producers including independent Capture, Resident, Discord, observer, TCLK preview/preparer/stager/watchers, Close1, activities, signer, dynamic instances, timers, cron and transient/manual launch paths, considering restart policies and resident Wants capture. Confirm no writer cgroups, processes or writable source file descriptors through a continuously maintained admission barrier; preserve metadata-block service. STOP if unknown writers, PID races, reboot/scheduler relaunch, source drift or any failed check. A single snapshot of 'inactive' is insufficient.

G6 — Create ONE source writer epoch and verified full-state copies while G5 stays held.
Record an original-host-specific monotonically increasing fence generation, independently captured start/end times, original app HEAD, stable inode/size/hash census, host/source proof and complete signer/nonce/receipt/approval/message cursors. Execute BOTH SQLite online backups (lobby-capture.sqlite3 and lobby-capture-service.sqlite3) in the same CONTINUOUS fenced epoch; do not copy live WAL/SHM and do not let independent Capture restart between backups. Record each output size/SHA256/schema/integrity, plus four exact JSON ledger pins from R1050, all additional TCLK/Close1/observer/activities/state and source inventory. Bind every file to the same fence generation and attest NO admission/relaunch across the entire acquisition. Independently recheck full original census, including the old four unclassified roots and symlinks, before any intentional omissions. A hash stored solely beside data or source-self-certified epoch is NOT authenticated origin. If snapshot budget expires or fence wavers, discard the entire candidate epoch, leave original protected and return to owner-approved recovery path; NEVER use partial/independent DB times as a successful cutover backup.

G7 — Seal, transport, restore and independently reconcile BEFORE any source deletion.
Reuse existing DRAFT primitives #876 (complete source coverage), #877 (64-shard geometry), #878 (real byte reassembly), #879 (authenticated AES-GCM envelope), #880 (two SQLite integrity images), #881 (bounded ciphertext ingress), #888 (six-file flat custody) and #890 (source signer routes), without relaxing their limits or rerunning historical synthetic CI. Independently authenticate original source identity/census and no-omission, verify encrypted source archive byte count/hash and actual offsite possession of ciphertext AND separately protected recovery secret. Perform a full restore in an inert sandbox without signing, POST, scheduling, notifications, wallet, external publishing or TradeBot access. Verify schema/integrity, full file set and restored byte hashes, cursor/nonce/receipt/DID continuity and same epoch; record independent verifier and result. A six-file bundle or encrypted metadata-only witness is not full-state recovery. STOP if any original byte cannot be accounted for, inaccessible links, unknown source root, no real restored full set or missing independent custody.

G8 — Separate live CUTOVER release decision, then distinct RETIREMENT release decision.
Only after all prior proofs and a NEW explicit owner approval: transition exactly ONE publisher from original OCI to AWS under a single epoch/lease/fail-closed rule, ensure original cannot sign/post or resurrect via systemd/cron/reboot while AWS is active, prove same DID and upstream nonce/receipt continuity with no ambiguous POST or double-publish, observe K137 mixed-load stability through real protected :02 cycles and keep old OCI DATA/VM for rollback. On any ambiguity, fail closed and do not simultaneously re-enable old and new. Rollback requires separate reconciliation of the latest upstream accepted attempts and prevention of overlapping signers; never blindly run both. This runbook alone cannot grant GO. Only AFTER independent restore, safe rollback hold, stable AWS live proof, fresh zero-references inventory and a SECOND explicit owner approval specifying exact Flop-owned OCI instance and exact deletion allowlist may retirement be considered. Never touch a separate Aerodrome/TradeBot OCI instance.

## Concrete release-evidence packet (no passwords, secret material or unredacted paths in GitHub)

A future reviewer must receive exactly one immutable packet for EACH G0–G8, containing:
- schema_version, gate_id, scope=Flop-owned-original-OCI or isolated-receiver, exact code HEAD and artifact digest;
- attestation timestamp and relevant monotonic/writer generation (timestamps alone never define common epoch);
- original host ID and witness origin in encrypted private custody (GitHub only redacted fingerprint);
- observed allowlist count, unexpected item count, scanned vs total, verification STOP codes, at most aggregate bounded metrics;
- independent verifier identity/public-key trust chain and signed digest or equivalent authenticated custody proof; a self-asserted unverified JSON label is insufficient;
- explicit status PASS/FAIL/UNKNOWN, validated source of external POST ACK, operation authorization and rollback boundary.

No packet may be marked PASS on missing fields, partial traversal, unverified signatures, mismatched epoch or a future-looking conjecture. The trusted attester/key protocol is UNSPECIFIED TODAY, thus no production GO may be issued by generating JSON with these fields. Publishing these packets must never expose secrets, raw original filenames, private keys, Vault material or wallet details.

## Deletion and expense policy — independent of migration

CLASS A NEVER TOUCH: TradeBot K137 private/public/H1 (especially missing h1-20261020T090000Z result), separate Aerodrome/TradeBot OCI VM, metadata-block guard, wallet/seed/nonce/DID, system logs that prove upstream accepted attempts, Oracle rollback copy before approval.
CLASS B RETAIN THROUGH RESTORE: entire original Flop state and two SQLite WAL source sets, TCLK/Close1, receipts/nonces/outbox, observer, capture, app release, security/operational logs; unknown symlinks/root contents remain presumed required.
CLASS C CANDIDATES ONLY AFTER PROOF: stale transient resident-state / heartbeat / observer-state (~19.436GB observed by older R995/R996; not additive to the ~19.523GB R938 snapshot). Classification requires measured bytes and in-use process/FD/reference check, proven regeneration and no financial/forensic role, complete backed-up/restored copy and exact owner allowlist. Name/age alone is never sufficient. Prefer no destructive cleanup until post-cutover hold.
CLASS D NEVER INFER OWNERSHIP: shared directories, unverified inode links or unexplained files; hard STOP.

For every later cleanup release require separate owner-approved exact finite path/inode allowlist, physical allocated-byte BEFORE/AFTER measurements, out-of-band full archive proof, zero references, hold expiry, reversible quarantine where possible and exact rollback. No recursive wildcard deletion, broad rm -rf, truncation, old-command replay or secret/log destruction. If incomplete, retain original and record reclaimable bytes as UNKNOWN.

## Current go/no-go summary
G0–G8 new full release packets: NOT PROVEN. R1034/R1039/R1041 and R1050/R1052 source-only PASS preserved as historical evidence only.
Any missing G1 authority, G3 same-DID custody, G5 external POST verdict, G6 two-DB epoch, G7 independent full restore or G8 K137 admission => NO_GO.
One approved step must NEVER implicitly approve the next step.
OCI_RETIREMENT=STRICT_NO_GO.
