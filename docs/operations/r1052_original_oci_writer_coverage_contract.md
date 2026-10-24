# R1052 — Original OCI writer and signer/POST route coverage contract

**2026-10-24 | SOURCE-ONLY | DRAFT / DO NOT MERGE, DEPLOY OR OPERATE PRODUCTION**

Authority: Issue #765 v232 and Issue #842 R1051. Source original Flop
production Git HEAD: `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`.
This document does not authorize an OCI service stop, timer disable,
manual POST, signer pause, nonce adjustment, copy, restart, reboot, AWS
activation or any cloud/IAM changes.

## What this change actually implements

`packaging/archive/r1052_offline_writer_route_contract.py` is a **pure
in-memory source integrity contract**. It can accept 27 previously copied
original `.service`/`.timer` template byte strings and compare each
to its exact original HEAD Git blob digest. It validates that the five
**known template** sign-and-POST entry points still call the expected
modules. It makes no network, process, shell or filesystem operations.
Its tests use committed source templates and synthetic negative
fixtures. It is NOT a live Oracle unit inventory or service fence.

Pinned original template count: 19 `.service` (including two
dynamically instantiated `@.service` templates) plus 8 `.timer`.
The production R1034 live source-to-systemd census found 26/27 known
installed (only close1-auto-resident absent) and four more units
not in those original templates. The original host may have drifted
since then; unit presence and current state are NOT ATTESTED by this
static contract.

### Five distinct signer / POST entry-point templates

1. `technocore-safe-agent-signer.service` →
   `flop_agent.oracle_signer` (Vault, nonce, receipt, POST).
2. `technocore-safe-agent-tclk-accept@.service` →
   `flop_agent.tclk_pilot_accept` (Vault signer, accept, POST, nonce).
3. `technocore-safe-agent-tclk-reveal@.service` →
   `flop_agent.tclk_pilot_reveal_publish` (Vault signer, reveal and
   follow-up transition POST, nonce, receipts).
4. `technocore-safe-agent-close1-approved-trade.service` →
   `flop_agent.close1_approved_trade` (Vault signer, approved POST).
5. `technocore-safe-agent-close1-batch-trade.service` →
   `flop_agent.close1_batch_trade` (multi-leg POST, nonce, receipt).

The two `tclk-*@.service` templates can be instantiated on demand,
independently of timer status. A zero outbox in
`oracle_signer.service` is NEVER evidence these independent POSTs
have finished. No one may replay old quarantined E2E messages.

Conversely `flop_agent.tclk_pilot_signer` and
`flop_agent.tclk_pilot_reveal` are preview/state writers, not
standalone transport POST modules, despite their names. They still
matter for the **all-writer** barrier, but must not be falsely counted
as direct external signer POST.

### Four guest-installed units without matching source templates

・`technocore-safe-agent-close1-discord-activation.service`
  (static, inactive, oneshot, ExecStart OTHER_UNVERIFIED).
・`technocore-safe-agent-close1-discord-activation.timer`
  (disabled/inactive at R1039).
・`technocore-safe-agent-close1-standalone-watch.timer`
  (disabled/inactive at R1039).
・`technocore-safe-agent-postreboot-check.service`
  (enabled/inactive, Flop dependency, ExecStart OTHER_UNVERIFIED).

These status observations are prior read-only *snapshots*, not a
durable systemd fence. No explicit `ReadWritePaths` is **not** a
read-only guarantee. Original R1039 cron inventory remains incomplete
(one non-regular object) and process enumeration remains incomplete.
No source-only validator can close those gaps.

## Precise prospective safety ordering — NOT A COMMAND SEQUENCE

**Phase A: disallow all NEW authority while keeping evidence.**
A future owner-approved barrier must cover interactive/manual unit
instantiation, the two TCLK `@.service` units, all five direct POST
paths, Close1 approvals and independent timer or reboot-driven
launchers. It must be deny-by-default for unexpected installed units,
transient jobs and cron. Must preserve metadata isolation guard.
No command implementation, host execution or approval exists here.

**Phase B: drain/reconcile truly in-flight work.**
Before any process fence, classify every known POST attempt as
externally accepted, definitely not accepted, or ambiguous by
independent external-authority evidence and the exact DID, nonce,
receipt, per-leg source identity. An ambiguous POST is a hard HOLD;
"queue=0", "unit inactive", "NRestarts=0" and local R1041
prepared/quarantined pairing cannot replace this proof. Do not
retry, replay, re-sign, cancel, or mutate any of these attempts
merely to obtain a clean verdict.

**Phase C: fence EVERY durable state writer under one epoch.**
A separately reviewed owner-approved runbook must establish a
single writer-fence admission sequence and explicit rollback points,
including signer, manual TCLK/Close1 units, Resident, independent
Capture, Discord, all eight known timers, any dynamic instances,
unknown oneshots, cron/process/FD/transient jobs and restart policies.
Original `resident.service` Wants independent
`lobby-capture.service`, so stopping or restarting a single unit
casually may change the other. The metadata-block security barrier
must remain intact. The original SOURCE file list alone can never
prove the host is quiet.

**Phase D: original common writer epoch, not separate clock readings.**
Only after Phase C is proven, independently bind all original
signer/nonce/DID/outbox/receipt/TCLK/Close1/observer metadata and
**both** `lobby-capture.sqlite3` and
`lobby-capture-service.sqlite3` using SQLite online-backup
protocol while the same writer fence is continuously maintained.
The original source HEAD, separate attested original-instance
identity, monotonic epoch, process/FD proof, file manifests and
offsite provenance must be mutually bound by trusted external
custody and an independently tested recovery. A source-owned
self-declared epoch is not sufficient.

**Phase E: isolated AWS authenticity/capacity, then separate cutover.**
Original `oracle_signer.py` uses OCI
`InstancePrincipalsSecurityTokenSigner` to fetch the existing
Vault secret and preserve the original DID. A Lightsail
`iam/info` HTTP200 response DOES NOT establish permissions for
AWS STS outbound identity or OCI JWT→RPST trust. Existing Flop AWS
Phase01/02/03C source+venv+core-wheels PASS are *consumed*
and do not install the OCI signer SDK or authorize signer
execution. Shared K137 is only 2GB/no swap; latest K137Q
public-only timer has a separate safely failed historical H1
(in TradeBot #626). No private trading, Flop live publisher,
full cohosting, new cloud fees or account changes are approved.

**Phase F: separately authorize ONE restored live publisher, rollback,
and eventual OCI instance retirement.** Never treat a successful
static route audit, an encrypted archive of six files, or source-only
CI as authority to destroy the original Oracle compute.

## The invariant returned by this source-only audit

Even after ALL 27 templates match the original Git blobs:

・`all_writers_fenced=NO`
・`signer_inflight_post_resolved=NO`
・`full_state_common_epoch=NOT_PROVEN`
・`aws_signer_did_custody=NOT_PROVEN`
・`oci_retirement=STRICT_NO_GO`

No "GO" mode exists in the R1052 code. It has no command-line
entry point or live host access; only safe fake/offline test input.
It does not re-run R1034, R1039, R1041 or R1044–R1048 and
cannot make their results more comprehensive.

**Next true release gate:** The authorized future on-host runbook must
first show that all five distinct sign/POST routes can be rejected
to NEW entrants while preserving evidence, and that every unrelated
state writer can be drained and fenced without losing independent
Capture or weakening the metadata barrier. This is not yet designed
as an executable procedure and has not been used on Production.
