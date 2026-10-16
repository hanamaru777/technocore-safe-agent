# R942 — Minimum-complete Flop application-state migration: do not bypass limits

2026-10-16 JST | Source-only safety decision | Draft; **NO CUTOVER / NO DELETE**

## Ground truth from owner's original Oracle guest

* R928: Cloud Shell host-pin screening + SSH guest identity **PASS**, not proof operator key uncompromised.
* R932: original protected production source `ec4bc4892d40cdd2a03e102faa44d72c89e01b99` and passwordless sudo **PASS**; scan was incomplete.
* R936/R934: 3,001 files ~19.4GB logical, 19 symbolic links and 4 unknown root directories; source untouched.
* R938: 3,017 regular files; 19,516,185,315 logical bytes, 19,523,031,040 allocated bytes; metadata INCOMPLETE. `statvfs` available 18,504,417,280 bytes.
* Observer atomic temporary **candidates**: 892 files / 10,199,298,048 allocated bytes. Other unclassified Observer temporary suffixes: 861 files / 3,052,670,976 allocated bytes. Neither class is safe to delete by name or age.
* Single unclassified Autopilot `.log` (anonymous ID 042f8b292e3b): 5,166,563,328 allocated bytes, older than one week. NOT the capped `autopilot-audit.jsonl`; contents/owner/purpose remain unknown. Preserve evidence.
* Original two SQLite files: 107,532,288 and 700,350,464 logical bytes; **not** proof of online backup, WAL consistency or reader/writer fence.
* Eight fixed systemd identities: 7 active, 1 inactive, 0 failed; which one inactive and **all** other writers have not been established.
* Source-only archive policy R861/R922 expects two online-backed SQLite images, 14 mandatory state paths, and TCLK/nonce/finance receipt/pending-attempt evidence. Original OCI Vault seed/private signer custody is **outside** the archive.

## Non-negotiable correctness constraints

1. R861 policy has `MAX_PATHS = 512`, `MAX_STATE = 6 GiB`, `MAX_FILE = 3 GiB`. A naive 3,017-file/19.5GB source manifest MUST STOP rather than quietly raise caps, ingest the 5GB log, ignore unknowns or misreport a complete backup.
2. A minimum archive is a **selected proven-complete state**, not a copy of every OS/cache/temp/log byte. A valid exclusion requires an explicit audited classification, stable pathname/inode facts from an authoritative source epoch, no active writer or open reference, and no effect on recovery, nonce ledger, TCLK hash locks, invoices, receipts, DID/Signer or historical forensic requirements.
3. A `.tmp` suffix, path under `uv-cache`, age older than a week, filename hash, or absence in one sampled `/proc` check are NEVER sufficient to prove exclusion/deletion. The source `observer.atomic_json_write` and `observer_state_writer_isolation._atomic_text_write` normally replace+unlink temporary files; accumulation reason is **not yet proved**. Source 5GB `.log` is unknown and may be forensically important.
4. Symlinks (19) and four unknown top-level state directories must be authoritatively resolved and represented in the full inventory before proving the selected state complete. Path/count digest alone is not a secret-safe destination manifest.
5. Original financial identity continuity requires one writer epoch and strict monotonic nonce, paired transaction attempts and receipts with no ambiguous in-flight send; preserve TCLK private preimages without exposing them through chat/GitHub or logs. Detecting ambiguity means **STOP**, never auto-replay.
6. Original Oracle compute-host InstancePrincipal signer cannot just run on AWS. External OCI Vault constrained identity might keep same DID while Oracle Compute retires but changes the trust boundary by making secret available to AWS RAM, and needs separate explicit credential/security consent and no-new-charge verification. Paid AWS KMS is excluded under zero-new-cost condition.
7. Existing 47GB manual FULL original Flop boot backup is AVAILABLE but crash-consistent, **not** an application-consistent encrypted off-host recovery. Do not delete it or the original Flop VM until independent AWS restored DID/nonce/finance/data verification and owner's scoped retirement permission. Unrelated Oracle Aerodrome 80GB and AWS Lightsail K137 TradeBot are always out of scope.

## Execution path — future distinct audited stages

* Stage A (read-only, not executed): reconcile actual fixed units/overlays, writer process lineage, recent abnormal interruptions and open-file/active-temp references, symlink and unknown-root topology, classification of the giant log, and aged temporary file candidates. Detect drift/ambiguity and STOP. Never echo private contents.
* Stage B (off-host backup plan, not executed): choose audited source-relative durable state records and database online backup images, prove TCLK and finance receipts/nonce coherence under one fenced source epoch; use a real owner-held **encrypted** transport and verify hashes. Metadata-only PR #855 is **not** encryption.
* Stage C (independent restoration, not executed): restore to an isolated disabled Flop AWS path with no signer, network POST or interference with TradeBot; independent SQLite integrity, file ownership/perms, DID/nonce/TCLK/ledger state, and fail-closed financial replay proof. Preserve source and original boot backup.
* Stage D (explicit approval, not executed): agree source-authoritative cutover and cross-cloud OCI Vault signer security model, verify non-overlapping signing and memory/PSI budgets; only then discuss activating AWS Flop.
* Stage E (separate owner approval, not executed): retire only Flop-owned Oracle Compute/boot volume after independent proof, decide when its last manual backup can be removed; Oracle Vault may remain. NEVER touch Aerodrome.

## Current outcome

**Offline code/CI proof only.** This document and R942 fail-closed regressions are not source authorization, production backup, archival success, cloud migration, clean signing or cleanup permission. Do not re-run consumed R931/R932/R936/R938 probes or historic backup creates. Prior protected main PASS remains untouched.
