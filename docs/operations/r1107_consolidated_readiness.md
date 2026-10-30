# R1107: consolidated readiness, not migration approval

Issue [#909](https://github.com/hanamaru777/technocore-safe-agent/issues/909)
is the source engineering scope. Starting source is
`ee9453d63298d964ae178977cec9876c2be12391`; the original Oracle application
remains pinned to `ec4bc4892d40cdd2a03e102faa44d72c89e01b99`.
See [the R1103 boundary audit](r1103_original_g4g5_proof_boundary.md).
No source archive, cutover or Oracle retirement is authorized by this package.
No production probe or R1095/R1097/R1102 operation is repeated.

## What is executable, and what is not

| Gate | New executable source / reuse | Actual acceptance boundary |
| --- | --- | --- |
| G1 | `r1107_g1g4_boundary.collect`: fixed read-only systemd metadata, two-pass effective-property census; reuse R1104 exact expected/extra/missing identities and launcher categories. Private inode/FD/mmap/mount-namespace metadata witness. | The Linux reader explicitly reports incomplete closure. It cannot prove every user-manager, generator, indirect cron/interpreter, manual/root or future activation path. No count-only PASS. |
| G2 | Fresh signed destination capacity, distinct original/destination host-pin digests; unchanged R1089 host/custody components remain pinned. | Host ownership and independent enrollment must be genuinely verified outside this source. No host discovery or SSH is performed by the new entrypoint. |
| G3 | Original-DID hash and public-key binding; unchanged encrypted-custody and inert-restore components. | Same-DID **signer portability remains NOT_PROVEN**. Original OCI instance-principal/Vault access is not AWS portability. No credential export or signer invocation. |
| G4 | Explicit DI-only `Controller.propose/preflight/apply/renew/guard/checkpoint/resume/rollback`; owner permission, independently enrolled Ed25519 issuer, 30-second maximum leases, sequence/hash-chain, epoch/census/backend/ledger binding. | **G4_NOT_PROVABLE:** no real root-wide future-launch/POST denial backend or independent lease producer is installed or supplied. A test adapter is not a production fence. |
| G5 | Original Oracle receipt/outbox, TCLK accept/reveal, permanent Close1 single/batch fences and original approvals/nonces; signed retained-positive export matching. Reuse R1103, R1106 and existing signature/terms verifiers. | Official retained JSONL cannot prove complete historical absence/finality. Missing history stays UNKNOWN. Reveal POST does not prove claim-CAS finality. **G5 remains NO_GO even if every known attempt has a retained match.** |
| G6 | `common_epoch`: both distinct SQLite read transactions/integrity/cursors, DB/WAL/SHM hashes and whole non-SQLite manifest, before/during/after census and continuous lease guards. | Needs a real independently held global fence and unchanged physical readonly images. An offline trial is labelled `OFFLINE_TRIAL` and cannot be promoted to original-host evidence. |
| G7 | `verify_backup_binding` reuses full R1089 AES-GCM verification and binds manifest, bytes, epoch, ledger, both DB/WAL/SHM hashes. `disarmed_smoke` validates an independent inert-restore receipt and fixed resource caps. | Authentication is not actual destination restoration. Real full restore, runtime/metadata isolation and original-DID continuity evidence are still required. Nothing starts services. |
| Resources / retirement | Fresh logical source bytes + 1 GiB SQLite allowance + **20 GiB protected reserve**; RAM/TradeBot/OS headroom and zero-cost evidence. Post-restore cache candidate review only. | No historic allocated/logical subtraction; no AWS garbage candidate, billing/resource change or deletion operation. Source archive/cutover **NO_GO**; Oracle retirement **STRICT_NO_GO**. |

Private census data may contain service names and effective arguments. It is
caller-custodied evidence, never suitable for GitHub, console logs or chat.
`report()` emits only fixed decisions, counts and digests. The kernel reader
does not read process command lines, environment, database content or journal.
Its inode approach catches visible renamed/hardlinked aliases and writable
mappings, but unlinked-before-census objects, races and later privileged actions
remain unproven. All such uncertainty blocks admission.

## Versioned owner entrypoint

`packaging/migration/r1107_owner_dryrun.ps1` is ASCII Windows PowerShell 5.1.
It accepts only independently SHA-256-pinned local public plan/enrollment
files with owner/SYSTEM-only protected ACLs. It uses the unchanged native
R1089 binary control pipe, bounded child lifetime, fixed project Python and a
new canonical-LF source-pin map. **The old R1089 and old PIN map are unchanged.**

The enrollment contains public keys only, with separate owner, independent,
upstream, destination, identity and restorer roles. The original DID's public
key is excluded as an attestation authority. No enrollment key is generated
or trusted automatically. Operator-supplied digests are a custody requirement,
not a substitute for independent verification of who controls each key.

The new entrypoint has no apply/SSH/restore switch, R987 prompt/decryption,
secret input, nonce allocation, signing, POST, activation or deletion path.
Even a syntactically valid, independently signed synthetic plan returns
`transfer=DISABLED`, `source_archive=NO_GO`, `cutover=NO_GO` and
`oci_retirement=STRICT_NO_GO`. It never calls old `SourceGuard` or silently
falls back to that private-mount-only fence. No owner production command is
provided here; ChatGPT independent audit must precede any operator action.

## Evidence and recovery contract

All attestations bind the R1063 original-host/source-HEAD/DID/roots/run/generation
context, issue-specific domain and kind, observation time and expiry. Freshness
and lease TTL are at most 30 seconds. Only an independently enrolled issuer
can provide a G4 lease **after** the backend has applied denial. Renewal cannot
change issuer or ledger, skip sequence, replay a packet or change the epoch.
Lost/expired leases and partial apply fault closed; they do not auto-rollback,
restart writers or continue reading source bytes. Resume requires durable
backend undo state and fresh independent checkpoint authorization. Rollback
requires separate owner/independent permission, destination writers fenced and
POST finality reconciled; it restores only the recorded prior state.

The five-route reconciler consumes exact private original sidecars, not a
generic caller-supplied ACCEPTED/NOT_ACCEPTED verdict. Optional whole-state
hash indexing avoids loading huge Observer data while requiring all signer,
outbox, Close1, nonces, activities and verified-DID sidecars. Individual private
JSON/byte inputs are bounded to 16 MiB; exceeding this bound is STOP, not silent
truncation. Permanent Close1 attempt fences are never removed or retried.

The only public reader is fixed HTTPS Technocore retained export GET, with
redirects/proxies disabled and bounded reads/timeouts. Two identical bytes and
generation checks reduce races but do not remove the official residual stamp
race or establish historical completeness. Empty exports, missing old nonces,
compacted/truncated histories, offline reads and unknown auxiliary claims cannot
authorize a new POST, migration or retirement.

The G6 library does not freeze, checkpoint or change source permissions. It
requires already readonly DB/WAL images under a continuously valid fence.
Full census guards include non-SQLite evidence. The synthetic trial cannot
authorize source acquisition. Backup verification and inert receipt consistency
cannot authorize starting the preserved source units on K137.

Cleanup review requires a matching authenticated full backup/restore receipt,
same-DID preservation, fresh byte hashes and independent **and** owner review
permission. Only known regenerated app pytest/Python cache files are candidates.
All state, DB/WAL/SHM, DID/custody, nonces, five-route pending/receipt history,
TradeBot, unknown objects and links stay excluded. Output is hashed-path
`REVIEW_ONLY`; there is deliberately no delete API.

## Testnet and next single owner action

Reuse the already merged R1105 official-public-source readiness work:
[PR #908](https://github.com/hanamaru777/technocore-safe-agent/pull/908),
main `04c2af6d4630abcd0a3bd65f81a9e722d81d5053`, and the
[#311 unblock list](https://github.com/hanamaru777/technocore-safe-agent/issues/311).
Do not cherry-pick or rebuild it here. Chain/genesis/RPC/faucet/receipt
authorities are still unverified; no real adapter, speculative signing schema,
wallet/faucet request, registration or scoring is added.

After independent ChatGPT review, the next safe grouped action is **one local
dry-run of authenticated public evidence** using the new pinned entrypoint.
Missing genuine evidence must STOP; do not fill it with fixture values or
self-attested summaries. This is not a request for secrets or another consumed
production inventory probe. Migration execution still needs a separately
approved real G4 backend/issuer, complete five-route finality, common frozen
epoch, actual encrypted offhost full restore, fresh K137 resource/same-DID
proof and independently reviewed rollback/retirement authority. Until those
exist, no meaningful production transfer/cutover command can safely be released.
