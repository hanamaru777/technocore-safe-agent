# R1063: consolidated offline release evidence review

Issue #900; parent #842; stacked on R1062 #899 at
`aaa8e74f5a1183f691ba7666a2608ca4b636983f`. SOURCE-ONLY / DRAFT.
This package implements the evidence contract and synthetic end-to-end review,
not an evidence collector or an executable production migration procedure.
No runtime authority, network client, SSH, cloud operation, database access,
archive creation, credential retrieval, or service operation is introduced.

## One entrypoint, fixed no-go boundary

From the checkout, `uv run python packaging/migration/r1063_release_gates.py`
prints one bounded JSON report containing G0–G8, fixed failure reasons and the
minimal next evidence for each gate. It exits 2 because no operation is released.
The optional `--stdin` accepts at most 1 MiB of **already redacted attestation
metadata**, not original files, command output, archives, credentials or keys.
No paths, URLs, nonce values, DID or supplied strings are echoed in reports.
Duplicate JSON keys, unknown fields, wrong types (including bool-as-int),
oversized data, stale/future claims, duplicate gates and mismatched contexts deny.

The CLI deliberately enrolls **no production trust roots**. An input cannot
install a verifier key or declare itself trusted. Even a correctly structured
packet is `TRUST_NOT_ENROLLED`. `evaluate(bundle, trust, now=...)` is the pure
offline library interface for independently pinned verifier **public keys** and
context supplied by a trusted caller. The synthetic tests exercise it with
ephemeral verifier keys. No production private material is needed or permitted.

`EVIDENCE_VALID` means only that authenticated assertions satisfy this offline
contract; it is not verification of the underlying physical archive or host.
Every report, including a complete synthetic positive case, says:

- `authority=OFFLINE_ASSESSMENT_ONLY`
- `production_trust_enrolled=false`
- `cutover=NO_GO`
- `all_writers_fenced=NOT_ASSERTED`
- `oci_retirement=STRICT_NO_GO`

There is no switch to turn synthetic evidence into a production GO. Enrollment
of actual attestors, independent validation of their acquisitions, review of
the final evidence and a separately authorized operation remain operator-only.
Green tests/CI, Git pins, a local SHA256 or a source-host signature cannot provide
that missing authority.

## Reused work and known truth

R1052's exact original 27 template names, original source HEAD and five POST
module bindings are imported, not rewritten. R1050/R1005 supply the two SQLite
names, four ledger names and image size bound. Importing these modules does not
execute their filesystem, backup or acquisition entrypoints. Protected source,
carriers, testnet adapter, archive tools and CI are unchanged.

Reviewed dependencies remain separate audited tools; do not rerun consumed
synthetic or live work merely to populate a PASS:

| Existing component | Reused responsibility / limit |
| --- | --- |
| #891 / R1054 | G0–G8 ordering and separate authority decisions |
| #876 / R963 | Independent full census vs manifest; no implicit omissions |
| #877 / R966 | 64 shards, 512 segments/shard, 6 GiB/shard, 3 GiB/segment |
| #878 / R969 | Actual source-byte reassembly, not metadata equality alone |
| #879 / R1001 | AES-256-GCM encrypted stream, final authenticated commit |
| #880 / R1005, #892 / R1055 | Two online-backup images and immutable integrity/schema verification; neither proves original epoch |
| #881 / R1015 | Bounded ciphertext ingress, minimum 20 GiB headroom |
| #887 / R1041, #888 / R1050 | Local receipt pairing and six-file pins; neither proves upstream POST finality or full restore |
| #890 / R1052, #899 / R1062 | Source authority contract and consumed original-host classification |

R1062 already established 30 units (26 of 27 expected, four historical extras),
four matched processes, **five writable FD objects classified Capture**, one
SPECIAL cron object and one proc RACE. Earlier four FDs reflect time drift, not
another release gate. FD counts are not writer counts. Missing exact template
identity is not freshly proven. Five POST templates exist; zero live TCLK
instances cannot rule out manual starts. These are known blockers, not new
input fixtures that can be relabeled as independent evidence. R1058–R1062 and
earlier owner probes are consumed: this task does not rerun them.

## Authentication and schema

Top-level JSON is exactly `{schema_version: 1, packets: [...]}`; at most one
packet per G0–G8. Each packet is exactly `{signer, body, signature}`. `signer` is
SHA256 of the attestor's raw 32-byte Ed25519 public key. The signature covers
`b"FLOP-R1063-EVIDENCE-v1\0"` (a real NUL, not backslash text) followed by
canonical sorted ASCII JSON with compact separators of the entire body.
The body contains exactly `gate, context, observed_at, expires_at, evidence`.
Times are integer UTC seconds, no future observations, maximum 900-second
freshness/lifetime. Clock and trust policy are independent caller inputs.

Context is exact across **all** packets and nested approvals/upstream verdicts:
`campaign, host, destination, did, source_head, generation`. Four identity fields
are SHA256 commitments; `source_head` is the original
`ec4bc4892d40cdd2a03e102faa44d72c89e01b99`; generation is a positive monotonic
writer-admission generation independently pinned in the policy. A new campaign,
generation, host or DID cannot be adopted from untrusted input. No raw hostname,
IP, OCID, DID, private path, nonce or file contents are part of the report.

Verifier roles are `independent`, `destination`, `identity`, `restorer`, `owner`
and `upstream`. Source-host key IDs are explicitly excluded even if otherwise
present in the trust map. The restore verifier must differ from the acquisition
verifier. Owner and upstream signatures are nested, separately role-checked and
bound to the same campaign/generation; a normal acquisition signature cannot
substitute. Key-to-role assignment and source exclusion are reviewed policy,
not claims the packet can supply. A compromised or dishonest *trusted* verifier
is outside cryptographic validation's guarantees: review the acquisition and
verify real artifact bytes with the existing tools before enrolling evidence.

Executable schema details are in `shape()` calls and validators. Positive and
negative packets are constructed entirely in memory by
`tests/test_r1063_release_gates.py`; no sample is claimed to be real evidence.

## Consolidated gates and exact remaining evidence

| Gate | Required independent evidence / rejection |
| --- | --- |
| G0 | Fresh original host and ownership scope, separate destination, source artifact and root census digests. Historic source pin alone is insufficient. |
| G1 | All 27 templates explicitly accounted present/absent, at least four extra-unit effects reviewed, complete launcher inventory, zero unresolved cron/proc/permissions/unknown authority. Absence must be independently established, never defaulted from a missing field. |
| G2 | Actual logical full-source bytes, encrypted worst-case peak, both images, rollback retention and 20 GiB ingress headroom; measured protected TradeBot/Flop/OS peaks plus >=256 MiB memory margin within existing 2 GiB, CPU/PSI and natural protected-cycle proof, zero incremental spend. No optimistic compression allowance. |
| G3 | Actual portable credential/issuer/subject/audience/expiry, permissions/trust and least privilege, revocation/rollback, no export, disarmed retained-DID and nonce/receipt continuity across all five routes. |
| G4 | Separate signed fence authorization issued before fence start, exact launcher coverage, continuously held generation, no relaunch, zero writers/writable/unknown FDs, metadata guard maintained. Observed hold must not be future, at most 30s old; enforceable lease expiry is separate, at most 900s after observation. A future timestamp never proves a future fence. |
| G5 | Complete attempt census and **five independent upstream verdict checks**, including all dynamic instances and Close1 legs. Each route binds inventory digest, exact attempt/leg, DID/room/nonce/text commitments, local status and upstream acknowledgment digest. ACCEPTED or DEFINITELY_NOT_ACCEPTED only. UNKNOWN/AMBIGUOUS/local-only/no authoritative empty census denies. No retry. |
| G6 | Both named DBs produced through online backup while the same barrier/generation remains held; ordered acquisition intervals, schema/integrity/WAL accounting, exact size/hash, four ledger pins and full-state epoch/census digest. Source-only two-image PASS cannot satisfy this gate. |
| G7 | Complete full census and roots bound to G0/G6; images/ledgers bound by canonical digests; exact restored file count and actual source/restored byte totals; no unexplained links, roots or omission; actual reassembly and authenticated AES-GCM full-content independent inert restore, offhost ciphertext and separate recovery custody. All historical shard bounds retained. Metadata archive or six-file bundle is not sufficient. |
| G8 | Non-overlap lease, original data retained and latest-POST reconciliation for rollback; cutover approval signs the digest of the complete G0–G7 packet set. A **later** distinct retirement approval signs that release plus cutover approval, with stable live destination proof, zero references, exact deletion scope and completed rollback hold. Both are assessed separately from the permanently inert runtime decision. |

The five route results are reported individually even if one route denies:
`oracle_signer`, `tclk_pilot_accept`, `tclk_pilot_reveal_publish`,
`close1_approved_trade`, `close1_batch_trade`. Exact nonce/DID values stay in
operator-private original evidence; the independent acquisition and upstream
verifier must recompute and match their commitments. An empty route still needs
an upstream-signed complete-census binding. No count of local queued items proves
absence of externally accepted work. Duplicate attempt/leg or DID-room-nonce
commitments deny. Neither evaluator nor tests access original receipts.

All nine external gates remain unproven for actual Production. Signing a
summary without performing its underlying verification is fabricated evidence.
The positive fixture is deliberately synthetic (4 GiB source, 34 GiB free),
**not** a new estimate of original state or actual K137 free space. It is not
permission to enlarge storage. Free space above the existing 60 GB disk itself
is rejected as destination drift. A 20 GiB full
source with full staging and rollback cannot meet that fixture budget on the
known shared disk. A separately proven $0 offhost destination/layout or a new
reviewed streaming space model is needed; this task neither invents nor deploys
one. The conservative evaluator can reject a feasible optimized layout until
its actual peak accounting is independently reviewed.

## Candidate future Capture/Resident fence and rollback design

This is a state transition design, not a shell recipe or executable procedure.
No operational authorization exists in this document.

1. Complete G0–G3 and prepare independent recovery/rollback custody **before**
   source interruption. Owner approval names exact original-host generation,
   full scope, reviewed procedure digest and abort boundary.
2. Deny new authority first: systemd timers/boot/restart/transient/manual starts,
   dynamic TCLK units, cron including the SPECIAL object, approval ingress,
   five POST entrypoints and other mutable producers. Protect metadata-block
   and unrelated workloads. The currently unreviewed OS enforcement mechanism
   is a blocker; setting a JSON flag or stopping a unit is not admission control.
3. Drain/classify each existing attempt against independent upstream evidence.
   Retain ambiguous records and stop the transition if any unresolved verdict
   exists. Never retry a POST to get a cleaner result.
4. Only after that drain, quiesce mutable producers under the same generation.
   Original `resident.service` **Wants** the independent Capture service; both
   use `Restart=on-failure`. A Resident stop alone cannot quiet Capture, and a
   crashed/restarted Capture can invalidate either SQLite acquisition. The
   admission mechanism must prevent both relaunches continuously while keeping
   the metadata security service. Resolve proc races rather than counting them
   as zero. All timers, cron, manual and transient paths remain covered.
5. Record one independently witnessed generation and source census; invoke the
   existing online-backup/verification components for both DBs and ledger/full
   source acquisition in that epoch. Preserve original WAL/data. Any lease
   expiry, race, relaunch, unexpected FD or source drift invalidates the entire
   candidate epoch. Isolate incomplete offhost evidence; delete nothing.
6. Seal and independently restore the full archive inertly using audited tools.
   Verify all original evidence and identities, not merely SQLite headers.
7. A separately approved cutover must transfer exactly one publisher lease;
   original remains fenced while destination holds authority. On trouble,
   fence new destination admission first, independently reconcile latest POSTs,
   then allow only a separately authorized single-side rollback. Never run both
   signers or blindly resurrect old prepared attempts. Keep original bytes and
   encrypted restore throughout the rollback hold. Retirement requires another
   later explicit owner approval; source deletion is not implemented here.

## Source-backed signer portability assessment

At the pinned original source HEAD, `oracle_signer.vault_seed()` constructs
`oci.auth.signers.InstancePrincipalsSecurityTokenSigner()` then calls
`SecretsClient(...).get_secret_bundle(..., stage="CURRENT")`. It expects OCI
instance-principal authentication. The original Resident cannot access metadata;
the isolated signer is the dedicated exception. That trust model does not move
unchanged to existing Lightsail, whose metadata response is not a service role.
The source still uses the same continuing DID and fixed signing lanes; this
package does not edit or call them.

Missing claims include actual credential issuer and trust chain, exact subject
and audience, token lifetime/refresh/revocation, authenticated token-exchange
client if applicable, least-privilege permission to only the existing secret
version, nonexport custody, denial to Observer/TradeBot, and independently
verified disarmed original-DID continuity for all five callers. A proposed AWS
STS token is not by itself OCI RPST, OAuth client authorization, Vault permission
or a proven $0 option. No IAM/OAuth/OCI identity provisioning is supplied.

Options requiring independent operator/security review:

- Retain the existing original isolated signer and keep any destination GET-only
  until real portable custody is established. This cannot retire OCI and is not
  a completed relocation; it introduces no claimed remote signing service.
- Review a real supported federated workload identity path only if both token
  issuance and authenticated OCI exchange permissions already exist or are
  separately authorized and verified $0. Require source-backed compatibility,
  exact claim validation and a disarmed test before changing any runtime.
- If neither meets no-export and zero-spend policy, **block signer cutover**.
  Do not export the seed, replace DID, assume a Lightsail role, create a paid
  credential service, or relax Observer/metadata isolation as a workaround.

## Validation and final operator boundary

The executable synthetic harness is
`uv run pytest -q tests/test_r1063_release_gates.py`. It exercises full signed
positive evidence and negative mutations, with no source DB, archive, secret,
cloud, network or service access. CLI subprocess tests run this local report
only. Existing R1052/R1050/R1055 PASS test suites are not repeated: their code is
unchanged, imports/constants are regression-checked by the new tests. Standard
existing PR GitHub Actions supplies the Linux full-suite and secret/history gate;
no workflow/cache/artifact/billing change is needed.

Operator-only blockers: trusted external attestor enrollment and authentic fresh
G0/G1; enforceable continuously held admission/fence and all five upstream
verdicts; coherent full original acquisition; authenticated full-content offhost
restore and independent recovery custody; proven original-DID portable signer;
actual $0 K137 resource/TradeBot safety; rollback; separate cutover and later
retirement approvals. Do not rerun consumed probes to pretend these are closed.

Official public TESTNET RPC/genesis/faucet/model/receipt facts remain unavailable
as recorded by #900 on 2026-10-26. The 2026-11-03 date is provisional; Devnet is
not airdrop proof. `src/flop_agent/testnet.py` stays unavailable and unchanged;
R1060 draft is not mixed into this branch. No testnet claim can waive a migration
gate. R987 custody, historical full backup and all original data remain intact.
