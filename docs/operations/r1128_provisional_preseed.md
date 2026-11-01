# R1128: provisional encrypted source preseed (not an authoritative migration)

Status: CODE ONLY / SOURCE NOT EXECUTED / NO OPERATOR COMMAND / DO NOT MERGE TO MAIN.

Canonical control: Issue #905 R1127 comment 6557487161; after real R1126 original host root-mount witness PASS. Immutable parent is R1126 Draft #916 head d085feb2ea7eba0af5bd84883221fe9d2fb88e48. Preserve original source HEAD ec4bc4892d40cdd2a03e102faa44d72c89e01b99, original DID, Oracle two boot backups, AWS K137 TradeBot.

## Scope

New `packaging/migration/r1128_provisional_preseed.py` is a library-only primitive, NOT a runnable CLI or Windows R987 sender. It narrows a first byte-transfer candidate to three exact original files:

- `state/verified-did.json` (16KiB maximum)
- `state/nonces.json` (1MiB maximum)
- `state/signer/oracle-signer-receipts.json` (8MiB maximum)

These are security-sensitive and cannot be exported until separate explicit source-data custody approval. Only selected bytes are encrypted and placed in the manifest; absolutely no live SQLite, WAL, service registry, other history or entire state is yet copied. File metadata (including path names) is contained inside the encrypted R1001-compatible manifest. Live source output must be ciphertext frames only, with a final authenticated commit only after source metadata/bytes recensus; on drift, no authenticated complete archive is produced.

Reuse unchanged R1066 manifest and exact inode/mtime/mode/hash protections, existing R1084 AES-256-GCM 1MiB chunk stream and R1001 PBKDF2-HMAC SHA256 600k, random per run salt/nonce/parts. No independent recovery key is hard-coded. Root git HEAD and source machine digest guards, three no-follow single-link regular files, max 16MiB selected plaintext, max 120s elapsed, 256MiB MemAvailable, memory PSI avg10 full<=5 and io PSI avg10 full<=10. Root/ancestor symlink guard; no guest filesystem write and no production service mutation. No use of old consumed R1112 or R1125/R1126.

It deliberately does not assert a coherent common epoch across even these three files, and may fail while they are modified. No static preseed fixes signer finality. It does not read/export DID seed, OCI Vault payload, private key or SSH key.

## Hard limits / blockers

- The library is NOT a production-ready owner action: no independently enrolled owner preseed-approval source, no authenticated R987 binary streaming carrier, no independent NTFS offhost custody, no bounded storage sink, no recipient-side AEAD+inert-restoration readback and no actual R1128 operator acceptance yet.
- A bare `owner_provisional_authorization` flag in a hypothetical future caller is NOT an authorized signature/lease. A future wrapper MUST independently prove the exact owner, source, destination, scope, signer/DID binding and recipient custody before invoking this function. Never add a CLI or loosen an existing R1089 G4/G5 guard to make the flag work.
- Even after real preliminary ciphertext export: `PROVISIONAL_LIVE_UNFENCED_NO_REPLAY` forever; NEVER treat as complete G5/G6 ledger, replay permission, signer migration, new AWS publisher or Oracle deletion proof.
- No user must run this module in its current form. No new GitHub CI job other than normal PR validation is necessary; no Codex.
- Next actual implementation is a separate exact-pinned, bounded, non-interactive owner SSH binary carrier plus independent NTFS ciphertext sink and AEAD verification. It should support one explicit owner approval for source-data custody. The real K137 mixed-load+disk and zero-spend constraints remain independently gated.
- Final complete archive requires a genuine durable writer fence, both Capture SQLite online images in one frozen epoch, all state and symlinks, five-route upstream negative finality or indefinite no-replay quarantine, exact original DID signer portability and independent offhost restored validation. No relaxation of R1117 controls.

Decision: R1128 source primitive is a risk-contained prerequisite to REAL preseed, not evidence that bytes left Oracle or a new full-backup strategy. `REAL_OFFHOST_BYTES=0`, `CUTOVER=NO_GO`, `OCI_RETIREMENT=STRICT_NO_GO`.
