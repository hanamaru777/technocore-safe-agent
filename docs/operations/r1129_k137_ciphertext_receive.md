# R1129 — K137 ciphertext-only preseed receiver (development / not deployed)

2026-11-01. Parent: R1128 Draft PR #917. Exact original R1126 root mount witness has already completed and must not be repeated. Original Oracle boot volume snapshots (Oct 15 and Nov 1) remain available.

## Implemented

- New single-purpose K137 Python receiver accepts R1084/R1001 ciphertext framing **only** on stdin; it does not decrypt or restore anything.
- The only possible destination root is the already-defined, separate owner-private \`/var/lib/flop-migration-r1066/disarmed\`. A new unique \`r1129-<32 lowercase hex>\` subdirectory is required. No replacement, no symlink parent, no arbitrary file paths.
- Requires Linux nonroot UID1000, independently enrolled SHA256 of current K137 machine ID, existing user-owned 0700 DISARMED root, and freshly available disk >=20GiB protected reserve + ciphertext max 32MiB + 1GiB sink reserve.
- Reuses exact existing R1084 bounded R1001 stream receiver, SHA256 per-file digest checks, 32MiB total quota, pending commit until complete frame/EOF; exit42 on fail, leaving partial ciphertext as incomplete and never mislabeling it as a completed backup.
- Fixed output says \`PROVISIONAL_CIPHERTEXT_STORED_ONLY\`, \`aead_verified:false\`, \`source_complete:false\`, \`history_finality:UNKNOWN\`, \`signer_portability:NOT_PROVEN\`, \`activated:false\`, \`cutover:NO_GO\`, \`oci_retirement:STRICT_NO_GO\`.
- Tests create real synthetic R1128 encrypted streams, exercise real receiver, confirm tamper rejection/partial no commit/host pin/refusal to overwrite. This is offline only.

## Not implemented or authorized

- No authenticated original OCI R987-to-K137 binary transport, no independently signed owner private export approval enrollment, no original source bytes collected, no in-flight data readback or true AEAD from an independent destination recovery key. No K137 command has been run, no new permanent systemd service, route, firewall or IAM changes.
- NEVER run this Python receiver directly on production. A future R1130 owner wrapper must authenticate *both* original source and independently verified K137 host keys and machine hashes, demonstrate K137 spare 20GiB and TradeBot isolation, and create only a fixed, owner-approved, ciphertext-only transfer. Do not reuse an unknown older R987 password as archive recovery key.
- This is only preliminary 3-file non-authoritative state as in R1128, NOT all SQLite/WAL, original DID signer, capture history, finality, no-writer-fence source archive, AWS activation, cutover, or Oracle retirement.
- No third Oracle backup. No reexecution of consumed R1095, R1097, R1102, R1112, R1125, R1126. Preserve existing PR#898 and parent PASS evidence.

Deployment / user action: NONE in this task. Full migration authority still NO_GO and retirement STRICT_NO_GO.
