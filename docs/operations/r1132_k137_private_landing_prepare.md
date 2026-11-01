# R1132 — K137 isolated ciphertext landing preparation

As-of: 2026-11-01. Source-only development; original Oracle and K137 have not been modified by GitHub operations.

Owner-provided read-only R1131 live proof: on tradebot-k137, UID1000=PASS, no symlink ancestor for planned DISARMED path, free=45,681,995,776 bytes (~42.55GiB), MemAvailable=1,479,460KiB, protected-disk-reserve=PASS; destination directory did NOT exist. R1131 did NOT inspect immediate existing parent ownership/mode. Owner-observed machine digest and ED25519 public host key remain private operational evidence in chat, not GitHub.

R1129 (PR #918) is only a synthetic-tested ciphertext receiver whose destination must already exist at /var/lib/flop-migration-r1066/disarmed, owned by dedicated uid1000 with mode0700. This R1132 helper provides narrow optional preflight and one-time owner-approved initializer.

Strict contract:

- Root-only APPLY on Linux; ubuntu account UID1000 and gid>=1000. Exact independently owner-observed SHA256(/etc/machine-id) required.

- Fresh available disk >=20GiB protected TradeBot reserve +1GiB sink headroom +32MiB future ciphertext.

- Root-owned non-world-writable /, /var, /var/lib; opens relative to anchored /var/lib fd using O_NOFOLLOW and O_DIRECTORY.

- Only two possible directory names: /var/lib/flop-migration-r1066 and child disarmed. Both end owned by ubuntu, mode0700. Newly made parent root-owned until child exists. New dirs only; NO service/systemd/cron/vault/firewall/DB/POST/sign/finance/OCI/TradeBot changes.

- Existing wrong owner/mode/symlink/special file MUST STOP without repair, chmod, chown, overwrite, delete. Partial failure leaves evidence; no blind retry.

- No-APPLY is check-only, no directory writes; synthetic tests use temporary directory. APPLY requires operator explicit approval and creates exactly the missing destination directories after guards.

- Even after R1132 success: source_bytes_transferred=0, no signed R1128 owner export, no R987 live original→K137 SSH transport, no independent AEAD restored state, no original signer or G4/G5 completeness. OCI two boot backups preserved, cutover NO_GO, retirement STRICT_NO_GO.

After bootstrap: separately implement and audit exact authorized owner SSH binary live stream and ciphertext verification with full K137 TradeBot insulation. Do not rerun consumed R1125/R1126 or completed evidence.