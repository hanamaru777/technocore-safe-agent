# R1130 — in-memory source-to-K137 ciphertext bridge

Status: 2026-11-01, internal code only, no enrolled production caller, DO NOT RUN ON REAL HOSTS.

## Scope and safety

- R1130 is a Python library that connects two independently authenticated child process pipes and forwards at most 32 MiB of a FLOPST01 ciphertext stream from the original source to the existing R1129 K137 cipher-only receiver. It does not persist files on the Windows relay host.
- The source request/control is provided in a mutable bytearray and overwritten with zero bytes on any exit, including failure. Source and destination subprocess stderr is discarded and the environment contains only LANG (plus Windows SystemRoot/ProgramData if applicable).
- A fixed 180s limit is enforced by terminating both children. The relay requires source and destination return codes zero, a strict exact R1129 non-authoritative JSON receipt, no unexpected fields, no positive AEAD/activation/cutover assertions and no oversized wire content.
- No arbitrary source files or remote shell invocation are exposed to the owner; the library deliberately has NO CLI or configured SSH endpoint. Its safe_argv verifies only structural invariants and DOES NOT establish trust.
- Dedicated synthetic subprocess tests exercise full bytes-in-memory transfer, source bad magic, source nonzero exit, forged destination GO, binary limits, strict response schema and owner-control zeroization.

## Missing before any live data action

A separate exact-pinned owner wrapper must enroll and authenticate both real SSH host keys and original/K137 machine digests, the original R987 V2 encrypted credential and NTFS temporary custody, the R1128 owner Ed25519 signed provisional export approval, the independent archive recovery secret and a private K137 destination under existing DISARMED custody with fresh 20GiB TradeBot reserve. It must pin every Python dependency and source host code before remote execution. No production issuer or original live source-data export is yet enrolled. Do not force this by accepting a bare boolean or disabling R1089 G4/G5.

Even an R1130 success is PROVISIONAL CIPHERTEXT ONLY. It is NOT a complete two-SQLite/WAL consistent backup, full history/finality proof, destination AES-GCM verification, signer continuity or activation. The original Oracle and K137 are unchanged by this development; original two boot backups must remain. G3/G4/G5/G6/G7 and actual cutover remain NO_GO; Oracle retirement STRICT_NO_GO.
