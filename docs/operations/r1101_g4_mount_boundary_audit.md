R1101: original mount view audit, 2026-10-30

Linux mount namespace per-mount read-only bind flags DO NOT prove that other
mount namespaces cannot still write the original source. man7 mount(2) and
mount_namespaces(7) describe the distinction:
https://man7.org/linux/man-pages/man2/mount.2.html
https://man7.org/linux/man-pages/man7/mount_namespaces.7.html

The original R1089 SourceGuard currently checks statvfs(ST_RDONLY) in its
own namespace. It must NOT be treated as sufficient G4 writer-admission
authority. Complete signed G4 all-launcher barrier plus independently
signed G5 five-route upstream finality and verified epoch are required.
A local view of an RO bind does not provide it.

A previous R1101 edit touched r1089_migration.py, r1089_source_pins.json,
r1066_owner_workflow.ps1 and tests/test_r1089_migration.py; CI rejected
five consumed Windows carrier pins to the owner workflow. ALL FOUR of these
files are now restored to their previous exact Git blobs. The new
r1101_original_mount_boundary_readonly.py is a distinct, read-only,
fail-closed necessary-condition audit. It does not claim G4 PASS and is
NOT yet integrated into a versioned owner acquisition. No Oracle/K137
operations, private key, SSH, filesystem modifications or service changes
are authorized by this code.

The next versioned owner workflow must enforce this boundary throughout
the source stream, and separately exclude writable aliases and all new
launchers under independently enrolled G4. Existing immutable R1089
source/Windows tools must remain preserved; no old cleanup replay.

G3=NO_GO; G4=NO_GO; G5=NO_GO; CUTOVER=NO_GO;
OCI_RETIREMENT=STRICT_NO_GO.
