# Oracle Resident package

This package is a deployment template only; it does not install, enable, or connect anything automatically. Run it only after reviewing paths, ownership, systemd unit names, and outbound-only networking. Keep all Resident state in `/var/lib/technocore-safe-agent`; do not place a DID seed on the VM. The optional Discord env file is mode 0600 and must contain only Discord controls, never a DID seed.

To transfer a locally created export, review it and run `import-state.py EXPORT.zip /var/lib/technocore-safe-agent`. The importer accepts only the documented public-state allowlist and verifies its manifest hashes.
