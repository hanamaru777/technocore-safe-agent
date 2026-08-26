# Oracle Resident package

This is a reviewed deployment package, not an installer that runs itself. It targets Ubuntu and Oracle Linux, uses the unprivileged `technocore` user, keeps root-managed Discord configuration in `/etc/technocore-safe-agent/env`, and puts public observer/resident state in `/var/lib/technocore-safe-agent`. It never requests, copies, or stores a DID seed.

After review, root may run `./install.sh REPOSITORY_URL` (or add `--discord` for the optional Discord dependency and unit). It clones the repository, installs locked dependencies, writes units, and calls `daemon-reload`; it never enables or starts either service. Review the empty `env` file and explicitly enable services afterwards.

`update.sh` fast-forwards `main`, syncs dependencies, runs secret scan and doctor, and restarts only services that are already active. A failed preflight leaves the running process untouched. `healthcheck.sh` checks the resident process plus observer health and state freshness. `import-state.py` accepts only the current relative-layout export, validates every manifest hash and JSON object, rejects zip-slip/duplicates/flat legacy exports, makes a backup before overwrite, and writes state atomically.
