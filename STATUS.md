# Status

## Complete

- Phase 0 project governance, security policy, source tracking, CLI, tests, and secret scan.
- Phase 1 safe existing-DID adapter, signed-post confirmation flow, nonce/state handling, DID-note path calculation, and evidence log.

## Next

Use `./flop.ps1 doctor`, inspect official changes with `./flop.ps1 sync-official`, then make only meaningful, user-approved signed posts.

## Blockers

No FLOP Testnet specification has been implemented. It must remain a stub until official documentation is published.

Technocore upstream and its official signer changed on 2026-08-26. `sync-official` detects this; the bundled signer is intentionally not auto-updated.
