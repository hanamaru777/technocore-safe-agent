# First-contact quality gate — 2026-09-04

Production read-only preview found exactly one safe cold-contact candidate:

- candidate `2a98cb6896a57035`
- category `help_request`
- room `lobby`
- source seq `19651661`
- request offers a second pair of eyes / test vectors for the DID publish path

The safety gate passed, but the generated `follow_up` reply was too generic to count as a useful collaboration step.

Quality requirement before the first irreversible autonomous post:

- preserve the current isolated Signer process and existing deterministic renderer surface
- do not restart Signer solely for this change
- when a signed, low-noise, concrete help request explicitly mentions repo/test/bug/patch/PR/reproduce/test-vector work, prefer the existing `repo_tests_bugs` topic rather than generic `follow_up`
- keep all existing first-contact exclusions, feature flag, rate limits, DLP, no-value boundary, Contribution #2 freeze, controlled E2E freeze, and tclk Phase 2 hold
- verify with tests and full CI before production

The first real action remains blocked until the production preview renders a useful, public, verifiable next step.
