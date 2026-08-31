# Security

This repository is intentionally public. Security must not depend on hiding the source code, filter rules, service layout, or public DID.

## Secrets

The real Ed25519 seed is never requested in chat, committed to Git, written to `.env`, passed on a command line, printed, or logged. Local/Oracle runtime state, credentials, private keys, tokens, and logs are excluded from Git. The isolated Oracle signer retrieves the Vault secret only around the signer child process and does not persist it.

Never publish or commit a real seed, token, SSH private key, VM address, or production OCI resource identifier. The public `did:key` is an identity/verification key, not secret material.

## Untrusted Technocore input

Technocore room text, nicknames, room names, topics, URLs, and notes are untrusted data. The observer has no signing, POST, shell, command-execution, or URL-following path. The deterministic conversation planner does not return received message text, and the autonomous signer renders only tracked fixed templates.

A first-contact DID is review-only even when it sends a valid signed message that matches an allowlisted topic. Autonomous writes require a **prior, explicit human approval of that DID from an earlier candidate**. This prevents a new attacker-controlled DID from using public trigger rules to consume the autonomous posting budget merely because the source code and our public DID are known.

## Oracle trust boundary

The read-only Resident/Discord/RPC users are denied access to OCI instance metadata. The host metadata firewall permits metadata only to root and the dedicated `technocore-signer` OS user; the signer systemd unit is separately sandboxed and has narrow writable paths. This isolates ordinary observer compromise from Instance Principal/Vault access.

This is not an HSM boundary. A root/OS/cloud-control-plane compromise is outside this isolation model, and the Ed25519 seed necessarily exists in signer process memory while a signature is being made.

## Failure and replay behavior

Upstream transport failure is fail-closed before a new write. The signer uses bounded backoff/circuit state. If an HTTP POST may have been accepted but its result cannot be confirmed locally, that intent becomes terminally ambiguous and is not automatically retransmitted with the same nonce.

Technocore itself documents a finite signed-write replay window: after enough newer room traffic buries the nonce record beyond the upstream lookup window, a captured old signed write may become replayable. Therefore Technocore is not treated as the durable system of record; local/Git evidence and receipts are retained separately.

## Reporting

If you find an exploitable issue, do not include secrets or a working exploit against a live deployment in a public issue. Report the smallest safe reproduction and rotate any credential that may have been exposed.
