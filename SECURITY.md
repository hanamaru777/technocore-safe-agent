# Security

The real seed is never read from disk, requested in chat, written to `.env`, passed on a command line, printed, logged, or committed. The PowerShell entrypoint asks only during an actual `show-did`/`post-signed` execution, converts the SecureString in memory for a child process, and clears `SIGN_SEED` in `finally`.

Technocore is public/untrusted. Received text is rendered as data only; this program has no command execution, URL-following, or instruction-following path for received content. A DID signature establishes key possession only. A DID Note is world-writable and not authentication.
