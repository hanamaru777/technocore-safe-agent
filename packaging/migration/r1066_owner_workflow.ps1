# Windows PowerShell 5.1. This entrypoint never replays consumed witnesses.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) {
    Write-Output '{"phase":"A","operation":"failed","code":"ARGUMENTS_STOP"}'
    exit 42
}
# No destination key, credential or writer-admission proof has been enrolled.
# Do not decrypt R987 or contact either host merely to discover those absences.
$report = [ordered]@{
    task = 'R1066'
    phase = 'A'
    operation = 'blocked'
    code = 'LIVE_TRANSPORT_AND_ADMISSION_NOT_ENROLLED'
    source_integrity = 'unknown'
    destination_integrity = 'unknown'
    common_sqlite_epoch = 'unknown'
    encrypted_archive = 'unknown'
    independent_restore = 'unknown'
    signer_public_identity_match = 'unknown'
    protected_tradebot = 'unknown'
    five_post_routes = 'unknown'
    owner_fence_approval = 'unknown'
    owner_cutover_approval = 'unknown'
    oci_alive = 'unknown'
    oci_retirement = 'STRICT_NO_GO'
    blockers = @(
        'PINNED_K137_HOST_KEY_AND_EXISTING_CREDENTIAL'
        'REAL_SOURCE_AUTHORITY_AND_CONTINUOUS_WRITER_ADMISSION'
        'FIVE_INDEPENDENT_POST_FINALITY_PROOFS'
        'K137_CAPACITY_AND_PROTECTED_CGROUP_APPROVAL'
        'PORTABLE_ORIGINAL_DID_AUTHENTICATION'
    )
}
Write-Output ($report | ConvertTo-Json -Depth 4 -Compress)
exit 42
