# R1141: strict non-authoritative K137 R1129 receipt gate for native R1140.
# An authenticated SSH peer and independent AEAD proof are NOT inferred here.
# Load only as an explicitly pinned library, not as an owner command.
function Assert-R1141R1129Receipt([byte[]]$Raw,[long]$ForwardedBytes) {
    if ($null -eq $Raw -or $Raw.Length -lt 100 -or $Raw.Length -gt 4096 -or
        $ForwardedBytes -lt 8 -or $ForwardedBytes -gt 33554432) {
        throw 'RECEIPT_BOUND_STOP'
    }
    foreach($v in $Raw) {
        if ($v -ne 10 -and $v -ne 13 -and ($v -lt 32 -or $v -gt 126)) {
            throw 'RECEIPT_ASCII_STOP'
        }
    }
    $rawText=[Text.Encoding]::ASCII.GetString($Raw).Trim()
    # R1129 emits compact, ASCII-only JSON with no escapes, nested payloads
    # or arbitrary string values. Reject escapes so quoted false keys cannot
    # confuse our structural duplicate-key check.
    if ($rawText -notmatch '\A\{[A-Za-z0-9_{}:,\s"]+\}\z' -or
        $rawText -match '\\' -or $rawText -match '[\[\]]') {
        throw 'RECEIPT_LEXICAL_STOP'
    }
    $keys=@('phase','result','files','bytes','aead_verified',
        'source_complete','sqlite_epoch','history_finality',
        'signer_portability','activated','cutover','oci_retirement')
    $found=[regex]::Matches($rawText,'(?<=[{,])\s*"([a-z_]+)"\s*:')
    if ($found.Count -ne $keys.Count) { throw 'RECEIPT_SCHEMA_STOP' }
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal)
    foreach($hit in $found) {
        $key=$hit.Groups[1].Value
        if ($keys -cnotcontains $key -or -not $seen.Add($key)) {
            throw 'RECEIPT_DUPLICATE_OR_UNKNOWN_STOP'
        }
    }
    try { $v=$rawText | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'RECEIPT_JSON_STOP' }
    if (@($v.PSObject.Properties.Name).Count -ne $keys.Count) {
        throw 'RECEIPT_SCHEMA_STOP'
    }
    foreach($key in $v.PSObject.Properties.Name) {
        if ($keys -cnotcontains $key) { throw 'RECEIPT_SCHEMA_STOP' }
    }
    if ($v.phase -cne 'R1129' -or
        $v.result -cne 'PROVISIONAL_CIPHERTEXT_STORED_ONLY' -or
        $v.aead_verified -isnot [bool] -or $v.aead_verified -or
        $v.source_complete -isnot [bool] -or $v.source_complete -or
        $v.activated -isnot [bool] -or $v.activated -or
        $v.sqlite_epoch -cne 'NOT_PROVEN' -or
        $v.history_finality -cne 'UNKNOWN' -or
        $v.signer_portability -cne 'NOT_PROVEN' -or
        $v.cutover -cne 'NO_GO' -or
        $v.oci_retirement -cne 'STRICT_NO_GO') {
        throw 'RECEIPT_RELEASE_STOP'
    }
    if (($v.files -isnot [int] -and $v.files -isnot [long]) -or
        $v.files -lt 3 -or $v.files -gt 258 -or
        ($v.bytes -isnot [int] -and $v.bytes -isnot [long]) -or
        $v.bytes -lt 1 -or $v.bytes -gt 33554432 -or
        $v.bytes -gt $ForwardedBytes) {
        throw 'RECEIPT_BYTES_STOP'
    }
    # Always use a newly constructed restricted output, never return the
    # remotely supplied JSON object or bytes as authoritative data.
    return [ordered]@{
        phase='R1141';result='CIPHERTEXT_RECEIPT_STRUCTURALLY_ACCEPTED_ONLY'
        recipient_ciphertext_bytes=[long]$v.bytes
        recipient_ciphertext_files=[long]$v.files
        forwarded_wire_bytes=$ForwardedBytes
        aead_verified=$false;source_complete=$false;activated=$false
        history_finality='UNKNOWN'
        cutover='NO_GO';oci_retirement='STRICT_NO_GO'
    }
}
