# Shared plumbing used by every check module: result recording, Graph paging/retry, and the
# Logs Ingestion API upload. Depends on script-scope state set up by Test-BreakGlassCompliance.ps1
# ($Results, $RunId, $ScopeHints, $NonScope403, $GraphV1, $GraphBeta) and on the bound parameters
# of that script ($ShowErrors, $OutputFile, $SkipLogAnalytics, $DceLogsIngestionEndpoint,
# $DcrImmutableId, $StreamName). Dot-sourced, never invoked standalone.

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][ValidateSet('CA', 'ACCT', 'ROLE', 'GRP', 'USE', 'TNT', 'SYS')][string]$Category,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'WARN', 'INFO', 'ERROR', 'NOPERM')][string]$Status,
        [Parameter(Mandatory)][string]$Detail,
        $Evidence = $null
    )
    $Results.Add([pscustomobject]@{
            TimeGenerated = (Get-Date).ToUniversalTime().ToString('o')
            RunId         = $RunId
            TenantId      = $script:TenantId
            CheckId       = $CheckId
            Category      = $Category
            Target        = $Target
            Status        = $Status
            Detail        = $Detail
            Evidence      = if ($null -eq $Evidence) { '' } else { ($Evidence | ConvertTo-Json -Depth 6 -Compress) }
        })
    $colour = switch ($Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'ERROR' { 'Magenta' } 'NOPERM' { 'DarkYellow' } default { 'Gray' } }
    Write-Host ("[{0,-6}] {1,-4} {2,-28} {3} :: {4}" -f $Status, $Category, $CheckId, $Target, $Detail) -ForegroundColor $colour
}

function Add-ErrorResult {
    <# Turns an exception into a concise result. Permission problems get their own NOPERM status and
       a one-line message; the raw error text is kept out of the output unless -ShowErrors is set.
       Accepts several CheckIds for the case where one Graph call backs several checks: each of them
       is a separate blind spot, so each gets its own record rather than being collapsed into one. #>
    param(
        [Parameter(Mandatory)][string[]]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)]$ErrorRecord
    )
    $raw = [string]$ErrorRecord
    $scope = ($ScopeHints.Keys | Where-Object { $raw.Contains($_) } | ForEach-Object { $ScopeHints[$_] } | Select-Object -First 1)
    $reason = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { [string]$ErrorRecord.CategoryInfo.Reason } else { $ErrorRecord.GetType().Name }

    # A 403 can mean "scope not granted" or "your tenant/role is not licensed for this API". Only the former is NOPERM.
    $isPerm = ($raw -match '\(403\)|accessDenied|PermissionScopeNotGranted|Authorization_RequestDenied|required scopes are missing|Insufficient privileges') `
        -and ($raw -notmatch $NonScope403)

    if ($isPerm) {
        $status = 'NOPERM'
        $detail = 'Missing permissions to complete this check' + $(if ($scope) { " (requires $scope)." } else { '.' })
    }
    elseif ($raw -match $NonScope403) {
        $status = 'ERROR'
        $detail = 'Endpoint refused the request for licensing or role reasons, not a missing Graph scope (Entra ID P1/P2 required).'
        $scope = $null   # not a scope problem; do not claim a required permission
    }
    else {
        # First non-empty line only, so the console stays readable.
        $first = @($raw -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1)[0]
        $first = if ($first) { $first.Trim() } else { '(no error message)' }
        if ($first.Length -gt 160) { $first = $first.Substring(0, 157) + '...' }
        $status = 'ERROR'
        $detail = "Check could not be completed: $first"
    }

    foreach ($id in $CheckId) {
        Add-Result -CheckId $id -Category $Category -Target $Target -Status $status -Detail $detail `
            -Evidence @{ errorReason = $reason; requiredPermission = $scope }
    }

    # Raw responses can contain UPNs, IPs and other identifiers, so they go to the console only -
    # never into the record shipped to Log Analytics.
    if ($ShowErrors) { Write-Host ("         raw: " + ($raw -replace '\s+', ' ')) -ForegroundColor DarkGray }
}

function Write-Results {
    <# -OutputFile writes to disk; -SkipLogAnalytics suppresses the stdout dump (local runs are read
       from the console); otherwise the JSON goes to the output stream for the Automation job record. #>
    # @() keeps the JSON an array even when there is a single record.
    $json = ConvertTo-Json -InputObject @($Results) -Depth 5
    if ($OutputFile) {
        $dir = Split-Path -Parent $OutputFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -Path $OutputFile -Value $json -Encoding utf8
        Write-Host "Results written to $OutputFile ($($Results.Count) records)."
    }
    elseif (-not $SkipLogAnalytics) {
        Write-Output $json
    }
}

function Get-AccessToken {
    <# Returns the token as a SecureString, which Invoke-RestMethod -Authentication Bearer consumes
       directly. Nothing here decrypts it: a bearer token for Graph or Monitor is a live credential,
       and materialising one as a plain string leaves it readable in the process for the lifetime of
       the run and puts it one Write-Output away from the job record.
       Az.Accounts >= 2.17 returns a SecureString already; older versions return plain text. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Wraps a token Az.Accounts < 2.17 has already returned as plain text. The plaintext originates upstream; converting it here narrows exposure rather than creating it, and there is no encrypted form to read instead.')]
    param([Parameter(Mandatory)][string]$ResourceUrl)
    try { $t = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString } catch { $t = Get-AzAccessToken -ResourceUrl $ResourceUrl }
    if ($t.Token -is [securestring]) { return $t.Token }
    return (ConvertTo-SecureString -String ([string]$t.Token) -AsPlainText -Force)
}

function Invoke-Graph {
    <# Calls Graph with paging and throttling retry. Returns the 'value' array for collections,
       or the object for single entities. Returns $null on 404 when -AllowNotFound. #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [switch]$AllowNotFound,
        [switch]$Beta,
        [switch]$ConsistencyLevel
    )
    if ($Uri -notmatch '^https://') { $Uri = ($(if ($Beta) { $GraphBeta } else { $GraphV1 })) + $Uri }
    $headers = @{}
    if ($ConsistencyLevel) { $headers['ConsistencyLevel'] = 'eventual' }

    # Splatted rather than set as an Authorization header, so the token stays a SecureString.
    $auth = @{}
    if ($script:GraphTransport -eq 'Token') {
        if (-not $script:GraphToken) { $script:GraphToken = Get-AccessToken -ResourceUrl 'https://graph.microsoft.com' }
        $auth = @{ Authentication = 'Bearer'; Token = $script:GraphToken }
    }

    $all = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $attempt = 0
        while ($true) {
            try {
                if ($script:GraphTransport -eq 'MgGraph') {
                    $resp = Invoke-MgGraphRequest -Method $Method -Uri $next -Headers $headers -OutputType PSObject
                }
                else {
                    $resp = Invoke-RestMethod -Method $Method -Uri $next -Headers $headers -ContentType 'application/json' @auth
                }
                break
            }
            catch {
                $status = $null
                try { $status = [int]$_.Exception.Response.StatusCode } catch {}
                if (-not $status) { try { $status = [int]$_.Exception.StatusCode } catch {} }
                # Invoke-MgGraphRequest throws HttpRequestException with no Response; recover the code from the text.
                if (-not $status -and "$($_.Exception.Message) $($_.ErrorDetails.Message)" -match '\b([45]\d{2})\b') { $status = [int]$Matches[1] }
                if ($status -eq 404 -and $AllowNotFound) { return $null }
                if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 5) {
                    $attempt++
                    $retry = 2 * $attempt
                    try { $ra = $_.Exception.Response.Headers.RetryAfter.Delta; if ($ra) { $retry = [int]$ra.Value.TotalSeconds } } catch {}
                    Start-Sleep -Seconds $retry
                    continue
                }
                $msg = "Graph $Method $next failed ($status): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                if ($status -eq 403) {
                    $hint = ($ScopeHints.Keys | Where-Object { "$next".Contains($_) } | ForEach-Object { $ScopeHints[$_] } | Select-Object -First 1)
                    if ($hint) { $msg += "`n  -> Requires the '$hint' permission. Tokens from Get-AzAccessToken do not carry it regardless of your Entra role; for local testing use -UseGraphPowerShell (see LOCAL_TEST.md)." }
                }
                throw $msg
            }
        }
        # Handle both transports: PSObject (Invoke-RestMethod / -OutputType PSObject) and hashtable.
        if ($resp -is [System.Collections.IDictionary]) {
            if (-not $resp.ContainsKey('value')) { return $resp }
            foreach ($v in $resp['value']) { $all.Add($v) }
            $next = $resp['@odata.nextLink']
        }
        elseif ($resp.PSObject.Properties.Name -contains 'value') {
            foreach ($v in $resp.value) { $all.Add($v) }
            $next = $resp.'@odata.nextLink'
        }
        else { return $resp }
    }
    return $all.ToArray()
}

function Test-Guid { param([string]$s) $tmp = [guid]::Empty; return [guid]::TryParse($s, [ref]$tmp) }

function Get-UserTransitiveGroupIds {
    param([string]$UserId)
    $groups = Invoke-Graph -Uri "/users/$UserId/transitiveMemberOf/microsoft.graph.group?`$select=id"
    return @($groups | ForEach-Object { $_.id })
}

function Send-ToLogAnalytics {
    param([object[]]$Records)
    if ($SkipLogAnalytics) { Write-Host 'Skipping Log Analytics ingestion (-SkipLogAnalytics).'; return }
    if (-not $DceLogsIngestionEndpoint -or -not $DcrImmutableId) {
        Write-Warning 'DceLogsIngestionEndpoint / DcrImmutableId not set; results not shipped to Log Analytics.'
        return
    }
    if (@($Records).Count -eq 0) { Write-Host 'No records to ship.'; return }

    $token = Get-AccessToken -ResourceUrl 'https://monitor.azure.com'
    $uri = "$($DceLogsIngestionEndpoint.TrimEnd('/'))/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2023-01-01"

    # The Logs Ingestion API rejects payloads over 1 MB. Record sizes differ by orders of magnitude
    # (Evidence is empty for most checks but carries a list of sign-in events for USE.*), so batches
    # are sized by serialised bytes - a fixed record count overflows on evidence-heavy runs.
    $maxBytes = 900 * 1024   # headroom for array brackets, separators and request framing
    $batches = [System.Collections.Generic.List[object]]::new()
    $batch = [System.Collections.Generic.List[object]]::new()
    $batchBytes = 0

    foreach ($record in $Records) {
        $size = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $record -Depth 4 -Compress)) + 1
        if ($size -gt $maxBytes) {
            throw "Result record '$($record.CheckId)' serialises to $([int]($size / 1KB)) KB, over the $([int]($maxBytes / 1KB)) KB per-request limit. Reduce its Evidence."
        }
        if ($batch.Count -gt 0 -and ($batchBytes + $size) -gt $maxBytes) {
            $batches.Add($batch.ToArray())
            $batch.Clear()
            $batchBytes = 0
        }
        $batch.Add($record)
        $batchBytes += $size
    }
    if ($batch.Count -gt 0) { $batches.Add($batch.ToArray()) }

    foreach ($chunk in $batches) {
        $body = ConvertTo-Json -InputObject @($chunk) -Depth 4 -Compress
        Invoke-RestMethod -Method POST -Uri $uri -Authentication Bearer -Token $token -ContentType 'application/json' -Body $body | Out-Null
    }
    Write-Host "Shipped $($Records.Count) record(s) to $StreamName in $($batches.Count) batch(es)."
}
