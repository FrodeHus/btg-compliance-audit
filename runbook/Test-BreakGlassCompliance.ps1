#Requires -Version 7.2
<#
.SYNOPSIS
    Verifies that Entra ID break-the-glass (BTG) accounts are configured according to policy.

.DESCRIPTION
    Designed to run as an Azure Automation PowerShell 7.2 runbook under a system-assigned
    managed identity, but also runs interactively (-UseCurrentAzContext).

    Check groups:
      CA    - Every enabled or report-only Conditional Access policy must exclude each BTG account
              (directly or through an excluded group). Disabled policies produce WARN.
      ACCT  - Account hygiene: enabled, cloud-only, member, *.onmicrosoft.com UPN, no licenses,
              password never expires, no owned objects, FIDO2-only strong auth, per-user MFA disabled.
      ROLE  - Permanent active Global Administrator, no PIM-eligible assignments, no extra roles.
      GRP   - BTG group posture: role-assignable, static membership, cloud-only, no owners, size.
      USE   - Any interactive sign-in (success or failure) in the lookback window.
      TNT   - Tenant guardrails: security defaults off, FIDO2 method policy enabled for BTG,
              Entra ID P1/P2 present, minimum two BTG accounts.

    Results are written as structured records to a Log Analytics custom table through the
    Logs Ingestion API (DCR) and emitted as JSON on the output stream. The runbook throws if any
    check is FAIL (or WARN when -FailOnWarn), so the job shows as Failed and can be alerted on.

    Only Az.Accounts is required (present by default in Automation PS 7.2). Graph is called with
    Invoke-RestMethod to avoid module drift.

.PARAMETER BreakGlassGroupIds
    Comma-separated object IDs (or display names) of security groups whose members are BTG accounts.
.PARAMETER BreakGlassUpns
    Comma-separated UPNs or object IDs of individual BTG accounts. Can be combined with groups.
.PARAMETER LookbackDays
    Sign-in lookback window. Default 7.
.PARAMETER DceLogsIngestionEndpoint
    Logs ingestion URI of the Data Collection Endpoint (https://<dce>.<region>.ingest.monitor.azure.com).
.PARAMETER DcrImmutableId
    Immutable ID of the Data Collection Rule.
.PARAMETER StreamName
    Stream declared in the DCR. Default Custom-BTGCompliance_CL.
.PARAMETER MaxExpectedAccounts
    WARN if more BTG accounts than this are found. Default 4.
.PARAMETER FailOnWarn
    Treat WARN as failure for the exit status.
.PARAMETER SkipLogAnalytics
    Do not ship results to Log Analytics (local testing).
.PARAMETER UseCurrentAzContext
    Use an existing Az context instead of the managed identity. Convenient, but Az tokens lack the
    resource-specific Graph scopes, so several checks will report NOPERM. Prefer -UseGraphPowerShell.
.PARAMETER UseGraphPowerShell
    Route Graph calls through Microsoft Graph PowerShell (Invoke-MgGraphRequest). Requires a prior
    Connect-MgGraph with the scopes listed under NOTES. This is the recommended way to run locally.
.PARAMETER GraphAccessToken
    Use a caller-supplied Graph access token (e.g. from your own app registration).
.PARAMETER ShowErrors
    Print the raw Graph error text to the console for failed checks. Off by default to keep output
    readable. The raw text is never written to Log Analytics or to -OutputFile, as it can contain
    identifiers from the API response.
.PARAMETER OutputFile
    Write the JSON results to this path instead of the output stream.

.OUTPUTS
    JSON array of result records, emitted on the output stream unless -SkipLogAnalytics or -OutputFile
    is used. Status is one of:
      PASS   - check passed
      FAIL   - check failed; the configuration needs fixing
      WARN   - non-blocking finding
      INFO   - context only, no judgement
      NOPERM - could not be evaluated: the identity lacks the Graph permission (a blind spot, not a pass)
      ERROR  - could not be evaluated for another reason

.NOTES
    Graph application permissions required by the managed identity (also the delegated scopes to pass
    to Connect-MgGraph when testing locally):
      Policy.Read.All, Policy.Read.AuthenticationMethod, Directory.Read.All,
      RoleManagement.Read.Directory, AuditLog.Read.All, UserAuthenticationMethod.Read.All
    Azure RBAC: Monitoring Metrics Publisher on the DCR.

    Security review required before production use (auth/data-access code).
#>
[CmdletBinding()]
param(
    [string]$BreakGlassGroupIds = '',
    [string]$BreakGlassUpns = '',
    [int]$LookbackDays = 7,
    [string]$DceLogsIngestionEndpoint = '',
    [string]$DcrImmutableId = '',
    [string]$StreamName = 'Custom-BTGCompliance_CL',
    [int]$MaxExpectedAccounts = 4,
    [switch]$FailOnWarn,
    [switch]$SkipLogAnalytics,
    [switch]$UseCurrentAzContext,
    [switch]$UseGraphPowerShell,
    [string]$GraphAccessToken = '',
    [switch]$ShowErrors,
    [string]$OutputFile = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# region ---------------------------------------------------------------- constants
$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$GraphV1 = 'https://graph.microsoft.com/v1.0'
$GraphBeta = 'https://graph.microsoft.com/beta'
$RunId = [guid]::NewGuid().ToString()
$Results = [System.Collections.Generic.List[object]]::new()
$script:GraphToken = $null
$script:TenantId = ''
$script:GraphTransport = 'Token'   # Token | MgGraph

# Scopes that Get-AzAccessToken tokens do NOT carry. Used to produce an actionable 403 message.
# Ordered so the most specific key wins deterministically.
$ScopeHints = [ordered]@{
    '/authentication/methods'                   = 'UserAuthenticationMethod.Read.All'
    '/authentication/requirements'              = 'Policy.Read.All'
    'roleAssignmentScheduleInstances'           = 'RoleManagement.Read.Directory'
    'roleEligibilityScheduleInstances'          = 'RoleManagement.Read.Directory'
    'identitySecurityDefaultsEnforcementPolicy' = 'Policy.Read.All'
    'authenticationMethodsPolicy'               = 'Policy.Read.AuthenticationMethod'
}

# 403s that are NOT about missing scopes (licensing / unsupported role) must not be reported as NOPERM.
$NonScope403 = 'RequestFromNonPremiumTenant|NonPremiumTenantOrB2CTenant|Premium license|RequestFromUnsupportedUserRole'
# endregion

# region ---------------------------------------------------------------- helpers
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
       a one-line message; the raw error text is kept out of the output unless -ShowErrors is set. #>
    param(
        [Parameter(Mandatory)][string]$CheckId,
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

    Add-Result -CheckId $CheckId -Category $Category -Target $Target -Status $status -Detail $detail `
        -Evidence @{ errorReason = $reason; requiredPermission = $scope }

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

function Get-PlainToken {
    param([string]$ResourceUrl)
    # Az.Accounts >= 2.17 supports -AsSecureString; older versions return plain text.
    try { $t = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString } catch { $t = Get-AzAccessToken -ResourceUrl $ResourceUrl }
    if ($t.Token -is [securestring]) { return (ConvertFrom-SecureString -SecureString $t.Token -AsPlainText) }
    return [string]$t.Token
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
    if ($script:GraphTransport -eq 'Token') {
        if (-not $script:GraphToken) { $script:GraphToken = Get-PlainToken -ResourceUrl 'https://graph.microsoft.com' }
        $headers['Authorization'] = "Bearer $($script:GraphToken)"
    }
    if ($ConsistencyLevel) { $headers['ConsistencyLevel'] = 'eventual' }

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
                    $resp = Invoke-RestMethod -Method $Method -Uri $next -Headers $headers -ContentType 'application/json'
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
    $token = Get-PlainToken -ResourceUrl 'https://monitor.azure.com'
    $uri = "$($DceLogsIngestionEndpoint.TrimEnd('/'))/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2023-01-01"
    $headers = @{ Authorization = "Bearer $token" }
    # Logs Ingestion API accepts max 1 MB per call; batch conservatively.
    $batchSize = 200
    for ($i = 0; $i -lt $Records.Count; $i += $batchSize) {
        $chunk = $Records[$i..([math]::Min($i + $batchSize - 1, $Records.Count - 1))]
        $body = ConvertTo-Json -InputObject @($chunk) -Depth 4 -Compress
        Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType 'application/json' -Body $body | Out-Null
    }
    Write-Host "Shipped $($Records.Count) records to $StreamName."
}
# endregion

# region ---------------------------------------------------------------- auth
# Graph and Azure Monitor are authenticated independently:
#   Graph   - managed identity (default), an explicit token, Graph PowerShell, or the Az context.
#   Monitor - always the Az context / managed identity, and only needed when shipping results.
#
# NOTE for local testing: a token from Get-AzAccessToken is issued to the Az PowerShell/CLI client and
# carries only that client's pre-consented delegated scopes. Directory reads work, but
# UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, Policy.Read.All and
# Policy.Read.AuthenticationMethod are absent, so those checks return 403 no matter which Entra role
# you hold. Use -UseGraphPowerShell (or -GraphAccessToken) instead. See LOCAL_TEST.md.
try {
    $needAz = (-not $SkipLogAnalytics -and $DceLogsIngestionEndpoint -and $DcrImmutableId)

    if ($GraphAccessToken) {
        $script:GraphTransport = 'Token'
        $script:GraphToken = $GraphAccessToken
        Write-Host 'Graph auth: caller-supplied access token.'
        if ($UseGraphPowerShell) { Write-Warning '-GraphAccessToken takes precedence over -UseGraphPowerShell.' }
    }
    elseif ($UseGraphPowerShell) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $mg = Get-MgContext
        if (-not $mg) { throw 'Not connected to Microsoft Graph. Run Connect-MgGraph -Scopes ... first (see LOCAL_TEST.md).' }
        $script:GraphTransport = 'MgGraph'
        Write-Host "Graph auth: Microsoft Graph PowerShell as $($mg.Account) ($($mg.AuthType))."
        Write-Verbose "Granted scopes: $($mg.Scopes -join ', ')"
    }
    elseif ($UseCurrentAzContext) {
        $script:GraphTransport = 'Token'
        if (-not (Get-AzContext)) { throw 'No Az context. Run Connect-AzAccount, or use -UseGraphPowerShell.' }
        Write-Warning 'Using an Az context token for Graph. Permission-scoped checks (auth methods, PIM roles, policies) will report NOPERM. Prefer -UseGraphPowerShell for local testing.'
    }
    else {
        $script:GraphTransport = 'Token'
        Disable-AzContextAutosave -Scope Process | Out-Null
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        $needAz = $true
        Write-Host 'Graph auth: system-assigned managed identity.'
    }

    if ($needAz) {
        if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
            throw 'Log Analytics ingestion requires the Az.Accounts module. Install it, or pass -SkipLogAnalytics.'
        }
        if (-not (Get-AzContext)) {
            throw 'Log Analytics ingestion requires an Az context. Run Connect-AzAccount, or pass -SkipLogAnalytics.'
        }
    }

    $org = Invoke-Graph -Uri '/organization?$select=id,displayName,onPremisesSyncEnabled'
    $script:TenantId = $org[0].id
    Write-Host "Tenant: $($org[0].displayName) ($script:TenantId)  RunId: $RunId"
}
catch {
    Add-ErrorResult -CheckId 'SYS.Auth' -Category SYS -Target 'tenant' -ErrorRecord $_
    # Must not mask the auth error with a file I/O error.
    try { Write-Results } catch { Write-Warning "Could not write results: $($_.Exception.Message)" }
    throw "Authentication failed: $($_.Exception.Message)"
}
# endregion

# region ---------------------------------------------------------------- resolve BTG accounts
$btgUsers = @{}      # id -> user object
$btgGroups = @{}     # id -> group object
$userSelect = 'id,userPrincipalName,displayName,accountEnabled,userType,onPremisesSyncEnabled,assignedLicenses,passwordPolicies,lastPasswordChangeDateTime,createdDateTime,mail'

foreach ($g in ($BreakGlassGroupIds -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    try {
        $grp = if (Test-Guid $g) {
            Invoke-Graph -Uri "/groups/$g`?`$select=id,displayName,isAssignableToRole,groupTypes,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled,securityEnabled,mailEnabled" -AllowNotFound
        }
        else {
            $m = @(Invoke-Graph -Uri "/groups?`$filter=displayName eq '$($g.Replace("'", "''"))'&`$select=id,displayName,isAssignableToRole,groupTypes,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled,securityEnabled,mailEnabled")
            if ($m.Count -ne 1) { throw "Group name '$g' resolved to $($m.Count) groups; use the object ID." }
            $m[0]
        }
        if (-not $grp) { throw "Group '$g' not found." }
        $btgGroups[$grp.id] = $grp
        $members = Invoke-Graph -Uri "/groups/$($grp.id)/transitiveMembers/microsoft.graph.user?`$select=$userSelect"
        foreach ($u in $members) { $btgUsers[$u.id] = $u }
        Add-Result -CheckId 'SYS.ResolveGroup' -Category SYS -Target $grp.displayName -Status INFO -Detail "Resolved $($members.Count) user(s) from group." -Evidence @{ groupId = $grp.id; members = @($members.userPrincipalName) }
    }
    catch { Add-ErrorResult -CheckId 'SYS.ResolveGroup' -Category SYS -Target $g -ErrorRecord $_ }
}

foreach ($u in ($BreakGlassUpns -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    try {
        $usr = Invoke-Graph -Uri "/users/$([uri]::EscapeDataString($u))?`$select=$userSelect" -AllowNotFound
        if (-not $usr) { throw "User '$u' not found." }
        $btgUsers[$usr.id] = $usr
    }
    catch { Add-ErrorResult -CheckId 'SYS.ResolveUser' -Category SYS -Target $u -ErrorRecord $_ }
}

if ($btgUsers.Count -eq 0) {
    Add-Result -CheckId 'SYS.NoAccounts' -Category SYS -Target 'tenant' -Status FAIL -Detail 'No break-the-glass accounts resolved. Check BreakGlassGroupIds / BreakGlassUpns.'
    Send-ToLogAnalytics -Records $Results.ToArray()
    Write-Results
    throw 'No break-the-glass accounts resolved.'
}

# Pre-compute transitive group membership per user (used by CA exclusion evaluation)
$userGroupIds = @{}
foreach ($id in $btgUsers.Keys) { $userGroupIds[$id] = Get-UserTransitiveGroupIds -UserId $id }
# endregion

# region ---------------------------------------------------------------- CA: Conditional Access exclusion
try {
    $policies = Invoke-Graph -Uri '/identity/conditionalAccess/policies'
    if (@($policies).Count -eq 0) {
        Add-Result -CheckId 'CA.NoPolicies' -Category CA -Target 'tenant' -Status WARN -Detail 'Tenant has no Conditional Access policies.'
    }
    foreach ($p in $policies) {
        $cond = $p.conditions.users
        $exUsers = @($cond.excludeUsers)
        $exGroups = @($cond.excludeGroups)
        $exRoles = @($cond.excludeRoles)
        $inUsers = @($cond.includeUsers)
        $inGroups = @($cond.includeGroups)
        $inRoles = @($cond.includeRoles)

        # Group-level exclusion: if a BTG group is configured, it should itself be excluded
        foreach ($gid in $btgGroups.Keys) {
            $groupExcluded = $exGroups -contains $gid
            if (-not $groupExcluded -and $p.state -ne 'disabled') {
                Add-Result -CheckId 'CA.GroupNotExcluded' -Category CA -Target "$($p.displayName)" -Status WARN `
                    -Detail "BTG group '$($btgGroups[$gid].displayName)' is not in the policy's excluded groups (accounts may still be excluded individually)." `
                    -Evidence @{ policyId = $p.id; state = $p.state; groupId = $gid }
            }
        }

        foreach ($uid in $btgUsers.Keys) {
            $u = $btgUsers[$uid]
            $direct = $exUsers -contains $uid
            $viaGroup = @($exGroups | Where-Object { $userGroupIds[$uid] -contains $_ })
            $viaRole = $exRoles -contains $GlobalAdminRoleId
            $excluded = $direct -or $viaGroup.Count -gt 0

            $inScope = ($inUsers -contains 'All') -or ($inUsers -contains $uid) -or
            (@($inGroups | Where-Object { $userGroupIds[$uid] -contains $_ }).Count -gt 0) -or
            ($inRoles -contains $GlobalAdminRoleId)

            $ev = @{
                policyId = $p.id; state = $p.state; directExclusion = $direct
                excludedViaGroups = $viaGroup; roleExclusionOnly = ($viaRole -and -not $excluded); inScope = $inScope
                grantControls = $p.grantControls.builtInControls; sessionControls = ($null -ne $p.sessionControls)
            }

            if ($excluded) {
                Add-Result -CheckId 'CA.Excluded' -Category CA -Target "$($u.userPrincipalName) | $($p.displayName)" -Status PASS `
                    -Detail ("Excluded {0}." -f $(if ($direct) { 'directly' } else { 'via group' })) -Evidence $ev
                continue
            }

            switch ($p.state) {
                'disabled' {
                    Add-Result -CheckId 'CA.NotExcluded' -Category CA -Target "$($u.userPrincipalName) | $($p.displayName)" -Status WARN `
                        -Detail 'Policy is disabled but does not exclude the account. Fix before it is ever enabled.' -Evidence $ev
                }
                default {
                    # enabled or enabledForReportingButNotEnforced
                    $sev = if ($inScope) { 'FAIL' } else { 'WARN' }
                    $why = if ($inScope) { 'Account is in scope and NOT excluded.' } else { 'Account is not currently targeted, but is not explicitly excluded. Exclusion must be explicit.' }
                    if ($viaRole -and -not $inScope) { $why += ' Only a role-based exclusion exists; role exclusions are not a substitute for direct/group exclusion.' }
                    Add-Result -CheckId 'CA.NotExcluded' -Category CA -Target "$($u.userPrincipalName) | $($p.displayName)" -Status $sev `
                        -Detail "[$($p.state)] $why" -Evidence $ev
                }
            }
        }
    }
}
catch { Add-ErrorResult -CheckId 'CA.Evaluate' -Category CA -Target 'tenant' -ErrorRecord $_ }
# endregion

# region ---------------------------------------------------------------- ACCT: account hygiene
foreach ($uid in $btgUsers.Keys) {
    $u = $btgUsers[$uid]
    $upn = $u.userPrincipalName
    try {
        # Enabled
        if ($u.accountEnabled) { Add-Result -CheckId 'ACCT.Enabled' -Category ACCT -Target $upn -Status PASS -Detail 'Account is enabled.' }
        else { Add-Result -CheckId 'ACCT.Enabled' -Category ACCT -Target $upn -Status FAIL -Detail 'Account is DISABLED. A break-glass account must be usable.' }

        # Cloud-only
        if ($u.onPremisesSyncEnabled) { Add-Result -CheckId 'ACCT.CloudOnly' -Category ACCT -Target $upn -Status FAIL -Detail 'Account is synchronised from on-premises AD. Must be cloud-only so on-prem compromise/outage cannot affect it.' }
        else { Add-Result -CheckId 'ACCT.CloudOnly' -Category ACCT -Target $upn -Status PASS -Detail 'Cloud-only account.' }

        # Member, not guest
        if ($u.userType -ne 'Member') { Add-Result -CheckId 'ACCT.UserType' -Category ACCT -Target $upn -Status FAIL -Detail "userType is '$($u.userType)'; must be Member." }
        else { Add-Result -CheckId 'ACCT.UserType' -Category ACCT -Target $upn -Status PASS -Detail 'userType is Member.' }

        # UPN on the initial domain (independent of federation / custom domain issues)
        if ($upn -match '\.onmicrosoft\.com$') { Add-Result -CheckId 'ACCT.UpnDomain' -Category ACCT -Target $upn -Status PASS -Detail 'UPN uses the *.onmicrosoft.com domain.' }
        else { Add-Result -CheckId 'ACCT.UpnDomain' -Category ACCT -Target $upn -Status WARN -Detail 'UPN is on a custom domain. Prefer *.onmicrosoft.com so federation or DNS failures cannot block sign-in.' }

        # No licences
        if (@($u.assignedLicenses).Count -gt 0) { Add-Result -CheckId 'ACCT.NoLicense' -Category ACCT -Target $upn -Status WARN -Detail "Account has $(@($u.assignedLicenses).Count) licence(s) assigned. BTG accounts should be unlicensed (no mailbox, no data)." -Evidence @{ skuIds = @($u.assignedLicenses.skuId) } }
        else { Add-Result -CheckId 'ACCT.NoLicense' -Category ACCT -Target $upn -Status PASS -Detail 'No licences assigned.' }

        # Password never expires
        if ([string]$u.passwordPolicies -match 'DisablePasswordExpiration') { Add-Result -CheckId 'ACCT.PwdNeverExpires' -Category ACCT -Target $upn -Status PASS -Detail 'Password expiration disabled.' }
        else { Add-Result -CheckId 'ACCT.PwdNeverExpires' -Category ACCT -Target $upn -Status FAIL -Detail "passwordPolicies='$($u.passwordPolicies)'. An expired password during an outage locks you out; set DisablePasswordExpiration." }

        # Authentication methods: FIDO2 only
        $methods = Invoke-Graph -Uri "/users/$uid/authentication/methods"
        $types = @($methods | ForEach-Object { ($_.'@odata.type' -replace '#microsoft.graph.', '') })
        $fido = @($methods | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.fido2AuthenticationMethod' })
        $disallowed = @($types | Where-Object { $_ -notin @('fido2AuthenticationMethod', 'passwordAuthenticationMethod') })
        if ($fido.Count -ge 1) { Add-Result -CheckId 'ACCT.Fido2Registered' -Category ACCT -Target $upn -Status PASS -Detail "$($fido.Count) FIDO2 key(s) registered." -Evidence @{ keys = @($fido | ForEach-Object { @{ model = $_.model; displayName = $_.displayName; created = $_.createdDateTime; aaGuid = $_.aaGuid } }) } }
        else { Add-Result -CheckId 'ACCT.Fido2Registered' -Category ACCT -Target $upn -Status FAIL -Detail 'No FIDO2 security key registered.' }
        if ($fido.Count -eq 1) { Add-Result -CheckId 'ACCT.Fido2Redundancy' -Category ACCT -Target $upn -Status WARN -Detail 'Only one FIDO2 key. Register a second key stored in a separate location.' }
        if ($disallowed.Count -gt 0) { Add-Result -CheckId 'ACCT.OnlyFido2' -Category ACCT -Target $upn -Status FAIL -Detail "Non-FIDO2 strong auth methods registered: $($disallowed -join ', '). Remove them so the account cannot be phished/SIM-swapped." -Evidence @{ methods = $types } }
        else { Add-Result -CheckId 'ACCT.OnlyFido2' -Category ACCT -Target $upn -Status PASS -Detail 'Only password + FIDO2 registered.' -Evidence @{ methods = $types } }

        # Per-user (legacy) MFA state must be disabled - CA/passkey governs auth, legacy MFA can block FIDO2 flows
        try {
            $req = Invoke-Graph -Uri "/users/$uid/authentication/requirements" -Beta
            if ($req.perUserMfaState -eq 'disabled') { Add-Result -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -Status PASS -Detail 'Legacy per-user MFA is disabled.' }
            else { Add-Result -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -Status FAIL -Detail "Legacy per-user MFA state is '$($req.perUserMfaState)'. Must be disabled; it bypasses CA exclusions and can force phone-based MFA." }
        }
        catch { Add-ErrorResult -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -ErrorRecord $_ }

        # Owned objects (apps, groups, devices) should be none
        $owned = Invoke-Graph -Uri "/users/$uid/ownedObjects?`$select=id,displayName"
        if (@($owned).Count -gt 0) { Add-Result -CheckId 'ACCT.NoOwnedObjects' -Category ACCT -Target $upn -Status WARN -Detail "Account owns $(@($owned).Count) object(s) (apps/groups). BTG accounts should own nothing." -Evidence @{ owned = @($owned | ForEach-Object { @{ type = $_.'@odata.type'; name = $_.displayName; id = $_.id } }) } }
        else { Add-Result -CheckId 'ACCT.NoOwnedObjects' -Category ACCT -Target $upn -Status PASS -Detail 'Owns no directory objects.' }

        # Password age - informational (rotation cadence is a policy decision)
        if ($u.lastPasswordChangeDateTime) {
            $age = [int]((Get-Date) - [datetime]$u.lastPasswordChangeDateTime).TotalDays
            Add-Result -CheckId 'ACCT.PasswordAge' -Category ACCT -Target $upn -Status INFO -Detail "Password last changed $age day(s) ago." -Evidence @{ lastPasswordChangeDateTime = $u.lastPasswordChangeDateTime }
        }
    }
    catch { Add-ErrorResult -CheckId 'ACCT.Evaluate' -Category ACCT -Target $upn -ErrorRecord $_ }
}
# endregion

# region ---------------------------------------------------------------- ROLE: Global Administrator posture
foreach ($uid in $btgUsers.Keys) {
    $upn = $btgUsers[$uid].userPrincipalName
    try {
        $principalIds = @($uid) + @($userGroupIds[$uid])
        $active = [System.Collections.Generic.List[object]]::new()
        $eligible = [System.Collections.Generic.List[object]]::new()
        foreach ($principalId in $principalIds) {
            $via = if ($principalId -eq $uid) { 'direct' } else { "group:$principalId" }
            $a = Invoke-Graph -Uri "/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$principalId'&`$expand=roleDefinition(`$select=id,displayName)"
            foreach ($x in $a) { $active.Add([pscustomobject]@{ via = $via; role = $x.roleDefinition.displayName; roleId = $x.roleDefinitionId; scope = $x.directoryScopeId; type = $x.assignmentType; end = $x.endDateTime }) }
            $e = Invoke-Graph -Uri "/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$principalId'&`$expand=roleDefinition(`$select=id,displayName)"
            foreach ($x in $e) { $eligible.Add([pscustomobject]@{ via = $via; role = $x.roleDefinition.displayName; roleId = $x.roleDefinitionId; scope = $x.directoryScopeId; end = $x.endDateTime }) }
        }

        $ga = @($active | Where-Object { $_.roleId -eq $GlobalAdminRoleId -and $_.scope -eq '/' })
        $gaPermanent = @($ga | Where-Object { $_.type -eq 'Assigned' -and -not $_.end })
        if ($gaPermanent.Count -gt 0) { Add-Result -CheckId 'ROLE.GlobalAdminPermanent' -Category ROLE -Target $upn -Status PASS -Detail "Permanent active Global Administrator ($($gaPermanent[0].via))." -Evidence @{ assignments = $ga } }
        elseif ($ga.Count -gt 0) { Add-Result -CheckId 'ROLE.GlobalAdminPermanent' -Category ROLE -Target $upn -Status FAIL -Detail "Global Administrator is active but time-bound or PIM-activated (type=$($ga[0].type), end=$($ga[0].end)). Must be a permanent assignment - PIM may be unavailable in the emergency." -Evidence @{ assignments = $ga } }
        else { Add-Result -CheckId 'ROLE.GlobalAdminPermanent' -Category ROLE -Target $upn -Status FAIL -Detail 'No active tenant-wide Global Administrator assignment.' -Evidence @{ assignments = $active } }

        if ($eligible.Count -gt 0) { Add-Result -CheckId 'ROLE.NoEligible' -Category ROLE -Target $upn -Status FAIL -Detail "Has $($eligible.Count) PIM-eligible assignment(s). BTG accounts must not depend on PIM activation." -Evidence @{ eligible = $eligible } }
        else { Add-Result -CheckId 'ROLE.NoEligible' -Category ROLE -Target $upn -Status PASS -Detail 'No PIM-eligible assignments.' }

        $extra = @($active | Where-Object { $_.roleId -ne $GlobalAdminRoleId })
        if ($extra.Count -gt 0) { Add-Result -CheckId 'ROLE.OnlyGlobalAdmin' -Category ROLE -Target $upn -Status WARN -Detail "Holds additional roles: $(($extra.role | Select-Object -Unique) -join ', '). Global Administrator alone is sufficient; extra roles add noise." -Evidence @{ extra = $extra } }
        else { Add-Result -CheckId 'ROLE.OnlyGlobalAdmin' -Category ROLE -Target $upn -Status PASS -Detail 'Holds only Global Administrator.' }
    }
    catch { Add-ErrorResult -CheckId 'ROLE.Evaluate' -Category ROLE -Target $upn -ErrorRecord $_ }
}
# endregion

# region ---------------------------------------------------------------- GRP: BTG group posture
foreach ($gid in $btgGroups.Keys) {
    $g = $btgGroups[$gid]
    $name = $g.displayName
    try {
        if ($g.isAssignableToRole) { Add-Result -CheckId 'GRP.RoleAssignable' -Category GRP -Target $name -Status PASS -Detail 'Group is role-assignable (membership changes require Privileged Role Admin / GA).' }
        else { Add-Result -CheckId 'GRP.RoleAssignable' -Category GRP -Target $name -Status FAIL -Detail 'Group is NOT role-assignable. Any Group Administrator/owner could add themselves and inherit the CA exclusion.' }

        if ((@($g.groupTypes) -contains 'DynamicMembership') -or $g.membershipRule) { Add-Result -CheckId 'GRP.StaticMembership' -Category GRP -Target $name -Status FAIL -Detail 'Group uses dynamic membership. Attribute manipulation could add accounts to the CA exclusion.' -Evidence @{ rule = $g.membershipRule } }
        else { Add-Result -CheckId 'GRP.StaticMembership' -Category GRP -Target $name -Status PASS -Detail 'Assigned (static) membership.' }

        if ($g.onPremisesSyncEnabled) { Add-Result -CheckId 'GRP.CloudOnly' -Category GRP -Target $name -Status FAIL -Detail 'Group is synced from on-premises AD; membership can be changed from AD.' }
        else { Add-Result -CheckId 'GRP.CloudOnly' -Category GRP -Target $name -Status PASS -Detail 'Cloud-only group.' }

        if (-not $g.securityEnabled -or $g.mailEnabled) { Add-Result -CheckId 'GRP.SecurityGroup' -Category GRP -Target $name -Status WARN -Detail "securityEnabled=$($g.securityEnabled), mailEnabled=$($g.mailEnabled). Expect a plain security group." }

        $owners = Invoke-Graph -Uri "/groups/$gid/owners?`$select=id,displayName,userPrincipalName"
        if (@($owners).Count -gt 0) { Add-Result -CheckId 'GRP.NoOwners' -Category GRP -Target $name -Status WARN -Detail "Group has $(@($owners).Count) owner(s). Owners can change membership; prefer no owners and manage via GA." -Evidence @{ owners = @($owners | ForEach-Object { $_.userPrincipalName ?? $_.displayName }) } }
        else { Add-Result -CheckId 'GRP.NoOwners' -Category GRP -Target $name -Status PASS -Detail 'No owners.' }

        $members = Invoke-Graph -Uri "/groups/$gid/members?`$select=id,displayName,userPrincipalName"
        $nonUsers = @($members | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.user' })
        if ($nonUsers.Count -gt 0) { Add-Result -CheckId 'GRP.OnlyUsers' -Category GRP -Target $name -Status FAIL -Detail "Group contains $($nonUsers.Count) non-user member(s) (nested groups / service principals / devices)." -Evidence @{ members = @($nonUsers | ForEach-Object { @{ type = $_.'@odata.type'; name = $_.displayName } }) } }
        else { Add-Result -CheckId 'GRP.OnlyUsers' -Category GRP -Target $name -Status PASS -Detail "All $(@($members).Count) member(s) are users." -Evidence @{ members = @($members.userPrincipalName) } }
    }
    catch { Add-ErrorResult -CheckId 'GRP.Evaluate' -Category GRP -Target $name -ErrorRecord $_ }
}
# endregion

# region ---------------------------------------------------------------- USE: sign-in activity
$since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
foreach ($uid in $btgUsers.Keys) {
    $upn = $btgUsers[$uid].userPrincipalName
    try {
        $signIns = Invoke-Graph -Uri "/auditLogs/signIns?`$filter=userId eq '$uid' and createdDateTime ge $since&`$top=50&`$orderby=createdDateTime desc"
        if (@($signIns).Count -eq 0) { Add-Result -CheckId 'USE.NoSignIns' -Category USE -Target $upn -Status PASS -Detail "No interactive sign-ins in the last $LookbackDays day(s)." }
        else {
            $ev = @($signIns | Select-Object -First 20 | ForEach-Object { @{ time = $_.createdDateTime; app = $_.appDisplayName; ip = $_.ipAddress; location = "$($_.location.city), $($_.location.countryOrRegion)"; status = $_.status.errorCode; failureReason = $_.status.failureReason; caStatus = $_.conditionalAccessStatus; authReq = $_.authenticationRequirement } })
            Add-Result -CheckId 'USE.NoSignIns' -Category USE -Target $upn -Status FAIL -Detail "$(@($signIns).Count) interactive sign-in event(s) in the last $LookbackDays day(s). Every BTG sign-in must be accounted for (planned test or incident)." -Evidence @{ signIns = $ev }
        }
    }
    catch { Add-ErrorResult -CheckId 'USE.NoSignIns' -Category USE -Target $upn -ErrorRecord $_ }
}
# endregion

# region ---------------------------------------------------------------- TNT: tenant guardrails
try {
    $sd = Invoke-Graph -Uri '/policies/identitySecurityDefaultsEnforcementPolicy'
    if ($sd.isEnabled) { Add-Result -CheckId 'TNT.SecurityDefaultsOff' -Category TNT -Target 'tenant' -Status FAIL -Detail 'Security Defaults are ENABLED. They force MFA on all admins with no exclusions and are mutually exclusive with Conditional Access.' }
    else { Add-Result -CheckId 'TNT.SecurityDefaultsOff' -Category TNT -Target 'tenant' -Status PASS -Detail 'Security Defaults disabled (Conditional Access in use).' }
}
catch { Add-ErrorResult -CheckId 'TNT.SecurityDefaultsOff' -Category TNT -Target 'tenant' -ErrorRecord $_ }

try {
    $fidoPolicy = Invoke-Graph -Uri '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'
    if ($fidoPolicy.state -ne 'enabled') { Add-Result -CheckId 'TNT.Fido2MethodEnabled' -Category TNT -Target 'tenant' -Status FAIL -Detail "FIDO2 authentication method policy state is '$($fidoPolicy.state)'." }
    else {
        $targets = @($fidoPolicy.includeTargets)
        $allUsers = $targets | Where-Object { $_.id -eq 'all_users' }
        $covered = @{}
        foreach ($uid in $btgUsers.Keys) {
            $covered[$uid] = [bool]$allUsers -or (@($targets | Where-Object { $_.targetType -eq 'group' -and $userGroupIds[$uid] -contains $_.id }).Count -gt 0)
        }
        $uncovered = @($covered.Keys | Where-Object { -not $covered[$_] } | ForEach-Object { $btgUsers[$_].userPrincipalName })
        if ($uncovered.Count -gt 0) { Add-Result -CheckId 'TNT.Fido2MethodEnabled' -Category TNT -Target 'tenant' -Status FAIL -Detail "FIDO2 is enabled but not targeted at: $($uncovered -join ', ')." -Evidence @{ includeTargets = $targets } }
        else { Add-Result -CheckId 'TNT.Fido2MethodEnabled' -Category TNT -Target 'tenant' -Status PASS -Detail 'FIDO2 method enabled and targets all BTG accounts.' -Evidence @{ enforceAttestation = $fidoPolicy.isAttestationEnforced; selfServiceRegistration = $fidoPolicy.isSelfServiceRegistrationAllowed; keyRestrictions = $fidoPolicy.keyRestrictions } }
        if ($fidoPolicy.keyRestrictions.isEnforced -and $fidoPolicy.keyRestrictions.enforcementType -eq 'allow') {
            Add-Result -CheckId 'TNT.Fido2KeyRestriction' -Category TNT -Target 'tenant' -Status INFO -Detail 'FIDO2 key allow-list is enforced. Confirm the BTG key AAGUIDs are on the list, or an unlisted spare key will be rejected.' -Evidence @{ aaGuids = $fidoPolicy.keyRestrictions.aaGuids }
        }
    }
}
catch { Add-ErrorResult -CheckId 'TNT.Fido2MethodEnabled' -Category TNT -Target 'tenant' -ErrorRecord $_ }

try {
    $skus = Invoke-Graph -Uri '/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans'
    $hasP1 = @($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' -and (@($_.servicePlans.servicePlanName) -match '^(AAD_PREMIUM|AAD_PREMIUM_P2)$') }).Count -gt 0
    if ($hasP1) { Add-Result -CheckId 'TNT.EntraPremium' -Category TNT -Target 'tenant' -Status PASS -Detail 'Entra ID P1/P2 service plan present (Conditional Access licensed).' }
    else { Add-Result -CheckId 'TNT.EntraPremium' -Category TNT -Target 'tenant' -Status WARN -Detail 'No Entra ID P1/P2 service plan found; Conditional Access may be unlicensed.' }
}
catch { Add-ErrorResult -CheckId 'TNT.EntraPremium' -Category TNT -Target 'tenant' -ErrorRecord $_ }

# Count of BTG accounts
if ($btgUsers.Count -lt 2) { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status FAIL -Detail "Only $($btgUsers.Count) break-glass account(s). Microsoft recommends at least two, with credentials stored in separate locations." }
elseif ($btgUsers.Count -gt $MaxExpectedAccounts) { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status WARN -Detail "$($btgUsers.Count) break-glass accounts found; expected at most $MaxExpectedAccounts. Unexpected members inherit CA exclusions." -Evidence @{ accounts = @($btgUsers.Values.userPrincipalName) } }
else { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status PASS -Detail "$($btgUsers.Count) break-glass accounts." -Evidence @{ accounts = @($btgUsers.Values.userPrincipalName) } }
# endregion

# region ---------------------------------------------------------------- summary, ship, exit
$fails = @($Results | Where-Object Status -eq 'FAIL').Count
$warns = @($Results | Where-Object Status -eq 'WARN').Count
$errors = @($Results | Where-Object Status -eq 'ERROR').Count
$noperm = @($Results | Where-Object Status -eq 'NOPERM').Count
$passes = @($Results | Where-Object Status -eq 'PASS').Count

$summaryStatus = if ($fails -gt 0 -or $errors -gt 0 -or $noperm -gt 0) { 'FAIL' } elseif ($warns -gt 0) { 'WARN' } else { 'PASS' }
Add-Result -CheckId 'SYS.Summary' -Category SYS -Target 'tenant' -Status $summaryStatus `
    -Detail "FAIL=$fails WARN=$warns NOPERM=$noperm ERROR=$errors PASS=$passes" `
    -Evidence @{ accounts = @($btgUsers.Values.userPrincipalName); groups = @($btgGroups.Values.displayName); graphTransport = $script:GraphTransport }

if ($noperm -gt 0) {
    $missing = @($Results | Where-Object Status -eq 'NOPERM' | Where-Object { $_.Evidence } |
        ForEach-Object { ($_.Evidence | ConvertFrom-Json -ErrorAction SilentlyContinue).requiredPermission } |
        Where-Object { $_ } | Select-Object -Unique)
    Write-Warning ("$noperm check(s) could not be evaluated for lack of permissions" + $(if ($missing) { ": $($missing -join ', ')" } else { '.' }))
    Write-Warning 'These are blind spots, not passes. Re-run with -ShowErrors for the raw Graph responses.'
}

try { Send-ToLogAnalytics -Records $Results.ToArray() } catch { Write-Warning "Log Analytics ingestion failed: $($_.Exception.Message)" }

Write-Results

if ($fails -gt 0 -or $errors -gt 0 -or $noperm -gt 0 -or ($FailOnWarn -and $warns -gt 0)) {
    throw "Break-the-glass compliance FAILED: $fails FAIL, $noperm NOPERM, $errors ERROR, $warns WARN. See output records."
}
Write-Host "Break-the-glass compliance PASSED ($warns warning(s))."
# endregion
