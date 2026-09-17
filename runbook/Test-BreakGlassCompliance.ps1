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

# region ---------------------------------------------------------------- module imports
# Locally these dot-source the modular helper/check files under ./lib, in the order each depends
# on the last. For the Azure Automation runbook, terraform/main.tf replaces this exact region
# (between the START/END markers) with the concatenated content of the same files, because
# Automation runbooks execute as a single script with no file system access to sibling files.
# RUNBOOK_LIB_IMPORTS_START
. "$PSScriptRoot/lib/Common.Helpers.ps1"
. "$PSScriptRoot/lib/Common.Auth.ps1"
. "$PSScriptRoot/lib/Resolve.BreakGlassAccounts.ps1"
. "$PSScriptRoot/lib/Checks.CA.ps1"
. "$PSScriptRoot/lib/Checks.Acct.ps1"
. "$PSScriptRoot/lib/Checks.Role.ps1"
. "$PSScriptRoot/lib/Checks.Grp.ps1"
. "$PSScriptRoot/lib/Checks.Use.ps1"
. "$PSScriptRoot/lib/Checks.Tnt.ps1"
# RUNBOOK_LIB_IMPORTS_END
# endregion

# region ---------------------------------------------------------------- auth
Connect-BreakGlassGraph
# endregion

# region ---------------------------------------------------------------- resolve BTG accounts
$resolved = Resolve-BreakGlassAccounts
$btgUsers = $resolved.BtgUsers
$btgGroups = $resolved.BtgGroups
$userGroupIds = $resolved.UserGroupIds
# endregion

# region ---------------------------------------------------------------- run checks
Invoke-ConditionalAccessChecks -BtgUsers $btgUsers -BtgGroups $btgGroups -UserGroupIds $userGroupIds -GlobalAdminRoleId $GlobalAdminRoleId
Invoke-AccountHygieneChecks -BtgUsers $btgUsers
Invoke-RoleAssignmentChecks -BtgUsers $btgUsers -UserGroupIds $userGroupIds -GlobalAdminRoleId $GlobalAdminRoleId
Invoke-GroupPostureChecks -BtgGroups $btgGroups
Invoke-SignInActivityChecks -BtgUsers $btgUsers -LookbackDays $LookbackDays
Invoke-TenantGuardrailChecks -BtgUsers $btgUsers -UserGroupIds $userGroupIds -MaxExpectedAccounts $MaxExpectedAccounts
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
