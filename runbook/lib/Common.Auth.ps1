# Graph and Azure Monitor authentication. Depends on Common.Helpers.ps1 (Add-ErrorResult, Write-Results)
# and on the bound parameters of Test-BreakGlassCompliance.ps1 ($GraphAccessToken, $UseGraphPowerShell,
# $UseCurrentAzContext, $SkipLogAnalytics, $DceLogsIngestionEndpoint, $DcrImmutableId). Sets
# $script:GraphTransport, $script:GraphToken and $script:TenantId. Dot-sourced, never invoked standalone.

function Connect-BreakGlassGraph {
    <# Graph and Azure Monitor are authenticated independently:
         Graph   - managed identity (default), an explicit token, Graph PowerShell, or the Az context.
         Monitor - always the Az context / managed identity, and only needed when shipping results.

       NOTE for local testing: a token from Get-AzAccessToken is issued to the Az PowerShell/CLI client
       and carries only that client's pre-consented delegated scopes. Directory reads work, but
       UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, Policy.Read.All and
       Policy.Read.AuthenticationMethod are absent, so those checks return 403 no matter which Entra
       role you hold. Use -UseGraphPowerShell (or -GraphAccessToken) instead. See LOCAL_TEST.md. #>
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
}
