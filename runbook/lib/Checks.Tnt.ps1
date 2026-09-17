# TNT category: tenant guardrails - security defaults off, FIDO2 method policy enabled for BTG,
# Entra ID P1/P2 present, minimum two BTG accounts. Depends on Common.Helpers.ps1 (Add-Result,
# Add-ErrorResult, Invoke-Graph). Dot-sourced, never invoked standalone.

function Invoke-TenantGuardrailChecks {
    <# Evaluates tenant-wide guardrails that affect every BTG account. #>
    param(
        [Parameter(Mandatory)][hashtable]$BtgUsers,
        [Parameter(Mandatory)][hashtable]$UserGroupIds,
        [Parameter(Mandatory)][int]$MaxExpectedAccounts
    )

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
            foreach ($uid in $BtgUsers.Keys) {
                $covered[$uid] = [bool]$allUsers -or (@($targets | Where-Object { $_.targetType -eq 'group' -and $UserGroupIds[$uid] -contains $_.id }).Count -gt 0)
            }
            $uncovered = @($covered.Keys | Where-Object { -not $covered[$_] } | ForEach-Object { $BtgUsers[$_].userPrincipalName })
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
    if ($BtgUsers.Count -lt 2) { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status FAIL -Detail "Only $($BtgUsers.Count) break-glass account(s). Microsoft recommends at least two, with credentials stored in separate locations." }
    elseif ($BtgUsers.Count -gt $MaxExpectedAccounts) { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status WARN -Detail "$($BtgUsers.Count) break-glass accounts found; expected at most $MaxExpectedAccounts. Unexpected members inherit CA exclusions." -Evidence @{ accounts = @($BtgUsers.Values.userPrincipalName) } }
    else { Add-Result -CheckId 'TNT.AccountCount' -Category TNT -Target 'tenant' -Status PASS -Detail "$($BtgUsers.Count) break-glass accounts." -Evidence @{ accounts = @($BtgUsers.Values.userPrincipalName) } }
}
