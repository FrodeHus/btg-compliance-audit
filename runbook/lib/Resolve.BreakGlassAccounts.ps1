# Resolves the break-the-glass accounts and groups under test. Depends on Common.Helpers.ps1
# (Add-Result, Add-ErrorResult, Invoke-Graph, Test-Guid, Get-UserTransitiveGroupIds, Write-Results,
# Send-ToLogAnalytics) and on the bound parameters of Test-BreakGlassCompliance.ps1
# ($BreakGlassGroupIds, $BreakGlassUpns). Dot-sourced, never invoked standalone.

function Resolve-BreakGlassAccounts {
    <# Returns a PSCustomObject with BtgUsers (id -> user), BtgGroups (id -> group) and
       UserGroupIds (user id -> transitive group ids, used later by the CA exclusion checks).
       Throws (after shipping a FAIL record) if no accounts resolve at all. #>
    $btgUsers = @{}
    $btgGroups = @{}
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

    [pscustomobject]@{
        BtgUsers     = $btgUsers
        BtgGroups    = $btgGroups
        UserGroupIds = $userGroupIds
    }
}
