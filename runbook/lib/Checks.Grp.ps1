# GRP category: BTG group posture - role-assignable, static membership, cloud-only, no owners,
# only user members. Depends on Common.Helpers.ps1 (Add-Result, Add-ErrorResult, Invoke-Graph).
# Dot-sourced, never invoked standalone.

function Invoke-GroupPostureChecks {
    <# Evaluates group hardening for each resolved BTG group. #>
    param([Parameter(Mandatory)][hashtable]$BtgGroups)

    foreach ($gid in $BtgGroups.Keys) {
        $g = $BtgGroups[$gid]
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
}
