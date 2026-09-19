# ROLE category: permanent active Global Administrator, no PIM-eligible assignments, no extra
# roles. Depends on Common.Helpers.ps1 (Add-Result, Add-ErrorResult, Invoke-Graph). Dot-sourced,
# never invoked standalone.

function Invoke-RoleAssignmentChecks {
    <# Evaluates Global Administrator role posture (direct + via group) for each resolved BTG user. #>
    param(
        [Parameter(Mandatory)][hashtable]$BtgUsers,
        [Parameter(Mandatory)][hashtable]$UserGroupIds,
        [Parameter(Mandatory)][string]$GlobalAdminRoleId
    )

    # Two Graph calls per principal, and BTG accounts normally share their groups - without a cache
    # the same group is queried once per member, so the sweep is O(users x groups) rather than one
    # lookup per distinct principal. Cached per call, not across runs, so results stay current.
    $activeCache = @{}
    $eligibleCache = @{}

    foreach ($uid in $BtgUsers.Keys) {
        $upn = $BtgUsers[$uid].userPrincipalName
        try {
            $principalIds = @($uid) + @($UserGroupIds[$uid])
            $active = [System.Collections.Generic.List[object]]::new()
            $eligible = [System.Collections.Generic.List[object]]::new()
            foreach ($principalId in $principalIds) {
                $via = if ($principalId -eq $uid) { 'direct' } else { "group:$principalId" }
                # Cached separately: if the second call throws, the first must not be left looking
                # complete for the next user that shares this principal.
                if (-not $activeCache.ContainsKey($principalId)) {
                    $activeCache[$principalId] = @(Invoke-Graph -Uri "/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$principalId'&`$expand=roleDefinition(`$select=id,displayName)")
                }
                if (-not $eligibleCache.ContainsKey($principalId)) {
                    $eligibleCache[$principalId] = @(Invoke-Graph -Uri "/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$principalId'&`$expand=roleDefinition(`$select=id,displayName)")
                }
                foreach ($x in $activeCache[$principalId]) { $active.Add([pscustomobject]@{ via = $via; role = $x.roleDefinition.displayName; roleId = $x.roleDefinitionId; scope = $x.directoryScopeId; type = $x.assignmentType; end = $x.endDateTime }) }
                foreach ($x in $eligibleCache[$principalId]) { $eligible.Add([pscustomobject]@{ via = $via; role = $x.roleDefinition.displayName; roleId = $x.roleDefinitionId; scope = $x.directoryScopeId; end = $x.endDateTime }) }
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
}
