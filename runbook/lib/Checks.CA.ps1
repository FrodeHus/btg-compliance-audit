# CA category: every enabled or report-only Conditional Access policy must exclude each BTG
# account (directly or through an excluded group). Depends on Common.Helpers.ps1 (Add-Result,
# Add-ErrorResult, Invoke-Graph). Dot-sourced, never invoked standalone.

function Invoke-ConditionalAccessChecks {
    <# Evaluates every Conditional Access policy against each resolved BTG account/group. #>
    param(
        [Parameter(Mandatory)][hashtable]$BtgUsers,
        [Parameter(Mandatory)][hashtable]$BtgGroups,
        [Parameter(Mandatory)][hashtable]$UserGroupIds,
        [Parameter(Mandatory)][string]$GlobalAdminRoleId
    )
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
            foreach ($gid in $BtgGroups.Keys) {
                $groupExcluded = $exGroups -contains $gid
                if (-not $groupExcluded -and $p.state -ne 'disabled') {
                    Add-Result -CheckId 'CA.GroupNotExcluded' -Category CA -Target "$($p.displayName)" -Status WARN `
                        -Detail "BTG group '$($BtgGroups[$gid].displayName)' is not in the policy's excluded groups (accounts may still be excluded individually)." `
                        -Evidence @{ policyId = $p.id; state = $p.state; groupId = $gid }
                }
            }

            foreach ($uid in $BtgUsers.Keys) {
                $u = $BtgUsers[$uid]
                $direct = $exUsers -contains $uid
                $viaGroup = @($exGroups | Where-Object { $UserGroupIds[$uid] -contains $_ })
                $viaRole = $exRoles -contains $GlobalAdminRoleId
                $excluded = $direct -or $viaGroup.Count -gt 0

                $inScope = ($inUsers -contains 'All') -or ($inUsers -contains $uid) -or
                (@($inGroups | Where-Object { $UserGroupIds[$uid] -contains $_ }).Count -gt 0) -or
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
}
