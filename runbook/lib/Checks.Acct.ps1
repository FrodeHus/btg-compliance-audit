# ACCT category: account hygiene - enabled, cloud-only, member, *.onmicrosoft.com UPN, no
# licenses, password never expires, no owned objects, FIDO2-only strong auth, per-user MFA
# disabled. Depends on Common.Helpers.ps1 (Add-Result, Add-ErrorResult, Invoke-Graph).
# Dot-sourced, never invoked standalone.

function Invoke-AccountHygieneChecks {
    <# Evaluates account-level hygiene for each resolved BTG user.

       Each independent Graph call sits in its own try/catch. A single catch around the whole user
       would let one missing permission abort the remaining checks, reporting a single error instead
       of one blind spot per check - and a check that never ran must never look like a check that
       passed. Checks sharing one call are grouped, since they share the same blind spot. #>
    param([Parameter(Mandatory)][hashtable]$BtgUsers)

    foreach ($uid in $BtgUsers.Keys) {
        $u = $BtgUsers[$uid]
        $upn = $u.userPrincipalName

        # -------- directory properties, already loaded by Resolve-BreakGlassAccounts (no Graph call)
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

            # Password age - informational (rotation cadence is a policy decision)
            if ($u.lastPasswordChangeDateTime) {
                $age = [int]((Get-Date) - [datetime]$u.lastPasswordChangeDateTime).TotalDays
                Add-Result -CheckId 'ACCT.PasswordAge' -Category ACCT -Target $upn -Status INFO -Detail "Password last changed $age day(s) ago." -Evidence @{ lastPasswordChangeDateTime = $u.lastPasswordChangeDateTime }
            }
        }
        catch { Add-ErrorResult -CheckId 'ACCT.Evaluate' -Category ACCT -Target $upn -ErrorRecord $_ }

        # -------- authentication methods: FIDO2 only (one call backs all three checks below)
        try {
            $methods = Invoke-Graph -Uri "/users/$uid/authentication/methods"
            # -replace takes a regex, so the dots need escaping and the prefix anchoring: the
            # unescaped form also matched things like "#microsoftXgraphY".
            $types = @($methods | ForEach-Object { ($_.'@odata.type' -replace '^#microsoft\.graph\.', '') })
            $fido = @($methods | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.fido2AuthenticationMethod' })
            $disallowed = @($types | Where-Object { $_ -notin @('fido2AuthenticationMethod', 'passwordAuthenticationMethod') })
            if ($fido.Count -ge 1) { Add-Result -CheckId 'ACCT.Fido2Registered' -Category ACCT -Target $upn -Status PASS -Detail "$($fido.Count) FIDO2 key(s) registered." -Evidence @{ keys = @($fido | ForEach-Object { @{ model = $_.model; displayName = $_.displayName; created = $_.createdDateTime; aaGuid = $_.aaGuid } }) } }
            else { Add-Result -CheckId 'ACCT.Fido2Registered' -Category ACCT -Target $upn -Status FAIL -Detail 'No FIDO2 security key registered.' }
            if ($fido.Count -eq 1) { Add-Result -CheckId 'ACCT.Fido2Redundancy' -Category ACCT -Target $upn -Status WARN -Detail 'Only one FIDO2 key. Register a second key stored in a separate location.' }
            if ($disallowed.Count -gt 0) { Add-Result -CheckId 'ACCT.OnlyFido2' -Category ACCT -Target $upn -Status FAIL -Detail "Non-FIDO2 strong auth methods registered: $($disallowed -join ', '). Remove them so the account cannot be phished/SIM-swapped." -Evidence @{ methods = $types } }
            else { Add-Result -CheckId 'ACCT.OnlyFido2' -Category ACCT -Target $upn -Status PASS -Detail 'Only password + FIDO2 registered.' -Evidence @{ methods = $types } }
        }
        catch { Add-ErrorResult -CheckId 'ACCT.Fido2Registered', 'ACCT.OnlyFido2' -Category ACCT -Target $upn -ErrorRecord $_ }

        # -------- per-user (legacy) MFA must be disabled - CA/passkey governs auth, legacy MFA can block FIDO2 flows
        try {
            $req = Invoke-Graph -Uri "/users/$uid/authentication/requirements" -Beta
            if ($req.perUserMfaState -eq 'disabled') { Add-Result -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -Status PASS -Detail 'Legacy per-user MFA is disabled.' }
            else { Add-Result -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -Status FAIL -Detail "Legacy per-user MFA state is '$($req.perUserMfaState)'. Must be disabled; it bypasses CA exclusions and can force phone-based MFA." }
        }
        catch { Add-ErrorResult -CheckId 'ACCT.PerUserMfaOff' -Category ACCT -Target $upn -ErrorRecord $_ }

        # -------- owned objects (apps, groups, devices) should be none
        try {
            $owned = Invoke-Graph -Uri "/users/$uid/ownedObjects?`$select=id,displayName"
            if (@($owned).Count -gt 0) { Add-Result -CheckId 'ACCT.NoOwnedObjects' -Category ACCT -Target $upn -Status WARN -Detail "Account owns $(@($owned).Count) object(s) (apps/groups). BTG accounts should own nothing." -Evidence @{ owned = @($owned | ForEach-Object { @{ type = $_.'@odata.type'; name = $_.displayName; id = $_.id } }) } }
            else { Add-Result -CheckId 'ACCT.NoOwnedObjects' -Category ACCT -Target $upn -Status PASS -Detail 'Owns no directory objects.' }
        }
        catch { Add-ErrorResult -CheckId 'ACCT.NoOwnedObjects' -Category ACCT -Target $upn -ErrorRecord $_ }
    }
}
