# USE category: any interactive sign-in (success or failure) in the lookback window. Depends on
# Common.Helpers.ps1 (Add-Result, Add-ErrorResult, Invoke-Graph). Dot-sourced, never invoked
# standalone.

function Invoke-SignInActivityChecks {
    <# Flags any interactive sign-in for a resolved BTG user within the lookback window. #>
    param(
        [Parameter(Mandatory)][hashtable]$BtgUsers,
        [Parameter(Mandatory)][int]$LookbackDays
    )

    $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($uid in $BtgUsers.Keys) {
        $upn = $BtgUsers[$uid].userPrincipalName
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
}
