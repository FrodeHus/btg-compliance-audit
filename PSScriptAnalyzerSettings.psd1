@{
    # Rules excluded deliberately, so that whatever PSScriptAnalyzer does report is signal.
    # Each exclusion is a property of how this runbook is built and run, not a style preference.
    ExcludeRules = @(
        # The runbook's stdout is its data channel: Write-Results emits the JSON result array that
        # the Automation job record and -OutputFile consume. Human-readable progress therefore has
        # to go to the host stream, or it would corrupt that payload. Azure Automation captures
        # Write-Host into the job output, so it is visible where it matters.
        'PSAvoidUsingWriteHost'

        # Invoke-*Checks, Write-Results and Get-UserTransitiveGroupIds each act on a set and emit
        # many records. The plural reads correctly at the call site and these are not shipped as a
        # module, so the singular-noun convention buys nothing here.
        'PSUseSingularNouns'

        # These two fire on the dot-source architecture, not on real dead code. The files in
        # runbook/lib read $Results, $RunId, $ScopeHints, $ShowErrors, $OutputFile and the ingestion
        # parameters from the scope of Test-BreakGlassCompliance.ps1, which analyses each file in
        # isolation and so cannot see the use. Revisit both if that coupling is ever replaced by an
        # explicit context object - they would become useful again.
        'PSReviewUnusedParameter'
        'PSUseDeclaredVarsMoreThanAssignments'

        # Invoke-Graph recovers an HTTP status code from exception shapes that differ between
        # Invoke-RestMethod and Invoke-MgGraphRequest, and reads an optional Retry-After header.
        # Each probe is best-effort by design and the surrounding code handles the absent case, so
        # an empty catch is the accurate expression of "this property may not exist".
        'PSAvoidUsingEmptyCatchBlock'
    )
}
