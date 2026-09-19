#Requires -Version 7.2
<#
.SYNOPSIS
    Build-time checks for the break-the-glass runbook.

.DESCRIPTION
    Azure Automation executes the runbook as a single script with no access to sibling files, so
    terraform/main.tf splices the contents of runbook/lib into the main script in place of its
    dot-source block. That assembled script - not what any one file in the repo looks like - is what
    actually runs in Azure, so it is what these checks parse.

    They also assert that the lib list in main.tf matches the dot-source block in the main script.
    Nothing at runtime notices when those two drift: the local -UseGraphPowerShell path keeps working
    from the dot-sources while the deployed runbook silently loses whatever main.tf was not told
    about. That failure is invisible until a check stops reporting in production.

    Exits non-zero if any check fails. Takes no arguments; locates the repo relative to itself.

.EXAMPLE
    ./tests/Test-RunbookBuild.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$mainPath = Join-Path $repoRoot 'runbook/Test-BreakGlassCompliance.ps1'
$libDir = Join-Path $repoRoot 'runbook/lib'
$tfPath = Join-Path $repoRoot 'terraform/main.tf'

$startMarker = '# RUNBOOK_LIB_IMPORTS_START'
$endMarker = '# RUNBOOK_LIB_IMPORTS_END'

$failed = [System.Collections.Generic.List[string]]::new()

function Assert-That {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Detail = ''
    )
    if ($Condition) {
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    else {
        Write-Host ("  FAIL  $Name" + $(if ($Detail) { " - $Detail" } else { '' })) -ForegroundColor Red
        $failed.Add($Name)
    }
}

Write-Host "`nRunbook build checks" -ForegroundColor Cyan

# ---------------------------------------------------------------- splice markers
$main = Get-Content $mainPath -Raw
$startCount = ([regex]::Matches($main, [regex]::Escape($startMarker))).Count
$endCount = ([regex]::Matches($main, [regex]::Escape($endMarker))).Count

# main.tf splits on these and indexes the result, so anything other than exactly one of each either
# fails the apply with an index error or silently drops part of the script.
Assert-That 'main script contains exactly one START marker' ($startCount -eq 1) "found $startCount"
Assert-That 'main script contains exactly one END marker' ($endCount -eq 1) "found $endCount"
if ($startCount -ne 1 -or $endCount -ne 1) {
    Write-Host "`nCannot continue without exactly one marker pair." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------- lib order: main script vs main.tf
$importsRegion = (($main -split [regex]::Escape($startMarker))[1] -split [regex]::Escape($endMarker))[0]
$dotSourced = @([regex]::Matches($importsRegion, '\.\s+"\$PSScriptRoot/lib/([^"]+)"') |
    ForEach-Object { $_.Groups[1].Value })

$tf = Get-Content $tfPath -Raw
$tfListMatch = [regex]::Match($tf, 'runbook_lib_files\s*=\s*\[(?<body>.*?)\]', 'Singleline')
Assert-That 'main.tf declares runbook_lib_files' $tfListMatch.Success
$tfList = @([regex]::Matches($tfListMatch.Groups['body'].Value, '"([^"]+)"') |
    ForEach-Object { $_.Groups[1].Value })

Assert-That 'main script dot-sources at least one lib file' ($dotSourced.Count -gt 0)
Assert-That 'main.tf and the main script agree on lib files and order' `
    (($dotSourced -join '|') -eq ($tfList -join '|')) `
    "script=[$($dotSourced -join ', ')] main.tf=[$($tfList -join ', ')]"

foreach ($f in $tfList) {
    Assert-That "lib file exists: $f" (Test-Path (Join-Path $libDir $f))
}

# Anything in lib/ that neither side lists would never reach Azure and never be dot-sourced locally.
$onDisk = @(Get-ChildItem -Path $libDir -Filter '*.ps1' | Select-Object -ExpandProperty Name)
$unlisted = @($onDisk | Where-Object { $_ -notin $tfList })
Assert-That 'every file in runbook/lib is listed' ($unlisted.Count -eq 0) "unlisted: $($unlisted -join ', ')"

# ---------------------------------------------------------------- assemble exactly as main.tf does
$libContent = ($tfList | ForEach-Object { Get-Content (Join-Path $libDir $_) -Raw }) -join "`n"
$assembled = ($main -split [regex]::Escape($startMarker))[0] +
$libContent +
($main -split [regex]::Escape($endMarker))[1]

$parseErrors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($assembled, [ref]$tokens, [ref]$parseErrors)

Assert-That 'assembled runbook parses without errors' (@($parseErrors).Count -eq 0) `
    (($parseErrors | ForEach-Object { "L$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')

# A surviving dot-source would throw at runtime in Azure: the sandbox has no lib directory.
Assert-That 'assembled runbook has no remaining dot-source of lib/' `
    (-not ($assembled -match '\.\s+"\$PSScriptRoot/lib/'))

# ---------------------------------------------------------------- the assembly is actually complete
$defined = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { $_.Name })

# The orchestration calls in the main body; if the splice drops a file these vanish silently.
$required = @(
    'Add-Result', 'Add-ErrorResult', 'Write-Results', 'Invoke-Graph', 'Send-ToLogAnalytics'
    'Connect-BreakGlassGraph', 'Resolve-BreakGlassAccounts'
    'Invoke-ConditionalAccessChecks', 'Invoke-AccountHygieneChecks', 'Invoke-RoleAssignmentChecks'
    'Invoke-GroupPostureChecks', 'Invoke-SignInActivityChecks', 'Invoke-TenantGuardrailChecks'
)
$missing = @($required | Where-Object { $_ -notin $defined })
Assert-That 'assembled runbook defines every entry-point function' ($missing.Count -eq 0) `
    "missing: $($missing -join ', ')"

# Each function must be defined once; the splice concatenating a file twice would shadow silently.
$dupes = @($defined | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
Assert-That 'no function is defined more than once' ($dupes.Count -eq 0) "duplicated: $($dupes -join ', ')"

# ---------------------------------------------------------------- result
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) check(s) failed.`n" -ForegroundColor Red
    exit 1
}
Write-Host "`nAll runbook build checks passed.`n" -ForegroundColor Green
