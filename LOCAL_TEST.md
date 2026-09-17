# LOCAL_TEST – Running the runbook manually

Use this to validate the checks before deploying the Automation infrastructure, to debug a failing scheduled run, or to do an ad-hoc check after a Conditional Access change.

## 1. Prerequisites

| | Requirement |
|---|---|
| Shell | PowerShell **7.2 or later** (`pwsh`). Windows PowerShell 5.1 will not work (uses `??`, `ConvertFrom-SecureString -AsPlainText`). |
| Module | `Microsoft.Graph.Authentication` – `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`. `Az.Accounts` ≥ 2.17 only if you also want to ship results to Log Analytics. |
| Account | Your **normal admin account** – never a break-glass account. **Global Reader** satisfies every check. |
| Consent | The delegated scopes below need admin consent once per tenant for the *Microsoft Graph Command Line Tools* app. A Global Administrator can approve the prompt on first connect. |
| Network | HTTPS to `graph.microsoft.com` (and `*.ingest.monitor.azure.com` only if you ship results). |

The runbook makes **no writes** to Entra ID. It is safe to run against production.

## 2. Sign in to Graph with the right scopes

**This matters.** Do not authenticate with `Connect-AzAccount` alone. A Graph token from `Get-AzAccessToken` is issued to the Az PowerShell/CLI client and carries only that client's pre-consented scopes. Directory reads (users, groups, CA policies) work, but these four endpoints return **403 regardless of your Entra role**, because the *token* lacks the scope:

| Endpoint | Missing scope |
|---|---|
| `/users/{id}/authentication/methods` | `UserAuthenticationMethod.Read.All` |
| `/roleManagement/directory/roleAssignmentScheduleInstances` | `RoleManagement.Read.Directory` |
| `/policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` |
| `/policies/authenticationMethodsPolicy/.../Fido2` | `Policy.Read.AuthenticationMethod` |

Use Graph PowerShell instead:

```powershell
pwsh
Connect-MgGraph -TenantId <tenant-id> -Scopes `
    'Directory.Read.All', `
    'Policy.Read.All', `
    'Policy.Read.AuthenticationMethod', `
    'RoleManagement.Read.Directory', `
    'AuditLog.Read.All', `
    'UserAuthenticationMethod.Read.All'

(Get-MgContext).Scopes     # verify all six are present
```

If a scope is missing from that output, consent was not granted – have a Global Administrator re-run the connect and approve, or grant admin consent to *Microsoft Graph Command Line Tools* in Entra admin center → Enterprise applications.

## 3. Dry run (no Log Analytics)

From the repository root:

```powershell
./runbook/Test-BreakGlassCompliance.ps1 `
    -BreakGlassGroupIds '<group-object-id>' `
    -UseGraphPowerShell `
    -SkipLogAnalytics
```

Or with explicit accounts:

```powershell
./runbook/Test-BreakGlassCompliance.ps1 `
    -BreakGlassUpns 'btg-01@contoso.onmicrosoft.com,btg-02@contoso.onmicrosoft.com' `
    -UseGraphPowerShell -SkipLogAnalytics
```

Both can be combined. Useful extras: `-LookbackDays 30` widens the sign-in window, `-MaxExpectedAccounts 2` tightens the count check, `-FailOnWarn` makes warnings fail the run, `-ShowErrors` prints the raw Graph error under any failed check, `-OutputFile ./results.json` saves the JSON.

### Other auth options

| Flag | When |
|---|---|
| `-UseGraphPowerShell` | **Recommended for local runs.** Requires `Connect-MgGraph` first. |
| `-GraphAccessToken '<jwt>'` | You have a token from your own app registration with the app roles granted. |
| `-UseCurrentAzContext` | Quick directory-only smoke test. The script warns, and the four scope-dependent checks report `NOPERM`. |
| *(none)* | Managed identity – only works inside Azure Automation. |

### What you should see

One coloured line per check:

```
[PASS  ] CA   CA.Excluded            btg-01@contoso.onmicrosoft.com | Require MFA for all users :: Excluded via group.
[FAIL  ] ACCT ACCT.OnlyFido2         btg-01@contoso.onmicrosoft.com :: Non-FIDO2 strong auth methods registered: ...
[WARN  ] GRP  GRP.NoOwners           BTG-Accounts :: Group has 1 owner(s). ...
[PASS  ] USE  USE.NoSignIns          btg-01@contoso.onmicrosoft.com :: No interactive sign-ins in the last 7 day(s).
[FAIL  ] SYS  SYS.Summary            tenant :: FAIL=1 WARN=3 NOPERM=0 ERROR=0 PASS=41
```

then the full result set as JSON on the output stream, then either

```
Break-the-glass compliance PASSED (3 warning(s)).
```

or a terminating error `Break-the-glass compliance FAILED: …`. The process exit code is non-zero on failure, so it works as a CI gate.

### Status values

| Status | Meaning |
|---|---|
| `PASS` | Check passed. |
| `FAIL` | Configuration needs fixing. |
| `WARN` | Non-blocking finding. |
| `INFO` | Context only, no judgement. |
| `NOPERM` | **Could not be evaluated** – the identity lacks the Graph permission. Shown as `Missing permissions to complete this check (requires X).` This is a blind spot, not a pass, so it fails the run. |
| `ERROR` | Could not be evaluated for another reason; first line of the error only. |

Raw error text is suppressed by default. `-ShowErrors` prints it to the console under the affected check:

```powershell
./runbook/Test-BreakGlassCompliance.ps1 -BreakGlassGroupIds '<id>' -UseGraphPowerShell -SkipLogAnalytics -ShowErrors
```

Raw responses stay on the console and are never written to the result records or Log Analytics, since they can contain UPNs, IP addresses and other identifiers.

## 4. Capture results for review

With `-SkipLogAnalytics` the JSON is **not** written to the output stream – the console lines are the report. To get machine-readable results, use `-OutputFile`:

```powershell
./runbook/Test-BreakGlassCompliance.ps1 -BreakGlassGroupIds '<id>' `
    -UseGraphPowerShell -SkipLogAnalytics -OutputFile ./btg-results.json

$results = Get-Content ./btg-results.json | ConvertFrom-Json

$results | Where-Object Status -in 'FAIL','ERROR','NOPERM' | Format-Table CheckId, Target, Detail -Wrap
$results | Group-Object Status | Select-Object Name, Count
$results | Export-Csv ./btg-results.csv -NoTypeInformation
```

`Evidence` is a JSON string per record; expand it with `$r.Evidence | ConvertFrom-Json`.

Output rules: `-OutputFile` writes to that path and nothing goes to stdout; `-SkipLogAnalytics` alone suppresses the stdout JSON; with neither, the JSON goes to the output stream (which is what the Automation job record captures).

## 5. Ship results to Log Analytics from your workstation (optional)

If the Terraform stack is deployed you can test ingestion end-to-end:

```powershell
Connect-AzAccount -TenantId <tenant-id>    # needed for the Azure Monitor token, in addition to Connect-MgGraph

$dce = terraform -chdir=terraform output -raw dce_logs_ingestion_endpoint
$dcr = terraform -chdir=terraform output -raw dcr_immutable_id

./runbook/Test-BreakGlassCompliance.ps1 -BreakGlassGroupIds '<id>' -UseGraphPowerShell `
    -DceLogsIngestionEndpoint $dce -DcrImmutableId $dcr
```

Graph and Azure Monitor are authenticated separately: `-UseGraphPowerShell` covers Graph, the Az context covers ingestion.

Your account needs **Monitoring Metrics Publisher** on the DCR:

```bash
az role assignment create --assignee <your-upn> --role "Monitoring Metrics Publisher" \
  --scope $(az monitor data-collection rule show -g rg-btg-compliance -n dcr-btg-compliance --query id -o tsv)
```

Query `BTGCompliance_CL | where TimeGenerated > ago(15m)` after 2–5 minutes.

## 6. Debugging a single Graph call

Reproduce a single call against the same session:

```powershell
Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -OutputType PSObject |
    Select-Object -ExpandProperty value | Select-Object displayName, state
```

Common local-only outcomes:

| Result | Cause |
|---|---|
| Four checks show `NOPERM` (auth methods, PIM roles, security defaults, FIDO2 policy) | You used `-UseCurrentAzContext`. Switch to `-UseGraphPowerShell` (step 2). |
| All `NOPERM` | `Connect-MgGraph` ran without the scopes, or consent was declined. Check `(Get-MgContext).Scopes`. |
| `SYS.Auth` fails with "Not connected to Microsoft Graph" | Run `Connect-MgGraph` in the same session before the script. |
| `USE.NoSignIns NOPERM` | `AuditLog.Read.All` missing; the sign-in log API also requires Entra ID P1/P2. |
| No `GRP.*` lines | You passed UPNs only; group checks run only for `-BreakGlassGroupIds`. |
| Script blocked by execution policy | `pwsh -ExecutionPolicy Bypass -File ./runbook/Test-BreakGlassCompliance.ps1 …` |

## 7. Prove the check is real (once, in a test tenant)

Add a BTG account to the include list of a **report-only** CA policy, re-run, and confirm `CA.NotExcluded` becomes FAIL for that policy. Revert. Similarly, register a Temporary Access Pass on a test BTG account and confirm `ACCT.OnlyFido2` fails.

---
Never run this signed in as a break-glass account — doing so creates the exact sign-in event `USE.NoSignIns` is meant to catch. This document was written with AI assistance; verify the steps before relying on them in production.
