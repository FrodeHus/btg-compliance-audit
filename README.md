# Break-the-glass account compliance monitor

This repository is published as open source for transparency, community review, and collaborative hardening of emergency-access monitoring in Microsoft Entra ID.

Key project docs:

- [LICENSE](LICENSE)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Automated, scheduled verification that Entra ID break-the-glass (BTG) accounts are configured the way an emergency demands: excluded from every Conditional Access policy, hardened, permanently Global Administrator, unused, and backed by tenant-level guardrails. Results land in a Log Analytics custom table and alert on drift.

```
Break-the-glass/
├── runbook/Test-BreakGlassCompliance.ps1   PowerShell 7.2 runbook (Az.Accounts only, Graph via REST)
└── terraform/                               Azure Verified Modules deployment
    ├── providers.tf   azurerm / azapi / azuread / time
    ├── variables.tf   configuration surface
    ├── main.tf        RG, Log Analytics + custom table, DCE, DCR, Automation Account + runbook + schedule, RBAC
    ├── graph.tf       Graph app-role grants to the managed identity, BTG UPN resolution
    ├── alerts.tf      Action group + 3 scheduled query alerts
    ├── outputs.tf
    └── terraform.tfvars.example
```

## What gets checked

Every result is tagged with a category, so you can filter the table on one concern at a time (`BTGCompliance_CL | where Category == "CA"`). The check IDs are prefixed with the same code.

| Category | Stands for | Scope of the checks | Asks the question |
|---|---|---|---|
| `CA` | Conditional Access | Every CA policy in the tenant, evaluated against every BTG account | Can a Conditional Access policy lock us out of our own tenant during an incident? |
| `ACCT` | Account hygiene | Each individual BTG user object and its credentials | Is this account itself usable in an emergency and hardened against misuse? |
| `ROLE` | Role assignments | Directory role assignments and PIM eligibility for each account | Will the account actually hold Global Administrator when we need it, without depending on PIM? |
| `GRP` | Group posture | The security group(s) whose members are treated as BTG accounts | Could someone quietly add themselves to the group and inherit its CA exclusion? |
| `USE` | Usage | Sign-in logs for each account over the lookback window | Has anyone used a break-glass account, and do we know why? |
| `TNT` | Tenant guardrails | Tenant-wide settings that apply regardless of the accounts | Are the tenant-level prerequisites for this whole design in place? |
| `SYS` | Runbook self-reporting | The run itself: authentication, account resolution, totals | Did the check actually run, and against the accounts we intended? |

`SYS` records are about the tooling rather than your configuration, which makes them the ones to watch first: a `SYS.NoAccounts` failure or a `SYS.Auth` error means none of the other categories can be trusted for that run.

| Category | CheckId | Severity on failure | What it verifies |
|---|---|---|---|
| CA | `CA.Excluded` / `CA.NotExcluded` | FAIL if account is in scope of an enabled or report-only policy and not excluded; WARN if not in scope but not explicitly excluded, or policy disabled | Each BTG account is excluded directly or via an excluded group. Role-based exclusion alone does not count. |
| CA | `CA.GroupNotExcluded` | WARN | The BTG group itself is in the policy's excluded groups (when a group is configured). |
| ACCT | `ACCT.Enabled` | FAIL | Account is enabled. |
| ACCT | `ACCT.CloudOnly` | FAIL | Not synced from on-prem AD. |
| ACCT | `ACCT.UserType` | FAIL | `Member`, not guest. |
| ACCT | `ACCT.UpnDomain` | WARN | UPN on `*.onmicrosoft.com`, immune to federation/DNS failures. |
| ACCT | `ACCT.NoLicense` | WARN | No licences (no mailbox, no data). |
| ACCT | `ACCT.PwdNeverExpires` | FAIL | `DisablePasswordExpiration` set. |
| ACCT | `ACCT.Fido2Registered` | FAIL | At least one FIDO2 key. |
| ACCT | `ACCT.Fido2Redundancy` | WARN | At least two keys (separate storage locations). |
| ACCT | `ACCT.OnlyFido2` | FAIL | No Authenticator, phone, email, OATH, TAP or WHfB methods registered. |
| ACCT | `ACCT.PerUserMfaOff` | FAIL | Legacy per-user MFA state is `disabled`; it bypasses CA exclusions. Beta endpoint, so it can report NOPERM. |
| ACCT | `ACCT.NoOwnedObjects` | WARN | Owns no apps or groups. |
| ACCT | `ACCT.PasswordAge` | INFO | Days since last password change (rotation cadence is your policy call). |
| ROLE | `ROLE.GlobalAdminPermanent` | FAIL | Permanent, active, tenant-scoped Global Administrator (direct or via role-assignable group). Time-bound or PIM-activated does not pass. |
| ROLE | `ROLE.NoEligible` | FAIL | No PIM-eligible assignments; PIM may be down in the emergency. |
| ROLE | `ROLE.OnlyGlobalAdmin` | WARN | No additional roles. |
| GRP | `GRP.RoleAssignable` | FAIL | Group is role-assignable so only PRA/GA can change membership. |
| GRP | `GRP.StaticMembership` | FAIL | No dynamic membership rule. |
| GRP | `GRP.CloudOnly` | FAIL | Group not synced from on-prem. |
| GRP | `GRP.NoOwners` | WARN | No owners. |
| GRP | `GRP.OnlyUsers` | FAIL | No nested groups, service principals or devices. |
| USE | `USE.NoSignIns` | FAIL | No interactive sign-ins (success or failure) in the lookback window. Any use must be accounted for. |
| TNT | `TNT.SecurityDefaultsOff` | FAIL | Security Defaults disabled (they cannot coexist with CA and have no exclusions). |
| TNT | `TNT.Fido2MethodEnabled` | FAIL | FIDO2 authentication method policy enabled and targeting the BTG accounts. |
| TNT | `TNT.Fido2KeyRestriction` | INFO | Key AAGUID allow-list is enforced; confirm spare keys are on it. |
| TNT | `TNT.EntraPremium` | WARN | Entra ID P1/P2 present. |
| TNT | `TNT.AccountCount` | FAIL < 2, WARN > `max_expected_accounts` | Two or more accounts, no unexpected extras. |
| SYS | `SYS.Summary` | | One record per run with totals; used by the "runbook silent" alert. |

Each result carries one of six statuses: `PASS`, `FAIL`, `WARN`, `INFO`, `NOPERM` (the check could not be evaluated because the identity lacks the Graph permission — a blind spot, not a pass) and `ERROR` (could not be evaluated for another reason). The runbook throws when any FAIL, NOPERM or ERROR exists, so the Automation job itself shows as Failed.

Raw Graph error text is kept out of the result records deliberately, since responses can contain identifiers; `-ShowErrors` prints it to the console for debugging.

## Scope

Single tenant by design. The runbook authenticates with the Automation Account's system-assigned managed identity, which is a tenant-local service principal and cannot read another tenant's directory. To cover several tenants, deploy the stack once per tenant with its own Terraform state; a central hub would mean replacing the managed identity with a multi-tenant app registration, which is deliberately out of scope here.

## State and security

This repo intentionally keeps Terraform state local by default. The state file can include BTG account identifiers, object IDs, and other sensitive directory metadata, so remote state should only be enabled deliberately after a security review and with appropriate access controls.

Do not commit a real `terraform.tfvars` file or any state file. The default is:

```bash
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

If you choose to enable a remote backend, do it only in a local, reviewed copy and never as the repository default.

## Deploy

Prerequisites: Terraform >= 1.9 and an `az login` as an identity with Owner (or Contributor + User Access Administrator) on the target subscription. No Entra admin role is needed for the infrastructure — granting the managed identity's Graph permissions is a separate, optional phase (see below).

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set subscription_id, group IDs / UPNs, receivers
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

Then run the runbook once manually from the Automation Account (Runbooks → Test-BreakGlassCompliance → Start) and confirm rows appear:

```kusto
BTGCompliance_CL
| where TimeGenerated > ago(1h)
| summarize count() by Status, Category
```

### What Terraform creates

Azure Verified Modules: `avm-res-resources-resourcegroup`, `avm-res-operationalinsights-workspace` (only when creating a workspace), `avm-res-insights-datacollectionendpoint`, `avm-res-insights-datacollectionrule` (stream `Custom-<table>`), `avm-res-automation-automationaccount` (PS 7.2 runbook, schedule, job schedule with parameters, system-assigned identity, diagnostics to the workspace, local auth off, public access off).

Native resources where no AVM module exists: `azapi_resource` (the custom table, so the schema is defined once for both the new- and existing-workspace paths), `azurerm_role_assignment` (Monitoring Metrics Publisher on the DCR), `azuread_app_role_assignment` (Graph permissions, optional), `azurerm_monitor_action_group`, three `azurerm_monitor_scheduled_query_rules_alert_v2`, optional `azurerm_monitor_aad_diagnostic_setting`.

### Bring your own Log Analytics workspace

Set `existing_log_analytics_workspace_resource_id` to reuse a workspace (a Sentinel one is a good choice — the sign-in alert then already has `SigninLogs`). No workspace is created, and the DCE, DCR and alert rules follow **the workspace's region** rather than `var.location`, because the Logs Ingestion API requires workspace, DCE and DCR to share a region. You need Log Analytics Contributor on it to create the table, or set `create_custom_table = false` and have its owner create the table from `local.table_api_columns` in `main.tf`. `table_name` is configurable.

### Deploying without Privileged Role Administrator

The infrastructure needs no Entra admin role. Graph permissions are a separate phase: deploy with `grant_graph_permissions = false` (the default), then run `terraform output -raw graph_permission_request` to get a submittable request containing the managed identity's object ID, each permission with its justification, and the grant commands for the approver. Details in INSTALL.md step 3b.

### Graph application permissions needed by the managed identity

`Policy.Read.All`, `Policy.Read.AuthenticationMethod`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`. All read-only; the runbook never writes to the directory.

### Alerts

`alert-*-fail` (Sev 1): any FAIL/ERROR record in the last 24 h. `alert-*-job-failed` (Sev 2): the Automation job itself failed, suspended or stopped (from the Automation diagnostic logs). Log alerts cap the lookback at 2 days, so "no run in a week" cannot be a query alert; if you need that, run the schedule daily or add an Automation `TotalJob` metric alert. `alert-*-signin` (Sev 0): any interactive or non-interactive sign-in by a BTG UPN, evaluated every 5 minutes. The sign-in alert needs `SignInLogs` and `NonInteractiveUserSignInLogs` in the same workspace; set `enable_entra_signin_export = true` or point it at your existing Sentinel workspace. The UPN list is resolved at plan time, so re-apply after changing group membership.

## Run locally

```powershell
Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All','Policy.Read.AuthenticationMethod',`
                        'RoleManagement.Read.Directory','AuditLog.Read.All','UserAuthenticationMethod.Read.All'
./runbook/Test-BreakGlassCompliance.ps1 -BreakGlassGroupIds '<group-object-id>' -UseGraphPowerShell -SkipLogAnalytics
```

Do not authenticate with `Connect-AzAccount` for local runs: a Graph token from `Get-AzAccessToken` carries only the Az client's pre-consented scopes, so the authentication-method, PIM-role and policy checks return NOPERM regardless of your Entra role. See LOCAL_TEST.md.

## Design decisions

Graph is called with `Invoke-RestMethod` and a managed-identity token rather than the Graph PowerShell SDK, so the runbook has no module dependencies beyond the built-in `Az.Accounts` and cannot break on SDK version drift. Results are shipped via the Logs Ingestion API (DCR) rather than the HTTP Data Collector API, which left support on 14 September 2026. Report-only CA policies are treated like enabled ones because they are one click from enforcement. Role-based exclusions are not accepted as a substitute for direct or group exclusion, in line with Microsoft's emergency-access guidance.

## Known limits and follow-ups

The per-user MFA check uses a beta Graph endpoint and degrades to WARN if unavailable. The sign-in check via Graph covers interactive sign-ins only; the Log Analytics alert covers non-interactive too. Legacy Identity Protection user-risk / sign-in-risk policies configured in the old portal blades are not readable via Graph; migrate them to risk-based CA policies, which are then covered by the CA check. The runbook does not verify that credentials are physically stored and split across locations, that a quarterly test sign-in actually happened, or that the FIDO2 keys still work; those belong in your emergency-access procedure and change calendar.

Security review required before production use. AI-generated code: check the results thoroughly; final responsibility remains with you.
