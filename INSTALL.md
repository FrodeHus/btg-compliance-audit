# INSTALL – Break-the-glass compliance monitor

Step-by-step deployment. Expect 30–45 minutes including the first validation run.

## 0. Before you start

You need:

| | Requirement |
|---|---|
| Tooling | Terraform ≥ 1.9, Azure CLI ≥ 2.60, PowerShell 7.2+ (for local testing only) |
| Azure RBAC | **Owner** on the target subscription (or Contributor + User Access Administrator – the deployment creates a role assignment) |
| Entra roles | **None required for the infrastructure.** Granting the managed identity's Graph permissions needs **Privileged Role Administrator** or Global Administrator, but that is a separate phase (step 3b) so it can go through an approval process. Directory read is used to expand BTG groups for the sign-in alert; disable with `resolve_btg_group_members = false` if you lack it. **Security Administrator** only if you set `enable_entra_signin_export = true` |
| Inputs | Subscription ID; object ID(s) of the BTG security group(s) and/or the BTG UPNs; at least one alert e-mail address |

Deploy from a normal admin workstation with an admin account, **not** with a break-glass account.

## 1. Collect the inputs

```bash
az login --tenant <tenant-id>
az account show --query id -o tsv                     # subscription_id

# Object ID of the BTG group (if you use a group)
az ad group show --group "<BTG group display name>" --query id -o tsv

# Or list the BTG UPNs you will pass explicitly
az ad user show --id btg-01@contoso.onmicrosoft.com --query userPrincipalName -o tsv
```

## 2. Configure

```bash
cd Break-the-glass/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
subscription_id       = "<subscription-id>"
location              = "norwayeast"
name_prefix           = "btg-compliance"        # 3–20 chars, lowercase/digits/hyphen

break_glass_group_ids = ["<group-object-id>"]  # and/or
break_glass_upns      = []
max_expected_accounts = 3                       # WARN above this

lookback_days         = 7
schedule_frequency    = "Week"                  # or "Day"
schedule_week_days    = ["Monday"]
schedule_timezone     = "Europe/Oslo"

# Log Analytics – leave empty to create a workspace, or reuse an existing one:
existing_log_analytics_workspace_resource_id = ""
table_name                                   = "BTGCompliance_CL"
create_custom_table                          = true
log_retention_days                           = 90

alert_email_receivers = { soc = "soc@contoso.com" }

# Graph permissions are requested separately (step 3b). Flip to true only if you hold
# Privileged Role Administrator and want Terraform to grant them directly.
grant_graph_permissions = false

enable_entra_signin_export = false              # see step 6
```

Optional but intentionally disabled by default: a remote `backend "azurerm"` in `providers.tf` can be uncommented only in a local, security-reviewed copy. This repo leaves state local by default because Terraform state may contain BTG UPNs, object IDs, and other tenant metadata. Do not commit the remote-backend configuration unless you have explicitly accepted that risk and have a secure storage account, RBAC model, and retention policy.

### Using an existing Log Analytics workspace

Set `existing_log_analytics_workspace_resource_id` to its full resource ID:

```bash
az monitor log-analytics workspace show \
  --resource-group <rg> --workspace-name <name> --query id -o tsv
```

What changes: no workspace is created, and the DCE, DCR and all three alert rules are deployed into **the workspace's region** rather than `var.location`, because the Logs Ingestion API requires workspace, DCE and DCR to share a region. `terraform output monitoring_location` shows the region that was used. The Automation Account and resource group still go in `var.location`.

Extra permissions on the existing workspace for the deploying identity: **Log Analytics Contributor** (or Contributor) to create the custom table, and read access so Terraform can look up the region. If a different team owns the table, have them create `BTGCompliance_CL` from the schema in `terraform/main.tf` (`local.table_api_columns`) and set `create_custom_table = false`.

If the workspace is in another subscription, the deploying identity needs those rights there too. Everything this stack creates still lands in `var.subscription_id`; only the workspace and table are remote. Cross-subscription log search alerts are supported, but confirm your alert-routing conventions before going that route.

Reusing a Sentinel workspace is a good default — the sign-in alert then has `SigninLogs` available already, so you can leave `enable_entra_signin_export = false` (step 6, option B).

## 3. Deploy

```bash
terraform init
terraform plan -out tfplan
```

Review the plan. Expect roughly: 1 resource group, 1 Log Analytics workspace (unless reusing one) + 1 custom table, 1 DCE, 1 DCR, 1 Automation Account with 1 runbook + 1 schedule + 1 job schedule, 1 role assignment, 1 action group, 2–3 alert rules, and telemetry resources from the AVM modules. With `grant_graph_permissions = true` you also get 6 Graph app-role assignments.

```bash
terraform apply tfplan
```

No Entra admin role is needed for this step. The infrastructure is now in place but the managed identity cannot read anything from Graph yet, so every check would report `NOPERM`.

## 3b. Request the Graph permissions

```bash
terraform output -raw graph_permission_request
```

This prints a ready-to-submit request containing the managed identity's object ID, the six read-only permissions with a justification for each, and the exact grant commands. Submit it through your approval process.

Once approved, either:

- **the approver runs Terraform** — `terraform apply -var grant_graph_permissions=true` (then set the same value in `terraform.tfvars` so later applies don't revoke it); or
- **the approver grants out-of-band** — they run Option B from the output, and you leave `grant_graph_permissions = false`. Terraform will not manage or revoke those grants. If you later want Terraform to own them, flip the flag and `terraform import` each assignment; applying with the flag on while the grants already exist fails on conflict.

Verify the grants landed:

```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$(terraform output -raw automation_managed_identity_principal_id)/appRoleAssignments" \
  --query "value[].appRoleId" -o tsv
```

## 4. Wait for permission propagation

Graph app-role grants to a managed identity can take 5–15 minutes to become effective. Grab a coffee before step 5, or the first run will report `NOPERM` on most checks.

## 5. First manual run

1. Azure portal → **Automation Accounts → aa-btg-compliance → Runbooks → Test-BreakGlassCompliance**.
2. **Start**. Leave parameters empty (the scheduled job supplies them) **or**, for the manual run, fill in:
   - `BREAKGLASSGROUPIDS` – the group object ID(s), comma-separated
   - `DCELOGSINGESTIONENDPOINT` – `terraform output -raw dce_logs_ingestion_endpoint`
   - `DCRIMMUTABLEID` – `terraform output -raw dcr_immutable_id`
3. Open the job → **Output**. You should see one line per check (`[PASS]`, `[WARN]`, `[FAIL]`, `[NOPERM]`) and a final summary. A job status of **Failed** is expected if any check is FAIL, NOPERM or ERROR – that is the design. `NOPERM` means the check could not be evaluated for lack of a Graph permission; treat it as a blind spot, not a pass, and revisit step 3.
4. Verify ingestion (allow 2–5 minutes):

```kusto
BTGCompliance_CL
| where TimeGenerated > ago(1h)
| summarize count() by Status, Category
| order by Status
```

If the table is empty but the job output shows records, check the order below – the first cause is by far the most common and is not a fault:

1. **Wait.** The first data to reach a newly created table takes 5–15 minutes to become queryable. Until then the table returns zero rows with no error, which looks identical to a failure. Only investigate further if it is still empty after ~15 minutes.
2. **Look for a `SYS.Ingest` record with status `ERROR`** in the job output, and for `Log Analytics ingestion failed` in the job's warning stream. The runbook adds that record and fails the job when the upload throws, so a genuine ingestion failure is never silent.
3. If `SYS.Ingest` is present, the usual cause is that the `Monitoring Metrics Publisher` role assignment on the DCR has not propagated yet (wait 5 minutes, re-run).

Note that `Write-Host` output does not appear in the Automation job's **Output** stream, so the runbook's progress lines are not a reliable way to confirm ingestion – use the `SYS.Ingest` record instead.

## 6. Enable sign-in alerting (recommended)

The Sev 0 sign-in alert queries `SigninLogs` and `AADNonInteractiveUserSignInLogs`. Pick one:

**Option A – export to this workspace**
Set `enable_entra_signin_export = true` in `terraform.tfvars`, run `terraform apply` with an account that is Security Administrator or Global Administrator. Entra ID P1/P2 is required for sign-in log export.

**Option B – you already export sign-ins to a Sentinel workspace**
In `alerts.tf`, change `scopes` of `azurerm_monitor_scheduled_query_rules_alert_v2.btg_signin` to that workspace's resource ID and re-apply. The deploying identity needs `Log Analytics Reader` on that workspace.

Test it: perform a planned, documented BTG sign-in test and confirm the alert e-mail arrives within ~10 minutes. Record the test in your emergency-access log.

## 7. Wire into your process

- Add the action group's e-mail to your SOC queue or ticketing system; a `FAIL` should open an incident.
- Put the weekly run on your change calendar. Any deliberate CA policy change should be followed by an ad-hoc run (**Start** the runbook manually).
- When BTG group membership changes, run `terraform apply` again – the sign-in alert's UPN list is resolved at plan time.

## 8. Ongoing maintenance

| When | Do |
|---|---|
| Quarterly | Physical BTG sign-in test (the runbook cannot do this). Expect `USE.NoSignIns` to FAIL that week – that is the proof the alert works. |
| After CA changes | Manual runbook run. |
| After BTG membership change | `terraform apply`. |
| AVM module updates | Bump `version` pins in `main.tf`, `terraform plan`, review, apply. |
| Runbook changes | Edit the entry point or the relevant file under `runbook/lib/`, `terraform apply` – `main.tf` reassembles and republishes the runbook content. |

## Uninstall

```bash
terraform destroy
```

The Graph app-role assignments are removed with the managed identity. The custom table and its data are deleted with the workspace (soft-delete: 14 days).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Most checks `NOPERM` ("Missing permissions to complete this check") | Graph permissions not yet propagated (step 4) or not granted (step 3b). Each NOPERM record names the permission it needs. |
| `terraform apply` fails on `azuread_app_role_assignment` with `Authorization_RequestDenied` | You set `grant_graph_permissions = true` without Privileged Role Administrator. Set it back to false; the rest of the stack is unaffected and already applied. Use step 3b. |
| `terraform apply` fails reading `azuread_group` | The deploying identity cannot read the directory. Set `resolve_btg_group_members = false` and list the accounts in `break_glass_upns` for the sign-in alert. |
| Table creation fails with `AuthorizationFailed` on an existing workspace | Need Log Analytics Contributor on that workspace, or have its owner create the table and set `create_custom_table = false`. |
| `SYS.NoAccounts` FAIL | Wrong group ID / UPN, or group is empty. Check `terraform.tfvars`. |
| `ACCT.PerUserMfaOff` NOPERM | Missing `Policy.Read.All`, or the beta endpoint is unavailable in your cloud. |
| `ROLE.*` NOPERM | Missing `RoleManagement.Read.Directory`. |
| `TNT.Fido2MethodEnabled` NOPERM | Missing `Policy.Read.AuthenticationMethod`. |
| `USE.NoSignIns` NOPERM | Missing `AuditLog.Read.All`. |
| `USE.NoSignIns` ERROR "licensing or role reasons" | Tenant has no Entra ID P1/P2; the sign-in log API requires it. |
| Anything `NOPERM` / `ERROR` and you want the raw response | Start the runbook with `ShowErrors` = true, or run locally with `-ShowErrors` (see LOCAL_TEST.md). |
| Alert rule apply fails on query validation | Should not happen (`skip_query_validation = true`); if it does, the table name in `local.table_name` was changed without updating the alerts. |
| Schedule apply fails "start time must be in the future" | `time_offset` stale after a schedule change; `terraform taint time_offset.schedule_start` and re-apply. |
| Runbook shows `Suspended` | Sandbox exceeded 3 h fair-share or memory. Very unlikely at this scale; check job **Errors** tab. |

---
This document was written with AI assistance. Verify the steps before relying on them in production.
