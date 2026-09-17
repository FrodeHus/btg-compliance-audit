output "resource_group_name" {
  value = module.resource_group.name
}

output "automation_account_id" {
  value = module.automation.resource_id
}

output "automation_managed_identity_principal_id" {
  description = "Object ID of the system-assigned managed identity that needs the Graph permissions."
  value       = module.automation.system_assigned_mi_principal_id
}

output "graph_permissions_granted" {
  description = "Whether this deployment granted the Graph application permissions."
  value       = var.grant_graph_permissions
}

output "graph_permissions_required" {
  description = "Microsoft Graph application permissions the managed identity needs."
  value       = sort(tolist(var.graph_app_roles))
}

output "graph_permission_request" {
  description = "Paste into your permission request. Includes the grant script for the approver."
  value       = var.grant_graph_permissions ? "Permissions were granted by this deployment; no request needed." : <<-REQUEST
    Microsoft Graph application permission request
    =============================================
    Requested for : Automation Account managed identity "aa-${var.name_prefix}"
    Principal type: System-assigned managed identity (service principal)
    Object ID     : ${module.automation.system_assigned_mi_principal_id}
    Tenant        : ${data.azurerm_client_config.current.tenant_id}
    Subscription  : ${var.subscription_id}
    Resource      : ${module.automation.resource_id}

    Permissions requested (Microsoft Graph, application, read-only):
    ${join("\n", [for r in sort(tolist(var.graph_app_roles)) : "- ${r}"])}

    Purpose: scheduled read-only verification that emergency-access (break-the-glass) accounts are
    excluded from Conditional Access and correctly hardened. The identity performs no writes to the
    directory. Justification per permission:
      Directory.Read.All                - read the accounts, their groups and owned objects
      Policy.Read.All                   - read Conditional Access policies and Security Defaults
      Policy.Read.AuthenticationMethod  - read the FIDO2 authentication method policy
      RoleManagement.Read.Directory     - read Global Administrator assignments and PIM eligibility
      AuditLog.Read.All                 - read sign-in logs to detect unexpected use
      UserAuthenticationMethod.Read.All - verify FIDO2 keys are registered and nothing weaker is

    Approver requires: Privileged Role Administrator or Global Administrator.

    Option A - approver runs Terraform:
      terraform apply -var grant_graph_permissions=true

    Option B - approver grants out-of-band (resolves role IDs by name, no hardcoded GUIDs):
      Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Application.Read.All'
      $mi    = '${module.automation.system_assigned_mi_principal_id}'
      $graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
      foreach ($p in @(${join(", ", [for r in sort(tolist(var.graph_app_roles)) : "'${r}'"])})) {
          $role = $graph.AppRoles | Where-Object Value -eq $p
          if (-not $role) { Write-Warning "Unknown permission: $p"; continue }
          New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi `
              -PrincipalId $mi -ResourceId $graph.Id -AppRoleId $role.Id
      }

    After granting, allow 5-15 minutes for propagation, then start the
    "Test-BreakGlassCompliance" runbook manually to confirm no check reports NOPERM.
  REQUEST
}

output "log_analytics_workspace_id" {
  description = "Workspace receiving the results, whether pre-existing or created here."
  value       = local.workspace_resource_id
}

output "log_analytics_workspace_created" {
  description = "False when an existing workspace was supplied."
  value       = !local.use_existing_law
}

output "monitoring_location" {
  description = "Region of the DCE, DCR and alert rules - forced to the workspace region by the Logs Ingestion API."
  value       = local.workspace_location
}

output "dce_logs_ingestion_endpoint" {
  value = module.dce.logs_ingestion_endpoint
}

output "dcr_immutable_id" {
  value = data.azurerm_monitor_data_collection_rule.dcr.immutable_id
}

output "compliance_table" {
  value = local.table_name
}

output "compliance_table_created" {
  description = "False when create_custom_table = false, i.e. the table is managed elsewhere."
  value       = var.create_custom_table
}

output "btg_accounts_in_signin_alert" {
  description = "UPNs the sign-in alert watches (resolved at plan time; re-apply after membership changes)."
  value       = local.btg_upns_for_alert
}
