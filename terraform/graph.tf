# Microsoft Graph application permissions for the Automation Account's managed identity.
#
# Granting these requires Privileged Role Administrator or Global Administrator. If your tenant
# routes that through an approval process, deploy with grant_graph_permissions = false, submit the
# request using the `graph_permission_request` output, and then either:
#   a) have the approver re-run `terraform apply` with grant_graph_permissions = true, or
#   b) let them grant it out-of-band with the script in that output and leave the flag false.
#
# Nothing else in this stack needs elevated Entra rights.

data "azuread_service_principal" "msgraph" {
  count     = var.grant_graph_permissions ? 1 : 0
  client_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
}

resource "azuread_app_role_assignment" "graph" {
  for_each = var.grant_graph_permissions ? var.graph_app_roles : toset([])

  app_role_id         = data.azuread_service_principal.msgraph[0].app_role_ids[each.value]
  principal_object_id = module.automation.system_assigned_mi_principal_id
  resource_object_id  = data.azuread_service_principal.msgraph[0].object_id

  lifecycle {
    precondition {
      condition     = contains(keys(data.azuread_service_principal.msgraph[0].app_role_ids), each.value)
      error_message = "'${each.value}' is not a Microsoft Graph application permission. Check graph_app_roles."
    }
  }
}

# ---------------------------------------------------------------- BTG UPNs for the sign-in alert
# Needs only directory read. Set resolve_btg_group_members = false if the deploying identity cannot
# read groups; the alert then watches break_glass_upns only.
data "azuread_group" "btg" {
  for_each  = var.resolve_btg_group_members ? toset(var.break_glass_group_ids) : toset([])
  object_id = each.value
}

data "azuread_users" "btg_group_members" {
  for_each       = { for k, v in data.azuread_group.btg : k => v if length(v.members) > 0 }
  object_ids     = each.value.members
  ignore_missing = true # tolerate non-user members; the runbook flags them separately (GRP.OnlyUsers)
}

locals {
  btg_upns_for_alert = distinct(concat(
    var.break_glass_upns,
    flatten([for k, v in data.azuread_users.btg_group_members : v.user_principal_names])
  ))
}
