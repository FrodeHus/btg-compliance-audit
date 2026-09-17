# No AVM Terraform resource modules exist yet for action groups or scheduled query rules,
# so these use native azurerm resources.

resource "azurerm_monitor_action_group" "security" {
  name                = "ag-${var.name_prefix}"
  resource_group_name = module.resource_group.name
  short_name          = "btgsec"
  tags                = var.tags

  dynamic "email_receiver" {
    for_each = var.alert_email_receivers
    content {
      name                    = email_receiver.key
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

# 1) Compliance drift: any FAIL/ERROR record from the runbook.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "compliance_fail" {
  name                = "alert-${var.name_prefix}-fail"
  resource_group_name = module.resource_group.name
  location            = local.workspace_location
  description         = "Break-the-glass compliance runbook reported FAIL, NOPERM or ERROR"
  severity            = 1
  enabled             = true
  tags                = var.tags

  scopes                  = [local.workspace_resource_id]
  evaluation_frequency    = "PT1H"
  window_duration         = "P1D"
  auto_mitigation_enabled = true
  skip_query_validation   = true # table is empty until the first run

  criteria {
    query                   = <<-KQL
      ${local.table_name}
      | where Status in ("FAIL", "ERROR", "NOPERM")
      | where CheckId != "SYS.Summary"
      | summarize Failures = count(), Checks = make_set(CheckId, 50), Targets = make_set(Target, 50) by RunId
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }

  depends_on = [azapi_resource.table]
}

# 2) Runbook job failed, was suspended, or never produced a summary record.
#    (Log alerts cap the window at 2 days, so "no run in 8 days" cannot be expressed here;
#    job failures from the Automation diagnostic setting cover the realistic breakages.)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "runbook_failed" {
  name                = "alert-${var.name_prefix}-job-failed"
  resource_group_name = module.resource_group.name
  location            = local.workspace_location
  description         = "Break-the-glass compliance runbook job failed or was suspended"
  severity            = 2
  enabled             = true
  tags                = var.tags

  scopes                  = [local.workspace_resource_id]
  evaluation_frequency    = "PT1H"
  window_duration         = "P1D"
  auto_mitigation_enabled = true
  skip_query_validation   = true

  criteria {
    query                   = <<-KQL
      AzureDiagnostics
      | where ResourceProvider == "MICROSOFT.AUTOMATION" and Category == "JobLogs"
      | where RunbookName_s == "${local.runbook_name}"
      | where ResultType in ("Failed", "Suspended", "Stopped")
      | summarize arg_max(TimeGenerated, *) by JobId_g
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }
}

# 3) Any break-the-glass sign-in (interactive or non-interactive), near real time.
#    Requires SignInLogs / NonInteractiveUserSignInLogs exported to this workspace
#    (enable_entra_signin_export = true or an existing diagnostic setting).
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "btg_signin" {
  count = length(local.btg_upns_for_alert) > 0 ? 1 : 0

  name                = "alert-${var.name_prefix}-signin"
  resource_group_name = module.resource_group.name
  location            = local.workspace_location
  description         = "A break-the-glass account was used"
  severity            = 0
  enabled             = true
  tags                = var.tags

  scopes                  = [local.workspace_resource_id]
  evaluation_frequency    = "PT5M"
  window_duration         = "PT10M"
  auto_mitigation_enabled = false
  skip_query_validation   = true # sign-in tables do not exist until the Entra export delivers data

  criteria {
    query                   = <<-KQL
      let btg = dynamic(${jsonencode(local.btg_upns_for_alert)});
      union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
      | where UserPrincipalName in~ (btg)
      | project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ResultType, ResultDescription, ConditionalAccessStatus, AuthenticationRequirement
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.security.id]
  }
}
