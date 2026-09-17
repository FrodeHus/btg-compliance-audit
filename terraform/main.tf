# Tenant/subscription context for the permission request output. Needs no special rights.
data "azurerm_client_config" "current" {}

locals {
  use_existing_law = var.existing_log_analytics_workspace_resource_id != ""
  table_name       = var.table_name
  stream_name      = "Custom-${var.table_name}"

  # Canonical schema. The DCR stream declaration and the Tables API disagree on the datetime
  # casing, so the table columns are derived from this list rather than duplicated.
  table_columns = [
    { name = "TimeGenerated", type = "datetime" },
    { name = "RunId", type = "string" },
    { name = "TenantId", type = "string" },
    { name = "CheckId", type = "string" },
    { name = "Category", type = "string" },
    { name = "Target", type = "string" },
    { name = "Status", type = "string" },
    { name = "Detail", type = "string" },
    { name = "Evidence", type = "string" },
  ]
  table_api_columns = [for c in local.table_columns : {
    name = c.name
    type = c.type == "datetime" ? "dateTime" : c.type
  }]

  # Resolved workspace, whichever path was taken.
  workspace_resource_id = local.use_existing_law ? var.existing_log_analytics_workspace_resource_id : module.law[0].resource_id

  # The Logs Ingestion API requires workspace, DCE and DCR to be in the same region, so monitoring
  # resources follow the workspace rather than var.location.
  workspace_location = local.use_existing_law ? data.azapi_resource.existing_law[0].output.location : var.location

  runbook_name = "Test-BreakGlassCompliance"
  runbook_path = "${path.module}/../runbook/Test-BreakGlassCompliance.ps1"
}

# ---------------------------------------------------------------- resource group (AVM)
module "resource_group" {
  source  = "Azure/avm-res-resources-resourcegroup/azurerm"
  version = "0.4.0"

  name     = "rg-${var.name_prefix}"
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------- Log Analytics: existing or new
# Read the existing workspace to discover its region. Works cross-subscription as long as the
# deploying identity can read it.
data "azapi_resource" "existing_law" {
  count = local.use_existing_law ? 1 : 0

  type                   = "Microsoft.OperationalInsights/workspaces@2023-09-01"
  resource_id            = var.existing_log_analytics_workspace_resource_id
  response_export_values = ["location", "properties.customerId"]
}

module "law" {
  source  = "Azure/avm-res-operationalinsights-workspace/azurerm"
  version = "0.5.1"
  count   = local.use_existing_law ? 0 : 1

  name                                      = "law-${var.name_prefix}"
  location                                  = var.location
  resource_group_name                       = module.resource_group.name
  log_analytics_workspace_sku               = "PerGB2018"
  log_analytics_workspace_retention_in_days = var.log_retention_days
  tags                                      = var.tags
}

# The custom table is created the same way on both paths, so the schema lives in one place.
# Requires Log Analytics Contributor (or Contributor) on the target workspace.
resource "azapi_resource" "table" {
  count = var.create_custom_table ? 1 : 0

  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = local.table_name
  parent_id = local.workspace_resource_id

  body = {
    properties = {
      plan                 = "Analytics"
      retentionInDays      = var.log_retention_days
      totalRetentionInDays = var.log_retention_days
      schema = {
        name        = local.table_name
        description = "Break-the-glass account compliance check results"
        columns     = local.table_api_columns
      }
    }
  }

  schema_validation_enabled = false
}

# ---------------------------------------------------------------- data collection endpoint (AVM)
module "dce" {
  source  = "Azure/avm-res-insights-datacollectionendpoint/azurerm"
  version = "0.2.0"

  name                  = "dce-${var.name_prefix}"
  location              = local.workspace_location
  parent_id             = module.resource_group.resource_id
  public_network_access = "Enabled" # Automation sandbox workers have no VNet
  tags                  = var.tags
}

# ---------------------------------------------------------------- data collection rule (AVM)
module "dcr" {
  source  = "Azure/avm-res-insights-datacollectionrule/azurerm"
  version = "0.1.0"

  name                        = "dcr-${var.name_prefix}"
  location                    = local.workspace_location
  parent_id                   = module.resource_group.resource_id
  description                 = "Logs Ingestion API rule for break-the-glass compliance results"
  data_collection_endpoint_id = module.dce.resource_id
  tags                        = var.tags

  stream_declarations = {
    (local.stream_name) = {
      columns = local.table_columns
    }
  }

  destinations = {
    log_analytics = [{
      name                  = "law"
      workspace_resource_id = local.workspace_resource_id
    }]
  }

  data_flows = [{
    streams       = [local.stream_name]
    destinations  = ["law"]
    output_stream = local.stream_name
    transform_kql = "source"
  }]

  # The destination table must exist before the rule references its stream.
  depends_on = [azapi_resource.table]
}

# The AVM DCR module does not expose immutableId; read it back.
data "azurerm_monitor_data_collection_rule" "dcr" {
  name                = module.dcr.name
  resource_group_name = module.resource_group.name
  depends_on          = [module.dcr]
}

# ---------------------------------------------------------------- schedule start (stable across plans)
resource "time_offset" "schedule_start" {
  offset_hours = 1
  # Recompute only when the schedule definition changes; the Automation API rejects a start_time in the past.
  triggers = {
    frequency = var.schedule_frequency
    week_days = join(",", sort(var.schedule_week_days))
    timezone  = var.schedule_timezone
  }
}

# ---------------------------------------------------------------- automation account + runbook (AVM)
module "automation" {
  source  = "Azure/avm-res-automation-automationaccount/azurerm"
  version = "0.2.0"

  name                          = "aa-${var.name_prefix}"
  location                      = var.location
  resource_group_name           = module.resource_group.name
  sku                           = "Basic"
  local_authentication_enabled  = false
  public_network_access_enabled = false
  tags                          = var.tags

  managed_identities = {
    system_assigned = true
  }

  diagnostic_settings = {
    law = {
      name                  = "diag-law"
      workspace_resource_id = local.workspace_resource_id
      log_groups            = ["allLogs"]
    }
  }

  automation_runbooks = {
    btg = {
      name         = local.runbook_name
      runbook_type = "PowerShell72"
      description  = "Verifies break-the-glass account posture: CA exclusion, hygiene, roles, sign-ins, tenant guardrails."
      log_progress = false
      log_verbose  = false
      content      = file(local.runbook_path)
      tags         = var.tags
    }
  }

  automation_schedules = {
    weekly = {
      name        = "sched-${var.name_prefix}"
      description = "Recurring break-the-glass compliance run"
      frequency   = var.schedule_frequency
      interval    = 1
      start_time  = time_offset.schedule_start.rfc3339
      timezone    = var.schedule_timezone
      week_days   = var.schedule_frequency == "Week" ? var.schedule_week_days : null
    }
  }

  # Parameter keys must be lowercase (Automation API requirement).
  automation_job_schedules = {
    btg_weekly = {
      runbook_key  = "btg"
      schedule_key = "weekly"
      parameters = {
        breakglassgroupids       = join(",", var.break_glass_group_ids)
        breakglassupns           = join(",", var.break_glass_upns)
        lookbackdays             = tostring(var.lookback_days)
        maxexpectedaccounts      = tostring(var.max_expected_accounts)
        dcelogsingestionendpoint = module.dce.logs_ingestion_endpoint
        dcrimmutableid           = data.azurerm_monitor_data_collection_rule.dcr.immutable_id
        streamname               = local.stream_name
      }
    }
  }
}

# ---------------------------------------------------------------- RBAC: MI may publish to the DCR
# Kept outside the DCR module to avoid a dependency cycle (DCR -> automation params -> DCR).
resource "azurerm_role_assignment" "mi_metrics_publisher" {
  scope                = module.dcr.resource_id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = module.automation.system_assigned_mi_principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------------------------------------------------------- optional: export Entra sign-in logs
resource "azurerm_monitor_aad_diagnostic_setting" "signins" {
  count = var.enable_entra_signin_export ? 1 : 0

  name                       = "diag-${var.name_prefix}-signins"
  log_analytics_workspace_id = local.workspace_resource_id

  enabled_log { category = "SignInLogs" }
  enabled_log { category = "NonInteractiveUserSignInLogs" }
  enabled_log { category = "AuditLogs" }
}
