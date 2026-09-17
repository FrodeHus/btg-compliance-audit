variable "subscription_id" {
  description = "Target subscription ID (azurerm 4.x requires it explicitly, or set ARM_SUBSCRIPTION_ID)."
  type        = string
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "norwayeast"
}

variable "name_prefix" {
  description = "Short prefix used in resource names (lowercase, letters/digits/hyphen)."
  type        = string
  default     = "btg-compliance"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-20 chars: lowercase letters, digits, hyphen."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    workload   = "break-the-glass-compliance"
    owner      = "security"
    managed_by = "terraform"
  }
}

# ---------------------------------------------------------------- BTG identification
variable "break_glass_group_ids" {
  description = "Object IDs of Entra security groups containing break-the-glass accounts. Combine with break_glass_upns as needed."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for g in var.break_glass_group_ids : can(regex("^[0-9a-fA-F-]{36}$", g))])
    error_message = "break_glass_group_ids must be object IDs (GUIDs)."
  }
}

variable "break_glass_upns" {
  description = "UPNs of individual break-the-glass accounts. Combine with break_glass_group_ids as needed."
  type        = list(string)
  default     = []
}

variable "max_expected_accounts" {
  description = "WARN when more than this many break-the-glass accounts are resolved."
  type        = number
  default     = 4
}

variable "lookback_days" {
  description = "Sign-in lookback window for the unexpected-use check."
  type        = number
  default     = 7
}

# ---------------------------------------------------------------- schedule
variable "schedule_frequency" {
  description = "Automation schedule frequency: Day or Week."
  type        = string
  default     = "Week"
  validation {
    condition     = contains(["Day", "Week"], var.schedule_frequency)
    error_message = "schedule_frequency must be Day or Week."
  }
}

variable "schedule_week_days" {
  description = "Days the runbook runs when schedule_frequency = Week."
  type        = set(string)
  default     = ["Monday"]
}

variable "schedule_timezone" {
  description = "IANA time zone for the schedule."
  type        = string
  default     = "Europe/Oslo"
}

# ---------------------------------------------------------------- Log Analytics
variable "existing_log_analytics_workspace_resource_id" {
  description = <<-DESC
    Resource ID of an existing Log Analytics workspace to send results to. Leave empty to create a
    new workspace. The DCE and DCR are always deployed into the workspace's region, because the
    Logs Ingestion API requires workspace, DCE and DCR to share a region.
    Format: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
  DESC
  type        = string
  default     = ""
  validation {
    condition = var.existing_log_analytics_workspace_resource_id == "" || can(regex(
      "^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\\.OperationalInsights/workspaces/[^/]+$",
      var.existing_log_analytics_workspace_resource_id
    ))
    error_message = "Must be empty or a full Log Analytics workspace resource ID."
  }
}

variable "table_name" {
  description = "Custom table that receives the compliance results. Must end with _CL."
  type        = string
  default     = "BTGCompliance_CL"
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]*_CL$", var.table_name))
    error_message = "table_name must start with a letter and end with _CL."
  }
}

variable "create_custom_table" {
  description = "Create the custom table. Set false if the table already exists or is provisioned by another process."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------- logging / alerting
variable "log_retention_days" {
  description = "Interactive retention for the custom table, and for the workspace when this module creates it. Ignored for an existing workspace's own retention."
  type        = number
  default     = 90
  validation {
    # The Tables API rejects anything outside 4-730; there is no local schema check because the
    # table resource runs with schema_validation_enabled = false.
    condition     = var.log_retention_days >= 4 && var.log_retention_days <= 730
    error_message = "log_retention_days must be between 4 and 730."
  }
}

variable "alert_email_receivers" {
  description = "Map of receiver name => email address for the action group."
  type        = map(string)
  default     = {}
}

variable "enable_entra_signin_export" {
  description = "Create the Entra ID diagnostic setting that exports SignInLogs to the workspace (needed by the BTG sign-in alert). Requires Security Administrator or Global Administrator on the deploying identity."
  type        = bool
  default     = false
}

variable "grant_graph_permissions" {
  description = <<-DESC
    Grant the Microsoft Graph application permissions to the managed identity as part of this
    deployment. Requires Privileged Role Administrator or Global Administrator. Leave false to
    deploy everything else first and request the permissions through an approval process - see the
    graph_permission_request output.
  DESC
  type        = bool
  default     = false
}

variable "resolve_btg_group_members" {
  description = "Expand break_glass_group_ids to UPNs for the sign-in alert. Needs directory read. Set false if the deploying identity cannot read groups; the alert then covers break_glass_upns only."
  type        = bool
  default     = true
}

variable "graph_app_roles" {
  description = "Microsoft Graph application permissions granted to the Automation managed identity."
  type        = set(string)
  default = [
    "Policy.Read.All",                   # CA policies, security defaults, per-user MFA state
    "Policy.Read.AuthenticationMethod",  # FIDO2 authentication method policy
    "Directory.Read.All",                # users, groups, transitive membership, owned objects
    "RoleManagement.Read.Directory",     # role assignment/eligibility schedule instances (PIM)
    "AuditLog.Read.All",                 # sign-in logs
    "UserAuthenticationMethod.Read.All", # FIDO2 and other registered methods
  ]
}
