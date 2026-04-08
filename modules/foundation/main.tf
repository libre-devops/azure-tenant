module "shared_vars" {
  source       = "../shared_vars"
  env          = var.env
  layer_name   = var.layer_name
  short        = var.short
  short_region = var.short_region
}

module "rg" {
  source  = "libre-devops/rg/azurerm"
  version = "~> 1.0.0"

  rg_name  = module.shared_vars.foundation_rg_name
  location = module.shared_vars.location
  tags     = module.shared_vars.tags
}

module "user_assigned_managed_identity" {
  source  = "libre-devops/user-assigned-managed-identity/azurerm"
  version = "~> 2.0.6"

  rg_name  = module.rg.rg_name
  location = module.rg.rg_location
  tags     = module.rg.rg_tags

  user_assigned_managed_identities = [
    {
      name = module.shared_vars.foundation_uid_name
    }
  ]
}

module "automation_account" {
  source  = "libre-devops/automation-account/azurerm"
  version = "~> 1.0.0"

  rg_name  = module.rg.rg_name
  location = module.rg.rg_location
  tags     = module.rg.rg_tags

  automation_account_name       = module.shared_vars.foundation_aa_name
  public_network_access_enabled = true

  identity_type = "UserAssigned"
  identity_ids  = [module.user_assigned_managed_identity.managed_identity_ids[module.shared_vars.foundation_uid_name]]
}

# ---------------------------------------------------------------------------
#  GRAPH SERVICE PRINCIPAL
#  WindowsDefenderATP is no longer required — MDE dependency removed.
# ---------------------------------------------------------------------------

data "azuread_service_principal" "graph" {
  client_id = "00000003-0000-0000-c000-000000000000" # MSGraph built-in SPN
}

data "azuread_service_principal" "mi" {
  depends_on = [module.automation_account]

  display_name = module.shared_vars.foundation_uid_name
}

resource "azuread_app_role_assignment" "graph_device_read" {
  principal_object_id = data.azuread_service_principal.mi.object_id
  resource_object_id  = data.azuread_service_principal.graph.object_id

  app_role_id = one([
    for role in data.azuread_service_principal.graph.app_roles :
    role.id if role.value == "Device.Read.All"
  ])
}

resource "azuread_app_role_assignment" "graph_group_rw" {
  principal_object_id = data.azuread_service_principal.mi.object_id
  resource_object_id  = data.azuread_service_principal.graph.object_id

  app_role_id = one([
    for role in data.azuread_service_principal.graph.app_roles :
    role.id if role.value == "GroupMember.ReadWrite.All"
  ])
}

# ---------------------------------------------------------------------------
#  GROUP SYNC CONFIG — one JSON file per group, loaded as Automation Variables
#
#  File layout expected:  ${path.module}/configs/<key>.json
#  Variable name in AA:   GroupConfig-<key>
#
#  To add or remove a group: edit the map below and re-apply.
#  The variable names passed to the runbook are derived automatically.
# ---------------------------------------------------------------------------

locals {
  group_configs = {
    for k, v in {
      linux-group1 = "${path.module}/configs/linux-group1.json"
      linux-group2 = "${path.module}/configs/linux-group2.json"
      linux-group3 = "${path.module}/configs/linux-group3.json"
      linux-group4 = "${path.module}/configs/linux-group4.json"
      linux-group5 = "${path.module}/configs/linux-group5.json"
      linux-group6 = "${path.module}/configs/linux-group6.json"
    } :
    k => jsonencode(jsondecode(file(v)))
  }

  # Produces the comma-separated string passed to the [string[]] runbook parameter.
  # Azure Automation splits on commas when binding job schedule parameters to arrays.
  automation_variable_names = join(",", [
    for k in sort(keys(local.group_configs)) : trimspace("GroupConfig-${k}")
  ])
}

resource "azurerm_automation_variable_string" "group_config" {
  for_each = local.group_configs

  resource_group_name     = module.rg.rg_name
  automation_account_name = module.automation_account.aa_name

  name        = "GroupConfig-${each.key}"
  value       = each.value
  encrypted   = false
  description = "Device sync config for Entra group: ${each.key}"
}

# ---------------------------------------------------------------------------
#  DEBUG RUNTIME + RUNBOOK  (unchanged)
# ---------------------------------------------------------------------------

resource "azurerm_automation_runtime_environment" "ps72_debug" {
  automation_account_id = module.automation_account.aa_id
  location              = module.rg.rg_location

  # Only 3 tags are allowed on runtime environments
  tags = {
    ContactEmail   = lookup(module.shared_vars.tags, "ContactEmail", null)
    Classification = lookup(module.shared_vars.tags, "Classification", null)
    CostCenter     = lookup(module.shared_vars.tags, "CostCenter", null)
  }

  name             = "Debug-Pwsh72-Runtime"
  runtime_language = "PowerShell"
  runtime_version  = "7.2"

  runtime_default_packages = {
    "az" = "11.2.0"
  }

  description = "Debug runtime for PowerShell 7.2"
}

resource "azurerm_automation_runbook" "runbook_debug" {
  resource_group_name = module.rg.rg_name
  location            = module.rg.rg_location
  tags                = module.rg.rg_tags

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_debug_automation_runbook_name

  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.ps72_debug.name
  log_verbose              = true
  log_progress             = true
  description              = "Test stuff"

  content = file("${path.module}/scripts/debug/Debug.ps1")
}

# ---------------------------------------------------------------------------
#  SYNC RUNTIME + RUNBOOK
# ---------------------------------------------------------------------------

resource "azurerm_automation_runtime_environment" "ps72_group_sync" {
  automation_account_id = module.automation_account.aa_id
  location              = module.rg.rg_location

  # Only 3 tags are allowed on runtime environments
  tags = {
    ContactEmail   = lookup(module.shared_vars.tags, "ContactEmail", null)
    Classification = lookup(module.shared_vars.tags, "Classification", null)
    CostCenter     = lookup(module.shared_vars.tags, "CostCenter", null)
  }

  name             = "GroupSync-Pwsh72-Runtime"
  runtime_language = "PowerShell"
  runtime_version  = "7.2"

  runtime_default_packages = {
    "az" = "11.2.0"
  }

  description = "Group sync runtime for PowerShell 7.2"
}

resource "azurerm_automation_runbook" "runbook_group_sync" {
  resource_group_name = module.rg.rg_name
  location            = module.rg.rg_location
  tags                = module.rg.rg_tags

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_mde_sync_automation_runbook_name

  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.ps72_group_sync.name
  log_verbose              = true
  log_progress             = true
  description              = "Sync explicitly-configured devices into Entra ID security groups"

  # Runbook reads group membership from Automation Variables — no MDE dependency.
  content = file("${path.module}/scripts/sync/Sync-EntraGroupsFromConfig.ps1")

  # Variables must exist before the runbook runs — enforce ordering.
  depends_on = [azurerm_automation_variable_string.group_config]
}

# ---------------------------------------------------------------------------
#  SCHEDULE  (shared 60-min schedule)
# ---------------------------------------------------------------------------

resource "azurerm_automation_schedule" "every_60_min" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_aa_every_60_min_schedule_name

  frequency = "Hour"
  interval  = 1
  timezone  = "Etc/UTC"
}

resource "azurerm_automation_job_schedule" "runbook_schedule_debug" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name

  runbook_name  = azurerm_automation_runbook.runbook_debug.name
  schedule_name = azurerm_automation_schedule.every_60_min.name

  # Parameter names must be lowercase — Azure SDK limitation.
  # See: https://github.com/Azure/azure-sdk-for-go/issues/4780
  parameters = {
    managedidentityclientid = module.user_assigned_managed_identity.managed_identity_client_ids[module.shared_vars.foundation_uid_name]
  }
}

resource "azurerm_automation_job_schedule" "runbook_schedule_group_sync" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name

  runbook_name  = azurerm_automation_runbook.runbook_group_sync.name
  schedule_name = azurerm_automation_schedule.every_60_min.name

  # Parameter names must be lowercase — Azure SDK limitation.
  # [string[]] parameters are passed as a comma-separated string; Azure Automation
  # splits on commas when binding to the array parameter in the runbook.
  parameters = {
    managedidentityclientid  = module.user_assigned_managed_identity.managed_identity_client_ids[module.shared_vars.foundation_uid_name]
    automationvariablenames  = local.automation_variable_names
    defaultremovestale       = "true"
    whatif                   = "false"
  }
}

# ---------------------------------------------------------------------------
#  ALERTING  (unchanged — still fires on failed jobs from the same runbook name)
# ---------------------------------------------------------------------------

resource "azurerm_monitor_action_group" "mde_sync_alerts" {
  name                = "ag-mde-sync-alerts"
  resource_group_name = module.rg.rg_name
  short_name          = "mde-sync"

  email_receiver {
    name                    = "craig-email"
    email_address           = "craig@craigthacker.dev"
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_metric_alert" "mde_sync_failed_jobs" {
  resource_group_name = module.rg.rg_name
  tags                = module.rg.rg_tags

  name = "alert-mde-sync-failed-jobs"

  scopes = [
    module.automation_account.aa_id
  ]

  description = "Alert when the group sync runbook has failed jobs"

  severity    = 2
  frequency   = "PT5M"
  window_size = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Automation/automationAccounts"
    metric_name      = "TotalJob"
    aggregation      = "Total"
    operator         = "GreaterThanOrEqual"
    threshold        = 1

    dimension {
      name     = "Runbook"
      operator = "Include"
      values   = [module.shared_vars.foundation_mde_sync_automation_runbook_name]
    }

    dimension {
      name     = "Status"
      operator = "Include"
      values   = ["Failed"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.mde_sync_alerts.id
  }
}
