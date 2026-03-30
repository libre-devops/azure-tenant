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

data "azuread_service_principal" "graph" {
  client_id = "00000003-0000-0000-c000-000000000000" # MSGraph in-built SPN
}

data "azuread_service_principal" "defender" {
  client_id = "fc780465-2017-40d4-a0c5-307022471b92" # WindowsATP in-built SPN
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

resource "azuread_app_role_assignment" "defender_machine_read" {
  principal_object_id = data.azuread_service_principal.mi.object_id
  resource_object_id  = data.azuread_service_principal.defender.object_id

  app_role_id = one([
    for role in data.azuread_service_principal.defender.app_roles :
    role.id if role.value == "Machine.Read.All"
  ])
}

resource "azurerm_automation_runtime_environment" "ps72_debug" {
  automation_account_id = module.automation_account.aa_id
  location              = module.rg.rg_location

  #Only 3 tags are allowed
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

  #Due to a bug in the implementation of Runbooks in Azure, the parameter names need to be specified in lowercase only. See: "https://github.com/Azure/azure-sdk-for-go/issues/4780" for more information
  parameters = {
    managedidentityclientid = module.user_assigned_managed_identity.managed_identity_client_ids[module.shared_vars.foundation_uid_name]
  }
}

resource "azurerm_automation_runtime_environment" "ps72_mde_sync" {
  automation_account_id = module.automation_account.aa_id
  location              = module.rg.rg_location

  #Only 3 tags are allowed
  tags = {
    ContactEmail   = lookup(module.shared_vars.tags, "ContactEmail", null)
    Classification = lookup(module.shared_vars.tags, "Classification", null)
    CostCenter     = lookup(module.shared_vars.tags, "CostCenter", null)
  }


  name             = "MDE-Sync-Pwsh72-Runtime"
  runtime_language = "PowerShell"
  runtime_version  = "7.2"

  runtime_default_packages = {
    "az" = "11.2.0"
  }

  description = "MDE Sync runtime for PowerShell 7.2"
}

resource "azurerm_automation_runbook" "runbook_mde_sync" {
  resource_group_name = module.rg.rg_name
  location            = module.rg.rg_location
  tags                = module.rg.rg_tags

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_mde_sync_automation_runbook_name

  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.ps72_mde_sync.name
  log_verbose              = true
  log_progress             = true
  description              = "Sync MDE devices to Entra Group"

  content = file("${path.module}/scripts/sync/Sync-MDELinuxDeviceToEntra.ps1")
}

resource "azurerm_automation_job_schedule" "runbook_schedule_mde_sync" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name

  runbook_name  = azurerm_automation_runbook.runbook_mde_sync.name
  schedule_name = azurerm_automation_schedule.every_60_min.name

  #Due to a bug in the implementation of Runbooks in Azure, the parameter names need to be specified in lowercase only. See: "https://github.com/Azure/azure-sdk-for-go/issues/4780" for more information
  parameters = {
    managedidentityclientid = module.user_assigned_managed_identity.managed_identity_client_ids[module.shared_vars.foundation_uid_name]
  }
}

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

  description = "Alert when Sync-MdeDevicesToEntraGroup runbook has failed jobs"

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
      values   = ["Sync-MdeDevicesToEntraGroup"]
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