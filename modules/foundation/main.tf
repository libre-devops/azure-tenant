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

resource "azurerm_automation_runbook" "test_runbook" {
  resource_group_name = module.rg.rg_name
  location            = module.rg.rg_location
  tags                = module.rg.rg_tags

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_test_automation_runbook_name

  runbook_type = "PowerShell"
  log_verbose  = true
  log_progress = true
  description  = "Test stuff"

  content = <<-EOF
    $ErrorActionPreference = 'Stop'

    function Get-ManagedIdentityToken {
        param ([string] $Resource)

        $uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2025-04-07&resource=$Resource"

        $res = Invoke-RestMethod -Uri $uri -Headers @{ Metadata = 'true' }
        return $res.access_token
    }

    Write-Host "Getting tokens..."

    $graphToken = Get-ManagedIdentityToken "https://graph.microsoft.com"
    $mdeToken   = Get-ManagedIdentityToken "https://api.securitycenter.microsoft.com"

    Write-Host "Testing Graph access..."
    $graph = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/devices" `
        -Headers @{ Authorization = "Bearer $graphToken" }

    Write-Host "Graph devices count: $($graph.value.Count)"

    Write-Host "Testing MDE access..."
    $mde = Invoke-RestMethod `
        -Uri "https://api.securitycenter.microsoft.com/api/machines" `
        -Headers @{ Authorization = "Bearer $mdeToken" }

    Write-Host "MDE machines count: $($mde.value.Count)"
  EOF
}

resource "azurerm_automation_schedule" "every_60_min" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name
  name                    = module.shared_vars.foundation_aa_every_60_min_schedule_name

  frequency = "Hour"
  interval  = 1
  timezone  = "UTC"
}

resource "azurerm_automation_job_schedule" "runbook_schedule" {
  resource_group_name = module.shared_vars.foundation_rg_name

  automation_account_name = module.automation_account.aa_name

  runbook_name  = azurerm_automation_runbook.test_runbook.name
  schedule_name = azurerm_automation_schedule.every_60_min.name
}