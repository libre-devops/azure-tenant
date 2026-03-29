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

  rg_name  = module.shared_vars.foundation_rg_name
  location = module.shared_vars.location
  tags     = module.shared_vars.tags

  user_assigned_managed_identities = [
    {
      name = module.shared_vars.foundation_uid_name
    }
  ]
}

module "automation_account" {
  source  = "libre-devops/automation-account/azurerm"
  version = "~> 1.0.0"

  rg_name  = module.shared_vars.foundation_rg_name
  location = module.shared_vars.location
  tags     = module.shared_vars.tags

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

# resource "azuread_app_role_assignment" "graph_device_read" {
#   principal_object_id = data.azuread_service_principal.mi.object_id
#   resource_object_id  = data.azuread_service_principal.graph.object_id
#
#   app_role_id = one([
#     for role in data.azuread_service_principal.graph.app_roles :
#     role.id if role.value == "Device.Read.All"
#   ])
# }
#
# resource "azuread_app_role_assignment" "graph_group_rw" {
#   principal_object_id = data.azuread_service_principal.mi.object_id
#   resource_object_id  = data.azuread_service_principal.graph.object_id
#
#   app_role_id = one([
#     for role in data.azuread_service_principal.graph.app_roles :
#     role.id if role.value == "GroupMember.ReadWrite.All"
#   ])
# }
#
# resource "azuread_app_role_assignment" "defender_machine_read" {
#   principal_object_id = data.azuread_service_principal.mi.object_id
#   resource_object_id  = data.azuread_service_principal.defender.object_id
#
#   app_role_id = one([
#     for role in data.azuread_service_principal.defender.app_roles :
#     role.id if role.value == "Machine.Read.All"
#   ])
# }