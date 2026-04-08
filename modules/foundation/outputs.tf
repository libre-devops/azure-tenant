output "rbac_client_id" {
  description = "The client ID used by the RBAC azurerm provider alias"
  value       = data.azurerm_client_config.rbac.client_id
}

output "rbac_object_id" {
  description = "The object ID of the service principal or user for the RBAC provider"
  value       = data.azurerm_client_config.rbac.object_id
}

output "rbac_subscription_id" {
  description = "The subscription ID used by the RBAC provider"
  value       = data.azurerm_client_config.rbac.subscription_id
}

output "rbac_tenant_id" {
  description = "The tenant ID used by the RBAC provider"
  value       = data.azurerm_client_config.rbac.tenant_id
}

output "rg_id" {
  description = "Resource group ID."
  value       = module.rg.rg_id
}

output "rg_location" {
  description = "Resource group location."
  value       = module.rg.rg_location
}

output "rg_name" {
  description = "Resource group name."
  value       = module.rg.rg_name
}

output "write_client_id" {
  description = "The client ID used by the default (write) azurerm provider"
  value       = data.azurerm_client_config.write.client_id
}

output "write_object_id" {
  description = "The object ID of the service principal or user for the write provider"
  value       = data.azurerm_client_config.write.object_id
}

output "write_subscription_id" {
  description = "The subscription ID used by the write provider"
  value       = data.azurerm_client_config.write.subscription_id
}

output "write_tenant_id" {
  description = "The tenant ID used by the write provider"
  value       = data.azurerm_client_config.write.tenant_id
}
