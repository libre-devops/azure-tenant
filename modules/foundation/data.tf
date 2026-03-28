data "azurerm_client_config" "write" {}

data "azurerm_client_config" "rbac" {
  provider = azurerm.rbac
}