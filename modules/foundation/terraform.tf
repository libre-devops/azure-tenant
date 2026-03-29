terraform {
  required_providers {
    azurerm = {
      configuration_aliases = [azurerm.rbac]
      source                = "hashicorp/azurerm"
      version               = "~> 4.64.0"
    }
    azapi = {
      configuration_aliases = [azapi.rbac]
      source                = "Azure/azapi"
      version               = "~> 2.8.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.8.0"
    }
    msgraph = {
      source  = "microsoft/msgraph"
      version = "~> 0.3.0"
    }
  }
}

