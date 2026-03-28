variable "env" {
  type        = string
  description = "Environment short code. e.g. dev, uat, prd."
}

variable "short_region" {
  type        = string
  description = "Short Azure region code. e.g. uks, ukw, euw."
}

variable "long_region" {
  type        = string
  description = "Azure region name. e.g. uksouth, ukwest, westeurope."
}

variable "tenant_id" {
  type        = string
  description = "Azure tenant ID (GUID)."
  ephemeral   = true
}

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID (GUID)."
  ephemeral   = true
}

variable "short" {
  type        = string
  description = "Short resource prefix used in naming."
}

variable "rbac_client_id" {
  type        = string
  description = "Client ID for the RBAC Service Principal used by the azurerm.rbac provider alias."
  ephemeral   = true
}

variable "write_client_id" {
  type        = string
  description = "Client ID for the write Service Principal used by the azurerm provider"
  ephemeral   = true
}

variable "identity_token" {
  type        = string
  description = "Identity token for OIDC connection"
  ephemeral   = true
}