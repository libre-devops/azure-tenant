############################################
# Variables
############################################

variable "env" {
  type        = string
  description = "Environment short code. Allowed values: dev, uat, prd."
  nullable    = false

  validation {
    condition     = contains(["dev", "uat", "prd"], lower(trimspace(var.env)))
    error_message = "env must be one of: dev, uat, prd (case-insensitive)."
  }
}

variable "short_region" {
  type        = string
  description = "Short code for Azure region. Allowed values: uks, ukw, euw."
  nullable    = false

  validation {
    condition     = contains(["uks", "ukw", "euw"], lower(trimspace(var.short_region)))
    error_message = "short_region must be one of: uks, ukw, euw (case-insensitive)."
  }
}

variable "short" {
  type        = string
  description = "Short resource prefix (e.g. libd)."
  nullable    = false
}

variable "layer_name" {
  type        = string
  description = "Platform layer identifier."
  nullable    = false

  validation {
    condition     = contains(["foundation"], lower(trimspace(var.layer_name)))
    error_message = "layer_name must be one of: foundation."
  }
}

############################################
# Locals
############################################

locals {
  ############################################
  # Normalise inputs
  ############################################

  normalised_env          = lower(trimspace(var.env))
  normalised_short        = lower(trimspace(var.short))
  normalised_short_region = lower(trimspace(var.short_region))
  normalised_layer        = lower(trimspace(var.layer_name))

  ############################################
  # Environment mapping
  ############################################

  env_map = {
    dev = "development"
    uat = "useracceptance"
    prd = "production"
  }

  validated_env = local.normalised_env
  long_env      = local.env_map[local.validated_env]

  ############################################
  # Region mapping (single source of truth)
  ############################################

  region_map = {
    uks = "uksouth"
    ukw = "ukwest"
    euw = "westeurope"
  }

  location = local.region_map[local.normalised_short_region]
}

############################################
# Outputs
############################################

output "normalised_env" {
  description = "Normalised short environment code"
  value       = local.validated_env
}

output "long_env" {
  description = "Long-form environment name"
  value       = local.long_env
}

output "location" {
  description = "Azure region in long form (derived from short_region)"
  value       = local.location
}

############################################
# Context Output (recommended consumption)
############################################

output "context" {
  description = "Standardised platform context object for downstream modules"

  value = {
    env = {
      short = local.validated_env
      long  = local.long_env
    }

    location = {
      short = local.normalised_short_region
      long  = local.location
    }

    naming = {
      prefix = local.normalised_short

      resource_group = {
        foundation = local.foundation_rg_name
      }
    }

    layer = local.normalised_layer
  }
}