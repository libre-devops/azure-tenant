locals {
  rg_prefix          = "rg"
  base_name          = "${local.normalised_short}-${local.validated_env}"
  foundation_rg_name = "${local.rg_prefix}-${local.base_name}-${local.normalised_layer}"
}

output "base_name" {
  description = "The base name for the resources"
  value       = local.base_name
}

output "foundation_rg_name" {
  description = "Deterministic name for the foundation resource group"
  value       = local.foundation_rg_name
}