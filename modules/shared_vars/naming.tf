locals {
  rg_prefix                             = "rg"
  user_assigned_managed_identity_prefix = "uid"
  automation_account_prefix             = "aa"
  base_name                             = "${local.normalised_short}-${local.validated_env}"
  foundation_rg_name                    = "${local.rg_prefix}-${local.base_name}-${local.normalised_layer}"
  foundation_uid_name                   = "${local.user_assigned_managed_identity_prefix}-${local.base_name}-${local.normalised_layer}"
  foundation_aa_name                    = "${local.automation_account_prefix}-${local.base_name}-${local.normalised_layer}"
}

output "base_name" {
  description = "The base name for the resources"
  value       = local.base_name
}

output "foundation_rg_name" {
  description = "Deterministic name for the foundation resource group"
  value       = local.foundation_rg_name
}

output "foundation_uid_name" {
  description = "Deterministic name for foundation uid"
  value       = local.foundation_uid_name
}

output "foundation_aa_name" {
  description = "Deterministic name for foundation aa"
  value       = local.foundation_aa_name
}