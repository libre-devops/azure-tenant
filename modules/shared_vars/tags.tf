variable "base_tags" {
  description = "Standard tags enforced by the module."
  type = object({
    ContactEmail   = optional(string, "noreply@libredevops.org")
    BusinessOwner  = optional(string, "Libre DevOps Owner")
    Classification = optional(string, "Internal")
    CostCenter     = optional(string, "1967")
    Creator        = optional(string, "Craig Thacker")
    Criticality    = optional(string, "Low")
    Deployment     = optional(string, "Terraform Stacks")
    ProjectCode    = optional(string, "1888")
  })
  default = {}

  validation {
    condition = alltrue([
      var.base_tags.ContactEmail == null || trimspace(var.base_tags.ContactEmail) == "" || can(regex(
        "^[^@\\s]+@libredevops\\.org$",
        lower(trimspace(var.base_tags.ContactEmail))
      )),
      var.base_tags.BusinessOwner == null || trimspace(var.base_tags.BusinessOwner) != "",
      var.base_tags.Classification == null || trimspace(var.base_tags.Classification) == "" || contains(
        ["pii", "public", "internal", "restricted"],
        lower(trimspace(var.base_tags.Classification))
      ),
      var.base_tags.CostCenter == null || trimspace(var.base_tags.CostCenter) != "",
      var.base_tags.Creator == null || trimspace(var.base_tags.Creator) != "",
      var.base_tags.Criticality == null || trimspace(var.base_tags.Criticality) == "" || contains(
        ["critical", "high", "medium", "low"],
        lower(trimspace(var.base_tags.Criticality))
      ),
      var.base_tags.Deployment == null || trimspace(var.base_tags.Deployment) != "",
      var.base_tags.ProjectCode == null || trimspace(var.base_tags.ProjectCode) != "",
    ])

    error_message = <<EOT
Invalid base_tags value.
- ContactEmail must be empty or end with @libredevops.org
- Classification must be one of: pii, public, internal, restricted
- Criticality must be one of: critical, high, medium, low
- Any provided tag value must not be empty
EOT
  }
}

variable "extra_tags" {
  description = "Caller-defined free-form tags."
  type        = map(string)
  default     = {}
}

variable "enabled" {
  description = "Whether the module should emit tags."
  type        = bool
  default     = true
}

locals {
  base_tags_clean = {
    for k, v in var.base_tags : k => trimspace(v)
    if v != null && trimspace(v) != ""
  }

  extra_tags_clean = {
    for k, v in var.extra_tags : k => trimspace(v)
    if v != null && trimspace(v) != ""
  }

  merged_tags = var.enabled ? merge(
    local.base_tags_clean,
    local.extra_tags_clean
  ) : {}

  normalized_tags = {
    for k, v in local.merged_tags : k => v
  }
}

output "base_tags" {
  description = "Cleaned base tags after validation and trimming."
  value       = local.base_tags_clean
}

output "extra_tags" {
  description = "Cleaned extra tags after trimming."
  value       = local.extra_tags_clean
}

output "tags" {
  description = "Final merged tag map."
  value       = local.normalized_tags
}

output "enabled" {
  description = "Whether tag output generation is enabled."
  value       = var.enabled
}
