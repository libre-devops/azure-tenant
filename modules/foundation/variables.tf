variable "env" {
  type        = string
  description = "Environment short code. Allowed values: dev, uat, prd."
  nullable    = false

  validation {
    condition     = contains(["dev", "uat", "prd"], lower(trimspace(var.env)))
    error_message = "env must be one of: dev, uat, prd (case-insensitive)."
  }
}

variable "short" {
  type        = string
  description = "Short resource prefix used in naming (lowercase letters/numbers/hyphens)."
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,22}[a-z0-9]$", lower(trimspace(var.short))))
    error_message = "short must be 2–24 chars, lowercase a-z/0-9/hyphen, start and end with a letter or number."
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

variable "layer_name" {
  type        = string
  description = "Platform layer identifier for this run. Allowed values: foundation, networking, automation-standard, automation-privileged, alerting, sentinel, integration (case-insensitive)."
  nullable    = false

  validation {
    condition     = contains(["foundation"], lower(trimspace(var.layer_name)))
    error_message = "layer_name must be one of: foundation, automation, integration (case-insensitive)."
  }
}