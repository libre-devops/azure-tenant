module "rg" {
  source  = "libre-devops/rg/azurerm"
  version = "~> 1.0.0"

  env          = var.env
  long_region  = var.long_region
  short        = var.short
  short_region = var.short_region
}