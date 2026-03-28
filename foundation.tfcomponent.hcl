component "foundation" {
  source = "./modules/foundation"

  providers = {
    azurerm      = provider.azurerm.write
    azurerm.rbac = provider.azurerm.rbac
    azapi        = provider.azapi.write
    azapi.rbac   = provider.azapi.rbac
  }


  inputs = {
    layer_name   = "foundation"
    env          = var.env
    short        = var.short
    long         = var.long
    short_region = var.short_region
  }
}