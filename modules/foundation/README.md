```hcl
resource "azurerm_resource_group" "this" {
  name     = "rg-${var.short}-${var.short_region}-${var.env}"
  location = var.long_region
}
```
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | ~> 4.60.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 4.60.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_resource_group.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_client_config.rbac](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |
| [azurerm_client_config.write](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_env"></a> [env](#input\_env) | Environment short code. Allowed values: dev, uat, prd. | `string` | n/a | yes |
| <a name="input_long_region"></a> [long\_region](#input\_long\_region) | Long code for Azure region. Allowed values: uksouth, ukwest, westeurope. | `string` | n/a | yes |
| <a name="input_short"></a> [short](#input\_short) | Short resource prefix used in naming (lowercase letters/numbers/hyphens). | `string` | n/a | yes |
| <a name="input_short_region"></a> [short\_region](#input\_short\_region) | Short code for Azure region. Allowed values: uks, ukw, euw. | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_rbac_client_id"></a> [rbac\_client\_id](#output\_rbac\_client\_id) | The client ID used by the RBAC azurerm provider alias |
| <a name="output_rbac_object_id"></a> [rbac\_object\_id](#output\_rbac\_object\_id) | The object ID of the service principal or user for the RBAC provider |
| <a name="output_rbac_subscription_id"></a> [rbac\_subscription\_id](#output\_rbac\_subscription\_id) | The subscription ID used by the RBAC provider |
| <a name="output_rbac_tenant_id"></a> [rbac\_tenant\_id](#output\_rbac\_tenant\_id) | The tenant ID used by the RBAC provider |
| <a name="output_rg__location"></a> [rg\_\_location](#output\_rg\_\_location) | Resource group location. |
| <a name="output_rg_id"></a> [rg\_id](#output\_rg\_id) | Resource group ID. |
| <a name="output_rg_name"></a> [rg\_name](#output\_rg\_name) | Resource group name. |
| <a name="output_write_client_id"></a> [write\_client\_id](#output\_write\_client\_id) | The client ID used by the default (write) azurerm provider |
| <a name="output_write_object_id"></a> [write\_object\_id](#output\_write\_object\_id) | The object ID of the service principal or user for the write provider |
| <a name="output_write_subscription_id"></a> [write\_subscription\_id](#output\_write\_subscription\_id) | The subscription ID used by the write provider |
| <a name="output_write_tenant_id"></a> [write\_tenant\_id](#output\_write\_tenant\_id) | The tenant ID used by the write provider |
