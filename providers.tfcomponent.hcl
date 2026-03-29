required_providers {
  azurerm = {
    source  = "hashicorp/azurerm"
    version = "~> 4.64.0"
  }
  azapi = {
    source  = "Azure/azapi"
    version = "~> 2.9.0"
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

provider "azurerm" "write" {
  config {
    features {
      resource_group {
        prevent_deletion_if_contains_resources = false
      }
    }

    storage_use_azuread = true
    use_oidc            = true
    use_cli             = false

    subscription_id = var.subscription_id
    tenant_id       = var.tenant_id
    client_id       = var.write_client_id
    oidc_token      = var.identity_token
  }
}

provider "azurerm" "rbac" {
  config {
    features {
      resource_group {
        prevent_deletion_if_contains_resources = false
      }
    }

    storage_use_azuread = true
    use_oidc            = true
    use_cli             = false

    subscription_id = var.subscription_id
    tenant_id       = var.tenant_id
    client_id       = var.rbac_client_id
    oidc_token      = var.identity_token
  }
}

provider "azapi" "write" {
  config {
    use_oidc            = true
    use_cli             = false

    subscription_id = var.subscription_id
    tenant_id       = var.tenant_id
    client_id       = var.write_client_id
    oidc_token      = var.identity_token
  }
}

provider "azapi" "rbac" {
  config {
    use_oidc            = true
    use_cli             = false

    subscription_id = var.subscription_id
    tenant_id       = var.tenant_id
    client_id       = var.rbac_client_id
    oidc_token      = var.identity_token
  }
}

provider "azuread" "this" {
  config {
    use_oidc            = true
    use_cli             = false

    tenant_id       = var.tenant_id
    client_id       = var.rbac_client_id
    oidc_token      = var.identity_token
  }
}

provider "msgraph" "this" {
  config {
    use_oidc            = true
    use_cli             = false
    use_powershell      = false

    tenant_id       = var.tenant_id
    client_id       = var.rbac_client_id
    oidc_token      = var.identity_token
  }
}