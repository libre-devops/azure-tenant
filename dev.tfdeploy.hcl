store "varset" "shared" {
  name     = "libre-devops-dev-shared"
  category = "terraform"
}

store "varset" "shared_env" {
  name     = "libre-devops-dev-shared"
  category = "env"
}

identity_token "azurerm" {
  audience = ["api://AzureADTokenExchange"]
}

deployment "dev" {
  inputs = {
    identity_token = identity_token.azurerm.jwt
    env            = "dev"
    short          = "libd"
    short_region   = "uks"

    subscription_id = store.varset.shared.subscription_id
    tenant_id       = store.varset.shared.tenant_id
    rbac_client_id  = store.varset.shared.rbac_client_id
    write_client_id = store.varset.shared.write_client_id
  }
  destroy = true
}