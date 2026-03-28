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

deployment_auto_approve "dev_auto_approve" {
  check {
    condition = deployment.dev.inputs.env == "dev"
    reason    = "Always auto approve in dev."
  }
}

deployment_group "dev_group" {
  auto_approve_checks = [
    deployment_auto_approve.dev_auto_approve
  ]
}

deployment "dev" {
  inputs = {
    identity_token = identity_token.azurerm.jwt
    env            = "dev"
    long           = "libre-devops"
    short          = "libd"
    short_region   = "uks"
    long_region    = "uksouth"

    subscription_id = store.varset.shared.subscription_id
    tenant_id       = store.varset.shared.tenant_id
    rbac_client_id  = store.varset.shared.rbac_client_id
    write_client_id = store.varset.shared.write_client_id
  }
}