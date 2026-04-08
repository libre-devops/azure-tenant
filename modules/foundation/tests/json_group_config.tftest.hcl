# tests/json_group_config.tftest.hcl
#
# Runs the foundation module under mock providers so the check blocks execute
# against the real JSON config files without any Azure credentials or state.
#
# PROVIDER ALIASES IN THIS MODULE
# ────────────────────────────────
# azurerm          → default
# azurerm.rbac     → aliased
# azapi            → default
# azapi.rbac       → aliased
# azuread          → default
# msgraph          → default

# ─────────────────────────────────────────────────────────────────────────────
#  MOCK PROVIDERS
# ─────────────────────────────────────────────────────────────────────────────

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000000"
      subscription_id = "00000000-0000-0000-0000-000000000000"
      client_id       = "00000000-0000-0000-0000-000000000000"
      object_id       = "00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "azurerm" {
  alias = "rbac"

  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000000"
      subscription_id = "00000000-0000-0000-0000-000000000000"
      client_id       = "00000000-0000-0000-0000-000000000000"
      object_id       = "00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "azapi" {}

mock_provider "azapi" {
  alias = "rbac"
}

mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-000000000000"
      app_roles = [
        {
          id                   = "11111111-1111-1111-1111-111111111111"
          value                = "Device.Read.All"
          allowed_member_types = ["Application"]
          description          = "mock"
          display_name         = "mock"
          enabled              = true
        },
        {
          id                   = "22222222-2222-2222-2222-222222222222"
          value                = "GroupMember.ReadWrite.All"
          allowed_member_types = ["Application"]
          description          = "mock"
          display_name         = "mock"
          enabled              = true
        },
      ]
    }
  }
}

mock_provider "msgraph" {}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE VARIABLES
# ─────────────────────────────────────────────────────────────────────────────

variables {
  env          = "dev"
  short        = "libd"
  short_region = "uks"
  layer_name   = "foundation"
}

# ─────────────────────────────────────────────────────────────────────────────
#  RUN — validate group configs
#
#  check blocks fire on every plan regardless of which run block you're in.
#  expect_failures suppresses known firing check blocks so the run can still
#  pass and assert on the checks that must never fire.
#
#  WHEN ALL GROUPS ARE POPULATED:
#    Remove check.no_empty_device_lists from expect_failures. The assertions
#    below already cover that condition and will catch any regression.
# ─────────────────────────────────────────────────────────────────────────────

run "validate_group_configs" {
  command = plan

  providers = {
    azurerm      = azurerm
    azurerm.rbac = azurerm.rbac
    azapi        = azapi
    azapi.rbac   = azapi.rbac
    azuread      = azuread
    msgraph      = msgraph
  }

  # TODO: check.no_empty_device_lists is expected to fire while groups 3-6 are
  # unpopulated. Remove this once all groups have devices configured.
  expect_failures = [
    check.no_empty_device_lists,
  ]

  # These must never fire regardless of rollout state.
  assert {
    condition     = length(local.invalid_schema_configs) == 0
    error_message = "Invalid JSON schema in configs: ${join(", ", local.invalid_schema_configs)}. Each config must have 'groupId' (string) and 'devices' (array)."
  }

  assert {
    condition = length(local.duplicate_device_groups) == 0
    error_message = "Duplicate devices found: ${
      join(", ", [
        for k, v in local.duplicate_device_groups :
        "${k} => [${join(", ", v)}]"
      ])
    }."
  }

  assert {
    condition = length(local.duplicate_group_ids) == 0
    error_message = "Duplicate groupIds detected: ${
      join(", ", [
        for gid, groups in local.duplicate_group_id_map :
        "${gid} => [${join(", ", groups)}]"
      ])
    }. Each group config must target a unique Entra group."
  }
}
