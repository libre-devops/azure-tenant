# Entra ID Group Sync — JSON Config-Driven

An Azure Automation runbook that synchronises explicitly configured Linux devices into Entra ID security groups, driven by per-group JSON definitions stored as Automation Variables.

---

## Background

When a Linux device is onboarded to MDE and Security Settings Management is enabled, Intune creates a **synthetic Entra ID device object** for that device. This allows Intune policies to be pushed to devices that are not formally enrolled.

The problem is that this synthetic object is not automatically added to any Entra ID group — which means it cannot be targeted by Conditional Access, RBAC, or other group-scoped policies without manual intervention.

This runbook bridges that gap by running on a schedule, reading an explicit allowlist of device names per group, resolving each device to its Entra ID Object ID, and ensuring the correct group membership is maintained.

### Why not MDE tags?

The previous version of this runbook queried the MDE Machines API and used device tags to drive group membership. That approach was replaced for the following reasons:

- MDE API lag means offboarded devices remain in query results for an indeterminate period
- Tag-based inclusion is implicit — any misconfigured tag causes incorrect group membership
- A single runbook could only target one group at a time

The JSON allowlist model provides an explicit, auditable, Git-controlled definition of which devices belong in which group.

---

## How It Works

```
Azure Automation (scheduled, every 60 minutes)
        │
        ├─ 1. Authenticate via User-Assigned Managed Identity
        │
        ├─ 2. Load group configs from Automation Variables
        │       └─ Each variable contains a JSON object (see schema below)
        │
        ├─ 3. Fetch ALL Entra device objects once into a local index
        │       └─ Single paginated Graph API call — O(1) lookups thereafter
        │
        ├─ 4. For each configured group:
        │       ├─ Resolve each device name against the local index
        │       │     ├─ Exact displayName match (FQDN and short name)
        │       │     ├─ Fuzzy startswith match on short name
        │       │     └─ Pending (not yet in Entra — will retry next run)
        │       │
        │       ├─ Get current group members (paginated)
        │       ├─ Add devices not yet in the group
        │       └─ Optionally remove members not in the config (removeStale)
        │
        └─ 5. Print per-group summary report and exit
```

---

## Repository Layout

```
modules/foundation/
  configs/
    linux-group1.json          # one file per group
    linux-group2.json
    ...
    linux-group6.json
  scripts/
    sync/
      Sync-MDELinuxDeviceToEntraFromJson.ps1
      Tests/
        Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1
    debug/
      Debug.ps1
  tests/
    json_group_config.tftest.hcl
  main.tf
  variables.tf
  versions.tf
```

---

## JSON Config Schema

Each Automation Variable contains a single JSON object:

```json
{
  "groupId":     "853451d5-e186-4362-9337-6f8ce967570a",
  "name":        "linux-group1",
  "removeStale": true,
  "devices": [
    "server01.contoso.local",
    "server02"
  ]
}
```

| Field         | Required | Description                                                                                                 |
|---------------|----------|-------------------------------------------------------------------------------------------------------------|
| `groupId`     | Yes      | Entra ID security group Object ID                                                                           |
| `name`        | No       | Human-readable label used in logging and the summary report                                                 |
| `removeStale` | No       | If `true`, removes group members not in `devices`. Defaults to the runbook's `DefaultRemoveStale` parameter |
| `devices`     | Yes      | Array of device names. Accepts FQDNs or short hostnames. Empty array = group skipped with WARN (no error)   |

Device names are matched case-insensitively. Both `server01.contoso.local` and `server01` will resolve correctly.

---

## Terraform Infrastructure

### Group Config Variables

Each JSON config file is stored in `configs/` and loaded as an Automation Variable via Terraform. The variable name is derived automatically from the filename:

```
configs/linux-group1.json  →  Automation Variable: GroupConfig-linux-group1
```

To add a new group:

1. Create `configs/linux-groupN.json` with the correct `groupId` and `devices`
2. Add the key to the `raw_group_configs` map in `main.tf`
3. Run `terraform apply`

The runbook parameter `automationvariablenames` is built automatically from the map keys — no manual string editing required.

### Terraform Check Blocks

`main.tf` includes four check blocks that validate JSON config files at plan time:

| Check                   | What it catches                                        |
|-------------------------|--------------------------------------------------------|
| `no_duplicate_devices`  | Same device listed twice within one group config       |
| `valid_schema`          | Missing `groupId` or `devices` field, or invalid types |
| `no_empty_device_lists` | `devices` array is present but empty                   |
| `unique_group_ids`      | Same `groupId` referenced in two or more configs       |

These fire as warnings during `terraform plan` and `terraform apply`. On HCP Terraform the plan can be approved despite a check warning — use the Terraform test suite (below) to enforce them in CI before the plan stage is reached.

### Terraform Test Suite

`terraform test` validates the JSON config files without any Azure credentials or real provider calls. All providers are mocked.

```bash
cd modules/foundation
terraform test
```

Two test runs are defined in `tests/json_group_config.tftest.hcl`:

| Run                                       | Purpose                                                                                      |
|-------------------------------------------|----------------------------------------------------------------------------------------------|
| `validate_config_integrity`               | Schema, duplicates, and unique groupIds — must always pass                                   |
| `acknowledge_empty_groups_during_rollout` | Asserts that `check.no_empty_device_lists` fires (expected while groups are being populated) |

When all groups have devices configured, remove the `acknowledge_empty_groups_during_rollout` run block and add an empty-device assertion to `validate_config_integrity`.

### Resources Provisioned

- `azurerm_resource_group`
- `azurerm_user_assigned_identity`
- `azurerm_automation_account` with `UserAssigned` identity
- `azuread_app_role_assignment` × 2 (Graph: `Device.Read.All`, `GroupMember.ReadWrite.All`)
- `azurerm_automation_variable_string` × N (one per group config, via `for_each`)
- `azurerm_automation_runtime_environment` (PowerShell 7.2 + Az 11.2.0)
- `azurerm_automation_runbook`
- `azurerm_automation_schedule` + `azurerm_automation_job_schedule`
- `azurerm_monitor_action_group`
- `azurerm_monitor_metric_alert`

> Note: `Machine.Read.All` on the WindowsDefenderATP service principal is no longer required. The MDE API dependency has been removed entirely.

---

## Prerequisites

### Azure Automation Account

- PowerShell 7.2 runtime environment
- Az module version `11.2.0` in the runtime
- A User-Assigned Managed Identity attached to the Automation Account

### Managed Identity API Permissions

Application permissions provisioned via Terraform (`azuread_app_role_assignment`):

| API                   | Permission                  | Purpose                             |
|-----------------------|-----------------------------|-------------------------------------|
| `graph.microsoft.com` | `Device.Read.All`           | Fetch all Entra device objects      |
| `graph.microsoft.com` | `GroupMember.ReadWrite.All` | Read, add, and remove group members |

### Entra ID — Synthetic Device Registration

For devices to be resolvable in Entra ID:

1. **MDE** → Settings → Endpoints → Configuration Management → Enforcement Scope: Linux must be enabled
2. **Intune** → Endpoint Security → Microsoft Defender for Endpoint: connector active, `Allow MDE to enforce security configurations` enabled

Once configured, devices appear in Entra ID within 15–60 minutes of their next MDE agent heartbeat. Until then, they are tracked as **Pending** in the summary — this is expected and not treated as a failure.

---

## Runbook Parameters

| Parameter                 | Type     | Default  | Description                                                                                                                                                 |
|---------------------------|----------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ManagedIdentityClientId` | `string` | —        | **Required.** Client ID of the User-Assigned Managed Identity. Passed via job schedule.                                                                     |
| `AutomationVariableNames` | untyped  | —        | **Required.** Comma-separated Automation Variable names. Passed via job schedule. Arrives as `System.String` regardless of declaration.                     |
| `DefaultRemoveStale`      | `bool`   | `$true`  | Fallback `removeStale` behaviour when not set per group. **Do not pass via job schedule** — `[bool]` binding from string is unreliable in Azure Automation. |
| `WhatIf`                  | `bool`   | `$false` | Dry-run mode — logs all changes without writing to any group. **Do not pass via job schedule.**                                                             |
| `MaxRetries`              | `int`    | `6`      | Maximum retry attempts for transient API failures                                                                                                           |
| `RetryDelaySeconds`       | `int`    | `20`     | Fallback delay between retries when no `Retry-After` header is present                                                                                      |

> `DefaultRemoveStale` and `WhatIf` are controlled by editing their default values in the script source, not by the job schedule. This avoids the `[bool]`-from-string binding issue in Azure Automation's job scheduler.

---

## Failure Model

| Situation                                    | Job Status | Alert   |
|----------------------------------------------|------------|---------|
| Device pending Entra registration            | Completed  | No      |
| Group config has empty devices array         | Completed  | No      |
| All groups have empty devices arrays         | Completed  | No      |
| Device name ambiguous (fuzzy match conflict) | Completed  | No      |
| Automation Variable missing or invalid JSON  | **Failed** | **Yes** |
| Graph API call fails after all retries       | **Failed** | **Yes** |
| Group add / remove operation fails           | **Failed** | **Yes** |
| Unhandled exception                          | **Failed** | **Yes** |

Pending devices are displayed in the summary under **Pending Entra Registration** and retried automatically on the next scheduled run. Ambiguous device names (where a fuzzy match returns multiple candidates) are shown under **Skipped — Ambiguous Resolution** and require the config to be corrected with a more specific name.

---

## Device Resolution

The runbook fetches all Entra device objects in a single paginated call and builds a local hashtable index. Per-device resolution is then O(1) for exact matches.

```
Step 1 — Exact displayName match (case-insensitive)
   Index lookup by full FQDN: 'server01.contoso.local'

Step 2 — Short-name match
   Index lookup by pre-dot segment: 'server01'

Step 3 — Fuzzy startswith match
   List scan: any device whose short name starts with the input short name
   Skipped if more than one candidate (ambiguous — logged as WARN, not error)

Step 4 — Pending
   Device not found by any strategy. Tracked in summary, retried next run.
```

---

## Logging

| Level   | PowerShell Stream          | Visible in Portal                        |
|---------|----------------------------|------------------------------------------|
| `DEBUG` | `Write-Verbose` (stream 4) | All Logs tab (when `log_verbose = true`) |
| `INFO`  | `Write-Host` (stream 6)    | Output tab and All Logs tab              |
| `WARN`  | `Write-Warning` (stream 3) | Warnings tab and All Logs tab            |
| `ERROR` | `Write-Host` (stream 6)    | Output tab and All Logs tab              |

`Write-Output` is never used inside any function — it writes to stream 1 (the pipeline) and would corrupt return values such as tokens and device IDs.

---

## Alerting Setup

| Setting                | Value                                                  |
|------------------------|--------------------------------------------------------|
| Resource               | Your Automation Account                                |
| Signal                 | `TotalJob` (metric)                                    |
| Dimension: RunbookName | Value of `foundation_mde_sync_automation_runbook_name` |
| Dimension: Status      | `Failed`                                               |
| Aggregation            | Total                                                  |
| Operator               | Greater than or equal to                               |
| Threshold              | `1`                                                    |
| Frequency              | `PT5M`                                                 |
| Window                 | `PT5M`                                                 |

> The metric name is `TotalJob` (singular) — the portal displays it as "Total Jobs" but the API name differs.

---

## Pester Tests

Unit tests cover the pure in-memory logic of the runbook with no Azure credentials or API calls.

```powershell
cd modules/foundation/scripts/sync
Invoke-Pester ./Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1 -Output Detailed
```

| Describe block               | What is tested                                                    |
|------------------------------|-------------------------------------------------------------------|
| `Log-Message stream routing` | Each level writes to the correct stream; ERROR does not throw     |
| `NormalizeVariableNames`     | Splitting, trimming, deduplication, sort order, throw on empty    |
| `Sanitize-InputString`       | Quote stripping, whitespace trimming, passthrough of clean values |
| `Resolve-Device`             | Exact, short-name, fuzzy, ambiguous, and pending resolution paths |
| `Build-DeviceIndex`          | Index structure, first-write-wins dedup, null displayName skip    |

---

## Known Behaviours

**Eventual consistency** — MDE and Entra ID are not strongly consistent. A newly onboarded device may take 15–60 minutes to appear in Entra ID after enrollment completes. The runbook handles this gracefully by tracking pending devices separately from errors.

**DNS variants** — `computerDnsName` in MDE may be a FQDN or just a hostname. Both are handled by the resolution index which stores both the full name and the pre-dot segment.

**Empty groups during rollout** — Groups with an empty `devices` array in their JSON config are skipped with a WARN and do not increment the error count. This allows the runbook to run cleanly while groups are being populated incrementally.

**Parameter binding** — Azure Automation passes all job schedule parameters as strings. `AutomationVariableNames` is declared untyped and split inside the runbook. `[bool]` parameters (`DefaultRemoveStale`, `WhatIf`) are not passed via job schedule to avoid coercion issues.

**Race conditions** — If two runbook instances overlap and both attempt to add the same device, Graph returns `400 already exists`. This is caught and silently ignored.

---