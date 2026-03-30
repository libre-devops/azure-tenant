# MDE → Entra ID Group Sync

An Azure Automation runbook that automatically synchronises Microsoft Defender for Endpoint (MDE) Linux devices into an Entra ID security group, driven by MDE device tags.

---

## Background

When a Linux device is onboarded to MDE and Security Settings Management is enabled, Intune creates a **synthetic Entra ID device object** for that device. This allows Intune policies to be pushed to devices that are not formally enrolled.

The problem is that this synthetic object is not automatically added to any Entra ID group — which means it cannot be targeted by Conditional Access, RBAC, or other group-scoped policies without manual intervention.

This runbook bridges that gap by running on a schedule, finding all tagged MDE devices, resolving their synthetic Entra IDs, and ensuring they are members of the correct security group.

---

## How It Works

```
Azure Automation (scheduled)
        │
        ├─ 1. Authenticate via User-Assigned Managed Identity
        │
        ├─ 2. Query MDE API for devices matching tags + OS + health filters
        │
        ├─ 3. Resolve each device to its Entra ID Object ID
        │       ├─ Fast path: aadDeviceId lookup
        │       ├─ Exact displayName match (FQDN and short name)
        │       └─ Fuzzy startswith match on short name
        │
        ├─ 4. Compare resolved devices against current group members
        │       ├─ Add any devices not yet in the group
        │       └─ Optionally remove members no longer matching the filter
        │
        └─ 5. Print summary report and exit
```

---

## Prerequisites

### Azure Automation Account

- PowerShell 7.2 runtime environment
- Az module version `11.2.0` installed in the runtime
- A **User-Assigned Managed Identity** attached to the Automation Account

### Managed Identity API Permissions

These are **application permissions** and must be granted via PowerShell or Terraform — the Azure Portal UI does not support assigning them to managed identities directly.

| API | Permission | Purpose |
|-----|-----------|---------|
| `api.securitycenter.microsoft.com` | `Machine.Read.All` | Read MDE device inventory and machine tags |
| `graph.microsoft.com` | `Device.Read.All` | Look up Entra device objects by ID or display name |
| `graph.microsoft.com` | `GroupMember.ReadWrite.All` | Read, add, and remove members from the target group |

These are provisioned via Terraform using `azuread_app_role_assignment` resources in the infrastructure layer.

### MDE Security Settings Management

For synthetic Entra ID device objects to be created, the following must be configured:

1. In **MDE** → Settings → Endpoints → Configuration Management → Enforcement Scope: Linux devices must be enabled
2. In **Intune** → Endpoint Security → Microsoft Defender for Endpoint: the connector must be active and `Allow MDE to enforce security configurations` must be enabled

Once both sides are configured, devices will appear in Entra ID within 15–60 minutes of their next MDE agent heartbeat.

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ManagedIdentityClientId` | `string` | — | **Required.** Client ID of the User-Assigned Managed Identity |
| `DeviceTag` | `string[]` | `@('RHEL-EDR', 'MDE-Management')` | One or more MDE machine tags. Devices matching any tag are included |
| `EntraGroupObjectId` | `string` | — | **Required.** Object ID of the target Entra ID security group |
| `RemoveStaleMembers` | `bool` | `$false` | If `$true`, removes group members that no longer match the tag filter |
| `MaxRetries` | `int` | `6` | Maximum retry attempts for transient API failures |
| `RetryDelaySeconds` | `int` | `20` | Fallback delay between retries when no `Retry-After` header is present |
| `OsPlatforms` | `string[]` | RHEL, Ubuntu, CentOS, Debian, SLES | MDE `osPlatform` values to include in the server-side filter |
| `HealthStatus` | `string[]` | `@('Active')` | MDE `healthStatus` values to include |
| `WhatIf` | `bool` | `$false` | Dry-run mode — logs intended changes without making them |

---

## Failure Model

The runbook distinguishes between two categories of failure, because not all failures are equal in a cloud environment.

### Pending devices — job succeeds, no alert

A device found in MDE but not yet resolvable in Entra ID is **not a failure**. It means the Intune/MDE synthetic registration is still propagating. The device is tracked in the summary under **Pending Entra Registration** and will be retried automatically on the next scheduled run. The job exits as `Completed`.

### API errors — job fails, alert fires

A genuine failure — retries exhausted on an API call, a permissions error, or a group add/remove operation that fails — increments the error counter. After the summary is printed, the job deliberately `throw`s, setting the job status to `Failed`. This causes the Azure Monitor metric alert to fire.

| Situation | Job Status | Alert |
|-----------|-----------|-------|
| Device pending Entra registration | Completed | No |
| 0 devices found (tag not yet applied) | Completed | No |
| API call fails after all retries | **Failed** | **Yes** |
| Group add / remove fails | **Failed** | **Yes** |
| Unhandled exception | **Failed** | **Yes** |

---

## Alerting Setup

No Application Insights or Log Analytics workspace is required for failure alerting. Create a single Azure Monitor metric alert rule:

| Setting | Value |
|---------|-------|
| Resource | Your Automation Account |
| Signal | `TotalJob` (metric) |
| Dimension: RunbookName | `Sync-MdeDevicesToEntraGroup` |
| Dimension: Status | `Failed` |
| Aggregation | Total |
| Operator | Greater than or equal to |
| Threshold | `1` |
| Frequency | `PT5M` |
| Action | Action Group (email / Teams webhook / SMS) |

> Note: The metric name is `TotalJob` (singular) — not `TotalJobs`. The portal displays it as "Total Jobs" but the API name differs.

---

## Logging

The runbook uses four log levels, each mapped to a distinct PowerShell stream to ensure function return values are never corrupted.

| Level | Stream | Visible in | Purpose |
|-------|--------|-----------|---------|
| `DEBUG` | `Write-Verbose` | Verbose output | Deep diagnostics, per-device resolution results |
| `INFO` | `Write-Verbose` | Verbose output | High-level operational flow |
| `WARN` | `Write-Warning` | Warning stream | Soft issues: pending devices, retries, fallback paths |
| `ERROR` | `Write-Host` | Output stream | Hard failures only |

> `Write-Output` is never used inside any function. At Az 11.2.0, `Write-Output` inside a function that also returns a value silently concatenates log lines onto the return value — this was the root cause of JWT corruption discovered during development.

To see INFO and DEBUG detail, enable **Verbose logging** on the runbook in the Azure Automation portal, or set `$VerbosePreference = 'Continue'` when running locally.

---

## Device Resolution

Because MDE synthetic devices often have `aadDeviceId = null`, the runbook uses a three-stage fallback strategy to locate the correct Entra device object.

```
Stage 1 — aadDeviceId fast path
   Query Graph by deviceId (exact, reliable when populated)

Stage 2 — Exact displayName match
   Query by FQDN (craig-rhel9-vm1.mshome.net) OR short name (craig-rhel9-vm1)
   Prefer result with blank trustType (characteristic of synthetic MDE devices)

Stage 3 — Fuzzy startswith match
   Query startswith(displayName, 'shortname')
   Prefer blank trustType, fall back to first result

Stage 4 — Soft failure
   Device logged as pending, tracked in summary, retried next run
```

---

## Terraform Infrastructure

The supporting infrastructure is provisioned via Terraform and includes:

- `azurerm_resource_group`
- `azurerm_user_assigned_identity` (the Managed Identity)
- `azurerm_automation_account` with `UserAssigned` identity
- `azuread_app_role_assignment` × 3 (Graph × 2, Defender × 1)
- `azurerm_automation_runtime_environment` (PowerShell 7.2 + Az 11.2.0)
- `azurerm_automation_runbook`
- `azurerm_automation_schedule` + `azurerm_automation_job_schedule`
- `azurerm_monitor_action_group`
- `azurerm_monitor_metric_alert`

---

## Running Locally

To run the script outside of Automation for testing:

```powershell
# Requires Az module installed and an active az login session
$VerbosePreference = 'Continue'   # show INFO/DEBUG logs

.\Sync-MdeDevicesToEntraGroup.ps1 `
    -ManagedIdentityClientId '<your-mi-client-id>' `
    -DeviceTag                @('RHEL-EDR') `
    -EntraGroupObjectId       '<your-group-object-id>' `
    -WhatIf                   $true   # dry run — no writes
```

---

## Known Behaviours

**Eventual consistency** — MDE and Entra ID are not strongly consistent. A device newly onboarded to MDE may take 15–60 minutes to appear in Entra ID after Security Settings Management enrollment completes. The runbook handles this gracefully.

**DNS variants** — The `computerDnsName` field in MDE may contain a fully qualified domain name (`host.domain.local`) or just a hostname. The resolution logic handles both by attempting FQDN and short name matches independently.

**Duplicate devices** — If a device carries multiple matching tags it will only appear once in the resolved set. Deduplication is handled via a `HashSet` keyed on the MDE device ID.

**Race conditions** — If two runbook instances overlap and both attempt to add the same device simultaneously, the Graph API returns a `400 already exists` error. This is caught and silently ignored.

---

## Potential Future Improvements

- Cache resolved Entra Object IDs across runs to reduce Graph API calls
- Parallel device resolution for large device inventories
- Persist the pending device list to storage and emit a warning if a device remains pending for more than N runs
- Export run metrics to Log Analytics for dashboarding and trend analysis