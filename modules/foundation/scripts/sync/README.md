# Sync-MDELinuxDeviceToEntraFromJson

Azure Automation runbook that synchronises explicitly configured devices into Entra ID
security groups, driven by per-group JSON definitions stored as Azure Automation Variables.

| | |
|---|---|
| **Runbook** | `Sync-MDELinuxDeviceToEntraFromJson.ps1` |
| **Tests** | `Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1` |
| **Runtime** | PowerShell 7.2+ |
| **Auth** | User-Assigned Managed Identity |
| **APIs** | Microsoft Graph (`graph.microsoft.com`) |
| **Test framework** | Pester 5.0+ |

---

## Table of Contents

- [Overview](#overview)
- [Why JSON instead of MDE tags](#why-json-instead-of-mde-tags)
- [Execution Flow](#execution-flow)
- [JSON Config Schema](#json-config-schema)
- [Parameters](#parameters)
- [Device Resolution](#device-resolution)
- [Multi-Match Policy](#multi-match-policy)
- [Error Philosophy and Failure Model](#error-philosophy-and-failure-model)
- [Blast-Radius Guard](#blast-radius-guard)
- [Reliability for Long-Running Jobs](#reliability-for-long-running-jobs)
- [Logging](#logging)
- [Required Permissions](#required-permissions)
- [Tests](#tests)
- [Operational Runbook](#operational-runbook)

---

## Overview

When a Linux device is onboarded to Microsoft Defender for Endpoint (MDE) with Security
Settings Management enabled, Intune creates a synthetic Entra ID device object so that
policy can be pushed to a device that is not formally enrolled. That object is not added
to any group automatically, so it cannot be targeted by Conditional Access, RBAC, or any
other group-scoped policy without manual intervention.

This runbook closes that gap. On a schedule it reads an explicit, Git-controlled allowlist
of device names per group, resolves each name to its Entra ID object ID, and reconciles the
group membership: it adds configured devices that are missing and, optionally, removes
members that are no longer in the config.

The model is deliberately explicit and auditable. Membership is whatever the JSON says it
is, nothing more.

---

## Why JSON instead of MDE tags

A previous version queried the MDE Machines API and used device tags to drive membership.
It was replaced because:

- MDE API lag keeps offboarded devices in query results for an indeterminate period.
- Tag-based inclusion is implicit; a single mistagged device silently lands in the wrong group.
- One runbook instance could target only one group at a time.

The JSON allowlist gives an explicit, reviewable definition of which devices belong in which
group, version-controlled alongside the infrastructure. The MDE API dependency is removed
entirely.

---

## Execution Flow

```
Azure Automation (scheduled)
        |
        |  1. Authenticate via User-Assigned Managed Identity
        |       Connect-AzAccount -Identity, with fallback to default MI resolution
        |
        |  2. Acquire and cache a Microsoft Graph token (script scope)
        |
        |  3. Load and validate every group config from its Automation Variable
        |       - missing groupId .............. ERROR, counts toward failure
        |       - invalid JSON ................. ERROR, counts toward failure
        |       - empty devices array .......... WARN, skipped, NOT an error
        |
        |  4. Fetch ALL Entra device objects once into a local index
        |       Single paginated Graph call, O(1) lookups thereafter
        |
        |  5. For each configured group:
        |       - refresh the Graph token if near expiry
        |       - read current members (paginated)
        |       - resolve each configured device against the index
        |       - add resolved devices that are not already members
        |       - if removeStale: remove members not in the config
        |               (subject to the blast-radius guard)
        |
        |  6. Print a per-group summary report
        |
        +-- 7. Throw at the end only if there were genuine API errors
```

Nothing executes at script scope outside function definitions. All work runs inside a single
top-level `try/catch`, so a fatal error is always logged to a portal-visible stream before the
job is marked Failed.

---

## JSON Config Schema

One JSON object per Automation Variable:

```json
{
  "groupId":     "853451d5-e186-4362-9337-6f8ce967570a",
  "name":        "Linux Prod EDR",
  "removeStale": true,
  "devices": [
    "server01.contoso.local",
    "server02"
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `groupId` | Yes | Entra ID security group object ID. Missing value is a hard error. |
| `name` | No | Human-readable label used in logs and the summary. Falls back to `groupId`. |
| `removeStale` | No | If `true`, members not in `devices` are removed. Overrides the runbook `DefaultRemoveStale`. |
| `devices` | Yes for sync | Array of device names (FQDN or short hostname). An empty array skips the group with a WARN and is not an error, which allows partial rollout. |

Device names are matched case-insensitively. Both `server01.contoso.local` and `server01`
resolve to the same object.

---

## Parameters

```powershell
param (
    [Parameter(Mandatory)] [string] $ManagedIdentityClientId,
    [Parameter(Mandatory)]          $AutomationVariableNames,   # intentionally untyped
    [bool]   $DefaultRemoveStale     = $true,
    [bool]   $WhatIf                 = $false,
    [int]    $MaxRetries             = 6,
    [int]    $RetryDelaySeconds      = 20,
    [int]    $StaleRemovalMinCount   = 5,
    [double] $StaleRemovalMaxPercent = 0.20
)
```

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `ManagedIdentityClientId` | string | required | Client ID of the User-Assigned Managed Identity on the Automation Account. |
| `AutomationVariableNames` | untyped | required | Comma-separated Automation Variable names. Declared untyped because Azure Automation passes job-schedule parameters as `System.String`; the runbook splits, trims, sorts, and dedupes it internally. |
| `DefaultRemoveStale` | bool | `$true` | Fallback for `removeStale` when a group does not set it. Do not pass via the job schedule; change the default in source if needed. |
| `WhatIf` | bool | `$false` | Dry run. Logs every add/remove without writing, and bypasses the blast-radius guard. Do not pass via the job schedule. |
| `MaxRetries` | int | `6` | Maximum attempts for a transient Graph failure. |
| `RetryDelaySeconds` | int | `20` | Fallback delay between retries when no `Retry-After` header is returned. |
| `StaleRemovalMinCount` | int | `5` | Absolute floor for the blast-radius guard. |
| `StaleRemovalMaxPercent` | double | `0.20` | Percentage ceiling for the blast-radius guard. |

> **Why `bool` parameters are not job-scheduled:** binding `[bool]` from a string is unreliable
> in Azure Automation's scheduler. `DefaultRemoveStale` and `WhatIf` are controlled by editing
> their defaults in source.

---

## Device Resolution

All Entra device objects are fetched once and indexed into three structures: an exact-name
hashtable, a short-name hashtable, and a fuzzy list. Each configured device name is resolved
in this order, returning one of `Resolved`, `Ambiguous`, or `Pending`.

| Step | Strategy | Cost | Result |
|---|---|---|---|
| 1 | Exact `displayName` match (case-insensitive) | O(1) hashtable | Resolved |
| 2 | Short-name (pre-dot segment) match | O(1) hashtable | Resolved or Ambiguous |
| 3 | Fuzzy `startswith` on short name | list scan | Resolved or Ambiguous |
| 4 | No match | n/a | Pending (retried next run) |

A `Pending` device is one that is not yet visible in Entra ID, which is the normal state for a
recently onboarded host. It is tracked separately and never fails the job.

---

## Multi-Match Policy

A single device name can resolve to more than one Entra object ID. The runbook distinguishes
two cases by comparing the `displayName` of the matches:

- **Identical `displayName` (same device re-enrolled).** The old synthetic object lingers
  beside the new one. They are indistinguishable by name, so **all** matching IDs are added.
  The live object is always covered and the stale one is harmless. Logged as WARN for cleanup.
- **Different FQDNs that share a short name or prefix** (for example `server01.site-a` vs
  `server01.site-b`). These are genuinely different machines, and adding both would mis-target
  a policy, so the name is left **Ambiguous and skipped**. Correct the config with the FQDN.

The rule: add all IDs that resolve to the **same** `displayName`; skip when matches span
**different** display names. Ambiguous matches are surfaced in the summary under
`SKIPPED` and do not increment the error count.

---

## Error Philosophy and Failure Model

Two independent counters drive the outcome:

- `$script:SyncErrorCount` counts genuine API or group-operation failures only.
- `$script:PendingCount` counts devices not yet found in Entra (expected during propagation).

Pending devices, ambiguous skips, and empty groups never fail the job. The runbook throws at
the end only when `SyncErrorCount > 0`.

| Situation | Job status | Alert |
|---|---|---|
| Device pending Entra registration | Completed | No |
| Group config has an empty `devices` array | Completed | No |
| All groups have empty `devices` arrays | Completed | No |
| Device name ambiguous (spans different display names) | Completed | No |
| Automation Variable missing or invalid JSON | Failed | Yes |
| Config missing required `groupId` | Failed | Yes |
| Graph API call fails after all retries | Failed | Yes |
| Group add or remove fails | Failed | Yes |
| Blast-radius guard trips for a group | Failed | Yes |
| Unhandled exception | Failed | Yes |

---

## Blast-Radius Guard

Stale removal is protected against a truncated or corrupt config, a bad bulk edit, or a
transiently empty device index gutting a group in one run.

For a given group, removals are aborted (and the job fails) only when **both** thresholds are
exceeded in the same run:

- the number of stale members is greater than `StaleRemovalMinCount` (default 5), **and**
- those stale members are more than `StaleRemovalMaxPercent` of current membership (default 20%).

Both must trip: the percentage stops large-group wipeouts, the absolute floor stops false
positives on tiny groups (20% of one member rounds to zero). Genuine bulk removals must be
staged across multiple runs so each run stays under the limit. `WhatIf` bypasses the guard
because nothing is actually written.

---

## Reliability for Long-Running Jobs

This runbook is expected to run unattended for years. Several design choices protect it.

**Token handling.** `Get-GraphToken` caches the Graph token at script scope and re-acquires it
when missing, forced, or within five minutes of expiry. It is called before each group, and
`Invoke-WithRetry` force-refreshes on a `401`, so a job that outlives the roughly 60 to 90
minute token lifetime (large tenants, many groups) does not fail on an expired token. The
token extraction handles both a plaintext string and a `SecureString` (the `.Token` default
changed to `SecureString` in `Az.Accounts` 5.x), so a pinned-module bump cannot silently
produce the literal `System.Security.SecureString` as a token.

**Retry and backoff.** Transient failures retry up to `MaxRetries`. A `Retry-After` response
header is honoured when present (read via `TryGetValues`, since
`HttpResponseHeaders` has no string indexer); otherwise `RetryDelaySeconds` applies.

**Module pinning.** The Automation Account pins its `Az` module versions. Module auto-update is
the most common silent breaker of long-lived runbooks; the token and property-probe defences
above are there for the day a pin is deliberately bumped.

**Idempotency.** Adding a device that is already a member returns `already exists` and is
ignored. Removing a device that is already gone returns `does not exist` and is ignored. Two
overlapping runs are therefore safe.

---

## Logging

Log levels are mapped onto PowerShell streams chosen so that nothing ever lands on the success
stream inside a value-returning function. Writing to stream 1 there would corrupt the return
value, which is the classic way a Graph token gets mangled into `Bearer <logline> <token>`.

| Level | Cmdlet | Stream | Visibility |
|---|---|---|---|
| `DEBUG` | `Write-Verbose` | 4 | All Logs tab, only when verbose is enabled |
| `INFO` | `Write-Verbose` | 4 | All Logs tab, only when verbose is enabled |
| `STATUS` | `Write-Host` | 6 | Always visible. Start, per-group result, and totals. The baseline audit trail. |
| `WARN` | `Write-Warning` | 3 | Warnings tab and All Logs tab |
| `ERROR` | `Write-Host` | 6 | Always visible. Non-terminating on purpose. |

`ERROR` uses `Write-Host` rather than `Write-Error` deliberately: under
`$ErrorActionPreference = 'Stop'`, `Write-Error` would throw and defeat the count-and-continue
design. `Write-Output` is never used anywhere in the runbook.

---

## Required Permissions

The Managed Identity needs the following Microsoft Graph application permissions:

| API | Permission | Purpose |
|---|---|---|
| `graph.microsoft.com` | `Device.Read.All` | Fetch all Entra device objects |
| `graph.microsoft.com` | `GroupMember.ReadWrite.All` | Read, add, and remove group members |

**Least-privilege alternative.** Keep the two reads as application permissions
(`Device.Read.All` + `GroupMember.Read.All`) and grant member writes through a custom Entra
directory role with the action
`microsoft.directory/groups.security.assignedMembership/members/update`, scoped to the target
groups. That action covers assigned-membership security groups only, not dynamic or
mail-enabled groups.

---

## Tests

`Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1` is a Pester 5 suite covering the pure,
in-memory logic of the runbook. It makes no API calls and needs no Azure credentials.

### Design

The runbook is dot-sourced inside `BeforeAll`. Because the script body runs to completion when
dot-sourced, the test first defines global stubs so nothing reaches the network or the Azure
context:

| Stub | Purpose |
|---|---|
| `Connect-AzAccount`, `Disable-AzContextAutosave` | No-ops, so auth does nothing |
| `Get-AzAccessToken` | Returns a fake token with a one-hour expiry |
| `Invoke-RestMethod` | Returns an empty `value` set by default |
| `Get-AutomationVariable` | Returns a valid config with an empty `devices` array |

The stub config drives MAIN down the "no devices, skip with WARN" path so it exits cleanly
without building the index or touching a group, leaving the functions loaded for direct
testing.

### Coverage

| Describe block | What is verified |
|---|---|
| `Log-Message stream routing` | Each level writes to its correct stream; `ERROR` and `STATUS` do not throw and do not write to the output stream; the prefix carries the timestamp and invocation name. |
| `NormalizeVariableNames` | Splitting a comma string, splitting a single-element array, trimming, removing empties, deduplication, sort order, and throwing when no valid names remain. |
| `Sanitize-InputString` | Whitespace trimming, single and multi-layer quote stripping, escaped-quote conversion, empty-string passthrough, and clean-value passthrough. |
| `Resolve-Device` | Exact, short-name, and fuzzy resolution; case-insensitivity; the multi-match add-all behaviour for identical display names; ambiguous skips across different names; and the pending path. |
| `Build-DeviceIndex` | Exact and short index keys, single-id mapping, short-name-only devices, fuzzy list size, identical-displayName duplicates keeping both IDs, and skipping objects with no `displayName`. |

### Running the tests

```powershell
cd modules/foundation/scripts/sync
Invoke-Pester ./Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1 -Output Detailed
```

Requires PowerShell 7.2+ and Pester 5.0+ (both declared via `#Requires` in the test file).

---

## Operational Runbook

**A device is missing from its group.**
Check the summary. If the device is under `PENDING ENTRA REGISTRATION`, it is not yet visible
in Entra; it will be added on the next successful run, typically within 15 to 60 minutes of the
device's next MDE heartbeat. If it is under `SKIPPED`, its short name is ambiguous; replace it
in the config with the full FQDN.

**The job failed with a blast-radius error.**
A group's stale-removal set exceeded both guard thresholds. Confirm the config was not
truncated or corrupted. If the removals are legitimate, stage them across several runs so each
run stays under the limit, or perform the bulk change manually.

**The job failed on auth or token.**
Confirm the Managed Identity is attached and the Client ID is correct, that both Graph
permissions are granted with admin consent, and that the pinned `Az.Accounts` version still
returns a usable token. The runbook already handles both plaintext and `SecureString` tokens.

**Duplicate-device WARNs in the log.**
Entra accumulates duplicate device objects as machines re-enrol. The runbook syncs all IDs for
an identical display name so the live object is always covered. Clean up the stale duplicates in
Entra to keep the summary tidy.

**Previewing a change.**
Set `WhatIf = $true` in source and run. Every add and remove is logged with a `[WHATIF]` prefix,
nothing is written, and the blast-radius guard is bypassed.
