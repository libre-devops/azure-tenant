# 🔄 MDE → Entra ID Group Sync (Azure Automation Runbook)

## 📦 Overview

This Azure Automation Runbook synchronises **Microsoft Defender for Endpoint (MDE)** Linux devices into an **Entra ID security group** based on device tags.

It is designed to be:

* ✅ **Idempotent**
* 🔁 **Retry-aware (429 / transient failures)**
* 🧠 **Eventual-consistency aware**
* 📊 **Observable with structured logging**
* 🛡️ **Production-safe**

---

## 🎯 What This Solves

MDE and Entra ID are **not strongly consistent systems**.

```text
MDE → Graph → Entra Group
      ↑
   delay / lag
```

This runbook handles that gap safely by:

* Filtering devices in MDE
* Resolving them into Entra device objects
* Adding/removing them from a target group
* **Not failing when devices haven’t propagated yet**

---

## ⚙️ How It Works

### 1. Authenticate (Managed Identity)

* Uses `Connect-AzAccount -Identity`
* Retrieves tokens for:

    * Microsoft Graph
    * MDE API

---

### 2. Query MDE Devices

* Calls:

```http
GET https://api.securitycenter.microsoft.com/api/machines
```

* Filters:

    * OS platform (e.g. RHEL, Ubuntu)
    * Health status (e.g. Active)
    * Tags (client-side, reliable)

---

### 3. Resolve Entra Device IDs

Resolution order:

```text
1. aadDeviceId (fast path)
2. Graph exact match (displayName)
3. Graph fuzzy match (startswith)
4. Soft failure (expected)
```

---

### 4. Sync Group Membership

* Add missing devices
* Optionally remove stale devices

```text
Desired State = MDE devices with tag
Actual State  = Entra group members
```

---

### 5. Output Summary

At the end of every run:

* Current group members
* Devices added
* Devices removed
* Error breakdown

---

## 🧠 Error Model (CRITICAL)

The script distinguishes between **expected vs real failures**.

### 🟡 Soft Errors (Expected)

These **do NOT fail the job**:

* Device not yet in Graph
* DNS mismatch
* Eventual consistency delays

```text
Example:
"Unresolved device (likely eventual consistency)"
```

---

### 🔴 Hard Errors (Real Failures)

These **FAIL the job**:

* Graph API failures
* Permission issues
* Add/remove failures
* Retry exhaustion

---

### 🎯 Final Behaviour

| Scenario                | Result      |
| ----------------------- | ----------- |
| Device not yet in Graph | ✅ Skipped   |
| Device appears next run | ✅ Added     |
| Graph failure           | ❌ Job fails |
| Permission issue        | ❌ Job fails |

---

## 🔧 Parameters

| Name                      | Type     | Description                              |
| ------------------------- | -------- | ---------------------------------------- |
| `ManagedIdentityClientId` | string   | User-assigned managed identity client ID |
| `DeviceTag`               | string[] | MDE tags to filter devices               |
| `EntraGroupObjectId`      | string   | Target Entra ID group                    |
| `RemoveStaleMembers`      | bool     | Remove devices not matching filter       |
| `MaxRetries`              | int      | Retry attempts for API calls             |
| `RetryDelaySeconds`       | int      | Delay between retries                    |
| `WhatIf`                  | bool     | Dry-run mode                             |
| `OsPlatforms`             | string[] | OS filter (server-side)                  |
| `HealthStatus`            | string[] | Health filter                            |

---

## 🔐 Required Permissions

### Microsoft Defender for Endpoint

* `Machine.Read.All`

### Microsoft Graph

* `Device.Read.All`
* `GroupMember.ReadWrite.All`

⚠️ These are **application permissions** assigned to the managed identity.

---

## 📊 Logging Strategy

| Level           | Purpose                    |
| --------------- | -------------------------- |
| INFO            | High-level flow            |
| WARN            | Soft issues / retries      |
| ERROR           | Hard failures              |
| DEBUG (Verbose) | Success + deep diagnostics |

---

### 🧪 Enable Verbose Logs

Set runbook log level to:

```text
Verbose
```

This enables:

* Resolution tracing
* Add/remove success logs
* Debug insight without polluting output

---

## 🔁 Retry Behaviour

* Retries transient failures (429, network issues)
* Honors `Retry-After` when present
* Configurable via:

    * `MaxRetries`
    * `RetryDelaySeconds`

---

## 🧪 Example Run

```text
Sync started
Matched 2 devices
Resolved 2 devices
Added 1 device
Removed 0 devices

Soft Errors: 1
Hard Errors: 0
```

---

## ⚠️ Known Behaviours

### 1. Eventual Consistency

Devices may:

* Exist in MDE
* But not yet in Graph

This is **expected** and handled safely.

---

### 2. Duplicate Devices

Handled via:

* HashSet tracking
* Safe Graph operations

---

### 3. DNS Variants

Handles:

```text
host
host.domain.local
```

---

## 🚀 Usage

Run via Azure Automation with:

* Managed Identity assigned
* Required API permissions granted

---

## 🧱 Design Principles

* Idempotent
* Fail only on real issues
* Retry-aware
* Cloud-consistent (not instant)
* Observable
* Safe by default

---

## 🔮 Future Improvements (v2 Ideas)

* 📦 Cache resolved device IDs (massive performance gain)
* 🗃️ Persist unresolved devices for retry
* ⚡ Parallel resolution
* 📊 Metrics export (Log Analytics / App Insights)

---

## 🧹 Summary

This runbook provides a **reliable bridge** between:

```text
Microsoft Defender for Endpoint → Entra ID Groups
```

Handling:

* API inconsistencies
* Timing gaps
* Real-world cloud behaviour

Without introducing:

* False failures
* Broken automation
* Operational noise
