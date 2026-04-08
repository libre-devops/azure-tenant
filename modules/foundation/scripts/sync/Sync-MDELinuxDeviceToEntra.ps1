#Requires -Version 7.2
<#
.SYNOPSIS
    Azure Automation Runbook — Syncs explicitly-configured devices into Entra ID security
    groups using per-group JSON definitions stored in Azure Automation Variables.

.DESCRIPTION
    Replaces the MDE-tag-based discovery model with an explicit JSON allowlist model.
    Each Automation Variable contains a JSON object defining one group and its member
    devices. The script loads all configs, fetches ALL Entra device objects once into a
    local index, then diffs and syncs each group independently.

    RESOLUTION ORDER (per device name)
    ────────────────────────────────────
    1. Exact displayName match (case-insensitive)         → fast hashtable O(1)
    2. Short-name (pre-dot) match                         → fast hashtable O(1)
    3. Fuzzy startswith match                             → list scan, skipped if ambiguous

    Ambiguous matches (>1 candidate in step 3) are skipped and logged as WARN. They
    appear in the summary under SKIPPED and do NOT increment the error count.

    ERROR PHILOSOPHY
    ────────────────
    $script:SyncErrorCount — genuine API / group operation failures only.
    $script:PendingCount   — devices not found in Entra (expected during propagation).

    Pending and skipped counts never cause the job to fail. Only API errors throw at end.

    LOGGING / RETRY / AUTH
    ──────────────────────
    Identical to the original runbook. Write-Verbose for INFO/DEBUG, Write-Warning for
    WARN, Write-Host for summary sections and ERROR lines only. Write-Output is never
    used — it would corrupt function return values.

.PARAMETER ManagedIdentityClientId
    Client ID of the User-Assigned Managed Identity attached to this Automation Account.

.PARAMETER AutomationVariableNames
    Array of Automation Variable names to load. Each must contain a valid JSON group
    config (see schema below). Variables are processed in order; invalid configs are
    skipped with an error logged.

.PARAMETER DefaultRemoveStale
    Global fallback for removeStale behaviour when not specified per group.
    Default: $true — devices absent from the config are removed from the group.

.PARAMETER MaxRetries
    Maximum retry attempts for transient API failures. Default: 6.

.PARAMETER RetryDelaySeconds
    Fallback retry delay (seconds) when no Retry-After header is present. Default: 20.

.PARAMETER WhatIf
    If $true, no writes are made to any group. All add/remove operations are logged only.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    JSON CONFIG SCHEMA  (one object per Automation Variable)
    ─────────────────────────────────────────────────────────────────────────────

    {
      "groupId":     "853451d5-e186-4362-9337-6f8ce967570a",  // required
      "name":        "Linux Prod EDR",                         // optional  (used for logging)
      "removeStale": true,                                     // optional  (overrides DefaultRemoveStale)
      "devices": [                                             // required  (1+ entries)
        "server01.contoso.local",
        "server02"
      ]
    }

    ─────────────────────────────────────────────────────────────────────────────
    REQUIRED MANAGED IDENTITY — API PERMISSIONS
    ─────────────────────────────────────────────────────────────────────────────

    APPLICATION permissions on the User-Assigned Managed Identity.
    Provisioned via Terraform (azuread_app_role_assignment).

    ┌─────────────────────────┬──────────────────────────────┬──────────────────────────────────┐
    │ API                     │ Permission                   │ Purpose                          │
    ├─────────────────────────┼──────────────────────────────┼──────────────────────────────────┤
    │ Microsoft Graph         │ Device.Read.All              │ Fetch all Entra device objects   │
    │ (graph.microsoft.com)   │ GroupMember.ReadWrite.All    │ Read, add and remove members     │
    └─────────────────────────┴──────────────────────────────┴──────────────────────────────────┘

    NOTE: WindowsDefenderATP / Machine.Read.All is no longer required.
          The MDE dependency has been removed entirely.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

    [Parameter(Mandatory)]
    [string[]] $AutomationVariableNames,

    [bool] $DefaultRemoveStale = $true,

    [int]  $MaxRetries = 6,
    [int]  $RetryDelaySeconds = 20,
    [bool] $WhatIf = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Genuine API / group operation failures — triggers Azure Monitor alert via throw at end.
$script:SyncErrorCount = 0

# Devices not found in Entra ID (propagation window). Does NOT trigger an alert.
$script:PendingCount = 0

# ============================================================
#  LOGGER  (unchanged from original)
# ============================================================

function Log-Message
{
    param (
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string] $Level,
        [string] $Message,
        [string] $InvocationName
    )

    $ts     = Get-Date -Format 'HH:mm:ss'
    $prefix = "$ts [$InvocationName]"

    switch ($Level)
    {
        'DEBUG' { Write-Verbose "$prefix $Message" }
        'INFO'  { Write-Verbose "$prefix $Message" }
        'WARN'  { Write-Warning "$prefix $Message" }
        'ERROR' { Write-Host   "$prefix $Message" -ForegroundColor Red }
    }
}


try
{
    Log-Message -Level DEBUG `
                -Message "Attempting to strip AutomationVariableNames. They currently are: $($AutomationVariableNames -join ', ')" `
                -InvocationName $MyInvocation.MyCommand.Name

    $AutomationVariableNames = $AutomationVariableNames | ForEach-Object {
        if ($_ -and $_ -is [string])
        {
            $_.Trim()
        }
        else
        {
            $_
        }
    }

    Log-Message -Level DEBUG `
                -Message "Stripped AutomationVariableNames, they now are: $($AutomationVariableNames -join ', ')" `
                -InvocationName $MyInvocation.MyCommand.Name
}
catch
{
    Log-Message -Level ERROR `
                -Message "Failed to normalise AutomationVariableNames: $($_.Exception.Message)" `
                -InvocationName $MyInvocation.MyCommand.Name

    throw
}

# ============================================================
#  AUTH  (unchanged from original)
# ============================================================

function Initialize-ManagedIdentityAuth
{
    try
    {
        Log-Message -Level INFO `
                    -Message "Authenticating via User-Assigned Managed Identity (ClientId: $ManagedIdentityClientId)..." `
                    -InvocationName $MyInvocation.MyCommand.Name

        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -ErrorAction Stop | Out-Null

        Log-Message -Level INFO `
                    -Message "Managed Identity authentication successful." `
                    -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Authentication FAILED: $($_.Exception.Message)" `
                    -InvocationName $MyInvocation.MyCommand.Name
        throw
    }
}

function Get-AccessToken
{
    param (
        [Parameter(Mandatory)]
        [string] $Resource
    )

    try
    {
        Log-Message -Level INFO `
                    -Message "Requesting token for: $Resource" `
                    -InvocationName $MyInvocation.MyCommand.Name

        $tokenResponse = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop

        if (-not $tokenResponse.Token)
        {
            throw "Token extraction failed — response contained no token."
        }

        $token = [string]$tokenResponse.Token

        Log-Message -Level DEBUG `
                    -Message "Token acquired (type: $($tokenResponse.Token.GetType().Name), length: $($token.Length))" `
                    -InvocationName $MyInvocation.MyCommand.Name

        return $token
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Failed to acquire token for '$Resource': $($_.Exception.Message)" `
                    -InvocationName $MyInvocation.MyCommand.Name
        throw
    }
}

# ============================================================
#  RETRY
# ============================================================

function Invoke-WithRetry
{
    param (
        [scriptblock] $ScriptBlock,
        [string]      $OperationName = 'Operation'
    )

    for ($i = 1; $i -le $MaxRetries; $i++)
    {
        try
        {
            return & $ScriptBlock
        }
        catch
        {
            $msg        = $_.Exception.Message
            $retryAfter = $null

            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response)
            {
                $retryAfter = $_.Exception.Response.Headers?['Retry-After']
            }
            if ($retryAfter -is [array]) { $retryAfter = $retryAfter[0] }

            $delay = if ($retryAfter -and ($retryAfter -as [int]))
            {
                [int]$retryAfter
            }
            else
            {
                $RetryDelaySeconds
            }

            if ($i -eq $MaxRetries)
            {
                Log-Message -Level ERROR `
                            -Message "FAILED after $MaxRetries attempts: $OperationName | $msg" `
                            -InvocationName $MyInvocation.MyCommand.Name
                throw
            }

            Log-Message -Level WARN `
                        -Message "Retry $i/$MaxRetries for '$OperationName' | waiting ${delay}s | $msg" `
                        -InvocationName $MyInvocation.MyCommand.Name
            Start-Sleep -Seconds $delay
        }
    }
}

# ============================================================
#  DEVICE INDEX
# ============================================================

function Build-DeviceIndex
{
    <#
    .SYNOPSIS
        Fetches ALL Entra ID device objects in a single paginated call and builds two
        lookup structures used by Resolve-Device:

        $DeviceIndex  — hashtable : lowercased displayName (exact + short) → Object ID
        $FuzzyList    — array     : PSCustomObjects for startswith fallback

        Replaces O(n) per-device Graph calls with a single bulk fetch.
        Handles pagination transparently via @odata.nextLink.
    #>
    param ([string] $GraphToken)

    $allDevices = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri        = "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName&`$top=999"

    do
    {
        $res = Invoke-WithRetry -OperationName 'Fetch all Entra devices' -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value) { $allDevices.AddRange([pscustomobject[]]$res.value) }

        $uri = if ($res.PSObject.Properties.Name -contains '@odata.nextLink')
        {
            $res.'@odata.nextLink'
        }
        else
        {
            $null
        }
    }
    while ($uri)

    Log-Message -Level INFO `
                -Message "Fetched $($allDevices.Count) Entra device object(s) into local index." `
                -InvocationName 'Build-DeviceIndex'

    $deviceIndex = @{}
    $fuzzyList   = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($d in $allDevices)
    {
        if (-not $d.displayName) { continue }

        $full  = $d.displayName.ToLower()
        $short = $full.Split('.')[0]

        # First-write-wins for duplicate names — consistent with original fallback behaviour.
        if (-not $deviceIndex.ContainsKey($full))  { $deviceIndex[$full]  = $d.id }
        if (-not $deviceIndex.ContainsKey($short)) { $deviceIndex[$short] = $d.id }

        $fuzzyList.Add([pscustomobject]@{
            Name  = $full
            Short = $short
            Id    = $d.id
        })
    }

    # Return both structures; caller unpacks with: $deviceIndex, $fuzzyList = Build-DeviceIndex ...
    return $deviceIndex, $fuzzyList.ToArray()
}

function Resolve-Device
{
    <#
    .SYNOPSIS
        Resolves a device name to an Entra Object ID using the pre-built index.

        Returns a typed PSCustomObject so callers can distinguish between:
            Resolved  — Id populated, device found
            Pending   — Id is $null, device not found anywhere (propagation window)
            Ambiguous — Id is $null, fuzzy match returned multiple candidates (skipped)

        This avoids conflating two distinct non-error states into a bare $null return.
    #>
    param (
        [string]    $DeviceName,
        [hashtable] $DeviceIndex,
        [array]     $FuzzyList
    )

    $normalized = $DeviceName.ToLower()
    $short      = $normalized.Split('.')[0]

    # 1. Exact displayName match (covers both FQDN and short name in one lookup)
    if ($DeviceIndex.ContainsKey($normalized))
    {
        Log-Message -Level DEBUG `
                    -Message "Resolved '$DeviceName' via exact match → $($DeviceIndex[$normalized])" `
                    -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $DeviceIndex[$normalized] }
    }

    if ($DeviceIndex.ContainsKey($short))
    {
        Log-Message -Level DEBUG `
                    -Message "Resolved '$DeviceName' via short-name match → $($DeviceIndex[$short])" `
                    -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $DeviceIndex[$short] }
    }

    # 2. Fuzzy startswith match — fallback only, skipped when ambiguous
    $candidates = @($FuzzyList | Where-Object { $_.Short.StartsWith($short) })

    if ($candidates.Count -eq 1)
    {
        Log-Message -Level DEBUG `
                    -Message "Resolved '$DeviceName' via fuzzy match → '$($candidates[0].Name)' ($($candidates[0].Id))" `
                    -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $candidates[0].Id }
    }

    if ($candidates.Count -gt 1)
    {
        $names = $candidates | Select-Object -ExpandProperty Name
        Log-Message -Level WARN `
                    -Message "Ambiguous fuzzy match for '$DeviceName' — $($candidates.Count) candidates: $($names -join ', '). Skipping to avoid incorrect assignment." `
                    -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Ambiguous'; Id = $null }
    }

    # Not found by any strategy
    Log-Message -Level WARN `
                -Message "Could not resolve '$DeviceName' in Entra ID — likely pending synthetic registration. Will retry next run." `
                -InvocationName 'Resolve-Device'
    return [pscustomobject]@{ Status = 'Pending'; Id = $null }
}

# ============================================================
#  GROUP OPS  (unchanged signatures from original)
# ============================================================

function Add-DeviceToGroup
{
    param ($GroupId, $DeviceId, $Token)

    if ($WhatIf)
    {
        Log-Message -Level INFO `
                    -Message "[WHATIF] Would add $DeviceId to group $GroupId." `
                    -InvocationName $MyInvocation.MyCommand.Name
        return
    }

    try
    {
        Invoke-WithRetry -OperationName "Add device ($DeviceId)" -ScriptBlock {
            Invoke-RestMethod `
                -Method  POST `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref" `
                -Headers @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' } `
                -Body    (@{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceId" } | ConvertTo-Json)
        }

        Log-Message -Level INFO `
                    -Message "Successfully added $DeviceId to group $GroupId." `
                    -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ($_.Exception.Message -match 'already exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already a member (race condition — safe to ignore)." `
                        -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Remove-DeviceFromGroup
{
    param ($GroupId, $DeviceId, $Token)

    if ($WhatIf)
    {
        Log-Message -Level INFO `
                    -Message "[WHATIF] Would remove $DeviceId from group $GroupId." `
                    -InvocationName $MyInvocation.MyCommand.Name
        return
    }

    try
    {
        Invoke-WithRetry -OperationName "Remove device ($DeviceId)" -ScriptBlock {
            Invoke-RestMethod `
                -Method  DELETE `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$DeviceId/`$ref" `
                -Headers @{ Authorization = "Bearer $Token" }
        }

        Log-Message -Level INFO `
                    -Message "Successfully removed $DeviceId from group $GroupId." `
                    -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ($_.Exception.Message -match 'does not exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already removed (safe to ignore)." `
                        -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Get-AllGroupMembers
{
    param (
        [Parameter(Mandatory)]
        [string] $GroupId,

        [Parameter(Mandatory)]
        [string] $Token
    )

    $all = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,displayName&`$top=999"

    do
    {
        $res = Invoke-WithRetry -OperationName "Get members ($GroupId)" -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $Token" }
        }

        if ($res.value)
        {
            foreach ($m in $res.value)
            {
                $all.Add([pscustomobject]@{
                    Id          = $m.id
                    DisplayName = if ($m.displayName) { $m.displayName } else { '(unknown)' }
                })
            }
        }

        $uri = if ($res.PSObject.Properties.Name -contains '@odata.nextLink')
        {
            $res.'@odata.nextLink'
        }
        else
        {
            $null
        }
    }
    while ($uri)

    Log-Message -Level INFO `
        -Message "Fetched $($all.Count) member(s) for group $GroupId." `
        -InvocationName 'Get-AllGroupMembers'

    return $all.ToArray()
}

# ============================================================
#  SUMMARY REPORT  (per-group aware)
# ============================================================

function Write-SyncSummary
{
    param (
        [object[]] $GroupResults,
        [int]      $TotalErrors
    )

    $sep = '=' * 72

    Write-Host ''
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host '  SYNC SUMMARY REPORT'                       -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "  WhatIf Mode : $WhatIf"                     -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan

    foreach ($r in $GroupResults)
    {
        Write-Host ''
        Write-Host "  GROUP : $($r.Name)"                    -ForegroundColor Cyan
        Write-Host "  ID    : $($r.GroupId)"
        Write-Host "  VAR   : $($r.SourceVar)"
        Write-Host "  $('-' * 68)"

        # ── Current members ──────────────────────────────────────────────────
        Write-Host "  ALL CURRENT GROUP MEMBERS ($($r.FinalMembers.Count))" -ForegroundColor Yellow
        if ($r.FinalMembers.Count -eq 0)
        {
            Write-Host '    (none)' -ForegroundColor DarkGray
        }
        else
        {
            foreach ($m in ($r.FinalMembers | Sort-Object DisplayName))
            {
                Write-Host ("    {0,-45} {1}" -f $m.DisplayName, $m.Id)
            }
        }

        # ── Added ─────────────────────────────────────────────────────────────
        Write-Host ''
        Write-Host "  ADDED THIS RUN ($($r.Added.Count))" -ForegroundColor Green
        if ($r.Added.Count -eq 0)
        {
            Write-Host '    (none — all resolved devices were already members)' -ForegroundColor DarkGray
        }
        else
        {
            foreach ($d in $r.Added)
            {
                Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Green
            }
        }

        # ── Removed ───────────────────────────────────────────────────────────
        Write-Host ''
        Write-Host "  REMOVED THIS RUN ($($r.Removed.Count))" -ForegroundColor Magenta
        if ($r.Removed.Count -eq 0)
        {
            Write-Host '    (none)' -ForegroundColor DarkGray
        }
        else
        {
            foreach ($d in $r.Removed)
            {
                Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Magenta
            }
        }

        # ── Pending (propagation window — not an error) ───────────────────────
        Write-Host ''
        Write-Host "  PENDING ENTRA REGISTRATION ($($r.Pending.Count))" -ForegroundColor Yellow
        if ($r.Pending.Count -eq 0)
        {
            Write-Host '    (none)' -ForegroundColor DarkGray
        }
        else
        {
            Write-Host '    Not yet visible in Entra ID. Will be added on next successful run.' -ForegroundColor DarkGray
            foreach ($name in $r.Pending)
            {
                Write-Host "    $name" -ForegroundColor Yellow
            }
        }

        # ── Skipped / ambiguous (resolution safety guard — not an error) ──────
        Write-Host ''
        Write-Host "  SKIPPED — AMBIGUOUS RESOLUTION ($($r.Skipped.Count))" -ForegroundColor Yellow
        if ($r.Skipped.Count -eq 0)
        {
            Write-Host '    (none)' -ForegroundColor DarkGray
        }
        else
        {
            Write-Host '    Fuzzy match returned multiple candidates. Correct the device name in config.' -ForegroundColor DarkGray
            foreach ($name in $r.Skipped)
            {
                Write-Host "    $name" -ForegroundColor Yellow
            }
        }

        Write-Host "  $('-' * 68)"
    }

    Write-Host ''
    Write-Host "  TOTAL API ERRORS : $TotalErrors" `
        -ForegroundColor $(if ($TotalErrors -gt 0) { 'Red' } else { 'DarkGray' })
    Write-Host ''
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ''
}

# ============================================================
#  MAIN
# ============================================================

Log-Message -Level INFO `
            -Message "========== Sync started | Variables: '$($AutomationVariableNames -join "', '")' | DefaultRemoveStale: $DefaultRemoveStale | WhatIf: $WhatIf ==========" `
            -InvocationName 'MAIN'

# ── Auth ─────────────────────────────────────────────────────────────────────

Initialize-ManagedIdentityAuth
$graphToken = Get-AccessToken -Resource 'https://graph.microsoft.com'

# ── Load and validate group configs ──────────────────────────────────────────

$groupConfigs = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($varName in $AutomationVariableNames)
{
    try
    {
        Log-Message -Level INFO `
                    -Message "Loading config from Automation Variable: '$varName'" `
                    -InvocationName 'MAIN'

        $raw = Get-AutomationVariable -Name $varName

        if (-not $raw)
        {
            Log-Message -Level ERROR `
                        -Message "Variable '$varName' is null or empty." `
                        -InvocationName 'MAIN'
            $script:SyncErrorCount++
            continue
        }

        $cfg = $raw | ConvertFrom-Json

        if (-not $cfg.groupId)
        {
            Log-Message -Level ERROR `
                        -Message "Variable '$varName' is missing required field 'groupId'." `
                        -InvocationName 'MAIN'
            $script:SyncErrorCount++
            continue
        }

        if (-not $cfg.devices -or @($cfg.devices).Count -eq 0)
        {
            Log-Message -Level ERROR `
                        -Message "Variable '$varName' is missing required field 'devices' (or is an empty array)." `
                        -InvocationName 'MAIN'
            $script:SyncErrorCount++
            continue
        }

        # Per-group removeStale overrides the global default; absence means use default.
        $removeStale = if ($null -ne $cfg.PSObject.Properties['removeStale'])
        {
            [bool]$cfg.removeStale
        }
        else
        {
            $DefaultRemoveStale
        }

        $displayName = if ($cfg.name) { $cfg.name } else { $cfg.groupId }

        $groupConfigs.Add([pscustomobject]@{
            GroupId     = $cfg.groupId
            Name        = $displayName
            Devices     = [string[]]$cfg.devices
            RemoveStale = $removeStale
            SourceVar   = $varName
        })

        Log-Message -Level INFO `
                    -Message "Loaded group '$displayName' from '$varName' ($($cfg.devices.Count) device(s), removeStale=$removeStale)." `
                    -InvocationName 'MAIN'
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Failed to load/parse variable '$varName': $($_.Exception.Message)" `
                    -InvocationName 'MAIN'
        $script:SyncErrorCount++
    }
}

if ($groupConfigs.Count -eq 0)
{
    throw "No valid group configs could be loaded. Check Automation Variables. Total parse errors: $script:SyncErrorCount"
}

Log-Message -Level INFO `
            -Message "Loaded $($groupConfigs.Count) valid group config(s). $($AutomationVariableNames.Count - $groupConfigs.Count) skipped due to errors." `
            -InvocationName 'MAIN'

# ── Build Entra device index (single Graph call, replaces per-device lookups) ─

$deviceIndex, $fuzzyList = Build-DeviceIndex -GraphToken $graphToken

# ── Process each group ────────────────────────────────────────────────────────

$groupResults = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($groupCfg in $groupConfigs)
{
    $groupId     = $groupCfg.GroupId
    $groupName   = $groupCfg.Name
    $removeStale = $groupCfg.RemoveStale

    Log-Message -Level INFO `
                -Message "--- Processing group '$groupName' ($groupId) | configuredDevices: $($groupCfg.Devices.Count) | removeStale: $removeStale ---" `
                -InvocationName 'MAIN'

    $addedDevices   = [System.Collections.Generic.List[pscustomobject]]::new()
    $removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
    $pendingDevices = [System.Collections.Generic.List[string]]::new()
    $skippedDevices = [System.Collections.Generic.List[string]]::new()

    # ── Get current group members ─────────────────────────────────────────────

    $currentMembers = Get-AllGroupMembers -GroupId $groupId -Token $graphToken
    $currentIds = @($currentMembers | Select-Object -ExpandProperty Id)

    # ── Resolve desired devices via index ─────────────────────────────────────

    $resolvedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($deviceName in $groupCfg.Devices)
    {
        $result = Resolve-Device `
            -DeviceName   $deviceName `
            -DeviceIndex  $deviceIndex `
            -FuzzyList    $fuzzyList

        switch ($result.Status)
        {
            'Resolved'
            {
                $resolvedDevices.Add([pscustomobject]@{
                    Id          = $result.Id
                    DisplayName = $deviceName
                })
            }
            'Pending'
            {
                $script:PendingCount++
                $pendingDevices.Add($deviceName)
                Log-Message -Level WARN `
                            -Message "'$deviceName' not yet in Entra — pending registration. Will retry next run." `
                            -InvocationName 'MAIN'
            }
            'Ambiguous'
            {
                # Ambiguous is not a pending state — the config name needs fixing.
                # Tracked separately so it's visible in the summary without inflating errors.
                $skippedDevices.Add($deviceName)
                Log-Message -Level WARN `
                            -Message "'$deviceName' skipped — ambiguous fuzzy match. Correct the name in '$($groupCfg.SourceVar)'." `
                            -InvocationName 'MAIN'
            }
        }
    }

    $resolvedIds = @($resolvedDevices | Select-Object -ExpandProperty Id)

    # ── Add missing devices ───────────────────────────────────────────────────

    foreach ($device in $resolvedDevices)
    {
        if ($currentIds -notcontains $device.Id)
        {
            try
            {
                Add-DeviceToGroup -GroupId $groupId -DeviceId $device.Id -Token $graphToken
                $addedDevices.Add($device)
                Log-Message -Level INFO `
                            -Message "Added '$($device.DisplayName)' ($($device.Id)) to '$groupName'." `
                            -InvocationName 'MAIN'
            }
            catch
            {
                $script:SyncErrorCount++
                Log-Message -Level ERROR `
                            -Message "Failed to add '$($device.DisplayName)' ($($device.Id)) to '$groupName': $($_.Exception.Message)" `
                            -InvocationName 'MAIN'
            }
        }
        else
        {
            Log-Message -Level DEBUG `
                        -Message "'$($device.DisplayName)' already in '$groupName'. Skipping." `
                        -InvocationName 'MAIN'
        }
    }

    # ── Remove stale members ──────────────────────────────────────────────────
    # A member is stale if it is in the group but not in $resolvedIds.
    # Only runs when removeStale is enabled for this group.
    # Note: pending and ambiguous devices are NOT in $resolvedIds — they are intentionally
    # excluded from the desired state and will not trigger removal of existing members.
    # This is the safe default. If you want stale removal to be definitive, ensure all
    # devices in the config are resolvable before enabling removeStale.

    if ($removeStale)
    {
        foreach ($member in $currentMembers)
        {
            if ($resolvedIds -notcontains $member.Id)
            {
                try
                {
                    Remove-DeviceFromGroup -GroupId $groupId -DeviceId $member.Id -Token $graphToken
                    $removedDevices.Add($member)
                    Log-Message -Level INFO `
                                -Message "Removed stale '$($member.DisplayName)' ($($member.Id)) from '$groupName'." `
                                -InvocationName 'MAIN'
                }
                catch
                {
                    $script:SyncErrorCount++
                    Log-Message -Level ERROR `
                                -Message "Failed to remove '$($member.DisplayName)' ($($member.Id)) from '$groupName': $($_.Exception.Message)" `
                                -InvocationName 'MAIN'
                }
            }
        }
    }

    # ── Final member list (post-change) ──────────────────────────────────────

    $finalMembers = Get-AllGroupMembers -GroupId $groupId -Token $graphToken

    Log-Message -Level INFO `
            -Message "Group '$groupName' complete | Added: $($addedDevices.Count) | Removed: $($removedDevices.Count) | Pending: $($pendingDevices.Count) | Skipped: $($skippedDevices.Count)" `
            -InvocationName 'MAIN'

    $groupResults.Add([pscustomobject]@{
        GroupId      = $groupId
        Name         = $groupName
        SourceVar    = $groupCfg.SourceVar
        Added        = $addedDevices.ToArray()
        Removed      = $removedDevices.ToArray()
        Pending      = $pendingDevices.ToArray()
        Skipped      = $skippedDevices.ToArray()
        FinalMembers = $finalMembers
    })
}

# ── Overall summary ───────────────────────────────────────────────────────────

$totalAdded   = ($groupResults | ForEach-Object { $_.Added.Count }   | Measure-Object -Sum).Sum
$totalRemoved = ($groupResults | ForEach-Object { $_.Removed.Count } | Measure-Object -Sum).Sum

Log-Message -Level INFO `
            -Message "========== Sync complete | Groups: $($groupResults.Count) | Added: $totalAdded | Removed: $totalRemoved | Pending: $script:PendingCount | API Errors: $script:SyncErrorCount ==========" `
            -InvocationName 'MAIN'

Write-SyncSummary `
    -GroupResults @($groupResults) `
    -TotalErrors  $script:SyncErrorCount

# ── Failure alerting ──────────────────────────────────────────────────────────
# Only throw for genuine API errors — increments the Azure Automation Failed Jobs
# metric and triggers Azure Monitor alerting.
# Pending and ambiguous devices produce a Completed job (no alert).

if ($script:SyncErrorCount -gt 0)
{
    throw "Sync finished with $script:SyncErrorCount API error(s). Review job output above. ($script:PendingCount device(s) pending Entra registration — these will retry automatically.)"
}