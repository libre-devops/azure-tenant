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

    Groups with an empty devices array are skipped with WARN — not counted as errors.
    This allows partial rollout (some groups configured, others not yet) without
    failing the job and triggering the Azure Monitor alert.

    Pending and skipped counts never cause the job to fail. Only API errors throw at end.

    LOGGING
    ───────
    Write-Verbose : INFO/DEBUG — visible in All Logs tab when log_verbose = true.
                    Safe inside functions that return values (does not enter pipeline).
    Write-Warning : WARN — visible in Warnings tab and All Logs.
    Write-Host    : ERROR lines and summary report only. Information stream, safe.
    Write-Output  : NEVER used — enters the pipeline and corrupts function return values.

.PARAMETER ManagedIdentityClientId
    Client ID of the User-Assigned Managed Identity attached to this Automation Account.

.PARAMETER AutomationVariableNames
    Intentionally untyped. Azure Automation passes job schedule parameters as strings,
    so this arrives as System.String regardless of how the parameter is declared.
    NormalizeVariableNames splits and cleans it inside MAIN.

.PARAMETER DefaultRemoveStale
    Global fallback for removeStale when not specified per group. Default: $true.
    Do NOT pass from job schedule — [bool] binding from string is unreliable in
    Azure Automation. Change the default here if needed.

.PARAMETER MaxRetries / RetryDelaySeconds
    Retry configuration for transient API failures.

.PARAMETER WhatIf
    If $true, no writes to any group. Do NOT pass from job schedule (same [bool] reason).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    JSON CONFIG SCHEMA  (one object per Automation Variable)
    ─────────────────────────────────────────────────────────────────────────────

    {
      "groupId":     "853451d5-e186-4362-9337-6f8ce967570a",  // required
      "name":        "Linux Prod EDR",                         // optional
      "removeStale": true,                                     // optional (overrides DefaultRemoveStale)
      "devices": [                                             // required for sync; empty = skip with WARN
        "server01.contoso.local",
        "server02"
      ]
    }

    ─────────────────────────────────────────────────────────────────────────────
    REQUIRED MANAGED IDENTITY — API PERMISSIONS
    ─────────────────────────────────────────────────────────────────────────────

    ┌─────────────────────────┬──────────────────────────────┬──────────────────────────────────┐
    │ API                     │ Permission                   │ Purpose                          │
    ├─────────────────────────┼──────────────────────────────┼──────────────────────────────────┤
    │ Microsoft Graph         │ Device.Read.All              │ Fetch all Entra device objects   │
    │ (graph.microsoft.com)   │ GroupMember.ReadWrite.All    │ Read, add and remove members     │
    └─────────────────────────┴──────────────────────────────┴──────────────────────────────────┘
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

# Intentionally untyped — arrives as System.String from job schedule.
# NormalizeVariableNames handles splitting inside MAIN.
    [Parameter(Mandatory)]
    $AutomationVariableNames,

# Do NOT pass these from the job schedule — [bool] from string is unreliable.
    [bool] $DefaultRemoveStale = $true,
    [bool] $WhatIf = $false,

    [int] $MaxRetries = 6,
    [int] $RetryDelaySeconds = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SyncErrorCount = 0
$script:PendingCount = 0

# ============================================================
#  LOGGER
#  Write-Verbose for INFO/DEBUG — safe inside returning functions.
#  Write-Host for ERROR/summary — Information stream, also safe.
#  Write-Output is NEVER used — it corrupts function return values.
# ============================================================

function Log-Message
{
    param (
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string] $Level,
        [string] $Message,
        [string] $InvocationName
    )

    $ts = Get-Date -Format 'HH:mm:ss'
    $prefix = "$ts [$InvocationName]"

    switch ($Level)
    {
        'DEBUG' {
            Write-Verbose "$prefix $Message"
        }                          # All Logs only — low-level detail
        'INFO'  {
            Write-Verbose   "$prefix $Message"
        }  # Always visible — operational steps
        'WARN'  {
            Write-Warning "$prefix $Message"
        }                          # Warnings tab + All Logs
        'ERROR' {
            Write-Error   "$prefix $Message"
        }  # Always visible — failures
    }
}

# ============================================================
#  UTILS
# ============================================================

function NormalizeVariableNames
{
    <#
    .SYNOPSIS
        Splits, trims, and dedupes the AutomationVariableNames input.
        Called inside MAIN's try block — never at script scope — so any
        failure is caught and logged before propagating.
    #>
    param ($Names)

    Log-Message -Level DEBUG `
        -Message "Raw input type: $( $Names.GetType().FullName ) | value: $Names" `
        -InvocationName $MyInvocation.MyCommand.Name

    # Azure Automation passes all job schedule params as strings.
    # Arrives as either a plain [string] or a single-element array wrapping it.
    if ($Names -is [string])
    {
        $Names = $Names.Split(',')
    }
    elseif ($Names.Count -eq 1 -and $Names[0] -match ',')
    {
        $Names = $Names[0].Split(',')
    }

    $Names = @(
    $Names |
            ForEach-Object { $_.Trim() } |
            Where-Object   { $_ -ne '' } |
            Sort-Object    -Unique
    )

    if ($Names.Count -eq 0)
    {
        throw 'No valid Automation Variable names after normalisation. Check the job schedule parameter.'
    }

    Log-Message -Level INFO `
        -Message "Normalised $( $Names.Count ) variable name(s): $( $Names -join ', ' )" `
        -InvocationName $MyInvocation.MyCommand.Name

    return $Names
}

function Sanitize-InputString
{
    param (
        [Parameter(Mandatory)]
        [string] $Value
    )

    if (-not $Value) { return $Value }

    $original = $Value

    # Trim whitespace first
    $Value = $Value.Trim()

    # Remove escaped quotes first (\" → ")
    $Value = $Value -replace '\\\"', '"'

    # Remove wrapping quotes repeatedly (handles ""value"" cases)
    while ($Value.StartsWith('"') -and $Value.EndsWith('"'))
    {
        $Value = $Value.Substring(1, $Value.Length - 2).Trim()
    }

    if ($original -ne $Value)
    {
        Write-Verbose "Sanitized input: '$original' → '$Value'"
    }

    return $Value
}

# ============================================================
#  AUTH
# ============================================================

function Initialize-ManagedIdentityAuth
{
    try
    {
        Log-Message -Level INFO `
                    -Message "Authenticating via User-Assigned Managed Identity (ClientId: $ManagedIdentityClientId)..." `
                    -InvocationName $MyInvocation.MyCommand.Name

        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        try {
            Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -ErrorAction Stop | Out-Null
        }
        catch {
            Log-Message -Level WARN -Message "Falling back to default managed identity resolution." -InvocationName $MyInvocation.MyCommand.Name
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        }


        Log-Message -Level INFO `
                    -Message 'Managed Identity authentication successful.' `
                    -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Authentication FAILED: $( $_.Exception.Message )" `
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
            throw 'Token extraction failed — response contained no token.'
        }

        # [string] cast guards against PS wrapping the token in Object[].
        # Write-Verbose (via Log-Message) is safe here — does not enter pipeline.
        $token = [string]$tokenResponse.Token

        Log-Message -Level DEBUG `
                    -Message "Token acquired (length: $( $token.Length ))" `
                    -InvocationName $MyInvocation.MyCommand.Name

        return $token
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Failed to acquire token for '$Resource': $( $_.Exception.Message )" `
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
            $msg = $_.Exception.Message
            $retryAfter = $null

            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response)
            {
                $retryAfter = $_.Exception.Response.Headers?['Retry-After']
            }
            if ($retryAfter -is [array])
            {
                $retryAfter = $retryAfter[0]
            }

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
    param ([string] $GraphToken)

    $allDevices = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri = "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName&`$top=999"

    do
    {
        $res = Invoke-WithRetry -OperationName 'Fetch all Entra devices' -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            $allDevices.AddRange([pscustomobject[]]$res.value)
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
                -Message "Fetched $( $allDevices.Count ) Entra device object(s) into local index." `
                -InvocationName 'Build-DeviceIndex'

    # ── Exact + short index ──────────────────────────────────
    $deviceIndex = @{}
    $fuzzyList = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($d in $allDevices)
    {
        if (-not $d.displayName) { continue }

        $full  = $d.displayName.ToLower()
        $short = $full.Split('.')[0]

        if (-not $deviceIndex.ContainsKey($full))
        {
            $deviceIndex[$full] = $d.id
        }

        if (-not $deviceIndex.ContainsKey($short))
        {
            $deviceIndex[$short] = $d.id
        }

        $fuzzyList.Add([pscustomobject]@{
            Name  = $full
            Short = $short
            Id    = $d.id
        })
    }

    Log-Message -Level INFO `
                -Message "Built device index ($( $deviceIndex.Count ) entries) and fuzzy list ($( $fuzzyList.Count ) entries)." `
                -InvocationName 'Build-DeviceIndex'

    return $deviceIndex, $fuzzyList.toArray()
}

function Resolve-Device
{
    param (
        [string]    $DeviceName,
        [hashtable] $DeviceIndex,
        [array]     $FuzzyList
    )

    $normalized = $DeviceName.ToLower()
    $short = $normalized.Split('.')[0]

    if ( $DeviceIndex.ContainsKey($normalized))
    {
        Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via exact match → $( $DeviceIndex[$normalized] )" -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $DeviceIndex[$normalized] }
    }

    if ( $DeviceIndex.ContainsKey($short))
    {
        Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via short-name match → $( $DeviceIndex[$short] )" -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $DeviceIndex[$short] }
    }

    $candidates = @($FuzzyList | Where-Object { $_.Short.StartsWith($short) })

    if ($candidates.Count -eq 1)
    {
        Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via fuzzy match → '$( $candidates[0].Name )' ($( $candidates[0].Id ))" -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Id = $candidates[0].Id }
    }

    if ($candidates.Count -gt 1)
    {
        Log-Message -Level WARN -Message "Ambiguous fuzzy match for '$DeviceName' — $( $candidates.Count ) candidates: $( ($candidates | Select-Object -ExpandProperty Name) -join ', ' ). Skipping." -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Ambiguous'; Id = $null }
    }

    Log-Message -Level WARN -Message "Could not resolve '$DeviceName' in Entra ID — pending registration. Will retry next run." -InvocationName 'Resolve-Device'
    return [pscustomobject]@{ Status = 'Pending'; Id = $null }
}

# ============================================================
#  GROUP OPS
# ============================================================

function Add-DeviceToGroup
{
    param ($GroupId, $DeviceId, $Token)

    if ($WhatIf)
    {
        Log-Message -Level INFO -Message "[WHATIF] Would add $DeviceId to group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
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
        Log-Message -Level INFO -Message "Successfully added $DeviceId to group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ($_.Exception.Message -match 'already exist')
        {
            Log-Message -Level DEBUG -Message "Device $DeviceId already a member (race condition — safe to ignore)." -InvocationName $MyInvocation.MyCommand.Name
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
        Log-Message -Level INFO -Message "[WHATIF] Would remove $DeviceId from group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
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
        Log-Message -Level INFO -Message "Successfully removed $DeviceId from group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ($_.Exception.Message -match 'does not exist')
        {
            Log-Message -Level DEBUG -Message "Device $DeviceId already removed (safe to ignore)." -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Get-AllGroupMembers
{
    param (
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $Token
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
                    Id = $m.id
                    DisplayName = if ($m.displayName)
                    {
                        $m.displayName
                    }
                    else
                    {
                        '(unknown)'
                    }
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

    Log-Message -Level INFO -Message "Fetched $( $all.Count ) member(s) for group $GroupId." -InvocationName 'Get-AllGroupMembers'
    return $all.ToArray()
}

# ============================================================
#  SUMMARY REPORT
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
    Write-Host "  $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )" -ForegroundColor Cyan
    Write-Host "  WhatIf Mode : $WhatIf"                     -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan

    foreach ($r in $GroupResults)
    {
        Write-Host ''
        Write-Host "  GROUP : $( $r.Name )"  -ForegroundColor Cyan
        Write-Host "  ID    : $( $r.GroupId )"
        Write-Host "  VAR   : $( $r.SourceVar )"
        Write-Host "  $( '-' * 68 )"

        Write-Host "  ALL CURRENT GROUP MEMBERS ($( $r.FinalMembers.Count ))" -ForegroundColor Yellow
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

        Write-Host ''
        Write-Host "  ADDED THIS RUN ($( $r.Added.Count ))" -ForegroundColor Green
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

        Write-Host ''
        Write-Host "  REMOVED THIS RUN ($( $r.Removed.Count ))" -ForegroundColor Magenta
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

        Write-Host ''
        Write-Host "  PENDING ENTRA REGISTRATION ($( $r.Pending.Count ))" -ForegroundColor Yellow
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

        Write-Host ''
        Write-Host "  SKIPPED — AMBIGUOUS RESOLUTION ($( $r.Skipped.Count ))" -ForegroundColor Yellow
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

        Write-Host "  $( '-' * 68 )"
    }

    Write-Host ''
    Write-Host "  TOTAL API ERRORS : $TotalErrors" -ForegroundColor $( if ($TotalErrors -gt 0)
    {
        'Red'
    }
    else
    {
        'DarkGray'
    } )
    Write-Host ''
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ''
}

# ============================================================
#  MAIN
#
#  Everything runs inside a single top-level try/catch.
#  Nothing executes at script scope outside function definitions — that pattern
#  causes unhandled exceptions before any logging is active, producing the
#  "job failed, no output" symptom seen previously.
# ============================================================

try
{
    # ── Normalise variable names ──────────────────────────────────────────────
    # Called here (inside try) not at script scope. If it throws, the catch
    # below writes the exception to Write-Host before re-throwing.
    $ManagedIdentityClientId = Sanitize-InputString -Value $ManagedIdentityClientId
    $AutomationVariableNames = Sanitize-InputString -Value $AutomationVariableNames
    $AutomationVariableNames = NormalizeVariableNames -Names $AutomationVariableNames

    Log-Message -Level INFO `
                -Message "========== Sync started | Variables: '$( $AutomationVariableNames -join "', '" )' | DefaultRemoveStale: $DefaultRemoveStale | WhatIf: $WhatIf ==========" `
                -InvocationName 'MAIN'

    # ── Auth ──────────────────────────────────────────────────────────────────

    Initialize-ManagedIdentityAuth
    $graphToken = Get-AccessToken -Resource 'https://graph.microsoft.com'

    # ── Load and validate group configs ──────────────────────────────────────

    $groupConfigs = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($varName in $AutomationVariableNames)
    {
        try
        {
            Log-Message -Level INFO -Message "Loading config from Automation Variable: '$varName'" -InvocationName 'MAIN'

            $raw = Get-AutomationVariable -Name $varName

            if (-not $raw)
            {
                Log-Message -Level ERROR -Message "Variable '$varName' is null or empty." -InvocationName 'MAIN'
                $script:SyncErrorCount++
                continue
            }

            $cfg = $raw | ConvertFrom-Json

            if (-not $cfg.groupId)
            {
                Log-Message -Level ERROR -Message "Variable '$varName' is missing required field 'groupId'." -InvocationName 'MAIN'
                $script:SyncErrorCount++
                continue
            }

            # Empty devices array = group not yet configured. Skip with WARN — not an error.
            # This allows partial rollout without failing the job and firing the monitor alert.
            if (-not $cfg.devices -or @($cfg.devices).Count -eq 0)
            {
                Log-Message -Level WARN -Message "Variable '$varName' has no devices configured — skipping group '$( $cfg.name ?? $cfg.groupId )'. Add devices to the JSON to enable sync." -InvocationName 'MAIN'
                continue
            }

            $removeStale = if ($null -ne $cfg.PSObject.Properties['removeStale'])
            {
                [bool]$cfg.removeStale
            }
            else
            {
                $DefaultRemoveStale
            }
            $displayName = if ($cfg.name)
            {
                $cfg.name
            }
            else
            {
                $cfg.groupId
            }

            $groupConfigs.Add([pscustomobject]@{
                GroupId = $cfg.groupId
                Name = $displayName
                Devices = [string[]]$cfg.devices
                RemoveStale = $removeStale
                SourceVar = $varName
            })

            Log-Message -Level INFO -Message "Loaded group '$displayName' from '$varName' ($( $cfg.devices.Count ) device(s), removeStale=$removeStale)." -InvocationName 'MAIN'
        }
        catch
        {
            Log-Message -Level ERROR -Message "Failed to load/parse variable '$varName': $( $_.Exception.Message )" -InvocationName 'MAIN'
            $script:SyncErrorCount++
        }
    }

    # No configured groups is only fatal if there were also parse errors.
    # If all groups simply have empty devices arrays, complete cleanly.
    if ($groupConfigs.Count -eq 0 -and $script:SyncErrorCount -eq 0)
    {
        Log-Message -Level WARN -Message 'No groups have devices configured yet. Nothing to sync.' -InvocationName 'MAIN'
        Write-SyncSummary -GroupResults @() -TotalErrors 0
        exit 0
    }

    if ($groupConfigs.Count -eq 0 -and $script:SyncErrorCount -gt 0)
    {
        throw "No valid group configs could be loaded. Total parse errors: $script:SyncErrorCount"
    }

    Log-Message -Level INFO `
                -Message "Loaded $( $groupConfigs.Count ) group(s) with devices. $( $AutomationVariableNames.Count - $groupConfigs.Count ) skipped (empty or errored)." `
                -InvocationName 'MAIN'

    # ── Build Entra device index (single Graph call) ──────────────────────────

    $deviceIndex, $fuzzyList = Build-DeviceIndex -GraphToken $graphToken

    # ── Process each group ────────────────────────────────────────────────────

    $groupResults = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($groupCfg in $groupConfigs)
    {
        $groupId = $groupCfg.GroupId
        $groupName = $groupCfg.Name
        $removeStale = $groupCfg.RemoveStale

        Log-Message -Level INFO `
                    -Message "--- Processing group '$groupName' ($groupId) | devices: $( $groupCfg.Devices.Count ) | removeStale: $removeStale ---" `
                    -InvocationName 'MAIN'

        $addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $pendingDevices = [System.Collections.Generic.List[string]]::new()
        $skippedDevices = [System.Collections.Generic.List[string]]::new()

        $currentMembers = Get-AllGroupMembers -GroupId $groupId -Token $graphToken
        $currentIds = @($currentMembers | Select-Object -ExpandProperty Id)

        $resolvedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($deviceName in $groupCfg.Devices)
        {
            $result = Resolve-Device -DeviceName $deviceName -DeviceIndex $deviceIndex -FuzzyList $fuzzyList

            switch ($result.Status)
            {
                'Resolved'  {
                    $resolvedDevices.Add([pscustomobject]@{ Id = $result.Id; DisplayName = $deviceName })
                }
                'Pending'   {
                    $script:PendingCount++;$pendingDevices.Add($deviceName)
                }
                'Ambiguous' {
                    $skippedDevices.Add($deviceName)
                }
            }
        }

        $resolvedIds = @($resolvedDevices | Select-Object -ExpandProperty Id)

        foreach ($device in $resolvedDevices)
        {
            if ($currentIds -notcontains $device.Id)
            {
                try
                {
                    Add-DeviceToGroup -GroupId $groupId -DeviceId $device.Id -Token $graphToken
                    $addedDevices.Add($device)
                    Log-Message -Level INFO -Message "Added '$( $device.DisplayName )' ($( $device.Id )) to '$groupName'." -InvocationName 'MAIN'
                }
                catch
                {
                    $script:SyncErrorCount++
                    Log-Message -Level ERROR -Message "Failed to add '$( $device.DisplayName )' ($( $device.Id )) to '$groupName': $( $_.Exception.Message )" -InvocationName 'MAIN'
                }
            }
            else
            {
                Log-Message -Level DEBUG -Message "'$( $device.DisplayName )' already in '$groupName'. Skipping." -InvocationName 'MAIN'
            }
        }

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
                        Log-Message -Level INFO -Message "Removed stale '$( $member.DisplayName )' ($( $member.Id )) from '$groupName'." -InvocationName 'MAIN'
                    }
                    catch
                    {
                        $script:SyncErrorCount++
                        Log-Message -Level ERROR -Message "Failed to remove '$( $member.DisplayName )' ($( $member.Id )) from '$groupName': $( $_.Exception.Message )" -InvocationName 'MAIN'
                    }
                }
            }
        }

        $finalMembers = Get-AllGroupMembers -GroupId $groupId -Token $graphToken

        Log-Message -Level INFO `
                    -Message "Group '$groupName' complete | Added: $( $addedDevices.Count ) | Removed: $( $removedDevices.Count ) | Pending: $( $pendingDevices.Count ) | Skipped: $( $skippedDevices.Count )" `
                    -InvocationName 'MAIN'

        $groupResults.Add([pscustomobject]@{
            GroupId = $groupId
            Name = $groupName
            SourceVar = $groupCfg.SourceVar
            Added = $addedDevices.ToArray()
            Removed = $removedDevices.ToArray()
            Pending = $pendingDevices.ToArray()
            Skipped = $skippedDevices.ToArray()
            FinalMembers = $finalMembers
        })
    }

    $totalAdded = ($groupResults | ForEach-Object { $_.Added.Count }   | Measure-Object -Sum).Sum
    $totalRemoved = ($groupResults | ForEach-Object { $_.Removed.Count } | Measure-Object -Sum).Sum

    Log-Message -Level INFO `
                -Message "========== Sync complete | Groups: $( $groupResults.Count ) | Added: $totalAdded | Removed: $totalRemoved | Pending: $script:PendingCount | Errors: $script:SyncErrorCount ==========" `
                -InvocationName 'MAIN'

    Write-SyncSummary -GroupResults @($groupResults) -TotalErrors $script:SyncErrorCount

    if ($script:SyncErrorCount -gt 0)
    {
        throw "Sync finished with $script:SyncErrorCount API error(s). Review job output above. ($script:PendingCount device(s) pending Entra registration — these will retry automatically.)"
    }
}
catch
{
    # Top-level catch — Write-Host so the message is always visible in the portal
    # before Azure Automation marks the job Failed and the detail is lost.
    Write-Host "$( Get-Date -Format 'HH:mm:ss' ) [FATAL] $( $_.Exception.Message )" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    throw
}