#Requires -Version 7.2
<#
.SYNOPSIS
    Azure Automation Runbook — Syncs MDE-tagged Linux devices into an Entra ID security group.

.DESCRIPTION
    Authenticates via a User-Assigned Managed Identity using the Az module
    (Connect-AzAccount + Get-AzAccessToken). Queries the MDE Machines API for Linux
    devices carrying a specified tag, and ensures each device's Entra ID object is a
    member of the target security group. Removes stale members if configured to do so.

    At the end of every run a summary is printed showing all current members, what was
    added, what was removed, and the total error count.

    If any non-fatal errors were encountered the job is deliberately failed after the
    summary prints, so the Azure Monitor 'Total Jobs / Failed' metric alert fires.

    Retry behaviour : Up to MaxRetries attempts with 429-aware Retry-After support.
    Logging         : All functions use Log-Message with Write-Host (never Write-Output)
                      to prevent log lines from polluting function return values.
    Auth            : User-Assigned Managed Identity via Az module.

.PARAMETER ManagedIdentityClientId
    Client ID of the User-Assigned Managed Identity attached to this Automation Account.

.PARAMETER DeviceTag
    The MDE machine tag to filter on (e.g. 'linux-mde-onboarded').

.PARAMETER EntraGroupObjectId
    Object ID of the target Entra ID security group.

.PARAMETER RemoveStaleMembers
    If $true, devices currently in the group that no longer carry the tag are removed.
    Defaults to $false (additive-only).

.PARAMETER MaxRetries
    Maximum number of retry attempts for transient API failures. Default: 6.

.PARAMETER RetryDelaySeconds
    Fallback delay (seconds) between retries when no Retry-After header is present.
    Default: 20.

.PARAMETER WhatIf
    If $true, no writes are made to the group. Add/remove operations are logged only.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    REQUIRED MANAGED IDENTITY — API PERMISSIONS
    ─────────────────────────────────────────────────────────────────────────────

    These are APPLICATION permissions assigned to the User-Assigned Managed Identity.
    They cannot be granted via the Azure Portal UI — provisioned via Terraform
    (azuread_app_role_assignment) in the infrastructure layer.

    ┌──────────────────────────────────────────────────┬──────────────────────────────────┬──────────────────────────────────────────────────────┐
    │ API                                              │ Permission                       │ Purpose                                              │
    ├──────────────────────────────────────────────────┼──────────────────────────────────┼──────────────────────────────────────────────────────┤
    │ WindowsDefenderATP                               │ Machine.Read.All                 │ Query MDE Machines API; read machineTags             │
    │ (api.securitycenter.microsoft.com)               │                                  │                                                      │
    ├──────────────────────────────────────────────────┼──────────────────────────────────┼──────────────────────────────────────────────────────┤
    │ Microsoft Graph                                  │ Device.Read.All                  │ Look up Entra device objects by aadDeviceId /        │
    │ (graph.microsoft.com)                            │                                  │ displayName                                          │
    │                                                  │ GroupMember.ReadWrite.All        │ Read, add and remove group members                   │
    └──────────────────────────────────────────────────┴──────────────────────────────────┴──────────────────────────────────────────────────────┘

    ─────────────────────────────────────────────────────────────────────────────
    LOGGER NOTE — Write-Host vs Write-Output
    ─────────────────────────────────────────────────────────────────────────────

    Log-Message uses Write-Host throughout. Write-Output feeds into the PowerShell
    pipeline and would be silently concatenated onto any value a function returns —
    corrupting tokens, IDs, and API results. Write-Host bypasses the output stream
    entirely and is safe to call inside any function that returns a value.
    ─────────────────────────────────────────────────────────────────────────────
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

    [string[]] $DeviceTag = @("RHEL-EDR", "MDE-Management"),

    [string] $EntraGroupObjectId = "853451d5-e186-4362-9337-6f8ce967570a",

    [bool] $RemoveStaleMembers = $false,
    [int]  $MaxRetries = 6,
    [int]  $RetryDelaySeconds = 20,
    [bool] $WhatIf = $false,

    [string[]] $OsPlatforms = @(
    "RedHatEnterpriseLinux",
    "Ubuntu",
    "CentOS"
),

    [string[]] $HealthStatus = @(
    "Active"
)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SoftErrorCount = 0   # Expected (eventual consistency)
$script:HardErrorCount = 0   # Real failures

# ============================================================
# LOGGER
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
        }
        'INFO'  {
            Write-Host    "$prefix $Message" -ForegroundColor Green
        }
        'WARN'  {
            Write-Warning "$prefix $Message"
        }
        'ERROR' {
            Write-Host    "$prefix $Message" -ForegroundColor Red
        }
    }
}

# ============================================================
# AUTH
# ============================================================

function Initialize-ManagedIdentityAuth
{
    try
    {
        Log-Message INFO "Authenticating via User-Assigned Managed Identity..." $MyInvocation.MyCommand.Name

        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        Connect-AzAccount `
            -Identity `
            -AccountId  $ManagedIdentityClientId `
            -ErrorAction Stop | Out-Null

        Log-Message INFO "Managed Identity authentication successful." $MyInvocation.MyCommand.Name
    }
    catch
    {
        Log-Message ERROR "Authentication FAILED: $( $_.Exception.Message )" $MyInvocation.MyCommand.Name
        throw
    }
}

function Get-AccessToken
{
    param ([Parameter(Mandatory)][string] $Resource)

    try
    {
        Log-Message DEBUG "Requesting token for $Resource" $MyInvocation.MyCommand.Name

        $tokenResponse = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop

        if (-not $tokenResponse.Token)
        {
            throw "Token extraction failed"
        }

        return [string]$tokenResponse.Token
    }
    catch
    {
        Log-Message ERROR "Token failure for ${Resource}: $( $_.Exception.Message )" $MyInvocation.MyCommand.Name
        throw
    }
}

# ============================================================
# RETRY
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

            if ($i -eq $MaxRetries)
            {
                Log-Message ERROR "FAILED after $MaxRetries attempts: $OperationName | $msg" $MyInvocation.MyCommand.Name
                throw
            }

            Log-Message WARN "Retry $i/$MaxRetries for '$OperationName'" $MyInvocation.MyCommand.Name
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

# ============================================================
# MDE
# ============================================================

function Get-MdeDevicesByTag
{
    param (
        [string[]] $Tags,
        [string]   $Token,
        [string[]] $OsPlatforms,
        [string[]] $HealthStatus
    )

    Log-Message INFO "Querying MDE (OS + health filtered)" $MyInvocation.MyCommand.Name

    $tagSet = [System.Collections.Generic.HashSet[string]]::new()
    $osSet = [System.Collections.Generic.HashSet[string]]::new()
    $healthSet = [System.Collections.Generic.HashSet[string]]::new()

    $Tags | ForEach-Object { [void]$tagSet.Add($_) }
    $OsPlatforms | ForEach-Object { [void]$osSet.Add($_) }
    $HealthStatus | ForEach-Object { [void]$healthSet.Add($_) }

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $all = [System.Collections.Generic.List[pscustomobject]]::new()

    $uri = "https://api.securitycenter.microsoft.com/api/machines"

    do
    {
        $res = Invoke-WithRetry -OperationName "MDE query" -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $Token" }
        }

        foreach ($device in $res.value)
        {
            if (-not $device.machineTags)
            {
                continue
            }
            if (-not $osSet.Contains($device.osPlatform))
            {
                continue
            }
            if (-not $healthSet.Contains($device.healthStatus))
            {
                continue
            }

            $match = $false
            foreach ($tag in $device.machineTags)
            {
                if ( $tagSet.Contains($tag))
                {
                    $match = $true; break
                }
            }

            if ($match -and $seen.Add($device.id))
            {
                $all.Add($device)
            }
        }

        $uri = $res.'@odata.nextLink'
    }
    while ($uri)

    Log-Message INFO "Matched $( $all.Count ) device(s)" $MyInvocation.MyCommand.Name

    return $all.ToArray()
}

# ============================================================
# RESOLUTION
# ============================================================

function Resolve-EntraDeviceId
{
    param ($Device, $GraphToken)

    $name = $Device.computerDnsName
    $shortName = $name.Split('.')[0]

    # FAST PATH
    if ($Device.aadDeviceId)
    {
        try
        {
            $res = Invoke-WithRetry -OperationName "aadDeviceId lookup ($name)" -ScriptBlock {
                Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$( $Device.aadDeviceId )'&`$select=id" `
                    -Headers @{ Authorization = "Bearer $GraphToken" }
            }

            if ($res.value)
            {
                Write-Verbose "SUCCESS: aadDeviceId resolved $name"
                return $res.value[0].id
            }
        }
        catch
        {
            Log-Message WARN "aadDeviceId lookup failed for '$name'" $MyInvocation.MyCommand.Name
        }
    }

    # EXACT MATCH
    try
    {
        $filter = "displayName eq '$name' or displayName eq '$shortName'"

        $res = Invoke-WithRetry -OperationName "Exact match ($name)" -ScriptBlock {
            Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=$filter&`$select=id,displayName,trustType" `
                -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            Write-Verbose "SUCCESS: exact match resolved $name"
            return $res.value[0].id
        }
    }
    catch
    {
        Log-Message WARN "Exact match failed for '$name'" $MyInvocation.MyCommand.Name
    }

    # FUZZY
    try
    {
        $res = Invoke-WithRetry -OperationName "Fuzzy match ($name)" -ScriptBlock {
            Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=startswith(displayName,'$shortName')" `
                -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            Write-Verbose "SUCCESS: fuzzy match resolved $name"
            return $res.value[0].id
        }
    }
    catch
    {
        Log-Message WARN "Fuzzy match failed for '$name'" $MyInvocation.MyCommand.Name
    }

    $script:SoftErrorCount++
    Log-Message WARN "Unresolved device (likely eventual consistency): '$name'" $MyInvocation.MyCommand.Name

    return $null
}

# ============================================================
# GROUP OPS (UPDATED)
# ============================================================

function Add-DeviceToGroup
{
    param ($GroupId, $DeviceId, $Token)

    if ($WhatIf)
    {
        Log-Message -Level INFO `
                    -Message "[WHATIF] Would add $DeviceId to group $GroupId." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
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

        Write-Verbose "SUCCESS: Added device $DeviceId to group $GroupId"
    }
    catch
    {
        if ($_.Exception.Message -match 'already exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already a member (safe)." `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            return
        }

        # ❌ HARD FAILURE
        $script:HardErrorCount++
        Log-Message -Level ERROR `
                    -Message "Failed to add device $DeviceId : $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }
}

function Remove-DeviceFromGroup
{
    param ($GroupId, $DeviceId, $Token)

    if ($WhatIf)
    {
        Log-Message -Level INFO `
                    -Message "[WHATIF] Would remove $DeviceId from group $GroupId." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
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

        Write-Verbose "SUCCESS: Removed device $DeviceId from group $GroupId"
    }
    catch
    {
        if ($_.Exception.Message -match 'does not exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already removed (safe)." `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            return
        }

        # ❌ HARD FAILURE
        $script:HardErrorCount++
        Log-Message -Level ERROR `
                    -Message "Failed to remove device $DeviceId : $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }
}

# ============================================================
# SUMMARY REPORT
# ============================================================

function Write-SyncSummary
{
    param (
        [string]   $GroupObjectId,
        [string]   $DeviceTag,
        [object[]] $CurrentMembers,
        [object[]] $AddedDevices,
        [object[]] $RemovedDevices,
        [int]      $SoftErrors,
        [int]      $HardErrors
    )

    $sep = '=' * 72

    Write-Host ''
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host '  SYNC SUMMARY REPORT'                       -ForegroundColor Cyan
    Write-Host "  $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )" -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Group Object ID : $GroupObjectId"
    Write-Host "  MDE Device Tag(s): $DeviceTag"
    Write-Host "  WhatIf Mode     : $WhatIf"
    Write-Host ''

    # -------------------------------
    # Current members
    # -------------------------------
    Write-Host "  ALL CURRENT GROUP MEMBERS ($( $CurrentMembers.Count ))" -ForegroundColor Yellow
    Write-Host "  $( '-' * 68 )"

    if ($CurrentMembers.Count -eq 0)
    {
        Write-Host '    (none)' -ForegroundColor DarkGray
    }
    else
    {
        foreach ($m in ($CurrentMembers | Sort-Object DisplayName))
        {
            Write-Host ("    {0,-45} {1}" -f $m.DisplayName, $m.Id)
        }
    }

    # -------------------------------
    # Added
    # -------------------------------
    Write-Host ''
    Write-Host "  ADDED THIS RUN ($( $AddedDevices.Count ))" -ForegroundColor Green
    Write-Host "  $( '-' * 68 )"

    if ($AddedDevices.Count -eq 0)
    {
        Write-Host '    (none — already in desired state)' -ForegroundColor DarkGray
    }
    else
    {
        foreach ($d in $AddedDevices)
        {
            Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Green
        }
    }

    # -------------------------------
    # Removed
    # -------------------------------
    Write-Host ''
    Write-Host "  REMOVED THIS RUN ($( $RemovedDevices.Count ))" -ForegroundColor Magenta
    Write-Host "  $( '-' * 68 )"

    if ($RemovedDevices.Count -eq 0)
    {
        Write-Host '    (none)' -ForegroundColor DarkGray
    }
    else
    {
        foreach ($d in $RemovedDevices)
        {
            Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Magenta
        }
    }

    # -------------------------------
    # Errors (NEW SPLIT)
    # -------------------------------
    Write-Host ''
    Write-Host "  SOFT ERRORS (expected) : $SoftErrors" -ForegroundColor Yellow
    Write-Host "  HARD ERRORS (real)     : $HardErrors" -ForegroundColor $( if ($HardErrors -gt 0)
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
# MAIN
# ============================================================

Log-Message -Level INFO `
    -Message "========== Sync started | Tags: '$( $DeviceTag -join "', '" )' | OS: '$( $OsPlatforms -join "', '" )' | Health: '$( $HealthStatus -join "', '" )' | Group: '$EntraGroupObjectId' | RemoveStale: $RemoveStaleMembers | WhatIf: $WhatIf ==========" `
    -InvocationName 'MAIN'

# Tracking lists
$addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
$removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

# ============================================================
# AUTH
# ============================================================

Initialize-ManagedIdentityAuth

# ============================================================
# TOKENS
# ============================================================

$graphToken = Get-AccessToken -Resource 'https://graph.microsoft.com'
$mdeToken = Get-AccessToken -Resource 'https://api.securitycenter.microsoft.com'

# ============================================================
# MDE DEVICES
# ============================================================

$mdeDevices = Get-MdeDevicesByTag `
    -Tags $DeviceTag `
    -Token $mdeToken `
    -OsPlatforms $OsPlatforms `
    -HealthStatus $HealthStatus

# ============================================================
# EARLY EXIT
# ============================================================

if (@($mdeDevices).Count -eq 0)
{
    Log-Message -Level WARN `
        -Message "MDE returned 0 devices. Nothing to sync." `
        -InvocationName 'MAIN'

    Write-SyncSummary `
        -GroupObjectId  $EntraGroupObjectId `
        -DeviceTag      $DeviceTag `
        -CurrentMembers @() `
        -AddedDevices   @() `
        -RemovedDevices @() `
        -SoftErrors     0 `
        -HardErrors     0

    exit 0
}

# ============================================================
# RESOLVE ENTRA IDs
# ============================================================

$resolved = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($d in $mdeDevices)
{
    $id = Resolve-EntraDeviceId -Device $d -GraphToken $graphToken

    if ($id)
    {
        $resolved.Add([pscustomobject]@{
            Id = $id
            DisplayName = $d.computerDnsName
        })

        Write-Verbose "SUCCESS: Resolved $( $d.computerDnsName )"
    }
    else
    {
        # ❗ NO HARD FAILURE HERE
        # Already counted as SoftError inside resolver
        Write-Verbose "SKIPPED: $( $d.computerDnsName ) (unresolved)"
    }
}

# ============================================================
# CURRENT GROUP MEMBERS
# ============================================================

$currentRaw = Invoke-WithRetry -OperationName 'Get current group members' -ScriptBlock {
    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/groups/$EntraGroupObjectId/members?`$select=id,displayName" `
        -Headers @{ Authorization = "Bearer $graphToken" }
}

$currentMembers = @($currentRaw.value) | ForEach-Object {
    [pscustomobject]@{
        Id = $_.id
        DisplayName = if ($_.displayName)
        {
            $_.displayName
        }
        else
        {
            '(unknown)'
        }
    }
}

$currentIds = @($currentMembers | Select-Object -ExpandProperty Id)

# ============================================================
# ADD DEVICES
# ============================================================

foreach ($device in $resolved)
{
    if ($currentIds -notcontains $device.Id)
    {
        try
        {
            Add-DeviceToGroup -GroupId $EntraGroupObjectId -DeviceId $device.Id -Token $graphToken

            $addedDevices.Add($device)

            Log-Message -Level INFO `
                -Message "Added '$( $device.DisplayName )' ($( $device.Id ))" `
                -InvocationName 'MAIN'
        }
        catch
        {
            $script:HardErrorCount++

            Log-Message -Level ERROR `
                -Message "Failed to add '$( $device.DisplayName )': $( $_.Exception.Message )" `
                -InvocationName 'MAIN'
        }
    }
    else
    {
        Log-Message -Level DEBUG `
            -Message "'$( $device.DisplayName )' already in group" `
            -InvocationName 'MAIN'
    }
}

# ============================================================
# REMOVE STALE
# ============================================================

if ($RemoveStaleMembers)
{
    $resolvedIds = $resolved | Select-Object -ExpandProperty Id

    foreach ($member in $currentMembers)
    {
        if ($resolvedIds -notcontains $member.Id)
        {
            try
            {
                Remove-DeviceFromGroup -GroupId $EntraGroupObjectId -DeviceId $member.Id -Token $graphToken

                $removedDevices.Add($member)

                Log-Message -Level INFO `
                    -Message "Removed stale '$( $member.DisplayName )'" `
                    -InvocationName 'MAIN'
            }
            catch
            {
                $script:HardErrorCount++

                Log-Message -Level ERROR `
                    -Message "Failed to remove '$( $member.DisplayName )': $( $_.Exception.Message )" `
                    -InvocationName 'MAIN'
            }
        }
    }
}

# ============================================================
# FINAL MEMBERS SNAPSHOT
# ============================================================

$finalRaw = Invoke-WithRetry -OperationName 'Get final group members' -ScriptBlock {
    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/groups/$EntraGroupObjectId/members?`$select=id,displayName" `
        -Headers @{ Authorization = "Bearer $graphToken" }
}

$finalMembers = @($finalRaw.value) | ForEach-Object {
    [pscustomobject]@{
        Id = $_.id
        DisplayName = if ($_.displayName)
        {
            $_.displayName
        }
        else
        {
            '(unknown)'
        }
    }
}

# ============================================================
# FINAL LOG + SUMMARY
# ============================================================

Log-Message -Level INFO `
    -Message "========== Sync complete | Added: $( $addedDevices.Count ) | Removed: $( $removedDevices.Count ) | SoftErrors: $script:SoftErrorCount | HardErrors: $script:HardErrorCount ==========" `
    -InvocationName 'MAIN'

Write-SyncSummary `
    -GroupObjectId  $EntraGroupObjectId `
    -DeviceTag      $DeviceTag `
    -CurrentMembers @($finalMembers) `
    -AddedDevices   @($addedDevices) `
    -RemovedDevices @($removedDevices) `
    -SoftErrors     $script:SoftErrorCount `
    -HardErrors     $script:HardErrorCount

# ============================================================
# FINAL FAILURE LOGIC
# ============================================================

if ($script:HardErrorCount -gt 0)
{
    throw "Sync failed with $script:HardErrorCount real error(s). Review logs."
}