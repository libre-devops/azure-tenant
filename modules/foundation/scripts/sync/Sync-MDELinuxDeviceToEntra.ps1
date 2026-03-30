#Requires -Version 7.2
<#
.SYNOPSIS
    Azure Automation Runbook — Syncs MDE-tagged Linux devices into an Entra ID security group.

.DESCRIPTION
    Authenticates via a User-Assigned Managed Identity using the Az module
    (Connect-AzAccount + Get-AzAccessToken). Queries the MDE Machines API for devices
    carrying specified tags, and ensures each device's Entra ID object is a member of
    the target security group. Removes stale members if configured to do so.

    At the end of every run a summary is printed showing all current members, what was
    added, what was removed, pending devices (eventual consistency), and the error count.

    ERROR PHILOSOPHY
    ────────────────
    $script:SyncErrorCount is incremented ONLY for genuine failures:
        - API call failures (retries exhausted)
        - Group add / remove failures

    Resolution failures (device found in MDE but not yet in Entra) are tracked
    separately as $script:PendingCount and logged as WARN. These are expected during
    the Intune/MDE synthetic registration propagation window and do NOT cause the job
    to fail — the next scheduled run will retry automatically.

    LOGGING
    ───────
    Write-Verbose : All operational detail (auth steps, token acquisition, per-device
                    resolution results, skip/add/remove per device). Safe inside
                    functions that return values — never pollutes the output stream.
    Write-Host    : Summary report sections and ERROR lines only.
    Write-Warning : WARN-level log messages.
    Write-Output  : NEVER used — would corrupt function return values (tokens, IDs).

    RETRY
    ─────
    Up to MaxRetries attempts with 429-aware Retry-After header support.

    AUTH
    ────
    User-Assigned Managed Identity via Az module (Connect-AzAccount + Get-AzAccessToken).

.PARAMETER ManagedIdentityClientId
    Client ID of the User-Assigned Managed Identity attached to this Automation Account.

.PARAMETER DeviceTag
    One or more MDE machine tags to filter on. Devices matching ANY tag are included.
    Example: @('RHEL-EDR', 'UBUNTU-EDR')

.PARAMETER EntraGroupObjectId
    Object ID of the target Entra ID security group.

.PARAMETER RemoveStaleMembers
    If $true, devices currently in the group that no longer match any tag are removed.
    Defaults to $false (additive-only).

.PARAMETER ForceRemoveDeviceIds
    One or more Entra ID Object IDs to explicitly remove from the group, regardless of
    tag state. Use this when MDE API lag prevents automatic stale removal of offboarded
    devices. If a supplied ID is not in the group, a 'nothing to do' message is logged
    and no error is raised.

.PARAMETER MaxRetries
    Maximum number of retry attempts for transient API failures. Default: 6.

.PARAMETER RetryDelaySeconds
    Fallback delay (seconds) between retries when no Retry-After header is present.
    Default: 20.

.PARAMETER OsPlatforms
    OS platform values to include when querying MDE. Defaults to common Linux distros.

.PARAMETER HealthStatus
    MDE health status values to include. Defaults to Active only.

.PARAMETER WhatIf
    If $true, no writes are made to the group. Add/remove operations are logged only.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    REQUIRED MANAGED IDENTITY — API PERMISSIONS
    ─────────────────────────────────────────────────────────────────────────────

    APPLICATION permissions on the User-Assigned Managed Identity.
    Provisioned via Terraform (azuread_app_role_assignment).

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
    FAILURE ALERTING (Option 1 — native Azure Monitor metric alert)
    ─────────────────────────────────────────────────────────────────────────────

    Resource   : Your Automation Account
    Signal     : TotalJob (metric)
    Filter     : RunbookName = Sync-MdeDevicesToEntraGroup, Status = Failed
    Threshold  : Count >= 1
    Action     : Action Group → email / Teams webhook / SMS

    Catches both hard crashes and runs that completed with genuine API errors.
    Resolution-pending devices (eventual consistency) do NOT trigger this alert.
    ─────────────────────────────────────────────────────────────────────────────
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

    [string[]] $DeviceTag = @('RHEL-EDR', 'MDE-Management'),

    [string] $EntraGroupObjectId = '853451d5-e186-4362-9337-6f8ce967570a',

    [bool] $RemoveStaleMembers = $false,

    [string[]] $ForceRemoveDeviceIds = @(),

    [int]  $MaxRetries = 6,
    [int]  $RetryDelaySeconds = 20,
    [bool] $WhatIf = $false,

    [string[]] $OsPlatforms = @(
    'RedHatEnterpriseLinux',
    'Ubuntu',
    'CentOS',
    'Debian',
    'SLES'
),

    [string[]] $HealthStatus = @('Active')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Genuine API / group operation failures — triggers Azure Monitor alert via throw at end
$script:SyncErrorCount = 0

# Devices found in MDE but not yet resolvable in Entra ID (Intune propagation window)
# Does NOT trigger an alert — next scheduled run will retry automatically
$script:PendingCount = 0

# ============================================================
#  LOGGER
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
        # Write-Verbose: operational detail, safe inside functions that return values.
        # Write-Output must NEVER be used — it corrupts return values (tokens, IDs).
        'DEBUG' {
            Write-Verbose "$prefix $Message"
        }
        'INFO'  {
            Write-Verbose "$prefix $Message"
        }
        # Write-Warning and Write-Host go to separate streams, safe anywhere.
        'WARN'  {
            Write-Warning "$prefix $Message"
        }
        'ERROR' {
            Write-Host   "$prefix $Message" -ForegroundColor Red
        }
    }
}

# ============================================================
#  AUTH (USER-ASSIGNED MANAGED IDENTITY)
# ============================================================

function Initialize-ManagedIdentityAuth
{
    <#
    .SYNOPSIS
        Establishes an Az module context for the specified User-Assigned Managed Identity.
        Must be called before Get-AccessToken.
    #>
    try
    {
        Log-Message -Level INFO `
                    -Message "Authenticating via User-Assigned Managed Identity (ClientId: $ManagedIdentityClientId)..." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"

        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        Connect-AzAccount `
            -Identity `
            -AccountId  $ManagedIdentityClientId `
            -ErrorAction Stop | Out-Null

        Log-Message -Level INFO `
                    -Message "Managed Identity authentication successful." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Authentication FAILED: $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
        throw
    }
}

function Get-AccessToken
{
    <#
    .SYNOPSIS
        Returns a plain-string bearer token for the given resource.

    .NOTES
        Write-Verbose is used throughout — Write-Output would concatenate log lines
        onto the token string, producing a corrupt JWT with extra content prepended.

        At Az 11.2.0, Get-AzAccessToken returns Token as a plain System.String.
        The explicit [string] cast guards against edge cases where PS wraps it in Object[].
    #>
    param (
        [Parameter(Mandatory)]
        [string] $Resource
    )

    try
    {
        Log-Message -Level INFO `
                    -Message "Requesting token for: $Resource" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"

        $tokenResponse = Get-AzAccessToken `
            -ResourceUrl $Resource `
            -ErrorAction Stop

        if (-not $tokenResponse.Token)
        {
            throw "Token extraction failed — response contained no token."
        }

        $token = [string]$tokenResponse.Token

        Log-Message -Level DEBUG `
                    -Message "Token acquired (type: $( $tokenResponse.Token.GetType().Name ), length: $( $token.Length ))" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"

        return $token
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Failed to acquire token for '$Resource': $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
        throw
    }
}

# ============================================================
#  RETRY (429-aware)
# ============================================================

function Invoke-WithRetry
{
    param (
        [scriptblock] $ScriptBlock,
        [string]      $OperationName = 'Operation'
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try
        {
            return & $ScriptBlock
        }
        catch
        {
            $msg = $_.Exception.Message

            # Safely extract Retry-After — plain exceptions (e.g. System.Exception thrown in tests
            # or non-HTTP errors) do not have a Response property. Under Set-StrictMode -Version Latest
            # accessing a missing property throws, so we guard with PSObject.Properties first.
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
                            -InvocationName "$( $MyInvocation.MyCommand.Name )"
                throw
            }

            Log-Message -Level WARN `
                        -Message "Retry $i/$MaxRetries for '$OperationName' | waiting ${delay}s | $msg" `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            Start-Sleep -Seconds $delay
        }
    }
}

# ============================================================
#  MDE
# ============================================================

function Get-MdeDevicesByTag
{
    param (
        [string[]] $Tags,
        [string]   $Token,
        [string[]] $OsPlatforms,
        [string[]] $HealthStatus
    )

    Log-Message -Level INFO `
                -Message "Querying MDE | Tags: '$( $Tags -join "', '" )' | OS: '$( $OsPlatforms -join "', '" )' | Health: '$( $HealthStatus -join "', '" )'" `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    $tagSet = [System.Collections.Generic.HashSet[string]]($Tags)
    $osSet = [System.Collections.Generic.HashSet[string]]($OsPlatforms)
    $healthSet = [System.Collections.Generic.HashSet[string]]($HealthStatus)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $all = [System.Collections.Generic.List[pscustomobject]]::new()

    # Server-side filter on OS, health, and exclusion status to reduce payload size.
    # isExcluded eq false ensures offboarded/inactive devices are excluded from results —
    # MDE does not promptly remove offboarded devices from the API but does stamp them
    # with isExcluded: true, which is the reliable signal for "no longer managed".
    $osFilter = ($OsPlatforms  | ForEach-Object { "osPlatform eq '$_'" }) -join ' or '
    $healthFilter = ($HealthStatus | ForEach-Object { "healthStatus eq '$_'" }) -join ' or '
    $uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=($osFilter) and ($healthFilter) and isExcluded eq false"

    do
    {
        $res = Invoke-WithRetry -OperationName 'MDE OS+Health query' -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $Token" }
        }

        if ($res.value)
        {
            foreach ($device in $res.value)
            {
                # Client-side defensive checks
                if (-not $device.osPlatform -or -not $osSet.Contains($device.osPlatform))
                {
                    continue
                }
                if (-not $device.healthStatus -or -not $healthSet.Contains($device.healthStatus))
                {
                    continue
                }
                if (-not $device.machineTags)
                {
                    continue
                }

                # Tag match — device must carry at least one of the requested tags
                $matched = $false
                foreach ($tag in $device.machineTags)
                {
                    if ( $tagSet.Contains($tag))
                    {
                        $matched = $true; break
                    }
                }

                if ($matched)
                {
                    if ( $seen.Add($device.id))
                    {
                        $all.Add($device)
                    }
                    else
                    {
                        Log-Message -Level DEBUG `
                                    -Message "Skipping duplicate '$( $device.computerDnsName )' (seen via another tag)." `
                                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
                    }
                }
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

    } while ($uri)

    Log-Message -Level INFO `
                -Message "Matched $( $all.Count ) device(s) after tag + OS + health + exclusion filtering." `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    return $all.ToArray()
}

# ============================================================
#  RESOLUTION
# ============================================================

function Resolve-EntraDeviceId
{
    <#
    .SYNOPSIS
        Attempts to resolve a device's Entra ID Object ID via three strategies:
        1. aadDeviceId fast path
        2. Exact displayName match (FQDN and short name)
        3. Fuzzy startswith match on short name

        Returns $null if the device is not yet in Entra ID (propagation pending).
        Callers should treat $null as WARN/pending, not as an error.
    #>
    param ($Device, $GraphToken)

    $name = $Device.computerDnsName
    $shortName = $name.Split('.')[0]

    # 1. Fast path — aadDeviceId populated
    if ($Device.aadDeviceId)
    {
        try
        {
            $res = Invoke-WithRetry -OperationName "Resolve aadDeviceId ($name)" -ScriptBlock {
                Invoke-RestMethod `
                    -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$( $Device.aadDeviceId )'&`$select=id,displayName" `
                    -Headers @{ Authorization = "Bearer $GraphToken" }
            }

            if ($res.value)
            {
                Log-Message -Level DEBUG `
                            -Message "Resolved '$name' via aadDeviceId → $( $res.value[0].id )" `
                            -InvocationName "$( $MyInvocation.MyCommand.Name )"
                return $res.value[0].id
            }
        }
        catch
        {
            Log-Message -Level WARN `
                        -Message "aadDeviceId lookup failed for '$name': $( $_.Exception.Message )" `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
        }
    }

    # 2. Exact displayName match (FQDN and short name)
    Log-Message -Level INFO `
                -Message "Attempting Graph exact match for '$name'." `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    try
    {
        $filter = "displayName eq '$name' or displayName eq '$shortName'"
        $res = Invoke-WithRetry -OperationName "Graph exact match ($name)" -ScriptBlock {
            Invoke-RestMethod `
                -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=$filter&`$select=id,displayName,trustType" `
                -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            # Prefer blank trustType (synthetic MDE/Intune device); fall back to first result
            $match = $res.value | Where-Object { -not $_.trustType } | Select-Object -First 1
            if (-not $match)
            {
                $match = $res.value | Select-Object -First 1
            }

            Log-Message -Level DEBUG `
                        -Message "Resolved '$name' via exact match → '$( $match.displayName )' ($( $match.id ))" `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            return $match.id
        }
    }
    catch
    {
        Log-Message -Level WARN `
                    -Message "Exact match lookup failed for '$name': $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }

    # 3. Fuzzy startswith match on short name
    Log-Message -Level INFO `
                -Message "Attempting fuzzy (startswith) match for '$name' using short name '$shortName'." `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    try
    {
        $res = Invoke-WithRetry -OperationName "Graph fuzzy match ($name)" -ScriptBlock {
            Invoke-RestMethod `
                -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=startswith(displayName,'$shortName')&`$select=id,displayName,trustType" `
                -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            $match = $res.value | Where-Object { -not $_.trustType } | Select-Object -First 1
            if (-not $match)
            {
                $match = $res.value | Select-Object -First 1
            }

            Log-Message -Level DEBUG `
                        -Message "Resolved '$name' via fuzzy match → '$( $match.displayName )' ($( $match.id ))" `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            return $match.id
        }
    }
    catch
    {
        Log-Message -Level WARN `
                    -Message "Fuzzy match failed for '$name': $( $_.Exception.Message )" `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }

    # All strategies exhausted — device not yet in Entra
    # This is expected during Intune/MDE propagation. Caller tracks as pending, not error.
    Log-Message -Level WARN `
                -Message "Could not resolve '$name' in Entra ID — likely pending synthetic registration. Will retry next run." `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    return $null
}

# ============================================================
#  GROUP OPS
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

        Log-Message -Level INFO `
                    -Message "Successfully added $DeviceId to group $GroupId." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }
    catch
    {
        if ($_.Exception.Message -match 'already exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already a member (race condition — safe to ignore)." `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
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

        Log-Message -Level INFO `
                    -Message "Successfully removed $DeviceId from group $GroupId." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }
    catch
    {
        if ($_.Exception.Message -match 'does not exist')
        {
            Log-Message -Level DEBUG `
                        -Message "Device $DeviceId already removed (safe to ignore)." `
                        -InvocationName "$( $MyInvocation.MyCommand.Name )"
            return
        }
        throw
    }
}

# ============================================================
#  SUMMARY REPORT
# ============================================================

function Write-SyncSummary
{
    param (
        [string]   $GroupObjectId,
        [string[]] $DeviceTags,
        [object[]] $CurrentMembers,
        [object[]] $AddedDevices,
        [object[]] $RemovedDevices,
        [object[]] $PendingDevices,
        [int]      $ErrorCount
    )

    $sep = '=' * 72

    Write-Host ''
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host '  SYNC SUMMARY REPORT'                       -ForegroundColor Cyan
    Write-Host "  $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )" -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Group Object ID  : $GroupObjectId"
    Write-Host "  MDE Tag(s)       : $( $DeviceTags -join ', ' )"
    Write-Host "  WhatIf Mode      : $WhatIf"
    Write-Host ''

    # Current members
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

    # Added
    Write-Host ''
    Write-Host "  ADDED THIS RUN ($( $AddedDevices.Count ))" -ForegroundColor Green
    Write-Host "  $( '-' * 68 )"
    if ($AddedDevices.Count -eq 0)
    {
        Write-Host '    (none — all resolved devices were already members)' -ForegroundColor DarkGray
    }
    else
    {
        foreach ($d in $AddedDevices)
        {
            Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Green
        }
    }

    # Removed
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

    # Pending (eventual consistency — not an error)
    Write-Host ''
    Write-Host "  PENDING ENTRA REGISTRATION ($( $PendingDevices.Count ))" -ForegroundColor Yellow
    Write-Host "  $( '-' * 68 )"
    if ($PendingDevices.Count -eq 0)
    {
        Write-Host '    (none)' -ForegroundColor DarkGray
    }
    else
    {
        Write-Host '    These devices exist in MDE but are not yet visible in Entra ID.' -ForegroundColor DarkGray
        Write-Host '    This is expected during Intune/MDE synthetic registration.' -ForegroundColor DarkGray
        Write-Host '    They will be added automatically on the next successful run.' -ForegroundColor DarkGray
        Write-Host ''
        foreach ($d in $PendingDevices)
        {
            Write-Host ("    {0}" -f $d) -ForegroundColor Yellow
        }
    }

    # Errors
    Write-Host ''
    Write-Host "  NON-FATAL API ERRORS : $ErrorCount" -ForegroundColor $( if ($ErrorCount -gt 0)
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
# ============================================================

Log-Message -Level INFO `
            -Message "========== Sync started | Tags: '$( $DeviceTag -join "', '" )' | OS: '$( $OsPlatforms -join "', '" )' | Group: '$EntraGroupObjectId' | RemoveStale: $RemoveStaleMembers | ForceRemove: $( $ForceRemoveDeviceIds.Count ) ID(s) | WhatIf: $WhatIf ==========" `
            -InvocationName 'MAIN'

$addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
$removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
$pendingDevices = [System.Collections.Generic.List[string]]::new()

# --- Auth ---
Initialize-ManagedIdentityAuth

# --- Tokens ---
$graphToken = Get-AccessToken -Resource 'https://graph.microsoft.com'
$mdeToken = Get-AccessToken -Resource 'https://api.securitycenter.microsoft.com'

# --- MDE devices ---
$mdeDevices = Get-MdeDevicesByTag `
    -Tags         $DeviceTag `
    -Token        $mdeToken `
    -OsPlatforms  $OsPlatforms `
    -HealthStatus $HealthStatus

# --- Current group members (needed by both normal sync and force-remove) ---
$currentRaw = Invoke-WithRetry -OperationName 'Get current group members' -ScriptBlock {
    Invoke-RestMethod `
        -Uri     "https://graph.microsoft.com/v1.0/groups/$EntraGroupObjectId/members?`$select=id,displayName" `
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

# --- Early exit if MDE returned no devices ---
# Only exit early if RemoveStaleMembers is false and no ForceRemoveDeviceIds are supplied.
# If RemoveStaleMembers is true, an empty MDE result is a valid desired state of
# "nothing should be in the group" — stale removal must still run to honour that.
if (@($mdeDevices).Count -eq 0 -and @($ForceRemoveDeviceIds).Count -eq 0 -and -not $RemoveStaleMembers)
{
    Log-Message -Level WARN `
                -Message "MDE returned 0 devices for tag(s): '$( $DeviceTag -join "', '" )'. Auth is working. Nothing to sync." `
                -InvocationName 'MAIN'

    $sep = '=' * 72
    Write-Host ''
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host '  SYNC SUMMARY REPORT'                       -ForegroundColor Cyan
    Write-Host "  $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )" -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Group Object ID  : $EntraGroupObjectId"
    Write-Host "  MDE Tag(s)       : $( $DeviceTag -join ', ' )"
    Write-Host "  WhatIf Mode      : $WhatIf"
    Write-Host ''
    Write-Host '  AUTH              : OK'                                                   -ForegroundColor Green
    Write-Host '  MDE DEVICES FOUND : 0 — no devices match the tag(s) and OS filter yet.'  -ForegroundColor Yellow
    Write-Host '  MEMBERS ADDED     : 0'
    Write-Host '  MEMBERS REMOVED   : 0'
    Write-Host '  PENDING           : 0'
    Write-Host '  API ERRORS        : 0'                                                    -ForegroundColor DarkGray
    Write-Host ''
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ''

    exit 0
}

# --- Resolve Entra Object IDs for MDE devices ---
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
    }
    else
    {
        # Not an error — device is pending Intune/MDE synthetic registration in Entra.
        # Track separately so the summary shows it and the job does not fail.
        $script:PendingCount++
        $pendingDevices.Add($d.computerDnsName)
        Log-Message -Level WARN `
                    -Message "'$( $d.computerDnsName )' not yet in Entra ID (pending registration). Will retry next run." `
                    -InvocationName 'MAIN'
    }
}

# --- Add missing devices ---
foreach ($device in $resolved)
{
    if ($currentIds -notcontains $device.Id)
    {
        try
        {
            Add-DeviceToGroup -GroupId $EntraGroupObjectId -DeviceId $device.Id -Token $graphToken
            $addedDevices.Add($device)
            Log-Message -Level INFO `
                        -Message "Added '$( $device.DisplayName )' ($( $device.Id )) to group." `
                        -InvocationName 'MAIN'
        }
        catch
        {
            $script:SyncErrorCount++
            Log-Message -Level ERROR `
                        -Message "Failed to add '$( $device.DisplayName )' ($( $device.Id )): $( $_.Exception.Message )" `
                        -InvocationName 'MAIN'
        }
    }
    else
    {
        Log-Message -Level DEBUG `
                    -Message "'$( $device.DisplayName )' already in group. Skipping." `
                    -InvocationName 'MAIN'
    }
}

# --- Remove stale members ---
# A device is stale if it is in the group but no longer appears in the MDE query results.
# The MDE query already excludes isExcluded devices, so offboarded devices naturally
# fall out of $resolved and get removed here when RemoveStaleMembers is enabled.
if ($RemoveStaleMembers)
{
    $resolvedIds = @($resolved | Select-Object -ExpandProperty Id)

    foreach ($member in $currentMembers)
    {
        if ($resolvedIds -notcontains $member.Id)
        {
            try
            {
                Remove-DeviceFromGroup -GroupId $EntraGroupObjectId -DeviceId $member.Id -Token $graphToken
                $removedDevices.Add($member)
                Log-Message -Level INFO `
                            -Message "Removed stale '$( $member.DisplayName )' ($( $member.Id )) from group." `
                            -InvocationName 'MAIN'
            }
            catch
            {
                $script:SyncErrorCount++
                Log-Message -Level ERROR `
                            -Message "Failed to remove '$( $member.DisplayName )' ($( $member.Id )): $( $_.Exception.Message )" `
                            -InvocationName 'MAIN'
            }
        }
    }
}

# --- Force remove (manual override) ---
# Explicitly removes specific Entra device Object IDs regardless of tag or MDE state.
# Use when MDE API lag prevents automatic stale removal of known-offboarded devices.
# Uses the pre-change $currentIds snapshot — consistent with the rest of MAIN.
if (@($ForceRemoveDeviceIds).Count -gt 0)
{
    Log-Message -Level INFO `
                -Message "Force-remove override: $( $ForceRemoveDeviceIds.Count ) device ID(s) supplied." `
                -InvocationName 'MAIN'

    foreach ($forceId in $ForceRemoveDeviceIds)
    {
        if ($currentIds -notcontains $forceId)
        {
            Log-Message -Level INFO `
                        -Message "Force-remove: '$forceId' is not in the group — nothing to do." `
                        -InvocationName 'MAIN'
            continue
        }

        try
        {
            Remove-DeviceFromGroup -GroupId $EntraGroupObjectId -DeviceId $forceId -Token $graphToken
            $removedDevices.Add([pscustomobject]@{
                Id = $forceId
                DisplayName = "(force-removed)"
            })
            Log-Message -Level INFO `
                        -Message "Force-remove: successfully removed '$forceId' from group." `
                        -InvocationName 'MAIN'
        }
        catch
        {
            $script:SyncErrorCount++
            Log-Message -Level ERROR `
                        -Message "Force-remove: failed to remove '$forceId': $( $_.Exception.Message )" `
                        -InvocationName 'MAIN'
        }
    }
}

# --- Final member list (post-change) ---
$finalRaw = Invoke-WithRetry -OperationName 'Get final group members' -ScriptBlock {
    Invoke-RestMethod `
        -Uri     "https://graph.microsoft.com/v1.0/groups/$EntraGroupObjectId/members?`$select=id,displayName" `
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

Log-Message -Level INFO `
            -Message "========== Sync complete | Added: $( $addedDevices.Count ) | Removed: $( $removedDevices.Count ) | Pending: $script:PendingCount | API Errors: $script:SyncErrorCount ==========" `
            -InvocationName 'MAIN'

Write-SyncSummary `
    -GroupObjectId  $EntraGroupObjectId `
    -DeviceTags     $DeviceTag `
    -CurrentMembers @($finalMembers) `
    -AddedDevices   @($addedDevices) `
    -RemovedDevices @($removedDevices) `
    -PendingDevices @($pendingDevices) `
    -ErrorCount     $script:SyncErrorCount

# ── Failure alerting ─────────────────────────────────────────────────────────
# Only throw if genuine API errors occurred (not pending devices).
# This causes the Azure Automation 'Total Jobs / Failed' metric to increment,
# triggering the Azure Monitor alert rule.
# Pending devices (eventual consistency) produce a Completed job — no alert fires.
if ($script:SyncErrorCount -gt 0)
{
    throw "Sync finished with $script:SyncErrorCount API error(s). Review job output above. ($script:PendingCount device(s) pending Entra registration — these are normal and will retry.)"
}