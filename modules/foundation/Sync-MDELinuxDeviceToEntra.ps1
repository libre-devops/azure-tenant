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

# Script-scoped error counter — incremented on every non-fatal error.
# Read at the very end to decide whether to surface a job failure to Azure Monitor.
$script:SyncErrorCount = 0

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
                    -Message "Authenticating via User-Assigned Managed Identity..." `
                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
        Log-Message -Level DEBUG `
                    -Message "ClientId: $ManagedIdentityClientId" `
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
        Returns a plain-string bearer token for the given resource using the Az context
        established by Initialize-ManagedIdentityAuth.

    .NOTES
        Get-AzAccessToken returns a PSAccessToken whose .Token property is a plain
        System.String at Az 11.2.0. It is cast explicitly to [string] to guarantee a
        clean scalar — this prevents edge cases where PowerShell returns an Object[]
        that interpolates as garbage inside the Authorization header.

        Never call Write-Output (or anything that writes to the output stream) inside
        this function — doing so concatenates log lines onto the return value.
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
                    -Message "Failed to acquire token for $Resource : $( $_.Exception.Message )" `
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

            $retryAfter = $_.Exception.Response?.Headers?['Retry-After']
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

    # OS filter (server-side)
        [string[]] $OsPlatforms = @(
        "RedHatEnterpriseLinux",
        "Ubuntu",
        "CentOS"
    ),

    # Health filter (server-side, future-proof)
        [string[]] $HealthStatus = @(
        "Active"
    )
    )

    Log-Message -Level INFO `
                -Message "Querying MDE (OS + health filtered, tag client-side). Tags: '$( $Tags -join "', '" )' | OS: '$( $OsPlatforms -join "', '" )' | Health: '$( $HealthStatus -join "', '" )'" `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    # Lookup sets
    $tagSet = [System.Collections.Generic.HashSet[string]]::new()
    $osSet = [System.Collections.Generic.HashSet[string]]::new()
    $healthSet = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($t in $Tags)
    {
        [void]$tagSet.Add($t)
    }
    foreach ($o in $OsPlatforms)
    {
        [void]$osSet.Add($o)
    }
    foreach ($h in $HealthStatus)
    {
        [void]$healthSet.Add($h)
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $all = [System.Collections.Generic.List[pscustomobject]]::new()

    # Build OData filters
    $osFilter = ($OsPlatforms  | ForEach-Object { "osPlatform eq '$_'" }) -join " or "
    $healthFilter = ($HealthStatus | ForEach-Object { "healthStatus eq '$_'" }) -join " or "

    $combinedFilter = "($osFilter) and ($healthFilter)"

    $uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=$combinedFilter"

    do
    {
        $res = Invoke-WithRetry -OperationName "MDE OS+Health query" -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $Token" }
        }

        if ($res.value)
        {
            foreach ($device in $res.value)
            {

                # Defensive checks (protect against API quirks)
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

                # Tag match (client-side)
                $match = $false
                foreach ($tag in $device.machineTags)
                {
                    if ( $tagSet.Contains($tag))
                    {
                        $match = $true
                        break
                    }
                }

                if ($match)
                {
                    if ( $seen.Add($device.id))
                    {
                        $all.Add($device)
                    }
                    else
                    {
                        Log-Message -Level DEBUG `
                                    -Message "Skipping duplicate device '$( $device.computerDnsName )'." `
                                    -InvocationName "$( $MyInvocation.MyCommand.Name )"
                    }
                }
            }
        }

        if ($res.PSObject.Properties.Name -contains '@odata.nextLink')
        {
            $uri = $res.'@odata.nextLink'
        }
        else
        {
            $uri = $null
        }

    } while ($uri)

    Log-Message -Level INFO `
                -Message "Matched $( $all.Count ) device(s) after filtering." `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

    return $all.ToArray()
}

# ============================================================
#  RESOLUTION
# ============================================================

function Resolve-EntraDeviceId
{
    param ($Device, $GraphToken)

    $name = $Device.computerDnsName
    $shortName = $name.Split('.')[0]

    # ============================================================
    # 1. FAST PATH — aadDeviceId
    # ============================================================

    if ($Device.aadDeviceId)
    {
        try
        {
            $res = Invoke-WithRetry -OperationName "Resolve aadDeviceId ($name)" -ScriptBlock {
                Invoke-RestMethod `
                    -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$( $Device.aadDeviceId )'&`$select=id" `
                    -Headers @{ Authorization = "Bearer $GraphToken" }
            }

            if ($res.value)
            {
                Log-Message -Level DEBUG `
                    -Message "Resolved via aadDeviceId: '$name'" `
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

    # ============================================================
    # 2. GRAPH-FIRST EXACT MATCH (PRIMARY PATH)
    # ============================================================

    Log-Message -Level WARN `
        -Message "Attempting Graph resolution for '$name'." `
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
            $match = $res.value |
                    Where-Object { -not $_.trustType } |
                    Select-Object -First 1

            if (-not $match)
            {
                $match = $res.value | Select-Object -First 1
            }

            Log-Message -Level DEBUG `
                -Message "Resolved via exact match: '$name' → '$($match.displayName)' ($($match.id))" `
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

    # ============================================================
    # 3. FUZZY MATCH (STARTSWITH)
    # ============================================================

    try
    {
        Log-Message -Level WARN `
            -Message "Falling back to fuzzy match for '$name'." `
            -InvocationName "$( $MyInvocation.MyCommand.Name )"

        $res = Invoke-WithRetry -OperationName "Graph fuzzy match ($name)" -ScriptBlock {
            Invoke-RestMethod `
                -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=startswith(displayName,'$shortName')&`$select=id,displayName,trustType" `
                -Headers @{ Authorization = "Bearer $GraphToken" }
        }

        if ($res.value)
        {
            $match = $res.value |
                    Where-Object { -not $_.trustType } |
                    Select-Object -First 1

            if (-not $match)
            {
                $match = $res.value | Select-Object -First 1
            }

            Log-Message -Level DEBUG `
                -Message "Resolved via fuzzy match: '$name' → '$($match.displayName)' ($($match.id))" `
                -InvocationName "$( $MyInvocation.MyCommand.Name )"

            return $match.id
        }
    }
    catch
    {
        Log-Message -Level ERROR `
            -Message "Fuzzy match failed for '$name': $( $_.Exception.Message )" `
            -InvocationName "$( $MyInvocation.MyCommand.Name )"
    }

    # ============================================================
    # 4. FINAL FAILURE
    # ============================================================

    Log-Message -Level ERROR `
        -Message "Failed to resolve Entra device for '$name'." `
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
        [string]   $DeviceTag,
        [object[]] $CurrentMembers,
        [object[]] $AddedDevices,
        [object[]] $RemovedDevices,
        [int]      $ErrorCount
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

    Write-Host ''
    Write-Host "  ADDED THIS RUN ($( $AddedDevices.Count ))" -ForegroundColor Green
    Write-Host "  $( '-' * 68 )"
    if ($AddedDevices.Count -eq 0)
    {
        Write-Host '    (none — all tagged devices were already members)' -ForegroundColor DarkGray
    }
    else
    {
        foreach ($d in $AddedDevices)
        {
            Write-Host ("    {0,-45} {1}" -f $d.DisplayName, $d.Id) -ForegroundColor Green
        }
    }

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

    Write-Host ''
    Write-Host "  NON-FATAL ERRORS : $ErrorCount" -ForegroundColor $( if ($ErrorCount -gt 0)
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
    -Message "========== Sync started | Tags: '$( $DeviceTag -join "', '" )' | OS: '$( $OsPlatforms -join "', '" )' | Health: '$( $HealthStatus -join "', '" )' | Group: '$EntraGroupObjectId' | RemoveStale: $RemoveStaleMembers | WhatIf: $WhatIf ==========" `
    -InvocationName 'MAIN'

# Tracking lists
$addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
$removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

# --- Auth ---
Initialize-ManagedIdentityAuth

# --- Tokens ---
$graphToken = Get-AccessToken -Resource 'https://graph.microsoft.com'
$mdeToken = Get-AccessToken -Resource 'https://api.securitycenter.microsoft.com'

# --- MDE devices ---
$mdeDevices = Get-MdeDevicesByTag `
    -Tags $DeviceTag `
    -Token $mdeToken `
    -OsPlatforms $OsPlatforms `
    -HealthStatus $HealthStatus

# --- Early exit if MDE returned no devices ---
# Auth succeeded and the API responded cleanly — there are simply no devices carrying
# any of the specified tags yet. Exit with Completed status rather than failing the job.
if (@($mdeDevices).Count -eq 0)
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
    Write-Host "  MDE Device Tag(s): $( $DeviceTag -join ', ' )"
    Write-Host "  WhatIf Mode      : $WhatIf"
    Write-Host ''
    Write-Host '  AUTH             : OK'                                          -ForegroundColor Green
    Write-Host '  MDE DEVICES FOUND: 0 — no devices carry this tag yet.'         -ForegroundColor Yellow
    Write-Host '  MEMBERS ADDED    : 0'
    Write-Host '  MEMBERS REMOVED  : 0'
    Write-Host '  NON-FATAL ERRORS : 0'                                           -ForegroundColor DarkGray
    Write-Host ''
    Write-Host $sep -ForegroundColor Cyan
    Write-Host ''

    exit 0
}

# --- Resolve Entra Object IDs ---
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
        $script:SyncErrorCount++
        Log-Message -Level ERROR `
                    -Message "Could not resolve Entra ID for '$( $d.computerDnsName )'. Device skipped." `
                    -InvocationName 'MAIN'
    }
}

# --- Current group members (snapshot before changes) ---
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
                        -Message "Added '$( $device.DisplayName )' ($( $device.Id ))." `
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
                            -Message "Removed stale '$( $member.DisplayName )' ($( $member.Id ))." `
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
            -Message "========== Sync complete | Added: $( $addedDevices.Count ) | Removed: $( $removedDevices.Count ) | Errors: $script:SyncErrorCount ==========" `
            -InvocationName 'MAIN'

Write-SyncSummary `
    -GroupObjectId  $EntraGroupObjectId `
    -DeviceTag      $DeviceTag `
    -CurrentMembers @($finalMembers) `
    -AddedDevices   @($addedDevices) `
    -RemovedDevices @($removedDevices) `
    -ErrorCount     $script:SyncErrorCount

# ── Option 1 failure alerting ────────────────────────────────────────────────
# Deliberately fail the job after the summary if any non-fatal errors occurred.
# This causes the Azure Automation 'Total Jobs / Failed' metric to increment,
# triggering the Azure Monitor alert rule without needing Application Insights.
if ($script:SyncErrorCount -gt 0)
{
    throw "Sync finished with $script:SyncErrorCount non-fatal error(s). Review job output above."
}