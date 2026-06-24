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

    MULTI-MATCH POLICY
    ──────────────────
    A device name may map to more than one Entra object ID. Two distinct cases:

      (a) Identical displayName duplicates — same physical device re-enrolled, the
          old synthetic object lingering beside the new one. Indistinguishable by
          name, so ALL matching IDs are added: the live object is always covered and
          the stale one in the group is harmless. Logged as WARN for cleanup.

      (b) Different FQDNs sharing a short name / prefix — genuinely different machines
          (server01.site-a vs server01.site-b). Adding both would mis-target a policy,
          so these stay SKIPPED as Ambiguous. Correct the config with the FQDN.

    The rule: add all IDs that resolve to the SAME displayName; skip when matches span
    DIFFERENT displaynames.

    Ambiguous matches are skipped and logged as WARN. They appear in the summary under
    SKIPPED and do NOT increment the error count.

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
    Log levels map onto streams chosen so nothing ever lands on the SUCCESS stream
    inside a value-returning function (that would corrupt the return value — the
    classic way the Graph token gets mangled into "Bearer <logline> <token>").

    DEBUG   → Write-Verbose : low-level detail. All Logs tab only, when verbose on.
    INFO    → Write-Verbose : operational steps. All Logs tab only, when verbose on.
    STATUS  → Write-Host    : key milestones (start, per-group result, totals).
                              ALWAYS visible, even with verbose off — the baseline
                              audit trail. Information stream (6), safe in functions.
    WARN    → Write-Warning : Warnings tab + All Logs. Always visible.
    ERROR   → Write-Host    : failures. Always visible. NON-terminating on purpose —
                              Write-Error would throw under $ErrorActionPreference=Stop
                              and defeat the count-and-continue design.
    Write-Output            : NEVER used — enters the success pipeline and corrupts
                              function return values.

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
    Retry configuration for transient API failures. A 401 inside the retry loop
    force-refreshes the Graph token before retrying (see TOKEN HANDLING in .NOTES).

.PARAMETER StaleRemovalMinCount / StaleRemovalMaxPercent
    Blast-radius guard for stale removal. A run that would remove MORE than
    StaleRemovalMinCount members AND MORE than StaleRemovalMaxPercent of a group's
    current membership aborts removals for that group and fails the job. BOTH must
    be exceeded. Defaults: 5 devices and 0.20 (20%). Stage genuine bulk removals
    across multiple runs so each stays under the limit. WhatIf bypasses the guard.

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

    Least-privilege alternative: keep the two READS as app permissions
    (Device.Read.All + GroupMember.Read.All) and grant member WRITES via a custom
    Entra directory role with action
    'microsoft.directory/groups.security.assignedMembership/members/update',
    scoped to the target groups. Note that action only covers ASSIGNED-membership
    security groups — not dynamic or M365/mail-enabled groups.

    ─────────────────────────────────────────────────────────────────────────────
    LONG-RUNNING RELIABILITY  (this runbook is expected to run unattended for years)
    ─────────────────────────────────────────────────────────────────────────────

    MODULE PINNING
        The Automation Account pins its Az module versions (managed in the
        environment / Terraform). This matters: module auto-update is the #1 silent
        breaker of long-lived runbooks. Upgrade deliberately, then re-test. The
        token extraction below is defence-in-depth for the day a pin is bumped.

    TOKEN HANDLING
        Get-GraphToken caches the Graph token at script scope and auto-refreshes
        when it is missing or within 5 minutes of expiry. It is called before each
        group, and Invoke-WithRetry force-refreshes on a 401 — so a job that runs
        longer than the ~60–90 min token lifetime (large tenants / many groups)
        does not fail on an expired token. Token extraction handles BOTH a plaintext
        string and a SecureString (.Token became SecureString-by-default in
        Az.Accounts 5.x) so a module bump can't silently produce a bad token.

    BLAST-RADIUS GUARD
        See StaleRemovalMinCount / StaleRemovalMaxPercent. Protects against a
        truncated/corrupt config (or a transient empty device index) gutting a group
        in one run. Genuine bulk removals are staged across runs.

    DUPLICATE DEVICES
        Entra accumulates duplicate device objects as machines re-enroll. The index
        keeps ALL IDs per displayName and WARNs on collisions; identical-name
        duplicates are all synced (see MULTI-MATCH POLICY) so the live object is
        always covered. Clean up duplicates in Entra to keep the summary tidy.
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
    [int] $RetryDelaySeconds = 20,

# Blast-radius guard for stale removal. A single run that would remove MORE than
# StaleRemovalMinCount members AND MORE than StaleRemovalMaxPercent of a group's
# current membership is aborted for that group and fails the job. BOTH thresholds
# must be exceeded — the percentage stops large-group wipeouts, the absolute floor
# stops false positives on tiny groups (20% of 1 rounds to 0). Stage genuine bulk
# removals across multiple runs.
    [int]    $StaleRemovalMinCount   = 5,
    [double] $StaleRemovalMaxPercent = 0.20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SyncErrorCount = 0
$script:PendingCount = 0

# Graph token cache. Populated by Get-GraphToken and read directly by every Graph
# call (via $script:GraphToken) so a force-refresh on 401 is picked up on retry.
$script:GraphResource       = 'https://graph.microsoft.com'
$script:GraphToken          = $null
$script:GraphTokenExpiresOn = [datetimeoffset]::MinValue

# ============================================================
#  LOGGER
#  DEBUG/INFO → Write-Verbose : All Logs only (needs verbose enabled).
#  STATUS     → Write-Host    : milestones, ALWAYS visible. Information stream.
#  WARN       → Write-Warning : Warnings tab + All Logs.
#  ERROR      → Write-Host    : failures, ALWAYS visible, non-terminating.
#  None touch the SUCCESS stream, so they are safe inside returning functions.
#  Write-Output is NEVER used — it corrupts function return values (and tokens).
# ============================================================

function Log-Message
{
    param (
        [ValidateSet('DEBUG', 'INFO', 'STATUS', 'WARN', 'ERROR')]
        [string] $Level,
        [string] $Message,
        [string] $InvocationName
    )

    $ts = Get-Date -Format 'HH:mm:ss'
    $prefix = "$ts [$InvocationName]"

    switch ($Level)
    {
        'DEBUG'  {
            Write-Verbose "$prefix $Message"
        }                          # All Logs only — low-level detail
        'INFO'   {
            Write-Verbose "$prefix $Message"
        }                          # All Logs only — operational steps (verbose)
        'STATUS' {
            Write-Host "$prefix $Message" -ForegroundColor Cyan
        }   # Always visible — milestone/audit baseline
        'WARN'   {
            Write-Warning "$prefix $Message"
        }                          # Warnings tab + All Logs
        'ERROR'  {
            Write-Host "$prefix $Message" -ForegroundColor Red
        }      # Always visible — non-terminating (Write-Error throws under -EAP Stop)
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
        [AllowEmptyString()]
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

function Get-GraphError
{
    <#
    .SYNOPSIS
        Extracts a useful, human-readable message from a failed Graph call.
    .DESCRIPTION
        In PowerShell 7, Invoke-RestMethod puts only the generic ".NET status
        code" text in $_.Exception.Message. The actual Graph error body — the
        bit you care about (error.code + error.message, e.g.
        'Authorization_RequestDenied') — lives in $_.ErrorDetails.Message.
        This surfaces the status code plus that body, falling back gracefully
        for non-HTTP errors.
    #>
    param ($ErrorRecord)

    $resp = $null
    if ($ErrorRecord.Exception.PSObject.Properties['Response'])
    {
        $resp = $ErrorRecord.Exception.Response
    }
    $status = if ($resp) { [int]$resp.StatusCode } else { '?' }

    $detail = $ErrorRecord.ErrorDetails.Message
    if ($detail)
    {
        try
        {
            $j = $detail | ConvertFrom-Json
            if ($j.error)
            {
                return "HTTP $status | $( $j.error.code ): $( $j.error.message )"
            }
        }
        catch { }   # body wasn't JSON — fall through to raw
        return "HTTP $status | $detail"
    }

    return "HTTP $status | $( $ErrorRecord.Exception.Message )"
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

function Get-GraphToken
{
    <#
    .SYNOPSIS
        Returns a valid Microsoft Graph token, refreshing transparently.
    .DESCRIPTION
        Caches the token at script scope and re-acquires it when missing, forced,
        or within 5 minutes of expiry. Called before each group, and force-refreshed
        on a 401 inside Invoke-WithRetry, so a run that outlives the ~60–90 min token
        lifetime (large tenants / many groups) does not fail on an expired token.
        Handles both plaintext and SecureString .Token (SecureString became the
        Az.Accounts 5.x default) so a pinned-module bump can't silently break auth.
    #>
    param ([switch] $Force)

    $stillValid = $script:GraphToken -and
                  ([datetimeoffset]::UtcNow -lt $script:GraphTokenExpiresOn.AddMinutes(-5))

    if (-not $Force -and $stillValid)
    {
        return $script:GraphToken
    }

    try
    {
        Log-Message -Level INFO `
                    -Message "$( if ($Force) { 'Force-refreshing' } else { 'Acquiring' } ) Graph token..." `
                    -InvocationName $MyInvocation.MyCommand.Name

        $tokenResponse = Get-AzAccessToken -ResourceUrl $script:GraphResource -ErrorAction Stop

        if (-not $tokenResponse.Token)
        {
            throw 'Token extraction failed — response contained no token.'
        }

        # .Token may be a SecureString OR a plaintext string depending on the pinned
        # Az.Accounts version (SecureString became the default in 5.x). Handle both so
        # a module bump can't turn the token into the literal 'System.Security.SecureString'.
        # [string] cast also guards against PS wrapping a plain token in Object[].
        $rawToken = $tokenResponse.Token
        $token = if ($rawToken -is [System.Security.SecureString])
        {
            [System.Net.NetworkCredential]::new('', $rawToken).Password
        }
        else
        {
            [string]$rawToken
        }

        if ([string]::IsNullOrWhiteSpace($token) -or $token -eq 'System.Security.SecureString')
        {
            throw 'Token extraction produced an empty or unconverted value — check the Az.Accounts module version.'
        }

        $script:GraphToken = $token
        $script:GraphTokenExpiresOn = if ($tokenResponse.ExpiresOn)
        {
            [datetimeoffset]$tokenResponse.ExpiresOn
        }
        else
        {
            [datetimeoffset]::UtcNow.AddMinutes(50)   # conservative fallback
        }

        Log-Message -Level INFO `
                    -Message "Graph token ready (length: $( $token.Length ), expires: $( $script:GraphTokenExpiresOn.ToString('u') ))" `
                    -InvocationName $MyInvocation.MyCommand.Name

        return $script:GraphToken
    }
    catch
    {
        Log-Message -Level ERROR `
                    -Message "Failed to acquire Graph token: $( $_.Exception.Message )" `
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
            $msg = Get-GraphError -ErrorRecord $_
            $retryAfter = $null

            $resp = if ($_.Exception.PSObject.Properties['Response']) { $_.Exception.Response } else { $null }
            $statusCode = if ($resp) { [int]$resp.StatusCode } else { 0 }

            # 401 mid-run = the token expired during a long job. Force-refresh it;
            # the Graph calls read $script:GraphToken, so the next attempt picks up
            # the new token. Refresh failures are swallowed — the retry will surface
            # the real error if auth is genuinely broken.
            if ($statusCode -eq 401)
            {
                Log-Message -Level WARN -Message "401 on '$OperationName' — refreshing Graph token before retry." -InvocationName $MyInvocation.MyCommand.Name
                try { Get-GraphToken -Force | Out-Null } catch { }
            }

            # HttpResponseHeaders has NO string indexer. The old
            # $...Headers?['Retry-After'] threw "Unable to index into an object
            # of type System.Net.Http.Headers.HttpResponseHeaders" from inside
            # this catch — which masked the real Graph error AND broke 429
            # backoff. TryGetValues is the supported access path.
            if ($resp)
            {
                $vals = $null
                if ($resp.Headers.TryGetValues('Retry-After', [ref]$vals))
                {
                    $retryAfter = @($vals)[0]
                }
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
    # Reads the token from $script:GraphToken so a mid-run refresh is picked up.
    $allDevices = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri = "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName&`$top=999"

    do
    {
        $res = Invoke-WithRetry -OperationName 'Fetch all Entra devices' -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $script:GraphToken" }
        }
        if ($res.value) { $allDevices.AddRange([pscustomobject[]]$res.value) }
        $uri = if ($res.PSObject.Properties.Name -contains '@odata.nextLink') { $res.'@odata.nextLink' } else { $null }
    }
    while ($uri)

    Log-Message -Level INFO -Message "Fetched $( $allDevices.Count ) Entra device object(s) into local index." -InvocationName 'Build-DeviceIndex'

    # exact: fullName(lower)  → List[string] ids        (>1 = identical-displayName duplicates)
    # short: shortName(lower) → List[{ Id; Full }]      (lets Resolve tell duplicates from distinct devices)
    $exactIndex = @{}
    $shortIndex = @{}
    $fuzzyList  = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($d in $allDevices)
    {
        if (-not $d.displayName) { continue }

        $full  = $d.displayName.ToLower()
        $short = $full.Split('.')[0]

        if (-not $exactIndex.ContainsKey($full))
        {
            $exactIndex[$full] = [System.Collections.Generic.List[string]]::new()
        }
        $exactIndex[$full].Add($d.id)

        if (-not $shortIndex.ContainsKey($short))
        {
            $shortIndex[$short] = [System.Collections.Generic.List[pscustomobject]]::new()
        }
        $shortIndex[$short].Add([pscustomobject]@{ Id = $d.id; Full = $full })

        $fuzzyList.Add([pscustomobject]@{ Name = $full; Short = $short; Id = $d.id })
    }

    # WARN on true duplicates (identical displayName, >1 object) so operators can clean up.
    foreach ($kv in $exactIndex.GetEnumerator())
    {
        if ($kv.Value.Count -gt 1)
        {
            Log-Message -Level WARN -Message "Duplicate Entra displayName '$( $kv.Key )' → $( $kv.Value.Count ) objects ($( $kv.Value -join ', ' )). All will be synced to keep the live object covered; clean up stale duplicates in Entra." -InvocationName 'Build-DeviceIndex'
        }
    }

    Log-Message -Level INFO -Message "Built exact index ($( $exactIndex.Count ) names), short index ($( $shortIndex.Count ) names), fuzzy list ($( $fuzzyList.Count ) entries)." -InvocationName 'Build-DeviceIndex'

    return $exactIndex, $shortIndex, $fuzzyList.ToArray()
}

function Resolve-Device
{
    param (
        [string]    $DeviceName,
        [hashtable] $ExactIndex,
        [hashtable] $ShortIndex,
        [array]     $FuzzyList
    )

    $normalized = $DeviceName.ToLower()
    $short = $normalized.Split('.')[0]

    # 1. Exact full displayName. Multiple IDs = identical-displayName duplicates
    #    (same device re-enrolled). Add ALL so the live object is always covered.
    if ($ExactIndex.ContainsKey($normalized))
    {
        $ids  = @($ExactIndex[$normalized])
        $note = if ($ids.Count -gt 1) { " ($( $ids.Count ) duplicate objects — adding all)" } else { '' }
        Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via exact match → $( $ids -join ', ' )$note" -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Ids = $ids }
    }

    # 2. Short name. Group matches by full displayName:
    #    one distinct full name → same device (maybe duplicated) → add all
    #    several distinct names → genuinely different machines     → ambiguous, skip
    if ($ShortIndex.ContainsKey($short))
    {
        $entries  = @($ShortIndex[$short])
        $distinct = @($entries.Full | Select-Object -Unique)

        if ($distinct.Count -eq 1)
        {
            $ids  = @($entries.Id)
            $note = if ($ids.Count -gt 1) { " ($( $ids.Count ) duplicate objects — adding all)" } else { '' }
            Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via short-name match → $( $ids -join ', ' )$note" -InvocationName 'Resolve-Device'
            return [pscustomobject]@{ Status = 'Resolved'; Ids = $ids }
        }

        Log-Message -Level WARN -Message "Ambiguous short-name match for '$DeviceName' — $( $distinct.Count ) distinct devices share short name '$short': $( $distinct -join ', ' ). Use the FQDN in config. Skipping." -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Ambiguous'; Ids = @() }
    }

    # 3. Fuzzy startswith. Same grouping rule.
    $candidates = @($FuzzyList | Where-Object { $_.Short.StartsWith($short) })
    $distinctF  = @($candidates.Name | Select-Object -Unique)

    if ($candidates.Count -eq 0)
    {
        Log-Message -Level WARN -Message "Could not resolve '$DeviceName' in Entra ID — pending registration. Will retry next run." -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Pending'; Ids = @() }
    }

    if ($distinctF.Count -eq 1)
    {
        $ids  = @($candidates.Id)
        $note = if ($ids.Count -gt 1) { " ($( $ids.Count ) duplicate objects — adding all)" } else { '' }
        Log-Message -Level DEBUG -Message "Resolved '$DeviceName' via fuzzy match → '$( $distinctF[0] )'$note" -InvocationName 'Resolve-Device'
        return [pscustomobject]@{ Status = 'Resolved'; Ids = $ids }
    }

    Log-Message -Level WARN -Message "Ambiguous fuzzy match for '$DeviceName' — $( $distinctF.Count ) candidates: $( $distinctF -join ', ' ). Skipping." -InvocationName 'Resolve-Device'
    return [pscustomobject]@{ Status = 'Ambiguous'; Ids = @() }
}

# ============================================================
#  GROUP OPS
# ============================================================

function Add-DeviceToGroup
{
    param ($GroupId, $DeviceId)

    if ($WhatIf)
    {
        Log-Message -Level INFO -Message "[WHATIF] Would add $DeviceId to group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
        return
    }

    try
    {
        $null = Invoke-WithRetry -OperationName "Add device ($DeviceId)" -ScriptBlock {
            Invoke-RestMethod `
                -Method  POST `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref" `
                -Headers @{ Authorization = "Bearer $script:GraphToken"; 'Content-Type' = 'application/json' } `
                -Body    (@{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceId" } | ConvertTo-Json)
        }
        Log-Message -Level INFO -Message "Successfully added $DeviceId to group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ((Get-GraphError -ErrorRecord $_) -match 'already exist')
        {
            Log-Message -Level DEBUG -Message "Device $DeviceId already a member (race condition — safe to ignore)." -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Remove-DeviceFromGroup
{
    param ($GroupId, $DeviceId)

    if ($WhatIf)
    {
        Log-Message -Level INFO -Message "[WHATIF] Would remove $DeviceId from group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
        return
    }

    try
    {
        $null = Invoke-WithRetry -OperationName "Remove device ($DeviceId)" -ScriptBlock {
            Invoke-RestMethod `
                -Method  DELETE `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$DeviceId/`$ref" `
                -Headers @{ Authorization = "Bearer $script:GraphToken" }
        }
        Log-Message -Level INFO -Message "Successfully removed $DeviceId from group $GroupId." -InvocationName $MyInvocation.MyCommand.Name
    }
    catch
    {
        if ((Get-GraphError -ErrorRecord $_) -match 'does not exist')
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
        [Parameter(Mandatory)] [string] $GroupId
    )

    $all = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,displayName&`$top=999"

    do
    {
        $res = Invoke-WithRetry -OperationName "Get members ($GroupId)" -ScriptBlock {
            Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $script:GraphToken" }
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
            Write-Host '    Resolution returned multiple distinct devices. Use the FQDN in config.' -ForegroundColor DarkGray
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
#  "job failed, no output".
# ============================================================

try
{
    # ── Normalise variable names ──────────────────────────────────────────────
    # Called here (inside try) not at script scope. If it throws, the catch
    # below writes the exception to Write-Host before re-throwing.
    $ManagedIdentityClientId = Sanitize-InputString -Value $ManagedIdentityClientId
    $AutomationVariableNames = Sanitize-InputString -Value $AutomationVariableNames
    $AutomationVariableNames = NormalizeVariableNames -Names $AutomationVariableNames

    Log-Message -Level STATUS `
                -Message "========== Sync started | Variables: '$( $AutomationVariableNames -join "', '" )' | DefaultRemoveStale: $DefaultRemoveStale | WhatIf: $WhatIf ==========" `
                -InvocationName 'MAIN'

    # ── Auth ──────────────────────────────────────────────────────────────────

    Initialize-ManagedIdentityAuth
    Get-GraphToken | Out-Null   # prime the cache; calls read $script:GraphToken

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

    Log-Message -Level STATUS `
                -Message "Loaded $( $groupConfigs.Count ) group(s) with devices. $( $AutomationVariableNames.Count - $groupConfigs.Count ) skipped (empty or errored)." `
                -InvocationName 'MAIN'

    # ── Build Entra device index (single Graph call) ──────────────────────────

    $exactIndex, $shortIndex, $fuzzyList = Build-DeviceIndex

    # ── Process each group ────────────────────────────────────────────────────

    $groupResults = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($groupCfg in $groupConfigs)
    {
        $groupId = $groupCfg.GroupId
        $groupName = $groupCfg.Name
        $removeStale = $groupCfg.RemoveStale

        # Refresh the token if it is close to expiry — keeps long, many-group runs alive.
        Get-GraphToken | Out-Null

        Log-Message -Level STATUS `
                    -Message "--- Processing group '$groupName' ($groupId) | devices: $( $groupCfg.Devices.Count ) | removeStale: $removeStale ---" `
                    -InvocationName 'MAIN'

        $addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $pendingDevices = [System.Collections.Generic.List[string]]::new()
        $skippedDevices = [System.Collections.Generic.List[string]]::new()

        $currentMembers = Get-AllGroupMembers -GroupId $groupId
        $currentIds = @($currentMembers | Select-Object -ExpandProperty Id)

        $resolvedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($deviceName in $groupCfg.Devices)
        {
            $result = Resolve-Device -DeviceName $deviceName -ExactIndex $exactIndex -ShortIndex $shortIndex -FuzzyList $fuzzyList

            switch ($result.Status)
            {
                'Resolved'  {
                    foreach ($id in $result.Ids)
                    {
                        $resolvedDevices.Add([pscustomobject]@{ Id = $id; DisplayName = $deviceName })
                    }
                }
                'Pending'   { $script:PendingCount++; $pendingDevices.Add($deviceName) }
                'Ambiguous' { $skippedDevices.Add($deviceName) }
            }
        }

        $resolvedIds = @($resolvedDevices | Select-Object -ExpandProperty Id)

        foreach ($device in $resolvedDevices)
        {
            if ($currentIds -notcontains $device.Id)
            {
                try
                {
                    Add-DeviceToGroup -GroupId $groupId -DeviceId $device.Id
                    $addedDevices.Add($device)
                    Log-Message -Level INFO -Message "Added '$( $device.DisplayName )' ($( $device.Id )) to '$groupName'." -InvocationName 'MAIN'
                }
                catch
                {
                    $script:SyncErrorCount++
                    Log-Message -Level ERROR -Message "Failed to add '$( $device.DisplayName )' ($( $device.Id )) to '$groupName': $( Get-GraphError -ErrorRecord $_ )" -InvocationName 'MAIN'
                }
            }
            else
            {
                Log-Message -Level DEBUG -Message "'$( $device.DisplayName )' already in '$groupName'. Skipping." -InvocationName 'MAIN'
            }
        }

        if ($removeStale)
        {
            $staleMembers = @($currentMembers | Where-Object { $resolvedIds -notcontains $_.Id })
            $staleCount   = $staleMembers.Count
            $memberCount  = $currentMembers.Count
            $stalePercent = if ($memberCount -gt 0) { $staleCount / $memberCount } else { 0 }

            # ── Blast-radius guard ────────────────────────────────────────────
            # A truncated/corrupt config (or a bad bulk edit) could otherwise gut
            # a group in a single run. Trip only when BOTH thresholds are exceeded:
            # the percentage stops large-group wipeouts, the absolute floor stops
            # false positives on small groups. Genuine bulk removals must be staged
            # across multiple runs to stay under the limit. WhatIf bypasses the
            # guard since nothing is actually written.
            if (-not $WhatIf -and $staleCount -gt $StaleRemovalMinCount -and $stalePercent -gt $StaleRemovalMaxPercent)
            {
                $script:SyncErrorCount++
                Log-Message -Level ERROR `
                    -Message ("BLAST-RADIUS GUARD: '$groupName' would remove $staleCount of $memberCount member(s) ({0:P1}) — exceeds limit (>{1} devices AND >{2:P0}). Skipping ALL removals for this group; stage the change across multiple runs. Run will fail." -f $stalePercent, $StaleRemovalMinCount, $StaleRemovalMaxPercent) `
                    -InvocationName 'MAIN'
            }
            else
            {
                foreach ($member in $staleMembers)
                {
                    try
                    {
                        Remove-DeviceFromGroup -GroupId $groupId -DeviceId $member.Id
                        $removedDevices.Add($member)
                        Log-Message -Level INFO -Message "Removed stale '$( $member.DisplayName )' ($( $member.Id )) from '$groupName'." -InvocationName 'MAIN'
                    }
                    catch
                    {
                        $script:SyncErrorCount++
                        Log-Message -Level ERROR -Message "Failed to remove '$( $member.DisplayName )' ($( $member.Id )) from '$groupName': $( Get-GraphError -ErrorRecord $_ )" -InvocationName 'MAIN'
                    }
                }
            }
        }

        $finalMembers = Get-AllGroupMembers -GroupId $groupId

        Log-Message -Level STATUS `
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

    Log-Message -Level STATUS `
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
