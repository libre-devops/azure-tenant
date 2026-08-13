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

    There is no fuzzy tier. A prefix scan resolved a config entry of 'srv1'
    against a tenant holding only 'srv10.contoso.com', binding silently because
    the ambiguity guard only fired on multiple matches, and added the wrong host
    to an EDR policy group. Tiers 1 and 2 cover a hand-authored allowlist, so
    anything unmatched after tier 2 is Pending.

    MULTI-MATCH POLICY
    ──────────────────
    A device name may map to more than one Entra object ID. Two distinct cases:

      (a) Identical displayName duplicates — same physical device re-enrolled, the
          old synthetic object lingering beside the new one. Indistinguishable by
          name, so ALL matching IDs are added: the live object is always covered and
          the stale one in the group is harmless. Logged as WARN for cleanup.

      (b) Different FQDNs sharing a short name — genuinely different machines
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

    That routing is fixed. The RENDERING is selectable via -LogFormat:

    Text          Default. Byte-for-byte what this runbook has always emitted:
                  HH:mm:ss [InvocationName] Message, coloured on Write-Host.
    Json          One compact OpenTelemetry log record per line (newline
                  delimited JSON), matching LibreDevOpsHelpers.Logger so both
                  land in a backend under one schema. Colour is dropped so no
                  ANSI escape can corrupt a line something has to parse.
    JsonIndented  Pretty-printed, for reading by eye. NOT newline delimited, so
                  it is for local debugging and not for ingestion.

    Changing the format cannot change behaviour: it only changes the string that
    each level hands to its (unchanged) stream.

    The end-of-run summary follows the format too. In Text it is the ASCII
    banner it has always been. In Json it becomes one group_summary record per
    group plus one run_summary record, carrying the same envelope as every other
    line, so a whole run stays parseable end to end with no special cases.

.PARAMETER ManagedIdentityClientId
    Optional. Client ID of a User-Assigned Managed Identity attached to this
    Automation Account. Leave it blank (the default) to authenticate as the
    Automation Account's system-assigned managed identity: a blank job schedule
    field supplies an empty string, which is why this parameter is not Mandatory.
    When a value IS supplied it must be a GUID and it must work. There is no
    fallback to the system-assigned identity, because that is a different
    principal with potentially different group-write permissions.

.PARAMETER AutomationVariableNames
    Intentionally untyped. Azure Automation passes job schedule parameters as strings,
    so this arrives as System.String regardless of how the parameter is declared.
    NormalizeVariableNames splits and cleans it inside MAIN.

.PARAMETER DefaultRemoveStale
    Global fallback for removeStale when not specified per group. Default: $true.
    Do NOT pass from job schedule — [bool] binding from string is unreliable in
    Azure Automation. Change the default here if needed.

.PARAMETER MaxRetries / RetryDelaySeconds
    Retry configuration for TRANSIENT API failures only: 408, 429 and 5xx. A 403
    or a 404 throws on the first attempt rather than burning the budget on a
    verdict that will not change, and so does a failure that produced no HTTP
    response at all. A 401 gets one token force-refresh and one retry (see TOKEN
    HANDLING in .NOTES). Full detail in the Invoke-WithRetry docstring.

.PARAMETER LogFormat
    Text (default), Json, or JsonIndented. See LOGGING above for what each emits.
    Resolution order is this parameter, then $env:LOG_FORMAT, then Text, the
    same order LibreDevOpsHelpers.Logger uses.

    Unlike DefaultRemoveStale, this one IS safe to pass from a job schedule: it
    is a string, so the [bool]'false' binding trap cannot apply. That means the
    format can be changed from the schedule without republishing the runbook.
    An unrecognised value falls back to Text silently and deliberately. A typo in
    a logging preference must never stop a security control from running, and the
    resolved format is echoed in the startup STATUS line so it can be confirmed.

    OTel attributes are picked up from the environment when set: SERVICE_NAME
    (falls back to the invocation name), SERVICE_VERSION,
    DEPLOYMENT_ENVIRONMENT, TRACE_ID, SPAN_ID, CORRELATION_ID.
    When no correlation id is supplied, the Azure Automation job id is used, so
    every record from one hourly run shares a correlation_id out of the box.

.PARAMETER StaleRemovalMinCount / StaleRemovalMaxPercent
    Blast-radius guard for stale removal. A run that would remove MORE than
    StaleRemovalMinCount members AND MORE than StaleRemovalMaxPercent of a group's
    current DEVICE membership aborts removals for that group and fails the job.
    BOTH must be exceeded. Defaults: 5 devices and 0.20 (20%). The denominator is
    device members only, because group membership is read through the
    microsoft.graph.device cast, so 20% means 20% of the group's devices and not
    of its total membership. Stage genuine bulk removals across multiple runs so
    each stays under the limit. A WhatIf run bypasses the guard.

    DRY RUN
    There is no -WhatIf parameter. Set $WhatIfPreference = $true at script scope
    (the assignment sits just below the param block) for a no-write rehearsal.
    The two leaf write functions declare SupportsShouldProcess and gate every
    Graph write on $PSCmdlet.ShouldProcess, which reads that preference from the
    calling scope. It is deliberately not a parameter, for the same reason
    DefaultRemoveStale is not: Azure Automation binds job schedule parameters as
    strings and [bool]'false' is $true.

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

    Grant these to whichever principal the runbook actually authenticates as: the
    Automation Account's system-assigned managed identity by default, or the
    user-assigned identity whose client ID is passed in ManagedIdentityClientId.
    The two are different service principals and the grants do not follow the
    Automation Account, so moving between them means moving the app role
    assignments with it (see the Terraform in modules/foundation/main.tf).

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
# Optional, and deliberately NOT Mandatory: a blank job schedule field supplies
# an empty string, which Mandatory rejects. Blank means authenticate as the
# system-assigned managed identity. A supplied value must be a GUID and must
# work, there is no fallback. See Initialize-ManagedIdentityAuth.
    [string] $ManagedIdentityClientId = '',

# Intentionally untyped — arrives as System.String from job schedule.
# NormalizeVariableNames handles splitting inside MAIN.
    [Parameter(Mandatory)]
    $AutomationVariableNames,

# Do NOT pass this from the job schedule — [bool] from string is unreliable.
    [bool] $DefaultRemoveStale = $true,

    [int] $MaxRetries = 6,
    [int] $RetryDelaySeconds = 20,

# Log rendering format: Text (default), Json, or JsonIndented. Text is exactly
# what this runbook has always emitted. Deliberately NOT ValidateSet and
# deliberately silent on an unrecognised value: a typo in a schedule field must
# fall back to Text and let the sync run, never fail the security control over a
# logging preference. Unlike DefaultRemoveStale this IS safe to pass from a job
# schedule, because it is a string and the [bool]'false' problem cannot apply.
    [string] $LogFormat = '',

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

# ShouldProcess must never attempt a prompt in the Automation sandbox: there is
# no console to answer it and the attempt throws under -EAP Stop. Two guards.
# First, Add-DeviceToGroup and Remove-DeviceFromGroup declare ConfirmImpact
# Medium, which is below the default $ConfirmPreference of High. Second, this
# line, in case a host or a caller ever ships a lower default.
$ConfirmPreference = 'None'

# Dry run switch. $true means nothing is written to any group: ShouldProcess in
# the two leaf write functions reads this preference from the calling scope and
# returns false, so both return before touching Graph. Set in source rather than
# taken as a parameter, because Azure Automation binds job schedule parameters as
# strings and [bool]'false' is $true, which would silently no-op the whole run.
$WhatIfPreference = $false

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
#
#  ROUTING IS FIXED, RENDERING IS NOT.
#  The stream each level goes to is a hard constraint of this runbook and does
#  NOT vary with the log format. ERROR in particular stays on Write-Host in every
#  format: Write-Error terminates under $ErrorActionPreference = 'Stop' and would
#  defeat the count-and-continue design. A format only changes how a line is
#  RENDERED, so switching to JSON can never alter control flow.
# ============================================================

# OpenTelemetry SeverityNumber per level, matching LibreDevOpsHelpers.Logger.
# STATUS is this runbook's own milestone level and has no OTel equivalent. That
# is fine and is what the spec intends: SeverityText carries the source's own
# vocabulary while SeverityNumber is the normalised value, so STATUS keeps its
# name and sorts at INFO severity. A backend can filter severity_number >= 9
# without knowing anything about this script's level names.
$script:SeverityNumbers = @{ DEBUG = 5; INFO = 9; STATUS = 9; WARN = 13; ERROR = 17 }

# Format resolution, in order: -LogFormat parameter, $env:LOG_FORMAT, Text.
# Same switch -Regex idiom and the same silent fallback as the helper module, so
# an unrecognised value degrades to the human format instead of failing the job.
# Resolved HERE, at script scope above every function, because the first
# Log-Message call happens inside NormalizeVariableNames before MAIN's try block
# is even entered. Assignments only: nothing on this path can throw at a point
# where no logging is available yet.
$script:LogFormat = switch -Regex ("$( if ($LogFormat) { $LogFormat } else { $env:LOG_FORMAT } )".Trim().Trim('"'))
{
    '^(?i)jsonindented$' { 'JsonIndented'; break }
    '^(?i)json$'         { 'Json'; break }
    default              { 'Text' }
}

# Ambient trace context, stamped onto every JSON record when set and omitted when
# empty. Seeded from the environment so records emitted here join a trace started
# by a parent process. Note the names are UNPREFIXED (TRACE_ID, not LDO_TRACE_ID)
# so a host configured for LibreDevOpsHelpers.Logger does not configure this
# script by accident, or vice versa. correlation_id falls
# back to the Azure Automation job id, which ties every line of a single hourly
# run together with no configuration at all. $PSPrivateMetadata exists only
# inside the Automation sandbox, so probe for it: under StrictMode Latest a bare
# reference to a missing variable throws.
$script:TraceContext = @{
    trace_id       = if ($env:TRACE_ID) { $env:TRACE_ID } else { '' }
    span_id        = if ($env:SPAN_ID) { $env:SPAN_ID } else { '' }
    correlation_id = if ($env:CORRELATION_ID) { $env:CORRELATION_ID } else { '' }
}

if (-not $script:TraceContext.correlation_id)
{
    $automationJob = Get-Variable -Name 'PSPrivateMetadata' -ErrorAction SilentlyContinue
    if ($automationJob -and
        $automationJob.Value -and
        $automationJob.Value.PSObject.Properties['JobId'] -and
        $automationJob.Value.JobId)
    {
        $script:TraceContext.correlation_id = [string]$automationJob.Value.JobId
    }
}

function Format-OtelLogRecord
{
    <#
    .SYNOPSIS
        Renders one log record as the OpenTelemetry-shaped JSON object used by
        LibreDevOpsHelpers.Logger.
    .DESCRIPTION
        Field order follows the OTel log data model: timestamp, level,
        severity_number, message, then service and resource attributes, then
        trace context, then any caller-supplied attributes.

        service.name falls back to the invocation name when SERVICE_NAME is
        unset, and service.version / deployment.environment appear only when
        their environment variables are set, all exactly as the helper module
        does it, so records from this runbook sit alongside records from the
        helper without a backend needing to understand two schemas.

        Every statement here either assigns or returns. Nothing may reach the
        success stream by accident, because this function's return value IS the
        log line.
    #>
    param (
        [string]    $Level,
        [string]    $Message,
        [string]    $InvocationName,

        # IDictionary, not [hashtable]: an [ordered]@{} cast to [hashtable] loses
        # its ordering, which would scramble attribute order in every record.
        [System.Collections.IDictionary] $Data
    )

    $serviceName = if ($env:SERVICE_NAME)
    {
        $env:SERVICE_NAME
    }
    else
    {
        $InvocationName
    }

    $record = [ordered]@{
        timestamp       = [datetime]::UtcNow.ToString('o')
        level           = $Level
        severity_number = $script:SeverityNumbers[$Level]
        message         = $Message
        'service.name'  = $serviceName
        invocation      = $InvocationName
    }

    if ($env:SERVICE_VERSION)        { $record['service.version'] = $env:SERVICE_VERSION }
    if ($env:DEPLOYMENT_ENVIRONMENT) { $record['deployment.environment'] = $env:DEPLOYMENT_ENVIRONMENT }

    if ($script:TraceContext.trace_id)       { $record['trace_id'] = $script:TraceContext.trace_id }
    if ($script:TraceContext.span_id)        { $record['span_id'] = $script:TraceContext.span_id }
    if ($script:TraceContext.correlation_id) { $record['correlation_id'] = $script:TraceContext.correlation_id }

    if ($Data)
    {
        foreach ($key in $Data.Keys)
        {
            $record[[string]$key] = $Data[$key]
        }
    }

    if ($script:LogFormat -eq 'JsonIndented')
    {
        return ($record | ConvertTo-Json -Depth 10)
    }

    return ($record | ConvertTo-Json -Depth 10 -Compress)
}

function Write-LogHostLine
{
    <#
    .SYNOPSIS
        Emits a STATUS or ERROR line via Write-Host, colourless in JSON mode.
    .DESCRIPTION
        Write-Host in BOTH formats, deliberately. It is the only stream that is
        always visible in the Automation portal without verbose enabled, and it
        never touches the success pipeline. Only the colour changes: an ANSI
        escape sequence wrapped around a JSON line is exactly the sort of thing
        that makes a log backend drop the record, so colour is Text mode only.
    #>
    param (
        [AllowEmptyString()] [string] $Line,
        [System.ConsoleColor] $Color
    )

    if ($script:LogFormat -eq 'Text')
    {
        Write-Host $Line -ForegroundColor $Color
    }
    else
    {
        Write-Host $Line
    }
}

function Log-Message
{
    <#
    .SYNOPSIS
        The single logging entry point. Fixed routing, switchable rendering.
    .PARAMETER Data
        Optional structured attributes merged into the JSON record. Ignored in
        Text mode, so a caller can attach detail for a log backend without
        changing a single character of what operators read in the portal today.
    #>
    param (
        [ValidateSet('DEBUG', 'INFO', 'STATUS', 'WARN', 'ERROR')]
        [string] $Level,
        [string] $Message,
        [string] $InvocationName,
        [System.Collections.IDictionary] $Data
    )

    $line = if ($script:LogFormat -eq 'Text')
    {
        "$( Get-Date -Format 'HH:mm:ss' ) [$InvocationName] $Message"
    }
    else
    {
        Format-OtelLogRecord -Level $Level -Message $Message -InvocationName $InvocationName -Data $Data
    }

    switch ($Level)
    {
        'DEBUG'  {
            Write-Verbose $line
        }                                           # All Logs only — low-level detail
        'INFO'   {
            Write-Verbose $line
        }                                           # All Logs only — operational steps (verbose)
        'STATUS' {
            Write-LogHostLine -Line $line -Color Cyan
        }              # Always visible — milestone/audit baseline
        'WARN'   {
            Write-Warning $line
        }                                           # Warnings tab + All Logs
        'ERROR'  {
            Write-LogHostLine -Line $line -Color Red
        }               # Always visible — non-terminating (Write-Error throws under -EAP Stop)
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

    # The leading comma is load-bearing. A bare 'return $Names' unrolls a
    # single-element array to a scalar String on the way out, and MAIN then
    # reads $AutomationVariableNames.Count, which throws under StrictMode
    # Latest because a scalar has no Count. That is a crash for any tenant
    # configured with exactly ONE Automation Variable. The comma wraps the
    # array so one level of unrolling hands the caller the array itself.
    return ,$Names
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

    # Remove wrapping quotes repeatedly (handles ""value"" cases).
    # The length guard is load-bearing: a lone " satisfies BOTH StartsWith and
    # EndsWith, so Substring(1, $Value.Length - 2) becomes Substring(1, -1) and
    # throws. Anything shorter than two characters cannot be quote-wrapped.
    while ($Value.Length -ge 2 -and $Value.StartsWith('"') -and $Value.EndsWith('"'))
    {
        $Value = $Value.Substring(1, $Value.Length - 2).Trim()
    }

    if ($original -ne $Value)
    {
        Write-Verbose "Sanitized input: '$original' → '$Value'"
    }

    return $Value
}

function Get-GraphErrorInfo
{
    <#
    .SYNOPSIS
        Decomposes a failed Graph call into status code, error code and text.
    .DESCRIPTION
        In PowerShell 7, Invoke-RestMethod puts only the generic ".NET status
        code" text in $_.Exception.Message. The actual Graph error body, the bit
        you care about (error.code + error.message, e.g.
        'Authorization_RequestDenied'), lives in $_.ErrorDetails.Message.

        Returns one object so callers can branch on the machine-readable parts
        rather than pattern-matching the prose. Graph's wording is not
        contractual and has changed before:

          Status  [int]    HTTP status. 0 means the call never produced a
                           response at all (socket reset, DNS, TLS) as opposed
                           to a Graph error.
          Code    [string] Graph error.code, '' when the body was not a Graph
                           error object.
          Message [string] Graph error.message, '' likewise.
          Text    [string] The human-readable one-liner used in log output.

        Every property read goes through PSObject.Properties: under
        Set-StrictMode -Version Latest, referencing a property that is not there
        throws instead of returning $null.
    #>
    param ($ErrorRecord)

    $resp = $null
    if ($ErrorRecord.Exception.PSObject.Properties['Response'])
    {
        $resp = $ErrorRecord.Exception.Response
    }
    $status = if ($resp) { [int]$resp.StatusCode } else { 0 }

    # Keep the original log format: no response reads as 'HTTP ?', not 'HTTP 0'.
    $shown = if ($status -eq 0) { '?' } else { $status }

    $code = ''
    $message = ''
    $text = ''

    # ErrorDetails is null whenever the failure carried no response body: a
    # transport error, or a bare 404. Reading .Message off that null throws
    # PropertyNotFoundException under StrictMode Latest, FROM INSIDE the error
    # handler, which masks the real error exactly like the old Retry-After
    # indexer did. Probe before reading.
    $detail = ''
    if ($ErrorRecord.PSObject.Properties['ErrorDetails'] -and $ErrorRecord.ErrorDetails)
    {
        $detail = [string]$ErrorRecord.ErrorDetails.Message
    }

    if ($detail)
    {
        try
        {
            $j = $detail | ConvertFrom-Json
            if ($j.PSObject.Properties['error'] -and $j.error)
            {
                if ($j.error.PSObject.Properties['code'])
                {
                    $code = [string]$j.error.code
                }
                if ($j.error.PSObject.Properties['message'])
                {
                    $message = [string]$j.error.message
                }
            }
        }
        catch { }   # body wasn't JSON, so leave code/message empty and show it raw

        $text = if ($code)
        {
            "HTTP $shown | $( $code ): $( $message )"
        }
        else
        {
            "HTTP $shown | $detail"
        }
    }
    else
    {
        $text = "HTTP $shown | $( $ErrorRecord.Exception.Message )"
    }

    return [pscustomobject]@{
        Status  = $status
        Code    = $code
        Message = $message
        Text    = $text
    }
}

function Get-GraphError
{
    <#
    .SYNOPSIS
        Human-readable one-liner for a failed Graph call, for log output.
    .DESCRIPTION
        Thin wrapper over Get-GraphErrorInfo. Use this inside log strings. Use
        Get-GraphErrorInfo when you need to BRANCH on the status or error code,
        which is the only supported way to recognise a specific failure.
    #>
    param ($ErrorRecord)

    return (Get-GraphErrorInfo -ErrorRecord $ErrorRecord).Text
}

# ============================================================
#  AUTH
# ============================================================

function Initialize-ManagedIdentityAuth
{
    <#
    .SYNOPSIS
        Authenticates as a managed identity, system-assigned by default.
    .DESCRIPTION
        A blank ManagedIdentityClientId (the default, and what an empty job
        schedule field supplies) connects with -Identity and no -AccountId, so
        the sandbox resolves the Automation Account's system-assigned identity.

        A supplied client ID is validated as a GUID and then used as-is. There is
        deliberately NO fallback: the previous behaviour, warning and retrying
        without -AccountId, silently authenticated as a DIFFERENT principal with
        potentially different group-write permissions. If a specific UAMI was
        asked for and cannot be used, that is fatal.
    #>
    try
    {
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        if ([string]::IsNullOrWhiteSpace($ManagedIdentityClientId))
        {
            Log-Message -Level INFO `
                        -Message 'No ManagedIdentityClientId supplied. Authenticating via the system-assigned Managed Identity...' `
                        -InvocationName $MyInvocation.MyCommand.Name

            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        }
        else
        {
            $parsedClientId = [guid]::Empty
            if (-not [guid]::TryParse($ManagedIdentityClientId, [ref]$parsedClientId))
            {
                throw "ManagedIdentityClientId '$ManagedIdentityClientId' is not a valid GUID. Supply the client ID of a User-Assigned Managed Identity attached to this Automation Account, or leave it blank to use the system-assigned identity."
            }

            Log-Message -Level INFO `
                        -Message "Authenticating via User-Assigned Managed Identity (ClientId: $ManagedIdentityClientId)..." `
                        -InvocationName $MyInvocation.MyCommand.Name

            Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -ErrorAction Stop | Out-Null
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

        # Under Set-StrictMode -Version Latest, referencing a missing property
        # THROWS rather than returning $null — so probe for existence via PSObject
        # before reading ExpiresOn. This lets the conservative fallback actually
        # fire if a module bump ever drops or renames the property.
        $hasExpiry = $tokenResponse.PSObject.Properties['ExpiresOn'] -and $tokenResponse.ExpiresOn
        $script:GraphTokenExpiresOn = if ($hasExpiry)
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
    <#
    .SYNOPSIS
        Runs a Graph call, retrying only failures that could plausibly succeed.
    .DESCRIPTION
        RETRYABLE
            408 (request timeout), 429 (throttled) and 5xx (server side).

        NOT RETRYABLE
            Everything else, Status 0 included. A 403 or a 404 throws on the
            first attempt: the verdict will not be different on attempt six, and
            burning MaxRetries * RetryDelaySeconds (six attempts at twenty
            seconds) per device across a few hundred devices is a plausible route
            to the three hour cloud job cap.

        401 IS SPECIAL
            A 401 mid-run normally means the token expired during a long job. It
            gets ONE force-refresh and ONE retry rather than the full retry
            budget: if a freshly minted token is still rejected then the grant is
            wrong, not the token, and waiting will not fix it. Graph calls read
            $script:GraphToken directly, so the retry picks up the new token.
    #>
    param (
        [scriptblock] $ScriptBlock,
        [string]      $OperationName = 'Operation'
    )

    $authRefreshed = $false

    for ($i = 1; $i -le $MaxRetries; $i++)
    {
        try
        {
            return & $ScriptBlock
        }
        catch
        {
            $err = Get-GraphErrorInfo -ErrorRecord $_
            $msg = $err.Text
            $statusCode = $err.Status
            $retryAfter = $null

            $resp = if ($_.Exception.PSObject.Properties['Response']) { $_.Exception.Response } else { $null }

            # Refresh failures are swallowed: the retry surfaces the real error
            # if auth is genuinely broken.
            if ($statusCode -eq 401)
            {
                if ($authRefreshed -or $i -eq $MaxRetries)
                {
                    Log-Message -Level ERROR `
                                -Message "FAILED: $OperationName | still 401 after a token refresh, so this is a permissions problem and not an expiry one. | $msg" `
                                -InvocationName $MyInvocation.MyCommand.Name
                    throw
                }

                $authRefreshed = $true
                Log-Message -Level WARN -Message "401 on '$OperationName': refreshing Graph token and retrying once." -InvocationName $MyInvocation.MyCommand.Name
                try { Get-GraphToken -Force | Out-Null } catch { }
                continue
            }

            # Anything deterministic is thrown straight back to the caller, which
            # counts it and moves on to the next device or group.
            #
            # Status 0 is NOT retried. It means the call produced no HTTP response
            # object at all: a transport failure, or a bug in the scriptblock
            # itself raising a plain exception. Retrying a bug six times at twenty
            # seconds a go just burns the job clock, and the hourly schedule is
            # already the retry for a genuine network blip.
            $isRetryable = ($statusCode -eq 408) -or
                           ($statusCode -eq 429) -or
                           ($statusCode -ge 500 -and $statusCode -le 599)

            if (-not $isRetryable)
            {
                Log-Message -Level ERROR `
                            -Message "FAILED (non-retryable, attempt $i of $MaxRetries): $OperationName | $msg" `
                            -InvocationName $MyInvocation.MyCommand.Name
                throw
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
    }

    # WARN on true duplicates (identical displayName, >1 object) so operators can clean up.
    foreach ($kv in $exactIndex.GetEnumerator())
    {
        if ($kv.Value.Count -gt 1)
        {
            Log-Message -Level WARN -Message "Duplicate Entra displayName '$( $kv.Key )' → $( $kv.Value.Count ) objects ($( $kv.Value -join ', ' )). All will be synced to keep the live object covered; clean up stale duplicates in Entra." -InvocationName 'Build-DeviceIndex'
        }
    }

    Log-Message -Level INFO -Message "Built exact index ($( $exactIndex.Count ) names) and short index ($( $shortIndex.Count ) names)." -InvocationName 'Build-DeviceIndex'

    return $exactIndex, $shortIndex
}

function Resolve-Device
{
    <#
    .SYNOPSIS
        Maps one configured device name onto Entra device object IDs.
    .DESCRIPTION
        Two tiers only, both O(1) hashtable lookups: exact displayName, then
        pre-dot short name. Anything that survives both is Pending, not fuzzy
        matched. See RESOLUTION ORDER in the file header for why the prefix scan
        was removed.
    #>
    param (
        [string]    $DeviceName,
        [hashtable] $ExactIndex,
        [hashtable] $ShortIndex
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

    # Neither tier matched. Pending is the safe answer: the device may simply not
    # have propagated into Entra yet, and the next run will pick it up. Guessing
    # by prefix is what put the wrong host in an EDR policy group.
    Log-Message -Level WARN -Message "Could not resolve '$DeviceName' in Entra ID — pending registration. Will retry next run." -InvocationName 'Resolve-Device'
    return [pscustomobject]@{ Status = 'Pending'; Ids = @() }
}

# ============================================================
#  GROUP OPS
# ============================================================

function Add-DeviceToGroup
{
    <#
    .SYNOPSIS
        Adds one device object to one group. A leaf write.
    .DESCRIPTION
        SupportsShouldProcess is declared HERE and nowhere else (not at script
        scope, not on MAIN) so there is exactly one gate per write and no nested
        skip behaviour. ConfirmImpact is Medium, below the default High, so
        ShouldProcess can never try to prompt: a prompt in the Automation sandbox
        would throw under $ErrorActionPreference = 'Stop'.

        Invoke-RestMethod is not ShouldProcess-aware, so nothing propagates for
        free. The gate below is what makes a dry run a dry run.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param ($GroupId, $DeviceId, [string] $DisplayName = '')

    $target = if ($DisplayName)
    {
        "$DisplayName ($DeviceId) in group $GroupId"
    }
    else
    {
        "device $DeviceId in group $GroupId"
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Add group member'))
    {
        Log-Message -Level INFO -Message "[WHATIF] Would add $target." -InvocationName $MyInvocation.MyCommand.Name
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
        # Graph answers a duplicate member reference with HTTP 400 and error code
        # 'Request_BadRequest'. Key on those, NOT on the words 'already exist' in
        # the message: the wording is not contractual and will change.
        #
        # Request_BadRequest is a broad code, so this also absorbs a malformed
        # request for the same device. That is acceptable here because $DeviceId
        # always comes out of the Entra device index and is therefore a real
        # directory object, and the full Graph text is logged either way.
        $err = Get-GraphErrorInfo -ErrorRecord $_
        if ($err.Status -eq 400 -and $err.Code -eq 'Request_BadRequest')
        {
            Log-Message -Level DEBUG -Message "Device $DeviceId already a member of $GroupId (race condition, safe to ignore). Graph said: $( $err.Text )" -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Remove-DeviceFromGroup
{
    <#
    .SYNOPSIS
        Removes one device object from one group. A leaf write.
    .DESCRIPTION
        Same gating contract as Add-DeviceToGroup: SupportsShouldProcess is
        declared here only, ConfirmImpact stays below $ConfirmPreference so it
        never prompts, and the explicit ShouldProcess call is what stops the
        write, because Invoke-RestMethod knows nothing about WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param ($GroupId, $DeviceId, [string] $DisplayName = '')

    $target = if ($DisplayName)
    {
        "$DisplayName ($DeviceId) in group $GroupId"
    }
    else
    {
        "device $DeviceId in group $GroupId"
    }

    if (-not $PSCmdlet.ShouldProcess($target, 'Remove group member'))
    {
        Log-Message -Level INFO -Message "[WHATIF] Would remove $target." -InvocationName $MyInvocation.MyCommand.Name
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
        # 404 means the reference is already gone, which is the outcome we wanted.
        # Key on the status, NOT on the words 'does not exist'. A 404 cannot mean
        # a missing GROUP here: Get-AllGroupMembers reads the same group first and
        # a failure there takes the whole group down the per-group catch instead.
        $err = Get-GraphErrorInfo -ErrorRecord $_
        if ($err.Status -eq 404)
        {
            Log-Message -Level DEBUG -Message "Device $DeviceId already removed from $GroupId (safe to ignore). Graph said: $( $err.Text )" -InvocationName $MyInvocation.MyCommand.Name
            return
        }
        throw
    }
}

function Get-AllGroupMembers
{
    <#
    .SYNOPSIS
        Returns the DEVICE members of a group, and nothing else.
    .DESCRIPTION
        The URI carries the OData cast /members/microsoft.graph.device, so users,
        nested groups and service principals never come back. That is not a
        tidiness choice. Stale removal is a set difference against a device-only
        resolved set, and nothing in this script inspects @odata.type, so a plain
        /members read would classify every non-device member of a target group as
        stale and delete it.

        Two knock-on effects of the cast:

          1. The blast-radius guard denominator is device members, not total
             membership. StaleRemovalMaxPercent of 0.20 therefore means 20% of
             the group's DEVICES.
          2. The CURRENT DEVICE MEMBERS block in the summary report (which was
             ALL CURRENT GROUP MEMBERS) lists devices only, so a group's true
             membership may be larger than the count printed there.
    #>
    param (
        [Parameter(Mandatory)] [string] $GroupId
    )

    $all = [System.Collections.Generic.List[pscustomobject]]::new()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/microsoft.graph.device?`$select=id,displayName&`$top=999"

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

    Log-Message -Level INFO -Message "Fetched $( $all.Count ) device member(s) for group $GroupId." -InvocationName 'Get-AllGroupMembers'
    return $all.ToArray()
}

# ============================================================
#  SUMMARY REPORT
# ============================================================

function Get-DeviceAttributeList
{
    <#
    .SYNOPSIS
        Projects Id/DisplayName device objects into snake_case JSON attributes.
    .DESCRIPTION
        The in-memory objects use PascalCase because that is PowerShell's idiom.
        The emitted record uses snake_case because that is what the rest of the
        OTel attributes use, and one record should not mix two conventions.
    #>
    param ([object[]] $Devices)

    # Guard before touching .Count: member enumeration on an empty or null array
    # throws under StrictMode Latest.
    if (-not $Devices -or $Devices.Count -eq 0)
    {
        return ,@()
    }

    # Both returns are comma-wrapped, and it is load-bearing on BOTH. A bare
    # 'return @(...)' unrolls on the way out, so a group with exactly one added
    # device would serialise as a JSON object and a group with two would
    # serialise as an array. That inconsistent shape is what makes a log backend
    # reject the document with a field type conflict, and it would only show up
    # in production on the first single-device group.
    return ,@($Devices | ForEach-Object { [ordered]@{ id = $_.Id; display_name = $_.DisplayName } })
}

function Write-SyncSummaryRecords
{
    <#
    .SYNOPSIS
        Emits the sync summary as structured records rather than an ASCII banner.
    .DESCRIPTION
        One record per group, then one run-level record, all emitted through
        Log-Message so they carry the same OTel envelope (timestamp, level,
        severity_number, service.name, trace context) as every other line in the
        job. That is the whole point: a run's summary is queryable in the same
        index, by the same fields, as the events that produced it.

        Records are tagged with an 'event' attribute, group_summary or
        run_summary, so a backend can select them without pattern-matching the
        message text, which is the same reason the Graph error handling keys on
        status codes rather than prose.

        STATUS level, so the summary is always visible without verbose enabled,
        exactly like the banner it replaces.
    #>
    param (
        [object[]] $GroupResults,
        [int]      $TotalErrors
    )

    foreach ($r in $GroupResults)
    {
        Log-Message -Level STATUS `
                    -Message "Group summary: $( $r.Name )" `
                    -InvocationName 'Write-SyncSummary' `
                    -Data ([ordered]@{
                        event               = 'group_summary'
                        group_id            = $r.GroupId
                        group_name          = $r.Name
                        source_variable     = $r.SourceVar
                        failed              = [bool]$r.Failed
                        device_member_count = $r.FinalMembers.Count
                        added_count         = $r.Added.Count
                        removed_count       = $r.Removed.Count
                        pending_count       = $r.Pending.Count
                        skipped_count       = $r.Skipped.Count
                        added               = Get-DeviceAttributeList -Devices $r.Added
                        removed             = Get-DeviceAttributeList -Devices $r.Removed
                        pending             = @($r.Pending)
                        skipped             = @($r.Skipped)
                        device_members      = Get-DeviceAttributeList -Devices $r.FinalMembers
                    })
    }

    # Measure-Object returns $null for Sum over an empty set, so cast: a JSON
    # null total would be indistinguishable from 'not measured' at the backend.
    $totalAdded   = [int]($GroupResults | ForEach-Object { $_.Added.Count }   | Measure-Object -Sum).Sum
    $totalRemoved = [int]($GroupResults | ForEach-Object { $_.Removed.Count } | Measure-Object -Sum).Sum

    Log-Message -Level STATUS `
                -Message 'Sync summary' `
                -InvocationName 'Write-SyncSummary' `
                -Data ([ordered]@{
                    event         = 'run_summary'
                    whatif        = [bool]$WhatIfPreference
                    group_count   = $GroupResults.Count
                    failed_groups = @($GroupResults | Where-Object { $_.Failed }).Count
                    total_added   = $totalAdded
                    total_removed = $totalRemoved
                    total_pending = $script:PendingCount
                    total_errors  = $TotalErrors
                })
}

function Write-SyncSummary
{
    <#
    .SYNOPSIS
        Writes the end-of-run summary in whichever format is configured.
    .DESCRIPTION
        Text renders the ASCII banner below, unchanged, and is the default. Json
        and JsonIndented hand off to Write-SyncSummaryRecords so the summary
        joins the newline-delimited stream instead of interrupting it with 70
        columns of box drawing.
    #>
    param (
        [object[]] $GroupResults,
        [int]      $TotalErrors
    )

    if ($script:LogFormat -ne 'Text')
    {
        Write-SyncSummaryRecords -GroupResults $GroupResults -TotalErrors $TotalErrors
        return
    }

    $sep = '=' * 72

    Write-Host ''
    Write-Host $sep                                           -ForegroundColor Cyan
    Write-Host '  SYNC SUMMARY REPORT'                       -ForegroundColor Cyan
    Write-Host "  $( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' )" -ForegroundColor Cyan
    Write-Host "  WhatIf Mode : $WhatIfPreference"          -ForegroundColor Cyan
    Write-Host $sep                                           -ForegroundColor Cyan

    foreach ($r in $GroupResults)
    {
        Write-Host ''
        Write-Host "  GROUP : $( $r.Name )"  -ForegroundColor Cyan
        Write-Host "  ID    : $( $r.GroupId )"
        Write-Host "  VAR   : $( $r.SourceVar )"
        Write-Host "  $( '-' * 68 )"

        # A group that threw is still reported, so a failure in group 2 of 6 is
        # visible rather than silently absent. Its counts are whatever had been
        # done before the throw.
        if ($r.Failed)
        {
            Write-Host '  STATUS: FAILED. Processing stopped early, counts below are partial.' -ForegroundColor Red
            Write-Host ''
        }

        # Devices only: membership is read through the microsoft.graph.device
        # cast, so users and nested groups in this group are not listed here.
        Write-Host "  CURRENT DEVICE MEMBERS ($( $r.FinalMembers.Count ))" -ForegroundColor Yellow
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
                -Message "========== Sync started | Variables: '$( $AutomationVariableNames -join "', '" )' | DefaultRemoveStale: $DefaultRemoveStale | WhatIf: $WhatIfPreference | LogFormat: $script:LogFormat ==========" `
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

            # 'name' is documented as OPTIONAL, so probe for it rather than
            # reading it: under StrictMode Latest a missing property throws, and
            # ?? does not rescue that because the property access throws first.
            # Resolved once, up here, because both the skip path below and every
            # log line after it want it.
            $displayName = if ($cfg.PSObject.Properties['name'] -and $cfg.name)
            {
                $cfg.name
            }
            else
            {
                $cfg.groupId
            }

            # Empty devices array = group not yet configured. Skip with WARN — not an error.
            # This allows partial rollout without failing the job and firing the monitor alert.
            if (-not $cfg.devices -or @($cfg.devices).Count -eq 0)
            {
                Log-Message -Level WARN -Message "Variable '$varName' has no devices configured — skipping group '$displayName'. Add devices to the JSON to enable sync." -InvocationName 'MAIN'
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

            # Validate every device name HERE, before it can reach resolution.
            # A null, empty or whitespace-only entry is a config typo (a trailing
            # comma, a blank line left in a bulk edit), never an instruction, so
            # drop it with a WARN and keep the rest of the group.
            $validDevices = [System.Collections.Generic.List[string]]::new()

            foreach ($entry in @($cfg.devices))
            {
                $deviceName = ([string]$entry).Trim()

                if ([string]::IsNullOrWhiteSpace($deviceName))
                {
                    Log-Message -Level WARN -Message "Variable '$varName' contains a null, empty or whitespace-only device entry, ignoring it. Fix the JSON for group '$displayName'." -InvocationName 'MAIN'
                    continue
                }

                $validDevices.Add($deviceName)
            }

            if ($validDevices.Count -eq 0)
            {
                Log-Message -Level WARN -Message "Variable '$varName' has no usable device names after validation. Skipping group '$displayName'." -InvocationName 'MAIN'
                continue
            }

            $groupConfigs.Add([pscustomobject]@{
                GroupId = $cfg.groupId
                Name = $displayName
                Devices = $validDevices.ToArray()
                RemoveStale = $removeStale
                SourceVar = $varName
            })

            Log-Message -Level INFO -Message "Loaded group '$displayName' from '$varName' ($( $validDevices.Count ) device(s), removeStale=$removeStale)." -InvocationName 'MAIN'
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

    $exactIndex, $shortIndex = Build-DeviceIndex

    # ── Process each group ────────────────────────────────────────────────────

    $groupResults = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($groupCfg in $groupConfigs)
    {
        $groupId = $groupCfg.GroupId
        $groupName = $groupCfg.Name
        $removeStale = $groupCfg.RemoveStale

        # Declared OUTSIDE the try so the per-group catch below can still report
        # whatever had been done before the failure.
        $addedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $removedDevices = [System.Collections.Generic.List[pscustomobject]]::new()
        $pendingDevices = [System.Collections.Generic.List[string]]::new()
        $skippedDevices = [System.Collections.Generic.List[string]]::new()

        # Per-group isolation. Get-AllGroupMembers has no try/catch of its own, so
        # exhausting its retries on group 2 of 6 unwound all the way to the
        # top-level catch and groups 3 to 6 were never processed at all. One bad
        # group must not take the rest of the tenant's policy targeting with it.
        # The job still fails at the end, but only after every group has had its
        # turn.
        try
        {
            # Refresh the token if it is close to expiry — keeps long, many-group runs alive.
            Get-GraphToken | Out-Null

            Log-Message -Level STATUS `
                        -Message "--- Processing group '$groupName' ($groupId) | devices: $( $groupCfg.Devices.Count ) | removeStale: $removeStale ---" `
                        -InvocationName 'MAIN'

            $currentMembers = Get-AllGroupMembers -GroupId $groupId

            # Set membership, not -notcontains. The two array scans this replaces
            # were O(n) each, inside a loop over m devices, so the diff was
            # O(n*m) while every other lookup on the resolution path is a
            # hashtable. OrdinalIgnoreCase because these are GUID strings whose
            # casing is not guaranteed to be stable between Graph responses.
            $currentIdSet = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]@($currentMembers | Select-Object -ExpandProperty Id),
                    [System.StringComparer]::OrdinalIgnoreCase)

            $resolvedDevices = [System.Collections.Generic.List[pscustomobject]]::new()

            foreach ($deviceName in $groupCfg.Devices)
            {
                $result = Resolve-Device -DeviceName $deviceName -ExactIndex $exactIndex -ShortIndex $shortIndex

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

            $resolvedIdSet = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]@($resolvedDevices | Select-Object -ExpandProperty Id),
                    [System.StringComparer]::OrdinalIgnoreCase)

            foreach ($device in $resolvedDevices)
            {
                if (-not $currentIdSet.Contains($device.Id))
                {
                    try
                    {
                        Add-DeviceToGroup -GroupId $groupId -DeviceId $device.Id -DisplayName $device.DisplayName
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
                $staleMembers = @($currentMembers | Where-Object { -not $resolvedIdSet.Contains($_.Id) })
                $staleCount   = $staleMembers.Count
                $memberCount  = $currentMembers.Count
                $stalePercent = if ($memberCount -gt 0) { $staleCount / $memberCount } else { 0 }

                # ── Blast-radius guard ────────────────────────────────────────
                # A truncated/corrupt config (or a bad bulk edit) could otherwise gut
                # a group in a single run. Trip only when BOTH thresholds are exceeded:
                # the percentage stops large-group wipeouts, the absolute floor stops
                # false positives on small groups. Genuine bulk removals must be staged
                # across multiple runs to stay under the limit. A WhatIf run bypasses
                # the guard since nothing is actually written.
                # Note the denominator: $currentMembers is device members only, so
                # the percentage is of the group's devices, not its total membership.
                if (-not $WhatIfPreference -and $staleCount -gt $StaleRemovalMinCount -and $stalePercent -gt $StaleRemovalMaxPercent)
                {
                    $script:SyncErrorCount++
                    Log-Message -Level ERROR `
                        -Message ("BLAST-RADIUS GUARD: '$groupName' would remove $staleCount of $memberCount device member(s) ({0:P1}) — exceeds limit (>{1} devices AND >{2:P0}). Skipping ALL removals for this group; stage the change across multiple runs. Run will fail." -f $stalePercent, $StaleRemovalMinCount, $StaleRemovalMaxPercent) `
                        -InvocationName 'MAIN'
                }
                else
                {
                    foreach ($member in $staleMembers)
                    {
                        try
                        {
                            Remove-DeviceFromGroup -GroupId $groupId -DeviceId $member.Id -DisplayName $member.DisplayName
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
                Failed = $false
                Added = $addedDevices.ToArray()
                Removed = $removedDevices.ToArray()
                Pending = $pendingDevices.ToArray()
                Skipped = $skippedDevices.ToArray()
                FinalMembers = $finalMembers
            })
        }
        catch
        {
            # Count it, record it, move on. FinalMembers is empty rather than
            # stale: the group was left in an unknown state, so printing a
            # membership list read before the failure would be a lie.
            $script:SyncErrorCount++
            Log-Message -Level ERROR `
                        -Message "Group '$groupName' ($groupId) FAILED and was abandoned: $( Get-GraphError -ErrorRecord $_ ). Continuing with the remaining group(s). The job will still fail at the end." `
                        -InvocationName 'MAIN'

            $groupResults.Add([pscustomobject]@{
                GroupId = $groupId
                Name = $groupName
                SourceVar = $groupCfg.SourceVar
                Failed = $true
                Added = $addedDevices.ToArray()
                Removed = $removedDevices.ToArray()
                Pending = $pendingDevices.ToArray()
                Skipped = $skippedDevices.ToArray()
                FinalMembers = @()
            })

            continue
        }
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
    # Top-level catch. Routed through Log-Message rather than a bare Write-Host so
    # the most important line in the whole job honours the configured format: in
    # Json mode a raw Write-Host here would drop an unparseable line into the
    # middle of a newline-delimited JSON stream. ERROR is still Write-Host
    # underneath, so this stays always-visible in the portal before Azure
    # Automation marks the job Failed and the detail is lost.
    #
    # InvocationName is 'FATAL' so the Text rendering is byte-identical to what
    # this handler printed before: HH:mm:ss [FATAL] <message>.
    Log-Message -Level ERROR `
                -Message $_.Exception.Message `
                -InvocationName 'FATAL' `
                -Data @{ stack_trace = $_.ScriptStackTrace }

    # In Json mode the stack trace is already an attribute on the record above.
    if ($script:LogFormat -eq 'Text')
    {
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }

    throw
}