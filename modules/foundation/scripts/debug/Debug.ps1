param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId,

    [Parameter(Mandatory)]
    $AutomationVariableNames   # intentionally untyped — avoids [string[]] binding issues
)

$ErrorActionPreference = 'Stop'
$VerbosePreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ── Canary lines ──────────────────────────────────────────────────────────────
# Write-Output at script scope (not inside any function) is safe — nothing is
# capturing these as a return value, so they go cleanly to the Output stream.
# If these lines do not appear, the failure is at parameter binding / runtime
# level and no code in this script is running. Check the Exception tab.
Write-Output "$(Get-Date -Format 'HH:mm:ss') [CANARY] Script body reached — parameters bound OK."
Write-Output "$(Get-Date -Format 'HH:mm:ss') [CANARY] ManagedIdentityClientId : $ManagedIdentityClientId"
Write-Output "$(Get-Date -Format 'HH:mm:ss') [CANARY] AutomationVariableNames type : $($AutomationVariableNames.GetType().FullName)"
Write-Output "$(Get-Date -Format 'HH:mm:ss') [CANARY] AutomationVariableNames value: $AutomationVariableNames"

# ============================================================
#  LOGGING
#
#  Write-Host  → Information stream — does NOT enter the pipeline.        ✅
#               Safe to call inside functions that return values.
#               Visible in the portal Output tab and All Logs tab.
#
#  Write-Output → Output stream — ENTERS the pipeline.                    ❌
#               Calling this inside a returning function corrupts the
#               return value. Used only for canary lines above (script
#               scope, nothing capturing the output).
#
#  Write-Warning → Warning stream — also pipeline-safe, shows in Warnings tab.
# ============================================================

function WriteLog {
    param (
        [string] $Message,
        [ValidateSet('INFO', 'DEBUG', 'WARN', 'ERROR')]
        [string] $Level = 'INFO'
    )

    $ts = Get-Date -Format 'HH:mm:ss'

    switch ($Level) {
        'INFO'  { Write-Host    "$ts [INFO]  $Message" -ForegroundColor Green  }
        'DEBUG' { Write-Host    "$ts [DEBUG] $Message" -ForegroundColor Cyan   }
        'WARN'  { Write-Warning "$ts [WARN]  $Message"                         }
        'ERROR' { Write-Host    "$ts [ERROR] $Message" -ForegroundColor Red    }
    }
}

# ============================================================
#  NORMALISE INPUT
# ============================================================

function NormalizeVariableNames {
    param ($Names)

    # Write-Host is safe here — it does not corrupt the function's return value.
    WriteLog "Raw input type : $($Names.GetType().FullName)" 'DEBUG'
    WriteLog "Raw input value: $Names" 'DEBUG'

    # Azure Automation job schedules pass all parameters as strings.
    # A [string[]] parameter arrives as either:
    #   (a) a plain [string] containing the comma-joined list, or
    #   (b) a single-element array whose only element is that comma-joined string.
    if ($Names -is [string]) {
        WriteLog 'Detected plain STRING input — splitting by comma.' 'DEBUG'
        $Names = $Names.Split(',')
    }
    elseif ($Names.Count -eq 1 -and $Names[0] -match ',') {
        WriteLog 'Detected single-element ARRAY with commas — splitting.' 'DEBUG'
        $Names = $Names[0].Split(',')
    }

    $Names = @(
    $Names |
            ForEach-Object { $_.Trim() } |
            Where-Object   { $_ -ne '' } |
            Sort-Object    -Unique
    )

    WriteLog "Normalised $($Names.Count) name(s): $($Names -join ', ')" 'DEBUG'

    # return is the ONLY thing that goes to the pipeline from this function.
    return $Names
}

# ============================================================
#  AUTH
# ============================================================

function InitAuth {
    WriteLog 'Authenticating via Managed Identity...' 'INFO'

    Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

    Connect-AzAccount `
        -Identity `
        -AccountId $ManagedIdentityClientId `
        -ErrorAction Stop | Out-Null

    WriteLog 'Auth success.' 'INFO'
}

function GetToken {
    param ([string] $Resource)

    # [string] cast ensures a clean scalar even if Get-AzAccessToken wraps the
    # value in an array or object on some Az module versions.
    $token = [string](Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop).Token

    # Write-Host here is safe — it does not enter the pipeline and will not
    # be concatenated onto $token at the call site.
    WriteLog "Token acquired for '$Resource' (length: $($token.Length))." 'DEBUG'

    return $token
}

# ============================================================
#  MAIN
# ============================================================

try {
    WriteLog '===== DEBUG RUN START =====' 'INFO'

    # ── Auth ─────────────────────────────────────────────────────────────────
    InitAuth
    $graphToken = GetToken 'https://graph.microsoft.com'

    # ── Normalise parameter ───────────────────────────────────────────────────
    # NormalizeVariableNames uses Write-Host internally — the return value is
    # only the clean string array, not a mix of log lines and names.
    $AutomationVariableNames = NormalizeVariableNames -Names $AutomationVariableNames

    # ── Variable load + JSON parse + Graph probe ──────────────────────────────
    foreach ($varName in $AutomationVariableNames) {

        WriteLog "--- Testing variable: '$varName' ---" 'INFO'

        # Retrieve
        try {
            $raw = Get-AutomationVariable -Name $varName
            WriteLog "Retrieved '$varName' OK (length: $($raw.Length))." 'INFO'
        }
        catch {
            WriteLog "FAILED to retrieve '$varName': $($_.Exception.Message)" 'ERROR'
            continue
        }

        # Parse
        try {
            $cfg = $raw | ConvertFrom-Json
            WriteLog 'JSON parsed OK.' 'INFO'
        }
        catch {
            WriteLog "JSON PARSE FAILED: $($_.Exception.Message)" 'ERROR'
            continue
        }

        # Validate shape
        WriteLog "  groupId     : $($cfg.groupId)"        'DEBUG'
        WriteLog "  name        : $($cfg.name)"            'DEBUG'
        WriteLog "  removeStale : $($cfg.removeStale)"     'DEBUG'
        WriteLog "  device count: $($cfg.devices.Count)"   'DEBUG'

        if (-not $cfg.groupId) { WriteLog "  !! Missing 'groupId'!"  'ERROR' }
        if (-not $cfg.devices -or $cfg.devices.Count -eq 0) {
            WriteLog "  !! 'devices' is missing or empty — update this JSON config." 'WARN'
        }

        # Graph probe — look up first device in the config
        if ($cfg.devices.Count -gt 0) {
            $testDevice = $cfg.devices[0].Trim()
            $shortName  = $testDevice.Split('.')[0]
            WriteLog "  Graph probe for first device: '$testDevice' (short: '$shortName')" 'INFO'

            try {
                $res = Invoke-RestMethod `
                    -Uri     "https://graph.microsoft.com/v1.0/devices?`$filter=startswith(displayName,'$shortName')&`$select=id,displayName&`$top=5" `
                    -Headers @{ Authorization = "Bearer $graphToken" }

                WriteLog "  Graph returned $($res.value.Count) result(s)." 'INFO'

                foreach ($r in $res.value) {
                    WriteLog "    → '$($r.displayName)'  id: $($r.id)" 'DEBUG'
                }
            }
            catch {
                WriteLog "  Graph probe FAILED: $($_.Exception.Message)" 'ERROR'
            }
        }
    }

    WriteLog '===== DEBUG RUN COMPLETE =====' 'INFO'
}
catch {
    # Write-Host here too — keeps the error message out of the pipeline.
    Write-Host "$(Get-Date -Format 'HH:mm:ss') [FATAL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    throw
}