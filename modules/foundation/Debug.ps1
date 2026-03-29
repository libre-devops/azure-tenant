param (
    [Parameter(Mandatory)]
    [string] $ManagedIdentityClientId
)

$ErrorActionPreference = 'Stop'
$VerbosePreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ============================================================
# LOGGING
# ============================================================

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO","DEBUG","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $ts = Get-Date -Format "HH:mm:ss"

    switch ($Level) {
        # Write-Host writes directly to the console and does NOT contribute to the
        # PowerShell output stream. Using Write-Output here causes any function that
        # calls Write-Log to return log lines concatenated with its actual return value,
        # corrupting tokens, IDs, and anything else the function is meant to return.
        "INFO"  { Write-Host    "$ts [INFO]  $Message" -ForegroundColor Green }
        "DEBUG" { Write-Host    "$ts [DEBUG] $Message" -ForegroundColor Cyan }
        "WARN"  { Write-Warning "$ts [WARN]  $Message" }
        "ERROR" { Write-Host    "$ts [ERROR] $Message" -ForegroundColor Red }
    }
}

# ============================================================
# AUTH (USER-ASSIGNED MI)
# ============================================================

function Initialize-ManagedIdentityAuth {
    try {
        Write-Log "Authenticating using User Assigned Managed Identity..." "INFO"
        Write-Log "ClientId: $ManagedIdentityClientId" "DEBUG"

        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

        Connect-AzAccount `
            -Identity `
            -AccountId $ManagedIdentityClientId `
            -ErrorAction Stop | Out-Null

        Write-Log "Managed Identity authentication successful." "INFO"
    }
    catch {
        Write-Log "Managed Identity authentication FAILED: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-AccessToken {
    param (
        [Parameter(Mandatory)]
        [string]$Resource
    )

    try {
        Write-Log "Requesting token for: $Resource" "INFO"

        $tokenResponse = Get-AzAccessToken `
            -ResourceUrl $Resource `
            -ErrorAction Stop

        if (-not $tokenResponse.Token) {
            throw "Token extraction failed — response contained no token."
        }

        # Cast explicitly to [string] to guarantee a clean scalar return value.
        # At Az 11.2.0 the token is already a plain string, but the explicit cast
        # prevents edge cases where PowerShell wraps it in an Object[].
        $token = [string]$tokenResponse.Token

        Write-Log "Token acquired for $Resource (type: $($tokenResponse.Token.GetType().Name), length: $($token.Length))" "DEBUG"
        return $token
    }
    catch {
        Write-Log "Failed to acquire token for $Resource : $($_.Exception.Message)" "ERROR"
        throw
    }
}

# ============================================================
# MAIN
# ============================================================

try {
    Write-Log "===== RUNBOOK START =====" "INFO"

    # --- AUTH ---
    Initialize-ManagedIdentityAuth

    # --- TOKENS ---
    $graphToken = Get-AccessToken "https://graph.microsoft.com"
    $mdeToken   = Get-AccessToken "https://api.securitycenter.microsoft.com"

    # ========================================================
    # GRAPH TEST
    # ========================================================

    try {
        Write-Log "Calling Microsoft Graph..." "INFO"

        $graph = Invoke-RestMethod `
            -Uri        "https://graph.microsoft.com/v1.0/devices" `
            -Headers    @{ Authorization = "Bearer $graphToken" } `
            -TimeoutSec 15 `
            -Verbose:$false

        $graphCount = if ($graph.value) { $graph.value.Count } else { 0 }
        Write-Log "Graph SUCCESS. Devices returned: $graphCount" "INFO"
    }
    catch {
        Write-Log "Graph FAILED: $($_.Exception.Message)" "ERROR"
        throw
    }

    # ========================================================
    # MDE TEST
    # ========================================================

    try {
        Write-Log "Calling Defender for Endpoint..." "INFO"

        $mde = Invoke-RestMethod `
            -Uri        "https://api.securitycenter.microsoft.com/api/machines" `
            -Headers    @{ Authorization = "Bearer $mdeToken" } `
            -TimeoutSec 15 `
            -Verbose:$false

        $mdeCount = if ($mde.value) { $mde.value.Count } else { 0 }
        Write-Log "MDE SUCCESS. Machines returned: $mdeCount" "INFO"
    }
    catch {
        Write-Log "MDE FAILED: $($_.Exception.Message)" "ERROR"
        throw
    }

    # ========================================================
    # FINAL VALIDATION OUTPUT
    # ========================================================

    Write-Log "===== RUNBOOK COMPLETED SUCCESSFULLY =====" "INFO"
    Write-Output "RESULT: GraphDevices=$graphCount; MDEDevices=$mdeCount"
}
catch {
    Write-Log "===== RUNBOOK FAILED =====" "ERROR"
    Write-Log $_.Exception.Message "ERROR"
    throw
}