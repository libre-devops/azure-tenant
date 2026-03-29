[CmdletBiding()]
param (
    [Parameter(Mandatory)]
    [string] $managedidentityclientid
)


$ErrorActionPreference = 'Stop'
$VerbosePreference     = 'Continue'
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
        "INFO"  { Write-Host    "$ts [INFO]  $Message" }
        "DEBUG" { Write-Verbose "$ts [DEBUG] $Message" }
        "WARN"  { Write-Warning "$ts [WARN]  $Message" }
        "ERROR" { Write-Error   "$ts [ERROR] $Message" }
    }
}

# ============================================================
# CONFIG
# ============================================================

$ManagedIdentityClientId = $managedidentityclientid

# ============================================================
# AUTH (USER-ASSIGNED MI)
# ============================================================

function Initialize-ManagedIdentityAuth {
    try {
        Write-Log "Authenticating using User Assigned Managed Identity..." "INFO"
        Write-Log "ClientId: $ManagedIdentityClientId" "DEBUG"

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
            throw "Token response was empty"
        }

        Write-Log "Token acquired for $Resource" "DEBUG"

        return $tokenResponse.Token
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
            -Uri "https://graph.microsoft.com/v1.0/devices" `
            -Headers @{ Authorization = "Bearer $graphToken" } `
            -TimeoutSec 15

        $count = if ($graph.value) { $graph.value.Count } else { 0 }

        Write-Log "Graph SUCCESS. Devices: $count" "INFO"
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
            -Uri "https://api.securitycenter.microsoft.com/api/machines" `
            -Headers @{ Authorization = "Bearer $mdeToken" } `
            -TimeoutSec 15

        $count = if ($mde.value) { $mde.value.Count } else { 0 }

        Write-Log "MDE SUCCESS. Machines: $count" "INFO"
    }
    catch {
        Write-Log "MDE FAILED: $($_.Exception.Message)" "ERROR"
        throw
    }

    Write-Log "===== RUNBOOK COMPLETED SUCCESSFULLY =====" "INFO"
}
catch {
    Write-Log "===== RUNBOOK FAILED =====" "ERROR"
    Write-Log $_.Exception.Message "ERROR"
    throw
}