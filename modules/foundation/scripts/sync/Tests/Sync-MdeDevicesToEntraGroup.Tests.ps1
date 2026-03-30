#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester unit tests for Sync-MDELinuxDeviceToEntra.ps1

.DESCRIPTION
    Tests the pure logic functions that do not require API calls.
    API-dependent functions (Get-MdeDevicesByTag, Resolve-EntraDeviceId, etc.)
    are covered via mocked Invoke-RestMethod where feasible.

.NOTES
    Run with:
        Invoke-Pester ./Sync-MDELinuxDeviceToEntra.Tests.ps1 -Output Detailed

    Requires Pester 5+:
        Install-Module Pester -MinimumVersion 5.0.0 -Force
#>

BeforeAll {
    # Dot-source the runbook so its functions are available.
    # We supply dummy mandatory params to prevent the script body from executing —
    # only the function definitions are needed for unit testing.
    $script:RunbookPath = "$PSScriptRoot/../Sync-MDELinuxDeviceToEntra.ps1"

    # Stub out Az cmdlets so the script can be dot-sourced without Az installed
    function global:Connect-AzAccount { }
    function global:Disable-AzContextAutosave { }
    function global:Get-AzAccessToken {
        return [pscustomobject]@{ Token = 'fake-test-token-for-unit-tests' }
    }

    # Stub Invoke-RestMethod so MAIN body doesn't make real HTTP calls during dot-source.
    # Returns a minimal valid response shape — empty value array, no nextLink.
    function global:Invoke-RestMethod {
        return [pscustomobject]@{ value = @() }
    }

    # Dot-source using & with -NoProfile equivalent — only loads function definitions
    . $script:RunbookPath `
        -ManagedIdentityClientId 'test-client-id' `
        -DeviceTag               @('TEST-TAG') `
        -EntraGroupObjectId      '00000000-0000-0000-0000-000000000000'
}

# ============================================================
#  Log-Message
# ============================================================

Describe 'Log-Message' {

    Context 'Stream routing' {

        It 'INFO writes to Verbose stream' {
            $verbose = $null
            Log-Message -Level INFO -Message 'hello' -InvocationName 'TEST' -Verbose 4>&1 |
                    ForEach-Object { $verbose = $_ }
            $verbose | Should -Match 'hello'
        }

        It 'DEBUG writes to Verbose stream' {
            $verbose = $null
            Log-Message -Level DEBUG -Message 'debug msg' -InvocationName 'TEST' -Verbose 4>&1 |
                    ForEach-Object { $verbose = $_ }
            $verbose | Should -Match 'debug msg'
        }

        It 'WARN writes to Warning stream' {
            $warning = Log-Message -Level WARN -Message 'watch out' -InvocationName 'TEST' 3>&1
            $warning | Should -Match 'watch out'
        }

        It 'ERROR writes to host (not output stream) — output stream should be empty' {
            $output = Log-Message -Level ERROR -Message 'bad thing' -InvocationName 'TEST'
            # Write-Host goes to Information stream (6), not stdout (1).
            # $output captures stdout only — it must be empty.
            $output | Should -BeNullOrEmpty
        }
    }

    Context 'Prefix format' {

        It 'Prefix contains the InvocationName in brackets' {
            $verbose = Log-Message -Level INFO -Message 'msg' -InvocationName 'MyFunc' -Verbose 4>&1
            $verbose | Should -Match '\[MyFunc\]'
        }

        It 'Prefix contains a timestamp in HH:mm:ss format' {
            $verbose = Log-Message -Level INFO -Message 'msg' -InvocationName 'T' -Verbose 4>&1
            $verbose | Should -Match '^\d{2}:\d{2}:\d{2}'
        }
    }
}

# ============================================================
#  Invoke-WithRetry
# ============================================================

Describe 'Invoke-WithRetry' {

    BeforeAll {
        # Override module-level variables that Invoke-WithRetry reads
        $script:MaxRetries        = 3
        $script:RetryDelaySeconds = 0   # zero so tests don't actually sleep
        Mock Start-Sleep { } -ModuleName $null   # suppress real sleep
    }

    It 'Returns result immediately on first success' {
        $result = Invoke-WithRetry -OperationName 'test' -ScriptBlock { 'success' }
        $result | Should -Be 'success'
    }

    It 'Returns result after transient failures' {
        $attempt = 0
        $result = Invoke-WithRetry -OperationName 'test' -ScriptBlock {
            $attempt++
            if ($attempt -lt 3) { throw 'transient' }
            'recovered'
        }
        $result   | Should -Be 'recovered'
        $attempt  | Should -Be 3
    }

    It 'Throws after MaxRetries exhausted' {
        $attempt = 0
        { Invoke-WithRetry -OperationName 'fail' -ScriptBlock {
            $attempt++
            throw 'always fails'
        }} | Should -Throw
        $attempt | Should -Be $script:MaxRetries
    }

    It 'Does not retry beyond MaxRetries' {
        $attempt = 0
        try {
            Invoke-WithRetry -OperationName 'overrun' -ScriptBlock {
                $attempt++
                throw 'keep failing'
            }
        } catch { }
        $attempt | Should -BeLessOrEqual $script:MaxRetries
    }
}

# ============================================================
#  Client-side tag/OS/health filtering (extracted from Get-MdeDevicesByTag)
# ============================================================

Describe 'Device filtering logic' {

    # Helper — runs the same client-side logic the function uses
    function Invoke-DeviceFilter {
        param(
            [pscustomobject[]] $Devices,
            [string[]]         $Tags,
            [string[]]         $OsPlatforms,
            [string[]]         $HealthStatuses
        )

        $tagSet    = [System.Collections.Generic.HashSet[string]]($Tags)
        $osSet     = [System.Collections.Generic.HashSet[string]]($OsPlatforms)
        $healthSet = [System.Collections.Generic.HashSet[string]]($HealthStatuses)

        $Devices | Where-Object {
            $device = $_
            if (-not $device.osPlatform    -or -not $osSet.Contains($device.osPlatform))     { return $false }
            if (-not $device.healthStatus  -or -not $healthSet.Contains($device.healthStatus)) { return $false }
            if (-not $device.machineTags)                                                      { return $false }
            foreach ($tag in $device.machineTags) {
                if ($tagSet.Contains($tag)) { return $true }
            }
            return $false
        }
    }

    BeforeAll {
        $script:GoodDevice = [pscustomobject]@{
            id            = 'device-1'
            computerDnsName = 'rhel-host-1'
            osPlatform    = 'RedHatEnterpriseLinux'
            healthStatus  = 'Active'
            machineTags   = @('RHEL-EDR')
        }
    }

    It 'Includes a device matching tag, OS, and health' {
        $result = Invoke-DeviceFilter `
            -Devices        @($script:GoodDevice) `
            -Tags           @('RHEL-EDR') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching tag' {
        $result = Invoke-DeviceFilter `
            -Devices        @($script:GoodDevice) `
            -Tags           @('UBUNTU-EDR') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        $result | Should -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching OS' {
        $result = Invoke-DeviceFilter `
            -Devices        @($script:GoodDevice) `
            -Tags           @('RHEL-EDR') `
            -OsPlatforms    @('Ubuntu') `
            -HealthStatuses @('Active')
        $result | Should -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching health status' {
        $inactive = [pscustomobject]@{
            id              = 'device-2'
            computerDnsName = 'rhel-host-2'
            osPlatform      = 'RedHatEnterpriseLinux'
            healthStatus    = 'Inactive'
            machineTags     = @('RHEL-EDR')
        }
        $result = Invoke-DeviceFilter `
            -Devices        @($inactive) `
            -Tags           @('RHEL-EDR') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        $result | Should -BeNullOrEmpty
    }

    It 'Excludes a device with no machineTags' {
        $noTags = [pscustomobject]@{
            id              = 'device-3'
            computerDnsName = 'rhel-host-3'
            osPlatform      = 'RedHatEnterpriseLinux'
            healthStatus    = 'Active'
            machineTags     = $null
        }
        $result = Invoke-DeviceFilter `
            -Devices        @($noTags) `
            -Tags           @('RHEL-EDR') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        $result | Should -BeNullOrEmpty
    }

    It 'Includes a device matching ANY of multiple supplied tags' {
        $multiTag = [pscustomobject]@{
            id              = 'device-4'
            computerDnsName = 'rhel-host-4'
            osPlatform      = 'RedHatEnterpriseLinux'
            healthStatus    = 'Active'
            machineTags     = @('MDE-Management')
        }
        $result = Invoke-DeviceFilter `
            -Devices        @($multiTag) `
            -Tags           @('RHEL-EDR', 'MDE-Management') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Handles multiple devices — includes only matching ones' {
        $devices = @(
            $script:GoodDevice,
            [pscustomobject]@{
                id              = 'device-bad'
                computerDnsName = 'ubuntu-host'
                osPlatform      = 'Ubuntu'
                healthStatus    = 'Active'
                machineTags     = @('RHEL-EDR')   # tag matches but OS doesn't
            }
        )
        $result = Invoke-DeviceFilter `
            -Devices        $devices `
            -Tags           @('RHEL-EDR') `
            -OsPlatforms    @('RedHatEnterpriseLinux') `
            -HealthStatuses @('Active')
        @($result).Count | Should -Be 1
        $result.id | Should -Be 'device-1'
    }
}

# ============================================================
#  Resolve-EntraDeviceId — trustType selection logic
# ============================================================

Describe 'Resolve-EntraDeviceId trustType selection' {

    # We test the selection logic independently of the HTTP calls
    # by using a helper that mimics what the function does when it gets results back

    function Invoke-TrustTypeSelection {
        param([pscustomobject[]] $Candidates)
        $match = $Candidates | Where-Object { -not $_.trustType } | Select-Object -First 1
        if (-not $match) { $match = $Candidates | Select-Object -First 1 }
        return $match
    }

    It 'Prefers the candidate with blank trustType (synthetic device)' {
        $candidates = @(
            [pscustomobject]@{ id = 'hybrid-id';    trustType = 'ServerAd' }
            [pscustomobject]@{ id = 'synthetic-id'; trustType = $null }
        )
        $result = Invoke-TrustTypeSelection -Candidates $candidates
        $result.id | Should -Be 'synthetic-id'
    }

    It 'Falls back to first result when all candidates have a trustType' {
        $candidates = @(
            [pscustomobject]@{ id = 'first-id';  trustType = 'Workplace' }
            [pscustomobject]@{ id = 'second-id'; trustType = 'AzureAd' }
        )
        $result = Invoke-TrustTypeSelection -Candidates $candidates
        $result.id | Should -Be 'first-id'
    }

    It 'Returns the only candidate when there is exactly one result' {
        $candidates = @(
            [pscustomobject]@{ id = 'only-id'; trustType = $null }
        )
        $result = Invoke-TrustTypeSelection -Candidates $candidates
        $result.id | Should -Be 'only-id'
    }
}

# ============================================================
#  Short name extraction
# ============================================================

Describe 'Short name extraction from computerDnsName' {

    # The runbook does: $shortName = $name.Split('.')[0]

    It 'Extracts hostname from a FQDN' {
        $name      = 'craig-rhel9-vm1.mshome.net'
        $shortName = $name.Split('.')[0]
        $shortName | Should -Be 'craig-rhel9-vm1'
    }

    It 'Returns the name unchanged when there is no dot' {
        $name      = 'craig-rhel9-vm2'
        $shortName = $name.Split('.')[0]
        $shortName | Should -Be 'craig-rhel9-vm2'
    }

    It 'Handles deep FQDNs correctly' {
        $name      = 'host.sub.domain.corp.local'
        $shortName = $name.Split('.')[0]
        $shortName | Should -Be 'host'
    }
}

# ============================================================
#  Add-DeviceToGroup — 'already exist' race condition handling
# ============================================================

Describe 'Add-DeviceToGroup — race condition handling' {

    BeforeAll {
        $script:WhatIf            = $false
        $script:MaxRetries        = 1
        $script:RetryDelaySeconds = 0
    }

    It 'Does not throw when Graph returns already-exists error' {
        Mock Invoke-RestMethod {
            throw [System.Exception]::new('One or more added object references already exist')
        }

        { Add-DeviceToGroup -GroupId 'group-1' -DeviceId 'device-1' -Token 'tok' } |
                Should -Not -Throw
    }

    It 'Does throw on a genuine API error' {
        Mock Invoke-RestMethod {
            throw [System.Exception]::new('Authorization_RequestDenied')
        }

        { Add-DeviceToGroup -GroupId 'group-1' -DeviceId 'device-1' -Token 'tok' } |
                Should -Throw
    }
}

# ============================================================
#  Remove-DeviceFromGroup — 'does not exist' handling
# ============================================================

Describe 'Remove-DeviceFromGroup — already-removed handling' {

    BeforeAll {
        $script:WhatIf            = $false
        $script:MaxRetries        = 1
        $script:RetryDelaySeconds = 0
    }

    It 'Does not throw when Graph says member does not exist' {
        Mock Invoke-RestMethod {
            throw [System.Exception]::new('Resource does not exist or one of its queried reference-property objects are not present')
        }

        { Remove-DeviceFromGroup -GroupId 'group-1' -DeviceId 'device-1' -Token 'tok' } |
                Should -Not -Throw
    }

    It 'Does throw on a genuine API error' {
        Mock Invoke-RestMethod {
            throw [System.Exception]::new('Authorization_RequestDenied')
        }

        { Remove-DeviceFromGroup -GroupId 'group-1' -DeviceId 'device-1' -Token 'tok' } |
                Should -Throw
    }
}

# ============================================================
#  WhatIf mode
# ============================================================

Describe 'WhatIf mode — no writes made' {

    BeforeAll {
        $script:WhatIf = $true
        Mock Invoke-RestMethod { throw 'Should not be called in WhatIf mode' }
    }

    AfterAll {
        $script:WhatIf = $false
    }

    It 'Add-DeviceToGroup does not call Invoke-RestMethod in WhatIf mode' {
        { Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' -Token 't' } | Should -Not -Throw
        Should -Invoke Invoke-RestMethod -Times 0
    }

    It 'Remove-DeviceFromGroup does not call Invoke-RestMethod in WhatIf mode' {
        { Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' -Token 't' } | Should -Not -Throw
        Should -Invoke Invoke-RestMethod -Times 0
    }
}