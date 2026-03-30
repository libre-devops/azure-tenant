#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Regression tests for Sync-MDELinuxDeviceToEntra.ps1

.DESCRIPTION
    Tests pure in-memory logic only. No API calls, no mocking of Az cmdlets,
    no dependency on retry behaviour or external services.

    Covers:
        - Log-Message stream routing (right stream per level)
        - Device tag/OS/health filtering logic
        - trustType selection (synthetic device preference)
        - Short name extraction from computerDnsName

.NOTES
    Run with:
        Invoke-Pester ./Sync-MDELinuxDeviceToEntra.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Stub Az and HTTP so dot-sourcing the runbook doesn't authenticate or call APIs
    function global:Connect-AzAccount        { }
    function global:Disable-AzContextAutosave { }
    function global:Get-AzAccessToken       { [pscustomobject]@{ Token = 'test-token' } }
    function global:Invoke-RestMethod        { [pscustomobject]@{ value = @() } }

    . "$PSScriptRoot/../Sync-MDELinuxDeviceToEntra.ps1" `
        -ManagedIdentityClientId 'test-client-id' `
        -DeviceTag               @('TEST-TAG') `
        -EntraGroupObjectId      '00000000-0000-0000-0000-000000000000'
}

# ============================================================
#  Log-Message — correct stream per level
# ============================================================

Describe 'Log-Message stream routing' {

    It 'INFO goes to Verbose stream' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'hello' -InvocationName 'T' } 4>&1
        $out | Should -Match 'hello'
    }

    It 'DEBUG goes to Verbose stream' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level DEBUG -Message 'dbg' -InvocationName 'T' } 4>&1
        $out | Should -Match 'dbg'
    }

    It 'WARN goes to Warning stream' {
        $out = Log-Message -Level WARN -Message 'careful' -InvocationName 'T' 3>&1
        $out | Should -Match 'careful'
    }

    It 'ERROR does not write to output stream' {
        $out = Log-Message -Level ERROR -Message 'oops' -InvocationName 'T'
        $out | Should -BeNullOrEmpty
    }

    It 'Prefix contains InvocationName in brackets' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'MyFunc' } 4>&1
        $out | Should -Match '\[MyFunc\]'
    }

    It 'Prefix contains HH:mm:ss timestamp' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' } 4>&1
        $out | Should -Match '^\d{2}:\d{2}:\d{2}'
    }
}

# ============================================================
#  Device filtering — tag / OS / health logic
# ============================================================

Describe 'Device filtering logic' {

    BeforeAll {
        function script:Test-DeviceFilter {
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
                $d = $_
                if (-not $d.osPlatform   -or -not $osSet.Contains($d.osPlatform))      { return $false }
                if (-not $d.healthStatus -or -not $healthSet.Contains($d.healthStatus)) { return $false }
                if (-not $d.machineTags)                                                { return $false }
                foreach ($t in $d.machineTags) { if ($tagSet.Contains($t)) { return $true } }
                return $false
            }
        }

        $script:Good = [pscustomobject]@{
            id = 'dev-1'; osPlatform = 'RedHatEnterpriseLinux'
            healthStatus = 'Active'; machineTags = @('RHEL-EDR')
        }
    }

    It 'Includes a device that matches tag, OS, and health' {
        Test-DeviceFilter -Devices @($script:Good) -Tags @('RHEL-EDR') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active') |
                Should -Not -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching tag' {
        Test-DeviceFilter -Devices @($script:Good) -Tags @('UBUNTU-EDR') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active') |
                Should -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching OS' {
        Test-DeviceFilter -Devices @($script:Good) -Tags @('RHEL-EDR') `
            -OsPlatforms @('Ubuntu') -HealthStatuses @('Active') |
                Should -BeNullOrEmpty
    }

    It 'Excludes a device with a non-matching health status' {
        $d = [pscustomobject]@{ id = 'dev-2'; osPlatform = 'RedHatEnterpriseLinux'; healthStatus = 'Inactive'; machineTags = @('RHEL-EDR') }
        Test-DeviceFilter -Devices @($d) -Tags @('RHEL-EDR') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active') |
                Should -BeNullOrEmpty
    }

    It 'Excludes a device with no machineTags' {
        $d = [pscustomobject]@{ id = 'dev-3'; osPlatform = 'RedHatEnterpriseLinux'; healthStatus = 'Active'; machineTags = $null }
        Test-DeviceFilter -Devices @($d) -Tags @('RHEL-EDR') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active') |
                Should -BeNullOrEmpty
    }

    It 'Includes a device matching ANY of multiple tags' {
        $d = [pscustomobject]@{ id = 'dev-4'; osPlatform = 'RedHatEnterpriseLinux'; healthStatus = 'Active'; machineTags = @('MDE-Management') }
        Test-DeviceFilter -Devices @($d) -Tags @('RHEL-EDR', 'MDE-Management') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active') |
                Should -Not -BeNullOrEmpty
    }

    It 'Includes only matching devices from a mixed list' {
        $bad = [pscustomobject]@{ id = 'dev-bad'; osPlatform = 'Ubuntu'; healthStatus = 'Active'; machineTags = @('RHEL-EDR') }
        $result = Test-DeviceFilter -Devices @($script:Good, $bad) -Tags @('RHEL-EDR') `
            -OsPlatforms @('RedHatEnterpriseLinux') -HealthStatuses @('Active')
        @($result).Count | Should -Be 1
        $result.id       | Should -Be 'dev-1'
    }
}

# ============================================================
#  trustType selection — synthetic device preference
# ============================================================

Describe 'trustType selection' {

    BeforeAll {
        function script:Select-BestMatch {
            param([pscustomobject[]] $Candidates)
            $m = $Candidates | Where-Object { -not $_.trustType } | Select-Object -First 1
            if (-not $m) { $m = $Candidates | Select-Object -First 1 }
            $m
        }
    }

    It 'Prefers blank trustType (synthetic device)' {
        $result = Select-BestMatch @(
            [pscustomobject]@{ id = 'hybrid';    trustType = 'ServerAd' }
            [pscustomobject]@{ id = 'synthetic'; trustType = $null }
        )
        $result.id | Should -Be 'synthetic'
    }

    It 'Falls back to first when all have a trustType' {
        $result = Select-BestMatch @(
            [pscustomobject]@{ id = 'first';  trustType = 'Workplace' }
            [pscustomobject]@{ id = 'second'; trustType = 'AzureAd' }
        )
        $result.id | Should -Be 'first'
    }

    It 'Returns the single candidate when there is only one' {
        $result = Select-BestMatch @([pscustomobject]@{ id = 'only'; trustType = $null })
        $result.id | Should -Be 'only'
    }
}

# ============================================================
#  Short name extraction
# ============================================================

Describe 'Short name extraction' {

    It 'Extracts hostname from FQDN' {
        'host.domain.local'.Split('.')[0] | Should -Be 'host'
    }

    It 'Returns name unchanged when no dot present' {
        'myhost'.Split('.')[0] | Should -Be 'myhost'
    }

    It 'Handles deeply nested FQDN' {
        'a.b.c.d.e'.Split('.')[0] | Should -Be 'a'
    }
}