#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Smoke tests for Sync-MDELinuxDeviceToEntraFromJson.ps1

.DESCRIPTION
    Tests pure in-memory logic only — no API calls, no Azure credentials.
    Stubs are defined in BeforeAll to prevent the script body from making
    any real network or authentication calls when dot-sourced.

    Covers:
        - Log-Message stream routing (correct stream per level)
        - NormalizeVariableNames (splitting, trimming, deduplication)
        - Sanitize-InputString (quote stripping, whitespace)
        - Resolve-Device (exact, short-name, fuzzy, ambiguous, pending)
        - Build-DeviceIndex (index structure, first-write-wins dedup)

.NOTES
    Run with:
        Invoke-Pester ./Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # ── Stubs — prevent real Az/HTTP calls when dot-sourcing ──────────────────
    function global:Connect-AzAccount         { }
    function global:Disable-AzContextAutosave { }
    function global:Get-AzAccessToken         { [pscustomobject]@{ Token = 'stub-token' } }
    function global:Invoke-RestMethod         { [pscustomobject]@{ value = @() } }

    # Return a valid JSON config with an empty devices array.
    # MAIN parses it, hits the "no devices — skipping" WARN path, and exits 0
    # without touching any ERROR logging. This keeps the dot-source clean
    # regardless of whether the Write-Error bug has been fixed yet.
    function global:Get-AutomationVariable {
        '{"groupId":"00000000-0000-0000-0000-000000000000","name":"stub-group","removeStale":false,"devices":[]}'
    }

    # Dot-source the script so all functions are loaded into scope for testing.
    # MAIN runs but exits cleanly via the empty-devices path above.
    . "$PSScriptRoot/../Sync-MDELinuxDeviceToEntraFromJson.ps1" `
        -ManagedIdentityClientId 'stub-client-id' `
        -AutomationVariableNames 'GroupConfig-stub'
}

# ============================================================
#  Log-Message — correct stream per level
# ============================================================

Describe 'Log-Message stream routing' {

    It 'INFO goes to Verbose stream (stream 4)' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'hello' -InvocationName 'T' } 4>&1
        $out | Should -Match 'hello'
    }

    It 'DEBUG goes to Verbose stream (stream 4)' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level DEBUG -Message 'debug-msg' -InvocationName 'T' } 4>&1
        $out | Should -Match 'debug-msg'
    }

    It 'WARN goes to Warning stream (stream 3)' {
        $out = Log-Message -Level WARN -Message 'watch-out' -InvocationName 'T' 3>&1
        $out | Should -Match 'watch-out'
    }

    It 'Prefix contains InvocationName in square brackets' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'MyFunc' } 4>&1
        $out | Should -Match '\[MyFunc\]'
    }

    It 'Prefix contains HH:mm:ss timestamp' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' } 4>&1
        $out | Should -Match '^\d{2}:\d{2}:\d{2}'
    }
}

# ============================================================
#  NormalizeVariableNames
# ============================================================

Describe 'NormalizeVariableNames' {

    It 'Splits a comma-separated plain string' {
        $result = NormalizeVariableNames -Names 'GroupConfig-a,GroupConfig-b,GroupConfig-c'
        $result.Count | Should -Be 3
    }

    It 'Splits a single-element array containing a comma-separated string' {
        $result = NormalizeVariableNames -Names @('GroupConfig-a,GroupConfig-b')
        $result.Count | Should -Be 2
    }

    It 'Trims whitespace from each name' {
        $result = NormalizeVariableNames -Names '  GroupConfig-a  ,  GroupConfig-b  '
        $result | Should -Contain 'GroupConfig-a'
        $result | Should -Contain 'GroupConfig-b'
    }

    It 'Removes empty entries after splitting' {
        $result = NormalizeVariableNames -Names 'GroupConfig-a,,GroupConfig-b,'
        $result.Count | Should -Be 2
    }

    It 'Deduplicates repeated names' {
        $result = NormalizeVariableNames -Names 'GroupConfig-a,GroupConfig-a,GroupConfig-b'
        $result.Count | Should -Be 2
    }

    It 'Returns names in sorted order' {
        $result = NormalizeVariableNames -Names 'GroupConfig-z,GroupConfig-a,GroupConfig-m'
        $result[0]  | Should -Be 'GroupConfig-a'
        $result[-1] | Should -Be 'GroupConfig-z'
    }

    It 'Passes through an already-clean array unchanged' {
        $result = NormalizeVariableNames -Names @('GroupConfig-a', 'GroupConfig-b')
        $result.Count | Should -Be 2
    }

    It 'Throws when input produces no valid names' {
        { NormalizeVariableNames -Names ',,,' } | Should -Throw
    }
}

# ============================================================
#  Sanitize-InputString
# ============================================================

Describe 'Sanitize-InputString' {

    It 'Trims leading and trailing whitespace' {
        Sanitize-InputString -Value '  hello  ' | Should -Be 'hello'
    }

    It 'Strips wrapping double quotes' {
        Sanitize-InputString -Value '"my-value"' | Should -Be 'my-value'
    }

    It 'Strips multiple layers of wrapping quotes' {
        Sanitize-InputString -Value '""my-value""' | Should -Be 'my-value'
    }

    It 'Converts escaped quotes before stripping' {
        Sanitize-InputString -Value '\"my-value\"' | Should -Be 'my-value'
    }

    It 'Returns empty string unchanged' {
        # Requires [AllowEmptyString()] on the Value parameter in the script.
        # Without it, [Parameter(Mandatory)] rejects empty strings at binding time
        # with ParameterBindingValidationException before the function body runs.
        Sanitize-InputString -Value '' | Should -BeNullOrEmpty
    }

    It 'Leaves a clean value untouched' {
        Sanitize-InputString -Value 'GroupConfig-linux-group1' | Should -Be 'GroupConfig-linux-group1'
    }
}

# ============================================================
#  Resolve-Device
# ============================================================

Describe 'Resolve-Device' {

    BeforeAll {
        $script:Index = @{
            'server01.contoso.local' = 'id-fqdn'
            'server01'               = 'id-fqdn'
            'server02'               = 'id-short'
        }

        $script:Fuzzy = @(
            [pscustomobject]@{ Name = 'server01.contoso.local'; Short = 'server01'; Id = 'id-fqdn'  }
            [pscustomobject]@{ Name = 'server02';               Short = 'server02'; Id = 'id-short' }
            [pscustomobject]@{ Name = 'db01.contoso.local';     Short = 'db01';     Id = 'id-db'   }
        )
    }

    It 'Resolves via exact FQDN match' {
        $r = Resolve-Device -DeviceName 'server01.contoso.local' -DeviceIndex $script:Index -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Id     | Should -Be 'id-fqdn'
    }

    It 'Resolves via short-name match' {
        $r = Resolve-Device -DeviceName 'server02' -DeviceIndex $script:Index -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Id     | Should -Be 'id-short'
    }

    It 'Resolves via case-insensitive exact match' {
        $r = Resolve-Device -DeviceName 'SERVER01.CONTOSO.LOCAL' -DeviceIndex $script:Index -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
    }

    It 'Resolves via fuzzy startswith when not in index' {
        $r = Resolve-Device -DeviceName 'db01' -DeviceIndex @{} -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Id     | Should -Be 'id-db'
    }

    It 'Returns Ambiguous when fuzzy matches multiple candidates' {
        $ambiguousFuzzy = @(
            [pscustomobject]@{ Name = 'web01a'; Short = 'web01a'; Id = 'id-1' }
            [pscustomobject]@{ Name = 'web01b'; Short = 'web01b'; Id = 'id-2' }
        )
        $r = Resolve-Device -DeviceName 'web01' -DeviceIndex @{} -FuzzyList $ambiguousFuzzy
        $r.Status | Should -Be 'Ambiguous'
        $r.Id     | Should -BeNullOrEmpty
    }

    It 'Returns Pending when nothing matches' {
        $r = Resolve-Device -DeviceName 'unknown-host' -DeviceIndex @{} -FuzzyList @()
        $r.Status | Should -Be 'Pending'
        $r.Id     | Should -BeNullOrEmpty
    }
}

# ============================================================
#  Build-DeviceIndex
# ============================================================

Describe 'Build-DeviceIndex' {

    BeforeAll {
        # Bypass Invoke-WithRetry so Build-DeviceIndex executes the scriptblock
        # directly without any retry/sleep logic or real HTTP calls.
        function global:Invoke-WithRetry {
            param ([scriptblock] $ScriptBlock, [string] $OperationName)
            & $ScriptBlock
        }

        $script:StandardPage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'id-alpha'; displayName = 'alpha.contoso.local' }
                [pscustomobject]@{ id = 'id-beta';  displayName = 'beta' }
            )
        }

        function global:Invoke-RestMethod { $script:StandardPage }
    }

    It 'Indexes the full FQDN lowercased' {
        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx.ContainsKey('alpha.contoso.local') | Should -BeTrue
    }

    It 'Indexes the short name lowercased' {
        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx.ContainsKey('alpha') | Should -BeTrue
    }

    It 'FQDN and short name both resolve to the same Object ID' {
        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx['alpha.contoso.local'] | Should -Be 'id-alpha'
        $idx['alpha']               | Should -Be 'id-alpha'
    }

    It 'Short-name-only device is indexed under its name' {
        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx.ContainsKey('beta') | Should -BeTrue
        $idx['beta']             | Should -Be 'id-beta'
    }

    It 'Fuzzy list contains one entry per device' {
        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $fl.Count | Should -Be 2
    }

    It 'First-write-wins for duplicate display names' {
        $dupPage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'first';  displayName = 'dup-host' }
                [pscustomobject]@{ id = 'second'; displayName = 'dup-host' }
            )
        }
        function global:Invoke-RestMethod { $dupPage }

        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx['dup-host'] | Should -Be 'first'
    }

    It 'Skips devices with no displayName' {
        $nullNamePage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'good'; displayName = 'valid-host' }
                [pscustomobject]@{ id = 'bad';  displayName = $null }
            )
        }
        function global:Invoke-RestMethod { $nullNamePage }

        $idx, $fl = Build-DeviceIndex -GraphToken 'stub'
        $idx.ContainsKey('valid-host') | Should -BeTrue
        $fl.Count                       | Should -Be 1
    }
}