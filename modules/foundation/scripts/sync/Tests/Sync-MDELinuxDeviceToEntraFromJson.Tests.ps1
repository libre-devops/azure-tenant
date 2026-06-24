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
        - Resolve-Device (exact, short-name, fuzzy, ambiguous, pending,
                          and multi-match add-all for identical displayNames)
        - Build-DeviceIndex (exact/short/fuzzy structure, duplicate handling)

.NOTES
    Run with:
        Invoke-Pester ./Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # ── Stubs — prevent real Az/HTTP calls when dot-sourcing ──────────────────
    function global:Connect-AzAccount         { }
    function global:Disable-AzContextAutosave { }
    function global:Get-AzAccessToken         { [pscustomobject]@{ Token = 'stub-token'; ExpiresOn = [datetimeoffset]::UtcNow.AddHours(1) } }
    function global:Invoke-RestMethod         { [pscustomobject]@{ value = @() } }

    # Return a valid JSON config with an empty devices array.
    # MAIN parses it, hits the "no devices — skipping" WARN path, and exits 0
    # without building the index or touching any group, so dot-source stays clean.
    function global:Get-AutomationVariable {
        '{"groupId":"00000000-0000-0000-0000-000000000000","name":"stub-group","removeStale":false,"devices":[]}'
    }

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

    It 'ERROR does not throw and does not write to Output stream' {
        # ERROR uses Write-Host (stream 6). Under $ErrorActionPreference=Stop a
        # Write-Error here would terminate — this guards against regressing to it.
        $out = $null
        { $out = Log-Message -Level ERROR -Message 'bad-thing' -InvocationName 'T' } | Should -Not -Throw
        $out | Should -BeNullOrEmpty
    }

    It 'STATUS does not write to Output stream' {
        # STATUS uses Write-Host (stream 6) — must not land on the pipeline.
        $out = Log-Message -Level STATUS -Message 'milestone' -InvocationName 'T'
        $out | Should -BeNullOrEmpty
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
        Sanitize-InputString -Value '' | Should -BeNullOrEmpty
    }

    It 'Leaves a clean value untouched' {
        Sanitize-InputString -Value 'GroupConfig-linux-group1' | Should -Be 'GroupConfig-linux-group1'
    }
}

# ============================================================
#  Resolve-Device
#
#  New contract: returns { Status; Ids = @(...) }.
#    Resolved  → Ids has one or more entries (multiple = identical-name duplicates)
#    Ambiguous → Ids empty (matches span different displaynames)
#    Pending   → Ids empty (nothing matched)
# ============================================================

Describe 'Resolve-Device' {

    BeforeAll {
        # exact: full displayName → List[string] ids
        $script:Exact = @{
            'server01.contoso.local' = [System.Collections.Generic.List[string]]@('id-fqdn')
            'server02'               = [System.Collections.Generic.List[string]]@('id-short')
        }

        # short: short name → list of { Id; Full }
        $script:Short = @{
            'server01' = @([pscustomobject]@{ Id = 'id-fqdn';  Full = 'server01.contoso.local' })
            'server02' = @([pscustomobject]@{ Id = 'id-short'; Full = 'server02' })
            'db01'     = @([pscustomobject]@{ Id = 'id-db';    Full = 'db01.contoso.local' })
        }

        $script:Fuzzy = @(
            [pscustomobject]@{ Name = 'server01.contoso.local'; Short = 'server01'; Id = 'id-fqdn'  }
            [pscustomobject]@{ Name = 'server02';               Short = 'server02'; Id = 'id-short' }
            [pscustomobject]@{ Name = 'db01.contoso.local';     Short = 'db01';     Id = 'id-db'   }
        )
    }

    It 'Resolves via exact FQDN match (single id)' {
        $r = Resolve-Device -DeviceName 'server01.contoso.local' -ExactIndex $script:Exact -ShortIndex $script:Short -FuzzyList $script:Fuzzy
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 1
        $r.Ids[0]    | Should -Be 'id-fqdn'
    }

    It 'Resolves via short-name match when full name not in exact index' {
        # 'server01' is not an exact key (only the FQDN is) — falls to short index.
        $r = Resolve-Device -DeviceName 'server01' -ExactIndex $script:Exact -ShortIndex $script:Short -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Ids[0] | Should -Be 'id-fqdn'
    }

    It 'Resolves via case-insensitive exact match' {
        $r = Resolve-Device -DeviceName 'SERVER01.CONTOSO.LOCAL' -ExactIndex $script:Exact -ShortIndex $script:Short -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Ids[0] | Should -Be 'id-fqdn'
    }

    It 'Resolves via fuzzy startswith when in neither index' {
        $r = Resolve-Device -DeviceName 'db01' -ExactIndex @{} -ShortIndex @{} -FuzzyList $script:Fuzzy
        $r.Status | Should -Be 'Resolved'
        $r.Ids[0] | Should -Be 'id-db'
    }

    It 'Exact match with multiple ids (identical displayName) adds ALL' {
        $dupExact = @{ 'dup.contoso.local' = [System.Collections.Generic.List[string]]@('id-1', 'id-2') }
        $r = Resolve-Device -DeviceName 'dup.contoso.local' -ExactIndex $dupExact -ShortIndex @{} -FuzzyList @()
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 2
        $r.Ids       | Should -Contain 'id-1'
        $r.Ids       | Should -Contain 'id-2'
    }

    It 'Short match with same full name duplicated adds ALL' {
        $dupShort = @{ 'dup' = @(
            [pscustomobject]@{ Id = 'id-1'; Full = 'dup.contoso.local' }
            [pscustomobject]@{ Id = 'id-2'; Full = 'dup.contoso.local' }
        ) }
        $r = Resolve-Device -DeviceName 'dup' -ExactIndex @{} -ShortIndex $dupShort -FuzzyList @()
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 2
    }

    It 'Short match across DIFFERENT full names is Ambiguous (skip)' {
        $ambShort = @{ 'web01' = @(
            [pscustomobject]@{ Id = 'id-a'; Full = 'web01.site-a.local' }
            [pscustomobject]@{ Id = 'id-b'; Full = 'web01.site-b.local' }
        ) }
        $r = Resolve-Device -DeviceName 'web01' -ExactIndex @{} -ShortIndex $ambShort -FuzzyList @()
        $r.Status    | Should -Be 'Ambiguous'
        $r.Ids.Count | Should -Be 0
    }

    It 'Fuzzy match across DIFFERENT names is Ambiguous (skip)' {
        $ambFuzzy = @(
            [pscustomobject]@{ Name = 'web01a.local'; Short = 'web01a'; Id = 'id-1' }
            [pscustomobject]@{ Name = 'web01b.local'; Short = 'web01b'; Id = 'id-2' }
        )
        $r = Resolve-Device -DeviceName 'web01' -ExactIndex @{} -ShortIndex @{} -FuzzyList $ambFuzzy
        $r.Status    | Should -Be 'Ambiguous'
        $r.Ids.Count | Should -Be 0
    }

    It 'Fuzzy match with same full name duplicated adds ALL' {
        $dupFuzzy = @(
            [pscustomobject]@{ Name = 'host.local'; Short = 'host'; Id = 'id-1' }
            [pscustomobject]@{ Name = 'host.local'; Short = 'host'; Id = 'id-2' }
        )
        $r = Resolve-Device -DeviceName 'host' -ExactIndex @{} -ShortIndex @{} -FuzzyList $dupFuzzy
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 2
    }

    It 'Returns Pending when nothing matches' {
        $r = Resolve-Device -DeviceName 'unknown-host' -ExactIndex @{} -ShortIndex @{} -FuzzyList @()
        $r.Status    | Should -Be 'Pending'
        $r.Ids.Count | Should -Be 0
    }
}

# ============================================================
#  Build-DeviceIndex
#
#  New contract: returns $exactIndex, $shortIndex, $fuzzyList where
#    $exactIndex[name] = List[string] of ids  (all ids for that displayName)
#    $shortIndex[short] = list of { Id; Full }
# ============================================================

Describe 'Build-DeviceIndex' {

    BeforeAll {
        # Bypass Invoke-WithRetry so the scriptblock runs directly, no retry/sleep.
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

    It 'Exact index contains the full FQDN lowercased' {
        $exact, $short, $fl = Build-DeviceIndex
        $exact.ContainsKey('alpha.contoso.local') | Should -BeTrue
    }

    It 'Short index contains the short name lowercased' {
        $exact, $short, $fl = Build-DeviceIndex
        $short.ContainsKey('alpha') | Should -BeTrue
    }

    It 'Exact index maps a single-object name to its id' {
        $exact, $short, $fl = Build-DeviceIndex
        @($exact['alpha.contoso.local'])[0] | Should -Be 'id-alpha'
    }

    It 'Short-name-only device is indexed in the exact index under its name' {
        $exact, $short, $fl = Build-DeviceIndex
        $exact.ContainsKey('beta')   | Should -BeTrue
        @($exact['beta'])[0]         | Should -Be 'id-beta'
    }

    It 'Fuzzy list contains one entry per device' {
        $exact, $short, $fl = Build-DeviceIndex
        $fl.Count | Should -Be 2
    }

    It 'Identical displayNames keep BOTH ids (multi-match policy)' {
        $dupPage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'first';  displayName = 'dup-host' }
                [pscustomobject]@{ id = 'second'; displayName = 'dup-host' }
            )
        }
        function global:Invoke-RestMethod { $dupPage }

        $exact, $short, $fl = Build-DeviceIndex
        @($exact['dup-host']).Count | Should -Be 2
        $exact['dup-host']          | Should -Contain 'first'
        $exact['dup-host']          | Should -Contain 'second'
    }

    It 'Skips devices with no displayName' {
        $nullNamePage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'good'; displayName = 'valid-host' }
                [pscustomobject]@{ id = 'bad';  displayName = $null }
            )
        }
        function global:Invoke-RestMethod { $nullNamePage }

        $exact, $short, $fl = Build-DeviceIndex
        $exact.ContainsKey('valid-host') | Should -BeTrue
        $fl.Count                        | Should -Be 1
    }
}