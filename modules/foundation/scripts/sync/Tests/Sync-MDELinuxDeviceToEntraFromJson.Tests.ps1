#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Smoke tests for Sync-MDELinuxDeviceToEntraFromJson.ps1

.DESCRIPTION
    Tests pure in-memory logic only: no API calls, no Azure credentials.
    Stubs are defined in BeforeAll to prevent the script body from making
    any real network or authentication calls when dot-sourced.

    Covers:
        - Log-Message stream routing (correct stream per level)
        - NormalizeVariableNames (splitting, trimming, deduplication)
        - Sanitize-InputString (quote stripping, whitespace, lone quote)
        - Resolve-Device (exact, short-name, ambiguous, pending, and
                          multi-match add-all for identical displayNames)
        - Build-DeviceIndex (exact/short structure, duplicate handling)
        - Get-GraphErrorInfo (status and error code extraction)
        - Invoke-WithRetry (what is retried and what is not)
        - Get-AllGroupMembers (device-only cast, no non-device ever removed)
        - Add-DeviceToGroup / Remove-DeviceFromGroup (ShouldProcess gating,
                          status-code based error handling)
        - Initialize-ManagedIdentityAuth (identity selection and validation)

    NOT covered, because it lives inline in MAIN rather than in a function:
    device-name validation at config load, and per-group failure isolation.
    Both need an end-to-end MAIN run against a fake Automation Variable.

.NOTES
    Run with:
        Invoke-Pester ./Tests/Sync-MDELinuxDeviceToEntraFromJson.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # ── Stubs: prevent real Az/HTTP calls when dot-sourcing ──────────────────
    function global:Connect-AzAccount         { }
    function global:Disable-AzContextAutosave { }
    function global:Get-AzAccessToken         { [pscustomobject]@{ Token = 'stub-token'; ExpiresOn = [datetimeoffset]::UtcNow.AddHours(1) } }
    function global:Invoke-RestMethod         { [pscustomobject]@{ value = @() } }

    # Return a valid JSON config with an empty devices array.
    # MAIN parses it, hits the "no devices configured" WARN path, and exits 0
    # without building the index or touching any group, so dot-source stays clean.
    function global:Get-AutomationVariable {
        '{"groupId":"00000000-0000-0000-0000-000000000000","name":"stub-group","removeStale":false,"devices":[]}'
    }

    # Builds a realistic failed-Graph-call ErrorRecord: an HttpResponseException
    # carrying a real HttpResponseMessage (so .Response.StatusCode is a genuine
    # status) plus the JSON body Graph would have returned in ErrorDetails.
    function global:New-GraphErrorRecord
    {
        param (
            [int]    $StatusCode,
            [string] $Body = ''
        )

        $response  = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$StatusCode)
        $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new(
                "Response status code does not indicate success: $StatusCode.", $response)

        $record = [System.Management.Automation.ErrorRecord]::new(
                $exception, 'GraphError', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)

        if ($Body)
        {
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($Body)
        }

        return $record
    }

    # ManagedIdentityClientId is deliberately NOT passed: blank is the supported
    # default and means "use the system-assigned identity".
    . "$PSScriptRoot/../Sync-MDELinuxDeviceToEntraFromJson.ps1" `
        -AutomationVariableNames 'GroupConfig-stub'
}

# ============================================================
#  Log-Message: correct stream per level
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
        # Write-Error here would terminate, and this guards against regressing to it.
        $out = $null
        { $out = Log-Message -Level ERROR -Message 'bad-thing' -InvocationName 'T' } | Should -Not -Throw
        $out | Should -BeNullOrEmpty
    }

    It 'STATUS does not write to Output stream' {
        # STATUS uses Write-Host (stream 6), must not land on the pipeline.
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
#  Log-Message rendering: Text is the default, Json is the OTel record
#
#  Routing must be IDENTICAL in both formats. Only the string changes.
# ============================================================

Describe 'Log-Message rendering' {

    AfterEach {
        $script:LogFormat = 'Text'
    }

    It 'Defaults to Text' {
        # The whole point: an existing deployment that passes no -LogFormat and
        # sets no environment variable must log exactly as it always has.
        $script:LogFormat | Should -Be 'Text'
    }

    It 'Text renders HH:mm:ss [Invocation] Message' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'hello' -InvocationName 'MyFunc' } 4>&1
        "$out" | Should -Match '^\d{2}:\d{2}:\d{2} \[MyFunc\] hello$'
    }

    It 'Json renders one parseable object per line' {
        $script:LogFormat = 'Json'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'hello' -InvocationName 'MyFunc' } 4>&1

        { "$out" | ConvertFrom-Json } | Should -Not -Throw
        "$out" | Should -Not -Match "`n"
    }

    It 'Json carries the OTel field set' {
        $script:LogFormat = 'Json'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'hello' -InvocationName 'MyFunc' } 4>&1
        $record = "$out" | ConvertFrom-Json

        $record.level           | Should -Be 'INFO'
        $record.severity_number | Should -Be 9
        $record.message         | Should -Be 'hello'
        $record.invocation      | Should -Be 'MyFunc'
        $record.'service.name'  | Should -Be 'MyFunc'   # falls back to invocation
    }

    It 'Json timestamp is an ISO-8601 UTC string on the wire' {
        $script:LogFormat = 'Json'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' } 4>&1

        # Assert on the RAW line, never on a ConvertFrom-Json round trip:
        # ConvertFrom-Json re-hydrates an ISO-8601 string into a [datetime] and
        # then renders it in LOCAL format, so a parsed value tells you nothing
        # about what was actually emitted. What a collector ingests is this text.
        "$out" | Should -Match '^\{"timestamp":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z",'
    }

    It 'Json emits timestamp first, as the OTel field order requires' {
        $script:LogFormat = 'Json'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' } 4>&1
        "$out" | Should -Match '"level":"INFO","severity_number":9,"message":"x"'
    }

    It 'Maps every level to its OTel severity number' {
        $script:LogFormat = 'Json'
        $expected = @{ DEBUG = 5; INFO = 9; STATUS = 9; WARN = 13; ERROR = 17 }

        foreach ($level in $expected.Keys)
        {
            # 6>&1 catches STATUS/ERROR (Write-Host), 4>&1 DEBUG/INFO, 3>&1 WARN.
            $out = & { $VerbosePreference = 'Continue'; Log-Message -Level $level -Message 'x' -InvocationName 'T' } 6>&1 4>&1 3>&1
            ("$out" | ConvertFrom-Json).severity_number | Should -Be $expected[$level]
        }
    }

    It 'STATUS keeps its own name in SeverityText' {
        # OTel treats SeverityText as the source's vocabulary, so STATUS survives
        # as a name while still sorting at INFO severity.
        $script:LogFormat = 'Json'
        $out = & { Log-Message -Level STATUS -Message 'milestone' -InvocationName 'T' } 6>&1
        $record = "$out" | ConvertFrom-Json
        $record.level           | Should -Be 'STATUS'
        $record.severity_number | Should -Be 9
    }

    It 'Merges -Data as additional attributes' {
        $script:LogFormat = 'Json'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' -Data @{ group_id = 'g1'; removed = 3 } } 4>&1
        $record = "$out" | ConvertFrom-Json
        $record.group_id | Should -Be 'g1'
        $record.removed  | Should -Be 3
    }

    It 'Ignores -Data in Text mode rather than corrupting the line' {
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'plain' -InvocationName 'T' -Data @{ ignored = 'yes' } } 4>&1
        "$out" | Should -Match '^\d{2}:\d{2}:\d{2} \[T\] plain$'
    }

    It 'JsonIndented is multi-line and still parses' {
        $script:LogFormat = 'JsonIndented'
        $out = & { $VerbosePreference = 'Continue'; Log-Message -Level INFO -Message 'x' -InvocationName 'T' } 4>&1
        ("$out" | ConvertFrom-Json).message | Should -Be 'x'
    }

    It 'Routes each level to the SAME stream in Json as in Text' {
        # The routing is a hard constraint. ERROR on Write-Error would terminate
        # under -EAP Stop, so it must stay on Write-Host in every format.
        foreach ($format in 'Text', 'Json')
        {
            $script:LogFormat = $format

            (& { $VerbosePreference = 'Continue'; Log-Message -Level INFO   -Message 'm' -InvocationName 'T' } 4>&1) | Should -Not -BeNullOrEmpty
            (& { Log-Message -Level WARN   -Message 'm' -InvocationName 'T' } 3>&1)                                  | Should -Not -BeNullOrEmpty
            (& { Log-Message -Level STATUS -Message 'm' -InvocationName 'T' } 6>&1)                                  | Should -Not -BeNullOrEmpty
            (& { Log-Message -Level ERROR  -Message 'm' -InvocationName 'T' } 6>&1)                                  | Should -Not -BeNullOrEmpty

            # Nothing on the success stream in either format.
            $out = Log-Message -Level STATUS -Message 'm' -InvocationName 'T'
            $out | Should -BeNullOrEmpty
        }
    }

    It 'Never throws on ERROR in Json mode' {
        $script:LogFormat = 'Json'
        { Log-Message -Level ERROR -Message 'bad' -InvocationName 'T' } | Should -Not -Throw
    }
}

# ============================================================
#  Write-SyncSummary: banner in Text, records in Json
# ============================================================

Describe 'Write-SyncSummary' {

    BeforeAll {
        $script:OneGroup = @(
            [pscustomobject]@{
                GroupId      = 'g1'
                Name         = 'Linux Prod'
                SourceVar    = 'GroupConfig-1'
                Failed       = $false
                Added        = @([pscustomobject]@{ Id = 'dev-a'; DisplayName = 'srv01.contoso.local' })
                Removed      = @()
                Pending      = @('srv09.contoso.local')
                Skipped      = @()
                FinalMembers = @([pscustomobject]@{ Id = 'dev-a'; DisplayName = 'srv01.contoso.local' })
            }
        )
    }

    AfterEach {
        $script:LogFormat = 'Text'
    }

    It 'Text still prints the ASCII banner' {
        $out = Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | Out-String
        $out | Should -Match 'SYNC SUMMARY REPORT'
        $out | Should -Match 'CURRENT DEVICE MEMBERS'
        $out | Should -Match '={20,}'
    }

    It 'Text emits no JSON' {
        $out = Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | Out-String
        $out | Should -Not -Match '"event"'
    }

    It 'Json emits one group_summary record per group plus a run_summary' {
        $script:LogFormat = 'Json'
        $lines = @(Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | ForEach-Object { "$_" })

        $records = @($lines | ForEach-Object { $_ | ConvertFrom-Json })
        @($records | Where-Object { $_.event -eq 'group_summary' }).Count | Should -Be 1
        @($records | Where-Object { $_.event -eq 'run_summary' }).Count   | Should -Be 1
    }

    It 'Json emits no ASCII banner' {
        $script:LogFormat = 'Json'
        $out = Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | Out-String
        $out | Should -Not -Match 'SYNC SUMMARY REPORT'
    }

    It 'group_summary carries the counts and the device lists' {
        $script:LogFormat = 'Json'
        $lines = @(Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | ForEach-Object { "$_" })
        $group = @($lines | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event -eq 'group_summary' })[0]

        $group.group_id            | Should -Be 'g1'
        $group.group_name          | Should -Be 'Linux Prod'
        $group.source_variable     | Should -Be 'GroupConfig-1'
        $group.failed              | Should -BeFalse
        $group.added_count         | Should -Be 1
        $group.pending_count       | Should -Be 1
        $group.device_member_count | Should -Be 1
        $group.added[0].id           | Should -Be 'dev-a'
        $group.added[0].display_name | Should -Be 'srv01.contoso.local'
    }

    It 'Device lists stay JSON ARRAYS even with exactly one entry' {
        # A bare 'return @(...)' unrolls a one-element array, so a single-device
        # group would serialise 'added' as an object while a two-device group
        # serialised it as an array. A log backend rejects that as a field type
        # conflict, and it would only ever show up in production.
        $script:LogFormat = 'Json'
        $lines = @(Write-SyncSummary -GroupResults $script:OneGroup -TotalErrors 0 6>&1 | ForEach-Object { "$_" })
        $raw = @($lines | Where-Object { $_ -match '"event":"group_summary"' })[0]

        $raw | Should -Match '"added":\['
        $raw | Should -Match '"device_members":\['
        $raw | Should -Match '"removed":\[\]'
        $raw | Should -Match '"skipped":\[\]'
        $raw | Should -Match '"pending":\['
    }

    It 'run_summary totals are numbers, never null, on an empty run' {
        # Measure-Object sums an empty set to $null. A null total is not the same
        # as zero to whatever is reading these.
        $script:LogFormat = 'Json'
        $lines = @(Write-SyncSummary -GroupResults @() -TotalErrors 0 6>&1 | ForEach-Object { "$_" })
        $run = @($lines | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event -eq 'run_summary' })[0]

        $run.group_count   | Should -Be 0
        $run.total_added   | Should -Be 0
        $run.total_removed | Should -Be 0
        $run.total_errors  | Should -Be 0
    }

    It 'run_summary reports failed groups' {
        $script:LogFormat = 'Json'
        $failed = @(
            [pscustomobject]@{
                GroupId = 'g2'; Name = 'Broken'; SourceVar = 'GroupConfig-2'; Failed = $true
                Added = @(); Removed = @(); Pending = @(); Skipped = @(); FinalMembers = @()
            }
        )
        $lines = @(Write-SyncSummary -GroupResults $failed -TotalErrors 1 6>&1 | ForEach-Object { "$_" })
        $run = @($lines | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.event -eq 'run_summary' })[0]

        $run.failed_groups | Should -Be 1
        $run.total_errors  | Should -Be 1
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

    It 'Returns an ARRAY even for a single name' {
        # A bare 'return $Names' unrolls a one-element array to a String on the
        # way out. MAIN then reads $AutomationVariableNames.Count, and a scalar
        # has no Count under StrictMode Latest, so a tenant configured with
        # exactly one Automation Variable crashed before it synced anything.
        $result = NormalizeVariableNames -Names 'GroupConfig-only'
        ($result -is [array]) | Should -BeTrue
        $result.Count         | Should -Be 1
        { $null = $result.Count } | Should -Not -Throw
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

    It 'Does not throw on a single double quote' {
        # A lone " satisfies BOTH StartsWith('"') and EndsWith('"'), so without
        # the length guard Substring(1, -1) throws.
        { Sanitize-InputString -Value '"' } | Should -Not -Throw
    }

    It 'Returns a single double quote unchanged' {
        Sanitize-InputString -Value '"' | Should -Be '"'
    }

    It 'Does not throw on a two-character pair of quotes' {
        { Sanitize-InputString -Value '""' } | Should -Not -Throw
    }
}

# ============================================================
#  ConvertTo-Bool and Resolve-BooleanParameter
#
#  Azure Automation hands job schedule parameters over as strings, and a plain
#  [bool] cast makes EVERY non-empty string $true. A field reading 'false' would
#  mean the opposite of what it says.
# ============================================================

Describe 'ConvertTo-Bool' {

    It 'Converts <Value> to <Expected>' -TestCases @(
        @{ Value = 'true';  Expected = $true  }
        @{ Value = 'TRUE';  Expected = $true  }
        @{ Value = 'True';  Expected = $true  }
        @{ Value = '1';     Expected = $true  }
        @{ Value = 'yes';   Expected = $true  }
        @{ Value = 'Y';     Expected = $true  }
        @{ Value = 'false'; Expected = $false }
        @{ Value = 'FALSE'; Expected = $false }
        @{ Value = 'False'; Expected = $false }
        @{ Value = '0';     Expected = $false }
        @{ Value = 'no';    Expected = $false }
        @{ Value = 'N';     Expected = $false }
    ) {
        param ($Value, $Expected)
        ConvertTo-Bool -Value $Value | Should -Be $Expected
    }

    It "Converts 'false' to FALSE, which a [bool] cast does not" {
        # The whole reason this function exists.
        [bool]'false'              | Should -BeTrue    # the trap
        ConvertTo-Bool -Value 'false' | Should -BeFalse   # the fix
    }

    It 'Tolerates surrounding whitespace' {
        ConvertTo-Bool -Value '  false  ' | Should -BeFalse
        ConvertTo-Bool -Value "`ttrue`t"  | Should -BeTrue
    }

    It 'Treats empty and whitespace as false' {
        ConvertTo-Bool -Value ''    | Should -BeFalse
        ConvertTo-Bool -Value '   ' | Should -BeFalse
        ConvertTo-Bool -Value $null | Should -BeFalse
    }

    It 'Throws on <Value> rather than guessing' -TestCases @(
        @{ Value = 'ture' }
        @{ Value = 'flase' }
        @{ Value = 'maybe' }
        @{ Value = '2' }
        @{ Value = '$false' }
    ) {
        param ($Value)
        { ConvertTo-Bool -Value $Value } | Should -Throw
    }
}

Describe 'Resolve-BooleanParameter' {

    It 'Passes a real boolean straight through' {
        Resolve-BooleanParameter -Value $true  -Default $false -Name 'T' | Should -BeTrue
        Resolve-BooleanParameter -Value $false -Default $true  -Name 'T' | Should -BeFalse
    }

    It 'An EMPTY field takes the default, and does not mean false' {
        # The trap this wrapper exists for. ConvertTo-Bool maps empty to $false,
        # which is right for a flag defaulting off and wrong for
        # DefaultRemoveStale, whose default is $true. Clearing the schedule field
        # must not silently disable stale removal across every group.
        Resolve-BooleanParameter -Value ''    -Default $true -Name 'DefaultRemoveStale' | Should -BeTrue
        Resolve-BooleanParameter -Value '   ' -Default $true -Name 'DefaultRemoveStale' | Should -BeTrue
        Resolve-BooleanParameter -Value $null -Default $true -Name 'DefaultRemoveStale' | Should -BeTrue
    }

    It 'An empty field still takes a false default' {
        Resolve-BooleanParameter -Value '' -Default $false -Name 'DryRun' | Should -BeFalse
    }

    It 'A supplied string overrides the default in both directions' {
        Resolve-BooleanParameter -Value 'false' -Default $true  -Name 'T' | Should -BeFalse
        Resolve-BooleanParameter -Value 'true'  -Default $false -Name 'T' | Should -BeTrue
        Resolve-BooleanParameter -Value 'no'    -Default $true  -Name 'T' | Should -BeFalse
    }

    It 'Throws on a typo rather than falling back to the default' {
        # Falling back would be worse than failing: the job would run in a mode
        # nobody asked for, and the schedule would still read 'flase'.
        { Resolve-BooleanParameter -Value 'flase' -Default $true -Name 'T' } | Should -Throw
    }
}

# ============================================================
#  Resolve-Device
#
#  Contract: returns { Status; Ids = @(...) }.
#    Resolved  → Ids has one or more entries (multiple = identical-name duplicates)
#    Ambiguous → Ids empty (matches span different displaynames)
#    Pending   → Ids empty (nothing matched in either tier)
#
#  Two tiers only. There is no fuzzy prefix tier.
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
    }

    It 'Resolves via exact FQDN match (single id)' {
        $r = Resolve-Device -DeviceName 'server01.contoso.local' -ExactIndex $script:Exact -ShortIndex $script:Short
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 1
        $r.Ids[0]    | Should -Be 'id-fqdn'
    }

    It 'Resolves via short-name match when full name not in exact index' {
        # 'server01' is not an exact key (only the FQDN is), so it falls to short index.
        $r = Resolve-Device -DeviceName 'server01' -ExactIndex $script:Exact -ShortIndex $script:Short
        $r.Status | Should -Be 'Resolved'
        $r.Ids[0] | Should -Be 'id-fqdn'
    }

    It 'Resolves via case-insensitive exact match' {
        $r = Resolve-Device -DeviceName 'SERVER01.CONTOSO.LOCAL' -ExactIndex $script:Exact -ShortIndex $script:Short
        $r.Status | Should -Be 'Resolved'
        $r.Ids[0] | Should -Be 'id-fqdn'
    }

    It 'Exact match with multiple ids (identical displayName) adds ALL' {
        $dupExact = @{ 'dup.contoso.local' = [System.Collections.Generic.List[string]]@('id-1', 'id-2') }
        $r = Resolve-Device -DeviceName 'dup.contoso.local' -ExactIndex $dupExact -ShortIndex @{}
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
        $r = Resolve-Device -DeviceName 'dup' -ExactIndex @{} -ShortIndex $dupShort
        $r.Status    | Should -Be 'Resolved'
        $r.Ids.Count | Should -Be 2
    }

    It 'Short match across DIFFERENT full names is Ambiguous (skip)' {
        $ambShort = @{ 'web01' = @(
            [pscustomobject]@{ Id = 'id-a'; Full = 'web01.site-a.local' }
            [pscustomobject]@{ Id = 'id-b'; Full = 'web01.site-b.local' }
        ) }
        $r = Resolve-Device -DeviceName 'web01' -ExactIndex @{} -ShortIndex $ambShort
        $r.Status    | Should -Be 'Ambiguous'
        $r.Ids.Count | Should -Be 0
    }

    It 'Returns Pending when nothing matches' {
        $r = Resolve-Device -DeviceName 'unknown-host' -ExactIndex @{} -ShortIndex @{}
        $r.Status    | Should -Be 'Pending'
        $r.Ids.Count | Should -Be 0
    }

    It 'A prefix of a real device name is Pending, NOT a silent match' {
        # The reason the fuzzy tier is gone: 'srv1' used to StartsWith-match
        # 'srv10.contoso.local' with a single candidate, so it bound silently and
        # put the wrong host in an EDR policy group.
        $exact = @{ 'srv10.contoso.local' = [System.Collections.Generic.List[string]]@('id-srv10') }
        $short = @{ 'srv10' = @([pscustomobject]@{ Id = 'id-srv10'; Full = 'srv10.contoso.local' }) }

        $r = Resolve-Device -DeviceName 'srv1' -ExactIndex $exact -ShortIndex $short
        $r.Status    | Should -Be 'Pending'
        $r.Ids.Count | Should -Be 0
    }

    It 'An empty device name resolves to Pending and never matches everything' {
        # StartsWith('') matched every device in the tenant. Config load drops
        # blank entries now, and this is the second line of defence.
        $exact = @{ 'srv10.contoso.local' = [System.Collections.Generic.List[string]]@('id-srv10') }
        $short = @{ 'srv10' = @([pscustomobject]@{ Id = 'id-srv10'; Full = 'srv10.contoso.local' }) }

        $r = Resolve-Device -DeviceName '' -ExactIndex $exact -ShortIndex $short
        $r.Status    | Should -Be 'Pending'
        $r.Ids.Count | Should -Be 0
    }
}

# ============================================================
#  Build-DeviceIndex
#
#  Contract: returns $exactIndex, $shortIndex where
#    $exactIndex[name]  = List[string] of ids  (all ids for that displayName)
#    $shortIndex[short] = list of { Id; Full }
# ============================================================

Describe 'Build-DeviceIndex' {

    BeforeAll {
        $script:StandardPage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'id-alpha'; displayName = 'alpha.contoso.local' }
                [pscustomobject]@{ id = 'id-beta';  displayName = 'beta' }
            )
        }

        function global:Invoke-RestMethod { $script:StandardPage }
    }

    AfterAll {
        function global:Invoke-RestMethod { [pscustomobject]@{ value = @() } }
    }

    It 'Exact index contains the full FQDN lowercased' {
        $exact, $short = Build-DeviceIndex
        $exact.ContainsKey('alpha.contoso.local') | Should -BeTrue
    }

    It 'Short index contains the short name lowercased' {
        $exact, $short = Build-DeviceIndex
        $short.ContainsKey('alpha') | Should -BeTrue
    }

    It 'Exact index maps a single-object name to its id' {
        $exact, $short = Build-DeviceIndex
        @($exact['alpha.contoso.local'])[0] | Should -Be 'id-alpha'
    }

    It 'Short-name-only device is indexed in the exact index under its name' {
        $exact, $short = Build-DeviceIndex
        $exact.ContainsKey('beta')   | Should -BeTrue
        @($exact['beta'])[0]         | Should -Be 'id-beta'
    }

    It 'Returns exactly two indexes, with no fuzzy list' {
        $result = Build-DeviceIndex
        @($result).Count | Should -Be 2
    }

    It 'Identical displayNames keep BOTH ids (multi-match policy)' {
        $dupPage = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id = 'first';  displayName = 'dup-host' }
                [pscustomobject]@{ id = 'second'; displayName = 'dup-host' }
            )
        }
        function global:Invoke-RestMethod { $dupPage }

        $exact, $short = Build-DeviceIndex
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

        $exact, $short = Build-DeviceIndex
        $exact.ContainsKey('valid-host') | Should -BeTrue
        $exact.Count                     | Should -Be 1
    }
}

# ============================================================
#  Get-GraphErrorInfo
#
#  Callers branch on Status and Code. The prose in Message is for humans only.
# ============================================================

Describe 'Get-GraphErrorInfo' {

    It 'Extracts the HTTP status code as an integer' {
        $err = Get-GraphErrorInfo -ErrorRecord (New-GraphErrorRecord -StatusCode 403)
        $err.Status | Should -Be 403
    }

    It 'Extracts the Graph error code from the response body' {
        $body = '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}'
        $err  = Get-GraphErrorInfo -ErrorRecord (New-GraphErrorRecord -StatusCode 403 -Body $body)
        $err.Code    | Should -Be 'Authorization_RequestDenied'
        $err.Message | Should -Be 'Insufficient privileges.'
    }

    It 'Reports status 0 when there was no HTTP response at all' {
        $record = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('socket closed'), 'x', 'NotSpecified', $null)
        $err = Get-GraphErrorInfo -ErrorRecord $record
        $err.Status | Should -Be 0
    }

    It 'Renders a missing status as HTTP ? in the log text' {
        $record = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('socket closed'), 'x', 'NotSpecified', $null)
        (Get-GraphErrorInfo -ErrorRecord $record).Text | Should -Match '^HTTP \?'
    }

    It 'Leaves Code empty when the body is not JSON' {
        $err = Get-GraphErrorInfo -ErrorRecord (New-GraphErrorRecord -StatusCode 500 -Body '<html>gateway</html>')
        $err.Code | Should -BeNullOrEmpty
        $err.Text | Should -Match 'gateway'
    }

    It 'Leaves Code empty when the JSON has no error object' {
        $err = Get-GraphErrorInfo -ErrorRecord (New-GraphErrorRecord -StatusCode 400 -Body '{"something":"else"}')
        $err.Code | Should -BeNullOrEmpty
    }

    It 'Get-GraphError returns the same text' {
        $record = New-GraphErrorRecord -StatusCode 404 -Body '{"error":{"code":"Request_ResourceNotFound","message":"gone"}}'
        Get-GraphError -ErrorRecord $record | Should -Be (Get-GraphErrorInfo -ErrorRecord $record).Text
    }
}

# ============================================================
#  Invoke-WithRetry
#
#  Retrying a 403 six times at twenty seconds a go, per device, is a route to
#  the three hour job cap. Only 408, 429, 5xx and transport failures retry.
# ============================================================

Describe 'Invoke-WithRetry' {

    BeforeEach {
        $script:Attempts = 0
    }

    It 'Does not retry a 403' {
        $MaxRetries = 4
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'forbidden' -ScriptBlock {
            $script:Attempts++
            throw (New-GraphErrorRecord -StatusCode 403 -Body '{"error":{"code":"Authorization_RequestDenied","message":"no"}}')
        } } | Should -Throw

        $script:Attempts | Should -Be 1
    }

    It 'Does not retry a 404' {
        $MaxRetries = 4
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'not found' -ScriptBlock {
            $script:Attempts++
            throw (New-GraphErrorRecord -StatusCode 404)
        } } | Should -Throw

        $script:Attempts | Should -Be 1
    }

    It 'Retries a 429 until the budget is exhausted' {
        $MaxRetries = 3
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'throttled' -ScriptBlock {
            $script:Attempts++
            throw (New-GraphErrorRecord -StatusCode 429)
        } } | Should -Throw

        $script:Attempts | Should -Be 3
    }

    It 'Retries a 503' {
        $MaxRetries = 2
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'unavailable' -ScriptBlock {
            $script:Attempts++
            throw (New-GraphErrorRecord -StatusCode 503)
        } } | Should -Throw

        $script:Attempts | Should -Be 2
    }

    It 'Does not retry a failure that produced no HTTP response' {
        # Status 0: a transport failure, or a bug in the scriptblock raising a
        # plain exception. Neither gets better on attempt six.
        $MaxRetries = 4
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'socket' -ScriptBlock {
            $script:Attempts++
            throw 'connection reset by peer'
        } } | Should -Throw

        $script:Attempts | Should -Be 1
    }

    It 'Refreshes the token once on 401 and retries exactly once' {
        # Six retries against a permanently bad grant is five wasted minutes per
        # device. One refresh, one retry, then out.
        $MaxRetries = 6
        $RetryDelaySeconds = 0

        { Invoke-WithRetry -OperationName 'unauthorised' -ScriptBlock {
            $script:Attempts++
            throw (New-GraphErrorRecord -StatusCode 401)
        } } | Should -Throw

        $script:Attempts | Should -Be 2
    }

    It 'Returns the scriptblock result when it succeeds' {
        Invoke-WithRetry -OperationName 'ok' -ScriptBlock { 'the-value' } | Should -Be 'the-value'
    }

    It 'Succeeds on a retry after a transient failure' {
        $MaxRetries = 3
        $RetryDelaySeconds = 0

        $result = Invoke-WithRetry -OperationName 'flaky' -ScriptBlock {
            $script:Attempts++
            if ($script:Attempts -lt 2) { throw (New-GraphErrorRecord -StatusCode 503) }
            'recovered'
        }

        $result           | Should -Be 'recovered'
        $script:Attempts  | Should -Be 2
    }
}

# ============================================================
#  Get-AllGroupMembers: device-only membership
#
#  Stale removal is a set difference against a device-only resolved set and
#  nothing inspects @odata.type, so a plain /members read would classify every
#  user and nested group in a target group as stale and delete it.
# ============================================================

Describe 'Get-AllGroupMembers device cast' {

    BeforeAll {
        # The mixed membership a plain /members read would return.
        $script:MixedMembers = @(
            [pscustomobject]@{ id = 'user-1';   displayName = 'Alice';        '@odata.type' = '#microsoft.graph.user' }
            [pscustomobject]@{ id = 'group-1';  displayName = 'Nested Group'; '@odata.type' = '#microsoft.graph.group' }
            [pscustomobject]@{ id = 'sp-1';     displayName = 'Some App';     '@odata.type' = '#microsoft.graph.servicePrincipal' }
            [pscustomobject]@{ id = 'device-1'; displayName = 'srv01.contoso.local'; '@odata.type' = '#microsoft.graph.device' }
            [pscustomobject]@{ id = 'device-2'; displayName = 'srv02.contoso.local'; '@odata.type' = '#microsoft.graph.device' }
        )

        # Stands in for Graph: honours the OData cast in the URI the way the
        # service does, and records every URI it was asked for.
        function global:Invoke-RestMethod
        {
            param ($Uri, $Headers, $Method, $Body, $ContentType)

            $script:RequestedUris += $Uri

            if ($Uri -match 'microsoft\.graph\.device')
            {
                return [pscustomobject]@{ value = @($script:MixedMembers | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device' }) }
            }

            return [pscustomobject]@{ value = $script:MixedMembers }
        }
    }

    AfterAll {
        function global:Invoke-RestMethod { [pscustomobject]@{ value = @() } }
    }

    BeforeEach {
        $script:RequestedUris = @()
    }

    It 'Requests the microsoft.graph.device cast' {
        $null = Get-AllGroupMembers -GroupId 'group-id'
        $script:RequestedUris[0] | Should -Match '/members/microsoft\.graph\.device'
    }

    It 'Returns device members only' {
        $members = Get-AllGroupMembers -GroupId 'group-id'
        @($members).Count | Should -Be 2
        @($members | Select-Object -ExpandProperty Id) | Should -Not -Contain 'user-1'
        @($members | Select-Object -ExpandProperty Id) | Should -Not -Contain 'group-1'
        @($members | Select-Object -ExpandProperty Id) | Should -Not -Contain 'sp-1'
    }

    It 'Never passes a non-device id to Remove-DeviceFromGroup' {
        # The full stale-removal path in miniature: read membership, diff it
        # against the resolved device set, remove what is left over.
        $currentMembers = Get-AllGroupMembers -GroupId 'group-id'

        $resolvedIdSet = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]@('device-1'), [System.StringComparer]::OrdinalIgnoreCase)

        $stale = @($currentMembers | Where-Object { -not $resolvedIdSet.Contains($_.Id) })

        $script:RequestedUris = @()
        foreach ($member in $stale)
        {
            Remove-DeviceFromGroup -GroupId 'group-id' -DeviceId $member.Id -DisplayName $member.DisplayName
        }

        $deleted = $script:RequestedUris -join ' '
        $deleted | Should -Not -Match 'user-1'
        $deleted | Should -Not -Match 'group-1'
        $deleted | Should -Not -Match 'sp-1'
        $deleted | Should -Match 'device-2'
    }
}

# ============================================================
#  ShouldProcess gating on the two leaf write functions
# ============================================================

Describe 'WhatIf gating' {

    BeforeAll {
        function global:Invoke-RestMethod
        {
            param ($Uri, $Headers, $Method, $Body, $ContentType)
            $script:WriteCount++
        }
    }

    AfterAll {
        function global:Invoke-RestMethod { [pscustomobject]@{ value = @() } }
    }

    BeforeEach {
        $script:WriteCount = 0
    }

    It 'Add-DeviceToGroup makes no call when $WhatIfPreference is true' {
        $WhatIfPreference = $true
        Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' -DisplayName 'srv01'
        $script:WriteCount | Should -Be 0
    }

    It 'Remove-DeviceFromGroup makes no call when $WhatIfPreference is true' {
        $WhatIfPreference = $true
        Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' -DisplayName 'srv01'
        $script:WriteCount | Should -Be 0
    }

    It 'Add-DeviceToGroup does call Graph when $WhatIfPreference is false' {
        $WhatIfPreference = $false
        Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' -DisplayName 'srv01'
        $script:WriteCount | Should -Be 1
    }

    It 'Remove-DeviceFromGroup does call Graph when $WhatIfPreference is false' {
        $WhatIfPreference = $false
        Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' -DisplayName 'srv01'
        $script:WriteCount | Should -Be 1
    }

    It 'Neither write function ever prompts' {
        # ConfirmImpact is Medium and $ConfirmPreference is None, so ShouldProcess
        # must not try to prompt. A prompt in the Automation sandbox throws under
        # $ErrorActionPreference = 'Stop'.
        $WhatIfPreference = $false
        { Add-DeviceToGroup      -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
        { Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
    }
}

# ============================================================
#  Group write error handling: status codes, not message text
# ============================================================

Describe 'Add-DeviceToGroup error handling' {

    AfterAll {
        function global:Invoke-RestMethod { [pscustomobject]@{ value = @() } }
    }

    It 'Treats 400 Request_BadRequest as already a member and does not throw' {
        $body = '{"error":{"code":"Request_BadRequest","message":"One or more added object references already exist."}}'
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 400 -Body $body) }

        { Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
    }

    It 'Does not depend on the words already exist' {
        # Same status and code, completely different prose. Graph has rewritten
        # this message before and will again.
        $body = '{"error":{"code":"Request_BadRequest","message":"Zut alors, la reference existe deja."}}'
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 400 -Body $body) }

        { Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
    }

    It 'Still throws on 403' {
        $body = '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}'
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 403 -Body $body) }

        { Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' } | Should -Throw
    }

    It 'Still throws on 404' {
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 404) }

        { Add-DeviceToGroup -GroupId 'g' -DeviceId 'd' } | Should -Throw
    }
}

Describe 'Remove-DeviceFromGroup error handling' {

    AfterAll {
        function global:Invoke-RestMethod { [pscustomobject]@{ value = @() } }
    }

    It 'Treats 404 as already removed and does not throw' {
        $body = '{"error":{"code":"Request_ResourceNotFound","message":"Resource not found."}}'
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 404 -Body $body) }

        { Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
    }

    It 'Does not depend on the words does not exist' {
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 404 -Body '{"error":{"code":"ResourceNotFound","message":"nope"}}') }

        { Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' } | Should -Not -Throw
    }

    It 'Still throws on 403' {
        $body = '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges."}}'
        function global:Invoke-RestMethod { throw (New-GraphErrorRecord -StatusCode 403 -Body $body) }

        { Remove-DeviceFromGroup -GroupId 'g' -DeviceId 'd' } | Should -Throw
    }
}

# ============================================================
#  Initialize-ManagedIdentityAuth
# ============================================================

Describe 'Initialize-ManagedIdentityAuth' {

    BeforeAll {
        function global:Connect-AzAccount
        {
            param ([switch] $Identity, [string] $AccountId, [string] $ErrorAction)
            $script:ConnectCalls += [pscustomobject]@{ Identity = [bool]$Identity; AccountId = $AccountId }
        }
    }

    AfterAll {
        function global:Connect-AzAccount { }
    }

    BeforeEach {
        $script:ConnectCalls = @()
    }

    It 'Connects with no AccountId when the client id is blank' {
        $ManagedIdentityClientId = ''
        Initialize-ManagedIdentityAuth

        @($script:ConnectCalls).Count      | Should -Be 1
        $script:ConnectCalls[0].Identity   | Should -BeTrue
        $script:ConnectCalls[0].AccountId  | Should -BeNullOrEmpty
    }

    It 'Connects with no AccountId when the client id is whitespace' {
        $ManagedIdentityClientId = '   '
        Initialize-ManagedIdentityAuth

        $script:ConnectCalls[0].AccountId | Should -BeNullOrEmpty
    }

    It 'Passes a valid GUID through as AccountId' {
        $ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555'
        Initialize-ManagedIdentityAuth

        $script:ConnectCalls[0].AccountId | Should -Be '11111111-2222-3333-4444-555555555555'
    }

    It 'Throws on a client id that is not a GUID' {
        $ManagedIdentityClientId = 'not-a-guid'
        { Initialize-ManagedIdentityAuth } | Should -Throw

        @($script:ConnectCalls).Count | Should -Be 0
    }

    It 'Does NOT fall back to the system-assigned identity when a UAMI fails' {
        # The old silent fallback authenticated as a different principal with
        # potentially different group-write permissions. That must now be fatal.
        function global:Connect-AzAccount
        {
            param ([switch] $Identity, [string] $AccountId, [string] $ErrorAction)
            $script:ConnectCalls += [pscustomobject]@{ Identity = [bool]$Identity; AccountId = $AccountId }
            throw 'identity not available'
        }

        $ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555'
        { Initialize-ManagedIdentityAuth } | Should -Throw

        # Exactly one attempt: the requested UAMI. No second, un-scoped attempt.
        @($script:ConnectCalls).Count     | Should -Be 1
        $script:ConnectCalls[0].AccountId | Should -Be '11111111-2222-3333-4444-555555555555'
    }
}
