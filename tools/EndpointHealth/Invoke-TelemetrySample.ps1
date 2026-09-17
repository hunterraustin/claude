<#
.SYNOPSIS
    One iteration of the always-on telemetry sampler.

.DESCRIPTION
    Invoked by the scheduled task created by Start-HealthCampaign.ps1. Each run:

      1. Checks whether the campaign has expired and tears itself down if so.
      2. Takes a lightweight performance-counter sample (a few KB).
      3. Records the top processes by CPU, private working set and IO.
      4. Evaluates trigger thresholds against recent samples.
      5. Fires a bounded deep capture (WPR or Procmon) when a trigger holds.
      6. Pushes staged data to the share on the configured interval.

    This is the piece that replaces "run Procmon for seven days". Continuous
    cost is a CSV row every few minutes. The expensive tracing only happens in
    the window where something is actually wrong.

.PARAMETER ConfigPath
    Path to config.json.

.PARAMETER Once
    Run a single sample and return, ignoring campaign state. Useful for testing
    the collector by hand.
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $Once
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

$config = Get-EHConfig -ConfigPath $ConfigPath
$state  = Get-EHState -Config $config

if (-not $state -and -not $Once) {
    Write-Warning 'No campaign state found. Run Start-HealthCampaign.ps1 first, or pass -Once.'
    return
}

$runName = if ($state) { $state.RunName } else { $null }
$layout  = New-EHRunLayout -Config $config -RunName $runName
Initialize-EHLog -Path (Join-Path $layout.Logs 'agent.log')

$logicalCpus = [int]$env:NUMBER_OF_PROCESSORS
if ($logicalCpus -lt 1) { $logicalCpus = 1 }

#region campaign expiry -----------------------------------------------------

if ($state -and -not $Once) {
    $endUtc = [datetime]::Parse($state.EndUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
    if ((Get-Date).ToUniversalTime() -ge $endUtc) {
        Write-EHLog ("Campaign ended at {0}. Running final analysis and tearing down." -f $endUtc)

        try {
            & (Join-Path $PSScriptRoot 'Invoke-TelemetryAnalysis.ps1') -ConfigPath $ConfigPath -RunName $layout.RunName
        }
        catch {
            Write-EHLog ("Final analysis failed: {0}" -f $_.Exception.Message) -Level ERROR
        }

        if (Test-EHSharePath -Path $config.SharePath) {
            [void](Invoke-EHUpload -Source $layout.Root -Destination $layout.ShareRoot)
        }

        # Teardown is detached on purpose. This script is running *inside* the
        # scheduled task it is about to unregister, so doing it inline risks
        # killing the process before the unregister completes, which would
        # leave the task in place trying to tear itself down every interval.
        try {
            $stopScript = Join-Path $PSScriptRoot 'Stop-HealthCampaign.ps1'
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $stopArgs = @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden'
                '-Command'
                ('Start-Sleep -Seconds 20; & "{0}" -ConfigPath "{1}" -KeepLocalData -SkipFinalUpload' -f $stopScript, $ConfigPath)
            )
            Start-Process -FilePath $psExe -ArgumentList $stopArgs -WindowStyle Hidden | Out-Null
            Write-EHLog 'Teardown handed off to a detached process.'
        }
        catch {
            Write-EHLog ("Could not hand off teardown: {0}. Run Stop-HealthCampaign.ps1 by hand." -f $_.Exception.Message) -Level ERROR
        }
        return
    }
}

#endregion

#region counter sample ------------------------------------------------------

function Get-SystemSample {
    <#
        One pass over the system-wide counters. Paths are resolved through the
        registry index table so this works on a non-English Windows build.
    #>
    [CmdletBinding()]
    param()

    $paths = @{
        # Processor Information is preferred over Processor: it is accurate on
        # machines with more than 64 logical processors and it exposes the
        # frequency ratio used for throttling detection.
        'cpu_total_pct'        = Get-EHCounterPath -Object 'Processor Information' -Counter '% Processor Time'    -Instance '_Total'
        'cpu_privileged_pct'   = Get-EHCounterPath -Object 'Processor Information' -Counter '% Privileged Time'   -Instance '_Total'
        'cpu_interrupt_pct'    = Get-EHCounterPath -Object 'Processor Information' -Counter '% Interrupt Time'    -Instance '_Total'
        'cpu_max_freq_pct'     = Get-EHCounterPath -Object 'Processor Information' -Counter '% of Maximum Frequency' -Instance '_Total'

        'sys_processor_queue'  = Get-EHCounterPath -Object 'System' -Counter 'Processor Queue Length'
        'sys_context_switches' = Get-EHCounterPath -Object 'System' -Counter 'Context Switches/sec'
        'sys_processes'        = Get-EHCounterPath -Object 'System' -Counter 'Processes'
        'sys_threads'          = Get-EHCounterPath -Object 'System' -Counter 'Threads'

        'mem_available_mb'     = Get-EHCounterPath -Object 'Memory' -Counter 'Available MBytes'
        'mem_committed_pct'    = Get-EHCounterPath -Object 'Memory' -Counter '% Committed Bytes In Use'
        # Pages Input/sec is the hard fault rate: pages that had to come off
        # disk. This is what "the machine is thrashing" looks like numerically.
        'mem_hard_faults_sec'  = Get-EHCounterPath -Object 'Memory' -Counter 'Pages Input/sec'
        'mem_pool_nonpaged_mb' = Get-EHCounterPath -Object 'Memory' -Counter 'Pool Nonpaged Bytes'
        'mem_pool_paged_mb'    = Get-EHCounterPath -Object 'Memory' -Counter 'Pool Paged Bytes'
        'mem_cache_faults_sec' = Get-EHCounterPath -Object 'Memory' -Counter 'Cache Faults/sec'

        # Latency counters are in seconds. Converted to ms below.
        'disk_read_latency_ms' = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Avg. Disk sec/Read'  -Instance '_Total'
        'disk_write_latency_ms'= Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Avg. Disk sec/Write' -Instance '_Total'
        'disk_queue_length'    = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Current Disk Queue Length' -Instance '_Total'
        'disk_idle_pct'        = Get-EHCounterPath -Object 'PhysicalDisk' -Counter '% Idle Time'         -Instance '_Total'
        'disk_reads_sec'       = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Disk Reads/sec'      -Instance '_Total'
        'disk_writes_sec'      = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Disk Writes/sec'     -Instance '_Total'
        'disk_bytes_sec'       = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Disk Bytes/sec'      -Instance '_Total'

        'proc_handle_count'    = Get-EHCounterPath -Object 'Process' -Counter 'Handle Count' -Instance '_Total'
    }

    $raw = Get-EHCounterSample -Paths $paths

    # Latency comes back in seconds; everybody reasons about it in ms.
    foreach ($k in @('disk_read_latency_ms', 'disk_write_latency_ms')) {
        if ($raw.ContainsKey($k)) { $raw[$k] = [math]::Round($raw[$k] * 1000, 3) }
    }
    foreach ($k in @('mem_pool_nonpaged_mb', 'mem_pool_paged_mb')) {
        if ($raw.ContainsKey($k)) { $raw[$k] = [math]::Round($raw[$k] / 1MB, 1) }
    }
    if ($raw.ContainsKey('disk_idle_pct')) {
        $raw['disk_busy_pct'] = [math]::Round([math]::Max(0, 100 - $raw['disk_idle_pct']), 1)
    }

    # Network throughput across all live adapters, summed.
    try {
        $netPath = Get-EHCounterPath -Object 'Network Interface' -Counter 'Bytes Total/sec' -Instance '*'
        $net = Get-Counter -Counter $netPath -MaxSamples 1 -ErrorAction Stop
        $raw['net_bytes_sec'] = [math]::Round((
            $net.CounterSamples |
                Where-Object { $_.InstanceName -notmatch 'isatap|Loopback|Teredo' } |
                Measure-Object -Property CookedValue -Sum).Sum, 0)
    }
    catch { }

    $raw
}

$sample = Get-SystemSample

# Fixed column order keeps Export-Csv -Append happy across restarts even when
# a counter goes missing on one pass.
$columns = @(
    'timestamp_local', 'timestamp_utc',
    'cpu_total_pct', 'cpu_privileged_pct', 'cpu_interrupt_pct', 'cpu_max_freq_pct',
    'sys_processor_queue', 'sys_context_switches', 'sys_processes', 'sys_threads',
    'mem_available_mb', 'mem_committed_pct', 'mem_hard_faults_sec',
    'mem_pool_nonpaged_mb', 'mem_pool_paged_mb', 'mem_cache_faults_sec',
    'disk_read_latency_ms', 'disk_write_latency_ms', 'disk_queue_length',
    'disk_busy_pct', 'disk_reads_sec', 'disk_writes_sec', 'disk_bytes_sec',
    'net_bytes_sec', 'proc_handle_count', 'logged_on_user', 'session_count'
)

$now = Get-Date
$row = [ordered]@{}
foreach ($c in $columns) { $row[$c] = $null }
$row['timestamp_local'] = $now.ToString('yyyy-MM-dd HH:mm:ss')
$row['timestamp_utc']   = $now.ToUniversalTime().ToString('o')
foreach ($k in $sample.Keys) {
    if ($row.Contains($k)) { $row[$k] = $sample[$k] }
}

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $row['logged_on_user'] = ConvertTo-EHSafeString -Value $cs.UserName -Redact:([bool]$config.RedactUserNames)
    $row['session_count']  = @(Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10').Count
}
catch { }

$samplesCsv = Join-Path $layout.Telemetry 'samples.csv'
# -Force lets the append tolerate a column-set change between agent versions
# rather than erroring out and losing the sample.
[pscustomobject]$row | Export-Csv -LiteralPath $samplesCsv -NoTypeInformation -Append -Force -Encoding UTF8

#endregion

#region process sample ------------------------------------------------------

function Get-ProcessSample {
    <#
        Per-process CPU, private working set and IO throughput in a single
        counter pass. Per-process "% Processor Time" is relative to one core,
        so it is divided by the logical processor count to get a share of the
        whole machine.
    #>
    [CmdletBinding()]
    param([int] $Top = 12)

    $result = @{}

    $sets = @{
        cpu_pct   = Get-EHCounterPath -Object 'Process' -Counter '% Processor Time'    -Instance '*'
        wsp_mb    = Get-EHCounterPath -Object 'Process' -Counter 'Working Set - Private' -Instance '*'
        io_bps    = Get-EHCounterPath -Object 'Process' -Counter 'IO Data Bytes/sec'  -Instance '*'
        handles   = Get-EHCounterPath -Object 'Process' -Counter 'Handle Count'       -Instance '*'
    }

    foreach ($metric in $sets.Keys) {
        try {
            $s = Get-Counter -Counter $sets[$metric] -MaxSamples 1 -ErrorAction Stop
            foreach ($cs in $s.CounterSamples) {
                $name = $cs.InstanceName
                if ($name -in '_Total', 'Idle', 'memory compression') { continue }
                if (-not $result.ContainsKey($name)) {
                    $result[$name] = [ordered]@{ name = $name; cpu_pct = 0; wsp_mb = 0; io_bps = 0; handles = 0 }
                }
                $value = [double]$cs.CookedValue
                switch ($metric) {
                    'cpu_pct' { $result[$name].cpu_pct = [math]::Round($value / $logicalCpus, 2) }
                    'wsp_mb'  { $result[$name].wsp_mb  = [math]::Round($value / 1MB, 1) }
                    'io_bps'  { $result[$name].io_bps  = [math]::Round($value, 0) }
                    'handles' { $result[$name].handles = [int]$value }
                }
            }
        }
        catch {
            Write-EHLog ("Process counter '{0}' unavailable: {1}" -f $metric, $_.Exception.Message) -Level DEBUG
        }
    }

    $all = @($result.Values | ForEach-Object { [pscustomobject]$_ })

    # Keep the union of the three top-N lists. A process that is quiet on CPU
    # but hammering the disk is exactly the one worth catching.
    $keep = @()
    $keep += $all | Sort-Object cpu_pct -Descending | Select-Object -First $Top
    $keep += $all | Sort-Object wsp_mb  -Descending | Select-Object -First $Top
    $keep += $all | Sort-Object io_bps  -Descending | Select-Object -First $Top
    $keep | Sort-Object name -Unique
}

$processes = Get-ProcessSample
$processCsv = Join-Path $layout.Telemetry 'processes.csv'
$processes |
    Select-Object @{ n = 'timestamp_local'; e = { $now.ToString('yyyy-MM-dd HH:mm:ss') } },
                  name, cpu_pct, wsp_mb, io_bps, handles |
    Export-Csv -LiteralPath $processCsv -NoTypeInformation -Append -Force -Encoding UTF8

#endregion

#region triggers ------------------------------------------------------------

function Test-Triggers {
    <#
        Returns the list of thresholds this sample breached. A trigger only
        counts once it has held for ConsecutiveSamples passes, which keeps a
        one-off spike (opening Outlook) from burning a capture slot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Sample,
        [Parameter(Mandatory)] $Thresholds
    )

    # label, metric key, threshold, direction
    $checks = @(
        @('SustainedCpu',     'cpu_total_pct',          $Thresholds.CpuPercent,         'above')
        @('DiskReadLatency',  'disk_read_latency_ms',   $Thresholds.DiskReadLatencyMs,  'above')
        @('DiskWriteLatency', 'disk_write_latency_ms',  $Thresholds.DiskWriteLatencyMs, 'above')
        @('DiskQueue',        'disk_queue_length',      $Thresholds.DiskQueueLength,    'above')
        @('HardFaults',       'mem_hard_faults_sec',    $Thresholds.HardFaultsPerSec,   'above')
        @('ProcessorQueue',   'sys_processor_queue',    $Thresholds.ProcessorQueue,     'above')
        @('LowMemory',        'mem_available_mb',       $Thresholds.AvailableMemoryMB,  'below')
    )

    $hits = New-Object System.Collections.ArrayList

    foreach ($check in $checks) {
        $label     = $check[0]
        $key       = $check[1]
        $limit     = $check[2]
        $direction = $check[3]

        if ($null -eq $limit) { continue }
        if (-not $Sample.ContainsKey($key)) { continue }

        $value = $Sample[$key]
        $breached = if ($direction -eq 'above') { $value -gt $limit } else { $value -lt $limit }

        if ($breached) {
            [void]$hits.Add([pscustomobject]@{
                Name      = $label
                Metric    = $key
                Value     = $value
                Threshold = $limit
                Direction = $direction
            })
        }
    }

    @($hits)
}

$thresholds = $config.Triggers
$hits = Test-Triggers -Sample $sample -Thresholds $thresholds

# Consecutive-breach tracking lives in campaign state so it survives the
# process exiting between scheduled runs.
if (-not $state) {
    $state = [pscustomobject]@{
        RunName = $layout.RunName
        EndUtc  = (Get-Date).ToUniversalTime().AddDays(1).ToString('o')
        Streaks = [pscustomobject]@{}
        Captures = @()
        LastUploadUtc = $null
    }
}
if (-not $state.PSObject.Properties['Streaks'])  { $state | Add-Member -NotePropertyName Streaks  -NotePropertyValue ([pscustomobject]@{}) -Force }
if (-not $state.PSObject.Properties['Captures']) { $state | Add-Member -NotePropertyName Captures -NotePropertyValue @() -Force }
if (-not $state.PSObject.Properties['LastUploadUtc']) { $state | Add-Member -NotePropertyName LastUploadUtc -NotePropertyValue $null -Force }

$hitNames = @($hits | ForEach-Object { $_.Name })
$streaks  = @{}
foreach ($p in $state.Streaks.PSObject.Properties) { $streaks[$p.Name] = [int]$p.Value }
foreach ($name in $hitNames) {
    $previous = 0
    if ($streaks.ContainsKey($name)) { $previous = [int]$streaks[$name] }
    $streaks[$name] = $previous + 1
}
foreach ($key in @($streaks.Keys)) {
    if ($key -notin $hitNames) { $streaks[$key] = 0 }
}
$state.Streaks = [pscustomobject]$streaks

$required = [int]$thresholds.ConsecutiveSamples
if ($required -lt 1) { $required = 1 }
$confirmed = @($hits | Where-Object { $streaks[$_.Name] -ge $required })

if ($hits.Count -gt 0) {
    Write-EHLog ("Threshold breach: {0}" -f (($hits | ForEach-Object {
        '{0}={1} ({2} {3})' -f $_.Metric, $_.Value, $_.Direction, $_.Threshold
    }) -join '; ')) -Level WARN
}

#endregion

#region deep capture --------------------------------------------------------

function Test-CaptureBudget {
    <#
        Guards against a machine that is simply always busy turning the deep
        capture into a continuous trace, which is the failure mode this whole
        design exists to avoid.
    #>
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)] $DeepCapture
    )

    if (-not $DeepCapture.Enabled) { return @{ Allowed = $false; Reason = 'deep capture disabled in config' } }

    $captures = @($State.Captures)
    $today = (Get-Date).Date
    $todayCount = @($captures | Where-Object {
        $_.StartedUtc -and ([datetime]::Parse($_.StartedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().Date -eq $today
    }).Count

    if ($todayCount -ge [int]$DeepCapture.MaxPerDay) {
        return @{ Allowed = $false; Reason = ('daily cap reached ({0})' -f $DeepCapture.MaxPerDay) }
    }

    $last = $captures | Sort-Object StartedUtc -Descending | Select-Object -First 1
    if ($last -and $last.StartedUtc) {
        $lastUtc = [datetime]::Parse($last.StartedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $minutes = ((Get-Date).ToUniversalTime() - $lastUtc).TotalMinutes
        if ($minutes -lt [int]$DeepCapture.CooldownMinutes) {
            return @{ Allowed = $false; Reason = ('cooldown, {0:N0} of {1} minutes elapsed' -f $minutes, $DeepCapture.CooldownMinutes) }
        }
    }

    $staged = Get-EHFolderSizeMB -Path $layout.Root
    if ($staged -ge [int]$config.MaxLocalStageMB) {
        return @{ Allowed = $false; Reason = ('local stage at {0} MB, cap is {1} MB' -f $staged, $config.MaxLocalStageMB) }
    }

    @{ Allowed = $true; Reason = 'ok' }
}

if ($confirmed.Count -gt 0 -and -not $Once) {
    $budget = Test-CaptureBudget -State $state -DeepCapture $config.DeepCapture

    if (-not $budget.Allowed) {
        Write-EHLog ("Trigger confirmed but capture skipped: {0}" -f $budget.Reason) -Level WARN
    }
    else {
        $reason = ($confirmed | ForEach-Object { '{0}={1}' -f $_.Metric, $_.Value }) -join ','
        Write-EHLog ("Trigger confirmed ({0}). Starting deep capture." -f $reason)

        try {
            $capture = & (Join-Path $PSScriptRoot 'Invoke-DeepCapture.ps1') `
                            -ConfigPath $ConfigPath `
                            -RunName $layout.RunName `
                            -Reason $reason

            $state.Captures = @($state.Captures) + @($capture)

            # Reset the streaks so the next capture needs a fresh breach.
            $state.Streaks = [pscustomobject]@{}
        }
        catch {
            Write-EHLog ("Deep capture failed: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }
}

#endregion

#region upload --------------------------------------------------------------

$shouldUpload = $false
if (-not $Once) {
    if (-not $state.LastUploadUtc) {
        $shouldUpload = $true
    }
    else {
        $lastUpload = [datetime]::Parse($state.LastUploadUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $shouldUpload = ((Get-Date).ToUniversalTime() - $lastUpload).TotalMinutes -ge [int]$config.UploadIntervalMinutes
    }
}

if ($shouldUpload) {
    if (Test-EHSharePath -Path $config.SharePath) {
        # Refresh the rolling analysis so the share always holds a current
        # SUMMARY.txt rather than only one at the end of the campaign.
        try {
            & (Join-Path $PSScriptRoot 'Invoke-TelemetryAnalysis.ps1') -ConfigPath $ConfigPath -RunName $layout.RunName -Quiet
        }
        catch {
            Write-EHLog ("Rolling analysis failed: {0}" -f $_.Exception.Message) -Level WARN
        }

        if (Invoke-EHUpload -Source $layout.Root -Destination $layout.ShareRoot) {
            $state.LastUploadUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    else {
        Write-EHLog ("Share {0} unreachable, deferring upload." -f $config.SharePath) -Level WARN
    }
}

#endregion

#region stage cap -----------------------------------------------------------

$stagedMb = Get-EHFolderSizeMB -Path $layout.Root
if ($stagedMb -ge [int]$config.MaxLocalStageMB) {
    Write-EHLog ("Local stage is {0} MB (cap {1} MB). Pruning oldest captures." -f $stagedMb, $config.MaxLocalStageMB) -Level WARN

    # Captures are the only large artifacts and the oldest are the least
    # useful. Telemetry CSVs and the snapshot are never pruned.
    #
    # Each capture is a directory (captures\20260917-142233\), so prune whole
    # directories rather than loose files.
    $captureDirs = @(Get-ChildItem -LiteralPath $layout.Captures -Directory -ErrorAction SilentlyContinue |
                     Sort-Object Name)

    foreach ($dir in $captureDirs) {
        if ((Get-EHFolderSizeMB -Path $layout.Root) -lt [int]$config.MaxLocalStageMB) { break }

        # Keep the capture metadata so the analysis still knows the capture
        # happened and why, even once the trace itself is gone.
        Get-ChildItem -LiteralPath $dir.FullName -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne 'capture.json' } |
            ForEach-Object {
                Write-EHLog ("  pruning {0}\{1}" -f $dir.Name, $_.Name) -Level WARN
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            }
    }
}

#endregion

if (-not $Once) {
    Set-EHState -Config $config -State $state
}

[pscustomobject]@{
    RunName    = $layout.RunName
    Sample     = $sample
    Triggers   = $confirmed
    StagedMB   = Get-EHFolderSizeMB -Path $layout.Root
}
