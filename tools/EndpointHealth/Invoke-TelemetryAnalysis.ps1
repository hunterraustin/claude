<#
.SYNOPSIS
    Turns a run's raw collection into a ranked list of findings.

.DESCRIPTION
    Reads the snapshot JSON files and the telemetry CSVs from a run folder,
    flattens everything into a single metric namespace, evaluates the
    correlation rules against it, and writes three artifacts:

      metrics.json  every metric the run produced, for writing new rules
      findings.json machine-readable findings with resolved evidence
      SUMMARY.txt   the "important stuff to review" a human reads first

    The rules live in rules\correlation-rules.json and are data, not code. Add
    a rule by adding an object; no changes here are needed.

.PARAMETER RunName
    Run folder to analyse. Defaults to the active campaign, then to the most
    recent run under LocalRoot\runs.

.PARAMETER ListMetrics
    Print the metric namespace for this run and exit. Use this when writing a
    new rule so the metric names are exact.

.PARAMETER Quiet
    Suppress console output. The files are still written.

.EXAMPLE
    .\Invoke-TelemetryAnalysis.ps1 -RunName WKS042_9-17_1059
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $RunName,
    [string] $RulesPath,
    [switch] $ListMetrics,
    [switch] $Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

$config = Get-EHConfig -ConfigPath $ConfigPath

if (-not $RunName) {
    $state = Get-EHState -Config $config
    if ($state) { $RunName = $state.RunName }
}
if (-not $RunName) {
    $runsRoot = Join-Path $config.LocalRoot 'runs'
    if (Test-Path -LiteralPath $runsRoot) {
        $latest = Get-ChildItem -LiteralPath $runsRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $RunName = $latest.Name }
    }
}
if (-not $RunName) { throw 'No run to analyse. Run Invoke-HealthSnapshot.ps1 or Start-HealthCampaign.ps1 first.' }

$layout = New-EHRunLayout -Config $config -RunName $RunName
Initialize-EHLog -Path (Join-Path $layout.Logs 'analysis.log')

if (-not $RulesPath) { $RulesPath = Join-Path $PSScriptRoot 'rules\correlation-rules.json' }
if (-not (Test-Path -LiteralPath $RulesPath)) { throw ("Rules file not found at {0}" -f $RulesPath) }

$ruleDoc = Get-Content -LiteralPath $RulesPath -Raw | ConvertFrom-Json

#region metric namespace ----------------------------------------------------

$metrics = [ordered]@{}

function Set-Metric {
    param([string] $Name, $Value)
    if ($null -eq $Value) { return }
    $metrics[$Name] = $Value
}

function Read-SnapshotFile {
    param([string] $FileName)
    $path = Join-Path $layout.Snapshot $FileName
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    catch {
        Write-EHLog ("Could not parse {0}: {1}" -f $FileName, $_.Exception.Message) -Level WARN
        $null
    }
}

function Get-Prop {
    <#
        Property access that returns $null instead of throwing when the object
        or the property is missing. Snapshot sections degrade independently, so
        half of them may be absent on any given run.
    #>
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p) { return $null }
    $p.Value
}

function Get-ArrayProp {
    <#
        Reads a property that should be a collection and always returns a real
        array with no null elements. A collector that failed leaves a section
        holding only CollectorError, so the property is simply absent and
        @($null) would otherwise produce a one-element array of nothing.
    #>
    param($Object, [string] $Name)

    $value = Get-Prop $Object $Name
    if ($null -eq $value) { return @() }
    @($value) | Where-Object { $null -ne $_ }
}

function Get-NumericColumn {
    <#
        Pulls one CSV column out as doubles, discarding blanks. A counter that
        was unavailable on some passes leaves gaps rather than zeros, and
        treating those gaps as zero would badly skew every percentile.
    #>
    param($Rows, [string] $Column)

    $out = New-Object System.Collections.Generic.List[double]
    foreach ($r in $Rows) {
        $p = $r.PSObject.Properties[$Column]
        if (-not $p) { continue }
        $v = $p.Value
        if ($null -eq $v -or "$v" -eq '') { continue }
        $parsed = 0.0
        if ([double]::TryParse("$v", [ref]$parsed)) { $out.Add($parsed) }
    }
    , $out.ToArray()
}

#endregion

#region system, hardware, storage, security, network ------------------------

$system = Read-SnapshotFile 'system.json'
if ($system) {
    Set-Metric 'system.computerName'      (Get-Prop $system 'ComputerName')
    Set-Metric 'system.model'             ('{0} {1}' -f (Get-Prop $system 'Manufacturer'), (Get-Prop $system 'Model'))
    Set-Metric 'system.serialNumber'      (Get-Prop $system 'SerialNumber')
    Set-Metric 'system.osCaption'         (Get-Prop $system 'OsCaption')
    Set-Metric 'system.osBuild'           (Get-Prop $system 'OsBuild')
    Set-Metric 'system.osDisplayVersion'  (Get-Prop $system 'OsDisplayVersion')
    Set-Metric 'system.uptimeDays'        (Get-Prop $system 'UptimeDays')
    Set-Metric 'system.biosVersion'       (Get-Prop $system 'BiosVersion')
    Set-Metric 'system.biosAgeDays'       (Get-Prop $system 'BiosAgeDays')
    Set-Metric 'system.isLaptop'          (Get-Prop $system 'IsLaptop')
    Set-Metric 'system.memoryGB'          (Get-Prop $system 'TotalMemoryGB')
    Set-Metric 'system.logicalProcessors' (Get-Prop $system 'LogicalProcessors')
}

$hardware = Read-SnapshotFile 'hardware.json'
if ($hardware) {
    Set-Metric 'hw.problemDeviceCount' (Get-Prop $hardware 'ProblemDeviceCount')
    $problem = @(Get-ArrayProp $hardware 'ProblemDevices')
    if ($problem.Count -gt 0) {
        Set-Metric 'hw.problemDeviceNames' @($problem | ForEach-Object { '{0} (code {1})' -f $_.Name, $_.ErrorCode })
    }

    $zones = @(Get-ArrayProp $hardware 'ThermalZones')
    if ($zones.Count -gt 0) {
        Set-Metric 'hw.thermalMaxC' ([math]::Round((@($zones | ForEach-Object { [double]$_.TemperatureC }) | Measure-Object -Maximum).Maximum, 1))
    }

    $battery = Get-Prop $hardware 'Battery'
    if ($battery) { Set-Metric 'hw.batteryHealthPercent' (Get-Prop $battery 'HealthPercent') }

    $gpus = @(Get-ArrayProp $hardware 'GraphicsCards')
    if ($gpus.Count -gt 0) {
        Set-Metric 'hw.gpuNames' @($gpus | ForEach-Object { $_.Name })
        $ages = @($gpus | ForEach-Object { $_.DriverAgeDays } | Where-Object { $null -ne $_ })
        if ($ages.Count -gt 0) { Set-Metric 'hw.gpuDriverAgeDays.max' (($ages | Measure-Object -Maximum).Maximum) }
    }

    Set-Metric 'hardware.memoryModuleCount' (Get-Prop $hardware 'MemorySlotsUsed')

    $cpus = @(Get-ArrayProp $hardware 'Processors')
    if ($cpus.Count -gt 0) {
        $ratios = @($cpus | ForEach-Object { $_.ClockRatioPercent } | Where-Object { $null -ne $_ })
        if ($ratios.Count -gt 0) { Set-Metric 'hw.cpuClockRatioPercent.min' (($ratios | Measure-Object -Minimum).Minimum) }
        Set-Metric 'hw.cpuName' $cpus[0].Name
    }
}

$storage = Read-SnapshotFile 'storage.json'
if ($storage) {
    $disks = @(Get-ArrayProp $storage 'PhysicalDisks')
    if ($disks.Count -gt 0) {
        Set-Metric 'disk.mediaTypes'    @($disks | ForEach-Object { "$($_.MediaType)" } | Sort-Object -Unique)
        Set-Metric 'disk.healthSummary' @($disks | ForEach-Object { '{0}: {1}' -f $_.FriendlyName, $_.HealthStatus })
        Set-Metric 'disk.unhealthyCount' @($disks | Where-Object { $_.HealthStatus -and "$($_.HealthStatus)" -ne 'Healthy' }).Count

        $wear = @($disks | ForEach-Object { $_.WearPercent } | Where-Object { $null -ne $_ })
        if ($wear.Count -gt 0) { Set-Metric 'disk.wearPercent.max' (($wear | Measure-Object -Maximum).Maximum) }

        $hours = @($disks | ForEach-Object { $_.PowerOnHours } | Where-Object { $null -ne $_ })
        if ($hours.Count -gt 0) { Set-Metric 'disk.powerOnHours.max' (($hours | Measure-Object -Maximum).Maximum) }

        $readErr = @($disks | ForEach-Object { $_.ReadErrorsTotal } | Where-Object { $null -ne $_ })
        if ($readErr.Count -gt 0) { Set-Metric 'disk.readErrorsTotal.max' (($readErr | Measure-Object -Maximum).Maximum) }

        $uncorrected = @($disks | ForEach-Object { $_.ReadErrorsUncorrected; $_.WriteErrorsUncorrected } | Where-Object { $null -ne $_ })
        if ($uncorrected.Count -gt 0) { Set-Metric 'disk.uncorrectedErrors.max' (($uncorrected | Measure-Object -Maximum).Maximum) }

        $temps = @($disks | ForEach-Object { $_.TemperatureC } | Where-Object { $null -ne $_ -and $_ -gt 0 })
        if ($temps.Count -gt 0) { Set-Metric 'disk.temperatureC.max' (($temps | Measure-Object -Maximum).Maximum) }
    }

    Set-Metric 'disk.smartPredictFailureCount' @(@(Get-ArrayProp $storage 'SmartPredict') | Where-Object { $_.PredictFailure }).Count

    $volumes = @(Get-ArrayProp $storage 'Volumes')
    if ($volumes.Count -gt 0) {
        Set-Metric 'disk.freePercent.min' (($volumes | ForEach-Object { [double]$_.FreePercent } | Measure-Object -Minimum).Minimum)
        Set-Metric 'disk.freeGB.min'      (($volumes | ForEach-Object { [double]$_.FreeGB } | Measure-Object -Minimum).Minimum)
        Set-Metric 'disk.volumeSummary'   @($volumes | ForEach-Object { '{0} {1}GB free of {2}GB ({3}%)' -f $_.DeviceID, $_.FreeGB, $_.SizeGB, $_.FreePercent })
    }

    $trim = Get-Prop $storage 'TrimStatus'
    if ($trim) {
        # fsutil prints "DisableDeleteNotify = 1" when TRIM is off. NTFS and
        # ReFS are reported separately on newer builds.
        Set-Metric 'disk.trimDisabled' ([bool]($trim -match 'DisableDeleteNotify\s*(\(\w+\))?\s*=\s*1'))
    }

    Set-Metric 'storage.pageFileAutoManaged' (Get-Prop $storage 'PageFileAutoManaged')
}

$security = Read-SnapshotFile 'security.json'
if ($security) {
    Set-Metric 'security.antivirusCount' (Get-Prop $security 'AntivirusCount')
    $av = @(Get-ArrayProp $security 'AntivirusProducts')
    if ($av.Count -gt 0) { Set-Metric 'security.antivirusNames' @($av | ForEach-Object { $_.DisplayName }) }

    $def = Get-Prop $security 'Defender'
    if ($def) {
        Set-Metric 'defender.realTimeEnabled'      (Get-Prop $def 'RealTimeProtectionEnabled')
        Set-Metric 'defender.tamperProtected'      (Get-Prop $def 'IsTamperProtected')
        Set-Metric 'defender.signatureAgeDays'     (Get-Prop $def 'AntivirusSignatureAge')
        Set-Metric 'defender.fullScanAgeDays'      (Get-Prop $def 'FullScanAge')
        Set-Metric 'defender.exclusionPathCount'   (Get-Prop $def 'ExclusionPathCount')
        Set-Metric 'defender.scanAvgCpuLoadFactor' (Get-Prop $def 'ScanAvgCPULoadFactor')
    }
}

$network = Read-SnapshotFile 'network.json'
if ($network) {
    $adapters = @(Get-ArrayProp $network 'Adapters')
    if ($adapters.Count -gt 0) {
        $errors = @($adapters | ForEach-Object { [double]($_.ReceivedErrors); [double]($_.OutboundErrors) } | Where-Object { $null -ne $_ })
        $discards = @($adapters | ForEach-Object { [double]($_.ReceivedDiscarded); [double]($_.OutboundDiscarded) } | Where-Object { $null -ne $_ })
        if ($errors.Count -gt 0)   { Set-Metric 'net.adapterErrors.total'   (($errors | Measure-Object -Sum).Sum) }
        if ($discards.Count -gt 0) { Set-Metric 'net.adapterDiscards.total' (($discards | Measure-Object -Sum).Sum) }

        Set-Metric 'net.linkSpeeds' @($adapters | ForEach-Object { '{0}: {1}' -f $_.Name, $_.LinkSpeed })
        $driverAges = @($adapters | ForEach-Object { $_.DriverAgeDays } | Where-Object { $null -ne $_ })
        if ($driverAges.Count -gt 0) { Set-Metric 'net.driverAgeDays.max' (($driverAges | Measure-Object -Maximum).Maximum) }
    }

    $ipcfg = @(Get-ArrayProp $network 'IPConfiguration')
    if ($ipcfg.Count -gt 0) {
        Set-Metric 'net.dnsServers' @($ipcfg | ForEach-Object { $_.DnsServers } | Where-Object { $_ } | Sort-Object -Unique)
    }
}

$softwareSnap = Read-SnapshotFile 'software.json'
if ($softwareSnap) {
    Set-Metric 'software.startupItemCount' @(Get-ArrayProp $softwareSnap 'StartupItems').Count
    Set-Metric 'software.autoServicesStoppedCount' @(Get-ArrayProp $softwareSnap 'AutoServicesStopped').Count
    Set-Metric 'software.installedCount' (Get-Prop $softwareSnap 'InstalledCount')

    $pending = Get-Prop $softwareSnap 'PendingReboot'
    if ($pending) {
        Set-Metric 'software.pendingReboot' ([bool]((Get-Prop $pending 'CbsRebootPending') -or
                                                     (Get-Prop $pending 'WindowsUpdate') -or
                                                     (Get-Prop $pending 'PendingFileRename')))
    }
}

$powerSnap = Read-SnapshotFile 'power.json'
if ($powerSnap) { Set-Metric 'power.activePlan' (Get-Prop $powerSnap 'ActivePlan') }

#endregion

#region events --------------------------------------------------------------

$eventsSnap = Read-SnapshotFile 'events.json'
if ($eventsSnap) {
    $eventMap = @{
        'events.whea.count'            = 'Whea'
        'events.kernelPower41.count'   = 'KernelPower41'
        'events.bugCheck.count'        = 'BugCheck'
        'events.disk.count'            = 'DiskErrors'
        'events.ntfs.count'            = 'NtfsErrors'
        'events.volmgr.count'          = 'VolmgrErrors'
        'events.tdr.count'             = 'DisplayTdr'
        'events.serviceFailures.count' = 'ServiceFailures'
        'events.dnsClient.count'       = 'DnsClient'
        'events.netlogon.count'        = 'NetlogonErrors'
        'events.timeService.count'     = 'TimeService'
        'events.smbClient.count'       = 'SmbClient'
        'events.appCrashes.count'      = 'AppCrashes'
        'events.appHangs.count'        = 'AppHangs'
        'events.dotNet.count'          = 'DotNetErrors'
        'events.groupPolicy.count'     = 'GroupPolicy'
        'events.wmi.count'             = 'WmiActivity'
        'events.memoryDiagnostic.count'= 'MemoryDiagnostic'
    }
    foreach ($metricName in $eventMap.Keys) {
        $section = Get-Prop $eventsSnap $eventMap[$metricName]
        if ($section) { Set-Metric $metricName (Get-Prop $section 'Count') }
    }
    Set-Metric 'events.lookbackDays' (Get-Prop $eventsSnap 'LookbackDays')
}

$reliabilitySnap = Read-SnapshotFile 'reliability.json'
if ($reliabilitySnap) {
    $bootStats = Get-Prop $reliabilitySnap 'BootTimeMsStats'
    if ($bootStats) {
        Set-Metric 'boot.timeMs.p95' (Get-Prop $bootStats 'P95')
        Set-Metric 'boot.timeMs.max' (Get-Prop $bootStats 'Max')
        Set-Metric 'boot.timeMs.avg' (Get-Prop $bootStats 'Avg')
        Set-Metric 'boot.count'      (Get-Prop $bootStats 'Count')
    }
    Set-Metric 'boot.fastStartupEnabled' (Get-Prop $reliabilitySnap 'FastStartupEnabled')

    $boots = @(Get-ArrayProp $reliabilitySnap 'Boots')
    if ($boots.Count -gt 0) {
        $deg = @($boots | ForEach-Object { $_.DegradationMs } | Where-Object { $null -ne $_ })
        if ($deg.Count -gt 0) { Set-Metric 'boot.degradationMs.max' (($deg | Measure-Object -Maximum).Maximum) }
    }
}

#endregion

#region telemetry -----------------------------------------------------------

$samplesCsv = Join-Path $layout.Telemetry 'samples.csv'
$sampleRows = @()
if (Test-Path -LiteralPath $samplesCsv) {
    $sampleRows = @(Import-Csv -LiteralPath $samplesCsv)
}

Set-Metric 'telemetry.sampleCount' $sampleRows.Count
if ($sampleRows.Count -gt 0) {
    Set-Metric 'telemetry.firstSample' $sampleRows[0].timestamp_local
    Set-Metric 'telemetry.lastSample'  $sampleRows[-1].timestamp_local

    # column -> metric prefix, and which aggregates matter for each
    $seriesMap = @(
        @{ Column = 'cpu_total_pct';          Prefix = 'cpu.total';          Stats = @('p95', 'max', 'avg') }
        @{ Column = 'cpu_privileged_pct';     Prefix = 'cpu.privileged';     Stats = @('p95', 'max') }
        @{ Column = 'cpu_interrupt_pct';      Prefix = 'cpu.interrupt';      Stats = @('p95', 'max') }
        @{ Column = 'cpu_max_freq_pct';       Prefix = 'cpu.maxFreqPct';     Stats = @('p05', 'avg', 'min') }
        @{ Column = 'sys_processor_queue';    Prefix = 'sys.processorQueue'; Stats = @('p95', 'max') }
        @{ Column = 'sys_context_switches';   Prefix = 'sys.contextSwitches';Stats = @('p95', 'avg') }
        @{ Column = 'sys_processes';          Prefix = 'sys.processes';      Stats = @('max', 'avg') }
        @{ Column = 'sys_threads';            Prefix = 'sys.threads';        Stats = @('max', 'avg') }
        @{ Column = 'mem_available_mb';       Prefix = 'mem.availableMB';    Stats = @('p05', 'min', 'avg') }
        @{ Column = 'mem_committed_pct';      Prefix = 'mem.committedPct';   Stats = @('max', 'p95', 'avg') }
        @{ Column = 'mem_hard_faults_sec';    Prefix = 'mem.hardFaults';     Stats = @('p95', 'max') }
        @{ Column = 'mem_pool_nonpaged_mb';   Prefix = 'mem.poolNonpagedMB'; Stats = @('max', 'avg') }
        @{ Column = 'mem_pool_paged_mb';      Prefix = 'mem.poolPagedMB';    Stats = @('max', 'avg') }
        @{ Column = 'disk_read_latency_ms';   Prefix = 'disk.readLatencyMs'; Stats = @('p95', 'max', 'avg') }
        @{ Column = 'disk_write_latency_ms';  Prefix = 'disk.writeLatencyMs';Stats = @('p95', 'max', 'avg') }
        @{ Column = 'disk_queue_length';      Prefix = 'disk.queue';         Stats = @('p95', 'max') }
        @{ Column = 'disk_busy_pct';          Prefix = 'disk.busyPct';       Stats = @('p95', 'avg') }
        @{ Column = 'disk_bytes_sec';         Prefix = 'disk.bytesSec';      Stats = @('p95', 'max') }
        @{ Column = 'net_bytes_sec';          Prefix = 'net.bytesSec';       Stats = @('p95', 'max') }
        @{ Column = 'proc_handle_count';      Prefix = 'sys.handles';        Stats = @('max', 'avg') }
    )

    foreach ($series in $seriesMap) {
        $values = Get-NumericColumn -Rows $sampleRows -Column $series.Column
        if ($values.Count -eq 0) { continue }

        $stats = Get-EHStats -Values $values
        foreach ($stat in $series.Stats) {
            switch ($stat) {
                'p95' { Set-Metric ('{0}.p95' -f $series.Prefix) $stats.P95 }
                'p50' { Set-Metric ('{0}.p50' -f $series.Prefix) $stats.P50 }
                'p05' { Set-Metric ('{0}.p05' -f $series.Prefix) (Get-EHPercentile -Values $values -Percentile 5) }
                'max' { Set-Metric ('{0}.max' -f $series.Prefix) $stats.Max }
                'min' { Set-Metric ('{0}.min' -f $series.Prefix) $stats.Min }
                'avg' { Set-Metric ('{0}.avg' -f $series.Prefix) $stats.Avg }
            }
        }
    }
}

#endregion

#region process aggregation -------------------------------------------------

$processCsv = Join-Path $layout.Telemetry 'processes.csv'
$processSummary = @()

if (Test-Path -LiteralPath $processCsv) {
    $procRows = @(Import-Csv -LiteralPath $processCsv)

    # Perf counter instance names disambiguate duplicates with #1, #2 and so
    # on. svchost#4 and svchost#11 are the same program, so collapse them.
    $grouped = $procRows |
        Where-Object { $_.name } |
        Group-Object -Property { ($_.name -replace '#\d+$', '').ToLowerInvariant() }

    foreach ($group in $grouped) {
        $cpuValues = Get-NumericColumn -Rows $group.Group -Column 'cpu_pct'
        $ioValues  = Get-NumericColumn -Rows $group.Group -Column 'io_bps'
        $memValues = Get-NumericColumn -Rows $group.Group -Column 'wsp_mb'
        $hdlValues = Get-NumericColumn -Rows $group.Group -Column 'handles'

        $cpuP95 = if ($cpuValues.Count) { Get-EHPercentile -Values $cpuValues -Percentile 95 } else { 0 }
        $ioP95  = if ($ioValues.Count)  { Get-EHPercentile -Values $ioValues  -Percentile 95 } else { 0 }
        $memMax = if ($memValues.Count) { ($memValues | Measure-Object -Maximum).Maximum } else { 0 }
        $hdlMax = if ($hdlValues.Count) { ($hdlValues | Measure-Object -Maximum).Maximum } else { 0 }

        # Impact is a coarse 0-3 score so rules can say "this process is a
        # problem" without every rule restating the same thresholds.
        $impact = 0
        if ($cpuP95 -ge 8)        { $impact++ }
        if ($ioP95  -ge 10485760) { $impact++ }   # 10 MB/s sustained
        if ($memMax -ge 2048)     { $impact++ }   # 2 GB private working set

        $key = $group.Name
        Set-Metric ('proc.{0}.cpu.p95' -f $key) ([math]::Round($cpuP95, 2))
        Set-Metric ('proc.{0}.ioBytesSec.p95' -f $key) ([math]::Round($ioP95, 0))
        Set-Metric ('proc.{0}.wspMB.max' -f $key) ([math]::Round($memMax, 1))
        Set-Metric ('proc.{0}.handles.max' -f $key) ([int]$hdlMax)
        Set-Metric ('proc.{0}.impact' -f $key) $impact

        $processSummary += [pscustomobject]@{
            Name        = $group.Name
            Samples     = @($group.Group).Count
            CpuP95      = [math]::Round($cpuP95, 2)
            IoMBsP95    = [math]::Round($ioP95 / 1MB, 2)
            WspMaxMB    = [math]::Round($memMax, 1)
            HandlesMax  = [int]$hdlMax
            Impact      = $impact
        }
    }

    if ($processSummary.Count -gt 0) {
        $topCpu = $processSummary | Sort-Object CpuP95 -Descending | Select-Object -First 1
        $topIo  = $processSummary | Sort-Object IoMBsP95 -Descending | Select-Object -First 1
        $topMem = $processSummary | Sort-Object WspMaxMB -Descending | Select-Object -First 1

        Set-Metric 'proc.topCpu.name'  $topCpu.Name
        Set-Metric 'proc.topCpu.p95'   $topCpu.CpuP95
        Set-Metric 'proc.topIo.name'   $topIo.Name
        Set-Metric 'proc.topIo.mbs'    $topIo.IoMBsP95
        Set-Metric 'proc.topMem.name'  $topMem.Name
        Set-Metric 'proc.topMem.maxMB' $topMem.WspMaxMB
    }
}

#endregion

#region captures ------------------------------------------------------------

$captures = @()
if (Test-Path -LiteralPath $layout.Captures) {
    $captures = @(Get-ChildItem -LiteralPath $layout.Captures -Filter 'capture.json' -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch { $null }
        } | Where-Object { $_ })
}
Set-Metric 'captures.count' $captures.Count

if ($ListMetrics) {
    $metrics.GetEnumerator() | Sort-Object Name | ForEach-Object {
        '{0} = {1}' -f $_.Name, (($_.Value -join ', '))
    }
    return
}

#endregion

#region rule evaluation -----------------------------------------------------

function Test-Condition {
    <#
        A missing metric makes a condition false, except for 'notexists'. That
        is deliberate: a rule must not fire because a collector was unavailable.
    #>
    param(
        [Parameter(Mandatory)] $Condition,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Metrics
    )

    $name = $Condition.metric
    $op   = $Condition.op
    $want = $Condition.value

    $present = $Metrics.Contains($name)
    if ($op -eq 'exists')    { return $present }
    if ($op -eq 'notexists') { return -not $present }
    if (-not $present)       { return $false }

    $have = $Metrics[$name]
    if ($null -eq $have) { return $false }

    switch ($op) {
        'eq' { return ("$have" -eq "$want") -or ($have -eq $want) }
        'ne' { return -not (("$have" -eq "$want") -or ($have -eq $want)) }
        'contains' {
            if ($have -is [System.Array]) {
                return @($have | Where-Object { "$_" -like "*$want*" }).Count -gt 0
            }
            return "$have" -like "*$want*"
        }
        'notcontains' {
            if ($have -is [System.Array]) {
                return @($have | Where-Object { "$_" -like "*$want*" }).Count -eq 0
            }
            return "$have" -notlike "*$want*"
        }
        'matches' { return "$have" -match "$want" }
        default {
            # Numeric comparisons. A non-numeric value fails closed.
            $a = 0.0; $b = 0.0
            if (-not [double]::TryParse("$have", [ref]$a)) { return $false }
            if (-not [double]::TryParse("$want", [ref]$b)) { return $false }
            switch ($op) {
                'gt'  { return $a -gt  $b }
                'gte' { return $a -ge  $b }
                'lt'  { return $a -lt  $b }
                'lte' { return $a -le  $b }
            }
            return $false
        }
    }
}

$severityRank = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1; 'Info' = 0 }
$findings = New-Object System.Collections.ArrayList

foreach ($rule in $ruleDoc.rules) {
    if (-not $rule.PSObject.Properties['all']) { continue }
    $conditions = @($rule.all)
    if ($conditions.Count -eq 0) { continue }

    $matched = $true
    foreach ($condition in $conditions) {
        if (-not (Test-Condition -Condition $condition -Metrics $metrics)) { $matched = $false; break }
    }
    if (-not $matched) { continue }

    if ($rule.PSObject.Properties['unless']) {
        $suppressed = $false
        foreach ($condition in @($rule.unless)) {
            if (Test-Condition -Condition $condition -Metrics $metrics) { $suppressed = $true; break }
        }
        if ($suppressed) { continue }
    }

    # Resolve the evidence metric names to their current values so the finding
    # stands on its own without cross-referencing metrics.json.
    $evidence = [ordered]@{}
    if ($rule.PSObject.Properties['evidence']) {
        foreach ($e in @($rule.evidence)) {
            if ($metrics.Contains($e)) { $evidence[$e] = $metrics[$e] }
            else { $evidence[$e] = '(not collected)' }
        }
    }

    $triggered = [ordered]@{}
    foreach ($condition in $conditions) {
        $observed = if ($metrics.Contains($condition.metric)) { $metrics[$condition.metric] } else { $null }
        $triggered[$condition.metric] = '{0} (rule: {1} {2})' -f $observed, $condition.op, $condition.value
    }

    # Read the descriptive fields defensively. A hand-added rule missing
    # 'severity' or 'category' should still produce a finding rather than
    # throwing part way through the report.
    $severity = Get-Prop $rule 'severity'
    if (-not $severity -or -not $severityRank.ContainsKey([string]$severity)) { $severity = 'Medium' }

    [void]$findings.Add([pscustomobject]@{
        Id             = Get-Prop $rule 'id'
        Title          = Get-Prop $rule 'title'
        Category       = Get-Prop $rule 'category'
        Severity       = [string]$severity
        SeverityRank   = $severityRank[[string]$severity]
        Triggered      = [pscustomobject]$triggered
        Explanation    = Get-Prop $rule 'explanation'
        Recommendation = Get-Prop $rule 'recommendation'
        Evidence       = [pscustomobject]$evidence
    })
}

$ranked = @($findings | Sort-Object -Property @{ Expression = 'SeverityRank'; Descending = $true }, Id)

#endregion

#region output --------------------------------------------------------------

Export-EHJson -InputObject $metrics -Path (Join-Path $layout.Root 'metrics.json') -Depth 5

$report = [pscustomobject]@{
    Tool          = 'EndpointHealth'
    RunName       = $layout.RunName
    ComputerName  = if ($metrics.Contains('system.computerName')) { $metrics['system.computerName'] } else { $env:COMPUTERNAME }
    GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    RulesEvaluated= @($ruleDoc.rules).Count
    FindingCount  = $ranked.Count
    SeverityCounts= [pscustomobject]@{
        Critical = @($ranked | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($ranked | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = @($ranked | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = @($ranked | Where-Object { $_.Severity -eq 'Low' }).Count
    }
    Findings      = $ranked
}
Export-EHJson -InputObject $report -Path (Join-Path $layout.Root 'findings.json') -Depth 8

# SUMMARY.txt is the file a technician opens first, so it leads with the
# findings and keeps the raw numbers underneath.
$sb = New-Object System.Text.StringBuilder

function Add-Line {
    param([string] $Text = '')
    [void]$sb.AppendLine($Text)
}

function Add-Wrapped {
    <#
        Word wraps prose to a fixed width with a leading indent, so SUMMARY.txt
        stays readable in Notepad on a share where nobody has word wrap on.
    #>
    param(
        [string] $Text,
        [int]    $Width = 72,
        [string] $Indent = '    '
    )

    if (-not $Text) { return }

    $line = ''
    foreach ($word in ($Text -split '\s+')) {
        if (-not $word) { continue }
        if ($line.Length -eq 0) {
            $line = $word
        }
        elseif (($line.Length + 1 + $word.Length) -le $Width) {
            $line = '{0} {1}' -f $line, $word
        }
        else {
            Add-Line ($Indent + $line)
            $line = $word
        }
    }
    if ($line) { Add-Line ($Indent + $line) }
}

Add-Line ('=' * 78)
Add-Line ' ENDPOINT HEALTH REPORT'
Add-Line ('=' * 78)
Add-Line ('Computer      : {0}' -f $report.ComputerName)
if ($metrics.Contains('system.model'))        { Add-Line ('Model         : {0}' -f $metrics['system.model']) }
if ($metrics.Contains('system.serialNumber')) { Add-Line ('Serial        : {0}' -f $metrics['system.serialNumber']) }
if ($metrics.Contains('system.osCaption'))    { Add-Line ('OS            : {0} (build {1})' -f $metrics['system.osCaption'], $metrics['system.osBuild']) }
Add-Line ('Run           : {0}' -f $layout.RunName)
Add-Line ('Generated     : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($metrics.Contains('telemetry.sampleCount')) {
    Add-Line ('Telemetry     : {0} samples, {1} to {2}' -f $metrics['telemetry.sampleCount'],
        $(if ($metrics.Contains('telemetry.firstSample')) { $metrics['telemetry.firstSample'] } else { 'n/a' }),
        $(if ($metrics.Contains('telemetry.lastSample')) { $metrics['telemetry.lastSample'] } else { 'n/a' }))
}
Add-Line ('Deep captures : {0}' -f $captures.Count)
Add-Line ''

Add-Line ('FINDINGS: {0} total ({1} critical, {2} high, {3} medium, {4} low)' -f `
    $report.FindingCount, $report.SeverityCounts.Critical, $report.SeverityCounts.High,
    $report.SeverityCounts.Medium, $report.SeverityCounts.Low)
Add-Line ('-' * 78)

if ($ranked.Count -eq 0) {
    Add-Line 'No rules fired. Nothing in the collected data matches a known fault pattern.'
    Add-Line 'That is not the same as "nothing is wrong": check metrics.json against the'
    Add-Line 'user-reported symptom, and consider lowering the trigger thresholds so the'
    Add-Line 'deep capture fires during the event the user actually notices.'
}
else {
    foreach ($f in $ranked) {
        Add-Line ''
        Add-Line ('[{0}] {1}  ({2} / {3})' -f $f.Severity.ToUpper(), $f.Title, $f.Id, $f.Category)
        Add-Line ''
        Add-Line '  Observed:'
        foreach ($p in $f.Triggered.PSObject.Properties) {
            Add-Line ('    {0} = {1}' -f $p.Name, $p.Value)
        }
        Add-Line ''
        Add-Line '  Why it matters:'
        Add-Wrapped -Text $f.Explanation
        Add-Line ''
        Add-Line '  What to do:'
        Add-Wrapped -Text $f.Recommendation
        Add-Line ''
        Add-Line '  Supporting data:'
        foreach ($p in $f.Evidence.PSObject.Properties) {
            Add-Line ('    {0} = {1}' -f $p.Name, ($p.Value -join ', '))
        }
        Add-Line ('  ' + ('-' * 74))
    }
}

Add-Line ''
Add-Line ('=' * 78)
Add-Line ' KEY METRICS'
Add-Line ('=' * 78)

$headline = @(
    'cpu.total.p95', 'cpu.total.max', 'cpu.privileged.p95', 'cpu.maxFreqPct.p05'
    'mem.availableMB.p05', 'mem.committedPct.max', 'mem.hardFaults.p95', 'mem.poolNonpagedMB.max'
    'disk.readLatencyMs.p95', 'disk.writeLatencyMs.p95', 'disk.queue.p95', 'disk.freePercent.min'
    'disk.wearPercent.max', 'disk.healthSummary'
    'sys.processorQueue.p95', 'boot.timeMs.p95', 'system.uptimeDays'
    'events.whea.count', 'events.disk.count', 'events.bugCheck.count', 'events.appHangs.count'
    'security.antivirusCount', 'hw.problemDeviceCount'
)
foreach ($m in $headline) {
    if ($metrics.Contains($m)) {
        Add-Line ('{0,-28} {1}' -f $m, ($metrics[$m] -join ', '))
    }
}

if ($processSummary.Count -gt 0) {
    Add-Line ''
    Add-Line ('=' * 78)
    Add-Line ' TOP PROCESSES (95th percentile across the sampled window)'
    Add-Line ('=' * 78)
    Add-Line ('{0,-28} {1,10} {2,12} {3,12} {4,10}' -f 'process', 'cpu %', 'io MB/s', 'priv WS MB', 'handles')
    foreach ($p in ($processSummary | Sort-Object CpuP95, IoMBsP95 -Descending | Select-Object -First 15)) {
        Add-Line ('{0,-28} {1,10} {2,12} {3,12} {4,10}' -f $p.Name, $p.CpuP95, $p.IoMBsP95, $p.WspMaxMB, $p.HandlesMax)
    }
}

if ($captures.Count -gt 0) {
    Add-Line ''
    Add-Line ('=' * 78)
    Add-Line ' DEEP CAPTURES'
    Add-Line ('=' * 78)
    foreach ($c in ($captures | Sort-Object StartedUtc)) {
        Add-Line ('{0}  {1,-40} {2} MB  {3}s' -f $c.Id, $c.Reason, $c.SizeMB, $c.ActualSeconds)
        if (@($c.Notes).Count -gt 0) { Add-Line ('    notes: {0}' -f (@($c.Notes) -join '; ')) }
    }
    Add-Line ''
    Add-Line 'Open trace.etl with Windows Performance Analyzer and procmon.pml with'
    Add-Line 'Process Monitor. burst-1s.csv holds one-second resolution counters for'
    Add-Line 'the capture window, which is usually enough on its own.'
}

Add-Line ''
Add-Line ('Full metric namespace: metrics.json. Machine-readable findings: findings.json.')

$summaryPath = Join-Path $layout.Root 'SUMMARY.txt'
$sb.ToString() | Set-Content -LiteralPath $summaryPath -Encoding UTF8

if (-not $Quiet) {
    Write-Host $sb.ToString()
}
Write-EHLog ("Analysis complete: {0} finding(s) from {1} rule(s)." -f $ranked.Count, @($ruleDoc.rules).Count)

# Self-contained HTML view of the same findings. Guarded on purpose: a report
# failure must never cost the run its SUMMARY.txt or findings.json.
try {
    $reportScript = Join-Path $PSScriptRoot 'New-HealthReport.ps1'
    if (Test-Path -LiteralPath $reportScript) {
        & $reportScript -RunPath $layout.Root -RulesPath $RulesPath | Out-Null
        Write-EHLog 'REPORT.html written.'
    }
}
catch {
    Write-EHLog ("HTML report generation failed: {0}" -f $_.Exception.Message) -Level WARN
}

#endregion

$report
