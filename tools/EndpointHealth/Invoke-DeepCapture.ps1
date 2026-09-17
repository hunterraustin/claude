<#
.SYNOPSIS
    Bounded deep capture fired when a telemetry trigger holds.

.DESCRIPTION
    Runs for a fixed number of seconds and stops, whatever happens. Three
    layers, cheapest first:

      1. A high-resolution burst: one performance sample per second for the
         duration, plus a full process table with command lines and the TCP
         connection list. This alone identifies the culprit most of the time
         and costs a few hundred KB.

      2. Windows Performance Recorder (built into Windows, nothing to deploy).
         Produces an ETL that Windows Performance Analyzer opens, with CPU
         sampling, disk IO and file IO stacks. This is the right tool for
         "where is the latency coming from".

      3. Process Monitor, if Procmon64.exe has been dropped into ToolsPath.
         Best for file and registry churn, which is what antivirus, backup and
         indexer contention look like.

    Every engine is wrapped in a size watchdog. A capture that grows past
    MaxCaptureMB is stopped early rather than filling the system drive. That
    guard is the whole reason this runs for two minutes on a trigger instead
    of seven days continuously.

.PARAMETER Reason
    Free text recorded alongside the capture, normally the trigger that fired.

.EXAMPLE
    .\Invoke-DeepCapture.ps1 -Reason 'manual' -DurationSeconds 60
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $RunName,
    [string] $Reason = 'manual',
    [int]    $DurationSeconds,
    [ValidateSet('WPR', 'Procmon', 'Both', 'None')]
    [string] $Engine
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

$config = Get-EHConfig -ConfigPath $ConfigPath
$layout = New-EHRunLayout -Config $config -RunName $RunName
Initialize-EHLog -Path (Join-Path $layout.Logs 'agent.log')

$dc = $config.DeepCapture
if (-not $DurationSeconds) { $DurationSeconds = [int]$dc.DurationSeconds }
if (-not $Engine)          { $Engine = [string]$dc.Engine }
$maxMb = [int]$dc.MaxCaptureMB

$startedUtc = (Get-Date).ToUniversalTime()
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$captureDir = Join-Path $layout.Captures $stamp
New-Item -ItemType Directory -Path $captureDir -Force | Out-Null

Write-EHLog ("Deep capture {0} starting: engine={1} duration={2}s reason='{3}'" -f $stamp, $Engine, $DurationSeconds, $Reason)

$produced = New-Object System.Collections.ArrayList
$notes    = New-Object System.Collections.ArrayList
$redact   = [bool]$config.RedactUserNames

#region layer 1: context and high-resolution burst --------------------------

function Get-ProcessTable {
    <#
        Win32_Process rather than Get-Process, because the command line is what
        tells you which of the nine chrome.exe is the problem.
    #>
    param()

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $owner = $null
        try {
            $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
            if ($o.ReturnValue -eq 0) { $owner = '{0}\{1}' -f $o.Domain, $o.User }
        }
        catch { }

        [pscustomobject]@{
            ProcessId       = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            Name            = $_.Name
            ExecutablePath  = ConvertTo-EHSafeString -Value $_.ExecutablePath -Redact:$redact
            CommandLine     = ConvertTo-EHSafeString -Value $_.CommandLine -Redact:$redact
            Owner           = ConvertTo-EHSafeString -Value $owner -Redact:$redact
            WorkingSetMB    = [math]::Round($_.WorkingSetSize / 1MB, 1)
            PrivateMB       = [math]::Round($_.PrivatePageCount / 1MB, 1)
            HandleCount     = $_.HandleCount
            ThreadCount     = $_.ThreadCount
            ReadOperations  = $_.ReadOperationCount
            WriteOperations = $_.WriteOperationCount
            ReadBytes       = $_.ReadTransferCount
            WriteBytes      = $_.WriteTransferCount
            CreationDate    = $_.CreationDate
        }
    }
}

try {
    Export-EHJson -InputObject @(Get-ProcessTable) -Path (Join-Path $captureDir 'processes.json') -Depth 5
    [void]$produced.Add('processes.json')
}
catch {
    Write-EHLog ("Process table failed: {0}" -f $_.Exception.Message) -Level WARN
}

try {
    $connections = Get-NetTCPConnection -ErrorAction Stop |
        Where-Object { $_.State -in 'Established', 'SynSent', 'CloseWait', 'TimeWait' } |
        ForEach-Object {
            $procName = $null
            try { $procName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            [pscustomobject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = "$($_.State)"
                OwningProcess = $_.OwningProcess
                ProcessName   = $procName
            }
        }
    Export-EHJson -InputObject @($connections) -Path (Join-Path $captureDir 'connections.json') -Depth 4
    [void]$produced.Add('connections.json')
}
catch {
    Write-EHLog ("TCP connection list failed: {0}" -f $_.Exception.Message) -Level WARN
}

#endregion

#region layer 2: WPR --------------------------------------------------------

$wprStarted = $false
$wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
$wprEtl = Join-Path $captureDir 'trace.etl'
$wprMarker = Join-Path $config.LocalRoot 'wpr-session.marker'

function Test-WprIdle {
    <#
        Only one WPR session can exist at a time. If something else on the box
        is already recording, this capture must not cancel it.
    #>
    param([string] $WprPath)

    try {
        $out = & $WprPath -status 2>&1 | Out-String
        # Both the English string and a non-zero exit imply no active session.
        if ($out -match 'not recording|No trace profiles') { return $true }
        if ($LASTEXITCODE -ne 0) { return $true }
        return $false
    }
    catch { return $false }
}

if ($Engine -in 'WPR', 'Both') {
    if (-not (Test-Path -LiteralPath $wpr)) {
        [void]$notes.Add('wpr.exe not present on this build')
    }
    elseif (-not (Test-EHElevated)) {
        [void]$notes.Add('WPR skipped, requires elevation')
    }
    elseif (-not (Test-WprIdle -WprPath $wpr)) {
        [void]$notes.Add('WPR skipped, another recording session is already active')
        Write-EHLog 'WPR is already recording (not ours). Leaving it alone.' -Level WARN
    }
    else {
        try {
            # File mode writes straight to disk so the capture is not limited
            # to the in-memory ring. The profile set is deliberately narrow:
            # CPU, disk and file IO are what endpoint slowness actually is.
            $startArgs = @(
                '-start', 'GeneralProfile'
                '-start', 'DiskIO'
                '-start', 'FileIO'
                '-filemode'
                '-recordtempto', $captureDir
            )
            & $wpr @startArgs 2>&1 | Out-String | ForEach-Object { if ($_.Trim()) { Write-EHLog $_.Trim() -Level DEBUG } }

            if ($LASTEXITCODE -ne 0) {
                throw ("wpr -start returned {0}" -f $LASTEXITCODE)
            }
            $wprStarted = $true

            # Marker so teardown can tell our WPR session from one started by
            # another tool. Without it, Stop-HealthCampaign would cancel
            # somebody else's trace.
            Set-Content -LiteralPath $wprMarker -Value $captureDir -Encoding UTF8 -ErrorAction SilentlyContinue

            Write-EHLog 'WPR recording started.'
        }
        catch {
            Write-EHLog ("WPR start failed: {0}" -f $_.Exception.Message) -Level WARN
            [void]$notes.Add(('WPR start failed: {0}' -f $_.Exception.Message))
        }
    }
}

#endregion

#region layer 3: Procmon ----------------------------------------------------

$procmonStarted = $false
$procmonExe = $null
$procmonPml = Join-Path $captureDir 'procmon.pml'

if ($Engine -in 'Procmon', 'Both') {
    foreach ($name in @('Procmon64.exe', 'Procmon.exe')) {
        $candidate = Join-Path $config.ToolsPath $name
        if (Test-Path -LiteralPath $candidate) { $procmonExe = $candidate; break }
    }

    if (-not $procmonExe) {
        [void]$notes.Add('Procmon skipped, Procmon64.exe not found in ToolsPath')
    }
    elseif (-not (Test-EHElevated)) {
        [void]$notes.Add('Procmon skipped, requires elevation')
    }
    else {
        try {
            $pmArgs = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$procmonPml`"")

            # A filter config exported from the Procmon GUI, with "Drop
            # Filtered Events" enabled, cuts the backing file by roughly an
            # order of magnitude. Without it a two minute capture on a busy
            # box is still several hundred MB.
            if ($dc.ProcmonConfig -and (Test-Path -LiteralPath $dc.ProcmonConfig)) {
                $pmArgs += @('/LoadConfig', "`"$($dc.ProcmonConfig)`"")
            }
            else {
                [void]$notes.Add('no Procmon filter config supplied, capture will be large')
            }

            Start-Process -FilePath $procmonExe -ArgumentList $pmArgs -WindowStyle Hidden | Out-Null
            Start-Sleep -Seconds 3
            $procmonStarted = $true
            Write-EHLog 'Procmon capture started.'
        }
        catch {
            Write-EHLog ("Procmon start failed: {0}" -f $_.Exception.Message) -Level WARN
            [void]$notes.Add(('Procmon start failed: {0}' -f $_.Exception.Message))
        }
    }
}

#endregion

#region burst sampling and size watchdog ------------------------------------

$burstCsv = Join-Path $captureDir 'burst-1s.csv'
$burstPaths = @{
    'cpu_total_pct'         = Get-EHCounterPath -Object 'Processor Information' -Counter '% Processor Time' -Instance '_Total'
    'cpu_privileged_pct'    = Get-EHCounterPath -Object 'Processor Information' -Counter '% Privileged Time' -Instance '_Total'
    'cpu_max_freq_pct'      = Get-EHCounterPath -Object 'Processor Information' -Counter '% of Maximum Frequency' -Instance '_Total'
    'disk_read_latency_ms'  = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Avg. Disk sec/Read'  -Instance '_Total'
    'disk_write_latency_ms' = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Avg. Disk sec/Write' -Instance '_Total'
    'disk_queue_length'     = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Current Disk Queue Length' -Instance '_Total'
    'disk_bytes_sec'        = Get-EHCounterPath -Object 'PhysicalDisk' -Counter 'Disk Bytes/sec' -Instance '_Total'
    'mem_available_mb'      = Get-EHCounterPath -Object 'Memory' -Counter 'Available MBytes'
    'mem_hard_faults_sec'   = Get-EHCounterPath -Object 'Memory' -Counter 'Pages Input/sec'
    'sys_processor_queue'   = Get-EHCounterPath -Object 'System' -Counter 'Processor Queue Length'
}

$deadline = (Get-Date).AddSeconds($DurationSeconds)
$stoppedEarly = $false
$elapsedSeconds = 0

while ((Get-Date) -lt $deadline) {
    $tick = Get-Date
    $s = Get-EHCounterSample -Paths $burstPaths

    foreach ($k in @('disk_read_latency_ms', 'disk_write_latency_ms')) {
        if ($s.ContainsKey($k)) { $s[$k] = [math]::Round($s[$k] * 1000, 3) }
    }

    $burstRow = [ordered]@{ timestamp_local = $tick.ToString('yyyy-MM-dd HH:mm:ss') }
    foreach ($k in ($burstPaths.Keys | Sort-Object)) {
        $value = $null
        if ($s.ContainsKey($k)) { $value = $s[$k] }
        $burstRow[$k] = $value
    }
    [pscustomobject]$burstRow | Export-Csv -LiteralPath $burstCsv -NoTypeInformation -Append -Force -Encoding UTF8

    # Size watchdog. Checked every second so a runaway trace is caught within
    # a second of crossing the cap rather than at the end of the window.
    $sizeMb = Get-EHFolderSizeMB -Path $captureDir
    if ($sizeMb -ge $maxMb) {
        Write-EHLog ("Capture hit the {0} MB cap after {1}s. Stopping early." -f $maxMb, $elapsedSeconds) -Level WARN
        [void]$notes.Add(('stopped early at {0} MB cap' -f $maxMb))
        $stoppedEarly = $true
        break
    }

    $elapsedSeconds++
    $remaining = 1000 - [int]((Get-Date) - $tick).TotalMilliseconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds $remaining }
}

[void]$produced.Add('burst-1s.csv')

#endregion

#region stop engines --------------------------------------------------------

if ($procmonStarted) {
    try {
        & $procmonExe '/Terminate' 2>&1 | Out-Null
        # Procmon flushes asynchronously; give the backing file a moment to
        # close before anything tries to compress it.
        Start-Sleep -Seconds 5
        if (Test-Path -LiteralPath $procmonPml) {
            [void]$produced.Add('procmon.pml')
            Write-EHLog ("Procmon stopped, backing file is {0} MB." -f [math]::Round((Get-Item -LiteralPath $procmonPml).Length / 1MB, 1))
        }
    }
    catch {
        Write-EHLog ("Procmon stop failed: {0}" -f $_.Exception.Message) -Level ERROR
        [void]$notes.Add('Procmon may still be running, check manually')
    }
}

if ($wprStarted) {
    try {
        & $wpr -stop $wprEtl "EndpointHealth: $Reason" 2>&1 | Out-String |
            ForEach-Object { if ($_.Trim()) { Write-EHLog $_.Trim() -Level DEBUG } }

        if (Test-Path -LiteralPath $wprEtl) {
            [void]$produced.Add('trace.etl')
            Write-EHLog ("WPR stopped, trace is {0} MB." -f [math]::Round((Get-Item -LiteralPath $wprEtl).Length / 1MB, 1))
        }
        else {
            [void]$notes.Add('wpr -stop produced no ETL')
        }
    }
    catch {
        Write-EHLog ("WPR stop failed, cancelling: {0}" -f $_.Exception.Message) -Level ERROR
        try { & $wpr -cancel 2>&1 | Out-Null } catch { }
        [void]$notes.Add('WPR stop failed and the session was cancelled')
    }
    finally {
        Remove-Item -LiteralPath $wprMarker -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region compress ------------------------------------------------------------

# ETL and PML compress roughly 5:1 to 10:1. Worth doing before anything
# crosses the network.
foreach ($big in @($wprEtl, $procmonPml)) {
    if (-not (Test-Path -LiteralPath $big)) { continue }
    try {
        $zip = [System.IO.Path]::ChangeExtension($big, '.zip')
        Compress-Archive -LiteralPath $big -DestinationPath $zip -CompressionLevel Optimal -Force
        Remove-Item -LiteralPath $big -Force
        [void]$produced.Add([System.IO.Path]::GetFileName($zip))
        $produced.Remove([System.IO.Path]::GetFileName($big))
    }
    catch {
        Write-EHLog ("Compression of {0} failed, leaving it raw: {1}" -f $big, $_.Exception.Message) -Level WARN
    }
}

#endregion

$record = [pscustomobject]@{
    Id              = $stamp
    StartedUtc      = $startedUtc.ToString('o')
    FinishedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    Reason          = $Reason
    Engine          = $Engine
    RequestedSeconds= $DurationSeconds
    ActualSeconds   = $elapsedSeconds
    StoppedEarly    = $stoppedEarly
    Directory       = $captureDir
    Files           = @($produced)
    SizeMB          = Get-EHFolderSizeMB -Path $captureDir
    Notes           = @($notes)
}

Export-EHJson -InputObject $record -Path (Join-Path $captureDir 'capture.json') -Depth 5
Write-EHLog ("Deep capture {0} finished: {1} MB, {2} file(s)." -f $stamp, $record.SizeMB, @($produced).Count)

$record
