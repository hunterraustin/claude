<#
.SYNOPSIS
    Shared library for the Endpoint Health campaign toolkit.
.DESCRIPTION
    Configuration, logging, run-folder naming, perf-counter resolution, state
    persistence and share upload. Every other script in this folder imports it.

    Targets Windows PowerShell 5.1 (the version present on a domain workstation
    without extra deployment). No external modules required.
#>

Set-StrictMode -Version 2.0

$script:EHCounterMap = $null
$script:EHLogPath    = $null

#region configuration -------------------------------------------------------

function Get-EHDefaultConfig {
    [CmdletBinding()]
    param()

    [ordered]@{
        # UNC path that collected data is copied to. The account the scheduled
        # task runs as must have Modify on this path. See README "Share rights".
        SharePath              = '\\CHANGE-ME\EndpointHealth$'

        # Everything is staged here first so a dead network link never stalls a
        # collection or blocks the sampler.
        LocalRoot              = 'C:\ProgramData\EndpointHealth'

        # Campaign length in days. The agent removes itself when this expires.
        CampaignDays           = 7

        # How often the lightweight sampler runs.
        SampleIntervalMinutes  = 5

        # How often staged data is pushed to the share.
        UploadIntervalMinutes  = 60

        # Folder naming. 'Compact' gives HOST_9-17_1059 (as requested).
        # 'Sortable' gives HOST_2026-09-17_1059, which actually sorts in Explorer.
        FolderNameStyle        = 'Compact'

        # Optional third-party binaries. Absent tools are skipped, not fatal.
        ToolsPath              = 'C:\ProgramData\EndpointHealth\bin'

        DeepCapture            = [ordered]@{
            Enabled          = $true
            # 'WPR'      - built into Windows, no download, best for latency work
            # 'Procmon'  - needs Procmon64.exe in ToolsPath, best for file/registry churn
            # 'Both'     - runs WPR, then Procmon, back to back
            Engine           = 'WPR'
            DurationSeconds  = 120
            MaxPerDay        = 6
            CooldownMinutes  = 60
            MaxCaptureMB     = 512
            # Optional Procmon filter config exported from the GUI. Cuts volume
            # by an order of magnitude when present.
            ProcmonConfig    = ''
        }

        # A trigger fires when a metric stays past its threshold for
        # ConsecutiveSamples samples in a row.
        Triggers               = [ordered]@{
            ConsecutiveSamples  = 2
            CpuPercent          = 90
            DiskReadLatencyMs   = 35
            DiskWriteLatencyMs  = 35
            DiskQueueLength     = 8
            AvailableMemoryMB   = 800
            HardFaultsPerSec    = 800
            ProcessorQueue      = 12
        }

        # Cap on staged data so a forgotten campaign cannot fill a system drive.
        MaxLocalStageMB        = 4096

        # Redact usernames from collected process paths and event text.
        RedactUserNames        = $false
    }
}

function Get-EHConfig {
    [CmdletBinding()]
    param(
        [string] $ConfigPath
    )

    $config = Get-EHDefaultConfig

    if (-not $ConfigPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot 'config.json')
            'C:\ProgramData\EndpointHealth\config.json'
        )
        $ConfigPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }

    if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
        try {
            $override = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            $config = Merge-EHConfig -Base $config -Override $override
            $config['ConfigPath'] = $ConfigPath
        }
        catch {
            Write-Warning ("Config at {0} is unreadable ({1}). Using defaults." -f $ConfigPath, $_.Exception.Message)
        }
    }

    [pscustomobject]$config
}

function Merge-EHConfig {
    param(
        [Parameter(Mandatory)] $Base,
        [Parameter(Mandatory)] $Override
    )

    foreach ($prop in $Override.PSObject.Properties) {
        $name = $prop.Name
        if (-not $Base.Contains($name)) {
            $Base[$name] = $prop.Value
            continue
        }

        $existing = $Base[$name]
        if ($existing -is [System.Collections.IDictionary] -and $prop.Value -is [psobject] -and
            $prop.Value -isnot [string] -and $prop.Value -isnot [ValueType]) {
            $Base[$name] = Merge-EHConfig -Base $existing -Override $prop.Value
        }
        else {
            $Base[$name] = $prop.Value
        }
    }

    $Base
}

#endregion

#region logging -------------------------------------------------------------

function Initialize-EHLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Path
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $script:EHLogPath = $Path
}

function Write-EHLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string] $Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }

    if ($script:EHLogPath) {
        # Best effort. A locked or full log must never kill a collection.
        try {
            Add-Content -LiteralPath $script:EHLogPath -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch { }
    }
}

#endregion

#region paths and naming ----------------------------------------------------

function Get-EHRunStamp {
    <#
        Produces the folder name the request asked for: COMPUTERNAME_9-17_1059.
        Sortable style is offered because the compact form sorts wrong once a
        campaign crosses a month boundary.
    #>
    [CmdletBinding()]
    param(
        [string]   $ComputerName = $env:COMPUTERNAME,
        [datetime] $Timestamp    = (Get-Date),
        [ValidateSet('Compact', 'Sortable')][string] $Style = 'Compact'
    )

    if ($Style -eq 'Sortable') {
        '{0}_{1}_{2}' -f $ComputerName, $Timestamp.ToString('yyyy-MM-dd'), $Timestamp.ToString('HHmm')
    }
    else {
        '{0}_{1}-{2}_{3}' -f $ComputerName, $Timestamp.Month, $Timestamp.Day, $Timestamp.ToString('HHmm')
    }
}

function New-EHRunLayout {
    <#
        Creates (or reuses) the staging folder tree for one run or campaign and
        returns the paths every collector writes into.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [string] $RunName
    )

    if (-not $RunName) {
        $RunName = Get-EHRunStamp -Style $Config.FolderNameStyle
    }

    $root = Join-Path (Join-Path $Config.LocalRoot 'runs') $RunName

    $layout = [pscustomobject]@{
        RunName   = $RunName
        Root      = $root
        Snapshot  = Join-Path $root 'snapshot'
        Telemetry = Join-Path $root 'telemetry'
        Captures  = Join-Path $root 'captures'
        Logs      = Join-Path $root 'logs'
        ShareRoot = if ($Config.SharePath) { Join-Path $Config.SharePath $RunName } else { $null }
    }

    foreach ($p in @($layout.Root, $layout.Snapshot, $layout.Telemetry, $layout.Captures, $layout.Logs)) {
        if (-not (Test-Path -LiteralPath $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
        }
    }

    $layout
}

function Export-EHJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)][string] $Path,
        [int] $Depth = 6
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $InputObject |
        ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

#endregion

#region state ---------------------------------------------------------------

function Get-EHStatePath {
    param([Parameter(Mandatory)] $Config)
    Join-Path $Config.LocalRoot 'campaign-state.json'
}

function Get-EHState {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Config)

    $path = Get-EHStatePath -Config $Config
    if (-not (Test-Path -LiteralPath $path)) { return $null }

    try {
        Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    catch {
        Write-EHLog ("Campaign state is corrupt: {0}" -f $_.Exception.Message) -Level ERROR
        $null
    }
}

function Set-EHState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] $State
    )

    Export-EHJson -InputObject $State -Path (Get-EHStatePath -Config $Config) -Depth 8
}

#endregion

#region performance counters ------------------------------------------------

function Initialize-EHCounterMap {
    <#
        Perf counter paths are localized. Get-Counter '\PhysicalDisk(_Total)\...'
        throws on a German or Spanish build. The registry holds an English
        (009) index->name table and a CurrentLanguage table keyed by the same
        indexes, so English names can be translated to whatever this box speaks.
    #>
    [CmdletBinding()]
    param()

    if ($script:EHCounterMap) { return }

    $map = @{}
    try {
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib'
        $english = (Get-ItemProperty -LiteralPath (Join-Path $base '009') -Name Counter -ErrorAction Stop).Counter
        $local   = (Get-ItemProperty -LiteralPath (Join-Path $base 'CurrentLanguage') -Name Counter -ErrorAction Stop).Counter

        $byIndex = @{}
        for ($i = 0; $i -lt $local.Count - 1; $i += 2) {
            $byIndex[$local[$i]] = $local[$i + 1]
        }
        for ($i = 0; $i -lt $english.Count - 1; $i += 2) {
            $idx  = $english[$i]
            $name = $english[$i + 1]
            if ($name -and $byIndex.ContainsKey($idx) -and -not $map.ContainsKey($name.ToLowerInvariant())) {
                $map[$name.ToLowerInvariant()] = $byIndex[$idx]
            }
        }
    }
    catch {
        Write-EHLog ("Counter name table unavailable, falling back to English paths: {0}" -f $_.Exception.Message) -Level DEBUG
    }

    $script:EHCounterMap = $map
}

function Get-EHCounterPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Object,
        [Parameter(Mandatory)][string] $Counter,
        [string] $Instance
    )

    Initialize-EHCounterMap

    $o = $Object
    $c = $Counter
    if ($script:EHCounterMap.Count -gt 0) {
        $ok = $script:EHCounterMap[$Object.ToLowerInvariant()]
        $ck = $script:EHCounterMap[$Counter.ToLowerInvariant()]
        if ($ok) { $o = $ok }
        if ($ck) { $c = $ck }
    }

    if ($PSBoundParameters.ContainsKey('Instance') -and $Instance) {
        '\{0}({1})\{2}' -f $o, $Instance, $c
    }
    else {
        '\{0}\{1}' -f $o, $c
    }
}

function Get-EHCounterSample {
    <#
        Reads a set of counters and returns a name -> value hashtable. Counters
        that do not exist on this box (no battery, no NIC) are skipped rather
        than failing the whole sample.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Paths,
        [int] $MaxSamples = 1
    )

    $result = @{}
    $lookup = @{}
    foreach ($key in $Paths.Keys) {
        $lookup[$Paths[$key].ToLowerInvariant()] = $key
    }

    try {
        $sample = Get-Counter -Counter @($Paths.Values) -MaxSamples $MaxSamples -ErrorAction Stop
        foreach ($cs in $sample.CounterSamples) {
            $name = $lookup[$cs.Path.ToLowerInvariant()]
            if (-not $name) {
                # Machine-qualified path (\\HOST\object\counter). Match on the tail.
                foreach ($k in $lookup.Keys) {
                    if ($cs.Path.ToLowerInvariant().EndsWith($k)) { $name = $lookup[$k]; break }
                }
            }
            if ($name) { $result[$name] = [math]::Round([double]$cs.CookedValue, 3) }
        }
    }
    catch {
        # Fall back to one counter at a time so a single bad path does not
        # cost the entire sample.
        foreach ($key in $Paths.Keys) {
            try {
                $cs = (Get-Counter -Counter $Paths[$key] -MaxSamples 1 -ErrorAction Stop).CounterSamples[0]
                $result[$key] = [math]::Round([double]$cs.CookedValue, 3)
            }
            catch { }
        }
    }

    $result
}

#endregion

#region statistics ----------------------------------------------------------

function Get-EHPercentile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][double[]] $Values,
        [Parameter(Mandatory)][ValidateRange(0, 100)][double] $Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) { return $null }

    $sorted = @($Values | Sort-Object)
    if ($sorted.Count -eq 1) { return $sorted[0] }

    # Linear interpolation between closest ranks.
    $rank = ($Percentile / 100.0) * ($sorted.Count - 1)
    $low  = [math]::Floor($rank)
    $high = [math]::Ceiling($rank)
    if ($low -eq $high) { return $sorted[[int]$low] }

    $frac = $rank - $low
    [math]::Round($sorted[[int]$low] + ($sorted[[int]$high] - $sorted[[int]$low]) * $frac, 3)
}

function Get-EHStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][double[]] $Values
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return [pscustomobject]@{ Count = 0; Min = $null; Max = $null; Avg = $null; P50 = $null; P95 = $null }
    }

    $measured = $Values | Measure-Object -Minimum -Maximum -Average
    [pscustomobject]@{
        Count = $Values.Count
        Min   = [math]::Round($measured.Minimum, 3)
        Max   = [math]::Round($measured.Maximum, 3)
        Avg   = [math]::Round($measured.Average, 3)
        P50   = Get-EHPercentile -Values $Values -Percentile 50
        P95   = Get-EHPercentile -Values $Values -Percentile 95
    }
}

#endregion

#region upload --------------------------------------------------------------

function Test-EHSharePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Path)

    if (-not $Path -or $Path -like '*CHANGE-ME*') { return $false }
    try { Test-Path -LiteralPath $Path -ErrorAction Stop }
    catch { $false }
}

function Invoke-EHUpload {
    <#
        Mirrors the staged run folder to the share. Robocopy is used because it
        resumes, retries and handles long paths better than Copy-Item, and its
        exit codes below 8 are all successes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Source,
        [Parameter(Mandatory)][string] $Destination,
        [int] $Retries = 3,
        [int] $WaitSeconds = 5,
        [switch] $Mirror
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        Write-EHLog ("Nothing to upload, {0} does not exist." -f $Source) -Level WARN
        return $false
    }

    $shareRoot = Split-Path -Parent $Destination
    if ($shareRoot -and -not (Test-EHSharePath -Path $shareRoot)) {
        Write-EHLog ("Share {0} is not reachable. Data stays staged locally." -f $shareRoot) -Level WARN
        return $false
    }

    $mode = if ($Mirror) { '/MIR' } else { '/E' }

    # No embedded quotes. The call operator quotes arguments that contain
    # spaces on its own; adding our own would pass the quote characters
    # through as part of the path.
    $roboArgs = @(
        $Source
        $Destination
        $mode
        '/R:2'          # per-file retries
        '/W:5'
        '/NP'           # no progress spam in the log
        '/NFL'
        '/NDL'
        '/FFT'          # 2-second granularity, avoids re-copy across SMB
        '/Z'            # restartable, survives a dropped link mid-file
    )

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $out = & robocopy.exe @roboArgs 2>&1
        $code = $LASTEXITCODE

        if ($code -lt 8) {
            Write-EHLog ("Upload to {0} succeeded (robocopy {1})." -f $Destination, $code)
            return $true
        }

        Write-EHLog ("Upload attempt {0}/{1} failed (robocopy {2})." -f $attempt, $Retries, $code) -Level WARN
        if ($attempt -lt $Retries) { Start-Sleep -Seconds ($WaitSeconds * $attempt) }
        else { Write-EHLog (($out | Select-Object -Last 15) -join [Environment]::NewLine) -Level DEBUG }
    }

    $false
}

function Get-EHFolderSizeMB {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { return 0 }
    [math]::Round($sum / 1MB, 1)
}

#endregion

#region misc ----------------------------------------------------------------

function Test-EHElevated {
    [CmdletBinding()]
    param()

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-EHSafeString {
    param(
        [AllowNull()][string] $Value,
        [switch] $Redact
    )

    if (-not $Value) { return $Value }
    if (-not $Redact) { return $Value }

    $Value -replace '(?i)([\\/])Users[\\/][^\\/]+', '$1Users$1<redacted>'
}

#endregion

Export-ModuleMember -Function @(
    'Get-EHDefaultConfig'
    'Get-EHConfig'
    'Initialize-EHLog'
    'Write-EHLog'
    'Get-EHRunStamp'
    'New-EHRunLayout'
    'Export-EHJson'
    'Get-EHState'
    'Set-EHState'
    'Get-EHStatePath'
    'Get-EHCounterPath'
    'Get-EHCounterSample'
    'Get-EHPercentile'
    'Get-EHStats'
    'Test-EHSharePath'
    'Invoke-EHUpload'
    'Get-EHFolderSizeMB'
    'Test-EHElevated'
    'ConvertTo-EHSafeString'
)
