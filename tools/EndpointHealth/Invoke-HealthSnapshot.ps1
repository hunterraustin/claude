<#
.SYNOPSIS
    Deep one-shot diagnostic snapshot of a Windows endpoint.

.DESCRIPTION
    Collects hardware inventory, storage health (SMART where the driver exposes
    it), firmware, device errors, boot/logon performance, power and thermal
    state, security posture, network configuration and a triaged slice of the
    event logs.

    Writes one JSON file per subsystem into the snapshot folder. Nothing here
    depends on a third-party binary; optional tools (smartctl, dxdiag) are used
    when present and skipped silently when not.

    Every collector is individually guarded. A machine missing a battery, a
    storage driver that does not expose reliability counters, or a disabled
    event log degrades that one section rather than failing the run.

.PARAMETER ConfigPath
    Path to config.json. Defaults to the one beside this script, then
    C:\ProgramData\EndpointHealth\config.json.

.PARAMETER RunName
    Existing run folder to write into. Omit to create a new HOST_9-17_1059
    folder.

.PARAMETER EventLookbackDays
    How far back to triage the event logs. Default 14.

.PARAMETER Upload
    Copy the finished snapshot to the configured share.

.EXAMPLE
    .\Invoke-HealthSnapshot.ps1 -Upload
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $RunName,
    [int]    $EventLookbackDays = 14,
    [switch] $Upload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

$config = Get-EHConfig -ConfigPath $ConfigPath
$layout = New-EHRunLayout -Config $config -RunName $RunName
Initialize-EHLog -Path (Join-Path $layout.Logs 'snapshot.log')

Write-EHLog ("Snapshot starting for {0} into {1}" -f $env:COMPUTERNAME, $layout.Root)
if (-not (Test-EHElevated)) {
    Write-EHLog 'Not elevated. SMART, WHEA and several event logs will be incomplete.' -Level WARN
}

$redact = [bool]$config.RedactUserNames

#region helpers -------------------------------------------------------------

function Invoke-Collector {
    <#
        Runs one collector and records the failure inline rather than aborting
        the snapshot. Returns whatever the scriptblock produced.
    #>
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][scriptblock] $Body
    )

    try {
        Write-EHLog ("  collecting {0}" -f $Name) -Level DEBUG
        & $Body
    }
    catch {
        Write-EHLog ("  {0} failed: {1}" -f $Name, $_.Exception.Message) -Level WARN
        [pscustomobject]@{ CollectorError = $_.Exception.Message }
    }
}

function Get-EHEventSummary {
    <#
        Counts matching events over the lookback window and keeps a bounded
        sample of the most recent ones. Counting is what the rules engine keys
        on; the samples are for the human reading SUMMARY.txt.
    #>
    param(
        [Parameter(Mandatory)][string] $LogName,
        [int[]]  $Ids,
        [string[]] $ProviderName,
        [int]    $Days = 14,
        [int]    $SampleCount = 10
    )

    $filter = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$Days) }
    if ($Ids)          { $filter['Id'] = $Ids }
    if ($ProviderName) { $filter['ProviderName'] = $ProviderName }

    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
    }
    catch {
        # "No events were found" is the normal, healthy case.
        if ($_.Exception.Message -match 'No events were found') {
            return [pscustomobject]@{ Count = 0; First = $null; Last = $null; Samples = @() }
        }
        return [pscustomobject]@{ Count = $null; Error = $_.Exception.Message; Samples = @() }
    }

    if ($events.Count -eq 0) {
        return [pscustomobject]@{ Count = 0; First = $null; Last = $null; Samples = @() }
    }

    $samples = $events |
        Select-Object -First $SampleCount |
        ForEach-Object {
            # Collapse whitespace, redact if configured, then cap the length.
            # Some providers emit multi-kilobyte messages that would dominate
            # the JSON without adding anything.
            $text = ConvertTo-EHSafeString -Value ("$($_.Message)" -replace '\s+', ' ') -Redact:$redact
            if ($text -and $text.Length -gt 400) { $text = $text.Substring(0, 400) + '...' }

            [pscustomobject]@{
                TimeCreated = $_.TimeCreated
                Id          = $_.Id
                Level       = $_.LevelDisplayName
                Provider    = $_.ProviderName
                Message     = $text
            }
        }

    [pscustomobject]@{
        Count   = $events.Count
        First   = ($events | Select-Object -Last 1).TimeCreated
        Last    = ($events | Select-Object -First 1).TimeCreated
        Samples = @($samples)
    }
}

function ConvertTo-Gb {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    [math]::Round([double]$Bytes / 1GB, 2)
}

#endregion

#region system identity -----------------------------------------------------

$system = Invoke-Collector 'system identity' {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $enc  = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue

    # ChassisTypes 8-14 and 30-32 are portable form factors. Used later to
    # decide whether battery and thermal findings apply.
    $chassis = if ($enc) { @($enc.ChassisTypes) } else { @() }
    $isLaptop = @($chassis | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 }).Count -gt 0

    $biosDate = $bios.ReleaseDate
    $biosAgeDays = if ($biosDate) { [int]((Get-Date) - $biosDate).TotalDays } else { $null }

    [pscustomobject]@{
        ComputerName      = $env:COMPUTERNAME
        Domain            = $cs.Domain
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        SerialNumber      = $bios.SerialNumber
        SystemType        = $cs.SystemType
        IsLaptop          = $isLaptop
        ChassisTypes      = $chassis
        BaseBoard         = if ($bb) { '{0} {1}' -f $bb.Manufacturer, $bb.Product } else { $null }
        BiosVersion       = $bios.SMBIOSBIOSVersion
        BiosReleaseDate   = $biosDate
        BiosAgeDays       = $biosAgeDays
        OsCaption         = $os.Caption
        OsVersion         = $os.Version
        OsBuild           = $os.BuildNumber
        OsDisplayVersion  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
        OsArchitecture    = $os.OSArchitecture
        OsInstallDate     = $os.InstallDate
        LastBootUpTime    = $os.LastBootUpTime
        UptimeDays        = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
        TotalMemoryGB     = ConvertTo-Gb $cs.TotalPhysicalMemory
        LogicalProcessors = $cs.NumberOfLogicalProcessors
        PhysicalProcessors= $cs.NumberOfProcessors
        SnapshotTimeUtc   = (Get-Date).ToUniversalTime()
        SnapshotTimeLocal = Get-Date
        TimeZone          = (Get-TimeZone -ErrorAction SilentlyContinue).Id
        CollectedBy       = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        Elevated          = Test-EHElevated
    }
}

Export-EHJson -InputObject $system -Path (Join-Path $layout.Snapshot 'system.json')

#endregion

#region hardware ------------------------------------------------------------

$hardware = Invoke-Collector 'hardware inventory' {
    $cpu = Get-CimInstance Win32_Processor | ForEach-Object {
        [pscustomobject]@{
            Name              = $_.Name
            Cores             = $_.NumberOfCores
            LogicalProcessors = $_.NumberOfLogicalProcessors
            MaxClockMHz       = $_.MaxClockSpeed
            CurrentClockMHz   = $_.CurrentClockSpeed
            # A current clock stuck well under max on an idle box is the usual
            # fingerprint of firmware throttling or a power-plan problem.
            ClockRatioPercent = if ($_.MaxClockSpeed) {
                                    [math]::Round(100 * $_.CurrentClockSpeed / $_.MaxClockSpeed, 1)
                                } else { $null }
            LoadPercentage    = $_.LoadPercentage
            Status            = $_.Status
            L3CacheKB         = $_.L3CacheSize
            VirtualizationOk  = $_.VirtualizationFirmwareEnabled
        }
    }

    $memory = Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        [pscustomobject]@{
            BankLabel    = $_.BankLabel
            DeviceLocator= $_.DeviceLocator
            CapacityGB   = ConvertTo-Gb $_.Capacity
            SpeedMHz     = $_.Speed
            ConfiguredMHz= $_.ConfiguredClockSpeed
            Manufacturer = $_.Manufacturer
            PartNumber   = ($_.PartNumber -replace '\s+$', '')
            SerialNumber = ($_.SerialNumber -replace '\s+$', '')
        }
    }

    $gpu = Get-CimInstance Win32_VideoController | ForEach-Object {
        [pscustomobject]@{
            Name              = $_.Name
            DriverVersion     = $_.DriverVersion
            DriverDate        = $_.DriverDate
            DriverAgeDays     = if ($_.DriverDate) { [int]((Get-Date) - $_.DriverDate).TotalDays } else { $null }
            AdapterRamGB      = ConvertTo-Gb $_.AdapterRAM
            CurrentResolution = if ($_.CurrentHorizontalResolution) {
                                    '{0}x{1}@{2}' -f $_.CurrentHorizontalResolution, $_.CurrentVerticalResolution, $_.CurrentRefreshRate
                                } else { $null }
            Status            = $_.Status
        }
    }

    # ConfigManagerErrorCode 0 is healthy. Anything else is a device Windows
    # could not start, which is the first place to look for "it's just slow".
    $problemDevices = Get-CimInstance Win32_PnPEntity |
        Where-Object { $_.ConfigManagerErrorCode -ne 0 } |
        ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                DeviceID    = $_.DeviceID
                ErrorCode   = $_.ConfigManagerErrorCode
                Status      = $_.Status
                Class       = $_.PNPClass
            }
        }

    $battery = $null
    if ($system -and $system.PSObject.Properties['IsLaptop'] -and $system.IsLaptop) {
        $b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
        $full = Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue
        $design = Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue

        if ($b) {
            $healthPct = $null
            if ($full -and $design -and $design.DesignedCapacity -gt 0) {
                $healthPct = [math]::Round(100 * $full.FullChargedCapacity / $design.DesignedCapacity, 1)
            }
            $battery = [pscustomobject]@{
                Name                  = $b.Name
                EstimatedChargePercent= $b.EstimatedChargeRemaining
                DesignCapacity        = if ($design) { $design.DesignedCapacity } else { $null }
                FullChargeCapacity    = if ($full) { $full.FullChargedCapacity } else { $null }
                HealthPercent         = $healthPct
                Status                = $b.BatteryStatus
            }
        }
    }

    $thermal = Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Instance     = $_.InstanceName
                # Reported in tenths of a Kelvin.
                TemperatureC = [math]::Round(($_.CurrentTemperature / 10) - 273.15, 1)
                Active       = $_.Active
            }
        }

    [pscustomobject]@{
        Processors     = @($cpu)
        MemoryModules  = @($memory)
        MemorySlotsUsed= @($memory).Count
        GraphicsCards  = @($gpu)
        ProblemDevices = @($problemDevices)
        ProblemDeviceCount = @($problemDevices).Count
        Battery        = $battery
        ThermalZones   = @($thermal)
    }
}

Export-EHJson -InputObject $hardware -Path (Join-Path $layout.Snapshot 'hardware.json') -Depth 8

#endregion

#region storage health ------------------------------------------------------

$storage = Invoke-Collector 'storage health' {
    $physical = @()
    try {
        $physical = Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $disk = $_
            $rel = $null
            try { $rel = $disk | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }

            [pscustomobject]@{
                FriendlyName      = $disk.FriendlyName
                SerialNumber      = $disk.SerialNumber
                MediaType         = "$($disk.MediaType)"
                BusType           = "$($disk.BusType)"
                SizeGB            = ConvertTo-Gb $disk.Size
                HealthStatus      = "$($disk.HealthStatus)"
                OperationalStatus = "$($disk.OperationalStatus)"
                FirmwareVersion   = $disk.FirmwareVersion
                # Wear is percent of rated write endurance consumed on an SSD.
                WearPercent       = if ($rel) { $rel.Wear } else { $null }
                TemperatureC      = if ($rel) { $rel.Temperature } else { $null }
                TemperatureMaxC   = if ($rel) { $rel.TemperatureMax } else { $null }
                PowerOnHours      = if ($rel) { $rel.PowerOnHours } else { $null }
                ReadErrorsTotal   = if ($rel) { $rel.ReadErrorsTotal } else { $null }
                ReadErrorsUncorrected = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
                WriteErrorsTotal  = if ($rel) { $rel.WriteErrorsTotal } else { $null }
                WriteErrorsUncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { $null }
                StartStopCycleCount = if ($rel) { $rel.StartStopCycleCount } else { $null }
                ReliabilitySource = if ($rel) { 'StorageReliabilityCounter' } else { 'unavailable' }
            }
        }
    }
    catch {
        Write-EHLog ("Get-PhysicalDisk unavailable: {0}" -f $_.Exception.Message) -Level WARN
    }

    # The legacy SMART predict-failure flag. Crude (it is a single bit) but it
    # is the one signal that works on older RAID and SATA stacks where the
    # Storage module reports nothing.
    $smartPredict = @()
    try {
        $status = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
        $smartPredict = $status | ForEach-Object {
            [pscustomobject]@{
                InstanceName   = $_.InstanceName
                PredictFailure = $_.PredictFailure
                Reason         = $_.Reason
            }
        }
    }
    catch { }

    $volumes = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [pscustomobject]@{
            DeviceID      = $_.DeviceID
            VolumeName    = $_.VolumeName
            FileSystem    = $_.FileSystem
            SizeGB        = ConvertTo-Gb $_.Size
            FreeGB        = ConvertTo-Gb $_.FreeSpace
            FreePercent   = if ($_.Size -gt 0) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { $null }
        }
    }

    $bitlocker = @()
    try {
        $bitlocker = Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                MountPoint       = $_.MountPoint
                ProtectionStatus = "$($_.ProtectionStatus)"
                VolumeStatus     = "$($_.VolumeStatus)"
                EncryptionPercentage = $_.EncryptionPercentage
            }
        }
    }
    catch { }

    # An SSD with TRIM disabled degrades badly over time. DisableDeleteNotify=1
    # means TRIM is off.
    $trim = $null
    try {
        $fsutil = & fsutil.exe behavior query DisableDeleteNotify 2>&1
        $trim = ($fsutil | Out-String).Trim()
    }
    catch { }

    $pagefile = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            AllocatedBaseMB = $_.AllocatedBaseSize
            CurrentUsageMB  = $_.CurrentUsage
            PeakUsageMB     = $_.PeakUsage
        }
    }

    [pscustomobject]@{
        PhysicalDisks    = @($physical)
        SmartPredict     = @($smartPredict)
        Volumes          = @($volumes)
        BitLocker        = @($bitlocker)
        TrimStatus       = $trim
        PageFiles        = @($pagefile)
        PageFileAutoManaged = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
    }
}

Export-EHJson -InputObject $storage -Path (Join-Path $layout.Snapshot 'storage.json') -Depth 8

#endregion

#region event log triage ----------------------------------------------------

$events = Invoke-Collector 'event log triage' {
    $d = $EventLookbackDays

    [pscustomobject]@{
        LookbackDays = $d

        # Hardware error architecture. Corrected memory or cache errors here
        # are the single most reliable pointer at a failing DIMM or CPU.
        Whea             = Get-EHEventSummary -LogName 'System' -ProviderName 'Microsoft-Windows-WHEA-Logger' -Days $d

        # Unexpected shutdown. Distinguishes "user held the power button" from
        # "it bugchecked".
        KernelPower41    = Get-EHEventSummary -LogName 'System' -Ids 41 -ProviderName 'Microsoft-Windows-Kernel-Power' -Days $d
        BugCheck         = Get-EHEventSummary -LogName 'System' -Ids 1001 -ProviderName 'Microsoft-Windows-WER-SystemErrorReporting' -Days $d

        # Storage stack. 153 is a retried IO, 129 is a reset controller, 51 is
        # a paging error. These are the classic "slow machine" evidence.
        DiskErrors       = Get-EHEventSummary -LogName 'System' -Ids 7, 11, 51, 52, 129, 153 -Days $d
        NtfsErrors       = Get-EHEventSummary -LogName 'System' -Ids 55, 98, 130, 137, 140 -ProviderName 'Microsoft-Windows-Ntfs' -Days $d
        VolmgrErrors     = Get-EHEventSummary -LogName 'System' -Ids 46, 49 -Days $d

        # Display driver reset. Causes visible multi-second freezes.
        DisplayTdr       = Get-EHEventSummary -LogName 'System' -Ids 4101, 4104 -Days $d

        # Services failing or timing out at boot drag logon out.
        ServiceFailures  = Get-EHEventSummary -LogName 'System' -Ids 7000, 7009, 7011, 7022, 7023, 7031, 7034, 7043 -Days $d

        # Name resolution and secure-channel problems. Common cause of slow
        # logons and mapped-drive hangs that get blamed on "the computer".
        DnsClient        = Get-EHEventSummary -LogName 'System' -Ids 1014 -ProviderName 'Microsoft-Windows-DNS-Client' -Days $d
        NetlogonErrors   = Get-EHEventSummary -LogName 'System' -Ids 5719, 5783, 5807 -Days $d
        TimeService      = Get-EHEventSummary -LogName 'System' -Ids 36, 47, 129, 134 -ProviderName 'Microsoft-Windows-Time-Service' -Days $d
        SmbClient        = Get-EHEventSummary -LogName 'Microsoft-Windows-SMBClient/Connectivity' -Days $d

        # Application-level crashes and hangs.
        AppCrashes       = Get-EHEventSummary -LogName 'Application' -Ids 1000 -ProviderName 'Application Error' -Days $d
        AppHangs         = Get-EHEventSummary -LogName 'Application' -Ids 1002 -ProviderName 'Application Hang' -Days $d
        DotNetErrors     = Get-EHEventSummary -LogName 'Application' -Ids 1023, 1026 -Days $d

        # Boot and logon degradation. IDs 100-110 in this log are Windows'
        # own measurement of what made startup slow, with the offending
        # file/service named in the payload.
        BootPerformance  = Get-EHEventSummary -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -Days $d -SampleCount 15

        # Group Policy processing time. Slow logons usually live here.
        GroupPolicy      = Get-EHEventSummary -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Ids 1055, 1085, 1129, 7017, 7320 -Days $d

        # WMI repository problems, which show up as a pegged WmiPrvSE.
        WmiActivity      = Get-EHEventSummary -LogName 'Microsoft-Windows-WMI-Activity/Operational' -Ids 5858 -Days $d

        # Memory diagnostic results, if the user ever ran one.
        MemoryDiagnostic = Get-EHEventSummary -LogName 'System' -ProviderName 'Microsoft-Windows-MemoryDiagnostics-Results' -Days 365
    }
}

Export-EHJson -InputObject $events -Path (Join-Path $layout.Snapshot 'events.json') -Depth 8

#endregion

#region boot and reliability ------------------------------------------------

$reliability = Invoke-Collector 'boot and reliability' {
    # Event 100 in the Diagnostics-Performance log carries the measured boot
    # timings. BootTime is the number users actually feel.
    $boots = @()
    try {
        $boots = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Diagnostics-Performance/Operational'
            Id        = 100
            StartTime = (Get-Date).AddDays(-$EventLookbackDays)
        } -ErrorAction Stop | ForEach-Object {
            $x = [xml]$_.ToXml()
            $data = @{}
            foreach ($n in $x.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }
            [pscustomobject]@{
                TimeCreated    = $_.TimeCreated
                BootTimeMs     = [int]$data['BootTime']
                MainPathBootMs = [int]$data['MainPathBootTime']
                BootPostBootMs = [int]$data['BootPostBootTime']
                DegradationMs  = [int]$data['BootDegradationTime']
            }
        }
    }
    catch { }

    $stability = $null
    try {
        $stability = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop |
            Sort-Object TimeGenerated -Descending |
            Select-Object -First 14 |
            ForEach-Object {
                [pscustomobject]@{
                    Date          = $_.TimeGenerated
                    StabilityIndex= [math]::Round($_.SystemStabilityIndex, 2)
                }
            }
    }
    catch { }

    $bootStats = if (@($boots).Count -gt 0) {
        Get-EHStats -Values ([double[]]@($boots | ForEach-Object { $_.BootTimeMs }))
    } else { $null }

    [pscustomobject]@{
        Boots              = @($boots)
        BootTimeMsStats    = $bootStats
        StabilityIndex     = @($stability)
        FastStartupEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    }
}

Export-EHJson -InputObject $reliability -Path (Join-Path $layout.Snapshot 'reliability.json') -Depth 8

#endregion

#region power ---------------------------------------------------------------

$power = Invoke-Collector 'power configuration' {
    $activePlan = $null
    try {
        $out = & powercfg.exe /getactivescheme 2>&1 | Out-String
        if ($out -match '\(([^)]+)\)') { $activePlan = $Matches[1] }
    }
    catch { }

    # Processor power management. A max processor state capped well below 100,
    # or a Balanced plan on a desktop that needs throughput, shows up here.
    $procPolicy = $null
    try {
        $q = & powercfg.exe /query SCHEME_CURRENT SUB_PROCESSOR 2>&1 | Out-String
        $procPolicy = @{
            MaxProcessorStateAcHex = if ($q -match '(?ms)PROCTHROTTLEMAX.*?Current AC Power Setting Index:\s*(0x[0-9a-f]+)') { $Matches[1] } else { $null }
            MinProcessorStateAcHex = if ($q -match '(?ms)PROCTHROTTLEMIN.*?Current AC Power Setting Index:\s*(0x[0-9a-f]+)') { $Matches[1] } else { $null }
        }
    }
    catch { }

    [pscustomobject]@{
        ActivePlan          = $activePlan
        ProcessorPolicy     = $procPolicy
        SleepStudyAvailable = (Test-Path 'C:\Windows\System32\powercfg.exe')
    }
}

Export-EHJson -InputObject $power -Path (Join-Path $layout.Snapshot 'power.json')

#endregion

#region security posture ----------------------------------------------------

$security = Invoke-Collector 'security posture' {
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $defender = [pscustomobject]@{
            AMServiceEnabled        = $mp.AMServiceEnabled
            RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
            AntivirusSignatureAge   = $mp.AntivirusSignatureAge
            QuickScanAge            = $mp.QuickScanAge
            FullScanAge             = $mp.FullScanAge
            IsTamperProtected       = $mp.IsTamperProtected
            # Exclusion counts only. The paths themselves are sensitive and
            # are not written to a share.
            ExclusionPathCount      = if ($pref) { @($pref.ExclusionPath).Count } else { $null }
            ExclusionProcessCount   = if ($pref) { @($pref.ExclusionProcess).Count } else { $null }
            ScanAvgCPULoadFactor    = if ($pref) { $pref.ScanAvgCPULoadFactor } else { $null }
        }
    }
    catch { }

    # Third-party AV registers here. Two real-time scanners fighting over the
    # same files is one of the most common causes of "the PC got slow".
    $avProducts = @()
    try {
        $avProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    DisplayName = $_.displayName
                    State       = ('0x{0:X}' -f $_.productState)
                    PathToSignedProductExe = $_.pathToSignedProductExe
                }
            }
    }
    catch { }

    # try/catch is a statement, not an expression, so these cannot sit inside a
    # hashtable literal. Resolve each one first, then build the object.
    $firewallProfiles = @()
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled } }
    }
    catch { }

    $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }

    $tpmPresent = $null
    try { $tpmPresent = (Get-Tpm -ErrorAction Stop).TpmPresent } catch { }

    [pscustomobject]@{
        Defender          = $defender
        AntivirusProducts = @($avProducts)
        AntivirusCount    = @($avProducts).Count
        FirewallProfiles  = @($firewallProfiles)
        SecureBootEnabled = $secureBoot
        TpmPresent        = $tpmPresent
    }
}

Export-EHJson -InputObject $security -Path (Join-Path $layout.Snapshot 'security.json') -Depth 8

#endregion

#region network -------------------------------------------------------------

$network = Invoke-Collector 'network configuration' {
    $adapters = @()
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            $a = $_
            $stats = $null
            try { $stats = $a | Get-NetAdapterStatistics -ErrorAction Stop } catch { }
            [pscustomobject]@{
                Name            = $a.Name
                InterfaceDescription = $a.InterfaceDescription
                LinkSpeed       = $a.LinkSpeed
                FullDuplex      = $a.FullDuplex
                MediaType       = $a.MediaType
                DriverVersion   = $a.DriverVersion
                DriverDate      = $a.DriverDate
                DriverAgeDays   = if ($a.DriverDate) { [int]((Get-Date) - $a.DriverDate).TotalDays } else { $null }
                # Non-zero discards or errors on a wired link is a cabling,
                # duplex or driver problem, not a bandwidth problem.
                ReceivedDiscarded = if ($stats) { $stats.ReceivedDiscardedPackets } else { $null }
                ReceivedErrors    = if ($stats) { $stats.ReceivedPacketErrors } else { $null }
                OutboundDiscarded = if ($stats) { $stats.OutboundDiscardedPackets } else { $null }
                OutboundErrors    = if ($stats) { $stats.OutboundPacketErrors } else { $null }
            }
        }
    }
    catch { }

    $ip = @()
    try {
        $ip = Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceAlias = $_.InterfaceAlias
                IPv4Address    = @($_.IPv4Address.IPAddress)
                IPv4Gateway    = @($_.IPv4DefaultGateway.NextHop)
                DnsServers     = @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
            }
        }
    }
    catch { }

    $tcpStats = $null
    try {
        $t = Get-CimInstance Win32_PerfRawData_Tcpip_TCPv4 -ErrorAction Stop
        $tcpStats = [pscustomobject]@{
            SegmentsRetransmittedTotal = $t.SegmentsRetransmittedPersec
            ConnectionsResetTotal      = $t.ConnectionsReset
            ConnectionFailuresTotal    = $t.ConnectionFailures
            ConnectionsEstablished     = $t.ConnectionsEstablished
        }
    }
    catch { }

    # Same rule as the security collector: resolve first, then build the object.
    $proxySettings = $null
    try {
        $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $proxySettings = [pscustomobject]@{ ProxyEnable = $p.ProxyEnable; AutoConfigURL = $p.AutoConfigURL }
    }
    catch { }

    $smbClientConfig = $null
    try {
        $s = Get-SmbClientConfiguration -ErrorAction Stop
        $smbClientConfig = [pscustomobject]@{
            SessionTimeout         = $s.SessionTimeout
            OplocksDisabled        = $s.OplocksDisabled
            DirectoryCacheLifetime = $s.DirectoryCacheLifetime
        }
    }
    catch { }

    [pscustomobject]@{
        Adapters        = @($adapters)
        IPConfiguration = @($ip)
        TcpCounters     = $tcpStats
        ProxySettings   = $proxySettings
        SmbClientConfig = $smbClientConfig
    }
}

Export-EHJson -InputObject $network -Path (Join-Path $layout.Snapshot 'network.json') -Depth 8

#endregion

#region software and autostart ----------------------------------------------

$software = Invoke-Collector 'software and autostart' {
    # Registry uninstall keys, not Win32_Product. Win32_Product triggers an MSI
    # reconfiguration of every installed package, which is itself a several
    # minute performance event.
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $installed = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object @{n = 'Name'; e = { $_.DisplayName } },
                      @{n = 'Version'; e = { $_.DisplayVersion } },
                      @{n = 'Publisher'; e = { $_.Publisher } },
                      @{n = 'InstallDate'; e = { $_.InstallDate } } |
        Sort-Object Name -Unique

    $startup = @()
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty -Path $key
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $startup += [pscustomobject]@{
                Location = $key
                Name     = $p.Name
                Command  = ConvertTo-EHSafeString -Value ([string]$p.Value) -Redact:$redact
            }
        }
    }

    $services = Get-CimInstance Win32_Service | ForEach-Object {
        [pscustomobject]@{
            Name      = $_.Name
            DisplayName = $_.DisplayName
            State     = $_.State
            StartMode = $_.StartMode
            PathName  = ConvertTo-EHSafeString -Value $_.PathName -Redact:$redact
            StartName = $_.StartName
        }
    }

    [pscustomobject]@{
        InstalledCount = @($installed).Count
        Installed      = @($installed)
        StartupItems   = @($startup)
        AutoServicesStopped = @($services | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })
        ServiceCount   = @($services).Count
        RunningServiceCount = @($services | Where-Object { $_.State -eq 'Running' }).Count
        PendingReboot  = [pscustomobject]@{
            CbsRebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            WindowsUpdate    = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            PendingFileRename= [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        }
        HotFixes       = @(Get-HotFix -ErrorAction SilentlyContinue |
                            Sort-Object InstalledOn -Descending |
                            Select-Object -First 25 HotFixID, Description, InstalledOn)
    }
}

Export-EHJson -InputObject $software -Path (Join-Path $layout.Snapshot 'software.json') -Depth 8

#endregion

#region optional external tools ---------------------------------------------

Invoke-Collector 'optional external tools' {
    $bin = $config.ToolsPath

    # smartctl gives per-attribute SMART data that Windows will not surface,
    # including the reallocated sector count that actually predicts failure.
    $smartctl = Join-Path $bin 'smartctl.exe'
    if (Test-Path -LiteralPath $smartctl) {
        $devices = & $smartctl --scan 2>&1 | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ -like '/dev/*' }
        $results = foreach ($dev in $devices) {
            $json = & $smartctl -a -j $dev 2>&1 | Out-String
            try { $json | ConvertFrom-Json } catch { [pscustomobject]@{ Device = $dev; ParseError = $true } }
        }
        Export-EHJson -InputObject @($results) -Path (Join-Path $layout.Snapshot 'smartctl.json') -Depth 10
        Write-EHLog ("smartctl collected {0} device(s)." -f @($devices).Count)
    }
    else {
        Write-EHLog 'smartctl.exe not present in ToolsPath, skipping per-attribute SMART.' -Level DEBUG
    }

    # Full DirectX/display diagnostic. Useful for GPU driver crash history.
    $dxdiag = Join-Path $env:SystemRoot 'System32\dxdiag.exe'
    if (Test-Path -LiteralPath $dxdiag) {
        $dxOut = Join-Path $layout.Snapshot 'dxdiag.txt'
        $p = Start-Process -FilePath $dxdiag -ArgumentList '/whql:off', '/t', "`"$dxOut`"" -PassThru -WindowStyle Hidden
        if (-not $p.WaitForExit(90000)) {
            try { $p.Kill() } catch { }
            Write-EHLog 'dxdiag timed out after 90s and was terminated.' -Level WARN
        }
    }
} | Out-Null

#endregion

#region finish --------------------------------------------------------------

$manifest = [pscustomobject]@{
    Tool          = 'EndpointHealth'
    Kind          = 'snapshot'
    RunName       = $layout.RunName
    ComputerName  = $env:COMPUTERNAME
    GeneratedUtc  = (Get-Date).ToUniversalTime()
    EventLookbackDays = $EventLookbackDays
    Elevated      = Test-EHElevated
    Files         = @(Get-ChildItem -LiteralPath $layout.Snapshot -File | Select-Object Name, Length)
}
Export-EHJson -InputObject $manifest -Path (Join-Path $layout.Root 'manifest.json') -Depth 6

Write-EHLog ("Snapshot complete. {0} MB staged at {1}" -f (Get-EHFolderSizeMB -Path $layout.Root), $layout.Root)

if ($Upload) {
    if (Test-EHSharePath -Path $config.SharePath) {
        [void](Invoke-EHUpload -Source $layout.Root -Destination $layout.ShareRoot)
    }
    else {
        Write-EHLog ("SharePath '{0}' is not set or not reachable. Skipping upload." -f $config.SharePath) -Level WARN
    }
}

# Hand the layout back so a caller can chain into analysis.
$layout

#endregion
