<#
.SYNOPSIS
    Starts a bounded telemetry campaign on this machine.

.DESCRIPTION
    Installs the agent under ProgramData, takes a baseline deep snapshot,
    writes campaign state, and registers a scheduled task that samples
    telemetry on an interval. The task runs at startup and on a repetition, so
    the campaign survives reboots and logoffs, and the agent removes itself
    when the campaign expires.

    Run this on the target machine. Deploy-EndpointHealth.ps1 is the wrapper
    for pushing it from ManageEngine or from an admin workstation.

.PARAMETER SharePath
    UNC path collected data is copied to. Overrides the value in config.json.

    IMPORTANT: the scheduled task runs as SYSTEM by default, which reaches the
    network as the machine account DOMAIN\COMPUTERNAME$. Either grant Domain
    Computers (or a computer group) Modify on the share and the folder, or pass
    -RunAsUser with a service account. This is the single most common reason a
    campaign collects data and uploads nothing.

.PARAMETER Days
    Campaign length. The agent tears itself down when this expires.

.PARAMETER SampleIntervalMinutes
    How often the sampler runs. Five minutes costs a few MB over a week.

.PARAMETER RunAsUser
    Optional service account for the scheduled task, in DOMAIN\user form. Use
    this when granting the machine account share rights is not acceptable.

.PARAMETER RunAsPassword
    Password for RunAsUser, as a SecureString.

.PARAMETER SkipSnapshot
    Skip the baseline snapshot. Only useful when re-arming a campaign on a
    machine that was snapshotted minutes ago.

.EXAMPLE
    .\Start-HealthCampaign.ps1 -SharePath \\fs01\EndpointHealth$ -Days 7

.EXAMPLE
    .\Start-HealthCampaign.ps1 -SharePath \\fs01\EndpointHealth$ -Days 7 `
        -RunAsUser 'CORP\svc-endpointhealth' -RunAsPassword (Read-Host -AsSecureString)
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $SharePath,
    [int]    $Days = 7,
    [int]    $SampleIntervalMinutes,
    [int]    $UploadIntervalMinutes,
    [ValidateSet('WPR', 'Procmon', 'Both', 'None')]
    [string] $CaptureEngine,
    [string] $RunAsUser,
    [securestring] $RunAsPassword,
    [switch] $SkipSnapshot,
    [switch] $Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

if (-not (Test-EHElevated)) {
    throw 'Start-HealthCampaign must run elevated. It registers a scheduled task running as SYSTEM.'
}

$TaskFolder = '\EndpointHealth'
$TaskName   = 'EndpointHealth-Sampler'

#region build the effective configuration -----------------------------------

$config = Get-EHConfig -ConfigPath $ConfigPath

# Command line wins over the config file, which wins over the defaults.
if ($SharePath)             { $config.SharePath = $SharePath }
if ($Days -gt 0)            { $config.CampaignDays = $Days }
if ($SampleIntervalMinutes) { $config.SampleIntervalMinutes = $SampleIntervalMinutes }
if ($UploadIntervalMinutes) { $config.UploadIntervalMinutes = $UploadIntervalMinutes }
if ($CaptureEngine) {
    $config.DeepCapture.Engine  = $CaptureEngine
    $config.DeepCapture.Enabled = ($CaptureEngine -ne 'None')
}

if (-not (Test-EHSharePath -Path $config.SharePath)) {
    $message = "SharePath '$($config.SharePath)' is not set or not reachable from this session."
    if ($Force) {
        Write-Warning ("{0} Continuing because -Force was supplied; data will stage locally." -f $message)
    }
    else {
        throw ("{0} Fix it, or pass -Force to collect locally and copy the data off by hand." -f $message)
    }
}

$localRoot = $config.LocalRoot
if (-not (Test-Path -LiteralPath $localRoot)) {
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
}

Initialize-EHLog -Path (Join-Path $localRoot 'campaign.log')

#endregion

#region install the agent ---------------------------------------------------

# The campaign must not depend on the folder it was launched from, which in a
# ManageEngine deployment is a temporary directory that gets cleaned up.
$agentDir = Join-Path $localRoot 'agent'
if (-not (Test-Path -LiteralPath $agentDir)) {
    New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
}

$sourceDir = $PSScriptRoot
if ((Resolve-Path $sourceDir).Path -ne (Resolve-Path $agentDir).Path) {
    Write-EHLog ("Installing agent from {0} to {1}" -f $sourceDir, $agentDir)
    Copy-Item -Path (Join-Path $sourceDir '*') -Destination $agentDir -Recurse -Force -Exclude 'runs', '*.log'
}
else {
    Write-EHLog 'Already running from the installed agent directory.'
}

# The task points at the installed config, not at whatever was passed in.
$installedConfig = Join-Path $localRoot 'config.json'
Export-EHJson -InputObject $config -Path $installedConfig -Depth 8
Write-EHLog ("Effective config written to {0}" -f $installedConfig)

#endregion

#region campaign state ------------------------------------------------------

$existing = Get-EHState -Config $config
if ($existing -and -not $Force) {
    $endUtc = [datetime]::Parse($existing.EndUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
    if ($endUtc -gt (Get-Date).ToUniversalTime()) {
        throw ("A campaign is already running (run '{0}', ends {1} UTC). Use -Force to replace it, or Stop-HealthCampaign.ps1 to end it." -f $existing.RunName, $endUtc)
    }
}

$startedUtc = (Get-Date).ToUniversalTime()
$layout = New-EHRunLayout -Config $config
Initialize-EHLog -Path (Join-Path $layout.Logs 'agent.log')

$state = [pscustomobject]@{
    RunName          = $layout.RunName
    ComputerName     = $env:COMPUTERNAME
    StartedUtc       = $startedUtc.ToString('o')
    EndUtc           = $startedUtc.AddDays([int]$config.CampaignDays).ToString('o')
    CampaignDays     = [int]$config.CampaignDays
    SharePath        = $config.SharePath
    StartedBy        = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
    RunAsUser        = if ($RunAsUser) { $RunAsUser } else { 'SYSTEM' }
    Streaks          = [pscustomobject]@{}
    Captures         = @()
    LastUploadUtc    = $null
}
Set-EHState -Config $config -State $state

Write-EHLog ("Campaign '{0}' starting: {1} day(s), ends {2} UTC." -f $state.RunName, $state.CampaignDays, $state.EndUtc)

#endregion

#region baseline snapshot ---------------------------------------------------

if (-not $SkipSnapshot) {
    Write-EHLog 'Taking baseline snapshot. This takes a minute or two.'
    try {
        & (Join-Path $agentDir 'Invoke-HealthSnapshot.ps1') -ConfigPath $installedConfig -RunName $layout.RunName | Out-Null
    }
    catch {
        # A failed snapshot is not fatal. The telemetry campaign is the part
        # that cannot be re-run after the fact.
        Write-EHLog ("Baseline snapshot failed: {0}" -f $_.Exception.Message) -Level ERROR
    }
}

#endregion

#region scheduled task ------------------------------------------------------

$samplerScript = Join-Path $agentDir 'Invoke-TelemetrySample.ps1'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$argumentString = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ConfigPath "{1}"' -f `
    $samplerScript, $installedConfig

$action = New-ScheduledTaskAction -Execute $psExe -Argument $argumentString

$interval = New-TimeSpan -Minutes ([int]$config.SampleIntervalMinutes)
# Bounded rather than indefinite: the campaign is days, and an unbounded
# repetition is harder to reason about if teardown ever fails.
$duration = New-TimeSpan -Days ([int]$config.CampaignDays + 2)

$repeating = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                -RepetitionInterval $interval -RepetitionDuration $duration

$triggers = @($repeating)

# A startup trigger makes the first post-reboot sample prompt instead of
# waiting for the repetition window to come round again.
try {
    $atStartup = New-ScheduledTaskTrigger -AtStartup
    $atStartup.Repetition = $repeating.Repetition
    $triggers += $atStartup
}
catch {
    Write-EHLog ("Could not attach a repetition to the startup trigger: {0}. The repeating trigger alone still survives reboots." -f $_.Exception.Message) -Level WARN
    try { $triggers += (New-ScheduledTaskTrigger -AtStartup) } catch { }
}

$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# Hidden keeps it out of the user's way; it is not a stealth setting and the
# task is plainly visible in Task Scheduler.
$settings.Hidden = $true

# Replace any previous registration rather than trying to update in place.
try {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath "$TaskFolder\" -Confirm:$false -ErrorAction Stop
    Write-EHLog 'Removed the previous sampler task.'
}
catch { }

$registerArgs = @{
    TaskName    = $TaskName
    TaskPath    = "$TaskFolder\"
    Action      = $action
    Trigger     = $triggers
    Settings    = $settings
    Description = ('EndpointHealth telemetry sampler. Campaign {0} ends {1} UTC. Removes itself on expiry.' -f $state.RunName, $state.EndUtc)
    Force       = $true
}

if ($RunAsUser) {
    if (-not $RunAsPassword) { throw 'RunAsUser requires RunAsPassword.' }
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RunAsPassword))
    $registerArgs['User']     = $RunAsUser
    $registerArgs['Password'] = $plain
    $registerArgs['RunLevel'] = 'Highest'
    Write-EHLog ("Sampler will run as {0}." -f $RunAsUser)
}
else {
    $registerArgs['Principal'] = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Write-EHLog 'Sampler will run as SYSTEM. The share must grant the machine account write access.'
}

$null = Register-ScheduledTask @registerArgs

if ($RunAsUser) {
    # Do not leave the plaintext password in the session any longer than the
    # registration needs it.
    Remove-Variable -Name plain -ErrorAction SilentlyContinue
    $registerArgs['Password'] = $null
}

Write-EHLog ("Registered {0}\{1}, repeating every {2} minute(s)." -f $TaskFolder, $TaskName, $config.SampleIntervalMinutes)

# Run one sample immediately so a misconfiguration surfaces now rather than in
# five minutes, or on the technician's next visit.
try {
    Start-ScheduledTask -TaskName $TaskName -TaskPath "$TaskFolder\"
    Write-EHLog 'First sample kicked off.'
}
catch {
    Write-EHLog ("Could not start the task immediately: {0}" -f $_.Exception.Message) -Level WARN
}

#endregion

Write-EHLog '---'
Write-EHLog ("Campaign      : {0}" -f $state.RunName)
Write-EHLog ("Ends          : {0} UTC" -f $state.EndUtc)
Write-EHLog ("Staging to    : {0}" -f $layout.Root)
Write-EHLog ("Uploading to  : {0}" -f $layout.ShareRoot)
Write-EHLog ("Stop early    : Stop-HealthCampaign.ps1")

[pscustomobject]@{
    RunName   = $state.RunName
    EndUtc    = $state.EndUtc
    LocalRoot = $layout.Root
    ShareRoot = $layout.ShareRoot
    TaskPath  = "$TaskFolder\$TaskName"
    RunAs     = $state.RunAsUser
}
