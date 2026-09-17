<#
.SYNOPSIS
    Ends a telemetry campaign and removes the agent's scheduled task.

.DESCRIPTION
    Called automatically by the sampler when a campaign expires, and by hand
    when you want to stop early. By default it runs a final analysis, pushes
    everything to the share, unregisters the scheduled task and leaves the
    local staging folder in place.

    Nothing here removes collected data from the share.

.PARAMETER KeepLocalData
    Leave the staged run folder under ProgramData. This is the default when
    the sampler calls it on expiry, so the data survives a failed upload.

.PARAMETER RemoveAgent
    Also delete the installed agent and configuration from ProgramData. Use
    this when decommissioning a machine from the programme entirely.

.PARAMETER SkipFinalUpload
    Do not attempt a final upload. Useful when the share is known to be down
    and you just want the task gone.

.EXAMPLE
    .\Stop-HealthCampaign.ps1

.EXAMPLE
    .\Stop-HealthCampaign.ps1 -RemoveAgent
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $KeepLocalData,
    [switch] $RemoveAgent,
    [switch] $SkipFinalUpload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

if (-not (Test-EHElevated)) {
    throw 'Stop-HealthCampaign must run elevated to unregister the scheduled task.'
}

$TaskFolder = '\EndpointHealth'
$TaskName   = 'EndpointHealth-Sampler'

$config = Get-EHConfig -ConfigPath $ConfigPath
$state  = Get-EHState -Config $config

Initialize-EHLog -Path (Join-Path $config.LocalRoot 'campaign.log')

if (-not $state) {
    Write-EHLog 'No campaign state found. Removing the scheduled task if it exists and stopping.' -Level WARN
}
else {
    Write-EHLog ("Stopping campaign '{0}' (started {1} UTC)." -f $state.RunName, $state.StartedUtc)
}

#region final analysis and upload -------------------------------------------

if ($state) {
    $layout = New-EHRunLayout -Config $config -RunName $state.RunName

    try {
        & (Join-Path $PSScriptRoot 'Invoke-TelemetryAnalysis.ps1') -ConfigPath $ConfigPath -RunName $state.RunName -Quiet | Out-Null
        Write-EHLog 'Final analysis written.'
    }
    catch {
        Write-EHLog ("Final analysis failed: {0}" -f $_.Exception.Message) -Level ERROR
    }

    # Record the outcome alongside the data so the run folder is self-describing.
    $state | Add-Member -NotePropertyName StoppedUtc -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
    $state | Add-Member -NotePropertyName StoppedBy  -NotePropertyValue ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) -Force
    Export-EHJson -InputObject $state -Path (Join-Path $layout.Root 'campaign.json') -Depth 8

    if (-not $SkipFinalUpload) {
        if (Test-EHSharePath -Path $config.SharePath) {
            if (Invoke-EHUpload -Source $layout.Root -Destination $layout.ShareRoot) {
                Write-EHLog ("Final upload complete: {0}" -f $layout.ShareRoot)
            }
            else {
                Write-EHLog 'Final upload failed. Local data is being kept regardless of -KeepLocalData.' -Level ERROR
                $KeepLocalData = $true
            }
        }
        else {
            Write-EHLog ("Share {0} unreachable. Local data is being kept." -f $config.SharePath) -Level WARN
            $KeepLocalData = $true
        }
    }
}

#endregion

#region stop any capture still running --------------------------------------

# A deep capture that was mid-flight when the campaign was stopped would
# otherwise leave a tracing session running indefinitely.
#
# Only our own session is cancelled. Invoke-DeepCapture drops a marker while
# it holds the WPR session; without that marker the running trace belongs to
# something else on the box and is left alone.
$wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
$wprMarker = Join-Path $config.LocalRoot 'wpr-session.marker'

if ((Test-Path -LiteralPath $wpr) -and (Test-Path -LiteralPath $wprMarker)) {
    try {
        Write-EHLog 'A deep capture was mid-flight. Cancelling its WPR session.' -Level WARN
        & $wpr -cancel 2>&1 | Out-Null
    }
    catch { }
    finally {
        Remove-Item -LiteralPath $wprMarker -Force -ErrorAction SilentlyContinue
    }
}

foreach ($name in @('Procmon64', 'Procmon')) {
    $running = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    if ($running.Count -eq 0) { continue }

    Write-EHLog ("{0} is still running. Terminating it." -f $name) -Level WARN

    # Ask Procmon to stop cleanly first so the backing file is flushed and
    # readable. Killing it outright usually leaves an unopenable PML.
    foreach ($exeName in @('Procmon64.exe', 'Procmon.exe')) {
        $exe = Join-Path $config.ToolsPath $exeName
        if (Test-Path -LiteralPath $exe) {
            try { & $exe '/Terminate' 2>&1 | Out-Null } catch { }
        }
    }
    Start-Sleep -Seconds 5
    Stop-Process -Name $name -Force -ErrorAction SilentlyContinue
}

#endregion

#region unregister ----------------------------------------------------------

# Deliberately no Stop-ScheduledTask here. When the sampler hands off teardown
# on expiry, stopping the task would terminate the very process doing the
# unregistering. Unregister on its own is enough; an in-flight sampler run
# finishes normally.
try {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath "$TaskFolder\" -Confirm:$false -ErrorAction Stop
    Write-EHLog ("Unregistered {0}\{1}." -f $TaskFolder, $TaskName)
}
catch {
    Write-EHLog ("Could not unregister the task (it may already be gone): {0}" -f $_.Exception.Message) -Level WARN
}

# Remove the now-empty task folder so Task Scheduler is left tidy.
try {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $root = $scheduler.GetFolder('\')
    $folder = $root.GetFolder($TaskFolder)
    if (@($folder.GetTasks(0)).Count -eq 0) {
        $root.DeleteFolder($TaskFolder, 0)
        Write-EHLog ("Removed empty task folder {0}." -f $TaskFolder)
    }
}
catch { }

#endregion

#region cleanup -------------------------------------------------------------

$statePath = Get-EHStatePath -Config $config
if (Test-Path -LiteralPath $statePath) {
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Write-EHLog 'Campaign state cleared.'
}

if (-not $KeepLocalData -and $state) {
    $runRoot = Join-Path (Join-Path $config.LocalRoot 'runs') $state.RunName
    if (Test-Path -LiteralPath $runRoot) {
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
        Write-EHLog ("Removed local staging at {0}." -f $runRoot)
    }
}

if ($RemoveAgent) {
    $agentDir = Join-Path $config.LocalRoot 'agent'
    # The running script may live inside the directory being deleted, so this
    # is scheduled rather than done inline.
    if (Test-Path -LiteralPath $agentDir) {
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $cmd = 'Start-Sleep -Seconds 10; Remove-Item -LiteralPath "{0}" -Recurse -Force -ErrorAction SilentlyContinue' -f $agentDir
        Start-Process -FilePath $psExe -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-Command', $cmd -WindowStyle Hidden | Out-Null
        Write-EHLog ("Agent removal from {0} scheduled." -f $agentDir)
    }
}

#endregion

Write-EHLog 'Campaign stopped.'

$shareRoot = $null
if ($state -and $config.SharePath) {
    $shareRoot = Join-Path $config.SharePath $state.RunName
}

[pscustomobject]@{
    RunName       = if ($state) { $state.RunName } else { $null }
    LocalDataKept = [bool]$KeepLocalData
    ShareRoot     = $shareRoot
}
