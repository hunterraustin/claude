<#
.SYNOPSIS
    Single entry point for the Endpoint Health toolkit. Run it locally, or
    point it at a computer on the domain.

.DESCRIPTION
    This is the script to hand to ManageEngine Endpoint Central, or to run from
    an admin workstation against a named machine. It does no collection itself;
    it decides where to run and calls the right script.

    Modes:
      Snapshot  one-shot deep diagnostic, analysed and uploaded. Minutes.
      Campaign  start a bounded telemetry campaign that survives reboots. Days.
      Stop      end a running campaign and collect the final data.
      Analyze   re-run the rules against data already collected.
      Status    report what is running on the target.

    Remote targeting uses PowerShell remoting. The toolkit is copied to the
    target's ProgramData and executed there, because a campaign has to keep
    running after the session closes.

.PARAMETER ComputerName
    Target machine. Omit to run locally, which is what ManageEngine does.

.PARAMETER Mode
    What to do. Defaults to Snapshot, which is the safe thing to run against a
    machine you know nothing about yet.

.PARAMETER SharePath
    UNC path for collected data. Folders are named COMPUTERNAME_9-17_1059.

.PARAMETER Days
    Campaign length for Mode Campaign.

.EXAMPLE
    # From ManageEngine, as a computer configuration or script:
    .\Deploy-EndpointHealth.ps1 -Mode Snapshot -SharePath \\fs01\EndpointHealth$

.EXAMPLE
    # From your workstation, against one machine, for a week:
    .\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Campaign -Days 7 `
        -SharePath \\fs01\EndpointHealth$

.EXAMPLE
    .\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Status
#>
[CmdletBinding()]
param(
    [string] $ComputerName,

    [ValidateSet('Snapshot', 'Campaign', 'Stop', 'Analyze', 'Status')]
    [string] $Mode = 'Snapshot',

    [string] $SharePath,
    [int]    $Days = 7,
    [int]    $SampleIntervalMinutes,
    [int]    $EventLookbackDays = 14,

    [ValidateSet('WPR', 'Procmon', 'Both', 'None')]
    [string] $CaptureEngine,

    [ValidateSet('Compact', 'Sortable')]
    [string] $FolderNameStyle,

    [pscredential] $Credential,

    # Service account for the scheduled task, when the machine account should
    # not be granted share rights.
    [string] $RunAsUser,
    [securestring] $RunAsPassword,

    [switch] $Force,
    [switch] $RemoveAgent
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$toolkitFiles = @(
    'EndpointHealth.psm1'
    'Invoke-HealthSnapshot.ps1'
    'Invoke-TelemetrySample.ps1'
    'Invoke-DeepCapture.ps1'
    'Invoke-TelemetryAnalysis.ps1'
    'New-HealthReport.ps1'
    'Start-HealthConsole.ps1'
    'Start-HealthCampaign.ps1'
    'Stop-HealthCampaign.ps1'
    'Deploy-EndpointHealth.ps1'
)

function Write-Step {
    param([string] $Message)
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

#region local execution -----------------------------------------------------

function Invoke-LocalMode {
    <#
        Runs the requested mode against the machine this function executes on.
        Called directly when local, and through Invoke-Command when remote.
    #>
    param(
        [Parameter(Mandatory)][string] $ScriptRoot,
        [Parameter(Mandatory)][string] $Mode,
        [hashtable] $Options
    )

    $ErrorActionPreference = 'Stop'

    # Build a config override from whatever was supplied, so a caller never has
    # to hand-edit config.json for a one-off run.
    #
    # Keys starting with an underscore are runtime arguments (including a
    # service account password) and must never reach the file on disk.
    $configPath = $null
    $persisted = @{}
    foreach ($k in $Options.Keys) {
        if ($k -like '_*') { continue }
        if ($k -eq 'EventLookbackDays') { continue }
        $persisted[$k] = $Options[$k]
    }

    if ($persisted.Count -gt 0) {
        $configDir = 'C:\ProgramData\EndpointHealth'
        if (-not (Test-Path -LiteralPath $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }

        $existing = @{}
        $livePath = Join-Path $configDir 'config.json'
        if (Test-Path -LiteralPath $livePath) {
            try {
                $loaded = Get-Content -LiteralPath $livePath -Raw | ConvertFrom-Json
                foreach ($p in $loaded.PSObject.Properties) { $existing[$p.Name] = $p.Value }
            }
            catch { }
        }
        foreach ($k in $persisted.Keys) { $existing[$k] = $persisted[$k] }

        $configPath = Join-Path $configDir 'config.json'
        $existing | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding UTF8
    }

    # Defaults for the two numeric options, so a caller that omits them does
    # not end up with a zero-day event lookback or a zero-day campaign.
    $lookbackDays = 14
    if ($Options.ContainsKey('EventLookbackDays') -and $Options['EventLookbackDays']) {
        $lookbackDays = [int]$Options['EventLookbackDays']
    }
    $campaignDays = 7
    if ($Options.ContainsKey('CampaignDays') -and $Options['CampaignDays']) {
        $campaignDays = [int]$Options['CampaignDays']
    }

    switch ($Mode) {
        'Snapshot' {
            $layout = & (Join-Path $ScriptRoot 'Invoke-HealthSnapshot.ps1') `
                            -ConfigPath $configPath `
                            -EventLookbackDays $lookbackDays
            & (Join-Path $ScriptRoot 'Invoke-TelemetryAnalysis.ps1') `
                            -ConfigPath $configPath -RunName $layout.RunName -Quiet | Out-Null

            # Upload after the analysis so SUMMARY.txt lands with the data.
            #
            # When this runs inside a remoting session the upload usually fails:
            # the caller's credential does not survive the second hop to the
            # file server. The caller detects Uploaded = $false and copies the
            # data back itself.
            Import-Module (Join-Path $ScriptRoot 'EndpointHealth.psm1') -Force
            $cfg = Get-EHConfig -ConfigPath $configPath
            $uploaded = $false
            if (Test-EHSharePath -Path $cfg.SharePath) {
                $uploaded = Invoke-EHUpload -Source $layout.Root -Destination $layout.ShareRoot
            }

            [pscustomobject]@{
                Mode      = 'Snapshot'
                RunName   = $layout.RunName
                LocalPath = $layout.Root
                SharePath = $layout.ShareRoot
                Uploaded  = [bool]$uploaded
                Summary   = Join-Path $layout.Root 'SUMMARY.txt'
            }
        }

        'Campaign' {
            $splat = @{ ConfigPath = $configPath; Days = $campaignDays }
            if ($Options.ContainsKey('_RunAsUser'))     { $splat['RunAsUser'] = $Options['_RunAsUser'] }
            if ($Options.ContainsKey('_RunAsPassword')) { $splat['RunAsPassword'] = (ConvertTo-SecureString $Options['_RunAsPassword'] -AsPlainText -Force) }
            if ($Options.ContainsKey('_Force'))         { $splat['Force'] = [bool]$Options['_Force'] }
            & (Join-Path $ScriptRoot 'Start-HealthCampaign.ps1') @splat
        }

        'Stop' {
            $splat = @{ ConfigPath = $configPath }
            if ($Options.ContainsKey('_RemoveAgent')) { $splat['RemoveAgent'] = [bool]$Options['_RemoveAgent'] }
            & (Join-Path $ScriptRoot 'Stop-HealthCampaign.ps1') @splat
        }

        'Analyze' {
            & (Join-Path $ScriptRoot 'Invoke-TelemetryAnalysis.ps1') -ConfigPath $configPath -Quiet
        }

        'Status' {
            Import-Module (Join-Path $ScriptRoot 'EndpointHealth.psm1') -Force
            $cfg = Get-EHConfig -ConfigPath $configPath
            $state = Get-EHState -Config $cfg

            $task = $null
            try {
                $task = Get-ScheduledTask -TaskName 'EndpointHealth-Sampler' -TaskPath '\EndpointHealth\' -ErrorAction Stop
            }
            catch { }

            $runRoot = $null
            if ($state) { $runRoot = Join-Path (Join-Path $cfg.LocalRoot 'runs') $state.RunName }

            [pscustomobject]@{
                ComputerName   = $env:COMPUTERNAME
                CampaignActive = [bool]$state
                RunName        = if ($state) { $state.RunName } else { $null }
                StartedUtc     = if ($state) { $state.StartedUtc } else { $null }
                EndUtc         = if ($state) { $state.EndUtc } else { $null }
                CaptureCount   = if ($state -and $state.PSObject.Properties['Captures']) { @($state.Captures).Count } else { 0 }
                LastUploadUtc  = if ($state -and $state.PSObject.Properties['LastUploadUtc']) { $state.LastUploadUtc } else { $null }
                TaskState      = if ($task) { "$($task.State)" } else { 'not registered' }
                SharePath      = $cfg.SharePath
                StagedMB       = if ($runRoot) { Get-EHFolderSizeMB -Path $runRoot } else { 0 }
            }
        }
    }
}

#endregion

#region assemble options ----------------------------------------------------

$options = @{}
if ($SharePath)             { $options['SharePath'] = $SharePath }
if ($Days -gt 0)            { $options['CampaignDays'] = $Days }
if ($SampleIntervalMinutes) { $options['SampleIntervalMinutes'] = $SampleIntervalMinutes }
if ($FolderNameStyle)       { $options['FolderNameStyle'] = $FolderNameStyle }
$options['EventLookbackDays'] = $EventLookbackDays

if ($CaptureEngine) {
    $options['DeepCapture'] = @{
        Enabled = ($CaptureEngine -ne 'None')
        Engine  = $CaptureEngine
    }
}

# Underscore-prefixed keys are passed through to the mode handler rather than
# written into config.json.
if ($RunAsUser) {
    $options['_RunAsUser'] = $RunAsUser
    if (-not $RunAsPassword) { throw 'RunAsUser requires RunAsPassword.' }
    $options['_RunAsPassword'] = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RunAsPassword))
}
if ($Force)        { $options['_Force'] = $true }
if ($RemoveAgent)  { $options['_RemoveAgent'] = $true }

# Keys the mode handler consumes must not end up in the persisted config.
$configOnly = @{}
foreach ($k in $options.Keys) {
    if ($k -notlike '_*' -and $k -ne 'EventLookbackDays') { $configOnly[$k] = $options[$k] }
}

#endregion

#region dispatch ------------------------------------------------------------

if (-not $ComputerName -or $ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq 'localhost') {

    Write-Step ("Running {0} locally on {1}." -f $Mode, $env:COMPUTERNAME)

    $localOptions = $configOnly.Clone()
    $localOptions['EventLookbackDays'] = $EventLookbackDays
    foreach ($k in $options.Keys) { if ($k -like '_*') { $localOptions[$k] = $options[$k] } }

    $result = Invoke-LocalMode -ScriptRoot $PSScriptRoot -Mode $Mode -Options $localOptions
    $result
    return
}

#endregion

#region remote --------------------------------------------------------------

Write-Step ("Targeting {0} over PowerShell remoting." -f $ComputerName)

try {
    $null = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
}
catch {
    throw ("WinRM is not answering on {0}. Enable PowerShell remoting on the target (Enable-PSRemoting, or the WinRM Group Policy), or run this script on the machine itself, which is how ManageEngine invokes it. Underlying error: {1}" -f $ComputerName, $_.Exception.Message)
}

$sessionArgs = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
if ($Credential) { $sessionArgs['Credential'] = $Credential }

$session = New-PSSession @sessionArgs
try {
    $remoteRoot = Invoke-Command -Session $session -ScriptBlock {
        $dir = 'C:\ProgramData\EndpointHealth\agent'
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $dir
    }

    Write-Step ("Copying the toolkit to {0} on {1}." -f $remoteRoot, $ComputerName)
    foreach ($file in $toolkitFiles) {
        $local = Join-Path $PSScriptRoot $file
        if (-not (Test-Path -LiteralPath $local)) { continue }
        Copy-Item -LiteralPath $local -Destination (Join-Path $remoteRoot $file) -ToSession $session -Force
    }

    $rulesLocal = Join-Path $PSScriptRoot 'rules\correlation-rules.json'
    if (Test-Path -LiteralPath $rulesLocal) {
        Invoke-Command -Session $session -ScriptBlock {
            param($root)
            $rulesDir = Join-Path $root 'rules'
            if (-not (Test-Path -LiteralPath $rulesDir)) { New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null }
        } -ArgumentList $remoteRoot
        Copy-Item -LiteralPath $rulesLocal -Destination (Join-Path $remoteRoot 'rules\correlation-rules.json') -ToSession $session -Force
    }

    Write-Step ("Running {0} on {1}." -f $Mode, $ComputerName)

    $remoteOptions = $configOnly.Clone()
    $remoteOptions['EventLookbackDays'] = $EventLookbackDays
    foreach ($k in $options.Keys) { if ($k -like '_*') { $remoteOptions[$k] = $options[$k] } }

    $result = Invoke-Command -Session $session `
        -ScriptBlock ${function:Invoke-LocalMode} `
        -ArgumentList $remoteRoot, $Mode, $remoteOptions

    # Second-hop fallback. A snapshot taken inside a remoting session normally
    # cannot write to the file server, because the caller's credential is not
    # delegated past the target. Pull the data back through the session and
    # push it to the share from here, where the credential is real.
    if ($Mode -eq 'Snapshot' -and $SharePath -and $result -and
        $result.PSObject.Properties['Uploaded'] -and -not $result.Uploaded) {

        Write-Step 'Target could not reach the share (expected over remoting). Relaying the data.'

        $staging = Join-Path ([System.IO.Path]::GetTempPath()) ('EndpointHealth-' + $result.RunName)
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
        New-Item -ItemType Directory -Path $staging -Force | Out-Null

        try {
            Copy-Item -LiteralPath $result.LocalPath -Destination $staging -FromSession $session -Recurse -Force

            $sourceDir = Join-Path $staging $result.RunName
            if (-not (Test-Path -LiteralPath $sourceDir)) { $sourceDir = $staging }

            $destination = Join-Path $SharePath $result.RunName
            $roboOut = & robocopy.exe $sourceDir $destination /E /R:2 /W:5 /NP /NFL /NDL
            if ($LASTEXITCODE -lt 8) {
                Write-Step ('Relayed to {0}.' -f $destination)
                $result | Add-Member -NotePropertyName Uploaded -NotePropertyValue $true -Force
                $result | Add-Member -NotePropertyName RelayedByCaller -NotePropertyValue $true -Force
            }
            else {
                Write-Warning ('Relay to {0} failed (robocopy {1}). Data is still on the target at {2}.' -f $destination, $LASTEXITCODE, $result.LocalPath)
                Write-Verbose (($roboOut | Select-Object -Last 10) -join [Environment]::NewLine)
            }
        }
        catch {
            Write-Warning ('Could not relay the snapshot: {0}. Data is still on the target at {1}.' -f $_.Exception.Message, $result.LocalPath)
        }
        finally {
            if (Test-Path -LiteralPath $staging) {
                Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $result
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($options.ContainsKey('_RunAsPassword')) { $options['_RunAsPassword'] = $null }
}

#endregion
