<#
.SYNOPSIS
    Browser console for the EndpointHealth toolkit.

.DESCRIPTION
    Hosts a small HTTPS service on this machine. A technician browses to it,
    is signed in silently by Kerberos, and can validate the share, check agent
    versions, install the optional binaries, launch a snapshot or campaign
    locally or against a remote machine, generate the Endpoint Central
    deployment arguments, and read any run's report straight from the share.

    Security model, deliberately narrow:

      * Authentication is Negotiate (Kerberos, falling back to NTLM). No login
        form exists and no password is ever typed, transmitted or stored. Every
        sign-in appears in the domain security log like any other Kerberos
        service ticket request.

      * Authorisation is membership in one AD group, named by -AllowedGroup.
        Everyone else gets 403 regardless of how privileged they are.

      * The service account this runs as should hold local administrator on the
        workstations under investigation and Modify on the share. It must not be
        a Domain Admin. Tier 0 credentials have no business on a Tier 2
        endpoint, and this console gives them no reason to be there.

      * State-changing requests require the X-EH-Token header, issued to the
        page by GET /api/session, and an Origin header matching this host.
        Integrated authentication is ambient, so without this any page a
        technician visited could drive the console in the background.

      * Binding to anything other than loopback requires HTTPS and
        authentication. The interlock cannot be switched off with a flag.

    Windows PowerShell 5.1. Must run elevated: reserving an HTTP namespace and
    remoting to endpoints both require it.

.PARAMETER Port
    TCP port to listen on. Default 8443.

.PARAMETER AllowedGroup
    AD group whose members may use the console, as DOMAIN\Group or a SID.
    Required unless -Local is used.

.PARAMETER Local
    Loopback-only mode: binds 127.0.0.1 over plain HTTP with no authentication,
    for a technician running the console on their own elevated session. Refuses
    to bind a network address.

.PARAMETER BindAddress
    Address to bind for network mode. Default '+' (all interfaces).

.EXAMPLE
    .\Start-HealthConsole.ps1 -AllowedGroup 'CORP\FCCI-EndpointHealth-Admins'

.EXAMPLE
    .\Start-HealthConsole.ps1 -Local
#>
[CmdletBinding()]
param(
    [int]    $Port = 8443,
    [string] $AllowedGroup,
    [switch] $Local,
    [string] $BindAddress = '+',
    [string] $ConfigPath,
    [switch] $NoBrowser
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

if (-not (Test-EHElevated)) {
    throw 'Start-HealthConsole must run elevated. It reserves an HTTP namespace and remotes to endpoints.'
}

#region mode interlock ------------------------------------------------------

if ($Local) {
    $BindAddress = '127.0.0.1'
    $scheme = 'http'
    if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = 8080 }
}
else {
    $scheme = 'https'
    if (-not $AllowedGroup) {
        throw 'Network mode requires -AllowedGroup. Name the AD group whose members may use this console, or use -Local for a loopback-only session.'
    }
    # The interlock. Anything reachable from the network is authenticated and
    # encrypted, with no override.
    if ($BindAddress -in '127.0.0.1', 'localhost', '::1') {
        throw 'A loopback bind in network mode is contradictory. Use -Local instead.'
    }
}

$prefix = '{0}://{1}:{2}/' -f $scheme, $BindAddress, $Port

#endregion

#region certificate preflight -----------------------------------------------

function Get-BoundCertificate {
    <#
        netsh is the only supported way to read the HTTP.SYS certificate
        bindings. HttpListener will not accept a certificate directly.
    #>
    param([int] $Port)

    foreach ($ip in @('0.0.0.0', '[::]')) {
        try {
            $out = & netsh.exe http show sslcert ipport=("{0}:{1}" -f $ip, $Port) 2>&1 | Out-String
            if ($out -match 'Certificate Hash\s*:\s*([0-9a-fA-F]{40})') {
                return [pscustomobject]@{ IpPort = ('{0}:{1}' -f $ip, $Port); Thumbprint = $Matches[1] }
            }
        }
        catch { }
    }
    $null
}

$certBinding = $null
if ($scheme -eq 'https') {
    $certBinding = Get-BoundCertificate -Port $Port
    if (-not $certBinding) {
        $fqdn = '{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN
        $appId = '{00000000-0000-0000-0000-000000000042}'

        Write-Host ''
        Write-Host 'No TLS certificate is bound to this port, so HTTPS cannot start.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Request a certificate from your internal CA for this host, then bind it.'
        Write-Host 'From an elevated prompt on this machine:'
        Write-Host ''
        Write-Host ('  # 1. Request a machine certificate for {0} from AD CS' -f $fqdn) -ForegroundColor Cyan
        Write-Host ('  Get-Certificate -Template WebServer -DnsName "{0}" -CertStoreLocation Cert:\LocalMachine\My' -f $fqdn) -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  # 2. Find its thumbprint' -ForegroundColor Cyan
        Write-Host ('  Get-ChildItem Cert:\LocalMachine\My | Where-Object {{ $_.Subject -like "*{0}*" }} | Format-List Subject, Thumbprint' -f $env:COMPUTERNAME) -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  # 3. Bind it to the port' -ForegroundColor Cyan
        Write-Host ('  netsh http add sslcert ipport=0.0.0.0:{0} certhash=<THUMBPRINT> appid="{1}"' -f $Port, $appId) -ForegroundColor Cyan
        Write-Host ''
        Write-Host 'Then start this console again. Use -Local for a loopback session in the meantime.'
        Write-Host ''
        throw ('No certificate bound to port {0}.' -f $Port)
    }
    Write-Host ("TLS certificate {0} bound on {1}." -f $certBinding.Thumbprint, $certBinding.IpPort) -ForegroundColor Green
}

#endregion

#region state ---------------------------------------------------------------

$script:Config = Get-EHConfig -ConfigPath $ConfigPath

# Save back to whatever file was actually loaded. Get-EHConfig prefers a
# config.json sitting beside the scripts over the one under LocalRoot, so
# writing blindly to LocalRoot would leave saved settings silently ignored on
# the next start.
$script:ConfigFile = $null
if ($script:Config.PSObject.Properties['ConfigPath'] -and $script:Config.ConfigPath) {
    $script:ConfigFile = [string]$script:Config.ConfigPath
}
if (-not $script:ConfigFile) {
    $script:ConfigFile = Join-Path $script:Config.LocalRoot 'config.json'
}
$script:Jobs       = @{}
$script:Token      = [guid]::NewGuid().ToString('N')
$script:ToolkitRoot = $PSScriptRoot

$script:ToolkitFiles = @(
    'EndpointHealth.psm1'
    'Invoke-HealthSnapshot.ps1'
    'Invoke-TelemetrySample.ps1'
    'Invoke-DeepCapture.ps1'
    'Invoke-TelemetryAnalysis.ps1'
    'New-HealthReport.ps1'
    'Start-HealthCampaign.ps1'
    'Stop-HealthCampaign.ps1'
    'Deploy-EndpointHealth.ps1'
)

Initialize-EHLog -Path (Join-Path $script:Config.LocalRoot 'console.log')

#endregion

#region http helpers --------------------------------------------------------

function Write-Response {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Body,
        [string] $ContentType = 'application/json; charset=utf-8',
        [int]    $Status = 200
    )

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $r = $Context.Response
        $r.StatusCode = $Status
        $r.ContentType = $ContentType
        $r.ContentLength64 = $bytes.Length
        $r.Headers['X-Content-Type-Options'] = 'nosniff'
        $r.Headers['X-Frame-Options'] = 'DENY'
        $r.Headers['Referrer-Policy'] = 'no-referrer'
        $r.Headers['Cache-Control'] = 'no-store'
        # Everything the page needs is served from this origin. Nothing external
        # is loaded, so the policy can be this tight.
        $r.Headers['Content-Security-Policy'] = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
        $r.OutputStream.Write($bytes, 0, $bytes.Length)
        $r.Close()
    }
    catch {
        Write-EHLog ("Response write failed: {0}" -f $_.Exception.Message) -Level DEBUG
    }
}

function Write-Json {
    param($Context, $Object, [int] $Status = 200)
    $json = $Object | ConvertTo-Json -Depth 10
    if ($null -eq $json) { $json = 'null' }
    Write-Response -Context $Context -Body $json -Status $Status
}

function Write-JsonArray {
    <#
        ConvertTo-Json unwraps a single-element array into a bare object, which
        breaks any caller doing .length on the result. List endpoints always
        emit a real array.
    #>
    param($Context, $Items, [int] $Status = 200)

    $arr = @($Items)
    if ($arr.Count -eq 0) {
        Write-Response -Context $Context -Body '[]' -Status $Status
        return
    }
    $json = $arr | ConvertTo-Json -Depth 10
    if ($arr.Count -eq 1) { $json = '[' + $json + ']' }
    Write-Response -Context $Context -Body $json -Status $Status
}

function Write-Problem {
    param($Context, [string] $Message, [int] $Status = 400)
    Write-Json -Context $Context -Object ([pscustomobject]@{ error = $Message }) -Status $Status
}

function Read-RequestJson {
    param($Context)
    $req = $Context.Request
    if (-not $req.HasEntityBody) { return $null }
    $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
    try { $text = $reader.ReadToEnd() } finally { $reader.Close() }
    if (-not $text) { return $null }
    try { $text | ConvertFrom-Json } catch { $null }
}

function Get-BodyValue {
    <#
        StrictMode turns a missing property into a terminating error, so every
        optional field in a request body has to be read through here. A caller
        that omits one should get a default, not a 500.
    #>
    param($Body, [string] $Name, $Default = '')

    if ($null -eq $Body) { return $Default }
    $p = $Body.PSObject.Properties[$Name]
    if (-not $p -or $null -eq $p.Value) { return $Default }
    $p.Value
}

#endregion

#region validation ----------------------------------------------------------

# Anything that reaches a remoting call or a generated script is validated
# against a whitelist first. These two are the only free-text values that do.
function Test-ComputerNameSafe {
    param([string] $Name)
    if (-not $Name) { return $false }
    [bool]($Name -match '^[A-Za-z0-9][A-Za-z0-9\-\.]{0,62}$')
}

function Test-RunNameSafe {
    param([string] $Name)
    if (-not $Name) { return $false }
    if ($Name -match '\.\.') { return $false }
    [bool]($Name -match '^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,127}$')
}

#endregion

#region preflight checks ----------------------------------------------------

function Get-ShareStatus {
    param([string] $SharePath)

    $result = [ordered]@{
        path      = $SharePath
        configured = $false
        reachable = $false
        writable  = $false
        detail    = ''
    }

    if (-not $SharePath -or $SharePath -like '*CHANGE-ME*') {
        $result.detail = 'No share path configured yet.'
        return [pscustomobject]$result
    }
    $result.configured = $true

    try {
        if (-not (Test-Path -LiteralPath $SharePath -ErrorAction Stop)) {
            $result.detail = 'Path does not exist or is not reachable from this host.'
            return [pscustomobject]$result
        }
    }
    catch {
        $result.detail = $_.Exception.Message
        return [pscustomobject]$result
    }
    $result.reachable = $true

    # A reachable share that cannot be written to is the single most common
    # reason a campaign collects perfectly and delivers nothing.
    $probe = Join-Path $SharePath ('.ehwrite-{0}.tmp' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        Set-Content -LiteralPath $probe -Value 'probe' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        $result.writable = $true
        $result.detail = 'Reachable and writable by this service account.'
    }
    catch {
        $result.detail = ('Reachable but not writable as {0}\{1}: {2}' -f $env:USERDOMAIN, $env:USERNAME, $_.Exception.Message)
    }

    [pscustomobject]$result
}

function Get-AgentVersionStatus {
    <#
        Compares the toolkit this console is running from against the copy
        installed under ProgramData. A stale agent is the quiet failure mode
        after the toolkit gets updated on the admin workstation only.
    #>
    param()

    $agentDir = Join-Path $script:Config.LocalRoot 'agent'
    $rows = @()

    foreach ($name in $script:ToolkitFiles) {
        $source = Join-Path $script:ToolkitRoot $name
        $installed = Join-Path $agentDir $name

        $sourceHash = $null
        $installedHash = $null
        if (Test-Path -LiteralPath $source)    { $sourceHash    = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash }
        if (Test-Path -LiteralPath $installed) { $installedHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash }

        $state = 'current'
        if (-not $sourceHash)                     { $state = 'missing here' }
        elseif (-not $installedHash)              { $state = 'not installed' }
        elseif ($sourceHash -ne $installedHash)   { $state = 'stale' }

        $rows += [pscustomobject]@{ file = $name; state = $state }
    }

    $rulesSource = Join-Path $script:ToolkitRoot 'rules/correlation-rules.json'
    $rows += [pscustomobject]@{
        file  = 'rules/correlation-rules.json'
        state = $(if (Test-Path -LiteralPath $rulesSource) { 'current' } else { 'missing here' })
    }

    [pscustomobject]@{
        agentDir = $agentDir
        files    = $rows
        stale        = @($rows | Where-Object { $_.state -eq 'stale' }).Count
        missing      = @($rows | Where-Object { $_.state -like '*missing*' }).Count
        notInstalled = @($rows | Where-Object { $_.state -eq 'not installed' }).Count
    }
}

function Get-DependencyStatus {
    param()

    $toolsPath = $script:Config.ToolsPath
    $winget = $null
    try { $winget = (Get-Command winget.exe -ErrorAction Stop).Source } catch { }

    $items = @()
    foreach ($d in @(
        @{ Name = 'Procmon64.exe'; Purpose = 'Procmon deep capture engine'; Package = '9NBLGGH4S4TG' },
        @{ Name = 'smartctl.exe';  Purpose = 'per-attribute SMART data';    Package = 'smartmontools.smartmontools' }
    )) {
        $path = Join-Path $toolsPath $d.Name
        $items += [pscustomobject]@{
            name    = $d.Name
            purpose = $d.Purpose
            package = $d.Package
            present = (Test-Path -LiteralPath $path)
        }
    }

    [pscustomobject]@{
        toolsPath      = $toolsPath
        wingetPath     = $winget
        wingetAvailable = [bool]$winget
        items          = $items
    }
}

function Get-RunList {
    param()

    $runs = @()

    $sharePath = $script:Config.SharePath
    if ($sharePath -and $sharePath -notlike '*CHANGE-ME*') {
        try {
            foreach ($d in @(Get-ChildItem -LiteralPath $sharePath -Directory -ErrorAction Stop)) {
                $runs += [pscustomobject]@{
                    name     = $d.Name
                    location = 'share'
                    modified = $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                    hasReport = (Test-Path -LiteralPath (Join-Path $d.FullName 'REPORT.html'))
                }
            }
        }
        catch { }
    }

    $localRuns = Join-Path $script:Config.LocalRoot 'runs'
    if (Test-Path -LiteralPath $localRuns) {
        try {
            foreach ($d in @(Get-ChildItem -LiteralPath $localRuns -Directory -ErrorAction Stop)) {
                if (@($runs | Where-Object { $_.name -eq $d.Name }).Count -gt 0) { continue }
                $runs += [pscustomobject]@{
                    name     = $d.Name
                    location = 'local'
                    modified = $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                    hasReport = (Test-Path -LiteralPath (Join-Path $d.FullName 'REPORT.html'))
                }
            }
        }
        catch { }
    }

    @($runs | Sort-Object modified -Descending)
}

function Resolve-RunPath {
    param([string] $RunName)

    $candidates = @()
    if ($script:Config.SharePath -and $script:Config.SharePath -notlike '*CHANGE-ME*') {
        $candidates += (Join-Path $script:Config.SharePath $RunName)
    }
    $candidates += (Join-Path (Join-Path $script:Config.LocalRoot 'runs') $RunName)

    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    $null
}

#endregion

#region job execution -------------------------------------------------------

function New-RunScript {
    <#
        Writes the run out as a standalone script with this run's variables
        already resolved. The job executes that file rather than an inline
        string, so exactly what ran is on disk afterwards and can be pasted
        into Endpoint Central or re-run by hand.
    #>
    param(
        [Parameter(Mandatory)][string] $JobId,
        [Parameter(Mandatory)][string] $Mode,
        [string] $Target,
        [int]    $Days,
        [string] $Engine
    )

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('# Generated by Start-HealthConsole.ps1. Safe to keep, re-run or hand to Endpoint Central.')
    [void]$lines.Add(('# Job {0}, requested {1}' -f $JobId, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    [void]$lines.Add('')
    [void]$lines.Add(('Set-Location -LiteralPath ''{0}''' -f $script:ToolkitRoot))
    [void]$lines.Add('')

    $splat = New-Object System.Collections.ArrayList
    [void]$splat.Add(('    Mode      = ''{0}''' -f $Mode))
    [void]$splat.Add(('    SharePath = ''{0}''' -f $script:Config.SharePath))
    if ($Target)            { [void]$splat.Add(('    ComputerName = ''{0}''' -f $Target)) }
    if ($Mode -eq 'Campaign' -and $Days -gt 0) { [void]$splat.Add(('    Days      = {0}' -f $Days)) }
    if ($Engine)            { [void]$splat.Add(('    CaptureEngine = ''{0}''' -f $Engine)) }

    [void]$lines.Add('$params = @{')
    foreach ($s in $splat) { [void]$lines.Add($s) }
    [void]$lines.Add('}')
    [void]$lines.Add('')
    [void]$lines.Add('& .\Deploy-EndpointHealth.ps1 @params')

    $dir = Join-Path $script:Config.LocalRoot 'jobs'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $path = Join-Path $dir ('{0}.ps1' -f $JobId)
    Set-Content -LiteralPath $path -Value ($lines -join [Environment]::NewLine) -Encoding UTF8
    $path
}

function Start-ConsoleJob {
    param(
        [Parameter(Mandatory)][string] $Mode,
        [string] $Target,
        [int]    $Days,
        [string] $Engine,
        [string] $RequestedBy
    )

    $jobId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6))
    $scriptPath = New-RunScript -JobId $jobId -Mode $Mode -Target $Target -Days $Days -Engine $Engine

    $job = Start-Job -Name $jobId -ScriptBlock {
        param($Path)
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Path 2>&1 | Out-String
    } -ArgumentList $scriptPath

    $script:Jobs[$jobId] = [pscustomobject]@{
        id          = $jobId
        mode        = $Mode
        target      = $(if ($Target) { $Target } else { 'this machine' })
        days        = $Days
        engine      = $Engine
        scriptPath  = $scriptPath
        requestedBy = $RequestedBy
        started     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        job         = $job
    }

    Write-EHLog ("Job {0}: {1} against {2}, requested by {3}" -f $jobId, $Mode, $script:Jobs[$jobId].target, $RequestedBy)
    $script:Jobs[$jobId]
}

function Get-JobView {
    param($Entry)

    $state = 'unknown'
    $output = ''
    try {
        $state = "$($Entry.job.State)"
        $output = ($Entry.job | Receive-Job -Keep -ErrorAction SilentlyContinue | Out-String)

        # A job that failed with nothing on stdout leaves the technician with
        # no reason at all, so fall back to the child job's error stream.
        if (-not $output.Trim()) {
            $errors = @()
            foreach ($child in @($Entry.job.ChildJobs)) {
                foreach ($e in @($child.Error)) { $errors += "$e" }
                foreach ($e in @($child.JobStateInfo.Reason)) { if ($e) { $errors += "$($e.Message)" } }
            }
            if ($errors.Count -gt 0) { $output = ($errors -join [Environment]::NewLine) }
        }
    }
    catch { }

    [pscustomobject]@{
        id          = $Entry.id
        mode        = $Entry.mode
        target      = $Entry.target
        started     = $Entry.started
        requestedBy = $Entry.requestedBy
        scriptPath  = $Entry.scriptPath
        state       = $state
        output      = $output
    }
}

#endregion

#region request handling ----------------------------------------------------

function Get-CallerName {
    param($Context)
    if ($Local) { return ('{0}\{1} (local)' -f $env:USERDOMAIN, $env:USERNAME) }
    try { return "$($Context.User.Identity.Name)" } catch { return 'unknown' }
}

function Test-Authorised {
    param($Context)

    if ($Local) { return $true }

    $identity = $null
    try { $identity = $Context.User.Identity } catch { }
    if (-not $identity -or -not $identity.IsAuthenticated) { return $false }

    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        if ($AllowedGroup -match '^S-1-') {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($AllowedGroup)
            return $principal.IsInRole($sid)
        }
        return $principal.IsInRole($AllowedGroup)
    }
    catch {
        Write-EHLog ("Group check failed for {0}: {1}" -f $identity.Name, $_.Exception.Message) -Level WARN
        $false
    }
}

function Test-CsrfOk {
    <#
        Integrated authentication is sent by the browser automatically, so a
        page on another origin could otherwise drive this console silently.
        A custom header cannot be set cross-origin without a preflight, which
        this service never approves, and the Origin header pins it further.
    #>
    param($Context)

    $req = $Context.Request
    if ($req.HttpMethod -eq 'GET') { return $true }

    $token = $req.Headers['X-EH-Token']
    if ($token -ne $script:Token) { return $false }

    $origin = $req.Headers['Origin']
    if ($origin) {
        try {
            $u = [uri]$origin
            if ($u.Host -ne $req.Url.Host -or $u.Port -ne $req.Url.Port) { return $false }
        }
        catch { return $false }
    }
    $true
}

function Invoke-Route {
    param($Context)

    $req    = $Context.Request
    $path   = $req.Url.AbsolutePath.TrimEnd('/')
    $method = $req.HttpMethod
    if (-not $path) { $path = '/' }

    # --- static page ---
    if ($path -eq '/' -and $method -eq 'GET') {
        $indexPath = Join-Path $script:ToolkitRoot 'console/index.html'
        if (-not (Test-Path -LiteralPath $indexPath)) {
            Write-Response -Context $Context -Body 'console/index.html is missing from the toolkit folder.' -ContentType 'text/plain' -Status 500
            return
        }
        $html = Get-Content -LiteralPath $indexPath -Raw
        $html = $html.Replace('__EH_TOKEN__', $script:Token)
        Write-Response -Context $Context -Body $html -ContentType 'text/html; charset=utf-8'
        return
    }

    # --- session ---
    if ($path -eq '/api/session' -and $method -eq 'GET') {
        Write-Json -Context $Context -Object ([pscustomobject]@{
            user        = Get-CallerName -Context $Context
            mode        = $(if ($Local) { 'local' } else { 'network' })
            scheme      = $scheme
            host        = $env:COMPUTERNAME
            runningAs   = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            allowedGroup = $(if ($AllowedGroup) { $AllowedGroup } else { '(loopback mode, no group check)' })
            token       = $script:Token
            certThumbprint = $(if ($certBinding) { $certBinding.Thumbprint } else { $null })
        })
        return
    }

    # --- config ---
    if ($path -eq '/api/config' -and $method -eq 'GET') {
        Write-Json -Context $Context -Object ([pscustomobject]@{
            sharePath             = $script:Config.SharePath
            localRoot             = $script:Config.LocalRoot
            toolsPath             = $script:Config.ToolsPath
            campaignDays          = $script:Config.CampaignDays
            sampleIntervalMinutes = $script:Config.SampleIntervalMinutes
            uploadIntervalMinutes = $script:Config.UploadIntervalMinutes
            folderNameStyle       = $script:Config.FolderNameStyle
            captureEngine         = $script:Config.DeepCapture.Engine
            redactUserNames       = $script:Config.RedactUserNames
            configFile            = $script:ConfigFile
        })
        return
    }

    if ($path -eq '/api/config' -and $method -eq 'POST') {
        $body = Read-RequestJson -Context $Context
        if (-not $body) { Write-Problem -Context $Context -Message 'No configuration supplied.'; return }

        foreach ($pair in @(
            @{ Key = 'sharePath';             Target = 'SharePath' },
            @{ Key = 'toolsPath';             Target = 'ToolsPath' },
            @{ Key = 'folderNameStyle';       Target = 'FolderNameStyle' },
            @{ Key = 'campaignDays';          Target = 'CampaignDays' },
            @{ Key = 'sampleIntervalMinutes'; Target = 'SampleIntervalMinutes' },
            @{ Key = 'uploadIntervalMinutes'; Target = 'UploadIntervalMinutes' },
            @{ Key = 'redactUserNames';       Target = 'RedactUserNames' }
        )) {
            $p = $body.PSObject.Properties[$pair.Key]
            if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') {
                $script:Config.$($pair.Target) = $p.Value
            }
        }

        $engineProp = $body.PSObject.Properties['captureEngine']
        if ($engineProp -and $engineProp.Value -in 'WPR', 'Procmon', 'Both', 'None') {
            $script:Config.DeepCapture.Engine  = $engineProp.Value
            $script:Config.DeepCapture.Enabled = ($engineProp.Value -ne 'None')
        }

        if (-not (Test-Path -LiteralPath $script:Config.LocalRoot)) {
            New-Item -ItemType Directory -Path $script:Config.LocalRoot -Force | Out-Null
        }
        Export-EHJson -InputObject $script:Config -Path $script:ConfigFile -Depth 8
        Write-EHLog ("Configuration updated by {0}." -f (Get-CallerName -Context $Context))

        Write-Json -Context $Context -Object ([pscustomobject]@{ saved = $true; configFile = $script:ConfigFile })
        return
    }

    # --- preflight ---
    if ($path -eq '/api/preflight' -and $method -eq 'GET') {
        Write-Json -Context $Context -Object ([pscustomobject]@{
            elevated     = (Test-EHElevated)
            runningAs    = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
            share        = Get-ShareStatus -SharePath $script:Config.SharePath
            agent        = Get-AgentVersionStatus
            dependencies = Get-DependencyStatus
            certThumbprint = $(if ($certBinding) { $certBinding.Thumbprint } else { $null })
        })
        return
    }

    # --- runs ---
    if ($path -eq '/api/runs' -and $method -eq 'GET') {
        Write-JsonArray -Context $Context -Items (Get-RunList)
        return
    }

    if ($path -like '/api/report/*' -and $method -eq 'GET') {
        $runName = $path.Substring('/api/report/'.Length)
        try { $runName = [uri]::UnescapeDataString($runName) } catch { }

        if (-not (Test-RunNameSafe -Name $runName)) {
            Write-Problem -Context $Context -Message 'Rejected run name.' -Status 400
            return
        }

        $runPath = Resolve-RunPath -RunName $runName
        if (-not $runPath) { Write-Problem -Context $Context -Message 'Run not found.' -Status 404; return }

        $reportPath = Join-Path $runPath 'REPORT.html'
        if (-not (Test-Path -LiteralPath $reportPath)) {
            # Older runs predate the report generator. Build one on demand,
            # falling back to a local copy when the share is read-only.
            try {
                & (Join-Path $script:ToolkitRoot 'New-HealthReport.ps1') -RunPath $runPath | Out-Null
            }
            catch {
                $temp = Join-Path $env:TEMP ('EH-{0}.html' -f $runName)
                try {
                    & (Join-Path $script:ToolkitRoot 'New-HealthReport.ps1') -RunPath $runPath -OutputPath $temp | Out-Null
                    $reportPath = $temp
                }
                catch {
                    Write-Problem -Context $Context -Message ('Could not build a report for that run: {0}' -f $_.Exception.Message) -Status 500
                    return
                }
            }
        }

        if (-not (Test-Path -LiteralPath $reportPath)) {
            Write-Problem -Context $Context -Message 'Report could not be produced.' -Status 500
            return
        }

        Write-Response -Context $Context -Body (Get-Content -LiteralPath $reportPath -Raw) -ContentType 'text/html; charset=utf-8'
        return
    }

    # --- dependency install ---
    if ($path -eq '/api/deps/install' -and $method -eq 'POST') {
        $body = Read-RequestJson -Context $Context
        $package = "$(Get-BodyValue $body 'package')"

        # Whitelist only. Nothing from the request reaches a command line
        # unless it is one of these exact known identifiers.
        $allowed = @('smartmontools.smartmontools', '9NBLGGH4S4TG')
        if ($package -notin $allowed) {
            Write-Problem -Context $Context -Message 'Unknown package.' -Status 400
            return
        }

        $winget = $null
        try { $winget = (Get-Command winget.exe -ErrorAction Stop).Source } catch { }
        if (-not $winget) {
            Write-Problem -Context $Context -Message 'winget is not available in this context. Note that winget is an MSIX-packaged app and generally does not work under a service account or SYSTEM. Install these by hand into ToolsPath instead.' -Status 409
            return
        }

        $out = & $winget install --id $package --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-String
        Write-EHLog ("winget install {0} requested by {1}." -f $package, (Get-CallerName -Context $Context))
        Write-Json -Context $Context -Object ([pscustomobject]@{ package = $package; output = $out })
        return
    }

    # --- run ---
    if ($path -eq '/api/run' -and $method -eq 'POST') {
        $body = Read-RequestJson -Context $Context
        if (-not $body) { Write-Problem -Context $Context -Message 'No request body.'; return }

        $mode = "$(Get-BodyValue $body 'mode')"
        if ($mode -notin 'Snapshot', 'Campaign', 'Stop', 'Status', 'Analyze') {
            Write-Problem -Context $Context -Message 'Unknown mode.'
            return
        }

        $target = ''
        $scope = "$(Get-BodyValue $body 'scope' 'local')"
        if ($scope -eq 'remote') {
            $target = "$(Get-BodyValue $body 'target')".Trim()
            if (-not (Test-ComputerNameSafe -Name $target)) {
                Write-Problem -Context $Context -Message 'That computer name is not a valid hostname.'
                return
            }
        }

        $days = 0
        [void][int]::TryParse("$(Get-BodyValue $body 'days' 0)", [ref]$days)
        if ($days -lt 0 -or $days -gt 30) { $days = 0 }

        $engine = "$(Get-BodyValue $body 'engine')"
        if ($engine -notin 'WPR', 'Procmon', 'Both', 'None') { $engine = '' }

        $entry = Start-ConsoleJob -Mode $mode -Target $target -Days $days -Engine $engine `
                                  -RequestedBy (Get-CallerName -Context $Context)
        Write-Json -Context $Context -Object (Get-JobView -Entry $entry)
        return
    }

    # --- jobs ---
    if ($path -eq '/api/jobs' -and $method -eq 'GET') {
        $views = @()
        foreach ($k in @($script:Jobs.Keys | Sort-Object -Descending)) {
            $views += Get-JobView -Entry $script:Jobs[$k]
        }
        Write-JsonArray -Context $Context -Items $views
        return
    }

    # --- endpoint central guide ---
    if ($path -eq '/api/manageengine' -and $method -eq 'GET') {
        $share = $script:Config.SharePath
        $days = [int]$script:Config.CampaignDays

        Write-Json -Context $Context -Object ([pscustomobject]@{
            campaignArgs = ('"-Mode" "Campaign" "-Days" "{0}" "-SharePath" "{1}"' -f $days, $share)
            snapshotArgs = ('"-Mode" "Snapshot" "-SharePath" "{0}"' -f $share)
            steps = @(
                'Configurations > Computer Configuration > Custom Script.'
                'Upload the whole EndpointHealth folder as dependency files, keeping the rules subfolder intact.'
                'Script to run: Deploy-EndpointHealth.ps1'
                'Paste the arguments above, each argument in its own quotes.'
                'Run as: System. The agent already runs as SYSTEM, which is what the sampler needs.'
                'Frequency: Once. Not Every Refresh Cycle and not During Every Startup, or the campaign restarts every 90 minutes.'
                'Tick Enable logging for troubleshooting so output lands in the Execution Status.'
                'Target the machines under investigation and deploy.'
            )
            note = 'The agent installs itself to C:\ProgramData\EndpointHealth\agent on first run and removes its own scheduled task when the campaign expires. No teardown configuration is needed.'
        })
        return
    }

    Write-Problem -Context $Context -Message 'No such endpoint.' -Status 404
}

#endregion

#region listen --------------------------------------------------------------

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)

if (-not $Local) {
    $listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::Negotiate
}
else {
    $listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::Anonymous
}

try {
    $listener.Start()
}
catch {
    Write-Host ''
    Write-Host ('Could not start the listener on {0}' -f $prefix) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''
    Write-Host 'If this is an access error, reserve the namespace first:' -ForegroundColor Yellow
    Write-Host ('  netsh http add urlacl url={0} user="{1}\{2}"' -f $prefix, $env:USERDOMAIN, $env:USERNAME) -ForegroundColor Cyan
    Write-Host ''
    throw
}

$displayHost = $(if ($Local) { '127.0.0.1' } else { '{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN })
$url = '{0}://{1}:{2}/' -f $scheme, $displayHost, $Port

Write-Host ''
Write-Host '  EndpointHealth console' -ForegroundColor Green
Write-Host ('  {0}' -f $url)
Write-Host ''
Write-Host ('  running as    : {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
if ($Local) {
    Write-Host '  mode          : loopback only, no authentication'
    Write-Host '  reachable by  : this machine only'
}
else {
    Write-Host '  authentication: Kerberos/Negotiate, no password is collected'
    Write-Host ('  authorised    : members of {0}' -f $AllowedGroup)
}
Write-Host ''
Write-Host '  Ctrl+C to stop.'
Write-Host ''

if (-not $NoBrowser -and $Local) {
    try { Start-Process $url | Out-Null } catch { }
}

try {
    while ($listener.IsListening) {
        $context = $null
        try { $context = $listener.GetContext() }
        catch { break }
        if (-not $context) { continue }

        $caller = Get-CallerName -Context $context

        try {
            if (-not (Test-Authorised -Context $context)) {
                Write-EHLog ("DENIED {0} {1} for {2}: not a member of {3}" -f `
                    $context.Request.HttpMethod, $context.Request.Url.AbsolutePath, $caller, $AllowedGroup) -Level WARN
                Write-Problem -Context $context -Message 'Your account is not authorised to use this console.' -Status 403
                continue
            }

            if (-not (Test-CsrfOk -Context $context)) {
                Write-EHLog ("REJECTED cross-origin or untokened {0} {1} from {2}" -f `
                    $context.Request.HttpMethod, $context.Request.Url.AbsolutePath, $caller) -Level WARN
                Write-Problem -Context $context -Message 'Request rejected.' -Status 403
                continue
            }

            Invoke-Route -Context $context
        }
        catch {
            Write-EHLog ("Handler error on {0}: {1}" -f $context.Request.Url.AbsolutePath, $_.Exception.Message) -Level ERROR
            try { Write-Problem -Context $context -Message $_.Exception.Message -Status 500 } catch { }
        }
    }
}
finally {
    try { $listener.Stop(); $listener.Close() } catch { }
    foreach ($k in @($script:Jobs.Keys)) {
        try { $script:Jobs[$k].job | Remove-Job -Force -ErrorAction SilentlyContinue } catch { }
    }
    Write-Host 'Console stopped.'
}

#endregion
