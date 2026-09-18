<#
.SYNOPSIS
    Builds a self-contained HTML report for one run folder.

.DESCRIPTION
    Reads a finished run (metrics.json, findings.json, the rules file and any
    capture metadata) and writes REPORT.html beside them.

    The point of this report is provenance. For every finding it shows the rule
    that fired, the exact comparison that fired it, the observed value, and the
    collector file that value came from. It also lists the rules that did NOT
    fire, so the reader can see what was checked and found clean.

    The output has no external references: no CDN, no fonts, no fetch. All data
    is inlined at generation time. That is deliberate, because the file has to
    open from a UNC share on a locked-down workstation, where a browser is not
    allowed to read sibling files.

    Windows PowerShell 5.1 compatible. Nothing here is Windows-specific, so the
    generator also runs under PowerShell 7 on any platform for testing.

.PARAMETER RunPath
    Path to a run folder. Use this to point straight at a folder on the share
    without needing config.json. Takes precedence over -RunName.

.PARAMETER RunName
    Run folder under LocalRoot\runs to report on. Defaults to the active
    campaign, then to the most recent run.

.PARAMETER OutputPath
    Where to write the HTML. Defaults to REPORT.html inside the run folder.

.EXAMPLE
    .\New-HealthReport.ps1 -RunPath \\fs01\EndpointHealth$\WKS042_9-17_1059

.EXAMPLE
    .\New-HealthReport.ps1 -RunName WKS042_9-17_1059
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $RunPath,
    [string] $RunName,
    [string] $RulesPath,
    [string] $OutputPath,
    [switch] $PassThru
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

#region locate the run ------------------------------------------------------

if (-not $RunPath) {
    Import-Module (Join-Path $PSScriptRoot 'EndpointHealth.psm1') -Force

    $config = Get-EHConfig -ConfigPath $ConfigPath

    if (-not $RunName) {
        $state = Get-EHState -Config $config
        if ($state) { $RunName = $state.RunName }
    }
    if (-not $RunName) {
        $runsRoot = Join-Path $config.LocalRoot 'runs'
        if (Test-Path -LiteralPath $runsRoot) {
            $latest = Get-ChildItem -LiteralPath $runsRoot -Directory |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latest) { $RunName = $latest.Name }
        }
    }
    if (-not $RunName) { throw 'No run to report on. Pass -RunPath, or run the analysis first.' }

    $RunPath = Join-Path (Join-Path $config.LocalRoot 'runs') $RunName
}

if (-not (Test-Path -LiteralPath $RunPath)) {
    throw ("Run folder not found: {0}" -f $RunPath)
}

$runFolderName = Split-Path -Leaf $RunPath
if (-not $OutputPath) { $OutputPath = Join-Path $RunPath 'REPORT.html' }

if (-not $RulesPath) { $RulesPath = Join-Path $PSScriptRoot 'rules/correlation-rules.json' }

#endregion

#region helpers -------------------------------------------------------------

function Read-JsonFile {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch {
        Write-Warning ("Could not parse {0}: {1}" -f $Path, $_.Exception.Message)
        $null
    }
}

function Get-Prop {
    # Property access that yields $null rather than throwing under StrictMode.
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p) { return $null }
    $p.Value
}

# Ordered prefix table mapping a metric name back to the file that produced it.
# First match wins, so the specific storage-snapshot disk metrics have to be
# listed before the generic 'disk.' latency metrics that come from telemetry.
$sourceRules = @(
    @{ Prefix = 'system.';        Source = 'snapshot/system.json' }
    @{ Prefix = 'hw.';            Source = 'snapshot/hardware.json' }
    @{ Prefix = 'hardware.';      Source = 'snapshot/hardware.json' }
    @{ Prefix = 'storage.';       Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.wear';      Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.health';    Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.media';     Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.unhealthy'; Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.powerOn';   Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.readErrors';    Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.uncorrected';   Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.temperature';   Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.smart';     Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.free';      Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.volume';    Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.trim';      Source = 'snapshot/storage.json' }
    @{ Prefix = 'disk.';          Source = 'telemetry/samples.csv' }
    @{ Prefix = 'security.';      Source = 'snapshot/security.json' }
    @{ Prefix = 'defender.';      Source = 'snapshot/security.json' }
    @{ Prefix = 'net.bytesSec';   Source = 'telemetry/samples.csv' }
    @{ Prefix = 'net.';           Source = 'snapshot/network.json' }
    @{ Prefix = 'software.';      Source = 'snapshot/software.json' }
    @{ Prefix = 'power.';         Source = 'snapshot/power.json' }
    @{ Prefix = 'events.';        Source = 'snapshot/events.json' }
    @{ Prefix = 'boot.';          Source = 'snapshot/reliability.json' }
    @{ Prefix = 'cpu.';           Source = 'telemetry/samples.csv' }
    @{ Prefix = 'mem.';           Source = 'telemetry/samples.csv' }
    @{ Prefix = 'sys.';           Source = 'telemetry/samples.csv' }
    @{ Prefix = 'telemetry.';     Source = 'telemetry/samples.csv' }
    @{ Prefix = 'proc.';          Source = 'telemetry/processes.csv' }
    @{ Prefix = 'captures.';      Source = 'captures/*/capture.json' }
)

function Get-MetricSource {
    param([string] $Name)
    foreach ($rule in $sourceRules) {
        if ($Name -like ($rule.Prefix + '*')) { return $rule.Source }
    }
    'unknown'
}

function Test-Condition {
    <#
        Display-only port of the evaluator in Invoke-TelemetryAnalysis.ps1. It
        exists so the report can show which condition of a non-fired rule was
        not met. findings.json stays the authority for what actually fired.
    #>
    param($Condition, [System.Collections.IDictionary] $Metrics)

    $name = Get-Prop $Condition 'metric'
    $op   = Get-Prop $Condition 'op'
    $want = Get-Prop $Condition 'value'

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
            $a = 0.0; $b = 0.0
            if (-not [double]::TryParse("$have", [ref]$a)) { return $false }
            if (-not [double]::TryParse("$want", [ref]$b)) { return $false }
            switch ($op) {
                'gt'  { return $a -gt $b }
                'gte' { return $a -ge $b }
                'lt'  { return $a -lt $b }
                'lte' { return $a -le $b }
            }
            return $false
        }
    }
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return '(not collected)' }
    if ($Value -is [System.Array]) { return (@($Value | ForEach-Object { "$_" }) -join ', ') }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    "$Value"
}

$opWords = @{
    'gt' = 'is above'; 'gte' = 'is at or above'; 'lt' = 'is below'; 'lte' = 'is at or below'
    'eq' = 'equals'; 'ne' = 'does not equal'; 'contains' = 'contains'; 'notcontains' = 'does not contain'
    'matches' = 'matches'; 'exists' = 'was collected'; 'notexists' = 'was not collected'
}

function Get-OpWord {
    param([string] $Op)
    if ($Op -and $opWords.ContainsKey($Op)) { return $opWords[$Op] }
    "$Op"
}

#endregion

#region load the run data ---------------------------------------------------

$metricsDoc  = Read-JsonFile (Join-Path $RunPath 'metrics.json')
$findingsDoc = Read-JsonFile (Join-Path $RunPath 'findings.json')
$ruleDoc     = Read-JsonFile $RulesPath

if (-not $metricsDoc)  { throw ("No metrics.json in {0}. Run Invoke-TelemetryAnalysis.ps1 first." -f $RunPath) }
if (-not $ruleDoc)     { throw ("Rules file not found or unreadable at {0}" -f $RulesPath) }

# Flatten metrics into a case-insensitive dictionary for lookups.
$metrics = New-Object 'System.Collections.Specialized.OrderedDictionary'
foreach ($p in $metricsDoc.PSObject.Properties) { $metrics[$p.Name] = $p.Value }

$firedById = @{}
foreach ($f in @(Get-Prop $findingsDoc 'Findings')) {
    if ($f -and (Get-Prop $f 'Id')) { $firedById[[string](Get-Prop $f 'Id')] = $f }
}

#endregion

#region build the model -----------------------------------------------------

function New-ConditionRows {
    param($Rule)

    $rows = @()
    foreach ($c in @(Get-Prop $Rule 'all')) {
        $metricName = [string](Get-Prop $c 'metric')
        $observed = $null
        $collected = $metrics.Contains($metricName)
        if ($collected) { $observed = $metrics[$metricName] }

        $rows += [pscustomobject]@{
            metric    = $metricName
            observed  = Format-Value $observed
            collected = $collected
            op        = [string](Get-Prop $c 'op')
            opWord    = Get-OpWord ([string](Get-Prop $c 'op'))
            value     = Format-Value (Get-Prop $c 'value')
            met       = [bool](Test-Condition -Condition $c -Metrics $metrics)
            source    = Get-MetricSource $metricName
        }
    }
    , $rows
}

$findings = @()
$passed   = @()

foreach ($rule in @(Get-Prop $ruleDoc 'rules')) {
    if (-not $rule.PSObject.Properties['all']) { continue }

    $id   = [string](Get-Prop $rule 'id')
    $rows = New-ConditionRows -Rule $rule
    $fired = $firedById.ContainsKey($id)

    if ($fired) {
        $hit = $firedById[$id]

        $evidence = @()
        $evidenceObj = Get-Prop $hit 'Evidence'
        if ($evidenceObj) {
            foreach ($e in $evidenceObj.PSObject.Properties) {
                $evidence += [pscustomobject]@{
                    metric = $e.Name
                    value  = Format-Value $e.Value
                    source = Get-MetricSource $e.Name
                }
            }
        }

        $findings += [pscustomobject]@{
            id             = $id
            title          = [string](Get-Prop $hit 'Title')
            category       = [string](Get-Prop $hit 'Category')
            severity       = [string](Get-Prop $hit 'Severity')
            explanation    = [string](Get-Prop $hit 'Explanation')
            recommendation = [string](Get-Prop $hit 'Recommendation')
            conditions     = $rows
            evidence       = $evidence
        }
    }
    else {
        $severity = [string](Get-Prop $rule 'severity')
        if (-not $severity) { $severity = 'Medium' }

        $passed += [pscustomobject]@{
            id         = $id
            title      = [string](Get-Prop $rule 'title')
            category   = [string](Get-Prop $rule 'category')
            severity   = $severity
            conditions = $rows
        }
    }
}

$severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
$findings = @($findings | Sort-Object `
    @{ Expression = { if ($severityOrder.ContainsKey($_.severity)) { $severityOrder[$_.severity] } else { 9 } } },
    @{ Expression = 'id' })

# Every metric, with where it came from.
$metricRows = @()
foreach ($key in $metrics.Keys) {
    $metricRows += [pscustomobject]@{
        name   = $key
        value  = Format-Value $metrics[$key]
        source = Get-MetricSource $key
    }
}
$metricRows = @($metricRows | Sort-Object name)

# Per-process rollup, reconstructed from the proc.* metric family.
$processMap = @{}
foreach ($key in $metrics.Keys) {
    if ($key -notlike 'proc.*') { continue }
    $rest = $key.Substring(5)
    $dot = $rest.IndexOf('.')
    if ($dot -lt 1) { continue }
    $name = $rest.Substring(0, $dot)
    if ($name -in 'topCpu', 'topIo', 'topMem') { continue }
    $field = $rest.Substring($dot + 1)

    if (-not $processMap.ContainsKey($name)) {
        $processMap[$name] = [ordered]@{ name = $name; cpuP95 = 0; ioMBs = 0; wspMaxMB = 0; handlesMax = 0; impact = 0 }
    }

    $v = 0.0
    [void][double]::TryParse("$($metrics[$key])", [ref]$v)
    switch ($field) {
        'cpu.p95'         { $processMap[$name].cpuP95     = $v }
        'ioBytesSec.p95'  { $processMap[$name].ioMBs      = [math]::Round($v / 1MB, 2) }
        'wspMB.max'       { $processMap[$name].wspMaxMB   = $v }
        'handles.max'     { $processMap[$name].handlesMax = [int]$v }
        'impact'          { $processMap[$name].impact     = [int]$v }
    }
}
$processes = @($processMap.Values | ForEach-Object { [pscustomobject]$_ } | Sort-Object cpuP95 -Descending)

# Capture metadata.
$captures = @()
$capturesDir = Join-Path $RunPath 'captures'
if (Test-Path -LiteralPath $capturesDir) {
    foreach ($file in @(Get-ChildItem -LiteralPath $capturesDir -Filter 'capture.json' -Recurse -ErrorAction SilentlyContinue)) {
        $c = Read-JsonFile $file.FullName
        if (-not $c) { continue }
        $captures += [pscustomobject]@{
            id         = [string](Get-Prop $c 'Id')
            reason     = [string](Get-Prop $c 'Reason')
            engine     = [string](Get-Prop $c 'Engine')
            startedUtc = [string](Get-Prop $c 'StartedUtc')
            seconds    = [string](Get-Prop $c 'ActualSeconds')
            sizeMB     = [string](Get-Prop $c 'SizeMB')
            files      = @(@(Get-Prop $c 'Files') | ForEach-Object { "$_" })
            notes      = @(@(Get-Prop $c 'Notes') | ForEach-Object { "$_" })
        }
    }
}
$captures = @($captures | Sort-Object id)

function Get-Metric {
    param([string] $Name)
    if ($metrics.Contains($Name)) { return Format-Value $metrics[$Name] }
    $null
}

$counts = Get-Prop $findingsDoc 'SeverityCounts'

$meta = [pscustomobject]@{
    computerName  = $(if (Get-Metric 'system.computerName') { Get-Metric 'system.computerName' } else { $runFolderName })
    model         = Get-Metric 'system.model'
    serial        = Get-Metric 'system.serialNumber'
    os            = Get-Metric 'system.osCaption'
    osBuild       = Get-Metric 'system.osBuild'
    uptimeDays    = Get-Metric 'system.uptimeDays'
    runName       = $runFolderName
    generated     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    sampleCount   = Get-Metric 'telemetry.sampleCount'
    firstSample   = Get-Metric 'telemetry.firstSample'
    lastSample    = Get-Metric 'telemetry.lastSample'
    captureCount  = $captures.Count
    rulesTotal    = @(Get-Prop $ruleDoc 'rules').Count
    findingCount  = $findings.Count
    critical      = [int](Get-Prop $counts 'Critical')
    high          = [int](Get-Prop $counts 'High')
    medium        = [int](Get-Prop $counts 'Medium')
    low           = [int](Get-Prop $counts 'Low')
    rulesFile     = Split-Path -Leaf $RulesPath
}

$model = [pscustomobject]@{
    meta      = $meta
    findings  = $findings
    passed    = $passed
    metrics   = $metricRows
    processes = $processes
    captures  = $captures
}

#endregion

#region render --------------------------------------------------------------

$payload = $model | ConvertTo-Json -Depth 12 -Compress
# Keep the JSON from terminating the script element early on any embedded markup.
$payload = $payload.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')

$template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EndpointHealth Report</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#15181d; --muted:#5d6570; --line:#dfe3e8;
  --accent:#2f6fd0; --chip:#eef1f5;
  --crit:#b3261e; --high:#c2570b; --med:#8a6a00; --low:#3a6ea5; --ok:#1f7a4d;
  --critbg:#fdeceb; --highbg:#fdf0e5; --medbg:#fbf5e0; --lowbg:#ecf2f9; --okbg:#e9f5ef;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0f1216; --panel:#171b21; --ink:#e7eaee; --muted:#98a1ad; --line:#2a313a;
    --accent:#6fa3f0; --chip:#222932;
    --crit:#ff8a80; --high:#ffb05c; --med:#e8cf72; --low:#8fbcf0; --ok:#6fd39b;
    --critbg:#2a1614; --highbg:#2a1f12; --medbg:#26220f; --lowbg:#151f2b; --okbg:#122219;
  }
}
:root[data-theme="dark"]{
  --bg:#0f1216; --panel:#171b21; --ink:#e7eaee; --muted:#98a1ad; --line:#2a313a;
  --accent:#6fa3f0; --chip:#222932;
  --crit:#ff8a80; --high:#ffb05c; --med:#e8cf72; --low:#8fbcf0; --ok:#6fd39b;
  --critbg:#2a1614; --highbg:#2a1f12; --medbg:#26220f; --lowbg:#151f2b; --okbg:#122219;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 80px}
header.top{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;justify-content:space-between;margin-bottom:8px}
h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
h2{font-size:15px;margin:0 0 12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.tile{background:var(--chip);border-radius:8px;padding:10px 12px}
.tile .n{font-size:22px;font-weight:650;line-height:1.1}
.tile .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.tile.crit .n{color:var(--crit)} .tile.high .n{color:var(--high)}
.tile.med .n{color:var(--med)} .tile.low .n{color:var(--low)} .tile.ok .n{color:var(--ok)}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:6px 20px;font-size:13px}
.kv div span{color:var(--muted)}
details.how{border:1px solid var(--line);border-radius:10px;background:var(--panel);padding:0;margin:16px 0}
details.how>summary{cursor:pointer;padding:14px 16px;font-weight:600;list-style:none;display:flex;gap:8px;align-items:center}
details.how>summary::-webkit-details-marker{display:none}
details.how>summary::before{content:"▸";color:var(--muted)}
details.how[open]>summary::before{content:"▾"}
details.how .body{padding:0 16px 16px}
ol.chain{margin:0;padding-left:20px}
ol.chain li{margin-bottom:10px}
code{background:var(--chip);padding:1px 5px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
input[type=search]{
  flex:1;min-width:200px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;
  background:var(--panel);color:var(--ink);font:inherit;font-size:14px;
}
button.btn{
  padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);
  color:var(--ink);font:inherit;font-size:13px;cursor:pointer;
}
button.btn:hover{border-color:var(--accent);color:var(--accent)}
.finding{border:1px solid var(--line);border-radius:10px;margin-bottom:12px;overflow:hidden;background:var(--panel)}
.finding>summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
.finding>summary::-webkit-details-marker{display:none}
.finding .ttl{font-weight:600;flex:1;min-width:200px}
.chip{font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:3px 8px;border-radius:999px;white-space:nowrap}
.chip.Critical{background:var(--critbg);color:var(--crit)}
.chip.High{background:var(--highbg);color:var(--high)}
.chip.Medium{background:var(--medbg);color:var(--med)}
.chip.Low{background:var(--lowbg);color:var(--low)}
.chip.pass{background:var(--okbg);color:var(--ok)}
.meta-chip{font-size:11.5px;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.finding .body{padding:0 14px 14px;border-top:1px solid var(--line);margin-top:0}
.blk{margin-top:14px}
.blk h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:6px 8px;border-bottom:1px solid var(--line);font-weight:600}
td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
td.mono,th.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.val{font-weight:650}
.met{color:var(--crit);font-weight:700}
.notmet{color:var(--muted)}
.src{color:var(--muted);font-size:12px}
p.prose{margin:0;max-width:78ch}
.empty{color:var(--muted);font-size:14px;padding:8px 0}
.foot{color:var(--muted);font-size:12px;margin-top:28px;text-align:center}
@media (max-width:640px){
  .wrap{padding:16px 16px 60px}
  table{font-size:12.5px}
}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div>
    <h1 id="hdr-host">EndpointHealth report</h1>
    <div class="sub" id="hdr-sub"></div>
  </div>
  <button class="btn" id="theme">Toggle theme</button>
</header>

<section class="panel">
  <h2>Result</h2>
  <div class="tiles" id="tiles"></div>
  <div class="kv" id="kv" style="margin-top:14px"></div>
</section>

<details class="how">
  <summary>How this report decides what is wrong</summary>
  <div class="body">
    <p class="prose" style="margin-bottom:12px">
      Nothing here is inferred, guessed or looked up online. Every finding is a
      fixed threshold comparison written by hand in the rules file, and the
      wording under "Why it matters" and "What to do" is static text stored in
      that same file. The chain runs in one direction:
    </p>
    <ol class="chain">
      <li><strong>Collect.</strong> <code>Invoke-HealthSnapshot.ps1</code> writes raw facts into
          <code>snapshot/*.json</code>. <code>Invoke-TelemetrySample.ps1</code> appends counter rows to
          <code>telemetry/samples.csv</code> and <code>telemetry/processes.csv</code>.</li>
      <li><strong>Flatten.</strong> <code>Invoke-TelemetryAnalysis.ps1</code> reduces all of that to one flat
          namespace of named numbers in <code>metrics.json</code>, for example
          <code>disk.readLatencyMs.p95</code>. Percentiles are computed here, not collected.</li>
      <li><strong>Compare.</strong> Each rule lists conditions. Every condition must be true for the rule to
          fire. A metric that was never collected makes its condition false, so a missing collector can
          never invent a finding.</li>
      <li><strong>Report.</strong> Rules that fired become findings, carrying their own canned explanation
          and recommendation. Everything else is listed below under checks that passed.</li>
    </ol>
    <p class="prose" style="margin-top:12px">
      Every number below shows the file it came from, so any finding can be traced back to raw
      collector output sitting in this same run folder.
    </p>
  </div>
</details>

<section class="panel">
  <h2>Findings</h2>
  <div class="controls">
    <input type="search" id="q" placeholder="Filter findings by title, id, category or metric">
    <button class="btn" id="expandAll">Expand all</button>
    <button class="btn" id="collapseAll">Collapse all</button>
  </div>
  <div id="findings"></div>
</section>

<section class="panel">
  <h2>Checks that passed</h2>
  <p class="sub" style="margin-bottom:12px">
    Rules that were evaluated and did not fire. The condition that was not met is marked, so you can
    see how close the machine came to a finding.
  </p>
  <div id="passed"></div>
</section>

<section class="panel">
  <h2>Top processes</h2>
  <div id="processes"></div>
</section>

<section class="panel">
  <h2>Deep captures</h2>
  <div id="captures"></div>
</section>

<section class="panel">
  <h2>Every metric this run produced</h2>
  <div class="controls">
    <input type="search" id="mq" placeholder="Filter metrics by name, value or source file">
  </div>
  <div id="metrics"></div>
</section>

<div class="foot" id="foot"></div>

</div>

<script type="application/json" id="eh-data">__EH_PAYLOAD__</script>
<script>
(function(){
  "use strict";

  var raw = document.getElementById('eh-data').textContent;
  var D = JSON.parse(raw);
  var M = D.meta;

  function esc(s){
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }
  function arr(a){ return Array.isArray(a) ? a : (a ? [a] : []); }

  document.getElementById('hdr-host').textContent =
    (M.computerName || 'EndpointHealth') + ' health report';

  var subBits = [];
  if (M.model) subBits.push(esc(M.model));
  if (M.os) subBits.push(esc(M.os) + (M.osBuild ? ' (build ' + esc(M.osBuild) + ')' : ''));
  subBits.push('run ' + esc(M.runName));
  subBits.push('generated ' + esc(M.generated));
  document.getElementById('hdr-sub').innerHTML = subBits.join(' &middot; ');

  var tiles = [
    { n: M.critical, l: 'Critical', c: 'crit' },
    { n: M.high,     l: 'High',     c: 'high' },
    { n: M.medium,   l: 'Medium',   c: 'med'  },
    { n: M.low,      l: 'Low',      c: 'low'  },
    { n: (M.rulesTotal - M.findingCount), l: 'Passed', c: 'ok' }
  ];
  document.getElementById('tiles').innerHTML = tiles.map(function(t){
    return '<div class="tile ' + t.c + '"><div class="n">' + esc(t.n || 0) +
           '</div><div class="l">' + esc(t.l) + '</div></div>';
  }).join('');

  var kv = [];
  function addKv(label, value){ if (value) kv.push('<div><span>' + esc(label) + ':</span> ' + esc(value) + '</div>'); }
  addKv('Serial', M.serial);
  addKv('Uptime (days)', M.uptimeDays);
  addKv('Telemetry samples', M.sampleCount);
  if (M.firstSample && M.lastSample) addKv('Sampled window', M.firstSample + ' to ' + M.lastSample);
  addKv('Deep captures', M.captureCount);
  addKv('Rules evaluated', M.rulesTotal);
  document.getElementById('kv').innerHTML = kv.join('');

  function condTable(conds, showResult){
    if (!conds || !conds.length) return '';
    var rows = conds.map(function(c){
      var obs = c.collected ? esc(c.observed) : '<span class="notmet">(not collected)</span>';
      var cls = c.met ? 'met' : 'notmet';
      var mark = c.met ? 'met' : 'not met';
      return '<tr>' +
        '<td class="mono">' + esc(c.metric) + '</td>' +
        '<td class="val">' + obs + '</td>' +
        '<td>' + esc(c.opWord) + ' <span class="val">' + esc(c.value) + '</span></td>' +
        (showResult ? '<td class="' + cls + '">' + mark + '</td>' : '') +
        '<td class="src">' + esc(c.source) + '</td>' +
      '</tr>';
    }).join('');
    return '<table><thead><tr><th class="mono">metric</th><th>observed</th><th>rule requires</th>' +
           (showResult ? '<th>result</th>' : '') + '<th>read from</th></tr></thead><tbody>' +
           rows + '</tbody></table>';
  }

  function evidenceTable(ev){
    if (!ev || !ev.length) return '';
    var rows = ev.map(function(e){
      return '<tr><td class="mono">' + esc(e.metric) + '</td><td class="val">' + esc(e.value) +
             '</td><td class="src">' + esc(e.source) + '</td></tr>';
    }).join('');
    return '<table><thead><tr><th class="mono">metric</th><th>value</th><th>read from</th></tr></thead><tbody>' +
           rows + '</tbody></table>';
  }

  function findingHtml(f){
    var hay = [f.id, f.title, f.category, f.severity].concat(
      arr(f.conditions).map(function(c){ return c.metric; })).join(' ').toLowerCase();
    return '<details class="finding" data-hay="' + esc(hay) + '">' +
      '<summary>' +
        '<span class="chip ' + esc(f.severity) + '">' + esc(f.severity) + '</span>' +
        '<span class="ttl">' + esc(f.title) + '</span>' +
        '<span class="meta-chip">' + esc(f.id) + ' / ' + esc(f.category) + '</span>' +
      '</summary>' +
      '<div class="body">' +
        '<div class="blk"><h3>Why this fired</h3>' + condTable(f.conditions, false) + '</div>' +
        (f.explanation ? '<div class="blk"><h3>Why it matters</h3><p class="prose">' + esc(f.explanation) + '</p></div>' : '') +
        (f.recommendation ? '<div class="blk"><h3>What to do</h3><p class="prose">' + esc(f.recommendation) + '</p></div>' : '') +
        (f.evidence && f.evidence.length ? '<div class="blk"><h3>Supporting data</h3>' + evidenceTable(f.evidence) + '</div>' : '') +
      '</div>' +
    '</details>';
  }

  var findingsEl = document.getElementById('findings');
  if (!D.findings || !D.findings.length) {
    findingsEl.innerHTML = '<div class="empty">No rules fired. That is not the same as "nothing is wrong": ' +
      'check the metrics below against what the user actually reported, and consider lowering the trigger ' +
      'thresholds so a deep capture fires during the event they notice.</div>';
  } else {
    findingsEl.innerHTML = D.findings.map(findingHtml).join('');
  }

  document.getElementById('passed').innerHTML = (D.passed && D.passed.length)
    ? D.passed.map(function(p){
        return '<details class="finding">' +
          '<summary>' +
            '<span class="chip pass">pass</span>' +
            '<span class="ttl">' + esc(p.title) + '</span>' +
            '<span class="meta-chip">' + esc(p.id) + ' / ' + esc(p.category) + '</span>' +
          '</summary>' +
          '<div class="body"><div class="blk"><h3>What was checked</h3>' +
            condTable(p.conditions, true) + '</div></div>' +
        '</details>';
      }).join('')
    : '<div class="empty">No rules to show.</div>';

  document.getElementById('processes').innerHTML = (D.processes && D.processes.length)
    ? '<table><thead><tr><th>process</th><th>cpu % p95</th><th>io MB/s p95</th>' +
      '<th>private WS max MB</th><th>handles max</th></tr></thead><tbody>' +
      D.processes.slice(0, 20).map(function(p){
        return '<tr><td class="mono">' + esc(p.name) + '</td><td>' + esc(p.cpuP95) + '</td><td>' +
               esc(p.ioMBs) + '</td><td>' + esc(p.wspMaxMB) + '</td><td>' + esc(p.handlesMax) + '</td></tr>';
      }).join('') + '</tbody></table>'
    : '<div class="empty">No per-process telemetry in this run. Snapshot-only runs do not sample processes.</div>';

  document.getElementById('captures').innerHTML = (D.captures && D.captures.length)
    ? '<table><thead><tr><th>capture</th><th>fired by</th><th>engine</th><th>seconds</th><th>MB</th><th>files</th></tr></thead><tbody>' +
      D.captures.map(function(c){
        var notes = c.notes && c.notes.length ? '<div class="src">notes: ' + esc(c.notes.join('; ')) + '</div>' : '';
        return '<tr><td class="mono">' + esc(c.id) + '</td><td>' + esc(c.reason) + notes + '</td><td>' +
               esc(c.engine) + '</td><td>' + esc(c.seconds) + '</td><td>' + esc(c.sizeMB) + '</td>' +
               '<td class="src">' + esc((c.files || []).join(', ')) + '</td></tr>';
      }).join('') + '</tbody></table>'
    : '<div class="empty">No deep captures. Nothing held a trigger threshold long enough during this run.</div>';

  var metricsEl = document.getElementById('metrics');
  function renderMetrics(filter){
    var f = (filter || '').toLowerCase();
    var rows = D.metrics.filter(function(m){
      if (!f) return true;
      return (m.name + ' ' + m.value + ' ' + m.source).toLowerCase().indexOf(f) !== -1;
    });
    if (!rows.length) { metricsEl.innerHTML = '<div class="empty">No metrics match that filter.</div>'; return; }
    metricsEl.innerHTML = '<table><thead><tr><th class="mono">metric</th><th>value</th><th>read from</th></tr></thead><tbody>' +
      rows.map(function(m){
        return '<tr><td class="mono">' + esc(m.name) + '</td><td class="val">' + esc(m.value) +
               '</td><td class="src">' + esc(m.source) + '</td></tr>';
      }).join('') + '</tbody></table>';
  }
  renderMetrics('');
  document.getElementById('mq').addEventListener('input', function(e){ renderMetrics(e.target.value); });

  document.getElementById('q').addEventListener('input', function(e){
    var f = e.target.value.toLowerCase();
    var items = findingsEl.querySelectorAll('.finding');
    for (var i = 0; i < items.length; i++) {
      var hay = items[i].getAttribute('data-hay') || '';
      items[i].style.display = (!f || hay.indexOf(f) !== -1) ? '' : 'none';
    }
  });
  document.getElementById('expandAll').addEventListener('click', function(){
    findingsEl.querySelectorAll('.finding').forEach(function(d){ d.open = true; });
  });
  document.getElementById('collapseAll').addEventListener('click', function(){
    findingsEl.querySelectorAll('.finding').forEach(function(d){ d.open = false; });
  });

  document.getElementById('theme').addEventListener('click', function(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : (cur === 'light' ? 'dark' :
      (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'light' : 'dark'));
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('eh-theme', next); } catch (err) {}
  });
  try {
    var saved = localStorage.getItem('eh-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  } catch (err) {}

  document.getElementById('foot').textContent =
    'Rules: ' + M.rulesFile + '. ' + M.rulesTotal + ' evaluated, ' + M.findingCount +
    ' fired. Raw data for every number above is in this run folder.';
})();
</script>
</body>
</html>
'@

$html = $template.Replace('__EH_PAYLOAD__', $payload)

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8

Write-Verbose ("Report written to {0}" -f $OutputPath)

#endregion

if ($PassThru) {
    [pscustomobject]@{
        RunPath      = $RunPath
        OutputPath   = $OutputPath
        FindingCount = $findings.Count
        PassedCount  = $passed.Count
        MetricCount  = $metricRows.Count
    }
}
