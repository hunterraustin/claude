# EndpointHealth

For setup and step-by-step operation, see [RUNBOOK.md](RUNBOOK.md).

Point it at a Windows machine on the domain. It runs a bounded diagnostic
campaign that survives reboots, drops everything into
`\\share\COMPUTERNAME_9-17_1059`, and hands back a ranked list of findings
instead of a pile of raw logs.

Windows PowerShell 5.1. No modules to install, no agent to license, nothing
required beyond what ships with Windows.

---

## Read this before you deploy it

The original ask was "run Procmon for 7 days and ship the data to a share."
That does not work, and the reason matters for how this tool is built.

Process Monitor writes roughly **1 to 5 GB per hour** on a normal workstation.
Seven days is multiple terabytes per machine. Worse, Procmon's filter driver
sits in the path of every file, registry and process operation, so a week-long
capture measurably slows down the machine you are trying to measure. You would
be recording a performance problem you partly caused, in a file nobody can
open.

What this tool does instead:

| Layer | Runs | Cost | What it gives you |
|---|---|---|---|
| Baseline snapshot | Once at start | ~2 min, a few MB | Hardware, SMART, firmware, event log triage, boot timings |
| Telemetry sampler | Every 5 min for the whole campaign | ~1 sec, a few KB | Continuous CPU, memory, disk latency, per-process load |
| Deep capture | Only when a threshold holds | 2 min, capped at 512 MB | WPR trace or Procmon log **from the moment it was actually broken** |
| Analysis | Hourly and at the end | Seconds | `SUMMARY.txt` ranked by severity |

A week of sampling is a few MB. The expensive tracing happens in the two
minute window where something is genuinely wrong, which is the only window
where it was ever going to be useful.

**This already exists, partly.** Before building on this, know what you would
be reinventing:

- **Microsoft TSS** (TroubleShootingScript toolset) — Microsoft's own successor
  to SDP. Closest first-party equivalent to the snapshot half of this.
- **Velociraptor** — free, agent-based, survives reboots, central collection,
  artifact-driven. If you want fleet-wide, use this.
- **windows_exporter + Prometheus + Grafana**, or **Netdata** — free continuous
  telemetry at per-second resolution with real dashboards.
- **Nexthink, Lakeside SysTrack, ControlUp Edge DX, Aternity, 1E** — the
  commercial digital experience monitoring segment. This is their whole product.
- **Intune Endpoint Analytics** — if the fleet is already licensed for it.

What none of them do cleanly is the narrow thing here: a single technician
pointing at one machine, getting a bounded campaign with a fixed end date, and
getting back a plain-text file that says what is wrong and what to do about it.
That is the gap this fills.

---

## Deploying from ManageEngine Endpoint Central

Endpoint Central runs scripts on the agent as SYSTEM, which is exactly what
this needs. No remoting involved.

1. Zip the `EndpointHealth` folder and upload it to **Admin → Script
   Repository** as a script template, or drop the folder on a share the agents
   can read.
2. Create a **Computer Configuration → Custom Script**:
   - Script: `Deploy-EndpointHealth.ps1`
   - Arguments: `-Mode Campaign -Days 7 -SharePath \\fs01\EndpointHealth$`
   - Run as: **System**
3. Target the machines under investigation.

The agent installs itself to `C:\ProgramData\EndpointHealth\agent` on first
run, so the campaign keeps going after Endpoint Central cleans up its temp
directory. It removes its own scheduled task when the campaign expires. You do
not need a second configuration to tear it down, though `-Mode Stop` is there
if you want to end one early.

For a one-off triage across a group of machines, use `-Mode Snapshot` instead.
It finishes in a couple of minutes and uploads immediately.

### Remote targeting without ManageEngine

`-ComputerName` uses PowerShell remoting. The toolkit is copied to the target's
ProgramData and executed there, because a campaign must outlive the session.

One caveat: a **snapshot** run over remoting cannot usually write to the file
server, because your credential does not survive the second hop. The script
detects this and relays the data back through the session and on to the share
from your workstation. Campaigns are unaffected, since their uploads come from
the scheduled task on the target, not from your session.

---

## What lands on the share

```
\\fs01\EndpointHealth$\WKS042_9-17_1059\
├── REPORT.html              <- open this first, findings with their evidence
├── SUMMARY.txt              <- same findings as plain text
├── findings.json            <- same findings, machine readable
├── metrics.json             <- every metric the run produced
├── manifest.json
├── campaign.json            <- campaign mode only
├── snapshot\
│   ├── system.json          identity, OS, firmware, uptime
│   ├── hardware.json        CPU, DIMMs, GPU, thermals, battery, dead devices
│   ├── storage.json         SMART, wear, volumes, BitLocker, TRIM, pagefile
│   ├── events.json          triaged event log counts and samples
│   ├── reliability.json     boot timings, stability index
│   ├── network.json         adapters, errors, DNS, SMB client
│   ├── security.json        Defender state, registered AV products
│   ├── software.json        installed, startup items, services, pending reboot
│   ├── smartctl.json        if smartctl.exe was provided
│   └── dxdiag.txt
├── telemetry\
│   ├── samples.csv          one row per sample, whole campaign
│   └── processes.csv        per-process CPU, working set, IO
├── captures\
│   └── 20260917-142233\
│       ├── capture.json     what fired it, how long, how big
│       ├── burst-1s.csv     one-second counters for the capture window
│       ├── processes.json   full process table with command lines
│       ├── connections.json TCP connections at the time
│       ├── trace.zip        WPR ETL, opens in Windows Performance Analyzer
│       └── procmon.zip      if the Procmon engine was used
└── logs\
    └── agent.log
```

`SUMMARY.txt` is plain text, wrapped to 78 columns, and readable in Notepad on
a share where nobody has word wrap turned on.

---

## How findings work

`Invoke-TelemetryAnalysis.ps1` flattens the snapshot and the telemetry into one
metric namespace, then evaluates `rules\correlation-rules.json` against it.
Roughly 40 rules ship, covering:

- Hardware faults: WHEA machine checks, SMART failure prediction, SSD wear,
  uncorrected read/write errors, dead devices, battery collapse
- Storage: sustained read/write latency, IO retries and controller resets, NTFS
  corruption, low free space, TRIM disabled
- Memory: physical exhaustion with hard faults, commit limit pressure,
  non-paged pool leaks
- CPU: sustained load, kernel time, interrupt storms, processor queue depth,
  frequency throttling
- Security contention: two real-time AV products fighting, Defender scanning
  high-churn paths, real-time protection off
- Platform: boot degradation, unexpected shutdowns, bugchecks, GPU driver TDRs,
  Group Policy and Netlogon failures, SMB session drops, service start failures
- Configuration: pending reboot, long uptime, stale firmware, startup bloat

Each finding carries what was observed, why it matters, what to do about it,
and the supporting metrics.

### Adding a rule

Rules are data. No code changes.

```powershell
# Print the exact metric names available for a given run
.\Invoke-TelemetryAnalysis.ps1 -RunName WKS042_9-17_1059 -ListMetrics
```

Then add an object to `rules\correlation-rules.json`:

```json
{
  "id": "LOCAL-001",
  "title": "EHR client is pegging a core",
  "category": "Performance",
  "severity": "High",
  "all": [
    { "metric": "proc.ehrclient.cpu.p95", "op": "gt", "value": 20 },
    { "metric": "disk.readLatencyMs.p95", "op": "gt", "value": 15 }
  ],
  "explanation": "What this pattern means in our environment.",
  "recommendation": "What the tech should actually do.",
  "evidence": ["proc.ehrclient.cpu.p95", "disk.readLatencyMs.p95"]
}
```

Every condition in `all` must be true for the rule to fire. Add an `unless`
array to suppress it. Operators: `gt`, `gte`, `lt`, `lte`, `eq`, `ne`,
`exists`, `notexists`, `contains`, `notcontains`, `matches`.

A missing metric makes a condition false, so a rule never fires because a
collector was unavailable.

---

## Tuning the triggers

The defaults are deliberately conservative: six captures a day maximum, one
hour cooldown, two consecutive breaches required.

**Getting no captures during the window the user complains about?** The
thresholds are too high or the sample interval is too coarse. Drop
`SampleIntervalMinutes` to 2 and lower `DiskReadLatencyMs` to 20.

**Getting six captures a day and none of them show the problem?** The
thresholds are catching normal load. Raise them, or raise
`ConsecutiveSamples` to 3 so a longer stall is required.

**Know roughly when it happens?** Run it by hand at the time:

```powershell
.\Invoke-DeepCapture.ps1 -Reason 'user reported freeze' -DurationSeconds 180 -Engine Both
```

---

## Optional binaries

Drop these in `ToolsPath` (`C:\ProgramData\EndpointHealth\bin` by default).
Neither is required and both are skipped silently when absent.

- **Procmon64.exe** (Sysinternals) — enables the Procmon capture engine. Export
  a filter config from the GUI with *Drop Filtered Events* enabled and point
  `DeepCapture.ProcmonConfig` at it. Without a filter, a two minute capture on a
  busy machine is several hundred MB.
- **smartctl.exe** (smartmontools) — per-attribute SMART, including reallocated
  sector counts that Windows will not surface through
  `Get-StorageReliabilityCounter`.

---

## Files

| File | Purpose |
|---|---|
| `Deploy-EndpointHealth.ps1` | Entry point. Local or remote, all modes. |
| `Start-HealthCampaign.ps1` | Installs the agent, registers the scheduled task. |
| `Stop-HealthCampaign.ps1` | Final analysis, upload, teardown. |
| `Invoke-HealthSnapshot.ps1` | The deep one-shot scan. |
| `Invoke-TelemetrySample.ps1` | One sampler iteration. Called by the task. |
| `Invoke-DeepCapture.ps1` | Trigger-fired WPR / Procmon burst. |
| `Invoke-TelemetryAnalysis.ps1` | Rules engine, writes SUMMARY.txt. |
| `New-HealthReport.ps1` | Builds REPORT.html, the traceable view of the findings. |
| `Start-HealthConsole.ps1` | Browser console. Kerberos auth, AD group gated. |
| `console\index.html` | The console UI. Served by the console, not opened directly. |
| `EndpointHealth.psm1` | Shared library. |
| `rules\correlation-rules.json` | The findings logic. Edit this, not the code. |
| `config.sample.json` | Copy to `config.json` and edit. |

---

## Design notes

Things that are the way they are on purpose:

- **Every collector is individually guarded.** A machine with no battery, a
  storage driver that does not expose reliability counters, or a disabled event
  log degrades that one section. It does not fail the run.
- **Performance counter paths are resolved through the registry index table**
  rather than hardcoded in English, so `\PhysicalDisk(_Total)\Avg. Disk sec/Read`
  works on a non-English Windows build.
- **`Win32_Product` is never queried.** Enumerating it triggers an MSI
  reconfiguration of every installed package, which is itself a multi-minute
  performance event. The registry uninstall keys are read instead.
- **Data stages locally first.** A dead network link never stalls a collection.
- **Captures are size-capped and checked every second,** so a runaway trace is
  stopped within a second of crossing the cap.
- **Defender exclusion paths are counted, not listed.** The count is what the
  rules need; the paths themselves are sensitive and do not belong on a share.
- **Missing metrics fail conditions closed.** A rule never fires because a
  collector was unavailable.

## Limitations

- Windows only, PowerShell 5.1 and later. Not tested on Server Core.
- Thermal readings come from ACPI thermal zones, which many vendors implement
  poorly. Treat `hw.thermalMaxC` as a prompt to measure properly with the
  vendor's own utility, not as a precise reading.
- `Get-StorageReliabilityCounter` returns nothing behind most hardware RAID
  controllers. Use `smartctl` there, or the controller's own tooling.
- The compact folder name (`HOST_9-17_1059`) does not sort correctly once you
  have runs from more than one month. Set `FolderNameStyle` to `Sortable` if
  that matters more than matching the requested format.
- A snapshot over PowerShell remoting relies on the relay-back path for share
  delivery. Kerberos delegation would avoid the extra hop, but enabling it is a
  larger decision than this tool should make for you.
