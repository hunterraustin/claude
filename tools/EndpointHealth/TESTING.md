# EndpointHealth: test plan

Every phase below has an explicit pass condition. If a phase does not pass, stop
there. Do not continue to the next phase hoping it sorts itself out, and do not
run any of this against a clinical machine until Phase 7 has passed on a lab
machine.

## What has and has not been verified

Be clear about this before you start, because it determines how much you trust
each phase.

**Verified, by execution:**

- All ten `.ps1` and `.psm1` files parse with zero errors.
- `rules/correlation-rules.json` and `config.sample.json` are valid JSON.
- `New-HealthReport.ps1` builds a report from a run folder. Tested against a
  synthetic run, with the findings produced by evaluating the real rules file.
  All 138 metrics resolved to a named source file.
- `Start-HealthConsole.ps1` serves every endpoint, and the UI renders with no
  JavaScript errors in light and dark themes.
- Console rejects, by test: a POST with no CSRF token, a POST with a wrong
  token, a POST from a foreign `Origin`, a shell-injection attempt in a computer
  name, a path traversal in a run name, and an unknown winget package id.
- Console config changes survive a restart.

**Not verified, and this is the important part:**

- **Nothing has run on Windows PowerShell 5.1.** All of the above was executed
  under PowerShell 7 on Linux. That is a different runtime. Phase 1 exists
  specifically to close this gap and must not be skipped.
- No collector has ever run against real Windows. Every `Get-CimInstance`,
  `Get-Counter`, `Get-WinEvent` and WPR call is unexercised.
- No campaign has completed. No scheduled task has been registered.
- No upload to a real SMB share has happened.
- Kerberos authentication has never been exercised. It cannot be, off a domain.
- No deep capture has ever run.

---

## Phase 0. Lab machine, not a clinical one

Requirements: a domain-joined Windows 10 or 11 workstation you can break, local
administrator on it, and Windows PowerShell 5.1.

```powershell
# Confirm the runtime. This must say 5.1.x
$PSVersionTable.PSVersion

# Confirm elevation. This must say True
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

**Pass:** version starts with 5.1, elevation is True.

If you only have PowerShell 7 open, close it. The sampler's scheduled task runs
under 5.1, so 5.1 is the runtime that has to work.

---

## Phase 1. Does it even parse under 5.1

This is the single most important phase, because it is the one thing known to be
untested.

```powershell
$dst = 'C:\Tools\EndpointHealth'
New-Item -ItemType Directory -Path $dst -Force | Out-Null
Invoke-WebRequest -UseBasicParsing 'https://github.com/hunterraustin/claude/archive/refs/heads/main.zip' -OutFile "$env:TEMP\eh.zip"
Expand-Archive "$env:TEMP\eh.zip" "$env:TEMP\eh" -Force
Copy-Item "$env:TEMP\eh\claude-main\tools\EndpointHealth\*" $dst -Recurse -Force
Get-ChildItem $dst -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process Bypass -Force
Set-Location $dst

Get-ChildItem -Include *.ps1,*.psm1 -Recurse | ForEach-Object {
  $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$e)
  '{0,-32} {1}' -f $_.Name, $(if ($e.Count) { "FAIL line $($e[0].Extent.StartLineNumber): $($e[0].Message)" } else { 'ok' })
}
```

**Pass:** ten files, all `ok`.

**If any file says FAIL:** stop. Send me the file name and line number. A parse
error under 5.1 that did not appear under 7 is exactly the class of bug this
phase exists to find.

Also confirm the module loads, which parsing alone does not prove:

```powershell
Import-Module .\EndpointHealth.psm1 -Force
Get-Command -Module EndpointHealth | Select-Object Name
```

**Pass:** 19 functions listed, no errors.

---

## Phase 2. Snapshot with no share at all

Isolates the collectors from anything network related.

```powershell
.\Invoke-HealthSnapshot.ps1 -Verbose
```

Takes one to three minutes. Expect warnings for things this machine does not
have, such as no battery on a desktop. Warnings are fine. Terminating errors are
not.

```powershell
$run = Get-ChildItem C:\ProgramData\EndpointHealth\runs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-ChildItem $run.FullName -Recurse | Select-Object FullName, Length
Get-Content (Join-Path $run.FullName 'snapshot\system.json') -Raw | ConvertFrom-Json | Format-List ComputerName, OsCaption, UptimeDays
```

**Pass:** a run folder exists, `snapshot\` holds nine or more `.json` files, none
of them zero bytes, and `system.json` shows this machine's real name and OS.

**Check for silently failed collectors:**

```powershell
Get-ChildItem (Join-Path $run.FullName 'snapshot') -Filter *.json | ForEach-Object {
  $j = Get-Content $_.FullName -Raw | ConvertFrom-Json
  if ($j.PSObject.Properties['CollectorError']) { "{0}: {1}" -f $_.Name, $j.CollectorError }
}
```

**Pass:** no output. Any output names a collector that failed and why. A couple
of failures is survivable, but note which ones, because their metrics will be
absent and rules depending on them will never fire.

---

## Phase 3. Analysis and report

```powershell
.\Invoke-TelemetryAnalysis.ps1 -RunName $run.Name
```

**Pass:** `SUMMARY.txt` prints to screen, and the run folder now contains
`metrics.json`, `findings.json`, `SUMMARY.txt` and `REPORT.html`.

```powershell
# How many metrics did a snapshot-only run produce?
((Get-Content (Join-Path $run.FullName 'metrics.json') -Raw | ConvertFrom-Json).PSObject.Properties | Measure-Object).Count

# Open the report
Start-Process (Join-Path $run.FullName 'REPORT.html')
```

**Pass:** the report opens, the header shows this machine's name, findings are
expandable, and every metric row shows a source file rather than `unknown`.

A snapshot-only run has no telemetry, so expect roughly 60 to 90 metrics rather
than the 138 a full campaign produces, and expect the top processes section to
say there is no per-process telemetry. That is correct behaviour, not a fault.

**If you see `unknown` in the "read from" column:** the provenance table in
`New-HealthReport.ps1` is missing a prefix. Tell me which metric.

---

## Phase 4. The share

Do Part 1 of RUNBOOK.md on the file server first, including the machine-account
write test. Do not skip that test. Then from the lab machine:

```powershell
Test-Path \\FS01\EndpointHealth$
# Prove YOUR account can write
'probe' | Set-Content \\FS01\EndpointHealth$\probe.txt
Remove-Item \\FS01\EndpointHealth$\probe.txt
```

**Pass:** both succeed.

That only proves your account works. The sampler runs as SYSTEM, which reaches
the network as the machine account. That is a different thing entirely, and it
is the most common single point of failure in the whole toolkit:

```powershell
schtasks /create /tn EHWriteTest /ru SYSTEM /sc once /st 23:59 /f /tr "cmd /c echo test > \\FS01\EndpointHealth$\machinetest.txt"
schtasks /run /tn EHWriteTest
Start-Sleep -Seconds 10
Test-Path \\FS01\EndpointHealth$\machinetest.txt
schtasks /delete /tn EHWriteTest /f
Remove-Item \\FS01\EndpointHealth$\machinetest.txt -ErrorAction SilentlyContinue
```

**Pass:** `Test-Path` returns True.

**If False:** every campaign will collect perfectly and upload nothing. Fix the
share rights before continuing. Nothing later in this plan will work.

Now a snapshot that uploads:

```powershell
.\Deploy-EndpointHealth.ps1 -Mode Snapshot -SharePath \\FS01\EndpointHealth$
```

**Pass:** output shows `Uploaded : True`, and the run folder exists on the share
with `REPORT.html` inside it.

---

## Phase 5. One deep capture, on purpose

Do not wait for a trigger to fire on its own. Force one, so you learn whether
WPR works on your build before a campaign depends on it.

```powershell
.\Invoke-DeepCapture.ps1 -Reason 'test' -DurationSeconds 30 -Engine WPR -RunName $run.Name
```

Takes about 30 seconds plus WPR's stop time, which can be another 30 to 60
seconds. Be patient before deciding it hung.

**Pass:** a folder under `captures\` containing `capture.json`, `burst-1s.csv`,
`processes.json`, `connections.json`, and `trace.zip`.

```powershell
Get-Content (Join-Path $run.FullName 'captures\*\capture.json') -Raw | ConvertFrom-Json | Format-List
```

**Pass:** `StoppedEarly` is False and `Notes` is empty.

**If Notes says WPR was skipped because another recording session is active:**
something else on the box is tracing. That is the guard working correctly.
`wpr -cancel` clears it if the other session is genuinely stale.

**If `trace.zip` is missing but `capture.json` exists:** WPR started but produced
no ETL. Check the agent log in `logs\agent.log`.

---

## Phase 6. A short campaign

Do not start with seven days. Prove the mechanism with one.

```powershell
.\Deploy-EndpointHealth.ps1 -Mode Campaign -Days 1 -SharePath \\FS01\EndpointHealth$ -SampleIntervalMinutes 2
```

**Pass immediately after:**

```powershell
Get-ScheduledTask -TaskPath '\EndpointHealth\' | Format-List TaskName, State
Get-Content C:\ProgramData\EndpointHealth\campaign-state.json -Raw | ConvertFrom-Json | Format-List RunName, EndUtc, RunAsUser
```

Task exists and is Ready or Running. State file shows an `EndUtc` one day out.

**Pass after ten minutes** (at a two minute interval, expect four or five rows):

```powershell
$run2 = Get-ChildItem C:\ProgramData\EndpointHealth\runs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
(Import-Csv (Join-Path $run2.FullName 'telemetry\samples.csv')).Count
Import-Csv (Join-Path $run2.FullName 'telemetry\samples.csv') | Select-Object -Last 1 | Format-List
```

Row count is climbing, and the last row has real numbers in `cpu_total_pct`,
`mem_available_mb` and `disk_read_latency_ms` rather than blanks.

**If columns are blank:** performance counter names did not resolve. Check
`logs\agent.log` for counter warnings. This is the most likely place for a
non-English Windows build to break.

**Reboot the machine.** Wait five minutes, then confirm sampling resumed:

```powershell
(Import-Csv (Join-Path $run2.FullName 'telemetry\samples.csv')).Count
```

**Pass:** count increased after the reboot. That proves the campaign survives
restarts, which is the entire point of the scheduled task design.

**Pass after an hour:** the run folder appears on the share and contains a
current `SUMMARY.txt` and `REPORT.html`.

Then end it early and confirm teardown:

```powershell
.\Deploy-EndpointHealth.ps1 -Mode Stop
Get-ScheduledTask -TaskPath '\EndpointHealth\' -ErrorAction SilentlyContinue
Test-Path C:\ProgramData\EndpointHealth\campaign-state.json
```

**Pass:** no scheduled task, state file gone, data still on the share.

---

## Phase 7. Console, loopback only

No certificate, no firewall, no AD group. Just prove the thing runs.

```powershell
.\Start-HealthConsole.ps1 -Local
```

A browser should open at `http://127.0.0.1:8080/`.

**Pass:** the page loads, the Run tab shows readiness checks, and the banner is
green or amber rather than red.

Work through every tab:

- **Run:** share shows reachable and writable. Start a Snapshot on this machine.
  The Activity tab should show it, and it should reach `Completed`.
- **Reports:** the drop-down lists your runs. Open one. The report opens in a
  new tab.
- **Setup:** change the campaign days to 5, save, restart the console, and
  confirm it is still 5. This exact path was broken and fixed, so it is worth
  re-proving on your machine.
- **Endpoint Central:** arguments are generated with your real share path.
- **Activity:** a failed job shows a reason, not a blank box.

**Pass:** all five behave as described.

---

## Phase 8. Console on the network

Only after Phase 7 passes. Follow RUNBOOK.md Part 2b, then two things that are
easy to miss and will otherwise cost you an afternoon:

**Register the SPN.** If the console runs as a domain service account rather
than the machine account, Kerberos needs an SPN pointing at that account.
Without it, Negotiate quietly falls back to NTLM, or fails outright if Extended
Protection is enforced:

```powershell
setspn -S HTTP/ehconsole.corp.local CORP\svc-endpointhealth
setspn -L CORP\svc-endpointhealth
```

**Pass:** the HTTP SPN is listed against the service account and nowhere else.
A duplicate SPN on two accounts breaks Kerberos for both.

**Put the console in the Local Intranet zone.** Browsers only send Windows
credentials silently to sites they consider intranet. Without this your techs
get a credential prompt, which defeats the entire no-password design. Push it by
GPO, or test it manually first in Internet Options, Security, Local intranet,
Sites, Advanced.

Then:

```powershell
.\Start-HealthConsole.ps1 -AllowedGroup 'CORP\FCCI-EndpointHealth-Admins'
```

From a different machine, browse to `https://ehconsole.corp.local:8443/`.

**Pass, all four:**

1. No certificate warning. A warning means the cert name does not match the URL,
   or the issuing CA is not trusted by the client.
2. No credential prompt. A prompt means the intranet zone step was missed.
3. The page header shows your own account name.
4. Sign in as an account outside the AD group. It must show a 403 and refuse.

Item 4 is the one people skip. Do not skip it. An authorisation control you have
never seen deny anyone is not a control.

---

## Phase 9. Remote target

```powershell
.\Deploy-EndpointHealth.ps1 -ComputerName WKS-LAB02 -Mode Snapshot -SharePath \\FS01\EndpointHealth$
```

**Pass:** it completes and the data reaches the share.

Expect `Uploaded : False` followed by a relay message. That is normal and
documented: your credential does not survive the second hop from the target to
the file server, so the script pulls the data back through the session and
pushes it to the share from your machine.

**Pass:** the run folder is on the share regardless of which path it took.

Then a remote campaign, which does not have the second-hop problem because the
scheduled task uploads under the machine account:

```powershell
.\Deploy-EndpointHealth.ps1 -ComputerName WKS-LAB02 -Mode Campaign -Days 1 -SharePath \\FS01\EndpointHealth$
.\Deploy-EndpointHealth.ps1 -ComputerName WKS-LAB02 -Mode Status
```

**Pass:** Status shows `CampaignActive: True` and a `TaskState` of Ready or
Running.

---

## Phase 10. Endpoint Central, one machine

Use the Endpoint Central tab to generate the arguments. Deploy to exactly one
lab machine first, with Frequency set to **Once**.

**Pass:** within a few minutes the agent directory exists on the target, and
within an hour the run folder appears on the share.

**If nothing appears:** check the configuration's Execution Status first, then
`C:\ProgramData\EndpointHealth\campaign.log` on the target. Between them they
say plainly what failed.

---

## Cleanup

```powershell
.\Deploy-EndpointHealth.ps1 -Mode Stop -RemoveAgent
Get-ScheduledTask -TaskPath '\EndpointHealth\' -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\EndpointHealth -Recurse -Force -ErrorAction SilentlyContinue
```

For the console host, if you are decommissioning it:

```powershell
netsh http delete sslcert ipport=0.0.0.0:8443
netsh http delete urlacl url=https://+:8443/
Remove-NetFirewallRule -DisplayName "EndpointHealth console"
setspn -D HTTP/ehconsole.corp.local CORP\svc-endpointhealth
```

Data on the share is never touched by any of this. Delete run folders on a
schedule, because traces contain file paths and command lines from clinical
machines.

---

## What to report back

For any failure, the useful three things are:

1. Which phase, and the exact command.
2. The full error, not a paraphrase.
3. The relevant log: `logs\agent.log` or `logs\snapshot.log` inside the run
   folder, `C:\ProgramData\EndpointHealth\campaign.log` for campaign problems,
   or `C:\ProgramData\EndpointHealth\console.log` for console problems.
