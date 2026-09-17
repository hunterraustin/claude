# EndpointHealth: runbook

For a technician who was handed a machine and told to find out what is wrong
with it, and for whoever sets this up the first time.

Two things have to exist before anyone can use this tool:

1. The collection share on the file server (Part 1). Done once, by IT
   infrastructure.
2. The toolkit on an admin workstation (Part 2). Done once per admin.

Everything after that is three commands.

**Fill these in before you copy anything below.**

| Placeholder | Yours |
|---|---|
| `FS01` | the file server hosting the share |
| `F:\IT\EndpointHealth` | the folder on that server |
| `\\FS01\EndpointHealth$` | the UNC path every command uses |

---

## Part 1. The share (file server, once)

Run this **on the file server**, in an elevated PowerShell, signed in with a
domain account. Not on your laptop. If you run it on a workstation, or leave
`DOMAIN` in as literal text, you get
`No mapping between account names and security IDs was done` and nothing is
created.

```powershell
# Run on the FILE SERVER, elevated, signed in with a domain account.
$Path      = 'F:\IT\EndpointHealth'
$Dom       = $env:USERDOMAIN
$ITGroup   = "$Dom\Domain Admins"
$Computers = "$Dom\Domain Computers"

New-Item -ItemType Directory -Path $Path -Force

icacls $Path /inheritance:r
icacls $Path /grant:r `
    'NT AUTHORITY\SYSTEM:(OI)(CI)F' `
    'BUILTIN\Administrators:(OI)(CI)F' `
    "${ITGroup}:(OI)(CI)M" `
    "${Computers}:(RD,AD,RA,X)" `
    'CREATOR OWNER:(OI)(CI)(IO)M'

New-SmbShare -Name 'EndpointHealth$' -Path $Path -FullAccess $ITGroup,'BUILTIN\Administrators' -ChangeAccess $Computers
Set-SmbShare -Name 'EndpointHealth$' -EncryptData $true -Force
```

Why the permissions look like that:

- The sampler runs as **SYSTEM**, which reaches the network as the computer
  account `DOMAIN\COMPUTERNAME$`, not as you. If computer accounts cannot
  write, a campaign collects perfectly and uploads nothing.
- The `Domain Computers` entry has no `(OI)(CI)`, so it applies to the top
  folder only: list it, create one run folder in it, nothing else. `CREATOR
  OWNER` then gives each machine rights to the folder it created. One
  workstation cannot read another workstation's data.
- `Domain Admins` is already inside the server's local Administrators, so that
  entry is belt and braces. Swap it for a helpdesk group if non-admin techs
  need to read summaries.
- Do not nest this inside an existing imaging or file share. Traces contain
  file paths and command lines from clinical machines, so this folder is PHI.
  Keep the SMB encryption on, keep read access to IT, and delete run folders on
  a schedule.

### Prove it works before you trust it

```powershell
# on the server
Get-SmbShareAccess EndpointHealth$
icacls F:\IT\EndpointHealth

# from a test workstation, elevated: proves the MACHINE account can write
schtasks /create /tn EHTest /ru SYSTEM /sc once /st 00:00 /f /tr 'cmd /c mkdir \\FS01\EndpointHealth$\TEST_9-17_1200'
schtasks /run /tn EHTest
timeout /t 10
schtasks /delete /tn EHTest /f
```

If `TEST_9-17_1200` appears on the share, every campaign will upload. If it
does not, stop here and fix it. Nothing else in this runbook will work.

---

## Part 2. The toolkit (admin workstation, once)

Put it on a **local** path. Not Documents, not Desktop: those are redirected to
H:, which makes the script's own root a network path and breaks the agent
install.

```powershell
# elevated PowerShell on your workstation
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dst = 'C:\Tools\EndpointHealth'
New-Item -ItemType Directory -Path $dst -Force | Out-Null
Invoke-WebRequest -UseBasicParsing 'https://github.com/hunterraustin/claude/archive/refs/heads/main.zip' -OutFile "$env:TEMP\eh.zip"
Expand-Archive "$env:TEMP\eh.zip" "$env:TEMP\eh" -Force
Copy-Item "$env:TEMP\eh\claude-main\tools\EndpointHealth\*" $dst -Recurse -Force
Get-ChildItem $dst -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem $dst -Recurse -File | Select-Object FullName
```

`Unblock-File` is not optional. Files that came out of a GitHub zip carry the
mark of the web and will not run until they are unblocked.

That last line should print 11 files, one of them ending in
`rules\correlation-rules.json`. **Keep the folder structure.** The scripts
resolve paths relative to themselves, and the analysis step looks for the
`rules` subfolder. Flatten it and every run fails.

Leave `config.sample.json` alone. Only `config.json` is read, and passing
`-SharePath` on the command line writes one to
`C:\ProgramData\EndpointHealth\config.json` for you.

### Syntax check after any edit

A parse error in one collector surfaces as a confusing error somewhere else
entirely, so check before you run:

```powershell
Get-ChildItem C:\Tools\EndpointHealth -Include *.ps1,*.psm1 -Recurse | ForEach-Object {
  $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$null,[ref]$e)
  '{0,-34} {1}' -f $_.Name, $(if($e.Count){"FAIL line $($e[0].Extent.StartLineNumber)"}else{'ok'})
}
```

All nine code files must say `ok`.

---

## Part 3. Pick one

| The complaint | Use | Takes |
|---|---|---|
| "It's slow." "It's been weird." You know nothing about the machine yet. | **Snapshot** | 3 minutes |
| "It freezes a couple of times a day." "It happens randomly." | **Campaign** | 7 days, hands off |

When in doubt, run Snapshot. It is safe, bounded, and often enough.

Run everything from **Windows PowerShell 5.1** (`powershell.exe`), not
PowerShell 7. The sampler's scheduled task runs under 5.1, so that is the
runtime that has to work. A clean run in 7 does not prove anything about the
campaign.

---

## Part 4. Run it

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass
Set-Location C:\Tools\EndpointHealth
```

### Snapshot

```powershell
# on the machine itself
.\Deploy-EndpointHealth.ps1 -Mode Snapshot -SharePath \\FS01\EndpointHealth$

# against another machine (needs PowerShell remoting enabled on the target)
.\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Snapshot -SharePath \\FS01\EndpointHealth$
```

It prints the run name, the share folder, and `Uploaded: True`. If it says
`Uploaded: False`, the share path is wrong or unreachable, and the data is
sitting in `C:\ProgramData\EndpointHealth\runs\`.

### Campaign

```powershell
# start it
.\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Campaign -Days 7 -SharePath \\FS01\EndpointHealth$

# check on it any time
.\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Status

# end it early (optional)
.\Deploy-EndpointHealth.ps1 -ComputerName WKS042 -Mode Stop
```

A campaign uploads about once an hour, survives reboots, and removes its own
scheduled task when the days run out. Nothing to clean up. Use `Stop` only if
you are finishing early.

---

## Part 5. Read the answer

```
\\FS01\EndpointHealth$\WKS042_9-17_1059\SUMMARY.txt
```

Folder name is `COMPUTERNAME_month-day_time`. Open `SUMMARY.txt` in Notepad.
Findings are worst first, and each says what was seen, why it matters, and what
to do. That is the deliverable. Attach it to the ticket.

Supporting evidence in the same folder:

- `snapshot\` hardware, storage, events, network, security state
- `telemetry\` sampled counters for the whole campaign
- `captures\` deep traces, only present if something tripped a threshold.
  `trace.zip` opens in Windows Performance Analyzer.
- `logs\agent.log` what the tool itself did

---

## Part 6. When nothing shows up on the share

In order:

1. `-Mode Status` against the machine. `TaskState: not registered` means the
   campaign never started. Re-run the start command from an elevated prompt.
2. `StagedMB` climbing but the share folder empty means share rights. Redo the
   machine-account write test in Part 1.
3. Read `C:\ProgramData\EndpointHealth\campaign.log` on the machine. It says
   plainly what failed.
4. Data is never lost meanwhile. It stages in
   `C:\ProgramData\EndpointHealth\runs\` and uploads when the path works.

Still stuck: IT infrastructure, 904-440-0711 or IT_Support@Firstcoastcardio.com.

---

## Part 7. Deploying from Endpoint Central

For several machines at once, without touching any of them.

1. Configurations > Computer Configuration > **Custom Script**.
2. Script: `Deploy-EndpointHealth.ps1` from the Script Repository, with the rest
   of the folder uploaded as dependency files.
3. Script Arguments, each argument in its own quotes:
   `"-Mode" "Campaign" "-Days" "7" "-SharePath" "\\FS01\EndpointHealth$"`
4. Frequency: **Once**. Not "Every Refresh Cycle" and not "During Every
   Startup", or the campaign restarts every 90 minutes.
5. Tick **Enable logging for troubleshooting** so script output lands in the
   configuration's Execution Status.

Endpoint Central runs scripts as SYSTEM, which is what this needs, and the
agent installs itself to `C:\ProgramData\EndpointHealth\agent` so it survives
the temp folder being cleaned up. No second configuration is needed to tear it
down.

---

## Part 8. Known first-run traps

- **`Missing closing '}' in statement block`** pointing at
  `Deploy-EndpointHealth.ps1`. A collector script failed to parse and the error
  surfaced at the caller. Run the syntax check in Part 2 to find the real file
  and line.
- **`No mapping between account names and security IDs was done`**. A literal
  `DOMAIN` in the share commands, or running them on a machine that is not the
  file server.
- **`Uploaded: False`**, or a campaign with no folder on the share. Placeholder
  server name, or computer accounts cannot write. Part 1.
- **Nothing runs at all.** Files still blocked from the zip, or execution
  policy. Part 2.
- **Optional binaries.** `smartctl.exe` (per-attribute SMART) and
  `Procmon64.exe` (Procmon capture engine) go in
  `C:\ProgramData\EndpointHealth\bin`. Both are skipped silently when absent.
- Test on a lab machine before a clinical one: Snapshot first, then a one day
  campaign to confirm the hourly uploads land.
