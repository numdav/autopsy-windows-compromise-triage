# Windows Compromise Triage for Autopsy

*Windows Compromise Triage* is an ingest module for [Autopsy](https://www.autopsy.com/) that answers one question
in a few minutes: **which Windows machines should be examined first, and why?**

Italian version of this page: [README.it.md](README.it.md)

The module runs a 41-point compromise checklist on a disk image or on a set of logical files (and, when a memory
image of the machine is available, on the results of Volatility 3) and gives a verdict:

| Verdict | Meaning |
| --- | --- |
| **INDICATORS OF COMPROMISE** | at least one decisive fact: an indicator that rarely has an innocent explanation and alone justifies examining the machine |
| **NEEDS REVIEW, HIGH PRIORITY** | no decisive fact, but findings to confirm in two families that come from different facts |
| **NEEDS REVIEW** | findings to confirm in a single family or about a single fact, or data that is missing or could not be read |
| **NO INDICATORS FOUND** | the checks that ran found nothing. It does not mean that the machine is clean |

> **Heuristic triage verdict**: it points out where to look first. It is neither a probability nor proof; the
> conclusion is up to the forensic analysis.

The verdict comes with the findings behind it, each one linked in the Autopsy tree to the file it comes from, and
with a self-contained HTML report.

![The HTML report](docs/screenshots/report-en.png)

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Memory (Volatility 3)](#memory-volatility-3)
- [Where the results are](#where-the-results-are)
- [How to read the results](#how-to-read-the-results)
- [The 41 checks](#the-41-checks)
- [Language](#language)
- [Evaluation](#evaluation)
- [Limits](#limits)
- [Tuning the rules](#tuning-the-rules)
- [Development](#development)
- [Compatibility and tests](#compatibility-and-tests)
- [Troubleshooting](#troubleshooting)
- [Project history](#project-history)
- [Credits](#credits)
- [License](#license)

## What it does

The module reads, with its own parsers:

- the registry: `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`, with their transaction logs;
- the event logs (`.evtx`): Security, System, Application, PowerShell, Task Scheduler, Terminal Services, Windows
  Defender, WMI-Activity, Sysmon and a few more;
- Prefetch, scheduled tasks, Startup folders, the WMI repository, `CryptnetUrlCache`, the PowerShell console history;
- the logs of AnyDesk, TeamViewer, LogMeIn and Pulseway, the Windows Defender detection history, the Recycle Bin;
- when a memory image of the machine was acquired: processes, connections and sessions, from the output of
  Volatility 3 collected with the script in `collectors/` (see [Memory](#memory-volatility-3)).

From these it looks for the traces an intrusion usually leaves: cleared logs, new or hidden accounts, logons from
public addresses and password-guessing bursts, persistence (services, scheduled tasks, Run keys, WMI subscriptions),
attack tools and dual-use tools, suspicious command lines and process parents, remote execution with Impacket and
PsExec, remote access tools (RMM), antivirus detections, files left in staging folders, anti-forensics.

It needs no other ingest module and no external program (for the memory, Volatility runs outside Autopsy, before
the analysis), and it is read-only: it never modifies the data source.
The results can be produced in English or in Italian.

## Requirements

- **Autopsy 4.23.1**, the version this release was tested with (see [Compatibility and tests](#compatibility-and-tests)).
  The module uses nothing but what Autopsy ships with: it is plain Jython 2.7 code.
- For the memory only, on the computer where the memory image is analyzed: **Python 3.8** or later and
  **[Volatility 3](https://github.com/volatilityfoundation/volatility3) 2.28.2**, the version tested on real memory
  images. The collector runs with older versions of Volatility too, but says so: they give less data (see
  [Limits](#limits)). Nothing has to be added to Autopsy.

## Installation

1. Download `TriageCompromissione-<version>.zip` from the [releases](../../releases) page and check its SHA-256 against
   the one in the release notes (in PowerShell: `Get-FileHash .\TriageCompromissione-1.3.zip -Algorithm SHA256`).
2. In Autopsy open **Tools > Python Plugins**: the folder of the Python modules opens (on Windows it is usually
   `%APPDATA%\autopsy\python_modules`).
3. Close Autopsy and extract the zip into that folder. The result must be `...\python_modules\TriageCompromissione\`
   containing `TriageCompromissione.py` and the `tc_*.py` files.
4. Open Autopsy again.

In the release zip the folder also holds `collectors\collect_memory.py`, the script for the memory image (see
[Memory](#memory-volatility-3)), `tools\verify_case.py`, which checks a case after an analysis, and `docs\`, with the
procedure to test the module on a Windows workstation; Autopsy ignores them.

To update, close Autopsy, replace the folder and open Autopsy again. A restart is also needed after any change to a
`tc_*.py` file: Autopsy reloads only the main file by itself.

## Usage

1. Open or create a case and add the data source (**Add Data Source**):
   - a disk image (E01, dd, vmdk, vhd...), or
   - **Logical Files**: the folder of a triage collection (KAPE, CyLR, Velociraptor...) or a copy of the Windows
     folder. With logical files, tick the timestamp boxes (modified, created, accessed): without them the check on
     recent files cannot tell recent files from old ones and considers them all.
2. In the list of ingest modules tick **Windows Compromise Triage**. It does not need the other modules: for
   triage alone you can leave them all off, which is the fastest way.
3. Settings (the panel on the right when the module is selected; they are remembered for the next runs):
   - **Days to treat as "recent"** (default 30). They are counted back from the machine's last activity, not from
     today.
   - **Authorized remote access (RMM)**: the names of the remote access tools that are authorized on that machine,
     separated by commas (for example `TeamViewer, AnyDesk`). They stay in the report as context but do not affect
     the verdict; a renamed copy of an authorized tool is still reported as a finding to confirm. A name that
     matches no known tool is pointed out in the report.
   - **Results language**: English or Italian, see [Language](#language).
   - **Memory (Volatility results)**: which memory collection goes with the machine. *Automatic* uses the collection
     in the same data source (if the data source holds a single installation of Windows) and those in the data
     sources of the same Autopsy host; *None* uses none; or choose one of the collections already in the case. See
     [Memory](#memory-volatility-3).
4. Start the ingest. In the tests every machine took from a few seconds to a minute; a 1 GB Security log adds
   about two minutes.

![The module in the ingest modules window](docs/screenshots/ingest-modules-en.png)

If the data source holds several Windows installations (several volumes, several machines in the same folder),
each one gets its own verdict and its own report, up to six per data source. Further installations and
`Windows.old` folders are not analyzed: a note in the report says so.

## Memory (Volatility 3)

A disk image does not contain what was running: processes, network connections, logged-on users. If a memory image
of the machine was acquired (on the live machine, before anything else), the module can use it as well. The work is
split in two, so that the verdict always comes from the same engine:

- `collectors/collect_memory.py` **only collects**. It runs a fixed set of Volatility 3 plugins on the memory image
  and keeps their JSON output unchanged, next to a manifest (`compromise-triage-memory.json`) that records the version
  of Volatility, the SHA-256 of the image and of every output, and how each plugin ended. It judges nothing.
- The **module** applies its rules to that folder, the same rules it applies to the disk, once the analyst has said
  which machine the memory belongs to.

**1. Collect.** On the analysis workstation, never on the suspect machine:

```
py -3 -m pip install volatility3==2.28.2
py -3 collect_memory.py D:\evidence\PC01.mem -o D:\case\PC01_vol3
```

(on Linux and macOS write `python3` instead of `py -3`). The script is in the `collectors` folder of the repository
and of the release zip. Before collecting it runs a **preflight check** and writes its outcome in the manifest: the
versions of Python and Volatility (with a warning if Volatility is older than 2.28.2), the plugins this Volatility
can load (a plugin it does not have is skipped and reported as "not available"), the symbols (a local folder, or
the Microsoft symbol server reachable) and the free space. `--vol` says how to start Volatility when it is not
installed in the same Python (for example `--vol "py -3 C:\volatility3\vol.py"`); Volatility downloads the symbols of
each Windows build from Microsoft the first time, so on a computer without Internet access use `--symbols` with a
local symbol pack and `--offline`; `--timeout` stops a plugin that runs too long (default 120 minutes); `--no-hash`
skips the SHA-256; `--lang en|it` chooses the language of the messages. Depending on the size of the image it takes
from a few minutes to half an hour.

| Volatility 3 plugin | Used for |
| --- | --- |
| `windows.info` | system time of the acquisition, Windows build |
| `windows.pslist`, `windows.pstree`, `windows.psscan`, `windows.cmdline` | check 4: processes, command lines, parents, hidden processes |
| `windows.netscan` (`windows.netstat` if netscan fails) | checks 5 and 7: connections and their processes |
| `windows.sessions` | check 3: who was logged on, at the console or through Remote Desktop |
| `windows.envars`, `windows.getsids` | the computer name, the user of each process, the machine SID |
| `windows.svcscan` | services in memory that the registry no longer has (checks 17 and 29) |

After collecting, the script checks the output against what a running Windows always has: dozens of processes,
among them `System`, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe` and `lsass.exe`; readable command lines;
listening ports; hundreds of services and environment variables; and not many more processes in `psscan` than in
`pslist`. Below those thresholds, as with a truncated image, it says *anomalous or possibly incomplete output* and
ends with exit status 1, so that the acquisition can be repeated. It also says when the connections come from
`netstat` instead of `netscan`, which does not see the connections already closed. Exit status: 0 if everything
worked, 1 if some plugin failed or the output looks anomalous (the folder is still usable: the module reports what is
missing), 2 if nothing could be run.

**2. Add the folder to the case** as **Logical Files**, and say which machine it belongs to. The module never pairs a
memory collection with a disk by computer name: a clone, a reinstalled machine or a standard name would join two
different machines. The pairing is the analyst's, in one of three ways:

- put the folder in the **same data source** as the files of the same machine (for example next to its KAPE
  collection, before adding it). This works when the data source holds a single installation of Windows: with
  several, the memory is used for none of them, with a warning;
- add the folder to the **same Autopsy host** as the disk: in the Add Data Source wizard, on the *Select Host* page,
  choose *Use existing host* and the host of the disk. Data sources already added can be moved by merging their hosts
  (*Merge Into Other Host*);
- choose the collection in the module settings, **Memory (Volatility results)**: the list shows the collections of the
  case, by data source and folder.

Then run the module on the disk. If the memory is added after the disk was analyzed, run the module on the disk
again: the new results replace the old ones. A memory collection of another host is not used; if it has the same
computer name as the machine, a note says so. Run on the memory folder alone, the module gives a verdict from the
memory only, with the coverage warnings for everything a disk would have shown.

**3. The module checks the pairing** with what it already read on the disk: the Windows build (by kernel: Windows 10
2004-22H2 all run kernel 19041), the computer name (against all the names the machine had in the registry and in the
event logs), the boot time (against the boot events of the System log, when the log covers that time), the machine
SID, and the acquisition time against the period covered by the event logs. If the build, the boot or the SID
contradict the choice, a warning says so and the findings of that memory stay in the report, marked, but do not count
for the verdict until the choice is corrected; a different name or time only gives a warning. The report has a
section *Memory: pairing and checks* with the image (and its SHA-256), who chose it and the outcome of every check.
The name of the installation never comes from the memory.

![The memory pairing and its checks in the HTML report](docs/screenshots/report-memory-en.png)

**4. What the module finds in memory.**

- With the same rules as on the disk: attack tools and dual-use tools, programs running from folders where programs
  do not belong (`C:\Users\Public`, `PerfLogs`, a `svchost.exe` outside System32...), command lines judged as for
  events 4688 (encoded PowerShell, download and run, `ssh -R`, `-L` or `-D` tunnels...), process parents (`lsass.exe`
  or `wininit.exe` that start a command interpreter, a shell started by netcat or ncat...), remote access tools (they
  join checks 32-36), services with the signatures of Impacket.
- With rules that make sense only in memory, labeled *extra rule*: a process found by the memory scan but missing
  from the list of active processes (*maybe hidden*), a system process with an unexpected parent or in more than one
  copy, a document program or a web server that starts a command interpreter, a Windows program that does not
  normally talk to the Internet (`rundll32.exe`, `mshta.exe`, `regsvr32.exe`...) with a connection to a public
  address, processes running as an account that the event logs show created or added to the administrators. A Remote
  Desktop session open at the time of the acquisition is reported as context.
- The report gets the tables of sessions, processes, connections and SMB connections found in memory. In the
  connection table, "?" means that Volatility did not attribute the connection to a process (it happens with the
  builds whose network structures it knows less well, for example Windows 11 22H2 and 23H2): it is not a finding.

**5. When the results are partial.** If a Volatility plugin failed, stopped or is missing, the report says which one,
with the reason recorded in the manifest, and which checks are incomplete; a file that Volatility does not recognize
(not a memory image of Windows, or symbols missing) is reported as such. The rows and the SHA-256 of every output
are compared with the manifest, and an interrupted collection is reported. The module applies the same plausibility
thresholds as the collector: an anomalous output gives a warning, and its findings stay in the report but do not take
the verdict beyond "needs review". In the table of the 41 checks a check with a missing source is *Partial*: for
example 5 and 7 when the connections come from `netstat`, 17 and 29 when `svcscan` is missing (services left only in
memory, as smbexec does, are not checked). A partial or unverifiable check because a source failed rules out "no
indicators found".

The DNS cache (check 6) and the SMB sessions with their user and shares cannot be obtained with the standard plugins of
Volatility 3: they remain with live triage. Autopsy's experimental memory data source (Windows only, based on
Volatility 2.6) is a different thing and is not needed.

## Where the results are

- **Ingest inbox** (the envelope at the top right): verdict, number of facts and findings, path of the report.
- **Autopsy tree, Analysis Results**:
  - *Compromise Triage: verdict*: one item per machine;
  - *Compromise Triage: findings*: one item per finding, attached to the file it comes from (hive, event log,
    `.pf` file, JSON file of Volatility...), with its fact number and its origin (disk, or memory with the SHA-256 of
    the image). The findings from a memory image kept in another data source are attached to the data source that was
    analyzed.

  The verdict *Indicators of compromise* has the score *Notable*, *Needs review* with findings *Likely Notable*.
  Decisive findings have the score *Notable* and findings to confirm *Likely Notable*, unless they come from a memory
  that the disk contradicts (*Unknown*) or from an anomalous memory (at most *Likely Notable*). They also show up
  under the *Score* node of the tree.

  ![The findings in the Autopsy tree](docs/screenshots/results-tree-en.png)
- **Report**: `<case folder>\Reports\TriageCompromissione\`
  - `Triage_<computer>_<date>.html`: the complete report;
  - `Triage_<computer>_<date>.csv`: the findings only, with their fact, origin, whether they count and their status.

  The report is also listed in the tree under **Reports**.

Times in the report are UTC. The only exception, pointed out where it occurs, is the TeamViewer connection log,
which is written in the machine's local time. In the Autopsy tree times follow the time zone chosen in
**Tools > Options > View**.

If you run the module again on the same data source, the old results are replaced by the new ones, except those
you tagged: tagged results are kept. The reports of the previous runs are not deleted.

## How to read the results

Every finding has a **weight**:

| Weight | Meaning | Examples |
| --- | --- | --- |
| **Decisive** | rarely has an innocent explanation and alone justifies examining the machine. It is not proof | Mimikatz executed, a service with the smbexec signatures, the Security log cleared, a shell started by `lsass.exe` or by netcat |
| **To confirm** | attackers do it, but administrators do it too | PsExec, an account created from the command line, RDP from a public address, a remote support tool, a dual-use tool found only by its name |
| **Informational** | context only: does not affect the verdict (the report groups these findings under *Context only*) | |

and a **family**: Logons, Accounts, Persistence, Program execution, Attack tools, Dual-use tools, Remote
execution, Remote access (RMM), Files, Anti-forensics, Antivirus, Exfiltration and tunneling.

Findings about the same object (a process, a command, a file, a task, a service, an account, an address, a log, a
script block) form one **fact**: the same command seen in event 4688, in Sysmon and in memory is one fact, and so are
the command that creates an account and the event 4720 of that account. The report counts facts ("2 decisive facts
(3 signals)") and its *Facts* table says where each one was seen: more sources confirm that something happened, not
that it is more serious. The line below it counts the signals by origin and weight ("disk: decisive 25, to confirm
31"): there a signal to confirm that belongs to a decisive fact is counted too, so it can give more signals to confirm
than the facts line, which counts them only for the facts to confirm.

The verdict:

| Situation | Verdict |
| --- | --- |
| at least **one decisive fact** | Indicators of compromise |
| findings to confirm in **two or more families**, from **different facts** | Needs review, high priority |
| findings to confirm in a single family, or all about the same fact | Needs review |
| findings only from an anomalous memory or from sources that disagree | Needs review |
| no decisive or to-confirm findings, but at least one coverage warning | Needs review |
| otherwise | No indicators found |

**Coverage warnings** say what the triage could not see: event logs or hives that are missing, damaged or too
short, unreadable files, logs that stop before the other artifacts, memory results that are missing, partial or
implausible, a memory that the disk contradicts, checks interrupted by an error. "No indicators found" is meaningful
only when there are no warnings, which is why a warning alone leads to "Needs review". **Notes** are observations
that do not touch the verdict (a clock that was moved, file dates that are those of the copy, an older Volatility...).

The same command weighs differently depending on where it is found. In something that starts by itself (a service,
a scheduled task, a Run key, a WMI subscription) or pasted into the Run dialog, an encoded command or one that
downloads and runs code is decisive. Among commands that were merely executed (events 4688, Sysmon, PowerShell, the
console history) it is only "to confirm", because management tools do similar things every day; only what has no
innocent explanation stays decisive (an attack tool, Impacket's output to `\\127.0.0.1`, a reverse shell...).
During the installation of Windows (from the install date in the registry, or from the event logs, which show the
names the machine had while it was prepared), the accounts and services that setup creates and the scripts that
prepare the image are context only.

"Recent" does not mean close to today. The window is counted back from a reference time: the older of the last
event written to the Security log and the last one written to the System log (if they are missing, the other logs
and the last shutdown time). The report says what it is.

**Every finding counts only until IT explains it.** Triage helps decide where to look first: it does not replace
the analysis.

## The 41 checks

| No. | Phase | Check |
| --- | --- | --- |
| 1 | 1. Context and volatile data | System context |
| 2-7 | | Prefetch copy, logged-on users, processes, network connections, DNS cache, SMB sessions: steps of live triage, *not applicable to a disk image*; 3, 4, 5 and 7 are also done on a memory image (see [Memory](#memory-volatility-3)) |
| 8 | 2. Accounts and logons | Log coverage and active auditing |
| 9 | | Cleared logs |
| 10 | | Local accounts, administrators, profiles |
| 11 | | Remote network and RDP logons |
| 12 | | Failed logons by address |
| 13 | | Explicit credentials and outbound connections |
| 14 | | RDP sessions (Terminal Services) |
| 15 | 3. Persistence | Scheduled tasks |
| 16 | | Hidden tasks |
| 17 | | Services |
| 18 | | Installed services (event 7045) |
| 19 | | Run keys and Startup folders |
| 20 | | WMI subscriptions |
| 21 | 4. Program execution | Prefetch |
| 22 | | BAM |
| 23 | | RunMRU |
| 24 | | Downloads with certutil |
| 25 | | Suspicious commands (events 4688, Sysmon, PowerShell) |
| 26 | | ShimCache, AmCache, UserAssist |
| 27 | 5. Remote execution with Impacket | Tasks created and deleted within moments |
| 28 | | Signatures of atexec in tasks |
| 29 | | Signatures of smbexec in services |
| 30 | | Leftover files |
| 31 | | Share access (event 5145) |
| 32 | 6. Remote access tools (RMM) | Installed programs |
| 33 | | Portable RMM tools, including renamed ones |
| 34 | | AnyDesk |
| 35 | | TeamViewer |
| 36 | | LogMeIn and Pulseway |
| 37 | 7. Files, antivirus and anti-forensics | Antivirus detections |
| 38 | | Recent files in staging folders |
| 39 | | Recycle Bin |
| 40 | | Shadow copies |
| 41 | | Disabled artifacts |

Checks 2 to 7 belong to live triage. Check 2, the copy of the Prefetch folder, is not needed on an image, because
check 21 reads Prefetch directly. Checks 3 to 7 concern volatile data, which a disk image does not contain: the
report marks them as "Cannot be verified", unless a memory collection of the machine was indicated (see
[Memory](#memory-volatility-3)); then checks 3, 4, 5 and 7 are done on the memory. All the other checks are run; the
report has a table with the outcome of each one: a finding with its weight, *Nothing to report*, *Partial* (done, but
a source is missing or incomplete: the note says which), *Artifact not found*, *Cannot be verified*, *Not run*.

Findings labeled **extra rule** come from well-known rules that are not part of the guides the checklist is built
on (sticky keys, Defender exclusions, PowerShell history, port forwarding, hidden accounts...).

## Language

The module speaks English and Italian.

- **Results** (inbox message, tree, HTML report, CSV): the language chosen in the settings panel, *Results
  language*. The first time it is preset to the language of the system; after that it is remembered like the other
  settings.
- **Settings panel and module description**: the language of the system, that is Java's default locale: Italian on
  an Italian system, English everywhere else.
- **Module name**: always *Windows Compromise Triage*. Autopsy recognizes ingest modules by their name in the saved
  ingest settings and in the ingest profiles, so the name does not change with the language.

Two things to know:

- In a case, the names of the two result types in the tree and of their columns are created by the first run and
  keep that language even if a later run uses the other one; the content of the results follows the language of
  each run.
- The CSV file uses the comma as separator in English and the semicolon in Italian, which is what Excel expects
  with the respective regional settings.

## Evaluation

The module was measured on data labeled by others: event logs of attacks, clean installations of Windows, and the
memory of two real compromised machines. The full evaluation of version 1.2, with the method, is attached to the
release (in Italian), with the register of the tests of version 1.3; version 1.3 applies its corrections. Here are the
numbers that matter for the use of the module. Percentages are on the samples that contain at least one event the
rules read ("in scope"); intervals are 95% Wilson intervals.

| What | Data | Version 1.2 | Version 1.3 |
| --- | --- | --- | --- |
| Attack samples with at least one finding to confirm or decisive | 161 event logs of attacks in scope ([EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)) | 88 (55%) | 90 (56%, 48-63%) |
| ... with a finding for the technique of the label | same | 70 (43%) | 72 (45%, 37-52%) |
| ... with the strongest verdict, for the technique | same | 26 (16%) | 26 (16%, 11-23%) |
| ... with no finding at all | same | 73 (45%) | 71 (44%, 37-52%) |
| Records of these logs the module could not decode | 12,812 records | 1,681 (13%) | 0 |
| Clean installations with the strongest verdict | 7 installations ([evtx-baseline](https://github.com/NextronSystems/evtx-baseline)) | 3 | 2 |
| Clean installations with findings to confirm or decisive | same | 4 | 4 |
| Sealed set, used once | 37 attack samples never used before | — | 25 of 33 in scope with findings (76%, 59-87%), 16 for the technique (48%, 33-65%); strongest verdict for the technique 11 (33%, 20-50%); no finding 8 (24%, 13-41%) |

Read them this way:

- **A negative verdict does not exclude an attack.** On these attack samples, 44% of those in scope give no finding at
  all (24% in the sealed set). "No indicators found" and "Needs review" mean that the triage saw nothing, not that
  there is nothing.
- **The strongest verdict is rare on a single log of a few minutes.** The verdict is made to add up evidence of
  different kinds (registry, files, events); an attack sample offers little of it.
- **The false alarms on clean systems** came from logs cleared by those who prepared the data, from accounts, services
  and scripts of the installation, and from remote access tools installed on purpose: version 1.3 treats the
  installation as context and no longer lets two remote access tools alone give the strongest verdict. The strongest
  verdict remains on two installations, both because of logs cleared by those who prepared the data; without those
  logs it would remain on none, and one of them (RDP from a public address and two remote access tools) would be
  "needs review, high priority".
- **After the corrections, those sets are no longer independent.** The 1.3 numbers on the attack samples and on the
  clean installations were measured on data that drove the corrections: they show that the corrections work there, not
  how the module does on new data. The sealed set is the only measure on data that drove no change: 37 event logs of
  attacks from [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) that share no event
  and no file name with the data already used, run once with the final code, with the protocol written before. It is
  small and comes from a single collection. There too a log cleared at the start of the recording, which the label
  does not mention, is enough for the strongest verdict: 9 of the 20 samples that get it owe it only to that, and the
  figures "for the technique" leave them out.
- **Not measured**: whole compromised and clean machines from independent sources, real incidents, company
  configurations. The verdict on a whole machine has no measured error rate.
- **Memory**: on the two real compromised machines of the evaluation, with Volatility 2.28.2, version 1.3 flags 3 of
  the 11 attack processes of the Windows 11 machine from the memory alone (the shell started by ncat, decisive; ncat
  and an SSH tunnel, to confirm) and, with the event logs of the Windows 10 machine, 3 of its 5 (the processes of the
  account the attacker created); version 1.2 flagged 1 of the 16. None of the 360 benign processes is flagged. With
  Volatility 2.4.1 a benign process that `windows.pslist` misses comes out as *maybe hidden*, marked as a disagreement
  between sources, and does not count. The memory of the Windows 10 machine alone gives no finding, so "needs review".
  A memory image cut in half now gives the warning *anomalous or possibly incomplete output*: the 30 processes it
  shows as *maybe hidden* stay in the report, marked as uncertain, and do not go beyond "needs review" (version 1.2
  gave no warning). Two machines describe the cases tried, they are not a rate; a whole clean machine with its real
  memory has never been tried, so "no indicators found" with memory has no measure.

## Limits

- **What the rules do not see well** (the techniques where most attack samples were missed in the evaluation): services
  created or modified (T1543.003), account manipulation (T1098), obfuscated files and commands (T1027), lateral
  movement with RDP, DCOM and SSH (T1021), brute force (T1110), account and group discovery (T1087, T1069). Version 1.3
  adds no rules for these: new rules have to be measured on data that was not used to write them.
- A tool found on the disk only by its name is at most "to confirm": a name proves neither that the file is that tool
  nor that it ran, unless there is a proof of execution or the version information of the file names it.
- ShimCache and AmCache prove that a file existed, not that it was executed: the report says so item by item. On
  Windows 8 and later, a missing `Amcache.hve` gives a coverage warning.
- WMI subscriptions are also searched among the deleted objects of the repository: an entry that is found may no
  longer be active.
- Shadow copies are not opened: the report only says whether they exist.
- Registry transaction logs in the old format (before Windows 8.1) are not applied.
- An IPv6 address is never considered "public".
- Commands obfuscated with `^` or `""` in the middle of words are restored to plain text and encoded PowerShell
  commands are decoded; more elaborate obfuscation is not undone.
- Command lines are visible only if the machine recorded them (event 4688 with the command line, Sysmon, the
  PowerShell logs): Windows does not do it by default. Without them the checks on registry, files, services, tasks,
  Prefetch and logons remain.
- With a partial collection of files the most frequent verdict is "Needs review", with the warnings saying what is
  missing.
- Deleted files are used only where they matter (Impacket leftovers, known tools searched by name).
- Each check keeps at most 40 findings of the same weight and family (160 for decisive ones). When there are
  more, the report says how many there were in all.
- A fact is an object (a process, a command, a file, a task, a service, an account, a script block...), not an
  action: one step of an attack recorded in several objects counts as several facts. On the event logs of one of
  the real machines of the evaluation the report counts 12 decisive facts, five of them PowerShell script blocks of
  stagers that the module does not tie to the command that launched them.
- Tools are searched by their known names. A renamed executable is recognized only from its version information,
  which is read for the 400 most recent executables in the staging folders (Downloads, Desktop, Public, Temp,
  ProgramData...).
- Memory is a snapshot of one moment. A process that has already ended is visible only while its structure has not
  been overwritten (psscan), and the command line and the user are missing for the processes whose memory was in the
  paging file. A process *maybe hidden* must be confirmed: the memory scan sometimes finds the remains of a process
  that has just ended.
- In memory, a process name is truncated to 14 characters when Volatility cannot read the full path of the program.
- Code injection is not looked for: the collector does not run `windows.malfind`.
- With a Volatility older than 2.28.2 the module gets less data: in 2.4.x `windows.svcscan` does not load unless
  `yara-python` is installed (checks 17 and 29 are then incomplete, and the report says so); on Windows 11 build 22621
  `windows.netscan` of 2.4.1 finds no TCP connection, only listening ports; on one image `windows.pslist` of 2.4.1
  missed a running process. With 2.28.2, on Windows 11 build 22621 the established TCP connections come without their
  process and creation time ("?").

## Tuning the rules

The names and patterns the rules work with are in `TriageCompromissione/tc_regole.py`, in commented lists (the
checks that use them are in the `tc_c_*.py` files):

| List | Content |
| --- | --- |
| `RMM` | remote access tools and how they are recognized |
| `_RX_ATTACCO`, `_NOMI_ATTACCO_ESATTI` | names of attack tools (decisive) |
| `_RX_DOPPIO_USO`, `_NOMI_DOPPIO_ESATTI` | dual-use tools (to confirm) |
| `FRAMMENTI_STRUMENTI` | name fragments used to search the disk for the tools above: a tool added to the lists above is looked for on disk only if a fragment of its name is here too |
| `_RX_PS_ATTACCO` | PowerShell attack scripts and commands |
| `COMANDI` | commands that weigh on their own, with their weight |
| `PADRI_MAI_INTERPRETI`, `STRUMENTI_DI_RETE` | system processes that never start interpreters, network tools whose child shell is decisive |
| `_NOMI_ANTIVIRUS` | antivirus services and processes |
| `_HOST_PRODUTTORI` | sites from which downloading an installer is normal |
| `_NOTI` | well-known installation scripts (Chocolatey, Scoop...) |
| `_PAROLE_NEI_NOMI` | words that tell a real name from eight random letters |

After a change restart Autopsy and run the tests (see below). A new or changed rule should come with its source and
its test cases, including clean ones that must not trigger it, and be measured on data that was not used to write it.

## Development

```
TriageCompromissione/     the plugin: this is the folder to copy into Autopsy
  TriageCompromissione.py   the ingest module (the only file that talks to Autopsy)
  tc_controlli.py           the engine: runs the checks, groups the findings into facts and decides the verdict
  tc_c_registro.py, tc_c_eventi.py, tc_c_file.py   the checks
  tc_regole.py              the rules (lists and command-line evaluation)
  tc_registro.py, tc_evtx.py, tc_prefetch.py, tc_artefatti.py   the parsers
  tc_eventi.py, tc_origine.py, tc_base.py           event collection, data source access, helpers
  tc_memoria.py             the memory: reads the output of Volatility 3, checks the pairing and judges it
  tc_report.py              HTML report and CSV
  tc_lingua.py, tc_lingua_en.py   language selection and the English catalog
collectors/collect_memory.py   runs Volatility 3 on a memory image (Python 3, outside Autopsy)
tests/                    tests of the rule engine (Jython) and of the memory collector (Python 3)
tools/check_translations.py   checks the English catalog against the code
tools/verify_case.py      checks an Autopsy case after an analysis (Python 3)
tools/make_release.py     builds the zip file to attach to a release (reproducible)
docs/windows-test.md      how to test the module on a Windows workstation
docs/screenshots/         the images of this page
```

The code, its comments and its identifiers are in Italian, the language the plugin was born in. Every text shown
to the analyst is written in Italian in the code, wrapped in `tr(u'...')`, and has its English translation in
`tc_lingua_en.py`; `N_(u'...')` only marks a text defined once at import time, which is then translated with `tr()`
where it is shown.

The source files must stay pure ASCII: accented letters are written as `\uXXXX` escapes (for example `\u00e8`
for "è"), the safest form with Jython 2.7.

**Checking the translations** (Python 3.8 or later):

```
python3 tools/check_translations.py
```

(on Windows: `py -3 tools\check_translations.py`)

It reports the texts that have no English translation, the translations that are no longer used and those whose
placeholders (`%s`, `%d`...) or HTML tags differ from the Italian text.

**Running the tests** needs only Java and the Jython jar. The jar is inside every Autopsy installation; on Windows
Autopsy also ships its own Java:

```
"C:\Program Files\Autopsy-4.23.1\jre\bin\java.exe" -jar "C:\Program Files\Autopsy-4.23.1\autopsy\modules\ext\jython-standalone-2.7.4.jar" tests\run_tests.py
```

(adjust the two paths to your installation; in PowerShell put `&` in front of the command; on Linux and macOS use
`java -jar .../jython-standalone-2.7.4.jar tests/run_tests.py`). The tests feed several hundred command lines,
service definitions, event sequences, memory outputs and synthetic timestamps to the rule engine and compare the
outcome with the expected one, in both languages. They need neither Autopsy nor any evidence file.

**Testing the memory collector** needs Python 3.8 or later, and neither Volatility nor a memory image: a small fake
Volatility answers like the real one, including its failures:

```
python3 tests/test_collect_memory.py
```

**Building the release zip**: `python3 tools/make_release.py` writes `dist/TriageCompromissione-<version>.zip`. The
zip is reproducible (the date of every entry is that of the last commit, or `SOURCE_DATE_EPOCH`): the GitHub Actions
checks rebuild it from the tag of a release and compare it with the one attached.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the few rules to follow when changing the code. To report a
security problem, follow [SECURITY.md](SECURITY.md): privately, not in a public issue.

## Compatibility and tests

- **Autopsy 4.23.1 on Linux**: the plugin installed from a zip built by `tools/make_release.py` with the code of this
  release, run from the command line on a raw disk image, on logical files with two installations, on logical files
  with memory collections (real and synthetic), with the memory in the same data source, in the same host and chosen
  in the settings; reports in English and Italian. Every run passed the checks of `tools/verify_case.py`. For version
  1.3: 45 planned tests (53 data sources, 54 verdicts), with the expected outcome written down before running them;
  43 matched it exactly, and in the other two the warning about `netstat` says what it should but names the plugins in
  full (`windows.netstat.NetStat`), where the expectation had the short name. Further runs made the images of this
  page and checked the release zip itself, with the same results as the tests on the same data. The register of the
  tests, with the requirement, the expectation and the outcome of each one, is attached to the release (in Italian).
- **Windows has not been tested.** The program is the same, but the installer, the bundled Java, the user folder, the
  antivirus and the paths differ. Before relying on the module on a Windows workstation, follow
  [docs/windows-test.md](docs/windows-test.md): it takes about half an hour and ends with `tools/verify_case.py`.
- **Other versions of Autopsy** are not supported by this release. Version 1.2 of the module was tested end to end on
  Autopsy 4.19.0, 4.20.0, 4.21.0, 4.22.1 and 4.23.1 on Linux, with identical results; version 1.3 was tested only on
  4.23.1.
- **Memory collector**: Python 3.8 and 3.11 with Volatility 3 2.28.2 on a real 8 GB image (identical outputs), and
  Volatility 2.4.1 for the preflight warnings; its tests run with Python 3.8 and with the latest Python.
- The engine runs with Jython 2.7.4, the one of Autopsy 4.23.1.

The tests on real artifacts use public forensic images and collections that are not part of this repository: the
repository contains the tests that need no evidence files.

## Troubleshooting

- **The module is not in the list**: the folder is not in the right place (it must be
  `python_modules\TriageCompromissione\`) or Autopsy was not restarted.
- **"Previously loaded ... module could not be found"**: Autopsy remembers the modules it last used. After an update
  from version 1.0, where the module was called *Triage compromissione Windows*, or after removing the module, press OK:
  Autopsy shows the notice once for each place where it had saved the name (the Add Data Source wizard, the Run Ingest
  Modules window, each ingest profile). From the command line (`--runIngest`) the first run ends with "Error running
  ingest on data source" and writes the same notice in the log; it also corrects the saved settings, so the next run
  works.
- **Autopsy aborts when two instances start at the same time**: seen on Linux, with and without this module: both
  copy their native libraries into the same temporary folder of the user. Start one instance at a time, or give each
  installation its own temporary folder (add `-J-Djava.io.tmpdir=<folder>` to `default_options` in
  `etc/autopsy.conf`).
- **"Triage failed on ..."**: the message in the ingest inbox shows the error. The details are in the Autopsy log
  (**Help > Open Log Folder**, file `autopsy.log.0`, search for "Triage").
- **"Triage: no Windows artifacts in ..."**: the data source has no `Windows\System32\config` folder and no
  recognizable `.evtx` files or hives.
- **Checks 3-7 still say "Cannot be verified" although the memory is in the case**: the memory was not indicated for
  this machine. Put it in the same data source or in the same host, or choose it in the module settings (see
  [Memory](#memory-volatility-3)), and run the module on the disk again. A note in the report says when a memory
  collection of another host has the same computer name.
- **"The memory ... does not seem to belong to this Windows installation"**: the build, the boot or the machine SID
  of the memory contradict the disk. Check that the right collection was chosen; the section *Memory: pairing and
  checks* of the report shows each check.
- **"Anomalous or possibly incomplete output"**: the output of Volatility has less than a running Windows always has.
  An incomplete image, a failed extraction and concealment cannot be told apart: check the image and, if you can,
  repeat the acquisition.
- **collect_memory.py stops at the first plugin with "Unsatisfied requirement"**: Volatility found neither a Windows
  kernel nor its symbols. Check that the file is a memory image of Windows; without Internet access, give Volatility
  the symbol pack with `--symbols`.
- **collect_memory.py says that a plugin is "not available in this Volatility"**: the Volatility in use does not have
  it, or cannot load it (for example `windows.svcscan` in 2.4.x without `yara-python`). Update Volatility:
  `pip install -U volatility3`.
- **The report says some checks were interrupted by an error**: the other checks ran anyway; if there are no
  findings the verdict is "Needs review" instead of "No indicators found". Please open an issue with the error
  text.

## Project history

The module was not the starting point. The project started on 30 September 2026 from a study of the 32 guides behind
its checklist and from the checklist itself, 41 checks to run on a live machine; then came the four versions, a
PowerShell script that runs the checklist on the spot, the evaluation of version 1.2 and the verification of version
1.3. The documents are in [history/](history/README.md), in Italian, and the history of this repository puts them in
the order they were made, with each version as a tagged commit and a release.

## Credits

The checklist behind the 41 checks is built on the 32 guides collected by Cyber Triage in the post
[Windows Artifact Forensics Guides – The Master List](https://www.linkedin.com/posts/cyber-triage_windows-artifact-forensics-guides-the-master-activity-7503822145521635328-H3iC)
(10 September 2026), plus Cyber Triage's guide
[How to Find WMI Consumers](https://www.cybertriage.com/blog/how-to-find-wmi-consumers/) for check 20.

The memory analysis relies on [Volatility 3](https://github.com/volatilityfoundation/volatility3) by the Volatility
Foundation, which is installed separately and distributed under its own license: this project does not include it.

This project is independent: it is not affiliated with, nor endorsed by, Cyber Triage, Sleuth Kit Labs, the
Volatility Foundation or the Autopsy project.

## License

Copyright 2026 Davide Numelli

Licensed under the [Apache License, Version 2.0](LICENSE). The software is provided "as is", without warranties of
any kind: it is a triage aid, and its verdict is not a substitute for the judgment of an analyst.

**Author**: Davide Numelli — GitHub [@numdav](https://github.com/numdav)
