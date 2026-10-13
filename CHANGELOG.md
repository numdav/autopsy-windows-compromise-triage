# Changelog

## 1.3 (October 2026)

This version applies the corrections of the evaluation of version 1.2 (see *Evaluation* in the README). In short:
the verdict no longer suggests a probability, findings about the same object count once, a memory image is paired
with a disk only as the analyst says and the pairing is checked, and the report says when the results of Volatility
are partial or implausible.

- **Verdict.** The labels are **INDICATORS OF COMPROMISE** (at least one decisive fact), **NEEDS REVIEW, HIGH
  PRIORITY** (findings to confirm in two families, from different facts), **NEEDS REVIEW** and **NO INDICATORS
  FOUND**: two families of findings to confirm no longer give the strongest verdict. At the top of the report and in
  the inbox message: *Heuristic triage verdict: it points out where to look first. It is neither a probability nor
  proof; the conclusion is up to the forensic analysis.* "Decisive" now means an indicator that rarely has an innocent
  explanation and alone justifies examining the machine. The Autopsy score of the verdict follows the label.
- **Facts.** Findings about the same object (process, command, file, task, service, account, address, log, script
  block) form one fact; for the verdict two families count only if they come from different facts. The report counts
  facts ("2 decisive facts (3 signals)") and has a *Facts* table that says where each fact was seen; the CSV and the
  tree have the fact number. A command that creates an account, or adds it to a group, joins the fact of that
  account.
- **Origin of every finding**: disk, or memory with the SHA-256 of the image, in the report, the CSV and the tree;
  under the verdict, the findings counted by origin.
- **Tools found only by name on the disk**: at most "to confirm", unless there is a proof of execution or the version
  information of the file names the tool.
- **Amcache.hve missing** on Windows 8 or later: a coverage warning.
- **Event logs**: records written without a template (inline binary XML) are now read; version 1.2 lost them (13% of
  the records of the blind evaluation set). The warning about records that cannot be read no longer calls the file
  "damaged".
- **Installation of Windows**: during the installation (from the install date in the registry, or from the event
  logs, which show the names the machine had while it was prepared), an account created and added to the
  administrators by the computer account, the temporary service of an installer and the Base64 PowerShell commands of
  the scripts that prepare the machine (Packer) are context only. Logs cleared during the preparation stay decisive,
  with a note.
- **New rules**: `lsass.exe` or `wininit.exe` that start a command interpreter or a reconnaissance tool (decisive);
  `services.exe` that starts a shell (to confirm); `WerFaultSecure.exe` launched with `/pid` against another process,
  the EDR-Freeze technique (decisive); a shell started by netcat, ncat or socat (decisive); `ssh -L` and `ssh -D` like
  `ssh -R` (to confirm); in memory, processes running as an account that the event logs show created or added to the
  administrators (to confirm). The driver of a memory acquisition tool is context only if the tool ran from the same
  folder and, for event 7045, the driver was installed within half an hour of the acquisition of the memory paired
  with the machine: the name alone is not enough. The hash of the driver is not compared (the module does not have
  the hashes of the tools): the report asks the analyst to check it.
- **Memory, which image goes with which machine**: the analyst says it. A memory collection is used for an
  installation of Windows if it is in the same data source (with a single installation), in a data source of the same
  Autopsy host, or chosen in the module settings (*Memory*). There is no pairing by computer name any more: a memory
  collection of another host with the same computer name only gets a note. A collection in a data source with several
  installations is used for none of them, with a warning.
- **Memory, compatibility checks**: Windows build (kernel family), computer name (all the names the machine had),
  boot (the System log), machine SID, acquisition time against the period of the logs. If build, boot or SID
  contradict the choice, a warning: the findings of that memory stay in the report, marked, but do not count for the
  verdict. The report has a section *Memory: pairing and checks* with the outcome of each check. The name of the
  installation never comes from the memory.
- **Memory, partial and implausible results**: the table of the 41 checks has a *Partial* status, with the sources
  that were missing; a partial or unverifiable check because a source failed rules out "no indicators found". An
  output below what a running Windows always has (dozens of processes with the system ones, readable command lines,
  listening ports, hundreds of services and environment variables), or with many more processes in psscan than in
  pslist, gives the warning *anomalous or possibly incomplete output* and its findings do not go beyond "needs review".
  The rows and SHA-256 of each output are compared with the manifest, and an incomplete collection is reported.
  Connections from `netstat` instead of `netscan` (which also sees closed connections): a warning, checks 5 and 7
  partial. Without `svcscan`, with the registry present, checks 17 and 29 are partial. The reason a plugin failed comes
  from the manifest; a file that Volatility does not recognize is reported as such, not as memory. The "?" in the
  connection table is explained. A note when the memory was collected with a Volatility older than 2.28.2.
- **Collector 1.3** (`collect_memory.py`): a preflight check (Python, Volatility against the version tested, the
  plugins it can load, the symbols, the free space), recorded in the manifest; a plugin that the Volatility in use
  does not have is skipped with a clear message; after the collection the output is checked with the same thresholds
  as the module: if it looks anomalous, the summary says so next to the count of completed plugins, a warning lists
  what is missing (in the language of the messages; the manifest keeps it in English) and the exit status is 1. The
  summary also says when `netstat` replaced `netscan`. The manifest keeps format version 1: version 1.2 of the module
  reads it too.
- **Report**: the CSV has the new columns *Fact no.*, *Source* (disk, or memory with its SHA-256), *Counts* and
  *Status*; "1 time", "1 hour", "1 decisive fact" in the singular.
- **Tools**: `tools/verify_case.py` checks an Autopsy case after an analysis (module loaded, analysis completed, no
  errors of the module, consistent counts, report); `docs/windows-test.md` is the procedure to test the module on a
  Windows workstation; `tools/make_release.py` builds a reproducible zip; the GitHub Actions checks run the collector
  tests with Python 3.8 and with the latest Python, the engine tests with the Jython of Autopsy 4.23.1, and rebuild
  the release zip and compare it with the one attached to the release. The zip also carries `tools/verify_case.py` and
  the Windows test procedure.
- **Requirements**: only the versions tested are declared: Autopsy 4.23.1 and, for the memory, Volatility 3 2.28.2
  with Python 3.8 or later.

## 1.2 (October 2026)

- **Memory.** The module can now use a memory image of the machine, analyzed with Volatility 3:
  - `collectors/collect_memory.py` runs ten Volatility 3 plugins (`windows.info`, `pslist`, `pstree`, `psscan`,
    `cmdline`, `netscan` or `netstat`, `sessions`, `envars`, `getsids`, `svcscan`) and keeps their JSON output
    unchanged, next to a manifest that records the version of Volatility, the SHA-256 of the image and the outcome of
    each plugin. It judges nothing. The release zip carries it in `TriageCompromissione/collectors/`.
  - The module finds that folder in the case, in the same data source or, paired by computer name, in another one,
    and fills checks 3, 4, 5 and 7 with the rules it applies to the disk, plus a few rules that make sense only in
    memory (*extra rules*): processes found only by the memory scan, system processes with an unexpected parent or in
    more than one copy, command interpreters started by a document program or a web server, Windows programs that
    should not connect to the Internet. Services that are in memory but no longer in the registry are judged too
    (checks 17 and 29). A Remote Desktop session open at the time of the acquisition is reported as context.
  - The report has the tables of the sessions, processes, network connections and SMB connections found in memory,
    and the *System* table names the memory image used, with its SHA-256. A Volatility plugin that produced nothing
    gives a coverage warning with the checks it leaves incomplete. *(Corrected in 1.3: the warning was given only for
    a plugin that failed, not for one that ended with no rows; version 1.3 checks that case too.)*
- Without memory, the note on checks 3-7 now says that a memory image analyzed with Volatility can fill them.
- Under the hood: the judgment of a process (`tc_eventi.giudica_processo`) is shared by events 4688/Sysmon and
  memory; new tests `tests/test_memoria.py` (Jython) and `tests/test_collect_memory.py` (Python 3), the latter also
  among the GitHub Actions checks.

Without memory, the results are identical to those of version 1.1 apart from the note on checks 3-7.

## 1.1 (October 2026)

- The results can be produced in English or in Italian: inbox message, results tree, HTML report and CSV. The
  language is chosen in the settings panel of the module (*Results language*), which is preset to the language of
  the system.
- The settings panel and the module description follow the language of the system: Italian on an Italian system,
  English everywhere else.
- The module is now listed as **Windows Compromise Triage** in every language (it was *Triage compromissione
  Windows*). Autopsy recognizes ingest modules by their name, so after the update it tells you that the module with
  the old name "could not be found", once for each place where the old name was saved (see *Troubleshooting* in the
  README). The saved settings are kept, and in a case analyzed with version 1.0 the old results are replaced as
  usual when the module is run again.
- The CSV file uses the comma as separator in English and keeps the semicolon in Italian.
- HTML report: short cells (a weight, a name, a date) no longer break in the middle of a word.
- A few Italian texts were corrected: "non è" was written with an apostrophe in three error messages, a warning
  and a note used a plural for a single event log, and the report's explanation of the "extra rule" label gave
  Meterpreter named pipes as an example, although those findings do not carry the label.
- Under the hood: every text shown to the analyst goes through `tc_lingua.tr()`, with the English translations in
  `tc_lingua_en.py`; `tools/check_translations.py` checks the catalog against the code; the tests of the rule engine
  are in `tests/`.

Apart from the corrected texts, in Italian the findings, weights, families, verdicts, tables and CSV are identical
to those of version 1.0.

## 1.0 (October 2026, not published)

- First version: the 41 checks of the compromise checklist on a disk image or on logical files, the verdict, the
  findings in the Autopsy tree, the HTML report and the CSV. Italian only.
