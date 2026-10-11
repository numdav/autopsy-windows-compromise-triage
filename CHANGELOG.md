# Changelog

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
    gives a coverage warning with the checks it leaves incomplete.
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
