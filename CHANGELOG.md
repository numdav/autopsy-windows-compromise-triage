# Changelog

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
