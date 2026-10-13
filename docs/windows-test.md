# Testing the module on a Windows workstation

The module has been tested inside Autopsy 4.23.1 **on Linux only**. On Windows Autopsy is the same program, but the
installation (the MSI package with its own Java), the user folder (`%APPDATA%\autopsy`), the paths, the antivirus
or EDR, the permissions of the account and the disks of the cases are different. Windows support can be claimed
only for the combinations (workstation, Windows version, Autopsy version) tested this way.

Run one test for each combination in use. It takes about 30 minutes the first time, 15 the following times.

## What you need

- The release zip `TriageCompromissione-<version>.zip` and its SHA-256, published in the release notes.
- `verify_case.py`, attached to the release and also in the zip (`TriageCompromissione\tools\verify_case.py`), and
  Python 3.8 or later to run it (`py -3`). Without Python the criteria can be checked by hand (step 9b).
- A test data source that you know well and that is not an open case: the image or the collection of a Windows
  machine you have already analyzed, preferably with a few findings (so that the findings and the report are not
  empty). A KAPE collection added as logical files is fine.
- The sheet [windows-test-sheet.csv](windows-test-sheet.csv) to write down the results.

## Steps

1. Write down the environment in the sheet: name of the workstation; Windows (Windows key + R, `winver`: edition,
   version, build); Autopsy (**Help > About**: version and Java); whether the account is an administrator; the
   antivirus or EDR in use; the disk where the cases are (local or network).
2. Check the package. In PowerShell, in the folder of the zip:

   ```
   Get-FileHash .\TriageCompromissione-<version>.zip -Algorithm SHA256
   ```

   The value must be the one in the release notes. If it is different, stop: it is not the package that was tested.
3. Install as the README says: in Autopsy, **Tools > Python Plugins** opens the `python_modules` folder; close
   Autopsy, extract the zip into that folder so that `python_modules\TriageCompromissione\TriageCompromissione.py`
   exists, and open Autopsy again.
4. Create a new case, single-user, on a local disk, in a new folder, named
   `Test_TC_<Autopsy version>_<workstation>` (for example `Test_TC_4.23.1_FOR03`).
5. **Test A (the module alone).** Add Data Source with the test data source. In the page of the ingest modules untick
   everything and leave only **Windows Compromise Triage**. Before going on, check that the module is listed: if it
   is not, step 3 did not work (see *Troubleshooting* in the README).
6. Wait for the end of the analysis (the progress bar at the bottom right). Write down every error window and the
   messages of the ingest inbox (the envelope at the top right) that say "Triage failed".
7. Look at the results: in the tree, **Analysis Results** with the verdict and the findings of the module; **Reports**
   with the HTML report, which must open and show the same verdict.
8. Close the case (**Case > Close Case**) and close Autopsy: the script reads the database of the case, which must be
   closed.
9. Check. In a command prompt, in the `tools` folder:

   ```
   py -3 verify_case.py "C:\Cases\Test_TC_4.23.1_FOR03_20261013_101500" --json result_A.json --user-log "%APPDATA%\autopsy\var\log\autopsy.log.0"
   ```

   (the folder is the one of the case, which holds the `.aut` file). The last line says `RESULT: PASSED` or
   `RESULT: FAILED`; above it are the criteria and the reasons.

   **9b.** Without Python, check by hand:
   - C1: the module is listed with the version of the release (in the ingest modules window, or in the case log);
   - C2: the analysis reached the end without being cancelled;
   - C3: in the case log (`<case folder>\Log\autopsy.log.0`) there is no `SEVERE` or `WARNING` line right under a line
     that contains `TriageCompromissioneModule`, and no Python traceback;
   - C4: the numbers of decisive findings and findings to confirm written in the verdict are those you see among the
     results;
   - C5: the HTML report and the CSV file are in `Reports\TriageCompromissione`, the report shows the verdict and the
     heuristic warning at the top, and it is listed under **Reports** in the tree.
10. **Test B (together with the other modules).** A new case, same data source, with the modules you usually use (your
    usual profile) plus Windows Compromise Triage. Repeat steps 6-9 with `--json result_B.json`, then:

    ```
    py -3 verify_case.py <folder of case B> --reference result_A.json
    ```

    The last part says whether the findings of the module are identical to those of test A. If they are not, write
    down the differences: they may have an explanation (for example files extracted by other modules), but they must
    be looked at.
11. **Test C (control)**, only if test B fails or shows errors: the same case B without the module (untick it). If the
    error remains, it comes from the environment or from another module, not from this one.
12. **Test D (the engine with the Java and the Jython of that Autopsy)**, recommended. In the folder of the
    repository:

    ```
    "C:\Program Files\Autopsy-4.23.1\jre\bin\java.exe" -jar "C:\Program Files\Autopsy-4.23.1\autopsy\modules\ext\jython-standalone-2.7.4.jar" tests\run_tests.py
    ```

    (adjust the paths to your installation). All the tests must pass.
13. Fill in the sheet and keep the sheet, `result_A.json`, `result_B.json` and any screenshots of errors together.

## When a test passes

Autopsy did not close by itself and showed no error of the module, and the script says `PASSED` (C1-C5 all OK). For
test B the findings must also be those of test A, or every difference must be explained.

## How to classify a problem

- **module**: it appears with the module and disappears without it (test C), or the log or the stack trace point to the
  files of the module (`TriageCompromissione`, `tc_*.py`);
- **environment**: it appears without the module too, or the workstation explains it (an antivirus that blocks or
  quarantines files, permissions, a full disk, memory, two instances of Autopsy open at the same time), with the
  evidence;
- **to be clarified**: everything else. Nothing is discarded: everything goes in the sheet.

## To watch on Windows (possible risks, not verified)

- antivirus or EDR: they may block or quarantine files of the test data source (for example attack tools in a
  collection), or the `.class` files that Jython writes next to the module; write down warnings and quarantines;
- very long paths in KAPE collections (more than 260 characters);
- two instances of Autopsy open at the same time: on Linux they copy their native libraries into the same temporary
  folder of the user, and one of them aborts; avoid it during the tests;
- cases on a network disk and multi-user cases: outside the tests done so far, write them down separately.
