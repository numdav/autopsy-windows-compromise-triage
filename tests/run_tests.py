# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""Run the tests of the triage engine with Jython 2.7, the Python that Autopsy uses.

The tests need neither Autopsy nor any evidence file: they feed command lines,
service definitions and synthetic timestamps to the rule engine and compare the
outcome with the expected one. Run them after changing tc_regole.py or the
English catalog:

    java -jar jython-standalone-2.7.4.jar tests/run_tests.py [-v] [name ...]

The jar is inside every Autopsy installation (autopsy/modules/ext); on Windows
Autopsy also ships a Java runtime (jre/bin), so there nothing has to be
downloaded. -v prints the output of every test, a name runs only the tests
whose file name contains it. Exit status: 0 if all the tests pass.
"""

import os
import re
import sys
import time
import traceback

sys.dont_write_bytecode = True      # no $py.class files next to the sources

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.normpath(os.path.join(HERE, os.pardir, 'TriageCompromissione'))
sys.path.insert(0, PLUGIN)
sys.path.insert(0, HERE)

# (file, patterns that must all match the output of the test)
TESTS = [
    ('test_comandi.py', [r'comandi: (\d+) casi su \1 corretti', r'powershell: (\d+) casi su \1 corretti']),
    ('test_regole.py', [r'casi sbagliati: 0\s*$']),
    ('test_regole_riviste.py', [r'prove fallite 0\s*$']),
    ('test_nominati.py', [r'sbagliati 0\s*$']),
    ('test_offuscati.py', [r'(?m)^sbagliati 0$']),
    ('test_comandi_nuovi.py', [r'sbagliati 0\s*$']),
    ('test_avvio.py', [r'sbagliati 0\s*$']),
    ('test_ricerche.py', [r'prove fallite 0\s*$']),
    ('test_wmi_consumer.py', [r'sbagliati 0\s*$']),
    ('test_tempi.py', [r'fallite 0\s*$']),
    ('test_lingua.py', [r'prove fallite 0\s*$']),
    ('test_memoria.py', [r'memoria: (\d+) prove, prove fallite 0\s*$']),
    ('test_evtx.py', [r'evtx: prove riuscite \d+, prove fallite 0\s*$']),
    ('test_verdetto.py', [r'verdetto: prove riuscite \d+, prove fallite 0\s*$']),
]


class Capture(object):
    """Collects what a test prints (byte strings and unicode alike)."""

    def __init__(self):
        self.parts = []

    def write(self, text):
        if isinstance(text, unicode):
            text = text.encode('utf-8')
        self.parts.append(text)

    def flush(self):
        pass

    def text(self):
        return ''.join(self.parts)


def emit(line):
    """Print captured output (UTF-8 bytes) in the encoding of the console, so
    that accented letters neither stop the run nor come out garbled."""
    text = line.decode('utf-8', 'replace')
    try:
        print text.encode(getattr(sys.stdout, 'encoding', None) or 'utf-8', 'replace')
    except (LookupError, UnicodeError):
        print text.encode('ascii', 'replace')


def run(name, patterns, verbose):
    import tc_lingua
    tc_lingua.imposta(tc_lingua.ITALIANO)       # every test starts in Italian
    path = os.path.join(HERE, name)
    capture = Capture()
    saved = sys.stdout
    started = time.time()
    crashed = False
    sys.stdout = capture
    try:
        try:
            execfile(path, {'__name__': '__main__', '__file__': path})
        except SystemExit:
            pass
        except BaseException:
            crashed = True
            capture.write(traceback.format_exc())
    finally:
        sys.stdout = saved
    output = capture.text()
    missing = [p for p in patterns if re.search(p, output) is None]
    passed = not crashed and not missing
    last = output.rstrip().split('\n')[-1][:100] if output.strip() else '(no output)'
    emit('%s  %-26s %5.1f s  %s' % ('ok  ' if passed else 'FAIL', name, time.time() - started, last))
    if verbose or not passed:
        for line in output.rstrip().split('\n')[-(200 if verbose else 25):]:
            emit('      | ' + line)
    return passed


def main(arguments):
    verbose = '-v' in arguments
    wanted = [a for a in arguments if not a.startswith('-')]
    if not os.path.isfile(os.path.join(PLUGIN, 'tc_regole.py')):
        print 'Plugin sources not found in %s' % PLUGIN
        return 2
    print 'Jython %s - plugin sources: %s' % (sys.version.split()[0], PLUGIN)
    failed = 0
    done = 0
    for name, patterns in TESTS:
        if wanted and not [w for w in wanted if w in name]:
            continue
        done += 1
        if not run(name, patterns, verbose):
            failed += 1
    print '%d test file(s) run, %d failed' % (done, failed)
    return 1 if failed or not done else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
