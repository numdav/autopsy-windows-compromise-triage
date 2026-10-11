#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests of collectors/collect_memory.py, the script that runs Volatility 3.

They need neither Volatility nor a memory image: a small fake Volatility,
written in a temporary folder, answers like the real one (the JSON renderer,
the error messages, the exit codes) and can be told to fail, to hang or to
print something that is not JSON. Run them with Python 3.8 or later:

    python3 tests/test_collect_memory.py

Exit status: 0 if all the checks pass.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.normpath(os.path.join(HERE, os.pardir, 'collectors', 'collect_memory.py'))

FAKE_VOLATILITY = r'''
import os, sys, time
args = sys.argv[1:]
if '-h' in args:
    print('Volatility 3 Framework 2.28.2')
    print('usage: vol [-h] ...')
    sys.exit(0)
plugin = args[-1]


def listed(variable):
    return plugin in [x for x in os.environ.get(variable, '').split(',') if x]


sys.stderr.write('Volatility 3 Framework 2.28.2\n')
if listed('FAKE_VOL_SLOW'):
    time.sleep(600)
if listed('FAKE_VOL_UNSATISFIED'):
    print('')
    print('Unsatisfied requirement plugins.Info.kernel.layer_name: ')
    sys.stderr.write("Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name']\n")
    sys.exit(1)
if listed('FAKE_VOL_FAIL'):
    sys.stdout.write('\n\n')
    sys.stderr.write('Volatility was unable to read a requested page:\nNo further results will be produced\n')
    sys.exit(1)
if listed('FAKE_VOL_GARBAGE'):
    print('this is not JSON')
    sys.exit(0)
path = os.path.join(os.environ['FAKE_VOL_DATA'], plugin + '.json')
if not os.path.isfile(path):
    sys.stderr.write('vol: error: argument PLUGIN: invalid choice %s\n' % plugin)
    sys.exit(2)
with open(path) as handle:
    sys.stdout.write(handle.read())
'''

PLUGINS = ['windows.info.Info', 'windows.pslist.PsList', 'windows.pstree.PsTree', 'windows.psscan.PsScan',
           'windows.cmdline.CmdLine', 'windows.netscan.NetScan', 'windows.netstat.NetStat',
           'windows.sessions.Sessions', 'windows.envars.Envars', 'windows.getsids.GetSIDs', 'windows.svcscan.SvcScan']
KEYS = ['info', 'pslist', 'pstree', 'psscan', 'cmdline', 'network', 'sessions', 'envars', 'getsids', 'svcscan']

checks = [0]
failures = []


def check(condition, what):
    checks[0] += 1
    if not condition:
        failures.append(what)
        print('FAILED: %s' % what)


def write_data(folder):
    """The output of every plugin, as the JSON renderer of Volatility writes it."""
    os.makedirs(folder)
    process = {'PID': 4, 'PPID': 0, 'ImageFileName': 'System', '__children': []}
    rows = {
        'windows.info.Info': [{'Variable': 'SystemTime', 'Value': '2026-09-28 14:05:12+00:00', '__children': []},
                              {'Variable': 'NtSystemRoot', 'Value': 'C:\\Windows', '__children': []}],
        'windows.pstree.PsTree': [dict(process, __children=[dict(process, PID=340, PPID=4)]),
                                  dict(process, PID=444, PPID=432)],
        'windows.envars.Envars': [{'PID': pid, 'Variable': 'COMPUTERNAME', 'Value': name, '__children': []}
                                  for pid, name in ((4, 'PC-A'), (340, 'PC-A'), (444, 'ZZ-OTHER'), (500, 'PC-A'))],
    }
    for plugin in PLUGINS:
        with open(os.path.join(folder, plugin + '.json'), 'w', encoding='ascii', newline='\n') as handle:
            handle.write('\n' + json.dumps(rows.get(plugin, [process]), indent=2, sort_keys=True) + '\n')


def run(work, arguments, **environment):
    """Runs the collector with the fake Volatility; returns (exit code, output)."""
    fake = os.path.join(work, 'fakevol.py')
    command = [sys.executable, COLLECTOR] + arguments
    if '--vol' not in arguments:
        command += ['--vol', '"%s" "%s"' % (sys.executable, fake)]
    env = dict(os.environ)
    env['FAKE_VOL_DATA'] = os.path.join(work, 'data')
    env.update(environment)
    result = subprocess.run(command, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    return result.returncode, result.stdout.decode('utf-8', 'replace')


def manifest_of(folder):
    with open(os.path.join(folder, 'compromise-triage-memory.json'), encoding='utf-8') as handle:
        return json.load(handle)


def sha256(path):
    with open(path, 'rb') as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main():
    try:
        sys.stdout.reconfigure(errors='backslashreplace')
    except (AttributeError, ValueError):
        pass
    work = tempfile.mkdtemp()
    try:
        with open(os.path.join(work, 'fakevol.py'), 'w', encoding='ascii') as handle:
            handle.write(FAKE_VOLATILITY)
        with open(os.path.join(work, 'notvol.py'), 'w', encoding='ascii') as handle:
            handle.write('print("hello")\n')
        write_data(os.path.join(work, 'data'))
        image = os.path.join(work, 'pc-a.raw')
        with open(image, 'wb') as handle:
            handle.write(os.urandom(3 * 1024 * 1024 + 17))

        # 1. everything works
        code, text = run(work, [image, '-o', 'all', '--lang', 'en'])
        folder = os.path.join(work, 'all')
        manifest = manifest_of(folder)
        check(code == 0, 'exit status 0 when every plugin works (%s)\n%s' % (code, text[-800:]))
        check(manifest['format'] == 'windows-compromise-triage/memory' and manifest['format_version'] == 1, 'format')
        check(manifest['complete'] is True and manifest['finished'], 'complete manifest')
        check([e['key'] for e in manifest['plugins']] == KEYS, 'one entry per key, in order: %s'
              % [e['key'] for e in manifest['plugins']])
        check(all(e['status'] == 'ok' for e in manifest['plugins']), 'every plugin ok')
        check(manifest['image']['sha256'] == sha256(image), 'SHA-256 of the image')
        check(manifest['image']['size'] == os.path.getsize(image), 'size of the image')
        check(manifest['host'] == {'computer_name': 'PC-A', 'system_time': '2026-09-28 14:05:12+00:00'},
              'computer name (the most frequent) and system time: %s' % manifest['host'])
        for entry in manifest['plugins']:
            path = os.path.join(folder, entry['file'])
            check(os.path.isfile(path) and entry['sha256'] == sha256(path), 'output and hash of %s' % entry['plugin'])
            check(os.path.isfile(os.path.join(folder, entry['log'])), 'log of %s' % entry['plugin'])
        tree = [e for e in manifest['plugins'] if e['key'] == 'pstree'][0]
        check(tree['rows'] == 3, 'nested rows are counted: %s' % tree['rows'])
        check(not [f for f in os.listdir(folder) if f.endswith('.part') or f.endswith('.tmp')], 'no temporary files')
        check(os.path.isfile(os.path.join(folder, 'collect_memory.log')), 'console log')
        with open(os.path.join(folder, 'windows.pslist.json'), encoding='ascii') as handle:
            with open(os.path.join(work, 'data', 'windows.pslist.PsList.json'), encoding='ascii') as original:
                check(handle.read() == original.read(), 'the output of Volatility is kept unchanged')

        # 2. a plugin fails (and netstat replaces netscan), one hangs, one prints something else
        code, text = run(work, [image, '-o', 'broken', '--timeout', '0.02', '--no-hash', '--lang', 'en'],
                         FAKE_VOL_FAIL='windows.netscan.NetScan,windows.getsids.GetSIDs',
                         FAKE_VOL_SLOW='windows.psscan.PsScan', FAKE_VOL_GARBAGE='windows.sessions.Sessions')
        manifest = manifest_of(os.path.join(work, 'broken'))
        status = [(e['key'], e['plugin'].split('.')[1], e['status']) for e in manifest['plugins']]
        check(code == 1, 'exit status 1 when some plugins fail (%s)' % code)
        check(manifest['image']['sha256'] is None, 'no hash with --no-hash')
        check(('psscan', 'psscan', 'timeout') in status, 'timeout: %s' % status)
        check(('network', 'netscan', 'failed') in status and ('network', 'netstat', 'ok') in status,
              'netstat after netscan: %s' % status)
        check(('sessions', 'sessions', 'failed') in status and ('getsids', 'getsids', 'failed') in status,
              'failures: %s' % status)
        errors = dict((e['plugin'], e['error']) for e in manifest['plugins'])
        check('unable to read a requested page' in errors['windows.netscan.NetScan'], 'error of Volatility kept')
        check('not the JSON' in errors['windows.sessions.Sessions'], 'output that is not JSON')
        check(not os.path.exists(os.path.join(work, 'broken', 'windows.sessions.json')), 'no file for a failed plugin')
        check(manifest['complete'] is True, 'the other plugins still ran')

        # 3. Volatility cannot analyze the image at all: stop after the first plugin
        code, text = run(work, [image, '-o', 'unsatisfied', '--no-hash', '--lang', 'en'],
                         FAKE_VOL_UNSATISFIED='windows.info.Info')
        manifest = manifest_of(os.path.join(work, 'unsatisfied'))
        check(code == 2 and len(manifest['plugins']) == 1 and manifest['complete'] is False,
              'stop when the requirements are not satisfied (%s, %d)' % (code, len(manifest['plugins'])))
        check('Unsatisfied requirement' in manifest['plugins'][0]['error'] or
              'Unable to validate' in manifest['plugins'][0]['error'], 'reason of the stop')

        # 4. what must not start
        os.makedirs(os.path.join(work, 'busy'))
        with open(os.path.join(work, 'busy', 'keep.txt'), 'w') as handle:
            handle.write('x')
        code, text = run(work, [image, '-o', 'busy'])
        check(code == 2 and os.listdir(os.path.join(work, 'busy')) == ['keep.txt'], 'output folder not empty')
        code, text = run(work, [os.path.join(work, 'missing.raw'), '-o', 'none'])
        check(code == 2 and not os.path.exists(os.path.join(work, 'none')), 'missing image')
        code, text = run(work, [image, '-o', 'notvol', '--vol', '"%s" "%s"' % (sys.executable, os.path.join(work, 'notvol.py'))])
        check(code == 2 and not os.path.exists(os.path.join(work, 'notvol')), 'a command that is not Volatility')

        # 5. default folder and Italian messages
        code, text = run(work, [image, '--no-hash', '--lang', 'it'])
        check(code == 0 and os.path.isdir(os.path.join(work, 'pc-a_vol3')), 'default output folder')
        check('Riepilogo' in text and 'Plugin completati: 10 su 10' in text, 'messages in Italian')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print('collect_memory: %d checks, %d failed' % (checks[0], len(failures)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
