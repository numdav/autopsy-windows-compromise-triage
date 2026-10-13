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
missing = [x for x in os.environ.get('FAKE_VOL_MISSING', '').split(',') if x]
if '-h' in args:
    # as the real one: the version, the usage, the options and, at the end, the plugins it could load
    print('Volatility 3 Framework %s' % os.environ.get('FAKE_VOL_VERSION', '2.28.2'))
    print('usage: vol [-h] [-c CONFIG] ... PLUGIN ...')
    print('')
    print('options:')
    print('  -h, --help            Show this help message and exit')
    print('')
    print('Plugins:')
    print('  For plugin specific options, run \'vol <plugin> --help\'')
    print('')
    print('  plugin')
    if not os.environ.get('FAKE_VOL_NOLIST'):
        for name in sorted(os.environ['FAKE_VOL_PLUGINS'].split(',') + ['windows.dlllist.DllList',
                           'windows.handles.Handles', 'windows.malware.malfind.Malfind']):
            if name in missing:
                continue
            if len(name) > 18:
                print('    %s' % name)
                print('                        Lists something of the memory image.')
            else:
                print('    %-18s  Lists something of the memory image.' % name)
    sys.exit(0)
plugin = args[-1]


def listed(variable):
    return plugin in [x for x in os.environ.get(variable, '').split(',') if x]


sys.stderr.write('Volatility 3 Framework 2.28.2\n')
if plugin in missing:
    sys.stderr.write("vol: error: argument PLUGIN: invalid choice %s (choose from banners.Banners, ...)\n" % plugin)
    sys.exit(2)
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


BOOT = '2026-09-28T08:00:00+00:00'


def write_data(folder, complete=True):
    """The output of every plugin, as the JSON renderer of Volatility writes it.
    complete: what a running Windows always has (dozens of processes with the
    system ones, a listening port, hundreds of services and variables);
    otherwise the little of a truncated image."""
    os.makedirs(folder)
    process = {'PID': 4, 'PPID': 0, 'ImageFileName': 'System', 'CreateTime': BOOT, 'ExitTime': None, 'Threads': 150,
               '__children': []}
    names = ['System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe'] + ['svchost.exe'] * 24
    processes = [dict(process, PID=4 if i == 0 else 100 + 4 * i, PPID=0 if i == 0 else 4, ImageFileName=name)
                 for i, name in enumerate(names if complete else names[:1])]
    computer = [{'PID': pid, 'Variable': 'COMPUTERNAME', 'Value': name, '__children': []}
                for pid, name in ((4, 'PC-A'), (340, 'PC-A'), (444, 'ZZ-OTHER'), (500, 'PC-A'))]
    rows = {
        'windows.info.Info': [{'Variable': 'SystemTime', 'Value': '2026-09-28 14:05:12+00:00', '__children': []},
                              {'Variable': 'NtSystemRoot', 'Value': 'C:\\Windows', '__children': []}],
        'windows.pslist.PsList': processes,
        'windows.psscan.PsScan': processes,
        'windows.pstree.PsTree': [dict(process, __children=[dict(process, PID=340, PPID=4)]),
                                  dict(process, PID=444, PPID=432)],
        'windows.cmdline.CmdLine': [{'PID': r['PID'], 'Process': r['ImageFileName'],
                                     'Args': None if r['PID'] == 4 else 'C:\\Windows\\System32\\%s' % r['ImageFileName'],
                                     '__children': []} for r in processes] if complete else [
                                    {'PID': 4, 'Process': 'System', 'Args': None, '__children': []},
                                    {'PID': 340, 'Process': 'smss.exe', 'Args': 'Required memory at 0x7ffd1000 is not valid',
                                     '__children': []}],
        'windows.netscan.NetScan': [{'Proto': 'TCPv4', 'LocalAddr': '0.0.0.0', 'LocalPort': 135, 'ForeignAddr': '*',
                                     'ForeignPort': 0, 'State': 'LISTENING' if complete else 'ESTABLISHED',
                                     'PID': 104, '__children': []}],
        'windows.svcscan.SvcScan': [{'Name': 'Service%d' % i, 'State': 'SERVICE_RUNNING', '__children': []}
                                    for i in range(120 if complete else 1)],
        'windows.envars.Envars': computer + [{'PID': 4, 'Variable': 'VARIABLE%d' % i, 'Value': 'x', '__children': []}
                                             for i in range(116 if complete else 0)],
    }
    rows['windows.netstat.NetStat'] = rows['windows.netscan.NetScan']
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
    env['FAKE_VOL_PLUGINS'] = ','.join(PLUGINS)
    env.update(environment)
    result = subprocess.run(command, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    return result.returncode, result.stdout.decode('utf-8', 'replace')


def manifest_of(folder):
    with open(os.path.join(folder, 'compromise-triage-memory.json'), encoding='utf-8') as handle:
        return json.load(handle)


def sha256(path):
    with open(path, 'rb') as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def check_hidden(work):
    """plausibility() on its own, with outputs written here."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('collect_memory', COLLECTOR)
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    folder = os.path.join(work, 'hidden')
    os.makedirs(folder)
    names = ['System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe'] + ['svchost.exe'] * 24
    listed = [{'PID': 4 if i == 0 else 100 + 4 * i, 'ImageFileName': name, 'CreateTime': BOOT, 'ExitTime': None,
               'Threads': 10} for i, name in enumerate(names)]
    hidden = [{'PID': 900 + i, 'ImageFileName': 'x.exe', 'CreateTime': '2026-09-28T09:00:00+00:00', 'ExitTime': None,
               'Threads': 3} for i in range(6)]
    earlier = [{'PID': 950 + i, 'ImageFileName': 'y.exe', 'CreateTime': '2026-09-27T09:00:00+00:00',
                'ExitTime': None, 'Threads': 3} for i in range(20)]
    for name, rows in (('pslist.json', listed), ('psscan.json', listed + hidden + earlier),
                       ('psscan5.json', listed + hidden[:5] + earlier)):
        with open(os.path.join(folder, name), 'w', encoding='ascii') as handle:
            json.dump(rows, handle)
    entries = [{'key': 'pslist', 'status': 'ok', 'file': 'pslist.json'},
               {'key': 'psscan', 'status': 'ok', 'file': 'psscan.json'}]
    check(collector.plausibility(folder, entries) == ['psscan finds 6 active processes that pslist does not list'],
          'hidden processes: %s' % collector.plausibility(folder, entries))
    check(collector.plausibility(folder, entries, 'it') == ['psscan trova 6 processi attivi che pslist non elenca'],
          'hidden processes in Italian: %s' % collector.plausibility(folder, entries, 'it'))
    entries[1]['file'] = 'psscan5.json'
    check(collector.plausibility(folder, entries) == [], 'five or fewer, or of an earlier boot: not anomalous')
    check(collector.seconds_of('2026-09-28T08:00:00.123456+00:00') == collector.seconds_of(BOOT) + 0.123456
          and collector.seconds_of('2026-09-28 08:00:00') == collector.seconds_of(BOOT)
          and collector.seconds_of('') is None and collector.seconds_of('N/A') is None, 'times of Volatility')


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
        write_data(os.path.join(work, 'data_small'), complete=False)
        os.makedirs(os.path.join(work, 'symbols', 'windows', 'ntkrnlmp.pdb'))
        with open(os.path.join(work, 'symbols', 'windows', 'ntkrnlmp.pdb', '0123ABCD-1.json.xz'), 'wb') as handle:
            handle.write(b'x')
        image = os.path.join(work, 'pc-a.raw')
        with open(image, 'wb') as handle:
            handle.write(os.urandom(3 * 1024 * 1024 + 17))

        # 1. everything works (local symbols: no check of the symbol server)
        code, text = run(work, [image, '-o', 'all', '-s', 'symbols', '--lang', 'en'])
        folder = os.path.join(work, 'all')
        manifest = manifest_of(folder)
        check(code == 0, 'exit status 0 when every plugin works (%s)\n%s' % (code, text[-800:]))
        check(manifest['format'] == 'windows-compromise-triage/memory' and manifest['format_version'] == 1, 'format')
        check(manifest['complete'] is True and manifest['finished'], 'complete manifest')
        preflight = manifest.get('preflight') or {}
        check(preflight.get('volatility') == '2.28.2' and preflight.get('volatility_older') is False
              and preflight.get('plugins_missing') == [] and preflight.get('warnings') == []
              and preflight.get('python') and preflight.get('free_space'), 'preflight in the manifest: %s' % preflight)
        check((preflight.get('symbols') or {}).get('tables') == 1, 'symbol tables counted: %s' % preflight.get('symbols'))
        check('Preflight check' in text and 'Plugins: all available (11)' in text, 'preflight on the screen')
        check(manifest.get('plausibility', {}).get('anomalies') == [], 'plausible output: %s'
              % manifest.get('plausibility'))
        check('anomalous' not in text and 'WARNING' not in text, 'no warning when everything works')
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
        code, text = run(work, [image, '-o', 'broken', '--timeout', '0.02', '--no-hash', '--offline', '--lang', 'en'],
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
        check('Network: windows.netscan did not work' in text and 'windows.netstat was used instead' in text,
              'the summary says that netstat replaced netscan')
        check('WARNING: offline and without --symbols' in text and
              manifest['preflight']['warnings'] == ['offline without local symbols'], 'offline without symbols')

        # 3. Volatility cannot analyze the image at all: stop after the first plugin
        code, text = run(work, [image, '-o', 'unsatisfied', '--no-hash', '--offline', '--lang', 'en'],
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
        code, text = run(work, [image, '--no-hash', '-s', 'symbols', '--lang', 'it'])
        check(code == 0 and os.path.isdir(os.path.join(work, 'pc-a_vol3')), 'default output folder')
        check('Riepilogo' in text and 'Plugin completati: 10 su 10' in text and 'Controllo preliminare' in text,
              'messages in Italian')

        # 6. an older Volatility without svcscan (as 2.4.1 without yara-python): said before and after, not run
        code, text = run(work, [image, '-o', 'old', '--no-hash', '-s', 'symbols', '--lang', 'en'],
                         FAKE_VOL_VERSION='2.4.1', FAKE_VOL_MISSING='windows.svcscan.SvcScan')
        manifest = manifest_of(os.path.join(work, 'old'))
        preflight = manifest['preflight']
        check(code == 1 and preflight['volatility_older'] is True
              and preflight['plugins_missing'] == ['windows.svcscan.SvcScan'], 'older Volatility: %s %s' % (code, preflight))
        check(text.count('WARNING: Volatility 2.4.1 is older than the version tested (2.28.2)') == 2,
              'the warning about the version is repeated in the summary')
        service = [e for e in manifest['plugins'] if e['key'] == 'svcscan']
        check(len(service) == 1 and service[0]['status'] == 'failed' and service[0]['exit_code'] is None
              and service[0]['error'].startswith('not available in this Volatility'), 'plugin not run: %s' % service)
        check('NOT AVAILABLE in this Volatility: skipped' in text and not
              os.path.exists(os.path.join(work, 'old', 'logs', 'windows.svcscan.log')), 'skipped plugin')

        # 7. the list of plugins cannot be read: every plugin is tried, a missing one says so clearly
        code, text = run(work, [image, '-o', 'nolist', '--no-hash', '-s', 'symbols', '--lang', 'en'],
                         FAKE_VOL_NOLIST='1', FAKE_VOL_MISSING='windows.getsids.GetSIDs')
        manifest = manifest_of(os.path.join(work, 'nolist'))
        sids = [e for e in manifest['plugins'] if e['key'] == 'getsids'][0]
        check(code == 1 and manifest['preflight']['plugins_missing'] is None and sids['exit_code'] == 2
              and sids['error'] == 'not available in this Volatility (the plugin is missing or cannot be loaded)',
              'invalid choice: %s %s' % (code, sids))
        check('Plugins: the list of this Volatility could not be read' in text, 'list not read')

        # 8. the output of a truncated image: every plugin works, but it is not what a running Windows has
        code, text = run(work, [image, '-o', 'small', '--no-hash', '-s', 'symbols', '--lang', 'en'],
                         FAKE_VOL_DATA=os.path.join(work, 'data_small'))
        manifest = manifest_of(os.path.join(work, 'small'))
        anomalies = manifest['plausibility']['anomalies']
        check(code == 1 and all(e['status'] == 'ok' for e in manifest['plugins']), 'exit status 1 (%s)' % code)
        check(anomalies == ['only 1 active processes in pslist',
                            'processes that a running Windows always has are missing: smss.exe, csrss.exe, '
                            'wininit.exe, services.exe, lsass.exe',
                            'no readable command line in cmdline (processes: 2)',
                            'no listening port in windows.netscan', 'only 1 services in svcscan',
                            'only 4 environment variables in envars'], 'anomalies: %s' % anomalies)
        check('WARNING: anomalous or possibly incomplete output (only 1 active processes in pslist;' in text,
              'anomaly in the summary')
        check('Plugins completed: 10 of 10, but their output looks anomalous' in text
              and 'Plugins completed: 10 of 10\n' not in text, 'never a bare "10 of 10" on an anomalous output')

        # 8b. the same in Italian: the warning is all in Italian, the manifest keeps the anomalies in English
        code, text = run(work, [image, '-o', 'small_it', '--no-hash', '-s', 'symbols', '--lang', 'it'],
                         FAKE_VOL_DATA=os.path.join(work, 'data_small'))
        manifest = manifest_of(os.path.join(work, 'small_it'))
        check(code == 1 and manifest['plausibility']['anomalies'] == anomalies, 'anomalies of the manifest in English')
        check('ATTENZIONE: output anomalo o forse incompleto (solo 1 processi attivi in pslist; mancano processi che '
              'un Windows acceso ha sempre: smss.exe' in text and 'nessuna riga di comando leggibile in cmdline '
              '(processi: 2); nessuna porta in ascolto in windows.netscan; solo 1 servizi in svcscan; solo 4 variabili '
              "d'ambiente in envars)" in text, 'anomalies in Italian')
        check('active processes' not in text and 'listening port' not in text and 'environment variables' not in text,
              'no English in the Italian summary')
        check('Plugin completati: 10 su 10, ma il loro output sembra anomalo' in text, 'qualified count in Italian')

        # 9. processes found by psscan and not by pslist: hidden ones count, those of an earlier boot do not
        check_hidden(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print('collect_memory: %d checks, %d failed' % (checks[0], len(failures)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
