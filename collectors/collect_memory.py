#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run Volatility 3 on a Windows memory image and save the results for the
Autopsy module "Windows Compromise Triage".

This script only collects. It runs a fixed set of Volatility 3 plugins with
the JSON renderer and keeps their output unchanged, next to a manifest
(compromise-triage-memory.json) that records what was run, with which
version of Volatility, on which image (with its SHA-256) and how each plugin
ended. It judges nothing: the Autopsy module reads the folder and applies its
own rules, the same ones it applies to the disk.

    python3 collect_memory.py MEMORY_IMAGE [-o OUTPUT_FOLDER]

Then add OUTPUT_FOLDER to the Autopsy case as "Logical Files" and run the
module on the disk of the same computer (or on the folder alone). See the
README, section "Memory (Volatility 3)".

Requirements: Python 3.8 or later and Volatility 3 2.4 or later
(pip install volatility3), importable by this Python or available as the
"vol" command (or given with --vol). On the first analysis of a Windows build
Volatility downloads the kernel symbols from Microsoft; on a computer without
Internet access use --symbols with a local symbol pack and --offline.

Exit status: 0 if every plugin worked, 1 if some failed (the folder is still
usable: the module reports what is missing), 2 if nothing could be run.
"""

import argparse
import collections
import datetime
import hashlib
import json
import locale
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time

VERSION = '1.2'
MANIFEST = 'compromise-triage-memory.json'
FORMAT = 'windows-compromise-triage/memory'
FORMAT_VERSION = 1

# What the module reads, in the order it is collected. For each key the
# plugins are tried in order and the first one that works is kept: netscan
# finds also the connections already closed, netstat is the fallback.
STEPS = [
    ('info', ('windows.info.Info',)),
    ('pslist', ('windows.pslist.PsList',)),
    ('pstree', ('windows.pstree.PsTree',)),
    ('psscan', ('windows.psscan.PsScan',)),
    ('cmdline', ('windows.cmdline.CmdLine',)),
    ('network', ('windows.netscan.NetScan', 'windows.netstat.NetStat')),
    ('sessions', ('windows.sessions.Sessions',)),
    ('envars', ('windows.envars.Envars',)),
    ('getsids', ('windows.getsids.GetSIDs',)),
    ('svcscan', ('windows.svcscan.SvcScan',)),
]

# The code that starts Volatility when it is installed in this Python.
VOL_FROM_PYTHON = 'import sys; sys.argv[0] = "vol"; from volatility3.cli import main; main()'

TEXTS = {
    'description': {
        'en': 'Runs Volatility 3 on a Windows memory image and saves the results for the Autopsy module '
              '"Windows Compromise Triage". It only collects: the module does the analysis.',
        'it': 'Esegue Volatility 3 su un\'immagine della memoria di Windows e salva i risultati per il modulo '
              'di Autopsy "Windows Compromise Triage". Raccoglie soltanto: l\'analisi la fa il modulo.'},
    'h_image': {'en': 'the memory image (raw, .mem, .vmem, crash dump...)',
                'it': 'l\'immagine della memoria (raw, .mem, .vmem, crash dump...)'},
    'h_output': {'en': 'folder for the results (default: <image name>_vol3 in the current folder); it must not '
                       'exist or be empty',
                 'it': 'cartella dei risultati (predefinita: <nome immagine>_vol3 nella cartella corrente); non deve '
                       'esistere o deve essere vuota'},
    'h_vol': {'en': 'how to start Volatility 3, for example "vol" or "python3 C:\\vol3\\vol.py" (default: the '
                    'volatility3 package of this Python, otherwise the "vol" command)',
              'it': 'come avviare Volatility 3, per esempio "vol" oppure "python3 C:\\vol3\\vol.py" (predefinito: il '
                    'pacchetto volatility3 di questo Python, altrimenti il comando "vol")'},
    'h_symbols': {'en': 'folder with Volatility symbol tables (passed to Volatility as -s)',
                  'it': 'cartella con le tabelle dei simboli di Volatility (passata a Volatility come -s)'},
    'h_offline': {'en': 'do not let Volatility download symbols from the Internet',
                  'it': 'non lasciare che Volatility scarichi i simboli da Internet'},
    'h_no_hash': {'en': 'do not compute the SHA-256 of the image (faster, but the manifest will not identify it)',
                  'it': 'non calcolare lo SHA-256 dell\'immagine (pi\u00f9 veloce, ma il manifesto non la identifica)'},
    'h_timeout': {'en': 'minutes after which a plugin is stopped (default 120, 0 = never)',
                  'it': 'minuti dopo i quali un plugin viene fermato (predefinito 120, 0 = mai)'},
    'h_lang': {'en': 'language of the messages (default: the one of the system)',
               'it': 'lingua dei messaggi (predefinita: quella del sistema)'},
    'title': {'en': 'Windows Compromise Triage - memory collection with Volatility 3 (collector %s)',
              'it': 'Windows Compromise Triage - raccolta dalla memoria con Volatility 3 (raccoglitore %s)'},
    'no_image': {'en': 'The memory image does not exist or is not a file: %s',
                 'it': 'L\'immagine della memoria non esiste o non \u00e8 un file: %s'},
    'empty_image': {'en': 'The memory image is empty: %s', 'it': 'L\'immagine della memoria \u00e8 vuota: %s'},
    'output_busy': {'en': 'The output folder already exists and is not empty: %s\nChoose another one with -o.',
                    'it': 'La cartella dei risultati esiste gi\u00e0 e non \u00e8 vuota: %s\nScegline un\'altra con -o.'},
    'no_vol': {'en': 'Volatility 3 not found. Install it (pip install volatility3) or say how to start it with '
                     '--vol, for example --vol "python3 C:\\volatility3\\vol.py".',
               'it': 'Volatility 3 non trovato. Installalo (pip install volatility3) oppure indica come avviarlo con '
                     '--vol, per esempio --vol "python3 C:\\volatility3\\vol.py".'},
    'bad_vol': {'en': 'The command does not start Volatility 3: %s\n%s',
                'it': 'Il comando non avvia Volatility 3: %s\n%s'},
    'vol_found': {'en': 'Volatility 3 %s: %s', 'it': 'Volatility 3 %s: %s'},
    'image': {'en': 'Image: %s (%s)', 'it': 'Immagine: %s (%s)'},
    'output': {'en': 'Results: %s', 'it': 'Risultati: %s'},
    'hashing': {'en': 'SHA-256 of the image...', 'it': 'SHA-256 dell\'immagine...'},
    'hash_progress': {'en': '  %d%%', 'it': '  %d%%'},
    'hash_done': {'en': 'SHA-256: %s (%.0f s)', 'it': 'SHA-256: %s (%.0f s)'},
    'hash_error': {'en': 'The image cannot be read: %s', 'it': 'L\'immagine non si legge: %s'},
    'running': {'en': '[%d/%d] %s', 'it': '[%d/%d] %s'},
    'ok': {'en': '      done: %d rows, %.0f s', 'it': '      fatto: %d righe, %.0f s'},
    'failed': {'en': '      FAILED (%.0f s): %s', 'it': '      NON RIUSCITO (%.0f s): %s'},
    'timeout': {'en': '      STOPPED after %g minutes', 'it': '      FERMATO dopo %g minuti'},
    'fallback': {'en': '      trying %s instead', 'it': '      provo invece %s'},
    'requirements': {
        'en': 'Volatility cannot analyze this image: it found neither a Windows kernel nor its symbols. Check that '
              'the file is a memory image of Windows and, if the computer is offline, use --symbols with the '
              'Windows symbol pack. The other plugins would fail in the same way: stopping here.',
        'it': 'Volatility non riesce ad analizzare l\'immagine: non trova un kernel di Windows o i suoi simboli. '
              'Controlla che il file sia un\'immagine della memoria di Windows e, se il computer non ha Internet, '
              'usa --symbols con il pacchetto dei simboli di Windows. Gli altri plugin fallirebbero allo stesso modo: '
              'mi fermo qui.'},
    'interrupted': {'en': 'Interrupted: the folder contains what was collected so far.',
                    'it': 'Interrotto: la cartella contiene quello che \u00e8 stato raccolto fin qui.'},
    'summary': {'en': 'Summary', 'it': 'Riepilogo'},
    'computer': {'en': 'Computer (from the memory): %s', 'it': 'Computer (dalla memoria): %s'},
    'unknown': {'en': 'not found', 'it': 'non trovato'},
    'system_time': {'en': 'System time in the memory: %s', 'it': 'Ora di sistema nella memoria: %s'},
    'plugins_ok': {'en': 'Plugins completed: %d of %d', 'it': 'Plugin completati: %d su %d'},
    'plugins_failed': {'en': 'Not completed: %s (the module will report what is missing)',
                       'it': 'Non completati: %s (il modulo segnaler\u00e0 cosa manca)'},
    'next': {'en': 'Next: in Autopsy add this folder to the case (Add Data Source > Logical Files), then run '
                   '"Windows Compromise Triage" on the disk of the same computer, or on this folder alone.',
             'it': 'Poi: in Autopsy aggiungi questa cartella al caso (Add Data Source > Logical Files) ed esegui '
                   '"Windows Compromise Triage" sul disco dello stesso computer, oppure su questa cartella da sola.'},
    'nothing': {'en': 'No plugin worked: there is nothing the module can use.',
                'it': 'Nessun plugin \u00e8 riuscito: non c\'\u00e8 nulla che il modulo possa usare.'},
}

LANGUAGE = 'en'


def say(key, *values):
    text = TEXTS[key][LANGUAGE]
    return text % values if values else text


def system_language():
    """'it' if the user works in Italian, otherwise 'en'."""
    for variable in ('LC_ALL', 'LC_MESSAGES', 'LANG', 'LANGUAGE'):
        value = os.environ.get(variable)
        if value:
            return 'it' if value.lower().startswith('it') else 'en'
    if os.name == 'nt':
        try:
            import ctypes
            # the primary language of the user interface: 0x10 is Italian
            return 'it' if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3ff == 0x10 else 'en'
        except Exception:
            pass
    try:
        name = locale.getlocale()[0] or ''
    except Exception:
        name = ''
    return 'it' if name.lower().startswith('it') else 'en'


class Console(object):
    """Prints a message and keeps it for the log file of the collection."""

    def __init__(self):
        self.lines = []

    def __call__(self, text='', end='\n'):
        print(text, end=end, flush=True)
        if end == '\n':
            self.lines.append(text)
        elif self.lines:
            self.lines[-1] += text
        else:
            self.lines.append(text)


def utc(timestamp=None):
    moment = datetime.datetime.fromtimestamp(time.time() if timestamp is None else timestamp, datetime.timezone.utc)
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def size_text(size):
    for unit in ('bytes', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024 or unit == 'TB':
            return ('%d %s' % (size, unit)) if unit == 'bytes' else ('%.1f %s' % (size, unit))
        size /= 1024.0


def quoted(command):
    """The command as it would be typed in the shell of this system."""
    if os.name == 'nt':
        return subprocess.list2cmdline(command)
    return ' '.join(shlex.quote(part) for part in command)


def described(vol):
    """How Volatility is started, in short."""
    if vol[1:3] == ['-c', VOL_FROM_PYTHON]:
        return 'volatility3 (%s)' % vol[0]
    return quoted(vol)


def sha256_of(path, show=None):
    digest = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    next_step = 10
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
            done += len(block)
            percent = done * 100 // total if total else 100
            if show and percent >= next_step and percent < 100:
                show(say('hash_progress', percent), end='')
                next_step = (percent // 10 + 1) * 10
    if show:
        show('')
    return digest.hexdigest()


def find_volatility(given):
    """The command (as a list) that starts Volatility 3, or None."""
    if given:
        if os.name == 'nt':
            # Windows paths contain backslashes: no escapes, only quotes
            return [part.strip('"') for part in shlex.split(given, posix=False)]
        return shlex.split(given)
    try:
        import importlib.util
        if importlib.util.find_spec('volatility3') is not None:
            return [sys.executable, '-c', VOL_FROM_PYTHON]
    except Exception:
        pass
    found = shutil.which('vol') or shutil.which('vol.py')
    if found:
        if found.lower().endswith('.py'):
            return [sys.executable, found]
        return [found]
    return None


def child_environment():
    environment = dict(os.environ)
    # messages and paths in UTF-8 whatever the console uses
    environment['PYTHONIOENCODING'] = 'utf-8'
    environment['PYTHONUTF8'] = '1'
    return environment


def volatility_version(vol):
    """(version, '') or (None, what went wrong)."""
    try:
        result = subprocess.run(vol + ['-h'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=child_environment(), timeout=300)
    except (OSError, subprocess.SubprocessError) as error:
        return None, str(error)
    text = result.stdout.decode('utf-8', 'replace')
    for line in text.splitlines():
        if line.startswith('Volatility 3 Framework'):
            return line.split()[-1], ''
    return None, '\n'.join(text.strip().splitlines()[-5:])


def count_rows(rows):
    total = 0
    for row in rows:
        total += 1
        if isinstance(row, dict):
            total += count_rows(row.get('__children') or [])
    return total


def last_lines(text, count=8, limit=800):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lines = [line for line in lines if not line.startswith('Volatility 3 Framework')]
    return ' | '.join(lines[-count:])[-limit:]


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def run_plugin(vol, options, image, plugin, folder, timeout):
    """Runs one plugin. Returns the entry of the manifest and the text
    Volatility wrote when it failed."""
    base = plugin.rsplit('.', 1)[0]
    target = os.path.join(folder, base + '.json')
    partial = target + '.part'
    log_name = 'logs/%s.log' % base
    log_path = os.path.join(folder, 'logs', base + '.log')
    command = vol + options + ['-q', '-r', 'json', '-f', image, plugin]
    entry = {'plugin': plugin, 'status': 'failed', 'exit_code': None, 'seconds': 0.0, 'file': None,
             'rows': 0, 'sha256': None, 'log': log_name, 'error': ''}
    started = time.time()
    interrupted = None
    with open(partial, 'wb') as out, open(log_path, 'wb') as err:
        err.write(('$ %s\n\n' % quoted(command)).encode('utf-8'))
        err.flush()
        process = subprocess.Popen(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                   env=child_environment())
        try:
            code = process.wait(timeout=timeout * 60 if timeout else None)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            code = None
            entry['status'] = 'timeout'
        except BaseException as error:      # Ctrl+C: Volatility stops too, nothing half written remains
            process.kill()
            process.wait()
            interrupted = error
    if interrupted is not None:
        with open(log_path, 'ab') as err:
            err.write(b'\n--- interrupted ---\n')
        os.remove(partial)
        raise interrupted
    entry['seconds'] = round(time.time() - started, 1)
    entry['exit_code'] = code
    with open(partial, 'rb') as handle:
        output = handle.read()
    rows = None
    if code == 0:
        try:
            rows = json.loads(output.decode('utf-8'))
        except ValueError:
            rows = None
    if code == 0 and isinstance(rows, list):
        os.replace(partial, target)
        entry.update({'status': 'ok', 'file': os.path.basename(target), 'rows': count_rows(rows),
                      'sha256': file_sha256(target)})
        return entry, ''
    # Not usable: what Volatility printed goes to the log, the partial output away
    text = output.decode('utf-8', 'replace')
    with open(log_path, 'rb') as handle:
        errors = handle.read().decode('utf-8', 'replace').split('\n', 2)[-1]     # without the command line
    if text.strip():
        with open(log_path, 'ab') as err:
            err.write(b'\n--- standard output ---\n' + output)
    os.remove(partial)
    unsatisfied = [line.strip() for line in text.splitlines() if line.startswith('Unsatisfied requirement')]
    if entry['status'] == 'timeout':
        entry['error'] = 'stopped after %g minutes' % timeout
    elif code == 0:
        entry['error'] = 'the output is not the JSON of Volatility: ' + last_lines(text, 3, 300)
    else:
        entry['error'] = last_lines(errors, 4) or last_lines(text, 4) or 'exit code %s' % code
        if unsatisfied and 'Unsatisfied requirement' not in entry['error']:
            entry['error'] = (entry['error'] + ' | ' + ' | '.join(unsatisfied))[:800]
    return entry, errors + '\n' + text


def read_rows(folder, entry):
    if not entry or entry.get('status') != 'ok':
        return []
    with open(os.path.join(folder, entry['file']), 'rb') as handle:
        return json.loads(handle.read().decode('utf-8'))


def host_details(folder, entries):
    """The computer name and the system time, as Volatility reports them:
    only to show them at the end and to let the module pair the memory with
    the disk without reading every output."""
    host = {'computer_name': None, 'system_time': None}
    found = dict((e['key'], e) for e in entries if e.get('status') == 'ok')
    try:
        for row in read_rows(folder, found.get('info')):
            if row.get('Variable') == 'SystemTime' and row.get('Value'):
                host['system_time'] = str(row['Value'])
    except (OSError, ValueError):
        pass
    try:
        names = collections.Counter()
        for row in read_rows(folder, found.get('envars')):
            if str(row.get('Variable') or '').upper() == 'COMPUTERNAME' and row.get('Value'):
                names[str(row['Value']).strip()] += 1
        if names:
            host['computer_name'] = names.most_common(1)[0][0]
    except (OSError, ValueError):
        pass
    return host


def write_manifest(folder, manifest):
    path = os.path.join(folder, MANIFEST)
    with open(path + '.tmp', 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write('\n')
    os.replace(path + '.tmp', path)


def main(argv=None):
    global LANGUAGE
    argv = sys.argv[1:] if argv is None else argv
    try:
        sys.stdout.reconfigure(errors='replace')
    except (AttributeError, ValueError):
        pass
    LANGUAGE = system_language()
    for i, arg in enumerate(argv):
        if arg.startswith('--lang='):
            LANGUAGE = 'it' if arg.split('=', 1)[1].lower().startswith('it') else 'en'
        elif arg == '--lang' and i + 1 < len(argv):
            LANGUAGE = 'it' if argv[i + 1].lower().startswith('it') else 'en'
    parser = argparse.ArgumentParser(description=say('description'))
    parser.add_argument('image', help=say('h_image'))
    parser.add_argument('-o', '--output', help=say('h_output'))
    parser.add_argument('--vol', help=say('h_vol'))
    parser.add_argument('-s', '--symbols', help=say('h_symbols'))
    parser.add_argument('--offline', action='store_true', help=say('h_offline'))
    parser.add_argument('--no-hash', action='store_true', help=say('h_no_hash'))
    parser.add_argument('--timeout', type=float, default=120, help=say('h_timeout'))
    parser.add_argument('--lang', choices=('en', 'it'), help=say('h_lang'))
    args = parser.parse_args(argv)
    show = Console()

    image = os.path.abspath(args.image)
    if not os.path.isfile(image):
        show(say('no_image', image))
        return 2
    size = os.path.getsize(image)
    if size == 0:
        show(say('empty_image', image))
        return 2
    stem = os.path.splitext(os.path.basename(image))[0] or 'memory'
    folder = os.path.abspath(args.output or (stem + '_vol3'))
    if os.path.exists(folder) and (not os.path.isdir(folder) or os.listdir(folder)):
        show(say('output_busy', folder))
        return 2
    vol = find_volatility(args.vol)
    if not vol:
        show(say('no_vol'))
        return 2
    version, problem = volatility_version(vol)
    if not version:
        show(say('bad_vol', quoted(vol), problem))
        return 2
    options = []
    if args.symbols:
        options += ['-s', os.path.abspath(args.symbols)]
    if args.offline:
        options.append('--offline')

    os.makedirs(os.path.join(folder, 'logs'))
    show(say('title', VERSION))
    show(say('vol_found', version, described(vol)))
    show(say('image', image, size_text(size)))
    show(say('output', folder))
    manifest = {
        'format': FORMAT, 'format_version': FORMAT_VERSION,
        'collector': {'name': 'collect_memory.py', 'version': VERSION, 'python': platform.python_version(),
                      'system': platform.platform(), 'arguments': argv},
        'volatility': {'version': version, 'command': vol + options},
        'image': {'name': os.path.basename(image), 'path': image, 'size': size, 'sha256': None,
                  'modified': utc(os.path.getmtime(image))},
        'host': {'computer_name': None, 'system_time': None},
        'started': utc(), 'finished': None, 'complete': False, 'plugins': [],
    }
    write_manifest(folder, manifest)
    code = 2
    try:
        if not args.no_hash:
            show(say('hashing'), end='')
            started = time.time()
            try:
                manifest['image']['sha256'] = sha256_of(image, show)
            except OSError as error:
                show('')
                show(say('hash_error', error))
                manifest['finished'] = utc()
                write_manifest(folder, manifest)
                return 2
            show(say('hash_done', manifest['image']['sha256'], time.time() - started))
            write_manifest(folder, manifest)
        stop = False
        for number, (key, plugins) in enumerate(STEPS):
            if stop:
                break
            for attempt, plugin in enumerate(plugins):
                if attempt:
                    show(say('fallback', plugin))
                else:
                    show(say('running', number + 1, len(STEPS), plugin))
                entry, text = run_plugin(vol, options, image, plugin, folder, args.timeout)
                entry['key'] = key
                manifest['plugins'].append(entry)
                write_manifest(folder, manifest)
                if entry['status'] == 'ok':
                    show(say('ok', entry['rows'], entry['seconds']))
                    break
                if entry['status'] == 'timeout':
                    show(say('timeout', args.timeout))
                else:
                    show(say('failed', entry['seconds'], entry['error'][:300]))
                if 'Unsatisfied requirement' in text and not [e for e in manifest['plugins'] if e['status'] == 'ok']:
                    show(say('requirements'))
                    stop = True
                    break
        manifest['host'] = host_details(folder, manifest['plugins'])
        manifest['complete'] = not stop
        manifest['finished'] = utc()
        write_manifest(folder, manifest)
        done = set(e['key'] for e in manifest['plugins'] if e['status'] == 'ok')
        missing = [key for key, _ in STEPS if key not in done]
        show('')
        show(say('summary'))
        show(say('computer', manifest['host']['computer_name'] or say('unknown')))
        show(say('system_time', manifest['host']['system_time'] or say('unknown')))
        show(say('plugins_ok', len(done), len(STEPS)))
        if missing:
            show(say('plugins_failed', ', '.join(missing)))
        if done:
            show(say('next'))
            code = 1 if missing else 0
        else:
            show(say('nothing'))
            code = 2
        return code
    except KeyboardInterrupt:
        show('')
        show(say('interrupted'))
        manifest['host'] = host_details(folder, manifest['plugins'])
        manifest['finished'] = utc()
        manifest['interrupted'] = True
        write_manifest(folder, manifest)
        return 130
    finally:
        try:
            with open(os.path.join(folder, 'collect_memory.log'), 'w', encoding='utf-8', newline='\n') as handle:
                handle.write('\n'.join(show.lines) + '\n')
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
