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

Requirements: Python 3.8 or later and Volatility 3 (pip install volatility3),
importable by this Python or available as the "vol" command (or given with
--vol). The version tested is Volatility 3 2.28.2: an older one works but may
give less data, and the collector says so. On the first analysis of a Windows
build Volatility downloads the kernel symbols from Microsoft; on a computer
without Internet access use --symbols with a local symbol pack and --offline.

Before collecting, a preflight check records in the manifest the versions of
Python and Volatility, which of the plugins this Volatility can load, whether
the symbols can be found and the free space. After collecting, the output is
checked against what a running Windows always has (dozens of processes, the
system processes, readable command lines, listening ports, hundreds of
services and environment variables): an output below those thresholds, as
from a truncated image, is reported, so that the acquisition can be repeated.
The Autopsy module applies the same thresholds.

Exit status: 0 if every plugin worked and the output looks complete, 1 if
some plugin failed or the output looks anomalous (the folder is still usable:
the module reports what is missing), 2 if nothing could be run.
"""

import argparse
import collections
import datetime
import hashlib
import json
import locale
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time

VERSION = '1.3'
TESTED_VOLATILITY = '2.28.2'
MINIMUM_PYTHON = (3, 8)
MINIMUM_FREE_SPACE = 512 * 1024 * 1024
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

# What a running Windows always has: the same thresholds as the Autopsy module (tc_memoria._plausibilita)
ESSENTIAL_PROCESSES = ('smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe')
MINIMUM_PROCESSES = 20
MINIMUM_SERVICES = 100
MINIMUM_ENVIRONMENT = 100
UNREADABLE_COMMAND = re.compile(r'^(process \d+: )?required memory at 0x[0-9a-f]+ is', re.I)

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
    'old_python': {'en': 'Python %s is too old: the collector needs Python %d.%d or later.',
                   'it': 'Python %s \u00e8 troppo vecchio: il raccoglitore richiede Python %d.%d o successivo.'},
    'preflight': {'en': 'Preflight check', 'it': 'Controllo preliminare'},
    'pf_python': {'en': '  Python %s: ok', 'it': '  Python %s: ok'},
    'pf_vol_ok': {'en': '  Volatility %s: the version tested', 'it': '  Volatility %s: la versione provata'},
    'pf_vol_old': {'en': '  WARNING: Volatility %s is older than the version tested (%s): some plugins may give less data '
                         'or fail (for example svcscan without yara-python). Update it: pip install -U volatility3',
                   'it': '  ATTENZIONE: Volatility %s \u00e8 pi\u00f9 vecchio della versione provata (%s): alcuni plugin '
                         'possono dare meno dati o non riuscire (per esempio svcscan senza yara-python). Aggiornalo: '
                         'pip install -U volatility3'},
    'pf_vol_new': {'en': '  Volatility %s: newer than the version tested (%s)',
                   'it': '  Volatility %s: pi\u00f9 recente della versione provata (%s)'},
    'pf_plugins_ok': {'en': '  Plugins: all available (%d)', 'it': '  Plugin: tutti disponibili (%d)'},
    'pf_plugins_missing': {'en': '  WARNING: this Volatility does not have (or cannot load) these plugins: %s',
                           'it': '  ATTENZIONE: questo Volatility non ha (o non riesce a caricare) questi plugin: %s'},
    'pf_plugins_unknown': {'en': '  Plugins: the list of this Volatility could not be read; they will be tried',
                           'it': '  Plugin: non si \u00e8 potuto leggere l\'elenco di questo Volatility; verranno provati'},
    'pf_symbols_local': {'en': '  Symbols: local folder %s (%d symbol tables for Windows)',
                         'it': '  Simboli: cartella locale %s (%d tabelle di simboli per Windows)'},
    'pf_symbols_empty': {'en': '  WARNING: the symbol folder %s contains no tables for Windows',
                         'it': '  ATTENZIONE: la cartella dei simboli %s non contiene tabelle per Windows'},
    'pf_symbols_online': {'en': '  Symbols: the Microsoft symbol server is reachable',
                          'it': '  Simboli: il server dei simboli di Microsoft \u00e8 raggiungibile'},
    'pf_symbols_offline': {'en': '  WARNING: offline and without --symbols: only the Windows builds already in the cache '
                                 'of Volatility can be analyzed',
                           'it': '  ATTENZIONE: offline e senza --symbols: si possono analizzare solo le build di Windows '
                                 'gi\u00e0 nella cache di Volatility'},
    'pf_symbols_unreachable': {'en': '  WARNING: the Microsoft symbol server is not reachable (%s): a Windows build not in '
                                     'the cache will fail; use --symbols with a local symbol pack',
                               'it': '  ATTENZIONE: il server dei simboli di Microsoft non \u00e8 raggiungibile (%s): una '
                                     'build di Windows che non \u00e8 nella cache non si potr\u00e0 analizzare; usa '
                                     '--symbols con un pacchetto di simboli locale'},
    'pf_space_ok': {'en': '  Free space for the results: %s', 'it': '  Spazio libero per i risultati: %s'},
    'pf_space_low': {'en': '  WARNING: only %s free for the results', 'it': '  ATTENZIONE: solo %s liberi per i risultati'},
    'not_available': {'en': '      NOT AVAILABLE in this Volatility: skipped',
                      'it': '      NON DISPONIBILE in questo Volatility: saltato'},
    'network_fallback': {'en': 'Network: %s did not work (%s); %s was used instead, which does not see the connections '
                               'already closed. The module will report checks 5 and 7 as partial.',
                         'it': 'Rete: %s non \u00e8 riuscito (%s); al suo posto \u00e8 stato usato %s, che non vede le '
                               'connessioni gi\u00e0 chiuse. Il modulo segner\u00e0 parziali i controlli 5 e 7.'},
    'plugins_ok_anomalous': {'en': 'Plugins completed: %d of %d, but their output looks anomalous: see the warning below',
                             'it': 'Plugin completati: %d su %d, ma il loro output sembra anomalo: vedi l\'avviso qui '
                                   'sotto'},
    # what makes an output anomalous (the manifest keeps them in English)
    'a_processes': {'en': 'only %d active processes in pslist', 'it': 'solo %d processi attivi in pslist'},
    'a_essential': {'en': 'processes that a running Windows always has are missing: %s',
                    'it': 'mancano processi che un Windows acceso ha sempre: %s'},
    'a_hidden': {'en': 'psscan finds %d active processes that pslist does not list',
                 'it': 'psscan trova %d processi attivi che pslist non elenca'},
    'a_commands': {'en': 'no readable command line in cmdline (processes: %d)',
                   'it': 'nessuna riga di comando leggibile in cmdline (processi: %d)'},
    'a_listening': {'en': 'no listening port in %s', 'it': 'nessuna porta in ascolto in %s'},
    'a_services': {'en': 'only %d services in svcscan', 'it': 'solo %d servizi in svcscan'},
    'a_environment': {'en': 'only %d environment variables in envars',
                      'it': 'solo %d variabili d\'ambiente in envars'},
    'anomalous': {'en': 'WARNING: anomalous or possibly incomplete output (%s). An acquisition problem, an extraction '
                        'problem and concealment cannot be told apart: check the image and, if you can, repeat the '
                        'acquisition.',
                  'it': 'ATTENZIONE: output anomalo o forse incompleto (%s). Non si distingue fra un problema di '
                        'acquisizione, di estrazione o un occultamento: controlla l\'immagine e, se puoi, ripeti '
                        'l\'acquisizione.'},
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
    """(version, '', plugins) or (None, what went wrong, None). plugins: the
    plugins listed by "vol -h" (the ones this Volatility can load), or None if
    the list cannot be read."""
    try:
        result = subprocess.run(vol + ['-h'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=child_environment(), timeout=300)
    except (OSError, subprocess.SubprocessError) as error:
        return None, str(error), None
    text = result.stdout.decode('utf-8', 'replace')
    version = None
    for line in text.splitlines():
        if line.startswith('Volatility 3 Framework'):
            version = line.split()[-1]
            break
    if version is None:
        return None, '\n'.join(text.strip().splitlines()[-5:]), None
    # the plugins are listed at the end of the help, indented: "    windows.info.Info   Show OS ..."
    plugins = set()
    for line in text.splitlines():
        parts = line.split()
        if line.startswith('    ') and parts and parts[0].startswith('windows.') and parts[0].count('.') >= 2:
            plugins.add(parts[0])
    # a list that names none of the plugins wanted is not understood (another
    # layout of the help): then nothing is skipped and every plugin is tried
    wanted = [plugin for _, alternatives in STEPS for plugin in alternatives]
    if len(plugins) < 10 or not [plugin for plugin in wanted if plugin in plugins]:
        plugins = None
    return version, '', plugins


def version_tuple(text):
    numbers = []
    for part in str(text).split('.'):
        digits = ''.join(c for c in part if c.isdigit())
        numbers.append(int(digits) if digits else 0)
    return tuple(numbers)


def symbol_tables(folder):
    """How many symbol tables for Windows a folder given with --symbols holds."""
    count = 0
    for root, _, names in os.walk(folder):
        if 'windows' in root.replace('\\', '/').lower().split('/'):
            count += len([n for n in names if n.endswith(('.json', '.json.xz', '.json.gz', '.json.bz2'))])
        elif names and [n for n in names if n.lower().endswith('.zip') and 'windows' in n.lower()]:
            count += len([n for n in names if n.lower().endswith('.zip') and 'windows' in n.lower()])
    return count


def symbol_server_reachable():
    """(True, '') if the Microsoft symbol server answers (any HTTP answer counts),
    otherwise (False, why). Uses the proxy of the environment, as Volatility does."""
    import urllib.error
    import urllib.request
    try:
        request = urllib.request.Request('https://msdl.microsoft.com/download/symbols', method='HEAD')
        urllib.request.urlopen(request, timeout=15).close()
        return True, ''
    except urllib.error.HTTPError:
        return True, ''
    except Exception as error:      # no network, proxy, certificate...
        return False, str(error)[:200]


def preflight(show, version, plugins, args, folder):
    """The checks before the collection. Returns what goes in the manifest
    and the warnings as shown on the screen (repeated in the summary)."""
    result = {'python': platform.python_version(), 'volatility': version, 'volatility_tested': TESTED_VOLATILITY,
              'volatility_older': version_tuple(version) < version_tuple(TESTED_VOLATILITY),
              'plugins_missing': None, 'symbols': None, 'free_space': None, 'warnings': []}
    shown = []

    def warning(english, key, *values):
        line = say(key, *values)
        show(line)
        shown.append(line.strip())
        result['warnings'].append(english)
    show(say('preflight'))
    show(say('pf_python', platform.python_version()))
    if result['volatility_older']:
        warning('Volatility %s is older than the version tested (%s)' % (version, TESTED_VOLATILITY),
                'pf_vol_old', version, TESTED_VOLATILITY)
    elif version_tuple(version) > version_tuple(TESTED_VOLATILITY):
        show(say('pf_vol_new', version, TESTED_VOLATILITY))
    else:
        show(say('pf_vol_ok', version))
    if plugins is None:
        show(say('pf_plugins_unknown'))
    else:
        wanted = [plugin for _, alternatives in STEPS for plugin in alternatives]
        missing = [plugin for plugin in wanted if plugin not in plugins]
        result['plugins_missing'] = missing
        if missing:
            warning('plugins not available: %s' % ', '.join(missing), 'pf_plugins_missing', ', '.join(missing))
        else:
            show(say('pf_plugins_ok', len(wanted)))
    if args.symbols:
        tables = symbol_tables(os.path.abspath(args.symbols))
        result['symbols'] = {'local': os.path.abspath(args.symbols), 'tables': tables}
        if tables:
            show(say('pf_symbols_local', os.path.abspath(args.symbols), tables))
        else:
            warning('the symbol folder contains no tables for Windows', 'pf_symbols_empty',
                    os.path.abspath(args.symbols))
    if args.offline:
        result['symbols'] = dict(result['symbols'] or {}, offline=True)
        if not args.symbols:
            warning('offline without local symbols', 'pf_symbols_offline')
    elif not args.symbols:
        reachable, why = symbol_server_reachable()
        result['symbols'] = {'server_reachable': reachable}
        if reachable:
            show(say('pf_symbols_online'))
        else:
            warning('symbol server not reachable: %s' % why, 'pf_symbols_unreachable', why)
    try:
        free = shutil.disk_usage(folder).free
        result['free_space'] = free
        if free < MINIMUM_FREE_SPACE:
            warning('only %s free for the results' % size_text(free), 'pf_space_low', size_text(free))
        else:
            show(say('pf_space_ok', size_text(free)))
    except OSError:
        pass
    show('')
    return result, shown


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
    elif 'invalid choice' in errors or 'invalid choice' in text:
        # Volatility lists every plugin it has after "invalid choice": the tail of that list says nothing
        entry['error'] = 'not available in this Volatility (the plugin is missing or cannot be loaded)'
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


def plausibility(folder, entries, language='en'):
    """What a running Windows always has, checked on the output: the same
    thresholds as the Autopsy module. Returns the anomalies found, in English
    (for the manifest) or in the language given (for the summary)."""
    found = dict((e['key'], e) for e in entries if e.get('status') == 'ok')
    anomalies = []

    def anomaly(key, value):
        anomalies.append(TEXTS[key][language] % value)

    def rows(key):
        try:
            return read_rows_flat(folder, found.get(key)) if key in found else None
        except (OSError, ValueError):
            return None
    listed = rows('pslist')
    if listed is not None:
        active = [r for r in listed if not r.get('ExitTime')]
        if len(active) < MINIMUM_PROCESSES:
            anomaly('a_processes', len(active))
        names = set(str(r.get('ImageFileName') or '').lower() for r in active)
        missing = [n for n in ESSENTIAL_PROCESSES if n not in names]
        if not [r for r in active if r.get('PID') == 4]:
            missing.insert(0, 'System')
        if missing:
            anomaly('a_essential', ', '.join(missing))
        scanned = rows('psscan')
        if scanned is not None:
            # the processes of an earlier boot, left in the memory, do not count (a minute of tolerance)
            boot = min([s for s in (seconds_of(r.get('CreateTime')) for r in listed if r.get('PID') == 4) if s]
                       or [0])
            known = set((r.get('PID'), str(r.get('CreateTime'))) for r in listed)
            hidden = [r for r in scanned if (r.get('PID'), str(r.get('CreateTime'))) not in known
                      and not r.get('ExitTime') and (r.get('Threads') or 0) > 0
                      and not (boot and (seconds_of(r.get('CreateTime')) or boot) < boot - 60)]
            if len(hidden) > max(5, len(active) // 10):
                anomaly('a_hidden', len(hidden))
    commands = rows('cmdline')
    if commands and not [r for r in commands if readable_command(r.get('Args'))]:
        anomaly('a_commands', len(commands))
    network = rows('network')
    if network is not None and not [r for r in network if str(r.get('State') or '').upper() == 'LISTENING']:
        anomaly('a_listening', found['network']['plugin'].rsplit('.', 1)[0])
    services = rows('svcscan')
    if services is not None and len(services) < MINIMUM_SERVICES:
        anomaly('a_services', len(services))
    variables = rows('envars')
    if variables is not None and len(variables) < MINIMUM_ENVIRONMENT:
        anomaly('a_environment', len(variables))
    return anomalies


def readable_command(value):
    """False for an empty command line and for the reason that Volatility up to
    2.11 writes in its place ("Required memory at 0x... is not valid")."""
    text = str(value or '').replace('\x00', '').strip()
    return bool(text) and not UNREADABLE_COMMAND.match(text)


def seconds_of(value):
    """Seconds since 1970 of a time written by Volatility (ISO 8601), or None."""
    text = str(value or '').strip().replace(' ', 'T', 1).replace('Z', '+00:00')
    if not text:
        return None
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        try:
            moment = datetime.datetime.fromisoformat(text[:19])
        except ValueError:
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.timestamp()


def read_rows_flat(folder, entry):
    """The rows of an output with the nested ones (pstree) after their parent."""
    flat = []

    def walk(rows):
        for row in rows:
            if isinstance(row, dict):
                flat.append(row)
                walk(row.get('__children') or [])
    walk(read_rows(folder, entry))
    return flat


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
    if sys.version_info[:2] < MINIMUM_PYTHON:
        print(say('old_python', platform.python_version(), MINIMUM_PYTHON[0], MINIMUM_PYTHON[1]))
        return 2
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
    version, problem, available = volatility_version(vol)
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
    show('')
    checked, warnings = preflight(show, version, available, args, folder)
    manifest = {
        'format': FORMAT, 'format_version': FORMAT_VERSION,
        'collector': {'name': 'collect_memory.py', 'version': VERSION, 'python': platform.python_version(),
                      'system': platform.platform(), 'arguments': argv},
        'volatility': {'version': version, 'command': vol + options},
        'image': {'name': os.path.basename(image), 'path': image, 'size': size, 'sha256': None,
                  'modified': utc(os.path.getmtime(image))},
        'host': {'computer_name': None, 'system_time': None},
        'preflight': checked,
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
                if available is not None and plugin not in available:
                    # the preflight check found that this Volatility does not have it: not run
                    entry = {'plugin': plugin, 'status': 'failed', 'exit_code': None, 'seconds': 0.0, 'file': None,
                             'rows': 0, 'sha256': None, 'log': None, 'key': key,
                             'error': 'not available in this Volatility (the plugin is missing or cannot be loaded)'}
                    manifest['plugins'].append(entry)
                    write_manifest(folder, manifest)
                    show(say('not_available'))
                    continue
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
        anomalies = plausibility(folder, manifest['plugins']) if not stop else []
        manifest['plausibility'] = {'anomalies': anomalies, 'minimum_processes': MINIMUM_PROCESSES,
                                    'essential_processes': list(ESSENTIAL_PROCESSES),
                                    'minimum_services': MINIMUM_SERVICES,
                                    'minimum_environment_variables': MINIMUM_ENVIRONMENT}
        write_manifest(folder, manifest)
        done = set(e['key'] for e in manifest['plugins'] if e['status'] == 'ok')
        missing = [key for key, _ in STEPS if key not in done]
        show('')
        show(say('summary'))
        show(say('computer', manifest['host']['computer_name'] or say('unknown')))
        show(say('system_time', manifest['host']['system_time'] or say('unknown')))
        show(say('plugins_ok_anomalous' if anomalies else 'plugins_ok', len(done), len(STEPS)))
        if missing:
            show(say('plugins_failed', ', '.join(missing)))
        network = [e for e in manifest['plugins'] if e['key'] == 'network']
        if len(network) > 1 and network[-1]['status'] == 'ok':
            show(say('network_fallback', network[0]['plugin'].rsplit('.', 1)[0], network[0]['error'][:200],
                     network[-1]['plugin'].rsplit('.', 1)[0]))
        for line in warnings:
            show(line)
        if anomalies:
            show(say('anomalous', '; '.join(plausibility(folder, manifest['plugins'], LANGUAGE))))
        if done:
            show(say('next'))
            code = 1 if missing or anomalies else 0
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
