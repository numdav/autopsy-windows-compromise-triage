#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the archive to attach to a GitHub release.

The archive contains the TriageCompromissione folder: the sources (no
compiled files) with the documentation, its images and the license next to
them, so that they travel with the plugin when the folder is copied into
Autopsy and the README can be read offline. The memory collector goes in
TriageCompromissione/collectors/ and the case verifier in
TriageCompromissione/tools/: Autopsy reads only the .py files directly
inside the plugin folder, so it ignores them.

    python3 tools/make_release.py

writes dist/TriageCompromissione-<version>.zip, where <version> is the value
of VERSIONE in TriageCompromissione/tc_controlli.py.

The archive is reproducible: the same sources give the same bytes. Every
entry has the same time, taken from SOURCE_DATE_EPOCH if it is set,
otherwise from the date of the last commit; the entries are sorted and have
the same permissions. The GitHub Actions checks rebuild it from the tag of a
release and compare it with the one attached.
"""

import os
import re
import subprocess
import sys
import time
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
PLUGIN = 'TriageCompromissione'
DOCUMENTS = ('README.md', 'README.it.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE', 'NOTICE')
IMAGES = 'docs/screenshots'
EXTRA = ('collectors/collect_memory.py', 'tools/verify_case.py', 'docs/windows-test.md', 'docs/windows-test-sheet.csv')


def version():
    with open(os.path.join(ROOT, PLUGIN, 'tc_controlli.py'), encoding='utf-8') as handle:
        found = re.search(r"^VERSIONE = u'([^']+)'", handle.read(), re.M)
    if found is None:
        sys.exit('VERSIONE not found in tc_controlli.py')
    return found.group(1)


def timestamp():
    """The time of every entry: SOURCE_DATE_EPOCH, or the date of the last commit."""
    if os.environ.get('SOURCE_DATE_EPOCH'):
        return int(os.environ['SOURCE_DATE_EPOCH'])
    try:
        out = subprocess.run(['git', 'log', '-1', '--format=%ct'], cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, check=True).stdout.decode('ascii').strip()
        return int(out)
    except (OSError, subprocess.CalledProcessError, ValueError):
        sys.exit('No date for the entries: set SOURCE_DATE_EPOCH or run inside the git repository')


def add(archive, source, name, moment):
    with open(os.path.join(ROOT, source), 'rb') as handle:
        data = handle.read()
    entry = zipfile.ZipInfo(name, date_time=moment)
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3                     # Unix, so that the permissions below are read
    entry.external_attr = 0o100644 << 16        # a regular file, rw-r--r--
    archive.writestr(entry, data, compresslevel=9)


def main():
    name = '%s-%s.zip' % (PLUGIN, version())
    target = os.path.join(ROOT, 'dist', name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    # the ZIP format keeps local times without a zone: the time is written in UTC
    moment = time.gmtime(max(timestamp(), 315532800))[:6]     # not before 1980, the first date ZIP can hold
    files = [('%s/%s' % (PLUGIN, f), '%s/%s' % (PLUGIN, f))
             for f in os.listdir(os.path.join(ROOT, PLUGIN)) if f.endswith('.py')]
    files += [(d, '%s/%s' % (PLUGIN, d)) for d in DOCUMENTS]
    # the READMEs refer to their images as docs/screenshots/<name>
    files += [('%s/%s' % (IMAGES, f), '%s/%s/%s' % (PLUGIN, IMAGES, f))
              for f in os.listdir(os.path.join(ROOT, IMAGES)) if f.endswith('.png')]
    files += [(e, '%s/%s' % (PLUGIN, e)) for e in EXTRA]
    with zipfile.ZipFile(target, 'w') as archive:
        for source, inside in sorted(files, key=lambda x: x[1]):
            add(archive, source, inside, moment)
    sources = len([f for f in files if f[1].count('/') == 1 and f[1].endswith('.py')])
    print('%s: %d source files, %d documents, %d images, %d other files; entries dated %s UTC'
          % (os.path.relpath(target, ROOT), sources, len(DOCUMENTS), len([f for f in files if IMAGES in f[0]]),
             len(EXTRA), time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(max(timestamp(), 315532800)))))


if __name__ == '__main__':
    main()
