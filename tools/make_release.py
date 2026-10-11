#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the archive to attach to a GitHub release.

The archive contains the TriageCompromissione folder: the sources (no
compiled files) with the documentation, its images and the license next to
them, so that they travel with the plugin when the folder is copied into
Autopsy and the README can be read offline. The memory collector goes in
TriageCompromissione/collectors/: Autopsy reads only the .py files directly
inside the plugin folder, so it ignores it.

    python3 tools/make_release.py

writes dist/TriageCompromissione-<version>.zip, where <version> is the value
of VERSIONE in TriageCompromissione/tc_controlli.py.
"""

import os
import re
import sys
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
PLUGIN = 'TriageCompromissione'
DOCUMENTS = ('README.md', 'README.it.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE', 'NOTICE')
IMAGES = 'docs/screenshots'
COLLECTORS = ('collectors/collect_memory.py',)


def version():
    with open(os.path.join(ROOT, PLUGIN, 'tc_controlli.py'), encoding='utf-8') as handle:
        found = re.search(r"^VERSIONE = u'([^']+)'", handle.read(), re.M)
    if found is None:
        sys.exit('VERSIONE not found in tc_controlli.py')
    return found.group(1)


def main():
    name = '%s-%s.zip' % (PLUGIN, version())
    target = os.path.join(ROOT, 'dist', name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    sources = sorted(f for f in os.listdir(os.path.join(ROOT, PLUGIN)) if f.endswith('.py'))
    images = sorted(f for f in os.listdir(os.path.join(ROOT, IMAGES)) if f.endswith('.png'))
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            archive.write(os.path.join(ROOT, PLUGIN, source), '%s/%s' % (PLUGIN, source))
        for document in DOCUMENTS:
            archive.write(os.path.join(ROOT, document), '%s/%s' % (PLUGIN, document))
        # the READMEs refer to their images as docs/screenshots/<name>
        for image in images:
            archive.write(os.path.join(ROOT, IMAGES, image), '%s/%s/%s' % (PLUGIN, IMAGES, image))
        for collector in COLLECTORS:
            archive.write(os.path.join(ROOT, collector), '%s/%s' % (PLUGIN, collector))
    print('%s: %d source files, %d documents, %d images, %d collector'
          % (os.path.relpath(target, ROOT), len(sources), len(DOCUMENTS), len(images), len(COLLECTORS)))


if __name__ == '__main__':
    main()
