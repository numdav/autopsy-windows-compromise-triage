#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that the English catalog matches the Italian texts used in the plugin.

The plugin source keeps every analyst-facing text in Italian, wrapped in
tr(u'...'), N_(u'...') or _ui(u'...'). The English version of each text lives
in TriageCompromissione/tc_lingua_en.py, a dictionary whose keys are the
Italian texts. This script reports:

  * texts used in the code that have no English translation;
  * catalog entries that no longer match any text in the code;
  * translations whose placeholders (%s, %d, ...), surrounding spaces, line
    breaks or HTML tags differ from the Italian text;
  * non-ASCII characters in the plugin sources and in the tests (they must
    be written as \\uXXXX escapes, the safest form for Jython 2.7).

With --hints it also lists unwrapped string literals that look like Italian
sentences, which usually means a tr() was forgotten.

It only reads the files: it needs Python 3.8 or later and nothing else.

    python3 tools/check_translations.py [--hints] [plugin folder]

Exit status: 0 if everything is consistent, 1 otherwise.
"""

import ast
import io
import os
import re
import sys
import tokenize

MARKERS = ('tr', 'N_', '_ui')
CATALOG = 'tc_lingua_en.py'
PLACEHOLDER = re.compile(r'%(?:[-+ #0]*\d*(?:\.\d+)?[sdrxXfi]|%)')
TAG = re.compile(r'</?[a-zA-Z][a-zA-Z0-9]*(?: [^<>]*)?>')
# <nome> and <numeri> are placeholders shown to the analyst, not HTML tags
NOT_TAGS = ('<nome>', '<numeri>', '<name>', '<numbers>')
ITALIAN_WORDS = re.compile(
    r"\b(il|lo|la|le|gli|un|una|di|del|della|dei|delle|che|non|con|per|sono|\u00e8|da|dal|dalla|nel|nella"
    r"|sul|sulla|alla|pi\u00f9|senza|gi\u00e0|anche|solo|come|dopo|prima|tra)\b", re.I)


def literal(tokens):
    """The value of one or more adjacent string tokens, or None."""
    try:
        parts = [ast.literal_eval(t) for t in tokens]
    except (SyntaxError, ValueError):
        return None
    if any(isinstance(p, bytes) for p in parts):
        try:
            parts = [p.decode('latin-1') if isinstance(p, bytes) else p for p in parts]
        except UnicodeDecodeError:
            return None
    return ''.join(parts)


def string_runs(path):
    """Yield (line, text, wrapper) for every run of adjacent string literals
    in a source file. wrapper is 'tr', 'N_' or '_ui' when the run is the only
    argument of that call, otherwise None. Docstrings are skipped."""
    with io.open(path, encoding='utf-8') as handle:
        tokens = list(tokenize.generate_tokens(handle.readline))
    skip = (tokenize.NL, tokenize.COMMENT)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.type != tokenize.STRING:
            i += 1
            continue
        run = [tok.string]
        last = i
        j = i + 1
        while j < len(tokens) and tokens[j].type in (tokenize.STRING,) + skip:
            if tokens[j].type == tokenize.STRING:
                run.append(tokens[j].string)
                last = j
            j += 1
        before = i - 1
        while before >= 0 and tokens[before].type in skip:
            before -= 1
        after = last + 1
        while after < len(tokens) and tokens[after].type in skip:
            after += 1
        docstring = (before < 0 or tokens[before].type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)) \
            and tokens[after].type == tokenize.NEWLINE
        wrapper = None
        if before >= 1 and tokens[before].string == '(' and tokens[before - 1].string in MARKERS \
                and tokens[after].string == ')':
            wrapper = tokens[before - 1].string
        if not docstring:
            yield tok.start[0], literal(run), wrapper
        i = last + 1


def load_catalog(path):
    """Return (translations, duplicated keys) from tc_lingua_en.py."""
    with io.open(path, encoding='utf-8') as handle:
        source = handle.read()
    duplicates = []
    seen = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if key.value in seen:
                        duplicates.append(key.value)
                    seen.add(key.value)
    scope = {}
    exec(compile(source, path, 'exec'), scope)
    return scope['TESTI'], duplicates


def shape_problems(italian, english):
    problems = []
    if PLACEHOLDER.findall(italian) != PLACEHOLDER.findall(english):
        problems.append('placeholders differ: %s / %s' % (PLACEHOLDER.findall(italian), PLACEHOLDER.findall(english)))
    if italian[:len(italian) - len(italian.lstrip())] != english[:len(english) - len(english.lstrip())]:
        problems.append('leading whitespace differs')
    if italian[len(italian.rstrip()):] != english[len(english.rstrip()):]:
        problems.append('trailing whitespace differs')
    if italian.count('\n') != english.count('\n'):
        problems.append('number of line breaks differs')
    if italian.count('\\') != english.count('\\'):
        problems.append('number of backslashes differs')
    tags_it = [t for t in TAG.findall(italian) if t not in NOT_TAGS]
    tags_en = [t for t in TAG.findall(english) if t not in NOT_TAGS]
    if tags_it != tags_en:
        problems.append('HTML tags differ: %s / %s' % (tags_it, tags_en))
    for entity in ('&gt;', '&lt;', '&amp;'):
        if italian.count(entity) != english.count(entity):
            problems.append('number of %s differs' % entity)
    return problems


def show(text):
    return text.replace('\\', '\\\\').replace('\n', '\\n')


def main(argv):
    # the texts contain accented letters and typographic quotes: on a console
    # that cannot show them, print an escape instead of stopping with an error
    sys.stdout.reconfigure(errors='backslashreplace')
    hints = '--hints' in argv
    args = [a for a in argv if not a.startswith('--')]
    here = os.path.dirname(os.path.abspath(__file__))
    folder = args[0] if args else os.path.join(here, os.pardir, 'TriageCompromissione')
    folder = os.path.normpath(folder)
    sources = sorted(name for name in os.listdir(folder) if name.endswith('.py') and name != CATALOG)
    if not sources or not os.path.isfile(os.path.join(folder, CATALOG)):
        print('No plugin sources found in %s' % folder)
        return 1

    used = {}           # Italian text -> first place where it is used
    unwrapped = []
    errors = 0
    ascii_only = [os.path.join(folder, name) for name in sources + [CATALOG]]
    tests = os.path.join(folder, os.pardir, 'tests')
    if os.path.isdir(tests):
        ascii_only += [os.path.join(tests, name) for name in sorted(os.listdir(tests)) if name.endswith('.py')]
    for path in ascii_only:
        with io.open(path, 'rb') as handle:
            data = handle.read()
        bad = [n + 1 for n, line in enumerate(data.split(b'\n')) if any(byte > 126 for byte in line)]
        if bad:
            errors += 1
            print('NON-ASCII  %s, line(s) %s: use \\uXXXX escapes'
                  % (os.path.relpath(path, os.path.join(folder, os.pardir)), ', '.join(str(n) for n in bad[:10])))
    for name in sources:
        for line, text, wrapper in string_runs(os.path.join(folder, name)):
            if text is None:
                continue
            if wrapper:
                used.setdefault(text, '%s:%d' % (name, line))
            elif hints and len(re.findall(r'[A-Za-z\u00c0-\u00ff]{2,}', text)) >= 3 and ' ' in text \
                    and ITALIAN_WORDS.search(text) and not re.search(r'\\[sdwb]|\(\?|\[\^|\.\*|\$$', text):
                unwrapped.append((name, line, text))

    catalog, duplicates = load_catalog(os.path.join(folder, CATALOG))
    missing = [text for text in used if text not in catalog]
    unused = [text for text in catalog if text not in used]
    for text in missing:
        errors += 1
        print('MISSING    %s  %s' % (used[text], show(text)))
    for text in unused:
        errors += 1
        print('UNUSED     %s' % show(text))
    for text in duplicates:
        errors += 1
        print('DUPLICATE  %s' % show(text))
    for text in used:
        if text in catalog:
            for problem in shape_problems(text, catalog[text]):
                errors += 1
                print('MISMATCH   %s  %s\n           IT: %s\n           EN: %s'
                      % (used[text], problem, show(text), show(catalog[text])))
    for name, line, text in unwrapped:
        print('HINT       %s:%d  not wrapped in tr(): %s' % (name, line, show(text)[:100]))

    print('%d texts in the code, %d translations, %d problem(s)' % (len(used), len(catalog), errors))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
