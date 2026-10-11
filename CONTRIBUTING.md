# Contributing

Bug reports, false positives, missed detections and new rules are welcome: open an issue or a pull request.

When you report a false positive or a missed detection, the most useful thing is the exact text involved (the
command line, the service path, the task action, the event), with names and addresses replaced if needed.
**Never attach evidence files or data from a real case.**

## Before you change the code

- The plugin runs on **Jython 2.7** inside Autopsy: Python 2 syntax, no third-party libraries, nothing newer than
  what Jython 2.7.2 supports (it is the version shipped with Autopsy 4.19-4.21).
- Source files are **pure ASCII**. Accented letters and typographic quotes are written as `\uXXXX` escapes.
- Code, comments and identifiers are in Italian. You can write a comment in English if Italian is a problem; keep
  the existing names.
- Only `TriageCompromissione.py` talks to Autopsy. Everything else (`tc_*.py`) is independent of it and can be
  run with a plain Jython interpreter, which is what the tests do.
- Autopsy reloads only the main file: after changing a `tc_*.py` file, restart Autopsy.
- The one exception is `collectors/collect_memory.py`, which runs outside Autopsy: Python 3.8 or later, standard
  library only, code and comments in English, messages in English and Italian (the `TEXTS` table). It must keep
  collecting only: every decision belongs to the module (`tc_memoria.py`). If the content of its output changes in a
  way the module has to know, raise `FORMAT_VERSION` there and `VERSIONE_FORMATO` in `tc_memoria.py` together.

## Texts and translations

Every text the analyst can see is written in Italian in the code and translated through `tc_lingua`:

```python
from tc_lingua import tr, N_

t.avviso(tr(u'Nessun registro eventi trovato.'))                 # translated when the text is created
t.segnala(10, peso, R.F_ACCOUNT, tr(u'Account %s creato da %s') % (nome, chi))   # tr() on the format string, then %

TITOLO = N_(u'Attivit\u00e0 pianificate')     # a constant defined at import time: only marked...
mostra(tr(TITOLO))                             # ...and translated where it is shown
```

- Add the English text to `tc_lingua_en.py`, in the function of the module that uses it. The key is the Italian
  text, character for character.
- Placeholders (`%s`, `%d`, `%.1f`...) must be the same and **in the same order** in the two languages: values are
  inserted by position.
- Singular and plural are two separate complete sentences, not a sentence with a variable ending.
- Do not make decisions by comparing a text with a literal written in one language. If the code has to recognize
  a kind of finding, give it a language-neutral marker (see `genere` in `Triage.prova_rmm`); where a text has to
  be recognized, compare it with `tr()` of the same constant, in one place (see `tc_regole.sui_registri`).
- Two different reasons must not share the same English translation: reasons are also used to avoid reporting the
  same fact twice.

Then run:

```
python3 tools/check_translations.py
```

## Rules

Most rules live in `tc_regole.py` (see the table in the README); the checks that apply them are in the
`tc_c_*.py` files. When you add or change one:

- add test cases to the matching file in `tests/`, including the commands that must **not** trigger: most of the
  work on this plugin has gone into avoiding false "decisive" findings;
- remember that the same command weighs differently in a persistence entry and among executed commands (see the
  docstring of `valuta_comando`);
- run the tests with the Jython jar found in any Autopsy installation:

```
java -jar jython-standalone-2.7.4.jar tests/run_tests.py
```

If you change the memory collector, run its tests too (Python 3, no Volatility needed):

```
python3 tests/test_collect_memory.py
```

## Commits and versions

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): a type, an optional scope and
a short summary, in English.

```
feat(memoria): judge services that exist only in memory
fix(regole): do not flag the signed Teams updater
docs(readme): explain how memory and disk are paired
test(eventi): cover event 4688 without a command line
```

The types used here are `feat` (a new check, rule or output), `fix` (a wrong or missed finding, a crash), `docs`,
`test`, `refactor` and `chore` (tools, checks, repository). A version is released with a commit that changes
`VERSIONE` in `tc_controlli.py` and adds its entry to the CHANGELOG (`chore(release): 1.3`), then the tag `v1.3`
and a GitHub release with the zip built by `tools/make_release.py`. Versions 1.0 to 1.2 were imported with one
commit each.

Before every commit look at the list of changed files: `.gitignore` keeps out the usual evidence formats (memory
and disk images, Autopsy cases, reports), but nothing from a real case must ever reach the repository.

## Pull requests

Keep them small and say what you tested and how (Autopsy version, operating system, kind of data source). The
checks run by GitHub Actions on every pull request are the commands shown above, with the tests run on both
Jython 2.7.2 and 2.7.4, plus a compilation of the plugin with Jython 2.7.2.
