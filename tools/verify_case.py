#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check an Autopsy case after an analysis with Windows Compromise Triage.

It reads the case folder (autopsy.db, Log/autopsy.log.0, Reports/) and says
whether the run PASSED or FAILED, criterion by criterion. It changes nothing:
the database is opened read-only. It needs only Python 3.8 or later, with no
other package, on Windows, Linux or macOS. Run it with Autopsy closed (or at
least with the case closed).

    python3 tools/verify_case.py "C:\\Cases\\Test_20261013_101500"
    python3 tools/verify_case.py <case folder> --json result.json
    python3 tools/verify_case.py <case folder> --reference result_of_another_run.json

On Windows use "py -3" instead of "python3". The criteria (all required):

  C1  the module was loaded, with the expected version (--version, default
      1.3), according to the case log or to the database;
  C2  the last ingest job that includes the module is COMPLETED;
  C3  no error of the module: no SEVERE or WARNING line of its logger and no
      Python traceback in the case log;
  C4  consistent results: at least one verdict; for each data source, the
      decisive findings that count (score "Notable") are as many as the
      verdicts declare; the CSV of each report lists the findings written in
      the database, and its counted findings and facts match the verdict;
  C5  report: for each verdict the HTML report exists, is registered in the
      case and contains the verdict and the heuristic warning; the CSV file is
      next to it.

With --reference the findings are also compared with those of another run of
the same data source in the same language: "identical" means the same
findings (file, check, weight, family, text, score, time) and the same
verdicts.

Exit status: 0 if the run passed, 1 if it did not.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import sys

MODULE_NAMES = ('Windows Compromise Triage', 'Triage compromissione Windows')
# the second word of the header of a log record: the class of the module that wrote it
SOURCE = 'TriageCompromissioneModule'
LOG_HEADER = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (\S+) (\S+)\s*$')
LOG_LEVEL = re.compile(r'^(SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST): ?(.*)$')
JOB_STATES = {0: 'STARTED', 1: 'CANCELLED', 2: 'COMPLETED'}
WEIGHTS = {'Decisive': 3, 'Decisivo': 3, 'To confirm': 2, 'Da confermare': 2, 'Informational': 1, 'Informativo': 1}
# org.sleuthkit.datamodel.Score.Significance
NOTABLE, LIKELY_NOTABLE, UNKNOWN = 19, 9, 0
WARNING_TEXTS = ('Heuristic triage verdict', 'Verdetto euristico di triage')
YES = ('yes', 's\u00ec')


def read_log(path):
    """The log of Autopsy (java.util.logging): a header line (time, class,
    method), then 'LEVEL: text' and any continuation lines (stack traces)."""
    records = []
    if not os.path.exists(path):
        return records
    current = None
    with open(path, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            line = line.rstrip('\r\n')
            found = LOG_HEADER.match(line)
            if found:
                current = {'time': found.group(1), 'logger': found.group(2), 'method': found.group(3), 'level': None,
                           'text': '', 'more': []}
                records.append(current)
                continue
            found = LOG_LEVEL.match(line)
            if found and current is not None and current['level'] is None:
                current['level'], current['text'] = found.group(1), found.group(2)
            elif current is not None:
                current['more'].append(line)
    return records


def open_database(folder):
    path = os.path.join(folder, 'autopsy.db')
    if not os.path.exists(path):
        raise SystemExit('autopsy.db not found in %s: give the case folder (the one with the .aut file)' % folder)
    uri = 'file:%s?mode=ro' % path.replace('\\', '/').replace('?', '%3F')
    return sqlite3.connect(uri, uri=True)


def data_source_name(cursor, obj_id):
    image = cursor.execute('select name from tsk_image_names where obj_id=? order by sequence limit 1',
                           (obj_id,)).fetchone()
    if image:
        return os.path.basename(image[0].replace('\\', '/'))
    row = cursor.execute('select name from tsk_files where obj_id=?', (obj_id,)).fetchone()
    return row[0] if row else str(obj_id)


def attributes(cursor, artifact_id):
    values = {}
    for name, text, small, big in cursor.execute(
            'select t.type_name, a.value_text, a.value_int32, a.value_int64 from blackboard_attributes a '
            'join blackboard_attribute_types t on t.attribute_type_id=a.attribute_type_id where a.artifact_id=?',
            (artifact_id,)):
        values[name] = text if text is not None else (big if big is not None else small)
    return values


def results(cursor):
    """The verdicts and the findings written by the module."""
    types = dict(cursor.execute("select type_name, artifact_type_id from blackboard_artifact_types "
                                "where type_name in ('TC_SEGNALE', 'TC_VERDETTO')").fetchall())
    has_results = cursor.execute("select count(*) from sqlite_master where name='tsk_analysis_results'").fetchone()[0]
    verdicts, findings = [], []
    for kind, target in (('TC_VERDETTO', verdicts), ('TC_SEGNALE', findings)):
        if kind not in types:
            continue
        rows = cursor.execute('select artifact_id, artifact_obj_id, obj_id, data_source_obj_id from blackboard_artifacts '
                              'where artifact_type_id=?', (types[kind],)).fetchall()
        for artifact, artifact_obj, obj, source in rows:
            values = attributes(cursor, artifact)
            outcome = None
            if has_results:
                outcome = cursor.execute('select significance, conclusion from tsk_analysis_results '
                                         'where artifact_obj_id=?', (artifact_obj,)).fetchone()
            item = cursor.execute('select parent_path, name from tsk_files where obj_id=?', (obj,)).fetchone()
            entry = {'source': data_source_name(cursor, source), 'source_id': source,
                     'object': (item[0] or '') + (item[1] or '') if item else '',
                     'score': outcome[0] if outcome else None, 'conclusion': outcome[1] if outcome else None}
            if kind == 'TC_VERDETTO':
                entry.update({'computer': values.get('TC_COMPUTER'), 'verdict': values.get('TC_VERDETTO_TESTO'),
                              'reason': values.get('TC_MOTIVO'), 'counts': values.get('TC_SEGNALE_TESTO'),
                              'report': values.get('TC_REPORT')})
            else:
                entry.update({'check': values.get('TC_CONTROLLO'), 'weight': values.get('TC_PESO'),
                              'family': values.get('TC_FAMIGLIA'), 'finding': values.get('TC_SEGNALE_TESTO'),
                              'details': values.get('TC_DETTAGLI'), 'time': values.get('TSK_DATETIME'),
                              'origin': values.get('TC_ORIGINE'), 'fact': values.get('TC_FATTO')})
            target.append(entry)
    return verdicts, findings


def numbers(text):
    return [int(x) for x in re.findall(r'\d+', text or '')]


def declared(verdict):
    """(decisive findings, findings to confirm, decisive facts, facts to confirm)
    from the counts of a verdict: four numbers since 1.3, two before."""
    found = numbers(verdict['counts'])
    if len(found) == 4:
        return found[1], found[3], found[0], found[2]
    if len(found) == 2:
        return found[0], found[1], None, None
    return None


def fingerprint(findings, verdicts, with_time=True):
    keys = sorted('|'.join(str(x) for x in (f['source'], f['check'], f['weight'], f['family'], f['finding'],
                                             f['object'], f['score'], f['time'] if with_time else ''))
                  for f in findings)
    keys += sorted('V|%s|%s|%s|%s' % (v['source'], v['computer'], v['verdict'], v['score']) for v in verdicts)
    return hashlib.sha256('\n'.join(keys).encode('utf-8')).hexdigest()


def local_report(folder, path):
    """The report file of a verdict, also when the case was moved."""
    if path and os.path.exists(path):
        return path
    if path:
        moved = os.path.join(folder, 'Reports', 'TriageCompromissione', os.path.basename(path.replace('\\', '/')))
        if os.path.exists(moved):
            return moved
    return None


def read_csv(path):
    """The rows of the CSV of a report: a semicolon in Italian, a comma in English."""
    with open(path, encoding='utf-8-sig', errors='replace', newline='') as handle:
        text = handle.read()
    first = text.split('\n', 1)[0]
    delimiter = ';' if first.startswith('"Peso"') else ','
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    return rows[0] if rows else [], rows[1:]


def check_csv(rows, verdict):
    """The counted findings and facts of the CSV against the counts of the verdict."""
    numbers_declared = declared(verdict)
    if not rows or len(rows[0]) < 13 or numbers_declared is None or numbers_declared[2] is None:
        return []           # a CSV of version 1.2 or earlier: nothing to compare
    full = [r for r in rows if r[11].strip().lower() in YES and not r[12].strip()]
    decisive = [r for r in full if WEIGHTS.get(r[0]) == 3]
    confirm = [r for r in full if WEIGHTS.get(r[0]) == 2]
    decisive_facts = set(r[9] for r in decisive)
    # the findings to confirm of a decisive fact are counted with it
    confirm = [r for r in confirm if r[9] not in decisive_facts]
    confirm_facts = set(r[9] for r in confirm)
    found = (len(decisive), len(confirm), len(decisive_facts), len(confirm_facts))
    if found != tuple(numbers_declared):
        return ['%s: the verdict declares %d decisive findings, %d to confirm, %d decisive facts and %d facts to '
                'confirm; the CSV has %d, %d, %d and %d' % ((verdict['computer'],) + tuple(numbers_declared) + found)]
    return []


def verify(folder, expected_version=None, user_log=None):
    try:
        return _verify(folder, expected_version, user_log)
    except (sqlite3.DatabaseError, SystemExit) as error:
        # no database, an empty one or an incomplete one: Autopsy stopped before creating the case
        failed = {'ok': False}
        return {'case': os.path.abspath(folder), 'notes': ['case database not readable: %s' % error],
                'criteria': {'C1_module_loaded': dict(failed), 'C2_job_completed': dict(failed),
                             'C3_no_module_errors': {'ok': True, 'errors': []},
                             'C4_consistent_results': dict(failed, problems=['database not readable']),
                             'C5_report': dict(failed, problems=[])},
                'jobs': [], 'verdicts': [], 'findings': 0, 'finding_list': [], 'other_severe_of_autopsy': {},
                'fingerprint': '', 'fingerprint_without_time': '', 'result': 'FAILED', 'registered_reports': [],
                'summaries_in_log': []}


def _verify(folder, expected_version=None, user_log=None):
    result = {'case': os.path.abspath(folder), 'criteria': {}, 'notes': []}
    database = open_database(folder)
    cursor = database.cursor()
    # ingest jobs
    modules = {}
    for job, name, version in cursor.execute('select m.ingest_job_id, i.display_name, i.version from ingest_job_modules m '
                                             'join ingest_modules i on i.ingest_module_id=m.ingest_module_id'):
        modules.setdefault(job, []).append((name, version))
    jobs = []
    for job, obj, start, end, state in cursor.execute('select ingest_job_id, obj_id, start_date_time, end_date_time, '
                                                      'status_id from ingest_jobs order by ingest_job_id').fetchall():
        jobs.append({'job': job, 'source': data_source_name(cursor, obj), 'state': JOB_STATES.get(state, state),
                     'seconds': round((end - start) / 1000.0, 1) if end and start else None,
                     'modules': ['%s %s' % m for m in modules.get(job, [])],
                     'module_version': [m[1] for m in modules.get(job, []) if m[0] in MODULE_NAMES]})
    result['jobs'] = jobs
    ours = [j for j in jobs if j['module_version']]
    # the case log (Autopsy rewrites it at every opening of the case: it covers the last session)
    case_log = read_log(os.path.join(folder, 'Log', 'autopsy.log.0'))
    every_log = case_log + (read_log(user_log) if user_log else [])
    loaded = []
    for record in case_log:
        found = re.search(r'Found ingest module factory: name = (.+?), version = (\S+)', record['text'])
        if found and found.group(1) in MODULE_NAMES:
            loaded.append(found.group(2))
    in_database = sorted(set(v for j in ours for v in j['module_version']))
    seen = loaded or in_database
    result['criteria']['C1_module_loaded'] = {
        'ok': bool(seen) and (expected_version is None or expected_version in seen),
        'versions_in_log': sorted(set(loaded)), 'versions_in_database': in_database, 'expected': expected_version}
    last = ours[-1] if ours else None
    result['criteria']['C2_job_completed'] = {'ok': bool(last) and last['state'] == 'COMPLETED',
                                              'jobs_with_the_module': len(ours), 'last': last}
    errors = []
    for record in every_log:
        text = record['text'] + '\n' + '\n'.join(record['more'])
        if record['logger'].endswith(SOURCE) and record['level'] in ('SEVERE', 'WARNING'):
            errors.append('%s %s: %s' % (record['time'], record['level'], record['text'][:300]))
        elif 'Traceback (most recent call last)' in text or re.search(r'org\.python\.core\.Py\w*Exception', text):
            errors.append('%s %s (%s): %s' % (record['time'], record['level'], record['logger'], record['text'][:300]))
        elif record['level'] == 'SEVERE' and re.search(r'TriageCompromissione|Windows Compromise Triage', text):
            errors.append('%s SEVERE (%s): %s' % (record['time'], record['logger'], record['text'][:300]))
    result['criteria']['C3_no_module_errors'] = {'ok': not errors, 'errors': errors[:20]}
    others = {}
    for record in case_log:
        if record['level'] == 'SEVERE' and not record['logger'].endswith(SOURCE):
            key = re.sub(r'\d+', '#', record['text'][:160])
            others[key] = others.get(key, 0) + 1
    result['other_severe_of_autopsy'] = others
    result['summaries_in_log'] = [r['text'] for r in case_log if r['logger'].endswith(SOURCE) and
                                  re.match(r'(Triage of|Triage di|Triage completed|Triage completato)', r['text'])]
    # results
    verdicts, findings = results(cursor)
    result['verdicts'] = verdicts
    result['findings'] = len(findings)
    problems = []
    if not verdicts:
        problems.append('no verdict in the database')
    per_source = {}
    for verdict in verdicts:
        counts = declared(verdict)
        if counts is None:
            problems.append('counts not readable in the verdict of %s: %r' % (verdict['computer'], verdict['counts']))
            continue
        total = per_source.setdefault((verdict['source_id'], verdict['source']), [0, 0])
        total[0] += counts[0]
        total[1] += counts[1]
    written = {}
    for finding in findings:
        key = (finding['source_id'], finding['source'])
        weight = WEIGHTS.get(finding['weight'])
        tally = written.setdefault(key, {'decisive': 0, 'decisive_notable': 0, 'confirm': 0, 'confirm_likely': 0,
                                         'all': 0})
        tally['all'] += 1
        if weight == 3:
            tally['decisive'] += 1
            tally['decisive_notable'] += 1 if finding['score'] in (NOTABLE, None) else 0
        elif weight == 2:
            tally['confirm'] += 1
            tally['confirm_likely'] += 1 if finding['score'] in (LIKELY_NOTABLE, None) else 0
    for (source_id, source), (decisive, confirm) in sorted(per_source.items()):
        tally = written.get((source_id, source), {'decisive_notable': 0, 'confirm_likely': 0})
        if decisive != tally['decisive_notable'] or confirm > tally['confirm_likely']:
            problems.append('%s: the verdicts declare %d decisive findings and %d to confirm that count; the database '
                            'has %d decisive findings scored "Notable" and %d to confirm scored "Likely Notable"'
                            % (source, decisive, confirm, tally['decisive_notable'], tally['confirm_likely']))
    for key in written:
        if key not in per_source:
            problems.append('%s (object %s): findings without a verdict' % (key[1], key[0]))
    # the CSV of each report against the database and the verdict
    csv_rows = {}
    for verdict in verdicts:
        path = local_report(folder, verdict.get('report'))
        if not path or not os.path.exists(path[:-5] + '.csv'):
            continue
        _, rows = read_csv(path[:-5] + '.csv')
        problems.extend(check_csv(rows, verdict))
        key = (verdict['source_id'], verdict['source'])
        csv_rows[key] = csv_rows.get(key, 0) + len(rows)
    for key, count in sorted(csv_rows.items()):
        in_database = written.get(key, {}).get('all', 0)
        if count != in_database:
            problems.append('%s: %d findings in the CSV files, %d in the database' % (key[1], count, in_database))
    result['criteria']['C4_consistent_results'] = {
        'ok': not problems, 'problems': problems,
        'findings_by_weight': dict(('%s#%s' % (k[1], k[0]), v) for k, v in written.items())}
    # reports
    registered = {}
    for path, name, module in cursor.execute('select path, report_name, src_module_name from reports'):
        full = os.path.join(folder, path) if not os.path.isabs(path) else path
        registered[os.path.normcase(os.path.normpath(full))] = name
    missing = []
    for verdict in verdicts:
        given = verdict.get('report')
        if not given:
            missing.append('%s: the verdict does not name its report' % verdict['computer'])
            continue
        path = local_report(folder, given)
        if not path:
            missing.append('%s: report not found (%s)' % (verdict['computer'], given))
            continue
        with open(path, encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        if verdict['verdict'] and verdict['verdict'] not in text:
            missing.append('%s: the report does not contain the verdict "%s"' % (verdict['computer'], verdict['verdict']))
        if expected_version not in ('1.0', '1.1', '1.2') and not [w for w in WARNING_TEXTS if w in text]:
            missing.append('%s: the report does not contain the heuristic warning' % verdict['computer'])
        if not os.path.exists(path[:-5] + '.csv'):
            missing.append('%s: no CSV file next to the report' % verdict['computer'])
        keys = (os.path.normcase(os.path.normpath(given)), os.path.normcase(os.path.normpath(path)))
        if keys[0] not in registered and keys[1] not in registered and \
                not [k for k in registered if os.path.basename(k) == os.path.basename(keys[1])]:
            missing.append('%s: report not registered in the case' % verdict['computer'])
    result['registered_reports'] = sorted(registered.values())
    result['criteria']['C5_report'] = {'ok': bool(verdicts) and not missing, 'problems': missing}
    result['fingerprint'] = fingerprint(findings, verdicts)
    result['fingerprint_without_time'] = fingerprint(findings, verdicts, with_time=False)
    result['finding_list'] = sorted('|'.join(str(x) for x in (f['source'], f['check'], f['weight'], f['family'],
                                                              f['finding'], f['object'], f['score'], f['time']))
                                    for f in findings)
    result['result'] = 'PASSED' if all(c['ok'] for c in result['criteria'].values()) else 'FAILED'
    database.close()
    return result


def compare(result, reference):
    mine, theirs = set(result['finding_list']), set(reference['finding_list'])
    verdicts_here = sorted('%s|%s|%s' % (v['source'], v['computer'], v['verdict']) for v in result['verdicts'])
    verdicts_there = sorted('%s|%s|%s' % (v['source'], v['computer'], v['verdict']) for v in reference['verdicts'])

    def without_time(items):
        return set(x.rsplit('|', 1)[0] for x in items)
    return {'identical': mine == theirs and verdicts_here == verdicts_there,
            'identical_without_time': without_time(mine) == without_time(theirs) and verdicts_here == verdicts_there,
            'only_here': sorted(mine - theirs)[:30], 'only_in_reference': sorted(theirs - mine)[:30],
            'verdicts_here': verdicts_here, 'verdicts_in_reference': verdicts_there}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Check an Autopsy case analyzed with Windows Compromise Triage.')
    parser.add_argument('case', help='the case folder (the one with autopsy.db and the .aut file)')
    parser.add_argument('--json', help='write the complete result here (JSON)')
    parser.add_argument('--version', default='1.3', help='expected version of the module (default: 1.3)')
    parser.add_argument('--reference', help='the JSON of another run on the same data source, in the same language')
    parser.add_argument('--user-log', help='also the general log of Autopsy (for example '
                                           '%%APPDATA%%\\autopsy\\var\\log\\autopsy.log.0)')
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors='replace')
    except (AttributeError, ValueError):
        pass
    result = verify(args.case, args.version, args.user_log)
    if args.reference:
        with open(args.reference, encoding='utf-8') as handle:
            result['comparison'] = compare(result, json.load(handle))
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(result, handle, indent=1, ensure_ascii=False)
    print('Case: %s' % result['case'])
    for job in result['jobs']:
        print('  job %s on %s: %s, %s s, modules: %s' % (job['job'], job['source'], job['state'], job['seconds'],
                                                         ', '.join(job['modules'])[:200]))
    for name, criterion in result['criteria'].items():
        print('  %-26s %s' % (name, 'OK' if criterion['ok'] else 'NO'))
        for key in ('errors', 'problems'):
            for item in criterion.get(key, []):
                print('      - %s' % item)
    for verdict in result['verdicts']:
        print('  verdict %s / %s: %s (%s)' % (verdict['source'], verdict['computer'], verdict['verdict'],
                                              verdict['counts']))
    print('  findings in the database: %d   fingerprint: %s' % (result['findings'], result['fingerprint'][:16]))
    if result['other_severe_of_autopsy']:
        print('  other SEVERE errors of Autopsy (not of the module):')
        for text, count in sorted(result['other_severe_of_autopsy'].items()):
            print('      %dx %s' % (count, text))
    if 'comparison' in result:
        comparison = result['comparison']
        print('  compared with the reference: %s' % ('identical' if comparison['identical'] else
                                                     'identical apart from the times'
                                                     if comparison['identical_without_time'] else 'DIFFERENT'))
    print('RESULT: %s' % result['result'])
    return 0 if result['result'] == 'PASSED' else 1


if __name__ == '__main__':
    sys.exit(main())
