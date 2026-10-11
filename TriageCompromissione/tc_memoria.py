# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_memoria - La RAM: i risultati di Volatility 3 raccolti con
collectors/collect_memory.py, letti e giudicati con le regole del plugin.

Lo script di raccolta non giudica nulla: lancia alcuni plugin di Volatility
e ne salva l'output JSON, senza toccarlo, accanto a un manifesto
(compromise-triage-memory.json) che dice cosa e' stato eseguito e com'e'
andato. L'analista aggiunge la cartella al caso come file logici; qui la si
ritrova e si riempiono i controlli dei dati volatili:

   3  utenti collegati           windows.sessions
   4  processi e riga di comando windows.pslist, pstree, psscan, cmdline
   5  connessioni di rete        windows.netscan (o netstat)
   7  connessioni SMB            windows.netscan (o netstat)

con le stesse regole che il plugin usa per il disco (tc_regole, e
tc_eventi.giudica_processo come per gli eventi 4688), piu' alcune regole che
hanno senso solo nella memoria: processi nascosti, processi di sistema con il
padre sbagliato, interpreti avviati da un documento o da un server web,
programmi che non dovrebbero collegarsi a Internet. I servizi trovati nella
memoria (windows.svcscan) si giudicano solo se il registro non li ha: quelli
che ci sono li ha gia' valutati il controllo 17.

La cache DNS (controllo 6) e le sessioni SMB vere e proprie non si ricavano
con i plugin di Volatility 3: restano al triage dal vivo.

Ogni risultato di Volatility e' legato a un computer: lo si riconosce dal
nome (variabile COMPUTERNAME dei processi). Si usa la RAM che sta nella
stessa origine dati dell'installazione di Windows oppure, da un'altra
origine dati del caso, quella con lo stesso nome di computer.
"""

import calendar
import json
import re

import tc_regole as R
import tc_eventi
import tc_c_registro
from tc_base import testo_orario as T, pulito, ERRORI
from tc_lingua import tr

NOME_MANIFESTO = u'compromise-triage-memory.json'
FORMATO = u'windows-compromise-triage/memory'
VERSIONE_FORMATO = 1
MASSIMO_FILE = 512 * 1024 * 1024        # un output piu' grande non si legge: Autopsy finirebbe la memoria
MASSIMO_RIGHE = 300000

# Le chiavi del manifesto, i plugin che le producono e i controlli che ne
# dipendono (per dire cosa resta incompleto se un plugin non e' riuscito)
CHIAVI = [
    (u'info', u'windows.info', ()),
    (u'pslist', u'windows.pslist', (4,)),
    (u'pstree', u'windows.pstree', (4,)),
    (u'psscan', u'windows.psscan', (4,)),
    (u'cmdline', u'windows.cmdline', (4,)),
    (u'network', u'windows.netscan', (5, 7)),
    (u'sessions', u'windows.sessions', (3,)),
    (u'envars', u'windows.envars', ()),
    (u'getsids', u'windows.getsids', ()),
    (u'svcscan', u'windows.svcscan', (17, 29)),
]

# Processi di sistema e il padre che hanno su ogni Windows (quello vero non
# termina mai, percio' si puo' controllare)
_PADRI_ATTESI = {
    u'svchost.exe': (u'services.exe',),
    u'services.exe': (u'wininit.exe',),
    u'lsass.exe': (u'wininit.exe',),
    u'lsaiso.exe': (u'wininit.exe',),
}
# processi di cui ne gira uno solo
_UNICI = (u'wininit.exe', u'services.exe', u'lsass.exe', u'lsaiso.exe')
# programmi per documenti e server: di norma non aprono interpreti di comandi
_PADRI_DOCUMENTI = set([u'winword.exe', u'excel.exe', u'powerpnt.exe', u'outlook.exe', u'msaccess.exe', u'mspub.exe',
                        u'onenote.exe', u'visio.exe', u'acrord32.exe', u'acrobat.exe', u'foxitpdfreader.exe',
                        u'w3wp.exe', u'sqlservr.exe', u'httpd.exe', u'nginx.exe', u'php-cgi.exe',
                        u'umworkerprocess.exe', u'tomcat.exe', u'tomcat8.exe', u'tomcat9.exe'])
_INTERPRETI = set([u'cmd.exe', u'powershell.exe', u'pwsh.exe', u'wscript.exe', u'cscript.exe', u'mshta.exe',
                   u'rundll32.exe', u'regsvr32.exe', u'certutil.exe', u'bitsadmin.exe', u'wmic.exe', u'msbuild.exe',
                   u'installutil.exe'])
# programmi di Windows che di norma non si collegano a Internet
_SENZA_INTERNET = set([u'rundll32.exe', u'regsvr32.exe', u'mshta.exe', u'wscript.exe', u'cscript.exe', u'msbuild.exe',
                       u'installutil.exe', u'regasm.exe', u'regsvcs.exe', u'cmstp.exe', u'certutil.exe',
                       u'bitsadmin.exe', u'notepad.exe', u'cmd.exe', u'powershell.exe', u'pwsh.exe', u'wmic.exe'])
# utenti che non sono persone (nella tabella delle sessioni)
_RX_UTENTE_DI_SISTEMA = re.compile(u'(^|[\\\\/])(system|local service|network service|dwm-\\d+|umfd-\\d+|'
                                   u'[^\\\\/]*\\$)$', re.I)
# una riga di comando che Volatility non ha potuto leggere (le versioni fino
# alla 2.11 scrivono il motivo al posto della riga)
_RX_RIGA_ILLEGGIBILE = re.compile(u'^(process \\d+: )?required memory at 0x[0-9a-f]+ is', re.I)
_RX_ORA = re.compile(u'^(\\d{4})-(\\d\\d)-(\\d\\d)[T ](\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?\\s*(Z|[+-]\\d\\d:?\\d\\d)?$')
_STATI_ATTIVI = (u'ESTABLISHED', u'SYN_SENT', u'SYN_RCVD', u'CLOSE_WAIT', u'FIN_WAIT1', u'FIN_WAIT2', u'CLOSING',
                 u'LAST_ACK', u'TIME_WAIT', u'CLOSED', u'DELETE_TCB')


# --------------------------------------------------------------------------
# Valori dell'output di Volatility
# --------------------------------------------------------------------------

def _testo(valore):
    """Un valore come testo ('' per null)."""
    if valore is None or valore is True or valore is False:
        return u''
    if isinstance(valore, unicode):
        return pulito(valore).strip()
    return pulito(unicode(valore)).strip()


def _intero(valore, predefinito=None):
    if isinstance(valore, bool):
        return predefinito
    if isinstance(valore, (int, long)):
        return valore
    try:
        return int(unicode(valore).strip(), 0)
    except ERRORI:
        return predefinito


def ora_da_iso(valore):
    """Un orario di Volatility ('2026-09-28T14:05:12+00:00', oppure con lo
    spazio, i decimali o un altro fuso) -> secondi epoch UTC (0 se non c'e')."""
    if not valore or not isinstance(valore, basestring):
        return 0.0
    m = _RX_ORA.match(valore.strip())
    if m is None:
        return 0.0
    try:
        secondi = calendar.timegm(tuple([int(m.group(i)) for i in range(1, 7)]) + (0, 0, 0))
    except ERRORI:
        return 0.0
    fuso = m.group(7)
    if fuso and fuso != u'Z':
        cifre = fuso[1:].replace(u':', u'')
        scarto = int(cifre[:2]) * 3600 + int(cifre[2:4]) * 60
        secondi -= scarto if fuso[0] == u'+' else -scarto
    return float(secondi) if secondi > 0 else 0.0


def _indirizzo(ip, porta):
    """Indirizzo e porta come si scrivono: 10.0.0.5:445, [fe80::1]:445."""
    if u':' in ip:
        return u'[%s]:%d' % (ip, porta)
    return u'%s:%d' % (ip, porta)


def _riga_di_comando(valore):
    riga = _testo(valore).replace(u'\x00', u'')
    if not riga or _RX_RIGA_ILLEGGIBILE.match(riga):
        return u''
    return riga


def _piatte(righe, uscita, profondita=0):
    """Le righe di un output, con quelle annidate (pstree) di seguito."""
    for r in righe:
        if not isinstance(r, dict):
            continue
        uscita.append(r)
        figli = r.get(u'__children')
        if figli and isinstance(figli, list) and profondita < 200:
            _piatte(figli, uscita, profondita + 1)
    return uscita


def _fatto_se_manca(t, controllo, nota):
    """Segna un controllo come fatto (con la nota) se nessun altro passo l'ha
    gia' fatto con i dati del disco."""
    if t.esiti.get(controllo, ('',))[0] != 'fatto':
        t.esito(controllo, 'fatto', nota)


def _dimensione(byte):
    for unita in (u'byte', u'KB', u'MB', u'GB', u'TB'):
        if byte < 1024 or unita == u'TB':
            return (u'%d %s' % (byte, unita)) if unita == u'byte' else (u'%.1f %s' % (byte, unita))
        byte /= 1024.0


# --------------------------------------------------------------------------
# I risultati di una RAM
# --------------------------------------------------------------------------

def trova(origine):
    """I manifesti delle raccolte della RAM presenti nell'origine."""
    return [e for e in origine.cerca(u'%', NOME_MANIFESTO) if not e.e_cartella and e.dimensione > 0]


class Memoria(object):
    """Una cartella prodotta da collect_memory.py: il manifesto e gli output
    dei plugin di Volatility."""

    def __init__(self, origine, manifesto, nome_origine=u'', stessa_origine=True):
        self.origine = origine
        self.manifesto = manifesto
        self.nome_origine = nome_origine or u''
        self.stessa_origine = stessa_origine
        self.letta = False
        self.errore = u''           # perche' la cartella non si puo' usare
        self.dati = {}
        self.voci = {}              # chiave -> voce del manifesto con esito 'ok'
        self.problemi = {}          # chiave -> esito ('failed', 'timeout', 'mancante', 'illeggibile')
        self.computer = u''
        self.ora = 0.0              # ora di sistema nella RAM (windows.info)
        self.immagine = u''
        self._righe = {}
        self._elementi = {}

    def cartella(self):
        return self.manifesto.cartella

    def etichetta(self):
        return self.immagine or self.cartella()

    def leggi(self):
        """Legge il manifesto (una volta sola). Falso se la cartella non si
        puo' usare: il motivo e' in self.errore."""
        if self.letta:
            return not self.errore
        self.letta = True
        try:
            dati = self.manifesto.tutto(16 * 1024 * 1024)
        except ERRORI, errore:
            self.errore = tr(u'manifesto non leggibile (%s)') % pulito(unicode(errore))[:200]
            return False
        finally:
            self.manifesto.chiudi()
        try:
            self.dati = json.loads(dati.decode('utf-8', 'replace'))
        except ERRORI:
            self.errore = tr(u'%s danneggiato: non \u00e8 un testo JSON valido') % NOME_MANIFESTO
            self.dati = {}
            return False
        if not isinstance(self.dati, dict) or self.dati.get(u'format') != FORMATO:
            self.errore = tr(u'%s non \u00e8 un manifesto dello script di raccolta') % NOME_MANIFESTO
            self.dati = {}
            return False
        versione = _intero(self.dati.get(u'format_version'), 0)
        if versione > VERSIONE_FORMATO:
            self.errore = tr(u'il manifesto \u00e8 di una versione pi\u00f9 recente dello script di raccolta (formato %d): '
                             u'aggiorna il plugin') % versione
            return False
        immagine = self.dati.get(u'image') if isinstance(self.dati.get(u'image'), dict) else {}
        self.immagine = _testo(immagine.get(u'name'))
        ospite = self.dati.get(u'host') if isinstance(self.dati.get(u'host'), dict) else {}
        self.computer = _testo(ospite.get(u'computer_name'))
        self.ora = ora_da_iso(_testo(ospite.get(u'system_time')))
        plugin = self.dati.get(u'plugins') if isinstance(self.dati.get(u'plugins'), list) else []
        for voce in plugin:
            if not isinstance(voce, dict):
                continue
            chiave = _testo(voce.get(u'key'))
            if voce.get(u'status') == u'ok' and voce.get(u'file') and chiave not in self.voci:
                self.voci[chiave] = voce
                self.problemi.pop(chiave, None)
            elif chiave not in self.voci:
                self.problemi[chiave] = _testo(voce.get(u'status')) or u'failed'
        for chiave, _, _ in CHIAVI:
            if chiave not in self.voci and chiave not in self.problemi:
                self.problemi[chiave] = u'mancante'
        if not self.computer:
            self.computer = self._computer_da_envars()
        if not self.ora:
            for r in self.righe(u'info') or []:
                if r.get(u'Variable') == u'SystemTime':
                    self.ora = ora_da_iso(_testo(r.get(u'Value')))
        return True

    def _computer_da_envars(self):
        conti = {}
        for r in self.righe(u'envars') or []:
            if _testo(r.get(u'Variable')).upper() == u'COMPUTERNAME':
                nome = _testo(r.get(u'Value'))
                if nome:
                    conti[nome] = conti.get(nome, 0) + 1
        if not conti:
            return u''
        return sorted(conti.items(), key=lambda x: (-x[1], x[0]))[0][0]

    def righe(self, chiave):
        """Le righe dell'output di un plugin (con quelle annidate), oppure
        None se il plugin non e' riuscito o il file non si legge."""
        if chiave in self._righe:
            return self._righe[chiave]
        righe = None
        voce = self.voci.get(chiave)
        if voce is not None:
            nome = _testo(voce.get(u'file'))
            trovati = [e for e in self.origine.in_cartella([self.manifesto.cartella], nome, self.manifesto.volume)]
            if not trovati or u'/' in nome or u'\\' in nome:
                self.problemi[chiave] = u'file mancante'
            elif trovati[0].dimensione > MASSIMO_FILE:
                self.problemi[chiave] = u'troppo grande'
            else:
                e = trovati[0]
                try:
                    try:
                        dati = e.tutto(MASSIMO_FILE)
                    finally:
                        e.chiudi()
                    contenuto = json.loads(dati.decode('utf-8', 'replace'))
                    if isinstance(contenuto, list):
                        righe = _piatte(contenuto, [])
                        if len(righe) > MASSIMO_RIGHE:
                            righe = righe[:MASSIMO_RIGHE]
                        self._elementi[chiave] = e
                    else:
                        self.problemi[chiave] = u'illeggibile'
                except ERRORI:
                    self.problemi[chiave] = u'illeggibile'
        if righe is None:
            self.voci.pop(chiave, None)
        self._righe[chiave] = righe
        return righe

    def elemento(self, chiave):
        """Il file a cui legare un segnale: quello dell'output, se la RAM sta
        nella stessa origine dati; altrimenti nessuno (il segnale va
        sull'origine analizzata, cosi' una nuova analisi lo sostituisce)."""
        if not self.stessa_origine:
            return None
        return self._elementi.get(chiave) or self.manifesto

    def plugin(self, chiave):
        voce = self.voci.get(chiave)
        if voce is not None:
            return _testo(voce.get(u'plugin'))
        return dict([(c, p) for c, p, _ in CHIAVI]).get(chiave, chiave)

    def scarta(self):
        """Libera le righe lette (occupano memoria): servono solo durante
        l'analisi."""
        self._righe = {}


# --------------------------------------------------------------------------
# L'analisi
# --------------------------------------------------------------------------

def analizza(t):
    """Il passo del triage: sceglie le RAM di questa installazione di Windows
    e le analizza. Senza RAM non fa nulla (i controlli 3-7 restano non
    verificabili)."""
    candidate = getattr(t, 'memorie', None) or []
    if not candidate:
        return
    computer = (t.contesto.get('computer') or u'').strip()
    scelte = []
    for m in candidate:
        if not m.leggi():
            if m.stessa_origine:
                t.avviso(tr(u'RAM: i risultati di Volatility in %s non si possono usare: %s. I controlli sui dati '
                            u'volatili non sono stati fatti.') % (m.cartella(), m.errore))
            continue
        nome = m.computer.lower()
        if t.radice.piatta:
            # Un'origine senza Windows: la RAM che contiene e', da sola, la
            # cosa da analizzare. Se contiene le RAM di piu' computer si
            # analizza quella del primo: mescolarle darebbe un verdetto che
            # non riguarda nessuna macchina.
            if computer and nome and nome != computer.lower():
                if m.stessa_origine:
                    t.nota(tr(u'Nell\'origine dati ci sono i risultati di Volatility di un altro computer (%s, in %s): '
                              u'non sono stati usati per %s.') % (m.computer, m.cartella(), computer))
                continue
            if m.stessa_origine or (computer and nome == computer.lower()):
                scelte.append(m)
                if not computer and m.computer:
                    computer = m.computer
            continue
        if computer and nome:
            if nome == computer.lower():
                scelte.append(m)
                if not m.stessa_origine:
                    t.nota(tr(u'La RAM viene da un\'altra origine dati del caso (\u00ab%s\u00bb, %s): \u00e8 stata usata '
                              u'perch\u00e9 il nome del computer \u00e8 lo stesso (%s).') % (m.nome_origine, m.cartella(), m.computer))
            elif m.stessa_origine:
                t.nota(tr(u'Nell\'origine dati ci sono i risultati di Volatility di un altro computer (%s, in %s): non sono '
                          u'stati usati per %s.') % (m.computer, m.cartella(), computer))
            continue
        if m.stessa_origine and t.radice.unica:
            scelte.append(m)
            t.nota(tr(u'I risultati di Volatility in %s sono stati usati perch\u00e9 stanno nella stessa origine dati, ma '
                      u'il nome del computer non si \u00e8 potuto confrontare con quello del registro.') % m.cartella())
    for m in candidate:
        if m not in scelte:
            m.scarta()      # le righe lette per riconoscerla (envars) non servono piu'
    for m in scelte:
        if not t.contesto.get('computer') and m.computer:
            t.contesto['computer'] = m.computer
        try:
            _analizza_una(t, m)
        finally:
            m.scarta()


def _analizza_una(t, m):
    etichetta = m.etichetta()
    dati = m.dati
    immagine = dati.get(u'image') if isinstance(dati.get(u'image'), dict) else {}
    volatility = dati.get(u'volatility') if isinstance(dati.get(u'volatility'), dict) else {}
    info = {'immagine': etichetta, 'sha256': _testo(immagine.get(u'sha256')),
            'dimensione': _intero(immagine.get(u'size'), 0) or 0, 'ora': m.ora, 'computer': m.computer,
            'volatility': _testo(volatility.get(u'version')), 'cartella': m.cartella(),
            'origine': u'' if m.stessa_origine else m.nome_origine, 'totale': len(CHIAVI)}
    t.contesto.setdefault('memorie', []).append(info)
    for r in m.righe(u'info') or []:
        variabile = _testo(r.get(u'Variable'))
        if variabile == u'Major/Minor':
            info['build'] = _testo(r.get(u'Value')).split(u'.')[-1]
        elif variabile == u'NtProductType':
            info['tipo'] = _testo(r.get(u'Value'))
    if m.computer or m.ora:
        # senza registro (un'origine con la sola RAM) il contesto viene dalla RAM
        _fatto_se_manca(t, 1, tr(u'dalla RAM: nome del computer e ora dell\'acquisizione'))
    processi = _processi(t, m)
    _rete(t, m, processi)
    _sessioni(t, m)
    _servizi(t, m)
    t.esito(6, 'non verificabile', tr(u'Volatility 3 non ha un plugin per la cache DNS: serve il triage dal vivo'))
    # i plugin senza risultati e i controlli che ne risentono
    info['riusciti'] = len([c for c, _, _ in CHIAVI if c in m.voci])
    mancanti = [c for c, _, _ in CHIAVI if c not in m.voci]
    if mancanti:
        motivi = {u'failed': tr(u'non riuscito'), u'timeout': tr(u'fermato dopo il tempo massimo'),
                  u'mancante': tr(u'non eseguito'), u'file mancante': tr(u'file non trovato'),
                  u'illeggibile': tr(u'output illeggibile'), u'troppo grande': tr(u'output troppo grande')}
        nomi = [u'%s (%s)' % (m.plugin(c), motivi.get(m.problemi.get(c), m.problemi.get(c) or motivi[u'failed']))
                for c in mancanti]
        toccati = []
        for c, _, controlli in CHIAVI:
            if c in mancanti:
                for n in controlli:
                    if n not in toccati:
                        toccati.append(n)
        if (17 in toccati or 29 in toccati) and t.contesto.get('servizi_registro') is not None:
            # i servizi li ha gia' controllati il registro
            toccati = [n for n in toccati if n not in (17, 29)]
        if toccati:
            t.avviso(tr(u'RAM %s, plugin di Volatility senza risultati: %s. Controlli incompleti: %s.')
                     % (etichetta, u', '.join(nomi), u', '.join([unicode(n) for n in sorted(toccati)])))
        else:
            t.nota(tr(u'RAM %s, plugin di Volatility senza risultati: %s. I controlli non ne risentono.')
                   % (etichetta, u', '.join(nomi)))
    if dati.get(u'interrupted'):
        t.nota(tr(u'RAM %s: la raccolta con Volatility \u00e8 stata interrotta prima della fine.') % etichetta)


class _Processo(object):
    """Un processo trovato da Volatility."""

    def __init__(self, r, in_lista):
        self.pid = _intero(r.get(u'PID'), -1)
        self.ppid = _intero(r.get(u'PPID'), -1)
        self.nome = _testo(r.get(u'ImageFileName'))
        self.creato = ora_da_iso(r.get(u'CreateTime'))
        self.uscito = ora_da_iso(r.get(u'ExitTime'))
        self.sessione = _intero(r.get(u'SessionId'))
        self.thread = _intero(r.get(u'Threads'), 0) or 0
        self.in_lista = in_lista
        self.in_scansione = not in_lista
        self.percorso = u''
        self.audit = u''
        self.riga = u''
        self.utente = u''
        self.immagine = u''
        self.base = u''
        self.peso = 0
        self.famiglia = u''

    def chiave(self):
        return (self.pid, int(self.creato))

    def breve(self):
        """Il nome del programma, con le maiuscole com'e' scritto."""
        if u'\\' in self.immagine:
            return self.immagine.rstrip(u'\\').split(u'\\')[-1]
        return self.immagine or self.nome

    def mostrato(self):
        return self.riga or self.immagine or self.nome


def _elenco_processi(m):
    """I processi di tutte le fonti, uniti: (elenco, lista riuscita, scansione riuscita)."""
    lista = m.righe(u'pslist')
    albero = m.righe(u'pstree')
    scansione = m.righe(u'psscan')
    base = lista if lista is not None else albero
    elenco = []
    per_chiave = {}
    for r in base or []:
        p = _Processo(r, True)
        if p.pid < 0 or p.chiave() in per_chiave:
            continue
        per_chiave[p.chiave()] = p
        elenco.append(p)
    per_pid = {}
    for p in elenco:
        per_pid.setdefault(p.pid, p)
    for r in albero or []:
        pid = _intero(r.get(u'PID'), -1)
        p = per_chiave.get((pid, int(ora_da_iso(r.get(u'CreateTime'))))) or per_pid.get(pid)
        if p is None:
            continue
        p.audit = p.audit or _testo(r.get(u'Audit'))
        p.percorso = p.percorso or _testo(r.get(u'Path'))
        p.riga = p.riga or _riga_di_comando(r.get(u'Cmd'))
    righe_comando = {}
    for r in m.righe(u'cmdline') or []:
        pid = _intero(r.get(u'PID'), -1)
        riga = _riga_di_comando(r.get(u'Args'))
        if riga:
            righe_comando.setdefault(pid, riga)
    for p in elenco:
        if not p.riga and p.pid in righe_comando:
            p.riga = righe_comando[p.pid]
    for r in scansione or []:
        p = _Processo(r, False)
        if p.pid < 0:
            continue
        gia = per_chiave.get(p.chiave())
        if gia is not None:
            gia.in_scansione = True
            continue
        if base is None:
            p.in_lista = True       # senza elenco dei processi attivi, la scansione e' l'elenco
        per_chiave[p.chiave()] = p
        elenco.append(p)
    # gli utenti: il primo SID del token (windows.getsids), altrimenti le variabili d'ambiente
    utenti = {}
    for r in m.righe(u'getsids') or []:
        pid = _intero(r.get(u'PID'), -1)
        sid = _testo(r.get(u'SID'))
        if pid not in utenti and sid.upper().startswith(u'S-'):    # non "Token unreadable"
            utenti[pid] = _testo(r.get(u'Name')) or sid
    if not utenti:
        variabili = {}
        for r in m.righe(u'envars') or []:
            nome = _testo(r.get(u'Variable')).upper()
            if nome in (u'USERNAME', u'USERDOMAIN'):
                variabili.setdefault(_intero(r.get(u'PID'), -1), {})[nome] = _testo(r.get(u'Value'))
        for pid, v in variabili.items():
            utenti[pid] = u'\\'.join([x for x in (v.get(u'USERDOMAIN'), v.get(u'USERNAME')) if x])
    for p in elenco:
        p.utente = utenti.get(p.pid, u'') if p.in_lista else u''
        p.immagine = _immagine(p)
        if u'\\' in p.immagine:
            p.base = R.nome_base(p.immagine)
        else:
            p.base = (p.immagine or p.nome).lower()
    elenco.sort(key=lambda p: (p.creato, p.pid))
    return elenco, base is not None, scansione is not None and base is not None


def _immagine(p):
    """Il percorso del programma: quello del PEB, poi quello del kernel
    (\\Device\\HarddiskVolumeN\\...), poi l'inizio della riga di comando."""
    if p.percorso and u'\\' in p.percorso:
        return p.percorso
    if p.audit and u'\\' in p.audit:
        return p.audit
    if p.riga:
        eseguibile = R.spezza_comando(p.riga)[0]
        if u'\\' in eseguibile:
            return eseguibile
    return p.nome


def _vivo_al(processi, pid, ora):
    """Il processo con quel PID che esisteva all'ora indicata (i PID si
    riusano: si prende l'ultimo avviato prima)."""
    scelto = None
    for p in processi:
        if p.pid != pid:
            continue
        if ora and p.creato and p.creato > ora + 1:
            continue
        if scelto is None or p.creato > scelto.creato:
            scelto = p
    return scelto


def _dettagli(p, padre, etichetta, fonti):
    righe = []
    if p.riga:
        righe.append(tr(u'Riga di comando: %s') % p.riga[:2500])
    if p.immagine and p.immagine != p.riga:
        righe.append(tr(u'Programma: %s') % p.immagine)
    if padre is not None:
        righe.append(tr(u'Processo padre: %s (PID %d)') % (padre.immagine or padre.nome, padre.pid))
    elif p.ppid >= 0:
        righe.append(tr(u'Processo padre: PID %d, non pi\u00f9 attivo') % p.ppid)
    if p.utente:
        righe.append(tr(u'Utente: %s') % p.utente)
    if p.creato:
        righe.append(tr(u'Avviato: %s (UTC)') % T(p.creato))
    if p.uscito:
        righe.append(tr(u'Terminato: %s (UTC)') % T(p.uscito))
    if not p.in_lista:
        righe.append(tr(u'Trovato solo dalla scansione della memoria (psscan), non nell\'elenco dei processi attivi.'))
    righe.append(tr(u'Fonte: RAM %s, %s') % (etichetta, fonti))
    return u'\n'.join(righe)


def _processi(t, m):
    """Controllo 4: processi, righe di comando e processi padre."""
    elenco, lista_ok, scansione_ok = _elenco_processi(m)
    if not elenco:
        t.esito(4, 'non verificabile', tr(u'la RAM c\'\u00e8, ma Volatility non ha prodotto l\'elenco dei processi'))
        return elenco
    t.fatto(4)
    etichetta = m.etichetta()
    fonte = u'pstree' if u'pstree' in m.voci else (u'pslist' if u'pslist' in m.voci else u'psscan')
    elemento = m.elemento(fonte)
    fonti = u', '.join([m.plugin(c) for c in (u'pslist', u'pstree', u'psscan', u'cmdline') if c in m.voci])
    per_pid = {}
    for p in elenco:
        per_pid.setdefault(p.pid, []).append(p)

    def padre_di(p):
        # il padre esisteva quando il figlio e' partito: avviato prima e non ancora terminato
        candidati = [x for x in per_pid.get(p.ppid, []) if x is not p
                     and not (x.creato and p.creato and x.creato > p.creato + 1)
                     and not (x.uscito and p.creato and x.uscito < p.creato - 1)]
        if not candidati:
            return None
        return sorted(candidati, key=lambda x: x.creato)[-1]

    def annota(p, peso, famiglia):
        if peso > p.peso:
            p.peso = peso
            p.famiglia = famiglia

    # le regole di sempre (come per gli eventi 4688 e Sysmon), un segnale per programma e motivo
    gruppi = {}
    ordine = []
    for p in elenco:
        for peso, famiglia, cosa, per_riga, chiaro in tc_eventi.giudica_processo(p.immagine, p.base, p.riga):
            chiave = (p.immagine.lower(), p.riga if per_riga else u'', cosa)
            g = gruppi.get(chiave)
            if g is None:
                g = {'peso': peso, 'famiglia': famiglia, 'cosa': cosa, 'processi': [], 'chiaro': chiaro, 'per_riga': per_riga}
                gruppi[chiave] = g
                ordine.append(chiave)
            g['processi'].append(p)
            annota(p, peso, famiglia)
        strumento = R.trova_rmm(p.immagine + u' ' + p.riga)
        if strumento:
            t.prova_rmm(strumento, tr(u'processo nella RAM'), u'%s (PID %d)' % (p.mostrato()[:300], p.pid), p.creato,
                        elemento, 4, genere='eseguito')
    for chiave in ordine:
        g = gruppi[chiave]
        primo = g['processi'][0]
        pid = u', '.join([unicode(x.pid) for x in g['processi'][:10]]) + (u'...' if len(g['processi']) > 10 else u'')
        mostrato = primo.mostrato() if g['per_riga'] else primo.immagine
        cosa = g['cosa']
        dettagli = _dettagli(primo, padre_di(primo), etichetta, fonti)
        if g['chiaro']:
            dettagli += tr(u'\nComando in chiaro: ') + u' '.join(g['chiaro'].split())[:1200]
        t.segnala(4, g['peso'], g['famiglia'], u'%s: %s (PID %s)' % (cosa[:1].upper() + cosa[1:], mostrato[:160], pid),
                  dettagli, primo.creato, elemento)
    # processi nascosti: nella scansione della memoria ma non nell'elenco dei processi attivi
    if scansione_ok:
        avvio = min([p.creato for p in per_pid.get(4, []) if p.creato] or [0])
        for p in elenco:
            if p.in_lista or p.uscito or p.thread <= 0:
                continue
            if avvio and p.creato and p.creato < avvio - 60:
                continue        # di un avvio precedente di Windows, rimasto nella memoria
            t.segnala(4, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                      tr(u'Processo nella memoria ma non nell\'elenco dei processi attivi, forse nascosto: %s (PID %d)')
                      % (p.mostrato()[:160], p.pid), _dettagli(p, padre_di(p), etichetta, fonti), p.creato,
                      m.elemento(u'psscan'), True)
            annota(p, R.DA_CONFERMARE, R.F_ANTIFORENSE)
    # processi di sistema con il padre sbagliato, o in piu' copie
    vivi = [p for p in elenco if p.in_lista and not p.uscito]
    for p in vivi:
        attesi = _PADRI_ATTESI.get(p.base)
        if not attesi:
            continue
        padre = padre_di(p)
        if padre is None or padre.base in attesi:
            continue
        t.segnala(4, R.DA_CONFERMARE, R.F_ESECUZIONE,
                  tr(u'%s con un processo padre insolito: %s (PID %d) invece di %s')
                  % (p.base, padre.base, padre.pid, u', '.join(attesi)), _dettagli(p, padre, etichetta, fonti),
                  p.creato, elemento, True)
        annota(p, R.DA_CONFERMARE, R.F_ESECUZIONE)
    for nome in _UNICI:
        copie = [p for p in vivi if p.base == nome]
        if len(copie) > 1:
            t.segnala(4, R.DA_CONFERMARE, R.F_ESECUZIONE,
                      tr(u'%d processi %s attivi nello stesso momento: di norma ce n\'\u00e8 uno solo (PID %s)')
                      % (len(copie), nome, u', '.join([unicode(p.pid) for p in copie[:10]])),
                      u'\n\n'.join([_dettagli(p, padre_di(p), etichetta, fonti) for p in copie[:5]]),
                      copie[-1].creato, elemento, True)
            for p in copie:
                annota(p, R.DA_CONFERMARE, R.F_ESECUZIONE)
    # interpreti avviati da un programma per documenti o da un server web
    for p in elenco:
        if p.base not in _INTERPRETI:
            continue
        padre = padre_di(p)
        if padre is None or padre.base not in _PADRI_DOCUMENTI:
            continue
        t.segnala(4, R.DA_CONFERMARE, R.F_ESECUZIONE,
                  tr(u'%s avviato da %s (PID %d): un programma per documenti o un server web di norma non apre '
                     u'interpreti di comandi') % (p.base, padre.base, padre.pid),
                  _dettagli(p, padre, etichetta, fonti), p.creato, elemento, True)
        annota(p, R.DA_CONFERMARE, R.F_ESECUZIONE)
    # la tabella: tutti i processi, in ordine di avvio
    righe = []
    for p in elenco[:400]:
        note = []
        if not p.in_lista:
            note.append(tr(u'solo psscan'))
        if p.peso:
            note.append(R.NOME_PESO[p.peso])
        padre = padre_di(p)
        righe.append([unicode(p.pid), u'%d %s' % (p.ppid, padre.breve() if padre is not None else u''),
                      p.nome, p.mostrato()[:300], p.utente, u'' if p.sessione is None else unicode(p.sessione),
                      T(p.creato), T(p.uscito), u', '.join(note)])
    nota = tr(u'Tutti i processi trovati da Volatility (%s), in ordine di avvio. \u00abSolo psscan\u00bb: trovato '
              u'dalla scansione della memoria ma non nell\'elenco dei processi attivi (terminato, oppure nascosto se '
              u'non ha l\'ora di fine).') % fonti
    if len(elenco) > 400:
        nota += tr(u' Sono mostrati i primi 400 di %d.') % len(elenco)
    t.tabella(4, tr(u'Processi nella RAM (%s)') % etichetta,
              [u'PID', tr(u'Padre'), tr(u'Nome'), tr(u'Riga di comando o programma'), tr(u'Utente'), tr(u'Sessione'),
               tr(u'Avviato (UTC)'), tr(u'Terminato (UTC)'), tr(u'Nota')], righe, nota)
    if not lista_ok:
        t.nota(tr(u'RAM %s: senza l\'elenco dei processi attivi (pslist e pstree) non si possono cercare i processi '
                  u'nascosti.') % etichetta)
    return elenco


def _rete(t, m, processi):
    """Controlli 5 e 7: le connessioni di rete con il processo proprietario."""
    righe_rete = m.righe(u'network')
    if righe_rete is None:
        motivo = tr(u'la RAM c\'\u00e8, ma Volatility non ha prodotto le connessioni (%s)') % m.plugin(u'network')
        t.esito(5, 'non verificabile', motivo)
        t.esito(7, 'non verificabile', motivo)
        return
    t.fatto(5)
    t.esito(7, 'fatto', tr(u'solo le connessioni sulla porta 445: le sessioni SMB richiedono il triage dal vivo'))
    etichetta = m.etichetta()
    elemento = m.elemento(u'network')
    fonte = m.plugin(u'network')
    righe = []
    smb = []
    visti = set()
    for r in righe_rete:
        proto = _testo(r.get(u'Proto'))
        locale, porta_l = _testo(r.get(u'LocalAddr')), _intero(r.get(u'LocalPort'), 0)
        remoto, porta_r = _testo(r.get(u'ForeignAddr')), _intero(r.get(u'ForeignPort'), 0)
        stato = _testo(r.get(u'State'))
        pid = _intero(r.get(u'PID'), -1)
        creata = ora_da_iso(r.get(u'Created'))
        p = _vivo_al(processi, pid, creata) if pid >= 0 else None
        nome = p.base if p is not None else _testo(r.get(u'Owner')).lower()
        mostrato_p = u'%s (%d)' % (p.breve() if p is not None else (_testo(r.get(u'Owner')) or u'?'), pid) if pid >= 0 \
            else (_testo(r.get(u'Owner')) or u'?')
        tcp = proto.upper().startswith(u'TCP')
        pubblico = tcp and stato.upper() in _STATI_ATTIVI and R.ip_pubblico(remoto)
        nota = []
        if pubblico:
            nota.append(tr(u'indirizzo pubblico'))
            chiave = (pid, remoto, porta_r)
            peso = 0
            if chiave not in visti:
                visti.add(chiave)
                verso = _indirizzo(remoto, porta_r)
                if p is not None and p.peso >= R.DA_CONFERMARE:
                    peso = R.DA_CONFERMARE
                    t.segnala(5, peso, p.famiglia,
                              tr(u'Connessione verso %s da un processo gi\u00e0 segnalato: %s (PID %d, %s)')
                              % (verso, p.mostrato()[:120], pid, stato),
                              tr(u'Locale %s - remoto %s - stato %s - creata %s (UTC)\nFonte: RAM %s, %s')
                              % (_indirizzo(locale, porta_l), verso, stato, T(creata) or u'-', etichetta, fonte),
                              creata, elemento)
                elif nome in _SENZA_INTERNET:
                    peso = R.DA_CONFERMARE
                    t.segnala(5, peso, R.F_ESECUZIONE,
                              tr(u'%s ha una connessione verso l\'indirizzo pubblico %s (PID %d, %s): di norma non si '
                                 u'collega a Internet') % (nome, verso, pid, stato),
                              tr(u'Locale %s - remoto %s - stato %s - creata %s (UTC)\nFonte: RAM %s, %s')
                              % (_indirizzo(locale, porta_l), verso, stato, T(creata) or u'-', etichetta, fonte)
                              + (u'\n' + (tr(u'Riga di comando: %s') % p.riga[:1500]) if p is not None and p.riga else u''),
                              creata, elemento, True)
            if peso:
                nota.append(R.NOME_PESO[peso])
        riga = [proto, _indirizzo(locale, porta_l), _indirizzo(remoto, porta_r) if remoto not in (u'*', u'') else remoto,
                stato, mostrato_p, T(creata), u', '.join(nota)]
        righe.append((0 if pubblico else (1 if stato.upper() != u'LISTENING' and tcp else 2), creata, riga))
        if tcp and (porta_l == 445 or porta_r == 445) and stato.upper() != u'LISTENING' and remoto not in (u'0.0.0.0', u'::'):
            direzione = tr(u'in entrata') if porta_l == 445 else tr(u'in uscita')
            smb.append((creata, [direzione, _indirizzo(locale, porta_l), _indirizzo(remoto, porta_r), stato,
                                 mostrato_p, T(creata)]))
    righe.sort(key=lambda x: (x[0], -x[1]))
    nota = tr(u'Le connessioni trovate da %s: prima quelle verso indirizzi pubblici, poi le altre, poi le porte in '
              u'ascolto.') % fonte
    if len(righe) > 300:
        nota += tr(u' Sono mostrate le prime 300 di %d.') % len(righe)
    t.tabella(5, tr(u'Connessioni di rete nella RAM (%s)') % etichetta,
              [tr(u'Protocollo'), tr(u'Locale'), tr(u'Remoto'), tr(u'Stato'), tr(u'Processo (PID)'), tr(u'Creata (UTC)'),
               tr(u'Nota')], [x[2] for x in righe[:300]], nota)
    smb.sort(key=lambda x: x[0])
    t.tabella(7, tr(u'Connessioni SMB (porta 445) nella RAM (%s)') % etichetta,
              [tr(u'Direzione'), tr(u'Locale'), tr(u'Remoto'), tr(u'Stato'), tr(u'Processo (PID)'), tr(u'Creata (UTC)')],
              [x[1] for x in smb[:200]],
              tr(u'Dalla RAM si vedono le connessioni sulla porta 445, non le sessioni SMB con l\'utente e le '
                 u'condivisioni aperte: per quelle serve il triage dal vivo.'))


def _sessioni(t, m):
    """Controllo 3: chi era collegato al momento dell'acquisizione."""
    righe_s = m.righe(u'sessions')
    if righe_s is None:
        t.esito(3, 'non verificabile', tr(u'la RAM c\'\u00e8, ma Volatility non ha prodotto le sessioni (%s)')
                % m.plugin(u'sessions'))
        return
    t.fatto(3)
    etichetta = m.etichetta()
    sessioni = {}
    for r in righe_s:
        numero = _intero(r.get(u'Session ID'))
        if numero is None:
            continue
        s = sessioni.setdefault(numero, {'tipi': [], 'utenti': [], 'processi': 0, 'primo': 0})
        tipo = _testo(r.get(u'Session Type'))
        if tipo and tipo not in s['tipi']:
            s['tipi'].append(tipo)
        utente = _testo(r.get(u'User Name'))
        if utente and not _RX_UTENTE_DI_SISTEMA.search(utente) and utente not in s['utenti']:
            s['utenti'].append(utente)
        s['processi'] += 1
        ora = ora_da_iso(r.get(u'Create Time'))
        if ora and (not s['primo'] or ora < s['primo']):
            s['primo'] = ora
    righe = []
    for numero in sorted(sessioni):
        s = sessioni[numero]
        remota = [x for x in s['tipi'] if x.upper().startswith(u'RDP-')]
        if remota and s['utenti']:
            t.segnala(3, R.INFORMATIVO, R.F_ACCESSI,
                      tr(u'Sessione di Desktop remoto aperta al momento dell\'acquisizione: %s (sessione %d, %s)')
                      % (u', '.join(s['utenti']), numero, u', '.join(remota)),
                      tr(u'Processi nella sessione: %d; il primo avviato il %s (UTC).\nFonte: RAM %s, %s')
                      % (s['processi'], T(s['primo']) or u'-', etichetta, m.plugin(u'sessions')),
                      s['primo'], m.elemento(u'sessions'))
        righe.append([unicode(numero), u', '.join(s['tipi']), u', '.join(s['utenti']), unicode(s['processi']), T(s['primo'])])
    t.tabella(3, tr(u'Sessioni nella RAM (%s)') % etichetta,
              [tr(u'Sessione'), tr(u'Tipo'), tr(u'Utenti'), tr(u'Processi'), tr(u'Primo processo (UTC)')], righe,
              tr(u'Il tipo viene dalla variabile SESSIONNAME dei processi: Console per chi sta davanti al computer, '
                 u'RDP-Tcp#N per il Desktop remoto. Senza utente: sessione dei servizi.'))


def _servizi(t, m):
    """Controlli 17 e 29: i servizi che la RAM conosce e il registro no (un
    servizio tolto dopo l'uso, come fanno smbexec e simili). Se il registro
    non c'e' (origine con la sola RAM) si giudicano tutti."""
    righe_s = m.righe(u'svcscan')
    if righe_s is None:
        return
    registro = t.contesto.get('servizi_registro')
    etichetta = m.etichetta()
    elemento = m.elemento(u'svcscan')
    righe = []
    for r in righe_s:
        nome = _testo(r.get(u'Name'))
        if not nome or (registro is not None and nome.lower() in registro):
            continue
        percorso = _testo(r.get(u'Binary')) or _testo(r.get(u'Binary (Registry)'))
        mostrato = _testo(r.get(u'Display'))
        stato = _testo(r.get(u'State'))
        avvio = _testo(r.get(u'Start'))
        pid = _intero(r.get(u'PID'))
        if percorso:
            peso, controllo, famiglia, motivi = tc_c_registro.giudica_servizio(nome, percorso)
            if peso and peso < R.DECISIVO and R.driver_forense(nome, percorso):
                peso = R.INFORMATIVO
                motivi.append(tr(u'driver di uno strumento di acquisizione forense: probabilmente lasciato da chi ha '
                                 u'raccolto le prove'))
        else:
            firma = R.firma_smbexec(nome, u'')
            peso, controllo, famiglia, motivi = (firma[0], 29, R.F_LATERALE, [firma[1]]) if firma else (0, 17, R.F_PERSISTENZA, [])
        strumento = R.trova_rmm(nome + u' ' + mostrato + u' ' + percorso)
        if strumento:
            t.prova_rmm(strumento, tr(u'servizio nella RAM'), u'%s: %s' % (nome, percorso[:300]), 0, elemento, 32)
        if registro is not None:
            motivi = [tr(u'nella RAM ma non nel registro')] + motivi
        if peso:
            motivo = u'; '.join(motivi)
            t.segnala(controllo, peso, famiglia, tr(u'Servizio \u00ab%s\u00bb: %s') % (nome, motivo),
                      tr(u'%s\nStato: %s - avvio: %s - PID: %s\nFonte: RAM %s, %s')
                      % (percorso[:1500] or tr(u'(programma non leggibile nella RAM)'), stato, avvio,
                         u'-' if pid is None else unicode(pid), etichetta, m.plugin(u'svcscan')),
                      0, elemento)
        if peso or registro is not None:
            righe.append([nome, stato, avvio, u'-' if pid is None else unicode(pid), percorso[:300],
                          R.NOME_PESO.get(peso, u''), u'; '.join(motivi)])
    if registro is None:
        _fatto_se_manca(t, 17, tr(u'solo i servizi trovati nella RAM'))
        _fatto_se_manca(t, 29, tr(u'solo i servizi trovati nella RAM'))
        titolo = tr(u'Servizi segnalati nella RAM (%s)') % etichetta
    else:
        titolo = tr(u'Servizi nella RAM che non sono nel registro (%s)') % etichetta
    t.tabella(17, titolo, [tr(u'Servizio'), tr(u'Stato'), tr(u'Avvio'), u'PID', tr(u'Programma'), tr(u'Peso'), tr(u'Motivo')],
              righe[:200])


def descrizione(info):
    """Una RAM analizzata, in poche righe (per il contesto del report)."""
    righe = []
    prima = info.get('immagine') or u''
    if info.get('dimensione'):
        prima += u' (%s)' % _dimensione(info['dimensione'])
    if info.get('sha256'):
        prima += u', SHA-256 %s' % info['sha256']
    righe.append(prima)
    if info.get('computer'):
        righe.append(tr(u'computer: %s') % info['computer'])
    if info.get('ora'):
        righe.append(tr(u'ora di sistema nella RAM: %s UTC') % T(info['ora']))
    if info.get('build'):
        righe.append(tr(u'Windows build %s') % info['build'])
    righe.append(tr(u'Volatility %s: %d plugin su %d con risultati') % (info.get('volatility') or u'?',
                                                                       info.get('riusciti', 0), info.get('totale', 0)))
    cartella = tr(u'cartella: %s') % info.get('cartella', u'')
    if info.get('origine'):
        cartella += tr(u' (origine dati \u00ab%s\u00bb)') % info['origine']
    righe.append(cartella)
    return u'\n'.join(righe)
