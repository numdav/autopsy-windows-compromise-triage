# -*- coding: utf-8 -*-
"""
tc_eventi - Lettura dei registri eventi per il plugin "Triage
compromissione".

Ogni file .evtx viene letto una volta sola: gli eventi utili sono smistati
in base a chi li ha scritti (provider) e al loro numero, e riassunti in una
"Raccolta" che i controlli interrogano dopo.
"""

import re

import tc_evtx
import tc_artefatti
import tc_regole as R
from tc_base import ERRORI

# Eventi letti per ciascun registro (gli altri vengono saltati in fretta)
ID_SICUREZZA = set([1102, 4624, 4625, 4648, 4688, 4697, 4698, 4699, 4702, 4720, 4722, 4724, 4726,
                    4728, 4732, 4756, 5145])
ID_SISTEMA = set([104, 7045, 7009])
ID_APPLICAZIONI = set([102, 104, 105, 202, 205, 24001, 1033, 11707])
ID_PER_FILE = {
    u'security.evtx': ID_SICUREZZA,
    u'system.evtx': ID_SISTEMA,
    u'application.evtx': ID_APPLICAZIONI,
    u'microsoft-windows-taskscheduler%4operational.evtx': set([106, 141, 200]),
    u'microsoft-windows-terminalservices-localsessionmanager%4operational.evtx': set([21, 22, 25]),
    u'microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx': set([1149]),
    u'microsoft-windows-windows defender%4operational.evtx': set([1116, 1117, 5001, 5007, 5010, 5012]),
    u'microsoft-windows-powershell%4operational.evtx': set([4104]),
    u'windows powershell.evtx': set([400]),
    u'microsoft-windows-wmi-activity%4operational.evtx': set([5861]),
    u'microsoft-windows-sysmon%4operational.evtx': set([1]),
    u'microsoft-windows-terminalservices-rdpclient%4operational.evtx': set([1024, 1102]),
    u'pulseway-commandaudit.evtx': None,
}
TUTTI_GLI_ID = set()
for _insieme in ID_PER_FILE.values():
    if _insieme:
        TUTTI_GLI_ID |= _insieme

# Nome leggibile dei registri principali (per la tabella della copertura)
REGISTRI_PRINCIPALI = [
    (u'security.evtx', u'Security'),
    (u'system.evtx', u'System'),
    (u'application.evtx', u'Application'),
    (u'microsoft-windows-taskscheduler%4operational.evtx', u'TaskScheduler/Operational'),
    (u'microsoft-windows-terminalservices-localsessionmanager%4operational.evtx', u'TerminalServices-LocalSessionManager'),
    (u'microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx', u'TerminalServices-RemoteConnectionManager'),
    (u'microsoft-windows-windows defender%4operational.evtx', u'Windows Defender/Operational'),
    (u'microsoft-windows-powershell%4operational.evtx', u'PowerShell/Operational'),
    (u'windows powershell.evtx', u'Windows PowerShell'),
    (u'microsoft-windows-sysmon%4operational.evtx', u'Sysmon/Operational'),
]

_UTENTI_DI_SISTEMA = set([u'system', u'local service', u'network service', u'anonymous logon', u'-', u''])
_RX_TMP8 = re.compile(u'(^|\\\\)temp\\\\[A-Za-z]{8}\\.tmp$', re.I)
_RX_EXE8 = re.compile(u'^[A-Za-z]{8}\\.exe$')
_RX_HOSTAPP = re.compile(u'HostApplication=(.*)')


def _in_utf16(testo):
    return testo.encode('utf-16-le')


# Gli eventi 5145 che interessano contengono una di queste stringhe (in
# minuscolo, UTF-16): gli altri vengono solo contati.
_SEGNI_5145 = [_in_utf16(x) for x in (u'svcctl', u'atsvc', u'psexesvc', u'remcom', u'paexec', u'admin$', u'\\c$')]

def _intero(valore, predefinito=-1):
    try:
        return int(valore)
    except ERRORI:
        try:
            return int(valore, 16)
        except ERRORI:
            return predefinito


def _somma(tabella, chiave, ora, massimo=200000):
    """Aggiorna un riassunto [conteggio, primo, ultimo] per una chiave."""
    r = tabella.get(chiave)
    if r is None:
        if len(tabella) >= massimo:
            return None
        r = [0, ora, ora]
        tabella[chiave] = r
    r[0] += 1
    if ora and (not r[1] or ora < r[1]):
        r[1] = ora
    if ora > r[2]:
        r[2] = ora
    return r


def _utente(dominio, nome):
    nome = (nome or u'').strip()
    dominio = (dominio or u'').strip()
    if dominio and dominio != u'-' and nome:
        return dominio + u'\\' + nome
    return nome or u'-'


class Raccolta(object):
    """I fatti raccolti dai registri eventi."""

    def __init__(self):
        # nome registro (minuscolo) -> [primo, ultimo, record dichiarati, elemento, record non decodificati,
        #   orario dell'ultimo record scritto, record persi, orari impossibili, blocchi danneggiati, record percorsi]
        self.copertura = {}
        self.conteggi = {}           # numero evento del Security -> quanti
        self.cancellazioni = []      # log cancellati
        self.logon = {}              # (utente, origine, host, tipo) -> [n, primo, ultimo]
        self.logon_per_tipo = {}
        self.falliti = {}            # origine -> [n, primo, ultimo, utenti, intervallo, n_intervallo, massimo, tipi, inizio raffica]
        self.riusciti = {}           # origine -> [(ora, utente in minuscolo, utente)] degli accessi riusciti (al massimo 200)
        self.espliciti = {}          # (soggetto, bersaglio, server, processo) -> [n, primo, ultimo]
        self.processi_totali = 0
        self.processi_con_riga = 0
        self.processi = {}           # (processo, riga, motivo) -> record
        self.ricognizione = []       # (ora, nome, utente, riga)
        self.servizi = []
        self.timeout = []            # (ora, nome servizio)
        self.attivita_create = []    # eventi 4698
        self.attivita_cancellate = []  # eventi 4699
        self.attivita_aggiornate = []  # eventi 4702
        self.attivita_registrate = []  # eventi 106
        self.attivita_rimosse = []   # eventi 141
        self.attivita_azioni = {}    # nome attivita' -> azioni viste (evento 200)
        self.account = []
        self.condivisioni = {}       # (classe, indirizzo, utente, share, esempio) -> [n, primo, ultimo]
        self.rdp = {}                # (utente, indirizzo) -> [n, primo, ultimo]
        self.rdp_autenticati = {}    # (utente, indirizzo) -> [n, primo, ultimo]
        self.rdp_uscita = {}         # server -> [n, primo, ultimo]
        self.defender = {}           # identificativo -> record
        self.defender_modifiche = []
        self.powershell = {}         # chiave -> record
        self._avvii_innocui = set()  # avvii di PowerShell (400) gia' giudicati senza trovare nulla
        self._righe_giudicate = {}   # riga di un blocco di script breve -> giudizio
        self.powershell_avvisi = 0
        self.wmi = []
        self.rmm = []
        self.installazioni = []
        self.computer = set()        # nomi con cui la macchina compare nei propri eventi
        self._giudizi = {}           # (processo, riga di comando) -> riscontri gia' calcolati
        self.non_letti = []          # (elemento, blocchi non letti) per i registri con errori di lettura
        self.non_validi = []         # file .evtx che non hanno l'intestazione di un registro eventi
        self.gestori = {
            (u'microsoft-windows-eventlog', 1102): self._cancellato,
            (u'microsoft-windows-eventlog', 104): self._cancellato,
            (u'microsoft-windows-security-auditing', 4624): self._4624,
            (u'microsoft-windows-security-auditing', 4625): self._4625,
            (u'microsoft-windows-security-auditing', 4648): self._4648,
            (u'microsoft-windows-security-auditing', 4688): self._4688,
            (u'microsoft-windows-security-auditing', 4697): self._4697,
            (u'microsoft-windows-security-auditing', 4698): self._attivita,
            (u'microsoft-windows-security-auditing', 4699): self._attivita,
            (u'microsoft-windows-security-auditing', 4702): self._attivita,
            (u'microsoft-windows-security-auditing', 5145): self._5145,
            (u'service control manager', 7045): self._7045,
            (u'service control manager', 7009): self._7009,
            (u'microsoft-windows-taskscheduler', 106): self._106,
            (u'microsoft-windows-taskscheduler', 141): self._141,
            (u'microsoft-windows-taskscheduler', 200): self._200,
            (u'microsoft-windows-terminalservices-localsessionmanager', 21): self._rdp,
            (u'microsoft-windows-terminalservices-localsessionmanager', 22): self._rdp,
            (u'microsoft-windows-terminalservices-localsessionmanager', 25): self._rdp,
            (u'microsoft-windows-terminalservices-remoteconnectionmanager', 1149): self._1149,
            (u'microsoft-windows-terminalservices-clientactivexcore', 1024): self._rdp_uscita,
            (u'microsoft-windows-terminalservices-clientactivexcore', 1102): self._rdp_uscita,
            (u'microsoft-windows-windows defender', 1116): self._defender,
            (u'microsoft-windows-windows defender', 1117): self._defender,
            (u'microsoft-windows-windows defender', 5001): self._defender_modifica,
            (u'microsoft-windows-windows defender', 5007): self._defender_modifica,
            (u'microsoft-windows-windows defender', 5010): self._defender_modifica,
            (u'microsoft-windows-windows defender', 5012): self._defender_modifica,
            (u'microsoft-windows-powershell', 4104): self._4104,
            (u'powershell', 400): self._400,
            (u'microsoft-windows-wmi-activity', 5861): self._5861,
            (u'microsoft-windows-sysmon', 1): self._sysmon1,
            (u'msiinstaller', 1033): self._msi,
            (u'msiinstaller', 11707): self._msi,
        }
        for ident in (4720, 4722, 4724, 4726, 4728, 4732, 4756):
            self.gestori[(u'microsoft-windows-security-auditing', ident)] = self._account
        for ident in (102, 104, 105, 202, 205):
            self.gestori[(u'logmein', ident)] = self._logmein

    # ---- lettura di un file ---------------------------------------------

    def leggi_file(self, elemento, annullato=None, tutti=False):
        """Legge un registro. Restituisce il numero di eventi utili."""
        nome = elemento.nome.lower()
        voluti = ID_PER_FILE.get(nome, TUTTI_GLI_ID)
        if nome.startswith(u'archive-'):
            for chiave, insieme in ID_PER_FILE.items():
                if nome.startswith(u'archive-' + chiave[:-5]):
                    voluti = insieme
        if tutti:
            voluti = TUTTI_GLI_ID
        try:
            log = tc_evtx.FileEvtx(elemento)
        except tc_evtx.ErroreEvtx:
            self.non_validi.append(elemento)    # c'e', ma non e' un registro eventi
            return 0
        self._elemento = elemento
        pulseway = nome == u'pulseway-commandaudit.evtx'
        utili = 0
        gestori = self.gestori
        try:
            for ev in log.eventi(id_voluti=voluti, annullato=annullato, filtro=self._filtro):
                provider = ev['Provider'].lower()
                g = gestori.get((provider, ev['EventID']))
                try:
                    if g is not None:
                        g(ev)
                        utili += 1
                    elif pulseway or ev['EventID'] == 24001:
                        self._pulseway(ev, pulseway)
                        utili += 1
                except ERRORI:
                    log.errori += 1
        finally:
            # la copertura va annotata anche se la lettura si interrompe a meta'
            vecchio = self.copertura.get(nome)
            if vecchio is None:
                self.copertura[nome] = [log.primo, log.ultimo, log.record, elemento, log.errori, log.ultimo_scritto,
                                        log.persi, log.fuori_scala, log.blocchi_danneggiati, log.visti]
            else:
                if log.primo and (not vecchio[0] or log.primo < vecchio[0]):
                    vecchio[0] = log.primo
                if log.ultimo and (not vecchio[1] or log.ultimo > vecchio[1]):
                    vecchio[1] = log.ultimo
                vecchio[2] += log.record
                vecchio[4] += log.errori
                if log.ultimo_scritto and (not vecchio[5] or log.ultimo_scritto > vecchio[5]):
                    vecchio[5] = log.ultimo_scritto
                vecchio[6] += log.persi
                vecchio[7] += log.fuori_scala
                vecchio[8] += log.blocchi_danneggiati
                vecchio[9] += log.visti
            if log.blocchi_non_letti:
                self.non_letti.append((elemento, log.blocchi_non_letti))
        return utili

    def _conta(self, ident):
        self.conteggi[ident] = self.conteggi.get(ident, 0) + 1

    def _filtro(self, ident, dati, posizione, dimensione):
        """Scarta prima della decodifica gli eventi 5145 che non riguardano
        l'esecuzione remota. Dove l'audit dettagliato delle condivisioni e'
        attivo (controller di dominio, file server) sono milioni: decodificarli
        tutti richiederebbe molti minuti."""
        if ident != 5145:
            return True
        basso = dati[posizione:posizione + dimensione].lower()
        for segno in _SEGNI_5145:
            if segno in basso:
                return True
        self._conta(5145)
        return False

    # ---- log cancellati ---------------------------------------------------

    def _cancellato(self, ev):
        d = ev['Dati']
        canale = d.get(u'Channel') or (u'Security' if ev['EventID'] == 1102 else ev['Canale'])
        self.cancellazioni.append({'ora': ev['Ora'], 'id': ev['EventID'], 'registro': canale,
                                   'utente': _utente(d.get(u'SubjectDomainName'), d.get(u'SubjectUserName')),
                                   'elemento': self._elemento})

    # ---- accessi ----------------------------------------------------------

    def _4624(self, ev):
        d = ev['Dati']
        self._conta(4624)
        tipo = _intero(d.get(u'LogonType'))
        self.logon_per_tipo[tipo] = self.logon_per_tipo.get(tipo, 0) + 1
        if tipo not in (3, 7, 10):
            return
        nome = d.get(u'TargetUserName') or u''
        basso = nome.lower()
        if basso in _UTENTI_DI_SISTEMA or nome.endswith(u'$') or basso.startswith((u'dwm-', u'umfd-')):
            return
        ip = (d.get(u'IpAddress') or u'-').strip()
        if tipo == 7 and not R.indirizzo_valido(ip):
            return
        host = (d.get(u'WorkstationName') or u'-').strip()
        chiave = (_utente(d.get(u'TargetDomainName'), nome), ip, host, tipo)
        _somma(self.logon, chiave, ev['Ora'])
        # serve a dire se un accesso riuscito viene DOPO una raffica di falliti
        origine = ip if R.indirizzo_valido(ip) else (host or u'-')
        elenco = self.riusciti.get(origine)
        if elenco is None:
            if len(self.riusciti) >= 50000:
                return
            elenco = []
            self.riusciti[origine] = elenco
        if len(elenco) < 200:
            elenco.append((ev['Ora'], basso, nome))

    def _4625(self, ev):
        d = ev['Dati']
        self._conta(4625)
        if len(self.computer) < 20:
            self.computer.add(ev['Computer'].split(u'.')[0].lower())
        ip = (d.get(u'IpAddress') or u'').strip()
        host = (d.get(u'WorkstationName') or u'').strip()
        origine = ip if R.indirizzo_valido(ip) else (host or u'-')
        ora = ev['Ora']
        r = self.falliti.get(origine)
        if r is None:
            if len(self.falliti) >= 50000:
                return
            r = [0, ora, ora, set(), -1, 0, 0, set(), 0]
            self.falliti[origine] = r
        r[0] += 1
        if ora and ora < r[1]:
            r[1] = ora
        if ora > r[2]:
            r[2] = ora
        if len(r[3]) < 30:
            r[3].add(d.get(u'TargetUserName') or u'-')
        intervallo = int(ora // 600)
        if intervallo == r[4]:
            r[5] += 1
        else:
            r[4] = intervallo
            r[5] = 1
        if r[5] > r[6]:
            r[6] = r[5]
        if r[5] == 10 and (not r[8] or ora < r[8]):
            r[8] = ora          # la prima volta che si contano 10 falliti in 10 minuti: qui c'e' una raffica
        r[7].add(_intero(d.get(u'LogonType')))

    def _4648(self, ev):
        d = ev['Dati']
        self._conta(4648)
        soggetto = d.get(u'SubjectUserName') or u''
        server = (d.get(u'TargetServerName') or u'').strip()
        if server.lower() in (u'localhost', u'', u'-') and soggetto.endswith(u'$'):
            return
        chiave = (_utente(d.get(u'SubjectDomainName'), soggetto),
                  _utente(d.get(u'TargetDomainName'), d.get(u'TargetUserName')), server,
                  R.nome_base(d.get(u'ProcessName') or u''), (d.get(u'IpAddress') or u'-').strip())
        _somma(self.espliciti, chiave, ev['Ora'], 50000)

    # ---- processi ---------------------------------------------------------

    def _4688(self, ev):
        d = ev['Dati']
        self._conta(4688)
        utente = d.get(u'TargetUserName')
        if not utente or utente == u'-':
            utente = d.get(u'SubjectUserName') or u'-'
        self._processo(ev['Ora'], d.get(u'NewProcessName') or u'', d.get(u'CommandLine') or u'',
                       d.get(u'ParentProcessName') or u'', utente, u'4688')

    def _sysmon1(self, ev):
        d = ev['Dati']
        self._processo(ev['Ora'], d.get(u'Image') or u'', d.get(u'CommandLine') or u'',
                       d.get(u'ParentImage') or u'', d.get(u'User') or u'-', u'Sysmon 1')

    def _processo(self, ora, immagine, riga, padre, utente, fonte):
        self.processi_totali += 1
        if riga:
            self.processi_con_riga += 1
        nome = R.nome_base(immagine)
        if nome in R.RICOGNIZIONE and len(self.ricognizione) < 20000:
            self.ricognizione.append((ora, nome, utente, riga))
        testo = riga or immagine
        # Sui server lo stesso comando si ripete migliaia di volte: il
        # giudizio su una coppia (processo, riga di comando) si calcola una
        # volta sola.
        trovati = self._giudizi.get((immagine, riga))
        if trovati is None:
            trovati = self._giudica_processo(immagine, nome, riga)
            if len(self._giudizi) < 50000:
                self._giudizi[(immagine, riga)] = trovati
        for peso, famiglia, cosa, per_riga, chiaro in trovati:
            chiave = (immagine.lower(), testo[:300] if per_riga else u'', cosa)
            r = self.processi.get(chiave)
            if r is None:
                if len(self.processi) >= 5000:
                    continue
                r = {'n': 0, 'primo': ora, 'ultimo': ora, 'processo': immagine, 'riga': testo, 'righe': [],
                     'padre': padre, 'utente': utente, 'motivo': cosa, 'peso': peso, 'chiaro': chiaro,
                     'famiglia': famiglia, 'fonte': fonte, 'elemento': self._elemento}
                self.processi[chiave] = r
            r['n'] += 1
            if len(r['righe']) < 6 and testo not in r['righe']:
                r['righe'].append(testo)
            if ora and ora < r['primo']:
                r['primo'] = ora
            if ora > r['ultimo']:
                r['ultimo'] = ora

    def _giudica_processo(self, immagine, nome, riga):
        """I riscontri su un processo: lista di (peso, famiglia, descrizione,
        uno per riga di comando?, comando in chiaro se era codificato)."""
        trovati = []
        peso, cosa = R.strumento(nome)
        if peso >= R.DA_CONFERMARE:
            trovati.append((peso, R.famiglia_strumento(nome), cosa, False, u''))
        # dove sta davvero il programma (dal percorso dell'immagine, non dalla riga di comando)
        g = R.valuta_comando(immagine, u'', persistenza=False)
        if g.livello >= 2 and not R.strumento_forense(nome):
            trovati.append((R.DA_CONFERMARE, R.F_ESECUZIONE, g.motivo(), False, u''))
        if riga:
            noti = R.comandi_noti(riga)
            for peso_c, famiglia_c, cosa_c in noti:
                trovati.append((peso_c, famiglia_c, cosa_c, True, u''))
            # Un comando soltanto eseguito non pesa come lo stesso comando in
            # una voce che parte da sola: gli strumenti di gestione eseguono
            # ogni giorno comandi codificati o che scaricano script. E'
            # decisivo solo se il motivo e' di quelli senza spiegazioni
            # innocenti (g.certo, vedi tc_regole.valuta_comando).
            g = R.valuta_comando(riga, persistenza=False)
            gia_decisivo = [1 for peso_c, _, _ in noti if peso_c >= R.DECISIVO]
            if (g.livello >= 3 or g.avvio) and (g.certo or not noti) and not gia_decisivo:
                trovati.append((R.DECISIVO if g.certo else R.DA_CONFERMARE, R.F_ESECUZIONE, g.motivo(), True,
                                g.decodificato))
        return trovati

    # ---- servizi ----------------------------------------------------------

    def _7045(self, ev):
        d = ev['Dati']
        if len(self.servizi) < 20000:
            self.servizi.append({'ora': ev['Ora'], 'nome': d.get(u'ServiceName') or u'',
                                 'percorso': d.get(u'ImagePath') or u'', 'tipo': d.get(u'ServiceType') or u'',
                                 'avvio': d.get(u'StartType') or u'', 'account': d.get(u'AccountName') or u'',
                                 'utente': ev['SidUtente'], 'fonte': u'7045', 'elemento': self._elemento})

    def _4697(self, ev):
        d = ev['Dati']
        self._conta(4697)
        if len(self.servizi) < 20000:
            self.servizi.append({'ora': ev['Ora'], 'nome': d.get(u'ServiceName') or u'',
                                 'percorso': d.get(u'ServiceFileName') or u'', 'tipo': d.get(u'ServiceType') or u'',
                                 'avvio': d.get(u'ServiceStartType') or u'', 'account': d.get(u'ServiceAccount') or u'',
                                 'utente': _utente(d.get(u'SubjectDomainName'), d.get(u'SubjectUserName')),
                                 'fonte': u'4697', 'elemento': self._elemento})

    def _7009(self, ev):
        d = ev['Dati']
        nome = d.get(u'param2') or (ev['Lista'][1] if len(ev['Lista']) > 1 else u'')
        if len(self.timeout) < 20000:
            self.timeout.append((ev['Ora'], nome))

    # ---- attivita' pianificate ------------------------------------------

    def _attivita(self, ev):
        d = ev['Dati']
        ident = ev['EventID']
        self._conta(ident)
        contenuto = d.get(u'TaskContent') or d.get(u'TaskContentNew') or u''
        voce = {'ora': ev['Ora'], 'nome': d.get(u'TaskName') or u'',
                'utente': _utente(d.get(u'SubjectDomainName'), d.get(u'SubjectUserName')),
                'azioni': [], 'avvii': [], 'autore': u'', 'elemento': self._elemento}
        if contenuto:
            try:
                info = tc_artefatti.attivita_da_testo(contenuto)
            except ERRORI:
                info = None
            if info:
                voce['azioni'] = info['azioni'][:4]
                voce['avvii'] = info['avvii'][:4]
                voce['autore'] = info['autore']
        elenco = {4698: self.attivita_create, 4699: self.attivita_cancellate, 4702: self.attivita_aggiornate}[ident]
        if len(elenco) < 20000:
            elenco.append(voce)

    def _106(self, ev):
        d = ev['Dati']
        if len(self.attivita_registrate) < 20000:
            self.attivita_registrate.append({'ora': ev['Ora'], 'nome': d.get(u'TaskName') or u'',
                                             'utente': d.get(u'UserContext') or u'', 'elemento': self._elemento})

    def _141(self, ev):
        d = ev['Dati']
        if len(self.attivita_rimosse) < 20000:
            self.attivita_rimosse.append({'ora': ev['Ora'], 'nome': d.get(u'TaskName') or u'',
                                          'utente': d.get(u'UserName') or u'', 'elemento': self._elemento})

    def _200(self, ev):
        d = ev['Dati']
        nome = d.get(u'TaskName') or u''
        if nome.count(u'\\') != 1:
            return
        azioni = self.attivita_azioni.get(nome)
        if azioni is None:
            if len(self.attivita_azioni) >= 5000:
                return
            azioni = set()
            self.attivita_azioni[nome] = azioni
        if len(azioni) < 5:
            azioni.add(d.get(u'ActionName') or u'')

    # ---- account ----------------------------------------------------------

    def _account(self, ev):
        d = ev['Dati']
        self._conta(ev['EventID'])
        if len(self.account) < 5000:
            self.account.append({'ora': ev['Ora'], 'id': ev['EventID'],
                                 'soggetto': _utente(d.get(u'SubjectDomainName'), d.get(u'SubjectUserName')),
                                 'bersaglio': _utente(d.get(u'TargetDomainName'), d.get(u'TargetUserName')),
                                 'sid_bersaglio': d.get(u'TargetSid') or u'',
                                 'membro': d.get(u'MemberSid') or u'', 'nome_membro': d.get(u'MemberName') or u'',
                                 'computer': ev['Computer'].split(u'.')[0].lower(), 'elemento': self._elemento})

    # ---- condivisioni (5145) --------------------------------------------

    def _5145(self, ev):
        d = ev['Dati']
        self._conta(5145)
        share = (d.get(u'ShareName') or u'').lower()
        bersaglio = d.get(u'RelativeTargetName') or u''
        basso = bersaglio.lower()
        classe = None
        if share.endswith(u'ipc$'):
            if basso in (u'svcctl', u'atsvc'):
                classe = basso
            elif u'psexesvc' in basso or u'remcom' in basso or u'paexec' in basso:
                classe = u'psexec'
        elif share.endswith(u'admin$') or share.endswith(u'c$'):
            if u'__output' in basso or (share.endswith(u'admin$') and basso.startswith(u'__') and
                                         re.match(u'^__\\d{9,}\\.\\d+$', basso)):
                classe = u'output'
            elif share.endswith(u'admin$') and _RX_TMP8.search(bersaglio):
                classe = u'tmp' if R.nome_casuale(bersaglio.split(u'\\')[-1][:8]) else u'tmp8'
            elif u'psexesvc' in basso or u'paexec' in basso:
                classe = u'psexec'
            elif share.endswith(u'admin$') and _RX_EXE8.match(bersaglio) and R.nome_casuale(bersaglio[:8]):
                classe = u'exe8'
        if classe is None:
            return
        chiave = (classe, (d.get(u'IpAddress') or u'-').strip(),
                  _utente(d.get(u'SubjectDomainName'), d.get(u'SubjectUserName')), share, bersaglio)
        r = _somma(self.condivisioni, chiave, ev['Ora'], 20000)
        if r is not None and len(r) == 3:
            r.append(self._elemento)

    # ---- RDP --------------------------------------------------------------

    def _rdp(self, ev):
        d = ev['Dati']
        indirizzo = (d.get(u'Address') or u'').strip()
        if not R.indirizzo_valido(indirizzo):
            return
        r = _somma(self.rdp, (d.get(u'User') or u'-', indirizzo), ev['Ora'], 50000)
        if r is not None and len(r) == 3:
            r.append(self._elemento)

    def _1149(self, ev):
        d = ev['Dati']
        indirizzo = (d.get(u'Param3') or u'').strip()
        if not R.indirizzo_valido(indirizzo):
            return
        r = _somma(self.rdp_autenticati, (_utente(d.get(u'Param2'), d.get(u'Param1')), indirizzo), ev['Ora'], 50000)
        if r is not None and len(r) == 3:
            r.append(self._elemento)

    def _rdp_uscita(self, ev):
        d = ev['Dati']
        server = d.get(u'Value') or u''
        if ev['EventID'] == 1102 and (d.get(u'Name') or u'') != u'ServerAddress':
            return
        if server:
            _somma(self.rdp_uscita, server, ev['Ora'], 5000)

    # ---- Defender ---------------------------------------------------------

    def _defender(self, ev):
        d = ev['Dati']
        chiave = d.get(u'Detection ID') or (d.get(u'Threat Name'), int(ev['Ora']))
        r = self.defender.get(chiave)
        if r is None:
            if len(self.defender) >= 2000:
                return
            r = {'ora': ev['Ora'], 'minaccia': d.get(u'Threat Name') or u'', 'gravita': d.get(u'Severity Name') or u'',
                 'categoria': d.get(u'Category Name') or u'', 'percorso': d.get(u'Path') or u'',
                 'utente': d.get(u'Detection User') or u'', 'processo': d.get(u'Process Name') or u'',
                 'azione': False, 'elemento': self._elemento}
            self.defender[chiave] = r
        if ev['EventID'] == 1117:
            r['azione'] = True
        elif ev['Ora'] and ev['Ora'] < r['ora']:
            r['ora'] = ev['Ora']

    def _defender_modifica(self, ev):
        d = ev['Dati']
        ident = ev['EventID']
        if ident == 5007:
            nuovo = d.get(u'New Value') or u''
            basso = nuovo.lower()
            if u'\\exclusions\\' in basso:
                testo = u'Esclusione aggiunta: ' + nuovo
            elif re.search(u'(disablerealtimemonitoring|disableantispyware|disablebehaviormonitoring'
                           u'|disableioavprotection|disablescriptscanning|disableantivirus)'
                           u'\\s*=\\s*0x1', basso):
                testo = u'Protezione disattivata: ' + nuovo
            else:
                return
        elif ident == 5001:
            testo = u'Protezione in tempo reale disattivata'
        else:
            testo = u'Analisi antimalware disattivata'
        if len(self.defender_modifiche) < 500:
            self.defender_modifiche.append({'ora': ev['Ora'], 'id': ident, 'testo': testo,
                                            'elemento': self._elemento})

    # ---- PowerShell -------------------------------------------------------

    def _4104(self, ev):
        d = ev['Dati']
        if _intero(ev['Livello']) == 3:
            self.powershell_avvisi += 1
        testo = d.get(u'ScriptBlockText') or u''
        if not testo:
            return
        # Uno script lungo arriva spezzato in piu' eventi. Nei pezzi si
        # cercano solo i nomi degli strumenti d'attacco e le modifiche alle
        # protezioni; la regola "scarica ed esegue" vale per i blocchi interi.
        intero = (d.get(u'MessageTotal') or u'1') == u'1'
        giudizio = R.ps_sospetto(testo, culla=intero)
        famiglia = None
        if giudizio is not None and intero and len(testo) <= 2000 and giudizio[1].startswith(R._COSA_SCRIPT) \
                and R.solo_cercato(testo):
            giudizio = None     # un comando breve che cerca lo script per nome: lo scrive chi indaga
        if intero and len(testo) <= 2000 and (giudizio is None or giudizio[0] < R.DECISIVO):
            # Un blocco breve e' un comando scritto a mano o passato a
            # PowerShell: vale quanto una riga della cronologia della console.
            migliore = self._giudica_blocco_breve(testo)
            if migliore is not None and (giudizio is None or migliore[0] > giudizio[0]):
                giudizio = migliore[0], migliore[2], migliore[4]
                famiglia = migliore[1]
        if giudizio is None or giudizio[0] < R.DA_CONFERMARE:
            return
        peso, motivo, posizione = giudizio
        estratto = testo[max(0, posizione - 80): posizione + 240]
        chiave = (d.get(u'Path') or u'', motivo, estratto[:120])
        r = self.powershell.get(chiave)
        if r is None:
            if len(self.powershell) >= 300:
                return
            r = {'ora': ev['Ora'], 'n': 0, 'percorso': d.get(u'Path') or u'', 'motivo': motivo, 'peso': peso,
                 'estratto': u' '.join(estratto.split()), 'utente': ev['SidUtente'], 'fonte': u'4104',
                 'elemento': self._elemento, 'famiglia': famiglia}
            self.powershell[chiave] = r
        r['n'] += 1
        if ev['Ora'] and ev['Ora'] < r['ora']:
            r['ora'] = ev['Ora']

    def _giudica_blocco_breve(self, testo):
        """Il riscontro piu' pesante tra le righe di un blocco di script
        breve: (peso, famiglia, motivo, comando in chiaro, posizione della
        riga nel blocco) oppure None. Gli stessi blocchi si ripetono migliaia
        di volte: il giudizio su ogni riga si calcola una volta sola."""
        migliore = None
        posizione = 0
        for riga in testo.split(u'\n')[:40]:
            pulita = riga.strip()
            if len(pulita) >= 4:
                if pulita in self._righe_giudicate:
                    g = self._righe_giudicate[pulita]
                else:
                    g = R.riga_di_console(pulita)
                    if len(self._righe_giudicate) < 20000:
                        self._righe_giudicate[pulita] = g
                if g is not None and (migliore is None or g[0] > migliore[0]):
                    migliore = g + (posizione,)
            posizione += len(riga) + 1
        return migliore

    def _400(self, ev):
        testo = u'\n'.join(ev['Lista'])
        m = _RX_HOSTAPP.search(testo)
        if m is None:
            return
        riga = m.group(1).strip()
        chiave = (u'', u'avvio', riga[:300])
        r = self.powershell.get(chiave)
        if r is None:
            if chiave in self._avvii_innocui or len(self.powershell) >= 300:
                return
            # Come per i processi: i comandi che pesano da soli (cancellare i
            # registri, creare un account...) valgono quello che valgono
            # ovunque; per il resto il livello 3 e' decisivo solo se certo.
            peso, motivo, famiglia = 0, u'', None
            noti = R.comandi_noti(riga)
            for peso_c, famiglia_c, cosa_c in noti:
                if peso_c > peso:
                    peso, motivo, famiglia = peso_c, cosa_c, famiglia_c
            g = R.valuta_comando(riga, persistenza=False)
            if (g.livello >= 3 or g.avvio) and peso < R.DECISIVO and (g.certo or not noti):
                peso_g = R.DECISIVO if g.certo else R.DA_CONFERMARE
                if peso_g > peso:
                    peso, motivo, famiglia = peso_g, g.motivo(), None
            if peso < R.DA_CONFERMARE:
                if len(self._avvii_innocui) < 20000:
                    self._avvii_innocui.add(chiave)     # lo stesso avvio si ripete: non va rigiudicato ogni volta
                return
            estratto = riga[:600]
            if g.decodificato:
                estratto += u'\nComando in chiaro: ' + u' '.join(g.decodificato.split())[:800]
            r = {'ora': ev['Ora'], 'n': 0, 'percorso': u'', 'motivo': motivo, 'peso': peso, 'famiglia': famiglia,
                 'estratto': estratto, 'utente': u'', 'fonte': u'400', 'elemento': self._elemento}
            self.powershell[chiave] = r
        r['n'] += 1
        if ev['Ora'] and ev['Ora'] < r['ora']:
            r['ora'] = ev['Ora']

    # ---- WMI --------------------------------------------------------------

    def _5861(self, ev):
        d = ev['Dati']
        if len(self.wmi) < 500:
            self.wmi.append({'ora': ev['Ora'], 'consumer': d.get(u'CONSUMER') or u'', 'filtro': d.get(u'ESS') or u'',
                             'testo': u' '.join((d.get(u'PossibleCause') or u'').split())[:4000],
                             'elemento': self._elemento})

    # ---- RMM --------------------------------------------------------------

    def _testo_evento(self, ev):
        parti = [x for x in ev['Lista'] if x]
        for k in sorted(ev['Dati'].keys()):
            if k != u'Binary' and ev['Dati'][k]:
                parti.append(u'%s=%s' % (k, ev['Dati'][k]))
        return u' | '.join(parti)[:1000]

    def _logmein(self, ev):
        if len(self.rmm) < 5000:
            self.rmm.append({'ora': ev['Ora'], 'strumento': u'LogMeIn', 'id': ev['EventID'],
                             'testo': self._testo_evento(ev), 'elemento': self._elemento})

    def _pulseway(self, ev, comandi):
        testo = self._testo_evento(ev)
        if not comandi and u'Received Request' not in testo and u'pulseway' not in ev['Provider'].lower():
            return
        if len(self.rmm) < 5000:
            self.rmm.append({'ora': ev['Ora'], 'strumento': u'Pulseway (comandi)' if comandi else u'Pulseway',
                             'id': ev['EventID'], 'testo': testo, 'elemento': self._elemento})

    def _msi(self, ev):
        prodotto = ev['Lista'][0] if ev['Lista'] else u''
        nome = R.trova_rmm(prodotto)
        if nome and len(self.installazioni) < 500:
            self.installazioni.append({'ora': ev['Ora'], 'strumento': nome, 'prodotto': prodotto,
                                       'elemento': self._elemento})
