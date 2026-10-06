# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_controlli - Il motore del plugin "Triage compromissione": esegue i
controlli della checklist su un'installazione di Windows e ne ricava un
verdetto.

Non dipende da Autopsy: riceve una "radice" (vedi tc_origine) e restituisce
segnali, tabelle e verdetto. I controlli veri e propri stanno in
tc_c_registro, tc_c_eventi e tc_c_file.
"""

import re
import time
import traceback

import tc_regole as R
import tc_c_registro
import tc_c_eventi
import tc_c_file
from tc_base import testo_orario, pulito, ERRORI
from tc_lingua import tr, N_

VERSIONE = u'1.1'
NUMERO_PASSI = 23       # i passi di Triage.esegui, per la barra di avanzamento

V_COMPROMESSA = N_(u'COMPROMISSIONE PROBABILE')
V_DA_VERIFICARE = N_(u'DA VERIFICARE')
V_NESSUN_INDIZIO = N_(u'NESSUN INDIZIO')

FASI = [
    (1, N_(u'Contesto e dati volatili')),
    (2, N_(u'Account e accessi')),
    (3, N_(u'Persistenza')),
    (4, N_(u'Programmi eseguiti')),
    (5, N_(u'Esecuzione remota con Impacket')),
    (6, N_(u'Strumenti di accesso remoto (RMM)')),
    (7, N_(u'File, antivirus e anti-forensics')),
]

# I 41 controlli della checklist: numero, fase, titolo
CONTROLLI = [
    (1, 1, N_(u'Contesto del sistema')),
    (2, 1, N_(u'Copia del Prefetch')),
    (3, 1, N_(u'Utenti collegati ora')),
    (4, 1, N_(u'Processi con riga di comando e processo padre')),
    (5, 1, N_(u'Connessioni di rete con il processo proprietario')),
    (6, 1, N_(u'Cache DNS')),
    (7, 1, N_(u'Sessioni e connessioni SMB')),
    (8, 2, N_(u'Copertura dei log e audit attivi')),
    (9, 2, N_(u'Log cancellati')),
    (10, 2, N_(u'Account locali, amministratori, profili')),
    (11, 2, N_(u'Logon remoti di rete e RDP')),
    (12, 2, N_(u'Accessi falliti per indirizzo')),
    (13, 2, N_(u'Credenziali esplicite e connessioni in uscita')),
    (14, 2, N_(u'Sessioni RDP (Terminal Services)')),
    (15, 3, N_(u'Attivit\u00e0 pianificate')),
    (16, 3, N_(u'Attivit\u00e0 nascoste')),
    (17, 3, N_(u'Servizi')),
    (18, 3, N_(u'Servizi installati (evento 7045)')),
    (19, 3, N_(u'Chiavi Run e cartelle Esecuzione automatica')),
    (20, 3, N_(u'Sottoscrizioni WMI')),
    (21, 4, u'Prefetch'),
    (22, 4, u'BAM'),
    (23, 4, u'RunMRU'),
    (24, 4, N_(u'Download con certutil')),
    (25, 4, N_(u'Comandi sospetti (eventi 4688, Sysmon, PowerShell)')),
    (26, 4, N_(u'ShimCache, AmCache, UserAssist')),
    (27, 5, N_(u'Attivit\u00e0 create e cancellate in pochi istanti')),
    (28, 5, N_(u'Firme di atexec nelle attivit\u00e0')),
    (29, 5, N_(u'Firme di smbexec nei servizi')),
    (30, 5, N_(u'File residui')),
    (31, 5, N_(u'Accessi alle share (evento 5145)')),
    (32, 6, N_(u'Programmi installati')),
    (33, 6, N_(u'RMM portabili, anche rinominati')),
    (34, 6, u'AnyDesk'),
    (35, 6, u'TeamViewer'),
    (36, 6, N_(u'LogMeIn e Pulseway')),
    (37, 7, N_(u'Rilevamenti dell\'antivirus')),
    (38, 7, N_(u'File recenti nelle cartelle di appoggio')),
    (39, 7, N_(u'Cestino')),
    (40, 7, N_(u'Copie shadow')),
    (41, 7, N_(u'Artefatti disattivati')),
]
TITOLO_CONTROLLO = dict([(n, titolo) for n, _, titolo in CONTROLLI])
FASE_CONTROLLO = dict([(n, fase) for n, fase, _ in CONTROLLI])
VOLATILI = (2, 3, 4, 5, 6, 7)


def _periodo(secondi):
    """Una durata in parole: '5 ore', 'un giorno', '12 giorni'."""
    if secondi < 2 * 86400:
        return tr(u'%d ore') % max(1, int(round(secondi / 3600.0)))
    return tr(u'%d giorni') % int(secondi / 86400.0)


class Opzioni(object):
    """Impostazioni dell'analisi."""

    def __init__(self):
        self.giorni_recenti = 30          # finestra dei controlli "recenti"
        self.rmm_autorizzati = []         # nomi (anche parziali) degli RMM da non segnalare
        self.massimo_per_controllo = 40   # segnali al massimo per ciascun controllo

    def autorizzato(self, strumento):
        """Vero se lo strumento e' tra quelli autorizzati. Il nome indicato
        deve comparire come parola intera in quello dello strumento ("vnc" in
        "VNC (Real, Tight...)"): una lettera sola non autorizza tutto."""
        basso = (strumento or u'').lower()
        for nome in self.rmm_autorizzati:
            nome = nome.strip().lower()
            if len(nome) >= 3 and re.search(u'(?<![a-z0-9])' + re.escape(nome) + u'(?![a-z0-9])', basso):
                return True
        return False

    def non_riconosciuti(self):
        """I nomi autorizzati che non corrispondono a nessuno strumento
        conosciuto (scritti male, o troppo corti): non hanno effetto."""
        ignoti = []
        for nome in self.rmm_autorizzati:
            pulito_ = nome.strip()
            if not pulito_:
                continue
            unico = Opzioni()
            unico.rmm_autorizzati = [pulito_]
            if not [1 for leggibile, _ in R.RMM if unico.autorizzato(leggibile)]:
                ignoti.append(pulito_)
        return ignoti


class Segnale(object):
    """Un riscontro di un controllo."""

    def __init__(self, controllo, peso, famiglia, descrizione, dettagli=u'', ora=0, elemento=None,
                 extra=False):
        self.controllo = controllo
        self.peso = peso
        self.famiglia = famiglia
        self.descrizione = descrizione
        self.dettagli = dettagli
        self.ora = ora or 0
        self.elemento = elemento
        self.extra = extra      # regola che non viene dalle 32 guide

    def titolo(self):
        return tr(TITOLO_CONTROLLO.get(self.controllo, u''))


class Tabella(object):

    def __init__(self, controllo, titolo, colonne, righe, nota=u''):
        self.controllo = controllo
        self.titolo = titolo
        self.colonne = colonne
        self.righe = righe
        self.nota = nota


class Triage(object):
    """Esegue i controlli su una radice e conserva i risultati."""

    def __init__(self, radice, opzioni=None, avanzamento=None, annullato=None, registra=None):
        self.radice = radice
        self.opzioni = opzioni or Opzioni()
        self._avanzamento = avanzamento
        self._annullato = annullato
        self._registra = registra
        self.segnali = []
        self.tabelle = []
        self.esiti = {}             # controllo -> (stato, nota); stato: 'fatto', 'assente', 'non verificabile'
        self.contesto = {}          # informazioni sul sistema
        self.avvisi = []            # limiti della copertura
        self.errori = []            # controlli non riusciti
        self.non_letti = []         # file che non e' stato possibile leggere: (percorso, motivo)
        self.profili = {}           # SID -> {'nome', 'percorso', 'ora'}
        self.esecuzioni = []        # prove di esecuzione o di esistenza di programmi
        self.rmm = {}               # strumento -> {'prove': [], 'sessioni': []}
        self.raccolta = None        # eventi (tc_eventi.Raccolta)
        self.attivita = {}          # attivita' pianificate dal registro
        self._rif = None            # il riferimento calcolato (None: da ricalcolare)
        self._rif_forzato = None    # il riferimento imposto da fuori (nelle prove)
        self._voti = {}             # fonte affidabile -> il suo orario piu' recente
        self._minuti_altri = {}     # minuto -> [orario piu' recente, quanti orari]: i 60 minuti piu' recenti delle altre fonti
        self._minimo_altri = None   # il piu' vecchio dei minuti tenuti
        self.ultimo_evento = 0.0    # la data piu' recente tra gli eventi di tutti i registri letti
        self._celle = []            # (nome dell'hive, insieme delle celle trovate rovinate)
        self.note = []              # osservazioni che non riguardano la copertura
        self._senza_date = None     # vero se l'origine non riporta le date dei file
        self._date_copia = None     # vero se le date di creazione dei file sono quelle della copia
        self.verdetto = V_NESSUN_INDIZIO
        self.motivo_verdetto = u''
        self.durata = 0.0
        self._per_controllo = {}    # controllo -> segnali emessi (anche quelli non conservati)
        self._per_gruppo = {}       # (controllo, peso, famiglia) -> segnali emessi

    # ---- servizi per i controlli ----------------------------------------

    def annullato(self):
        try:
            return bool(self._annullato and self._annullato())
        except ERRORI:
            return False

    def avanza(self, testo, passo=False):
        """Aggiorna il testo dell'avanzamento. Con passo=True conta anche un
        passo in piu' sulla barra (lo fa solo l'inizio di ogni controllo)."""
        if self._avanzamento:
            try:
                self._avanzamento(testo, passo)
            except TypeError:
                try:
                    self._avanzamento(testo)       # funzione con un solo argomento
                except ERRORI:
                    pass
            except ERRORI:
                pass

    def battito(self, quanti, ogni, testo):
        """Da chiamare dentro i cicli lunghi: ogni 'ogni' elementi aggiorna
        l'avanzamento e dice se l'utente ha annullato. Cosi' Autopsy non
        sembra fermo e l'annullamento non aspetta la fine del ciclo."""
        if quanti and quanti % ogni == 0:
            self.avanza(testo % quanti)
            return self.annullato()
        return False

    def fallita(self, cosa, errore=None):
        """Una ricerca nel database del caso (o un altro passo di un
        controllo) non e' riuscita: il controllo e' incompleto e si deve
        sapere. Finisce tra gli errori, che danno un avviso sul verdetto."""
        testo = cosa
        if errore is not None:
            try:
                testo = u'%s: %s' % (cosa, errore)
            except ERRORI:
                testo = cosa
        testo = pulito(testo)[:600]
        if testo not in self.errori:
            self.errori.append(testo)
        self.registra(tr(u'Non riuscito: %s') % testo)

    def registra(self, testo):
        if self._registra:
            try:
                self._registra(testo)
            except ERRORI:
                pass

    def segnala(self, controllo, peso, famiglia, descrizione, dettagli=u'', ora=0, elemento=None,
                extra=False):
        """Aggiunge un segnale. Ogni combinazione di controllo, peso e
        famiglia ha il suo tetto: i segnali in piu' vengono contati ma non
        conservati. Il tetto e' per combinazione e non per controllo, cosi'
        una valanga di voci informative non puo' far sparire un segnale piu'
        pesante e il primo segnale di ogni famiglia resta sempre (e' quello
        che conta per il verdetto)."""
        self._per_controllo[controllo] = self._per_controllo.get(controllo, 0) + 1
        gruppo = (controllo, peso, famiglia)
        n = self._per_gruppo.get(gruppo, 0) + 1
        self._per_gruppo[gruppo] = n
        tetto = self.opzioni.massimo_per_controllo
        if peso >= R.DECISIVO:
            tetto *= 4
        if n > tetto:
            return None
        s = Segnale(controllo, peso, famiglia, pulito(descrizione), pulito(dettagli), ora, elemento, extra)
        self.segnali.append(s)
        return s

    def tabella(self, controllo, titolo, colonne, righe, nota=u''):
        if righe:
            self.tabelle.append(Tabella(controllo, titolo, colonne, righe, nota))

    def esito(self, controllo, stato, nota=u''):
        vecchio = self.esiti.get(controllo)
        if vecchio is not None and vecchio[0] == 'fatto' and stato != 'fatto':
            return
        self.esiti[controllo] = (stato, nota)

    def fatto(self, *controlli):
        for c in controlli:
            self.esiti[c] = ('fatto', u'')

    def avviso(self, testo):
        if testo not in self.avvisi:
            self.avvisi.append(testo)

    def nota(self, testo):
        """Un'osservazione per chi legge il report che non tocca il verdetto."""
        if testo not in self.note:
            self.note.append(testo)

    def non_letto(self, elemento, motivo=u''):
        """Annota un file che non si e' riusciti a leggere (settori
        danneggiati, file non accessibile): finisce tra gli avvisi."""
        try:
            percorso = elemento.percorso
        except ERRORI:
            percorso = u'?'
        if not isinstance(motivo, unicode):
            try:
                motivo = unicode(motivo)
            except ERRORI:
                motivo = u''
        if len(self.non_letti) < 500 and percorso not in [x[0] for x in self.non_letti]:
            self.non_letti.append((percorso, pulito(motivo)[:200]))
        self.registra(tr(u'File non letto: %s (%s)') % (percorso, motivo))

    def inizio(self, elemento, quanti):
        """I primi byte di un file ('' se non si leggono; in quel caso il
        file viene annotato tra quelli non letti)."""
        try:
            try:
                return elemento.leggi(0, min(quanti, elemento.dimensione))
            finally:
                elemento.chiudi()
        except ERRORI, errore:
            self.non_letto(elemento, errore)
            return ''

    def senza_date(self):
        """Vero se l'origine non riporta le date dei file. Succede con i
        file logici aggiunti ad Autopsy senza spuntare le date: creazione e
        modifica valgono zero per tutti."""
        if self._senza_date is None:
            campioni = self._campioni()
            self._senza_date = bool(campioni) and not [e for e in campioni if e.creato or e.modificato]
        return self._senza_date

    def _campioni(self):
        """Gli hive di sistema e i registri eventi: i file su cui si giudica
        se le date dell'origine sono utilizzabili."""
        campioni = [self.contesto.get(k) for k in ('hive_software', 'hive_system', 'hive_sam')]
        if self.raccolta is not None:
            campioni.extend([v[3] for v in self.raccolta.copertura.values()])
        return [e for e in campioni if e is not None]

    def date_della_copia(self):
        """Vero se le date di creazione dei file sono posteriori all'ultima
        attivita' della macchina: succede con i file logici copiati su un
        altro disco prima di aggiungerli ad Autopsy. In quel caso la data di
        creazione e' quella della copia e non dice nulla sulla macchina."""
        if self._date_copia is None:
            ultima = self.ultima_attivita()
            campioni = [e for e in self._campioni() if e.creato]
            self._date_copia = bool(ultima and len(campioni) >= 3 and
                                    not [e for e in campioni if e.creato <= ultima + 86400.0])
        return self._date_copia

    def contenuto(self, elemento, massimo=None):
        """Il contenuto di un file, oppure None se la lettura fallisce (in
        quel caso il file viene annotato tra quelli non letti)."""
        try:
            try:
                if massimo is None:
                    return elemento.tutto()
                return elemento.tutto(massimo)
            finally:
                elemento.chiudi()
        except ERRORI, errore:
            self.non_letto(elemento, errore)
            return None

    def vede(self, ora, affidabile=False, fonte=u''):
        """Annota un orario visto negli artefatti: serve a stabilire il
        riferimento, cioe' il momento da cui si conta all'indietro la finestra
        dei controlli "recenti". Le fonti affidabili sono l'ultimo evento
        scritto in ciascun registro eventi e l'ora di spegnimento (fonte dice
        quale); tutte le altre (BAM, UserAssist, Prefetch, SAM...) contano
        solo se quelle mancano. Gli orari oltre domani non sono credibili e
        vengono ignorati."""
        if not (ora > 0) or ora > time.time() + 86400:
            return
        if affidabile:
            if ora > self._voti.get(fonte, 0):
                self._voti[fonte] = ora
                self._rif = None
            return
        minuto = int(ora // 60)
        minuti = self._minuti_altri
        voce = minuti.get(minuto)
        if voce is not None:
            voce[1] += 1
            if ora > voce[0]:
                voce[0] = ora
                self._rif = None
        elif len(minuti) < 60:
            minuti[minuto] = [ora, 1]
            if self._minimo_altri is None or minuto < self._minimo_altri:
                self._minimo_altri = minuto
            self._rif = None
        elif minuto > self._minimo_altri:
            del minuti[self._minimo_altri]
            minuti[minuto] = [ora, 1]
            self._minimo_altri = min(minuti)
            self._rif = None

    def _calcola_riferimento(self):
        """Il riferimento non e' "l'orario piu' recente visto": un solo
        orario sbagliato, o messo apposta, sposterebbe la finestra in avanti
        e farebbe passare per vecchia l'attivita' recente. Percio':
        - se ci sono Security e System, vale il piu' vecchio dei loro ultimi
          eventi scritti (ogni sessione di Windows scrive in entrambi: un
          record isolato con una data sbagliata in uno dei due non conta);
        - altrimenti il terzo piu' recente tra gli ultimi eventi degli altri
          registri e l'ora di spegnimento (il piu' vecchio se sono meno di tre);
        - senza fonti affidabili, il terzo minuto piu' recente in cui gli
          altri artefatti mostrano attivita'.
        Sbagliare all'indietro allarga soltanto la finestra."""
        voti = self._voti
        sicurezza = voti.get(u'security.evtx')
        sistema = voti.get(u'system.evtx')
        if sicurezza and sistema:
            return min(sicurezza, sistema)
        valori = sorted(voti.values(), reverse=True)
        if valori:
            return valori[min(3, len(valori)) - 1]
        minuti = self._minuti_altri
        if minuti:
            return minuti[sorted(minuti)[-3:][0]][0]
        return 0.0

    def _leggi_riferimento(self):
        if self._rif_forzato is not None:
            return self._rif_forzato
        if self._rif is None:
            self._rif = self._calcola_riferimento()
        return self._rif

    def _imposta_riferimento(self, valore):
        self._rif_forzato = valore

    riferimento = property(_leggi_riferimento, _imposta_riferimento)

    def ultima_attivita(self):
        """L'orario piu' recente tra tutti quelli credibili (per il report)."""
        orari = [self.ultimo_evento] + list(self._voti.values()) + [v[0] for v in self._minuti_altri.values()]
        return max(orari + [0.0])

    def celle_di(self, nome, hive):
        """Tiene d'occhio un hive aperto: alla fine, se i controlli vi hanno
        trovato celle rovinate, lo si dice. Si conserva solo l'insieme delle
        celle, non l'hive (che puo' pesare centinaia di MB)."""
        self._celle.append((nome, hive.danneggiate))

    def _controlla_hive(self):
        rovinati = []
        for nome, celle in self._celle:
            if celle:
                rovinati.append(u'%s (%d)' % (nome, len(celle)))
        if rovinati:
            self.avviso(tr(u'Hive del registro con chiavi o valori non leggibili (tra parentesi quanti): %s%s. Sono '
                        u'danneggiati: i controlli che li leggono possono essere incompleti.')
                        % (u', '.join(rovinati[:8]), tr(u' e altri') if len(rovinati) > 8 else u''))

    def _controlla_orari(self):
        """Attivita' piu' recente dell'ultimo evento di tutti i registri: i
        controlli sugli eventi non coprono quel periodo, e chi legge il
        verdetto deve saperlo. Succede se la registrazione degli eventi e'
        stata fermata, se l'orologio e' stato spostato, o se i file raccolti
        vengono da momenti diversi."""
        ultimo_evento = self.ultimo_evento
        if not ultimo_evento:
            return
        soglia = ultimo_evento + 86400.0
        dopo = [v for v in self._minuti_altri.values() if v[0] > soglia]
        if dopo:
            quanti = sum([v[1] for v in dopo])
            ultimo = max([v[0] for v in dopo])
            quanto = _periodo(ultimo - ultimo_evento)
            if len(dopo) >= 3 or quanti >= 5:
                self.avviso(tr(u'I registri eventi si fermano al %s UTC, ma gli altri artefatti (Prefetch, BAM, '
                            u'UserAssist, AmCache, registro) mostrano attivit\u00e0 fino al %s UTC, %s dopo: i '
                            u'controlli sugli eventi non coprono quel periodo. O la registrazione degli eventi '
                            u'\u00e8 stata fermata, o l\'orologio \u00e8 stato spostato, oppure i file raccolti '
                            u'vengono da momenti diversi.')
                            % (testo_orario(ultimo_evento), testo_orario(ultimo), quanto))
            else:
                if quanti == 1:
                    self.nota(tr(u'Negli altri artefatti c\'\u00e8 un orario (fino al %s UTC) posteriore di %s all\'ultimo '
                              u'evento dei registri (%s UTC): un orologio sbagliato o un orario alterato. Non sposta la '
                              u'finestra dei controlli recenti.')
                              % (testo_orario(ultimo), quanto, testo_orario(ultimo_evento)))
                else:
                    self.nota(tr(u'Negli altri artefatti ci sono %d orari (fino al %s UTC) posteriori di %s all\'ultimo '
                              u'evento dei registri (%s UTC): un orologio sbagliato o un orario alterato. Non spostano '
                              u'la finestra dei controlli recenti.')
                              % (quanti, testo_orario(ultimo), quanto, testo_orario(ultimo_evento)))
        spegnimento = self.contesto.get('spegnimento', 0)
        if spegnimento and soglia < spegnimento <= time.time() + 86400:
            self.avviso(tr(u'L\'ultimo spegnimento di Windows (%s UTC) \u00e8 posteriore di %s all\'ultimo evento dei '
                        u'registri (%s UTC). Windows scrive sempre eventi quando si spegne: o la registrazione era '
                        u'ferma, o i registri raccolti vengono da un momento precedente.')
                        % (testo_orario(spegnimento), _periodo(spegnimento - ultimo_evento),
                           testo_orario(ultimo_evento)))

    def recente(self, ora):
        """Vero se l'istante cade nella finestra recente (rispetto all'ultimo
        istante di attivita' della macchina, non a oggi)."""
        if not ora or not self.riferimento:
            return False
        return ora >= self.riferimento - self.opzioni.giorni_recenti * 86400.0

    def nome_utente(self, sid):
        p = self.profili.get(sid)
        if p and p.get('nome'):
            return p['nome']
        noti = {u'S-1-5-18': u'SYSTEM', u'S-1-5-19': u'LOCAL SERVICE', u'S-1-5-20': u'NETWORK SERVICE'}
        return noti.get(sid, sid)

    def prova_rmm(self, strumento, tipo, dettaglio, ora=0, elemento=None, controllo=32, genere=''):
        """Una traccia di uno strumento di accesso remoto. 'tipo' e' il testo
        mostrato (gia' nella lingua dell'analisi); 'genere' serve ai
        ragionamenti e non cambia con la lingua: 'eseguito' se la traccia
        prova che il programma e' stato avviato, 'installato' se dice quando
        e' stato installato."""
        voce = self.rmm.setdefault(strumento, {'prove': [], 'sessioni': []})
        if len(voce['prove']) < 200:
            voce['prove'].append({'tipo': tipo, 'dettaglio': dettaglio, 'ora': ora or 0, 'elemento': elemento,
                                  'controllo': controllo, 'genere': genere})

    def sessione_rmm(self, strumento, ora, dettaglio, elemento=None, controllo=34, in_entrata=True):
        voce = self.rmm.setdefault(strumento, {'prove': [], 'sessioni': []})
        if len(voce['sessioni']) < 2000:
            voce['sessioni'].append({'ora': ora or 0, 'dettaglio': dettaglio, 'elemento': elemento,
                                     'controllo': controllo, 'in_entrata': in_entrata})

    def esecuzione(self, percorso, ora, fonte, utente=u'', conteggio=0, elemento=None, eseguito=True,
                   orari=None, nota=u''):
        """Registra una prova che un programma e' stato eseguito (o, con
        eseguito=False, che il file esisteva)."""
        if len(self.esecuzioni) >= 60000:
            return
        self.esecuzioni.append({'percorso': percorso, 'ora': ora or 0, 'fonte': fonte, 'utente': utente,
                                'conteggio': conteggio, 'elemento': elemento, 'eseguito': eseguito,
                                'orari': orari or ([ora] if ora else []), 'nota': nota})
        self.vede(ora)

    # ---- esecuzione -----------------------------------------------------

    def _passo(self, nome, funzione):
        if self.annullato():
            return
        self.avanza(nome, True)
        t0 = time.time()
        try:
            funzione(self)
        except ERRORI:
            # un controllo che non riesce non ferma gli altri: l'errore
            # finisce nel report e nel log di Autopsy
            try:
                traccia = traceback.format_exc().decode('utf-8', 'replace')
            except ERRORI:
                traccia = tr(u'(traccia dell\'errore non disponibile)')
            self.errori.append(u'%s: %s' % (nome, traccia[-1500:]))
            self.registra(tr(u'Errore in "%s": %s') % (nome, traccia))
        self.registra(u'%s: %.1f s' % (nome, time.time() - t0))

    def esegui(self):
        inizio = time.time()
        for c in VOLATILI:
            self.esiti[c] = ('non verificabile', tr(u'dato volatile: serve il triage dal vivo o un dump della RAM'))
        self.esiti[2] = ('non verificabile', tr(u'non serve su un\'immagine: il Prefetch viene letto dal controllo 21'))
        passi = [
            # (se cambia il numero dei passi va aggiornato NUMERO_PASSI qui sotto)
            (tr(u'Registro: SOFTWARE'), tc_c_registro.software),
            (tr(u'Registro: SYSTEM'), tc_c_registro.system),
            (tr(u'Registro: SAM'), tc_c_registro.sam),
            (tr(u'Registri eventi'), tc_c_eventi.leggi),
            (tr(u'Registro: profili degli utenti'), tc_c_registro.utenti),
            (tr(u'Registro: AmCache'), tc_c_registro.amcache),
            (u'Prefetch', tc_c_file.prefetch),
            (tr(u'Attivit\u00e0 pianificate'), tc_c_file.attivita),
            (tr(u'Esecuzione automatica'), tc_c_file.avvio_automatico),
            (tr(u'Sottoscrizioni WMI'), tc_c_file.wmi),
            (u'CryptnetUrlCache', tc_c_file.cryptnet),
            (tr(u'File residui di Impacket'), tc_c_file.residui),
            (tr(u'Strumenti di accesso remoto'), tc_c_file.rmm),
            (u'Antivirus', tc_c_file.defender),
            (tr(u'Cronologia di PowerShell'), tc_c_file.cronologia_powershell),
            (tr(u'Cartelle di appoggio'), tc_c_file.appoggio),
            (tr(u'Cestino'), tc_c_file.cestino),
            (tr(u'Copie shadow'), tc_c_file.shadow),
            (tr(u'Analisi degli eventi'), tc_c_eventi.analizza),
            (tr(u'Attivit\u00e0 pianificate: riepilogo'), tc_c_registro.riepilogo_attivita),
            (tr(u'Programmi eseguiti'), tc_c_registro.valuta_esecuzioni),
            (tr(u'Strumenti di accesso remoto: riepilogo'), tc_c_file.riepilogo_rmm),
            (tr(u'Account: riepilogo'), tc_c_registro.riepilogo_account),
        ]
        assert len(passi) == NUMERO_PASSI
        for nome in self.opzioni.non_riconosciuti():
            self.nota(tr(u'Tra gli strumenti di accesso remoto autorizzati c\'\u00e8 \u00ab%s\u00bb, che non corrisponde a '
                      u'nessuno strumento conosciuto: non ha effetto. I nomi riconosciuti sono nell\'elenco RMM del '
                      u'file tc_regole.py.') % nome[:60])
        for nome, funzione in passi:
            self._passo(nome, funzione)
        if self.errori:
            # un controllo interrotto da un errore e' un controllo non fatto:
            # non deve poter passare per "nessun indizio"
            if len(self.errori) == 1:
                self.avviso(tr(u'1 controllo interrotto da un errore: i risultati sono incompleti (i dettagli sono qui sotto '
                            u'e nel log di Autopsy).'))
            else:
                self.avviso(tr(u'%d controlli interrotti da un errore: i risultati sono incompleti (i dettagli sono qui '
                            u'sotto e nel log di Autopsy).') % len(self.errori))
        if self.senza_date():
            self.nota(tr(u'L\'origine dati non riporta le date dei file (succede con i file logici aggiunti ad Autopsy '
                      u'senza spuntare le date). Il controllo 38 non pu\u00f2 distinguere i file recenti da quelli vecchi '
                      u'e li considera tutti; ai segnali che vengono dai file manca l\'orario.'))
        if not self.senza_date() and self.date_della_copia():
            self.nota(tr(u'Le date di creazione dei file dell\'origine sono posteriori all\'ultima attivit\u00e0 della '
                      u'macchina: sono le date della copia, non quelle originali. Per i controlli sui file (38 e profili '
                      u'degli utenti) \u00e8 stata usata la data di modifica.'))
        self._controlla_orari()
        self._controlla_hive()
        if self.non_letti:
            nomi = [x[0].rstrip(u'/').split(u'/')[-1] for x in self.non_letti]
            if len(nomi) == 1:
                self.avviso(tr(u'1 file non letto per errori di lettura (immagine danneggiata o file non accessibili): %s. '
                            u'I controlli che ne dipendono sono incompleti.') % nomi[0])
            else:
                self.avviso(tr(u'%d file non letti per errori di lettura (immagine danneggiata o file non accessibili): %s%s. '
                            u'I controlli che ne dipendono sono incompleti.')
                            % (len(nomi), u', '.join(nomi[:8]), tr(u' e altri') if len(nomi) > 8 else u''))
        self.decidi()
        self.durata = time.time() - inizio
        return self

    # ---- verdetto ---------------------------------------------------------

    def copertura_scarsa(self):
        """Motivi per cui l'assenza di segnali non basta a escludere una
        compromissione."""
        return list(self.avvisi)

    def decidi(self):
        decisivi = [s for s in self.segnali if s.peso == R.DECISIVO]
        conferme = [s for s in self.segnali if s.peso == R.DA_CONFERMARE]
        famiglie = []
        for s in conferme:
            if s.famiglia not in famiglie:
                famiglie.append(s.famiglia)
        if decisivi:
            self.verdetto = V_COMPROMESSA
            n = len(decisivi)
            if n == 1:
                self.motivo_verdetto = tr(u'1 segnale decisivo: basta uno solo per trattare la macchina come compromessa.')
            else:
                self.motivo_verdetto = (tr(u'%d segnali decisivi: basta uno solo per trattare la macchina come '
                                        u'compromessa.') % n)
        elif len(famiglie) >= 2:
            self.verdetto = V_COMPROMESSA
            self.motivo_verdetto = (tr(u'Nessun segnale decisivo, ma segnali da confermare in %d famiglie diverse '
                                    u'(%s): presi insieme puntano nella stessa direzione.')
                                    % (len(famiglie), u', '.join([tr(f) for f in famiglie])))
        elif len(famiglie) == 1:
            self.verdetto = V_DA_VERIFICARE
            self.motivo_verdetto = (tr(u'Segnali da confermare in una sola famiglia (%s): da soli non bastano. '
                                    u'Cerca conferme dall\'IT, dall\'utente e dai log centralizzati.') % tr(famiglie[0]))
        elif self.avvisi:
            self.verdetto = V_DA_VERIFICARE
            self.motivo_verdetto = (tr(u'Nessun segnale, ma la copertura \u00e8 insufficiente: l\'assenza di tracce '
                                    u'non esclude una compromissione.'))
        else:
            self.verdetto = V_NESSUN_INDIZIO
            self.motivo_verdetto = (tr(u'I controlli eseguiti non hanno trovato segnali. Il triage non sostituisce '
                                    u'l\'analisi completa se ci sono altri motivi di sospetto.'))

    # ---- riepiloghi -------------------------------------------------------

    def stato_controllo(self, numero):
        """(etichetta, peso massimo, numero di segnali, nota) per la tabella
        dei 41 controlli."""
        miei = [s for s in self.segnali if s.controllo == numero]
        esito = self.esiti.get(numero)
        if miei:
            peso = max([s.peso for s in miei])
            etichetta = {R.DECISIVO: tr(u'Segnale decisivo'), R.DA_CONFERMARE: tr(u'Da confermare'),
                         R.INFORMATIVO: tr(u'Solo contesto')}[peso]
            return etichetta, peso, self._per_controllo.get(numero, len(miei)), u''
        if esito is None:
            return tr(u'Non eseguito'), 0, 0, u''
        if esito[0] == 'fatto':
            return tr(u'Nulla da segnalare'), 0, 0, esito[1]
        if esito[0] == 'assente':
            return tr(u'Artefatto non trovato'), -1, 0, esito[1]
        return tr(u'Non verificabile'), -1, 0, esito[1]

    def segnali_ordinati(self):
        return sorted(self.segnali, key=lambda s: (-s.peso, s.controllo, -(s.ora or 0)))

    def cronologia(self):
        """I segnali decisivi e da confermare che hanno un orario, in
        ordine di tempo."""
        con_ora = [s for s in self.segnali if s.ora and s.peso >= R.DA_CONFERMARE]
        con_ora.sort(key=lambda s: s.ora)
        return con_ora

    def riassunto(self):
        decisivi = len([s for s in self.segnali if s.peso == R.DECISIVO])
        conferme = len([s for s in self.segnali if s.peso == R.DA_CONFERMARE])
        return tr(u'%s - %d decisivi, %d da confermare') % (tr(self.verdetto), decisivi, conferme)


def orario(epoch):
    """Orario leggibile (UTC) per tabelle e segnali."""
    return testo_orario(epoch)
