# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
Triage compromissione Windows - modulo di ingest per Autopsy (nell'elenco
dei moduli compare come "Windows Compromise Triage").

Esegue sull'origine dati i controlli della checklist "Questa macchina
Windows e' compromessa?" e dice in pochi minuti dove guardare prima. Produce:
  - un verdetto euristico di triage (Indicatori di compromissione / Da
    verificare, priorita' alta / Da verificare / Nessun indicatore trovato):
    non e' una probabilita' ne' una prova;
  - i segnali, come risultati di analisi nell'albero di Autopsy
    (Analysis Results > Triage compromissione: segnali);
  - un report HTML e un CSV nella cartella Reports del caso.
I risultati possono essere in italiano o in inglese (vedi tc_lingua.py).

Installazione: copiare l'intera cartella TriageCompromissione nella cartella
dei moduli Python di Autopsy (menu Tools > Python Plugins) e riavviare
Autopsy. Vedi README.it.md (in inglese: README.md).
"""

import os
import re
import time
import codecs
import inspect
import traceback

import jarray
from java.lang import IllegalArgumentException
from java.util import ArrayList
from java.util.logging import Level
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing import JSpinner
from javax.swing import SpinnerNumberModel
from javax.swing import BoxLayout
from javax.swing import Box
from javax.swing import BorderFactory
from java.awt import Color
from java.awt import Component
from java.awt import Dimension
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices

# I moduli del plugin vanno importati qui, in cima al file: Autopsy toglie
# la cartella del plugin dal percorso di ricerca subito dopo averlo caricato.
# Non vengono ricaricati con reload(): Autopsy rilegge questo file ogni volta
# che apre la finestra dei moduli di ingest, e ricaricare gli elenchi delle
# regole mentre un'analisi e' in corso su un altro thread gliele farebbe
# trovare a meta'. Dopo aver modificato un file tc_*.py va riavviato Autopsy.
import tc_base
import tc_lingua
import tc_evtx
import tc_registro
import tc_prefetch
import tc_artefatti
import tc_regole
import tc_origine
import tc_eventi
import tc_c_registro
import tc_c_eventi
import tc_c_file
import tc_memoria
import tc_controlli
import tc_report
from tc_lingua import tr

# Le lingue sono due. Quella dell'interfaccia (descrizione del modulo,
# pannello delle impostazioni) e' quella del sistema, cioe' di Java: italiano
# se Windows (o Autopsy) e' in italiano, altrimenti inglese. Quella dei
# risultati (messaggio, albero, report) si sceglie nel pannello e, finche'
# non la si sceglie, e' la stessa.
LINGUA_SISTEMA = tc_lingua.del_sistema()


def _ui(testo):
    """Un testo dell'interfaccia, nella lingua del sistema."""
    return tc_lingua.tr_in(LINGUA_SISTEMA, testo)


# Il nome del modulo NON si traduce. Autopsy riconosce i moduli dal nome: lo
# salva nelle impostazioni di ingest e nei profili usati da riga di comando.
# Se cambiasse con la lingua, alla prima analisi dopo il cambio Autopsy
# direbbe che il modulo "non si trova piu'" e un'ingest da riga di comando
# con quel profilo non partirebbe.
NOME_MODULO = u'Windows Compromise Triage'
TIPO_SEGNALE = u'TC_SEGNALE'
TIPO_VERDETTO = u'TC_VERDETTO'

# Gli errori che non devono fermare il modulo: in Jython le eccezioni Java di
# Autopsy (TskCoreException e simili) non sono sottoclassi di Exception.
ERRORI = tc_base.ERRORI


def _traccia():
    """La traccia dell'errore in corso, come testo."""
    try:
        return traceback.format_exc().decode('utf-8', 'replace')
    except ERRORI:
        return tr(u'(traccia non disponibile)')

try:
    from org.python.core import Py
    from org.python.core.util import StringUtil

    def _da_byte(vettore, quanti):
        return Py.newString(StringUtil.fromBytes(vettore, 0, quanti))
except ERRORI:
    def _da_byte(vettore, quanti):
        return vettore[:quanti].tostring()


# --------------------------------------------------------------------------
# L'origine dati di Autopsy vista dai controlli
# --------------------------------------------------------------------------

class ElementoAutopsy(tc_origine.Elemento):
    """Un file del caso."""

    def __init__(self, f):
        self.rif = f
        self.nome = f.getName()
        cartella = f.getParentPath()
        self.cartella = cartella if cartella else u'/'
        self.dimensione = f.getSize()
        self.creato = f.getCrtime()
        self.modificato = f.getMtime()
        self.e_cartella = f.isDir()
        try:
            self.cancellato = bool(f.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC) or
                                   f.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC))
        except ERRORI:
            self.cancellato = False
        self.volume = None
        try:
            v = f.getFileSystemObjectId()
            if v.isPresent():
                self.volume = v.get()
        except ERRORI:
            # Autopsy 4.19 (TSK 4.11) non ha getFileSystemObjectId(): per i
            # file di un file system l'identificativo e' getFileSystemId().
            # I file logici non hanno ne' l'uno ne' l'altro: restano senza.
            try:
                self.volume = f.getFileSystemId()
            except ERRORI:
                pass

    def leggi(self, posizione, quanti):
        """Legge dal file. Un errore di Autopsy (file illeggibile, settore
        danneggiato) diventa un IOError di Python, cosi' chi chiama puo'
        saltare il file e andare avanti."""
        if posizione < 0 or posizione >= self.dimensione:
            return ''
        quanti = min(quanti, self.dimensione - posizione)
        if quanti <= 0:
            return ''
        try:
            vettore = jarray.zeros(quanti, 'b')
            letti = self.rif.read(vettore, posizione, quanti)
        except ERRORI, errore:
            try:
                dettaglio = unicode(errore).encode('ascii', 'replace')
            except ERRORI:
                dettaglio = tr(u'errore non descrivibile')
            raise IOError(tr(u'lettura non riuscita (posizione %d): %s') % (posizione, dettaglio[:300]))
        if letti <= 0:
            return ''
        return _da_byte(vettore, letti)

    def chiudi(self):
        """Rilascia il file aperto nell'immagine (si riapre da solo alla
        prossima lettura): senza, migliaia di file resterebbero aperti fino
        alla fine dell'analisi."""
        try:
            self.rif.close()
        except ERRORI:
            pass


def _apici(testo):
    return testo.replace(u"'", u"''")


class OrigineAutopsy(tc_origine.Origine):
    """Cerca i file nel database del caso."""

    def __init__(self, sorgente_dati, caso):
        self.id = sorgente_dati.getId()
        self.nome = sorgente_dati.getName()
        self.sk = caso.getSleuthkitCase()
        self.interrogazioni = 0

    def _esegui(self, condizioni, cancellati):
        # tipi di file: 0 file system, 2 derivati (estratti da archivi),
        # 3 file locali, 8 cartelle locali. Esclusi slack e spazio non allocato.
        dove = [u'data_source_obj_id = %d' % self.id, u'type IN (0, 2, 3, 8)']
        if not cancellati:
            dove.append(u'dir_flags <> 2')
        dove.extend(condizioni)
        self.interrogazioni += 1
        try:
            trovati = self.sk.findAllFilesWhere(u' AND '.join(dove))
        except ERRORI, errore:
            try:
                dettaglio = unicode(errore).encode('ascii', 'replace')
            except ERRORI:
                dettaglio = tr(u'errore non descrivibile')
            raise IOError(tr(u'interrogazione del database del caso non riuscita: %s') % dettaglio[:300])
        elementi = []
        for f in trovati:
            try:
                elementi.append(ElementoAutopsy(f))
            except ERRORI:
                continue
        return elementi

    def cerca(self, cartella, nome=u'%', cancellati=False, cartelle=False, estensioni=None):
        # prima le condizioni che costano meno (l'estensione, il nome), poi il percorso
        condizioni = []
        modelli = cartella if isinstance(cartella, (list, tuple)) else [cartella]
        if estensioni:
            condizioni.append(u'extension IN (%s)' % u', '.join([u"'%s'" % _apici(x) for x in estensioni]))
        if nome != u'%':
            condizioni.append(u"LOWER(name) LIKE '%s'" % _apici(nome))
        if u'%' not in modelli:
            condizioni.append(u'(' + u' OR '.join([u"LOWER(parent_path) LIKE '%s'" % _apici(m) for m in modelli]) + u')')
        if not condizioni:
            return []
        return self.filtra(self._esegui(condizioni, cancellati), cartella, nome, cancellati, cartelle, estensioni)

    def in_cartella(self, cartelle, nome, volume=None):
        condizioni = [u'parent_path IN (%s)' % u', '.join([u"'%s'" % _apici(c) for c in cartelle]),
                      u"LOWER(name) = '%s'" % _apici(nome.lower())]
        return [e for e in self._esegui(condizioni, False) if e.volume == volume and not e.e_cartella]

    def cerca_frammenti(self, frammenti, estensioni=None, cancellati=False):
        if not frammenti:
            return []
        condizioni = []
        if estensioni:
            condizioni.append(u'extension IN (%s)' % u', '.join([u"'%s'" % _apici(x) for x in estensioni]))
        condizioni.append(u'(' + u' OR '.join([u"LOWER(name) LIKE '%%%s%%'" % _apici(f) for f in frammenti]) + u')')
        return self.filtra_frammenti(self._esegui(condizioni, cancellati), frammenti, estensioni, cancellati)


# --------------------------------------------------------------------------
# Fabbrica del modulo e pannello delle impostazioni
# --------------------------------------------------------------------------

class TriageCompromissioneFactory(IngestModuleFactoryAdapter):

    moduleName = NOME_MODULO

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        # nella finestra dei moduli Autopsy mostra solo i primi 60 caratteri
        # circa (il resto compare fermando il mouse sul testo)
        return _ui(u'Triage rapido: indica quali macchine Windows esaminare per prime. Cerca indicatori di '
                   u'compromissione nei registri eventi, nel registro di sistema, nel Prefetch, negli altri artefatti e '
                   u'nella RAM analizzata con Volatility; produce un verdetto euristico, i segnali e un report HTML.')

    def getModuleVersionNumber(self):
        return tc_controlli.VERSIONE

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return TriageCompromissioneModule(ingestOptions)

    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, GenericIngestModuleJobSettings):
            raise IllegalArgumentException(_ui(u'Le impostazioni devono essere di tipo GenericIngestModuleJobSettings'))
        return TriageCompromissionePanel(settings)


def _raccolte_ram():
    """Le cartelle di collect_memory.py nel caso aperto: (identificativo del
    manifesto, testo da mostrare). Vuoto se non c'e' un caso."""
    trovate = []
    try:
        sk = Case.getCurrentCase().getSleuthkitCase()
        nomi = {}
        for d in sk.getDataSources():
            nomi[d.getId()] = d.getName()
        for f in sk.findAllFilesWhere(u"LOWER(name) = '%s' AND dir_flags <> 2" % tc_memoria.NOME_MANIFESTO):
            if f.isDir() or f.getSize() <= 0:
                continue
            origine = nomi.get(f.getDataSourceObjectId(), u'?')
            cartella = (f.getParentPath() or u'/').rstrip(u'/').split(u'/')[-1] or u'/'
            trovate.append((f.getId(), (u'%s: %s' % (origine, cartella))[:60]))
    except ERRORI:
        pass
    return sorted(trovate, key=lambda x: x[1])[:100]


class TriageCompromissionePanel(IngestModuleIngestJobSettingsPanel):
    """Le impostazioni dell'analisi. (Non si puo' usare un attributo
    chiamato 'settings': Jython lo confonde con getSettings().)"""

    def __init__(self, impostazioni):
        # Nella finestra dei moduli di ingest di Autopsy lo spazio per questo
        # pannello e' largo circa 320 punti: righe corte e campo stretto,
        # altrimenti il testo viene tagliato e compare la barra di scorrimento.
        self.impostazioni_locali = impostazioni
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        giorni = 30
        try:
            giorni = int(impostazioni.getSetting('giorni_recenti') or 30)
        except ERRORI:
            pass
        riga = Box.createHorizontalBox()
        riga.add(JLabel(_ui(u'Giorni da considerare \u00abrecenti\u00bb:')))
        riga.add(Box.createRigidArea(Dimension(8, 0)))
        self.campo_giorni = JSpinner(SpinnerNumberModel(max(1, min(3650, giorni)), 1, 3650, 1))
        self.campo_giorni.setPreferredSize(Dimension(70, 26))
        self.campo_giorni.setMaximumSize(Dimension(70, 26))
        riga.add(self.campo_giorni)
        riga.add(Box.createHorizontalGlue())
        self._aggiungi(riga)
        self._nota(_ui(u'Contati dall\'ultima attivit\u00e0 della macchina.'))
        self.add(Box.createRigidArea(Dimension(0, 12)))
        self._aggiungi(JLabel(_ui(u'Accesso remoto autorizzato (RMM):')))
        self.campo_rmm = JTextField(impostazioni.getSetting('rmm_autorizzati') or u'')
        self.campo_rmm.setPreferredSize(Dimension(280, 26))
        self.campo_rmm.setMaximumSize(Dimension(280, 26))
        self._aggiungi(self.campo_rmm)
        self._nota(_ui(u'Nomi separati da virgola: TeamViewer, AnyDesk'))
        self._nota(_ui(u'Restano nel report ma non pesano sul verdetto.'))
        self.add(Box.createRigidArea(Dimension(0, 12)))
        riga = Box.createHorizontalBox()
        riga.add(JLabel(_ui(u'Lingua dei risultati:')))
        riga.add(Box.createRigidArea(Dimension(8, 0)))
        self.campo_lingua = JComboBox()
        for sigla in tc_lingua.LINGUE:
            self.campo_lingua.addItem(tc_lingua.NOMI[sigla])
        scelta = None
        try:
            scelta = tc_lingua.valida(impostazioni.getSetting('lingua'))
        except ERRORI:
            pass
        self.campo_lingua.setSelectedIndex(list(tc_lingua.LINGUE).index(scelta or LINGUA_SISTEMA))
        self.campo_lingua.setPreferredSize(Dimension(110, 26))
        self.campo_lingua.setMaximumSize(Dimension(110, 26))
        riga.add(self.campo_lingua)
        riga.add(Box.createHorizontalGlue())
        self._aggiungi(riga)
        self._nota(_ui(u'Vale per il messaggio, l\'albero e il report.'))
        self.add(Box.createRigidArea(Dimension(0, 12)))
        self._aggiungi(JLabel(_ui(u'RAM (risultati di Volatility):')))
        self.campo_ram = JComboBox()
        self.valori_ram = [u'auto', u'nessuna']
        self.campo_ram.addItem(_ui(u'Automatica: stessa origine o stesso host'))
        self.campo_ram.addItem(_ui(u'Nessuna'))
        for identificativo, testo in _raccolte_ram():
            self.valori_ram.append(u'id:%d' % identificativo)
            self.campo_ram.addItem(testo)
        attuale = u'auto'
        try:
            attuale = impostazioni.getSetting('ram') or u'auto'
        except ERRORI:
            pass
        if attuale not in self.valori_ram:
            # la RAM scelta in un altro caso: qui non c'e', lo dira' il report
            self.valori_ram.append(attuale)
            self.campo_ram.addItem(_ui(u'Scelta prima, non trovata in questo caso'))
        self.campo_ram.setSelectedIndex(self.valori_ram.index(attuale))
        self.campo_ram.setPreferredSize(Dimension(280, 26))
        self.campo_ram.setMaximumSize(Dimension(280, 26))
        self._aggiungi(self.campo_ram)
        self._nota(_ui(u'Quale RAM va con questa macchina lo dici tu:'))
        self._nota(_ui(u'il plugin controlla la scelta e avvisa.'))
        self.add(Box.createRigidArea(Dimension(0, 12)))
        self._nota(_ui(u'Legge soltanto: non modifica l\'origine dati.'))
        self._nota(_ui(u'Il report va nella cartella Reports del caso.'))

    def _aggiungi(self, componente):
        componente.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.add(componente)

    def _nota(self, testo):
        etichetta = JLabel(testo)
        etichetta.setForeground(Color(90, 90, 90))
        self._aggiungi(etichetta)

    def getSettings(self):
        try:
            self.impostazioni_locali.setSetting('giorni_recenti', str(int(self.campo_giorni.getValue())))
            self.impostazioni_locali.setSetting('rmm_autorizzati', self.campo_rmm.getText() or u'')
        except ERRORI:
            pass
        try:
            indice = self.campo_lingua.getSelectedIndex()
            if 0 <= indice < len(tc_lingua.LINGUE):
                self.impostazioni_locali.setSetting('lingua', str(tc_lingua.LINGUE[indice]))
        except ERRORI:
            pass
        try:
            indice = self.campo_ram.getSelectedIndex()
            if 0 <= indice < len(self.valori_ram):
                self.impostazioni_locali.setSetting('ram', str(self.valori_ram[indice]))
        except ERRORI:
            pass
        return self.impostazioni_locali


# --------------------------------------------------------------------------
# Il modulo
# --------------------------------------------------------------------------

class TriageCompromissioneModule(DataSourceIngestModule):

    _logger = Logger.getLogger(NOME_MODULO)

    def __init__(self, impostazioni):
        self.impostazioni = impostazioni
        self.context = None
        self._ripulito = False
        self._tenuti = set()            # (file, testo) dei segnali vecchi con un'etichetta dell'analista
        self._verdetti_tenuti = set()   # (verdetto, motivo, computer) dei verdetti vecchi con un'etichetta
        self._vecchi = []               # i risultati dell'analisi precedente, da togliere a scrittura riuscita
        self._lavagna = None

    def log(self, livello, testo):
        try:
            self._logger.logp(livello, self.__class__.__name__, inspect.stack()[1][3], testo)
        except ERRORI:
            pass

    def startUp(self, context):
        self.context = context

    def _lingua(self):
        """La lingua dei risultati: quella scelta nel pannello, altrimenti
        quella del sistema."""
        scelta = None
        try:
            if self.impostazioni is not None:
                scelta = tc_lingua.valida(self.impostazioni.getSetting('lingua'))
        except ERRORI:
            pass
        return scelta or LINGUA_SISTEMA

    def _opzioni(self):
        opzioni = tc_controlli.Opzioni()
        if self.impostazioni is None:
            return opzioni
        # le due impostazioni si leggono separatamente: un valore sbagliato
        # in una non deve far perdere l'altra
        try:
            giorni = self.impostazioni.getSetting('giorni_recenti')
            if giorni:
                opzioni.giorni_recenti = max(1, min(3650, int(float(unicode(giorni).strip().replace(u',', u'.')))))
        except ERRORI:
            self.log(Level.WARNING, tr(u'Impostazione "giorni recenti" non valida: uso 30'))
        try:
            rmm = self.impostazioni.getSetting('rmm_autorizzati')
            if rmm:
                # separatori: virgola (anche quella larga delle tastiere orientali), punto e virgola, a capo
                nomi = [x.strip(u' "\'\u201c\u201d\u00ab\u00bb') for x in
                        re.split(u'[,;\\n\\r\\t\uff0c\u3001]+', unicode(rmm)[:20000])]
                opzioni.rmm_autorizzati = [x for x in nomi if x][:200]
        except ERRORI:
            self.log(Level.WARNING, tr(u'Impostazione "RMM autorizzati" non leggibile: ignorata'))
        return opzioni

    def process(self, dataSource, progressBar):
        # da qui in poi, in questo thread, i testi escono nella lingua scelta
        tc_lingua.imposta(self._lingua())
        try:
            return self._analizza(dataSource, progressBar)
        except ERRORI:
            # qualunque errore imprevisto: lo si dice all'utente invece di
            # lasciare che Autopsy segnali solo un generico errore del modulo
            traccia = _traccia()
            self.log(Level.SEVERE, tr(u'Triage non riuscito: ') + traccia)
            self._messaggio(IngestMessage.MessageType.ERROR, tr(u'Triage non riuscito su %s') % self._nome(dataSource),
                            u'<pre>%s</pre>' % tc_report._e(traccia))
            return IngestModule.ProcessResult.ERROR

    def _nome(self, dataSource):
        try:
            return dataSource.getName() or tr(u'origine dati')
        except ERRORI:
            return tr(u'origine dati')

    def _analizza(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        caso = Case.getCurrentCase()
        inizio = time.time()
        nome_origine = self._nome(dataSource)
        origine = OrigineAutopsy(dataSource, caso)
        progressBar.progress(tr(u'Cerco le installazioni di Windows'))
        radici, scartate = tc_origine.trova_radici(origine)
        memorie, problemi_ram = self._memorie(dataSource, caso, origine)
        per_radice = tc_controlli.NUMERO_PASSI + 1      # i controlli, piu' report e pubblicazione
        passi_totali = per_radice * len(radici)
        progressBar.switchToDeterminate(passi_totali)
        fatti = [0]
        esito = IngestModule.ProcessResult.OK
        self._ripulito = False      # i risultati di un'analisi precedente si elencano una volta sola
        self._vecchi = []
        self._lavagna = None
        pubblicate = 0
        for numero, radice in enumerate(radici):
            if self.context.dataSourceIngestIsCancelled():
                break
            etichetta = u'' if len(radici) == 1 else tr(u'[%d di %d] ') % (numero + 1, len(radici))
            fatti[0] = numero * per_radice

            def avanza(testo, passo=False, etichetta=etichetta, limite=(numero + 1) * per_radice - 1):
                if passo:
                    fatti[0] = min(fatti[0] + 1, limite)
                try:
                    progressBar.progress(etichetta + testo, fatti[0])
                except ERRORI:
                    pass

            def registra(testo):
                self.log(Level.INFO, testo)

            try:
                t = tc_controlli.Triage(radice, self._opzioni(), avanza, self.context.dataSourceIngestIsCancelled, registra)
                t.memorie = memorie
                t.contesto['installazioni_origine'] = len(radici)
                for genere, testo in problemi_ram:
                    if genere == 'avviso':
                        t.avviso(testo)
                    else:
                        t.nota(testo)
                t.esegui()
            except ERRORI:
                esito = IngestModule.ProcessResult.ERROR
                traccia = _traccia()
                self.log(Level.SEVERE, tr(u'Triage non riuscito: ') + traccia)
                self._messaggio(IngestMessage.MessageType.ERROR, tr(u'Triage non riuscito su %s') % nome_origine,
                                u'<pre>%s</pre>' % tc_report._e(traccia))
                continue
            if self.context.dataSourceIngestIsCancelled():
                break       # analisi annullata: i risultati di prima restano come sono
            if scartate:
                t.nota(tr(u'Nell\'origine ci sono anche altre installazioni di Windows, non analizzate: %s.') % u', '.join(scartate[:5]))
            if self._vuoto(t):
                self._messaggio(IngestMessage.MessageType.INFO,
                                tr(u'Triage: nessun artefatto di Windows in %s') % nome_origine,
                                tr(u'Non ho trovato n\u00e9 registro di sistema n\u00e9 registri eventi: il triage non \u00e8 stato eseguito.'))
                continue
            for e in t.errori:
                self.log(Level.WARNING, tr(u'Controllo non riuscito: ') + e)
            try:
                progressBar.progress(etichetta + tr(u'Scrivo il report e i risultati'), (numero + 1) * per_radice - 1)
            except ERRORI:
                pass
            percorso_report = None
            try:
                percorso_report = self._report(t, caso, dataSource, numero, len(radici), scartate)
            except ERRORI:
                self.log(Level.SEVERE, tr(u'Report non scritto: ') + _traccia())
            # Da qui non si guarda piu' se l'utente ha annullato: scrivere i
            # risultati richiede un attimo, e fermarsi a meta' lascerebbe
            # nell'albero un verdetto con solo una parte dei suoi segnali.
            non_scritti = -1
            try:
                non_scritti = self._pubblica(t, caso, dataSource, percorso_report)
                pubblicate += 1
            except ERRORI:
                self.log(Level.SEVERE, tr(u'Risultati non pubblicati: ') + _traccia())
            self._riepilogo(t, dataSource, percorso_report, origine.interrogazioni, non_scritti)
            try:
                progressBar.progress(etichetta + tr(u'Fatto'), (numero + 1) * per_radice)
            except ERRORI:
                pass
        # i risultati dell'analisi precedente si tolgono solo adesso, e solo
        # se quelli nuovi sono stati scritti: se qualcosa e' andato storto, o
        # l'analisi e' stata annullata, restano
        if pubblicate:
            self._togli_vecchi()
        self.log(Level.INFO, tr(u'Triage completato in %.1f s') % (time.time() - inizio))
        return esito

    # ---- utilita' -----------------------------------------------------------

    def _scelta_ram(self):
        """L'impostazione "RAM": 'auto', 'nessuna' oppure 'id:<manifesto>'."""
        try:
            valore = (self.impostazioni.getSetting('ram') or u'auto') if self.impostazioni is not None else u'auto'
        except ERRORI:
            valore = u'auto'
        return valore if (valore in (u'auto', u'nessuna') or valore.startswith(u'id:')) else u'auto'

    def _memorie(self, dataSource, caso, origine):
        """Le RAM (cartelle di collect_memory.py) che l'analista ha indicato per
        questa origine dati: con l'impostazione "Automatica" quelle nella stessa
        origine e quelle delle origini dello stesso host di Autopsy; altrimenti
        quella scelta. Le RAM delle origini di altri host si leggono solo per
        dire, se sono dello stesso computer, che non sono state usate.
        Restituisce (memorie, problemi): i problemi vanno tra gli avvisi."""
        memorie = []
        problemi = []
        scelta = self._scelta_ram()
        if scelta == u'nessuna':
            try:
                if tc_memoria.trova(origine):
                    problemi.append(('nota', tr(u'Nell\'origine dati ci sono risultati di Volatility, ma nelle impostazioni '
                                                u'dell\'ingest la RAM \u00e8 esclusa: i controlli sui dati volatili non sono '
                                                u'stati fatti.')))
            except ERRORI:
                pass
            return memorie, problemi
        sk = caso.getSleuthkitCase()
        if scelta.startswith(u'id:'):
            f = None
            try:
                f = sk.getAbstractFileById(long(scelta[3:]))
            except ERRORI:
                f = None
            if f is None or f.getName().lower() != tc_memoria.NOME_MANIFESTO:
                problemi.append(('avviso', tr(u'La RAM scelta nelle impostazioni dell\'ingest non si trova in questo caso: '
                                              u'i controlli sui dati volatili non sono stati fatti. Sceglila di nuovo.')))
                return memorie, problemi
            try:
                altra = f.getDataSource()
                o = origine if altra.getId() == dataSource.getId() else OrigineAutopsy(altra, caso)
                memorie.append(tc_memoria.Memoria(o, ElementoAutopsy(f), altra.getName(), altra.getId() == dataSource.getId(),
                                                  tc_memoria.INDICATA))
            except ERRORI:
                self.log(Level.WARNING, tr(u'RAM scelta non leggibile: ') + _traccia())
                problemi.append(('avviso', tr(u'La RAM scelta nelle impostazioni dell\'ingest non si legge: i controlli '
                                              u'sui dati volatili non sono stati fatti.')))
            return memorie, problemi
        try:
            for e in tc_memoria.trova(origine):
                memorie.append(tc_memoria.Memoria(origine, e, self._nome(dataSource), True, tc_memoria.STESSA_ORIGINE))
        except ERRORI:
            self.log(Level.WARNING, tr(u'Ricerca dei risultati della RAM non riuscita: ') + _traccia())
        mio_host = None
        try:
            mio_host = dataSource.getHost().getHostId()
        except ERRORI:
            mio_host = None         # Autopsy senza host (prima della 4.19)
        try:
            altre = list(sk.getDataSources())
        except ERRORI:
            altre = []
            self.log(Level.WARNING, tr(u'Elenco delle origini dati del caso non riuscito: ') + _traccia())
        for altra in altre:
            try:
                if altra.getId() == dataSource.getId():
                    continue
                stesso = False
                try:
                    stesso = mio_host is not None and altra.getHost().getHostId() == mio_host
                except ERRORI:
                    stesso = False
                o = OrigineAutopsy(altra, caso)
                for e in tc_memoria.trova(o):
                    memorie.append(tc_memoria.Memoria(o, e, altra.getName(), False,
                                                      tc_memoria.STESSO_HOST if stesso else tc_memoria.ALTRO_HOST))
            except ERRORI:
                self.log(Level.WARNING, tr(u'Ricerca dei risultati della RAM non riuscita: ') + _traccia())
        return memorie, problemi

    def _vuoto(self, t):
        """Vero se nell'origine non c'era nulla da analizzare. Se invece
        qualcosa c'era ma non si e' lasciato leggere, o un controllo si e'
        interrotto, il triage va riportato lo stesso: dire "nessun artefatto"
        sarebbe falso."""
        if t.segnali or t.esecuzioni or t.attivita or t.errori or t.non_letti:
            return False
        if t.contesto.get('computer') or t.contesto.get('prodotto') or t.contesto.get('utenti_sam'):
            return False
        if t.contesto.get('memorie'):
            return False
        if t.raccolta is not None and t.raccolta.copertura:
            return False
        return True

    def _messaggio(self, tipo, oggetto, dettagli):
        try:
            IngestServices.getInstance().postMessage(IngestMessage.createMessage(tipo, NOME_MODULO, oggetto, dettagli))
        except ERRORI:
            pass

    def _riepilogo(self, t, dataSource, percorso_report, interrogazioni, non_scritti=0):
        """Il messaggio nella posta di Autopsy. non_scritti: quanti segnali
        non si e' riusciti a scrivere nell'albero (-1: nessun risultato scritto)."""
        R = tc_regole
        contano = [s for s in t.segnali if s.conta and not s.discordante and not s.limitato]
        decisivi = [s for s in contano if s.peso == R.DECISIVO]
        conferme = [s for s in contano if s.peso == R.DA_CONFERMARE]
        computer = tc_base.pulito(t.contesto.get('computer') or t.contesto.get('computer_ram')) or self._nome(dataSource)
        c = t.conteggi or {}
        righe = [u'<i>%s</i>' % tc_report._e(tr(tc_controlli.AVVERTENZA)),
                 u'<b>%s</b><br>%s' % (tc_report._e(tr(t.verdetto)), tc_report._e(t.motivo_verdetto)),
                 tr(u'Fatti decisivi: %d (segnali: %d) - fatti da confermare: %d (segnali: %d)')
                 % (c.get('fatti_decisivi', 0), c.get('segnali_decisivi', 0), c.get('fatti_da_confermare', 0),
                    c.get('segnali_da_confermare', 0))]
        principali = sorted(decisivi, key=lambda s: s.ora)[:8]
        if not principali:
            principali = sorted(conferme, key=lambda s: s.ora)[:8]
        if principali:
            righe.append(u'<ul>' + u''.join([u'<li>%s</li>' % tc_report._e(s.descrizione[:220]) for s in principali]) + u'</ul>')
        for a in t.avvisi[:3]:
            righe.append(u'<i>%s</i>' % tc_report._e(a))
        if t.errori:
            if len(t.errori) == 1:
                righe.append(tr(u'<i>1 controllo non riuscito: i dettagli sono nel report e nel log di Autopsy.</i>'))
            else:
                righe.append(tr(u'<i>%d controlli non riusciti: i dettagli sono nel report e nel log di Autopsy.</i>')
                             % len(t.errori))
        if percorso_report:
            righe.append(tr(u'Report: %s') % tc_report._e(percorso_report))
        else:
            righe.append(tr(u'<b>Il report non \u00e8 stato scritto</b>: vedi il log di Autopsy (Help &gt; Open Log Folder).'))
        if non_scritti == 0:
            righe.append(tr(u'Nell\'albero: Analysis Results &gt; Triage compromissione.'))
        elif non_scritti == 1:
            righe.append(tr(u'Nell\'albero: Analysis Results &gt; Triage compromissione. <b>1 segnale non \u00e8 stato '
                         u'scritto nell\'albero</b> (vedi il log di Autopsy): il report li contiene tutti.'))
        elif non_scritti > 1:
            righe.append(tr(u'Nell\'albero: Analysis Results &gt; Triage compromissione. <b>%d segnali non sono stati '
                         u'scritti nell\'albero</b> (vedi il log di Autopsy): il report li contiene tutti.')
                         % non_scritti)
        else:
            righe.append(tr(u'<b>I risultati non sono stati scritti nell\'albero</b>: il report \u00e8 completo, il '
                         u'motivo \u00e8 nel log di Autopsy (Help &gt; Open Log Folder). I risultati nell\'albero vengono '
                         u'scritti da Autopsy 4.19 in poi.'))
        tipo = IngestMessage.MessageType.WARNING if t.verdetto != tc_controlli.V_NESSUN_INDICATORE else IngestMessage.MessageType.INFO
        self._messaggio(tipo, tr(u'Triage di %s: %s') % (computer, tr(t.verdetto)), u'<br>'.join(righe))
        self.log(Level.INFO, tr(u'Triage di %s: %s (%.1f s, %d interrogazioni al database)')
                 % (computer, t.riassunto(), t.durata, interrogazioni))

    def _report(self, t, caso, dataSource, numero, quante, scartate):
        cartella = os.path.join(caso.getReportDirectory(), u'TriageCompromissione')
        if not os.path.isdir(cartella):
            os.makedirs(cartella)
        computer = tc_base.pulito(t.contesto.get('computer'))
        nome = re.sub(u'[^A-Za-z0-9_.-]+', u'_', computer or self._nome(dataSource))[:60] or tr(u'origine')
        adesso = time.time()
        momento = time.localtime(adesso)
        quando = time.strftime('%Y%m%d_%H%M%S', momento)
        base = u'Triage_%s_%s%s' % (nome, quando, u'_%d' % (numero + 1) if quante > 1 else u'')
        # due origini dati con lo stesso nome di computer finite nello stesso
        # secondo non devono scriversi una sopra l'altra
        lettere = u'bcdefghijklmnopqrstuvwxyz'
        contatore = 0
        libero = base
        while os.path.exists(os.path.join(cartella, libero + u'.html')) and contatore < len(lettere):
            libero = base + lettere[contatore]
            contatore += 1
        base = libero
        info = {'origine': self._nome(dataSource), 'caso': caso.getDisplayName(), 'generato': adesso}
        # prima si prepara il testo, poi si scrive: se la preparazione
        # fallisce non resta sul disco un file vuoto
        testo_html = tc_report.html(t, info)
        percorso = os.path.join(cartella, base + u'.html')
        f = codecs.open(percorso, 'w', 'utf-8')
        try:
            f.write(testo_html)
        finally:
            f.close()
        try:
            testo_csv = tc_report.csv(t)
            f = codecs.open(os.path.join(cartella, base + u'.csv'), 'w', 'utf-8-sig')
            try:
                f.write(testo_csv)
            finally:
                f.close()
        except ERRORI:
            self.log(Level.WARNING, tr(u'File CSV non scritto: ') + _traccia())
        # il report compare anche nell'albero di Autopsy, sotto Reports; se
        # la registrazione non riesce il file resta comunque nella cartella
        nome_report = tr(u'Triage compromissione: %s (%s) - %s') % (computer or self._nome(dataSource), tr(t.verdetto),
                                                                time.strftime('%Y-%m-%d %H:%M:%S', momento))
        try:
            try:
                caso.addReport(percorso, NOME_MODULO, nome_report, dataSource)
            except TypeError:
                caso.addReport(percorso, NOME_MODULO, nome_report)
        except ERRORI:
            self.log(Level.WARNING, tr(u'Report scritto ma non registrato nel caso: ') + _traccia())
        return percorso

    def _pubblica(self, t, caso, dataSource, percorso_report):
        """Scrive verdetto e segnali come risultati di analisi. Restituisce
        quanti segnali non si e' riusciti a scrivere (di norma zero).

        Una nuova analisi sostituisce i risultati della precedente sulla
        stessa origine dati, ma quelli vecchi si tolgono solo alla fine (vedi
        _togli_vecchi), quando i nuovi sono scritti: se la scrittura si
        interrompe, i nuovi gia' scritti vengono ritirati e i vecchi restano.
        I risultati a cui l'analista ha messo un'etichetta (tag) non si
        toccano mai: cancellarli farebbe sparire anche l'etichetta e il suo
        commento. Un risultato nuovo uguale a uno rimasto non viene riscritto."""
        R = tc_regole
        lavagna = caso.getSleuthkitCase().getBlackboard()
        self._lavagna = lavagna
        STRINGA = BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
        tipo_segnale = lavagna.getOrAddArtifactType(TIPO_SEGNALE, tr(u'Triage compromissione: segnali'),
                                                    BlackboardArtifact.Category.ANALYSIS_RESULT)
        tipo_verdetto = lavagna.getOrAddArtifactType(TIPO_VERDETTO, tr(u'Triage compromissione: verdetto'),
                                                     BlackboardArtifact.Category.ANALYSIS_RESULT)
        a_peso = lavagna.getOrAddAttributeType(u'TC_PESO', STRINGA, tr(u'Peso'))
        a_controllo = lavagna.getOrAddAttributeType(u'TC_CONTROLLO', STRINGA, tr(u'Controllo'))
        a_famiglia = lavagna.getOrAddAttributeType(u'TC_FAMIGLIA', STRINGA, tr(u'Famiglia'))
        a_segnale = lavagna.getOrAddAttributeType(u'TC_SEGNALE_TESTO', STRINGA, tr(u'Segnale'))
        a_dettagli = lavagna.getOrAddAttributeType(u'TC_DETTAGLI', STRINGA, tr(u'Dettagli'))
        a_verdetto = lavagna.getOrAddAttributeType(u'TC_VERDETTO_TESTO', STRINGA, tr(u'Verdetto'))
        a_motivo = lavagna.getOrAddAttributeType(u'TC_MOTIVO', STRINGA, tr(u'Motivo'))
        a_computer = lavagna.getOrAddAttributeType(u'TC_COMPUTER', STRINGA, u'Computer')
        a_report = lavagna.getOrAddAttributeType(u'TC_REPORT', STRINGA, u'Report')
        a_origine = lavagna.getOrAddAttributeType(u'TC_ORIGINE', STRINGA, tr(u'Origine'))
        a_fatto = lavagna.getOrAddAttributeType(u'TC_FATTO', STRINGA, tr(u'Fatto n.'))
        a_quando = BlackboardAttribute.Type.TSK_DATETIME

        def testo_di(risultato, attributo):
            try:
                valore = risultato.getAttribute(attributo)
                return valore.getValueString() if valore is not None else u''
            except ERRORI:
                return u''

        # i risultati dell'analisi precedente: si elencano una volta sola,
        # prima di scrivere qualunque cosa
        if not self._ripulito:
            self._ripulito = True
            self._vecchi = []
            self._tenuti = set()
            self._verdetti_tenuti = set()
            sk = caso.getSleuthkitCase()
            for tipo in (tipo_segnale, tipo_verdetto):
                try:
                    for vecchio in lavagna.getAnalysisResultsByType(tipo.getTypeID(), dataSource.getId()):
                        try:
                            etichettato = not sk.getBlackboardArtifactTagsByArtifact(vecchio).isEmpty()
                        except ERRORI:
                            etichettato = True      # nel dubbio non si cancella
                        if not etichettato:
                            self._vecchi.append(vecchio)
                        elif tipo is tipo_verdetto:
                            self._verdetti_tenuti.add((testo_di(vecchio, a_verdetto), testo_di(vecchio, a_motivo),
                                                       testo_di(vecchio, a_computer)))
                        else:
                            try:
                                self._tenuti.add((vecchio.getObjectID(), testo_di(vecchio, a_segnale)))
                            except ERRORI:
                                pass
                except ERRORI:
                    self.log(Level.WARNING, tr(u'Risultati precedenti non elencati (resteranno accanto ai nuovi): ') + _traccia())
                    self._messaggio(IngestMessage.MessageType.WARNING, tr(u'Triage: risultati precedenti non rimossi'),
                                    tr(u'Non \u00e8 stato possibile elencare i risultati dell\'analisi precedente: restano '
                                    u'nell\'albero accanto a quelli nuovi. Il report pi\u00f9 recente \u00e8 quello valido.'))
        idlavoro = self.context.getJobId()
        nuovi = []
        non_scritti = 0

        def pubblica(risultato):
            # avvisa Autopsy del nuovo risultato (albero, ricerca, timeline)
            try:
                try:
                    lavagna.postArtifact(risultato, NOME_MODULO, idlavoro)
                except TypeError:
                    lavagna.postArtifact(risultato, NOME_MODULO)     # Autopsy 4.19
            except ERRORI:
                self.log(Level.WARNING, tr(u'Risultato scritto ma non annunciato: ') + _traccia())

        try:
            # verdetto, sull'origine dati
            c = t.conteggi or {}
            computer = tc_base.pulito(t.contesto.get('computer') or t.contesto.get('computer_ram'))
            verdetto = tr(t.verdetto)
            if (verdetto, t.motivo_verdetto, computer) not in self._verdetti_tenuti:
                # Il punteggio segue il verdetto: "indicatori" e' notevole, "da verificare" con
                # segnali e' probabilmente notevole. "Da verificare" solo per la copertura e
                # "nessun indicatore trovato" restano sconosciuti: non dicono nulla della
                # macchina. (SCORE_NONE significherebbe "esaminato e buono" e, sugli stessi
                # file, coprirebbe i punteggi "probabilmente notevole".)
                if t.verdetto == tc_controlli.V_INDICATORI:
                    punteggio = Score.SCORE_NOTABLE
                elif t.verdetto == tc_controlli.V_PRIORITA or (t.verdetto == tc_controlli.V_DA_VERIFICARE and
                                                               [s for s in t.segnali if s.conta and s.peso >= R.DA_CONFERMARE]):
                    punteggio = Score.SCORE_LIKELY_NOTABLE
                else:
                    punteggio = Score.SCORE_UNKNOWN
                attributi = ArrayList()
                attributi.add(BlackboardAttribute(a_verdetto, NOME_MODULO, verdetto))
                attributi.add(BlackboardAttribute(a_motivo, NOME_MODULO, t.motivo_verdetto))
                attributi.add(BlackboardAttribute(a_computer, NOME_MODULO, computer))
                attributi.add(BlackboardAttribute(a_segnale, NOME_MODULO,
                                                  tr(u'Fatti decisivi: %d (segnali: %d) - fatti da confermare: %d (segnali: %d)')
                                                  % (c.get('fatti_decisivi', 0), c.get('segnali_decisivi', 0),
                                                     c.get('fatti_da_confermare', 0), c.get('segnali_da_confermare', 0))))
                if percorso_report:
                    attributi.add(BlackboardAttribute(a_report, NOME_MODULO, percorso_report))
                risultato = dataSource.newAnalysisResult(tipo_verdetto, punteggio, verdetto, tc_controlli.VERSIONE,
                                                         t.motivo_verdetto + u' ' + tr(tc_controlli.AVVERTENZA),
                                                         attributi).getAnalysisResult()
                nuovi.append(risultato)
            # segnali, ciascuno sul file da cui viene
            punteggi = {R.DECISIVO: Score.SCORE_NOTABLE, R.DA_CONFERMARE: Score.SCORE_LIKELY_NOTABLE,
                        R.INFORMATIVO: Score.SCORE_UNKNOWN}
            # un segnale che non conta (RAM contraddetta) non da' punteggio; uno incerto
            # (discordanza, RAM anomala) al massimo "probabilmente notevole"
            def punteggio_di(s):
                if not s.conta:
                    return Score.SCORE_UNKNOWN
                if (s.discordante or s.limitato) and s.peso >= R.DA_CONFERMARE:
                    return Score.SCORE_LIKELY_NOTABLE
                return punteggi[s.peso]
            for s in t.segnali_ordinati():
                contenuto = dataSource
                if s.elemento is not None and getattr(s.elemento, 'rif', None) is not None:
                    contenuto = s.elemento.rif
                try:
                    if (contenuto.getId(), s.descrizione[:1000]) in self._tenuti:
                        continue        # c'e' gia', con l'etichetta dell'analista
                except ERRORI:
                    pass
                try:
                    attributi = ArrayList()
                    attributi.add(BlackboardAttribute(a_peso, NOME_MODULO, tr(R.NOME_PESO[s.peso])))
                    if s.ora and 0 < s.ora < 253402300800.0:      # una data vera (fino all'anno 9999)
                        attributi.add(BlackboardAttribute(a_quando, NOME_MODULO, long(s.ora)))
                    attributi.add(BlackboardAttribute(a_controllo, NOME_MODULO,
                                                      u'%02d. %s%s' % (s.controllo, s.titolo(),
                                                                       tr(u' (regola in pi\u00f9)') if s.extra else u'')))
                    attributi.add(BlackboardAttribute(a_famiglia, NOME_MODULO, tr(s.famiglia)))
                    attributi.add(BlackboardAttribute(a_segnale, NOME_MODULO, s.descrizione[:1000]))
                    if s.dettagli:
                        attributi.add(BlackboardAttribute(a_dettagli, NOME_MODULO, s.dettagli[:4000]))
                    attributi.add(BlackboardAttribute(a_origine, NOME_MODULO, tc_report.origine(s)))
                    if s.fenomeno:
                        attributi.add(BlackboardAttribute(a_fatto, NOME_MODULO, unicode(s.fenomeno)))
                    risultato = contenuto.newAnalysisResult(tipo_segnale, punteggio_di(s), tr(R.NOME_PESO[s.peso]),
                                                            tr(u'Controllo %d') % s.controllo, s.descrizione[:1000],
                                                            attributi).getAnalysisResult()
                except ERRORI:
                    # un segnale che non si scrive non deve far perdere gli altri
                    non_scritti += 1
                    if non_scritti <= 5:
                        self.log(Level.WARNING, tr(u'Segnale non scritto: ') + _traccia())
                    continue
                nuovi.append(risultato)
        except ERRORI:
            # la scrittura si e' interrotta (di solito sul verdetto): si
            # ritirano i risultati nuovi gia' scritti e quelli vecchi restano
            for risultato in nuovi:
                try:
                    lavagna.deleteAnalysisResult(risultato)
                except ERRORI:
                    pass
            raise
        if non_scritti > 5:
            self.log(Level.WARNING, tr(u'In tutto %d segnali non scritti') % non_scritti)
        for risultato in nuovi:
            pubblica(risultato)
        return non_scritti

    def _togli_vecchi(self):
        """Toglie i risultati dell'analisi precedente (quelli senza etichetta)."""
        vecchi, self._vecchi = self._vecchi, []
        falliti = 0
        for vecchio in vecchi:
            try:
                self._lavagna.deleteAnalysisResult(vecchio)
            except ERRORI:
                falliti += 1
                if falliti == 1:
                    self.log(Level.WARNING, tr(u'Risultato precedente non rimosso: ') + _traccia())
        if falliti:
            self.log(Level.WARNING, tr(u'%d risultati dell\'analisi precedente non rimossi: restano accanto ai nuovi') % falliti)
            self._messaggio(IngestMessage.MessageType.WARNING, tr(u'Triage: risultati precedenti non rimossi'),
                            tr(u'%d risultati dell\'analisi precedente non sono stati rimossi e restano nell\'albero '
                            u'accanto a quelli nuovi. Il report pi\u00f9 recente \u00e8 quello valido.') % falliti)
