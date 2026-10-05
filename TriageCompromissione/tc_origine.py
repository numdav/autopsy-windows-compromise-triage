# -*- coding: utf-8 -*-
"""
tc_origine - Da dove arrivano i file analizzati dal plugin "Triage
compromissione".

I controlli non parlano direttamente con Autopsy: chiedono i file a una
"origine". In Autopsy l'origine legge dal database del caso; qui c'e' anche
un'origine che legge da una cartella del disco locale, usata per le prove.

Una "radice" e' un'installazione di Windows dentro l'origine: il punto in
cui si trova la cartella Windows (per esempio "/" in un'immagine disco,
"/LogicalFileSet1/raccolta/C/" in una cartella aggiunta come file logici).
"""

import os
import re

from tc_base import ERRORI


def modello_a_regex(modello):
    """Trasforma un modello con % (come in SQL LIKE) in un'espressione
    regolare ancorata."""
    parti = [re.escape(x) for x in modello.split(u'%')]
    return re.compile(u'^' + u'.*'.join(parti) + u'$', re.S)


def estensione(nome):
    """Estensione di un nome di file, senza punto ('' se non c'e')."""
    p = nome.rfind(u'.')
    if p <= 0 or p == len(nome) - 1:
        return u''
    return nome[p + 1:]


class Elemento(object):
    """Un file (o una cartella) dell'origine."""

    nome = u''
    cartella = u'/'          # percorso della cartella che lo contiene, con / finale
    dimensione = 0
    creato = 0               # epoch UTC, 0 se sconosciuto
    modificato = 0
    cancellato = False
    e_cartella = False
    volume = None            # identificativo del file system, se c'e'
    rif = None               # riferimento all'oggetto di Autopsy

    @property
    def percorso(self):
        return self.cartella + self.nome

    def leggi(self, posizione, quanti):
        raise NotImplementedError

    def inizio(self, quanti):
        try:
            return self.leggi(0, min(quanti, self.dimensione))
        except ERRORI:
            return ''

    def tutto(self, massimo=1536 * 1024 * 1024):
        """L'intero contenuto (fino a 'massimo' byte)."""
        da_leggere = min(self.dimensione, massimo)
        pezzi = []
        pos = 0
        while pos < da_leggere:
            pezzo = self.leggi(pos, min(8 * 1024 * 1024, da_leggere - pos))
            if not pezzo:
                break
            pezzi.append(pezzo)
            pos += len(pezzo)
        return ''.join(pezzi)

    def chiudi(self):
        pass


class Origine(object):
    """Interfaccia di un'origine. cerca() riceve due modelli in minuscolo,
    con % come carattere jolly: uno per la cartella (percorso con / finale;
    puo' essere anche una lista di modelli) e uno per il nome."""

    nome = u''

    def cerca(self, cartella, nome=u'%', cancellati=False, cartelle=False, estensioni=None):
        """estensioni: lista di estensioni senza punto, in minuscolo; se
        indicata, restituisce solo i file con una di quelle estensioni."""
        raise NotImplementedError

    def cerca_frammenti(self, frammenti, estensioni=None, cancellati=False):
        """I file il cui nome contiene almeno uno dei frammenti (minuscoli),
        ovunque nell'origine."""
        raise NotImplementedError

    def in_cartella(self, cartelle, nome, volume=None):
        """I file con quel nome (confronto senza maiuscole) in una delle
        cartelle indicate, scritte esattamente come nell'origine, e nel
        volume indicato. La cartella viene confrontata per uguaglianza e non
        con un modello: cosi' funziona anche con nomi che contengono %, _ o
        lettere accentate, e in un'immagine con due Windows non si pesca il
        file dell'altro volume."""
        raise NotImplementedError

    def fratelli(self, elemento, nome):
        """I file con quel nome nella stessa cartella dell'elemento."""
        return self.in_cartella([elemento.cartella], nome, elemento.volume)

    @staticmethod
    def filtra(elementi, cartella, nome, cancellati, cartelle, estensioni=None):
        if isinstance(cartella, (list, tuple)):
            rx_c = [modello_a_regex(c) for c in cartella]
        else:
            rx_c = [modello_a_regex(cartella)]
        rx_n = modello_a_regex(nome)
        buoni = []
        for e in elementi:
            if e.e_cartella != cartelle:
                continue
            if e.cancellato and not cancellati:
                continue
            basso = e.nome.lower()
            if basso in (u'.', u'..'):
                continue
            if estensioni is not None and estensione(basso) not in estensioni:
                continue
            if rx_n.match(basso) is None:
                continue
            dove = e.cartella.lower()
            for rx in rx_c:
                if rx.match(dove) is not None:
                    buoni.append(e)
                    break
        return buoni

    @staticmethod
    def filtra_frammenti(elementi, frammenti, estensioni, cancellati):
        buoni = []
        for e in elementi:
            if e.e_cartella or (e.cancellato and not cancellati):
                continue
            basso = e.nome.lower()
            if estensioni is not None and estensione(basso) not in estensioni:
                continue
            for f in frammenti:
                if f in basso:
                    buoni.append(e)
                    break
        return buoni


# --------------------------------------------------------------------------
# Origine su cartella locale (per le prove e per l'uso fuori da Autopsy)
# --------------------------------------------------------------------------

class ElementoLocale(Elemento):

    def __init__(self, percorso_locale, cartella, nome, e_cartella):
        self.locale = percorso_locale
        self.cartella = cartella
        self.nome = nome
        self.e_cartella = e_cartella
        self._f = None
        try:
            st = os.stat(percorso_locale)
            self.dimensione = 0 if e_cartella else st.st_size
            self.modificato = int(st.st_mtime)
            self.creato = int(st.st_mtime)
        except ERRORI:
            pass

    def leggi(self, posizione, quanti):
        if self._f is None:
            self._f = open(self.locale, 'rb')
        self._f.seek(posizione)
        return self._f.read(quanti)

    def chiudi(self):
        if self._f is not None:
            try:
                self._f.close()
            except ERRORI:
                pass
            self._f = None


class OrigineCartella(Origine):
    """Tutti i file sotto una cartella del disco locale. 'prefisso' simula
    il percorso che Autopsy da' ai file logici (deve iniziare e finire
    con /)."""

    def __init__(self, cartella_locale, prefisso=u'/'):
        self.nome = cartella_locale
        self.elementi = []
        base = os.path.abspath(cartella_locale)
        if not isinstance(base, unicode):
            base = base.decode('utf-8')
        for radice, cartelle, nomi in os.walk(base):
            relativo = radice[len(base):].replace(os.sep, u'/').strip(u'/')
            cartella = prefisso + (relativo + u'/' if relativo else u'')
            for n in cartelle:
                self.elementi.append(ElementoLocale(os.path.join(radice, n), cartella, n, True))
            for n in nomi:
                self.elementi.append(ElementoLocale(os.path.join(radice, n), cartella, n, False))

    def cerca(self, cartella, nome=u'%', cancellati=False, cartelle=False, estensioni=None):
        return self.filtra(self.elementi, cartella, nome, cancellati, cartelle, estensioni)

    def cerca_frammenti(self, frammenti, estensioni=None, cancellati=False):
        return self.filtra_frammenti(self.elementi, frammenti, estensioni, cancellati)

    def in_cartella(self, cartelle, nome, volume=None):
        basso = nome.lower()
        return [e for e in self.elementi if e.cartella in cartelle and e.volume == volume
                and not e.e_cartella and not e.cancellato and e.nome.lower() == basso]


# --------------------------------------------------------------------------
# Radici: le installazioni di Windows dentro l'origine
# --------------------------------------------------------------------------

_DA_SCARTARE = (u'windows.old', u'$windows.~bt', u'$windows.~ws', u'$sysreset', u'/recovery/',
                u'system volume information', u'$recycle.bin')


class Radice(object):

    def __init__(self, origine, prefisso, volume, piatta=False):
        self.origine = origine
        self.prefisso = prefisso        # in minuscolo, con / finale
        self.volume = volume
        self.piatta = piatta            # True: nessuna struttura di cartelle riconosciuta
        self.unica = True               # e' l'unica radice dell'origine

    def descrizione(self):
        if self.piatta:
            return u'file sparsi (nessuna cartella Windows riconosciuta)'
        return self.prefisso

    def file(self, cartella, nome=u'%', sotto=False, cancellati=False, cartelle=False,
             ovunque=False, tutti_i_volumi=False, estensioni=None):
        """Cerca nella radice.
        cartella: percorso relativo alla radice, minuscolo, con / finale e
                  senza / iniziale ('windows/prefetch/'); puo' contenere %.
                  La stringa vuota indica la cartella radice del volume.
                  Puo' essere una lista di (cartella, sotto) per cercare in
                  piu' posti con una sola interrogazione.
        nome:     modello del nome, minuscolo, con % come jolly.
        sotto:    anche nelle sottocartelle, a qualunque profondita'.
        ovunque:  se la radice e' 'piatta' cerca il nome in tutta l'origine.
        tutti_i_volumi: non limitare la ricerca al volume di Windows.
        estensioni: solo i file con una di queste estensioni."""
        if self.piatta:
            if not ovunque:
                return []
            return self.origine.cerca(u'%', nome, cancellati, cartelle, estensioni)
        if isinstance(cartella, (list, tuple)):
            code = [c + (u'%' if s else u'') for c, s in cartella]
        else:
            code = [cartella + (u'%' if sotto else u'')]
        modelli = [(u'%/' + coda) if coda and not coda.startswith(u'%') else (coda or u'%') for coda in code]
        modelli = [m if m != u'%%' else u'%' for m in modelli]
        trovati = self.origine.cerca(modelli if len(modelli) > 1 else modelli[0], nome, cancellati, cartelle, estensioni)
        if tutti_i_volumi and self.unica:
            return trovati
        esatti = [modello_a_regex(self.prefisso.replace(u'%', u'\x00') + coda) for coda in code]
        buoni = []
        for e in trovati:
            if e.volume != self.volume:
                continue
            dove = e.cartella.lower().replace(u'%', u'\x00')
            for rx in esatti:
                if rx.match(dove) is not None:
                    buoni.append(e)
                    break
        return buoni

    def con_nome(self, frammenti, estensioni=None, cancellati=False):
        """I file della radice il cui nome contiene uno dei frammenti."""
        trovati = self.origine.cerca_frammenti(frammenti, estensioni, cancellati)
        if self.piatta or self.unica:
            return trovati
        return [e for e in trovati if e.volume == self.volume and e.cartella.lower().startswith(self.prefisso)]

    def uno(self, cartella, nome, ovunque=True):
        """Il file con quel nome in quella cartella (il piu' grande se ce n'e'
        piu' d'uno), oppure None."""
        trovati = self.file(cartella, nome, ovunque=ovunque)
        if not trovati:
            return None
        trovati.sort(key=lambda e: (-e.dimensione, len(e.cartella)))
        return trovati[0]

    def relativo(self, elemento):
        """Percorso dell'elemento come lo vedrebbe Windows (C:\\...)."""
        p = elemento.percorso
        if not self.piatta and p.lower().startswith(self.prefisso):
            if elemento.volume != self.volume:
                # un altro volume dell'immagine: la lettera non si conosce
                return u'[altro volume]' + p.replace(u'/', u'\\')
            p = p[len(self.prefisso):]
            return u'C:\\' + p.replace(u'/', u'\\')
        return p


def trova_radici(origine, massimo=6):
    """Cerca le installazioni di Windows nell'origine. Restituisce
    (radici, scartate): le scartate sono installazioni precedenti o copie
    (Windows.old e simili) che non vengono analizzate."""
    candidati = {}
    ancore = ((u'%/windows/system32/config/', u'system'),
              (u'%/windows/system32/config/', u'software'),
              (u'%/windows/system32/winevt/logs/', u'security.evtx'))
    falliti = 0
    for modello, nome in ancore:
        coda = modello[2:]
        try:
            trovati = origine.cerca(modello, nome)
        except ERRORI:
            falliti += 1
            if falliti == len(ancore):
                raise       # l'origine non risponde affatto: meglio dirlo che fingere che sia vuota
            trovati = []
        for e in trovati:
            c = e.cartella.lower()
            if not c.endswith(coda):
                continue
            prefisso = c[:len(c) - len(coda)]
            candidati[(e.volume, prefisso)] = True
    radici = []
    scartate = []
    chiavi = candidati.keys()
    chiavi.sort(key=lambda k: (len(k[1]), k[1], k[0]))
    for volume, prefisso in chiavi:
        scarta = False
        for s in _DA_SCARTARE:
            if s in prefisso:
                scarta = True
        if scarta or len(radici) >= massimo:
            scartate.append(prefisso)
            continue
        radici.append(Radice(origine, prefisso, volume))
    if not radici:
        radici.append(Radice(origine, u'', None, piatta=True))
    for r in radici:
        r.unica = len(radici) == 1
    return radici, scartate
