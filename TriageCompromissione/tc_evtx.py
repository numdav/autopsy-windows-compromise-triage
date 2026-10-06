# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_evtx - Lettore dei registri eventi di Windows (.evtx) in Python 2.7 puro.

Fa parte del plugin "Triage compromissione" per Autopsy. Non usa librerie
esterne: gira nel Jython incluso in Autopsy.

Uso:
    log = FileEvtx(percorso)        # oppure un oggetto con dimensione e leggi()
    primo, ultimo, quanti = log.estremi()
    for ev in log.eventi(id_voluti=set([4624, 4625])):
        ev['EventID'], ev['Ora'], ev['Dati'].get('TargetUserName') ...

Ogni evento e' un dizionario con:
    EventID, Ora (secondi epoch UTC, float), Record, Provider, Canale,
    Computer, Livello, SidUtente, Dati (nome -> valore), Lista (valori
    senza nome, in ordine).

Il formato: un file .evtx e' fatto di blocchi ("chunk") da 64 KB. Ogni
record contiene XML binario: un modello (template) condiviso da tutti gli
eventi dello stesso tipo, piu' i valori da sostituire nel modello.
"""

import calendar
import time

from tc_base import leggi, filetime_a_epoch, testo_orario, orario_da_testo, testo_sid, decodifica16, ERRORI
from tc_lingua import tr

DIM_CHUNK = 65536
DIM_TESTATA = 4096


class ErroreEvtx(Exception):
    pass


class Tempo(float):
    """Un orario in secondi epoch UTC (serve a distinguerlo dai numeri)."""
    pass


class _Frammento(object):
    """Risultato di un valore di tipo XML binario annidato."""

    def __init__(self, elementi):
        self.elementi = elementi


class _Modello(object):
    """Un modello gia' analizzato: albero di nodi piu' dove trovare EventID."""

    def __init__(self, nodi):
        self.nodi = nodi
        self.indice_id = None      # indice della sostituzione che contiene EventID
        self.id_fisso = None       # oppure valore letterale
        self._cerca_id(nodi, 0)

    def _cerca_id(self, nodi, livello):
        for n in nodi:
            if n[0] != 'e':
                continue
            if n[1] == u'EventID':
                for f in n[3]:
                    if f[0] == 's':
                        self.indice_id = f[1]
                        return True
                    if f[0] == 't':
                        try:
                            self.id_fisso = int(f[1])
                        except ValueError:
                            pass
                        return True
                return True
            if livello < 3 and self._cerca_id(n[3], livello + 1):
                return True
        return False


_ENTITA = {u'amp': u'&', u'lt': u'<', u'gt': u'>', u'quot': u'"', u'apos': u"'"}


class _Chunk(object):
    """Analizza un blocco da 64 KB."""

    def __init__(self, dati, modelli_globali):
        self.b = dati
        self.nomi = {}
        self.modelli = {}
        self.modelli_globali = modelli_globali

    # ---- nomi -----------------------------------------------------------

    def _nome(self, pos_nome, pos_nodo):
        b = self.b
        r = self.nomi.get(pos_nome)
        if r is None:
            lung = leggi('<H', b, pos_nome + 6)[0]
            testo = decodifica16(b[pos_nome + 8: pos_nome + 8 + lung * 2])
            r = (testo, 10 + lung * 2)
            self.nomi[pos_nome] = r
        if pos_nome > pos_nodo:
            return r[0], r[1]
        return r[0], 0

    # ---- modelli --------------------------------------------------------

    def _modello(self, pos):
        m = self.modelli.get(pos)
        if m is not None:
            return m
        b = self.b
        chiave = b[pos + 4: pos + 24]
        m = self.modelli_globali.get(chiave)
        if m is None:
            p = pos + 24
            if ord(b[p]) & 0x0F == 0x0F:
                p += 4
            nodi, _ = self._contenuto(p)
            m = _Modello(nodi)
            if len(self.modelli_globali) < 4000:
                self.modelli_globali[chiave] = m
        self.modelli[pos] = m
        return m

    # ---- analisi dell'XML binario --------------------------------------

    def _parte(self, p):
        """Legge un token di valore. Restituisce (nodo, nuova posizione, altro)."""
        b = self.b
        t = ord(b[p])
        base = t & 0x0F
        altro = t & 0x40
        if base == 0x05:
            tipo = ord(b[p + 1])
            if tipo == 0x01:
                lung = leggi('<H', b, p + 2)[0]
                testo = decodifica16(b[p + 4: p + 4 + lung * 2])
                return ('t', testo), p + 4 + lung * 2, altro
            raise ErroreEvtx(tr(u'valore letterale di tipo %d non gestito') % tipo)
        if base == 0x0D or base == 0x0E:
            indice, tipo = leggi('<HB', b, p + 1)
            return ('s', indice, tipo, base == 0x0E), p + 4, altro
        if base == 0x08:
            codice = leggi('<H', b, p + 1)[0]
            return ('t', unichr(codice)), p + 3, altro
        if base == 0x09:
            pos_nome = leggi('<I', b, p + 1)[0]
            nome, lung = self._nome(pos_nome, p)
            return ('t', _ENTITA.get(nome, u'&' + nome + u';')), p + 5 + lung, altro
        if base == 0x07:
            lung = leggi('<H', b, p + 1)[0]
            testo = decodifica16(b[p + 3: p + 3 + lung * 2])
            return ('t', testo), p + 3 + lung * 2, altro
        raise ErroreEvtx(tr(u'token %02x non gestito') % t)

    def _elemento(self, p):
        b = self.b
        t = ord(b[p])
        con_attributi = t & 0x40
        pos_nome = leggi('<I', b, p + 7)[0]
        nome, lung = self._nome(pos_nome, p)
        q = p + 11 + lung
        if con_attributi:
            q += 4
        attributi = []
        while ord(b[q]) & 0x0F == 0x06:
            pos_nome = leggi('<I', b, q + 1)[0]
            nome_attr, lung = self._nome(pos_nome, q)
            q += 5 + lung
            parti = []
            while True:
                nodo, q, altro = self._parte(q)
                parti.append(nodo)
                if not altro:
                    break
            attributi.append((nome_attr, parti))
        t = ord(b[q])
        if t == 0x03:
            return ('e', nome, attributi, []), q + 1
        if t != 0x02:
            raise ErroreEvtx(tr(u'atteso fine apertura elemento, trovato %02x') % t)
        figli, q = self._contenuto(q + 1)
        return ('e', nome, attributi, figli), q

    def _contenuto(self, p):
        b = self.b
        figli = []
        while True:
            t = ord(b[p])
            base = t & 0x0F
            if base == 0x04 or base == 0x00:
                return figli, p + 1
            if base == 0x01:
                nodo, p = self._elemento(p)
                figli.append(nodo)
            elif base == 0x0F:
                p += 4
            elif base == 0x0C:
                # istanza di modello in mezzo al contenuto: la trattiamo come frammento
                fr, p = self._istanza(p)
                figli.append(('f', fr))
            else:
                nodo, p, _ = self._parte(p)
                figli.append(nodo)

    # ---- istanze e valori ----------------------------------------------

    def _istanza(self, p):
        """Legge un'istanza di modello a partire dal token 0x0C.
        Restituisce ((modello, descrittori, posizioni), posizione finale)."""
        b = self.b
        pos_modello = leggi('<I', b, p + 6)[0]
        q = p + 10
        if pos_modello == q:
            lung = leggi('<I', b, pos_modello + 20)[0]
            q = pos_modello + 24 + lung
        m = self._modello(pos_modello)
        n = leggi('<I', b, q)[0]
        q += 4
        if n > 2000:
            raise ErroreEvtx(tr(u'troppe sostituzioni: %d') % n)
        descr = leggi('<' + 'HBB' * n, b, q)
        q += 4 * n
        posizioni = []
        for i in xrange(n):
            posizioni.append(q)
            q += descr[i * 3]
        return (m, descr, posizioni), q

    def _valore(self, istanza, indice):
        m, descr, posizioni = istanza
        if indice * 3 >= len(descr):
            return None
        dim = descr[indice * 3]
        tipo = descr[indice * 3 + 1]
        return self._decodifica(posizioni[indice], dim, tipo)

    def _decodifica(self, pos, dim, tipo):
        b = self.b
        if tipo == 0x00:
            return None
        if tipo == 0x01:
            return decodifica16(b[pos: pos + dim]).rstrip(u'\x00')
        if tipo == 0x02:
            return b[pos: pos + dim].decode('cp1252', 'replace').rstrip(u'\x00')
        if dim == 0:
            return None
        if tipo == 0x04:
            return ord(b[pos])
        if tipo == 0x03:
            return leggi('<b', b, pos)[0]
        if tipo == 0x06:
            return leggi('<H', b, pos)[0]
        if tipo == 0x05:
            return leggi('<h', b, pos)[0]
        if tipo == 0x08:
            return leggi('<I', b, pos)[0]
        if tipo == 0x07:
            return leggi('<i', b, pos)[0]
        if tipo == 0x0A:
            return leggi('<Q', b, pos)[0]
        if tipo == 0x09:
            return leggi('<q', b, pos)[0]
        if tipo == 0x0B:
            return leggi('<f', b, pos)[0]
        if tipo == 0x0C:
            return leggi('<d', b, pos)[0]
        if tipo == 0x0D:
            return leggi('<i', b, pos)[0] != 0
        if tipo == 0x0E:
            return u''.join([u'%02X' % ord(c) for c in b[pos: pos + dim]])
        if tipo == 0x0F:
            return _guid(b, pos)
        if tipo == 0x10:
            if dim == 4:
                return u'0x%x' % leggi('<I', b, pos)[0]
            return u'0x%x' % leggi('<Q', b, pos)[0]
        if tipo == 0x11:
            return Tempo(filetime_a_epoch(leggi('<Q', b, pos)[0]))
        if tipo == 0x12:
            a, me, _, g, h, mi, s, ms = leggi('<8H', b, pos)
            try:
                return Tempo(calendar.timegm((a, me, g, h, mi, s, 0, 0, 0)) + ms / 1000.0)
            except ERRORI:
                return None
        if tipo == 0x13:
            return _sid(b, pos, dim)
        if tipo == 0x14:
            return u'0x%x' % leggi('<I', b, pos)[0]
        if tipo == 0x15:
            return u'0x%x' % leggi('<Q', b, pos)[0]
        if tipo == 0x21:
            return self._frammento(pos, pos + dim)
        if tipo == 0x81:
            testo = decodifica16(b[pos: pos + dim])
            parti = testo.split(u'\x00')
            if parti and parti[-1] == u'':
                parti.pop()
            return parti
        if tipo & 0x80:
            base = tipo & 0x7F
            passo = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8,
                     0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4, 0x0F: 16, 0x11: 8, 0x12: 16,
                     0x14: 4, 0x15: 8}.get(base)
            if not passo:
                return u''.join([u'%02X' % ord(c) for c in b[pos: pos + dim]])
            return [self._decodifica(pos + i, passo, base) for i in xrange(0, dim - passo + 1, passo)]
        return u''.join([u'%02X' % ord(c) for c in b[pos: pos + dim]])

    def _frammento(self, p, fine):
        """Un valore XML binario annidato: restituisce gli elementi risolti."""
        b = self.b
        elementi = []
        while p < fine:
            t = ord(b[p])
            base = t & 0x0F
            if base == 0x0F:
                p += 4
            elif base == 0x0C:
                istanza, p = self._istanza(p)
                elementi.extend(self._risolvi_nodi(istanza[0].nodi, istanza))
            elif base == 0x01:
                nodo, p = self._elemento(p)
                elementi.extend(self._risolvi_nodi([nodo], None))
            elif base == 0x00:
                break
            else:
                break
        return _Frammento(elementi)

    # ---- dal modello all'evento -----------------------------------------

    def _testo_parti(self, parti, istanza):
        """Valore di una lista di parti (letterali e sostituzioni).
        Con una parte sola restituisce il valore cosi' com'e' (numero,
        orario, testo); con piu' parti le unisce in un testo."""
        pezzi = []
        for n in parti:
            if n[0] == 't':
                pezzi.append(n[1])
            elif n[0] == 's':
                if istanza is None:
                    continue
                v = self._valore(istanza, n[1])
                if v is None:
                    continue
                pezzi.append(v)
        if not pezzi:
            return None
        if len(pezzi) == 1:
            return pezzi[0]
        return u''.join([_stringa(x) for x in pezzi])

    def _risolvi_nodi(self, nodi, istanza):
        """Trasforma i nodi del modello in elementi risolti:
        (nome, attributi dict, figli list, valori list)."""
        risultato = []
        for n in nodi:
            tipo = n[0]
            if tipo == 'e':
                attributi = {}
                for nome_attr, parti in n[2]:
                    v = self._testo_parti(parti, istanza)
                    if v is not None:
                        attributi[nome_attr] = v
                figli = []
                valori = []
                for f in n[3]:
                    k = f[0]
                    if k == 'e':
                        figli.extend(self._risolvi_nodi([f], istanza))
                    elif k == 't':
                        valori.append(f[1])
                    elif k == 's':
                        if istanza is None:
                            continue
                        v = self._valore(istanza, f[1])
                        if v is None:
                            continue
                        if isinstance(v, _Frammento):
                            figli.extend(v.elementi)
                        else:
                            valori.append(v)
                    elif k == 'f':
                        figli.extend(self._risolvi_nodi(f[1][0].nodi, f[1]))
                risultato.append((n[1], attributi, figli, valori))
            elif tipo == 'f':
                risultato.extend(self._risolvi_nodi(n[1][0].nodi, n[1]))
        return risultato

    def id_evento(self, istanza):
        m = istanza[0]
        if m.indice_id is not None:
            v = self._valore(istanza, m.indice_id)
            if isinstance(v, (int, long)):
                return v
            try:
                return int(v)
            except ERRORI:
                return None
        return m.id_fisso

    def evento(self, istanza):
        elementi = self._risolvi_nodi(istanza[0].nodi, istanza)
        ev = {'EventID': None, 'Ora': 0.0, 'Record': None, 'Provider': u'', 'Canale': u'',
              'Computer': u'', 'Livello': None, 'SidUtente': u'', 'Dati': {}, 'Lista': []}
        for radice in elementi:
            if radice[0] != u'Event':
                continue
            for sezione in radice[2]:
                nome = sezione[0]
                if nome == u'System':
                    _leggi_system(sezione, ev)
                elif nome == u'EventData':
                    _leggi_eventdata(sezione, ev)
                elif nome == u'UserData':
                    _appiattisci(sezione, ev['Dati'], 0)
        return ev


def _guid(b, pos):
    d1, d2, d3 = leggi('<IHH', b, pos)
    resto = b[pos + 8: pos + 16]
    return u'{%08X-%04X-%04X-%s-%s}' % (
        d1, d2, d3,
        u''.join([u'%02X' % ord(c) for c in resto[:2]]),
        u''.join([u'%02X' % ord(c) for c in resto[2:]]))


def _sid(b, pos, dim):
    if dim < 8:
        return u''
    try:
        return testo_sid(b, pos)[0]
    except ERRORI:
        return u''


def _stringa(v):
    if isinstance(v, unicode):
        return v
    if isinstance(v, Tempo):
        return testo_orario(v)
    if isinstance(v, bool):
        return u'true' if v else u'false'
    if isinstance(v, list):
        return u', '.join([_stringa(x) for x in v])
    if isinstance(v, str):
        return v.decode('latin-1')
    return unicode(v)


def _primo(valori):
    if not valori:
        return None
    if len(valori) == 1:
        return valori[0]
    return u''.join([_stringa(v) for v in valori])


def _leggi_system(sezione, ev):
    for el in sezione[2]:
        nome = el[0]
        v = _primo(el[3])
        if nome == u'EventID':
            try:
                ev['EventID'] = int(v)
            except ERRORI:
                ev['EventID'] = None
        elif nome == u'Provider':
            ev['Provider'] = _stringa(el[1].get(u'Name') or el[1].get(u'EventSourceName') or u'')
        elif nome == u'TimeCreated':
            t = el[1].get(u'SystemTime')
            if isinstance(t, Tempo):
                ev['Ora'] = float(t)
            elif t:
                ev['Ora'] = orario_da_testo(_stringa(t))
        elif nome == u'EventRecordID':
            try:
                ev['Record'] = int(v)
            except ERRORI:
                pass
        elif nome == u'Channel':
            ev['Canale'] = _stringa(v) if v is not None else u''
        elif nome == u'Computer':
            ev['Computer'] = _stringa(v) if v is not None else u''
        elif nome == u'Level':
            ev['Livello'] = v
        elif nome == u'Security':
            ev['SidUtente'] = _stringa(el[1].get(u'UserID') or u'')


def _leggi_eventdata(sezione, ev):
    dati = ev['Dati']
    lista = ev['Lista']
    for el in sezione[2]:
        nome = el[1].get(u'Name')
        valori = el[3]
        if el[0] == u'Data':
            if nome:
                v = _primo(valori)
                if nome not in dati:
                    dati[nome] = _stringa(v) if v is not None else u''
            else:
                for v in valori:
                    if isinstance(v, list):
                        for x in v:
                            lista.append(_stringa(x))
                    else:
                        lista.append(_stringa(v))
                if not valori:
                    lista.append(u'')
                if el[2]:
                    # <Data><string>..</string></Data>
                    for f in el[2]:
                        v = _primo(f[3])
                        lista.append(_stringa(v) if v is not None else u'')
        elif el[0] == u'Binary':
            v = _primo(valori)
            if v is not None:
                dati[u'Binary'] = _stringa(v)
        else:
            _appiattisci(el, dati, 0)


def _appiattisci(el, dati, livello):
    """Per UserData: ogni elemento foglia diventa nome -> testo."""
    if livello > 6:
        return
    for f in el[2]:
        if f[2]:
            _appiattisci(f, dati, livello + 1)
        else:
            v = _primo(f[3])
            if f[0] not in dati:
                dati[f[0]] = _stringa(v) if v is not None else u''
        for nome_attr, v in f[1].items():
            if nome_attr != u'xmlns' and (f[0] + u'@' + nome_attr) not in dati:
                dati[f[0] + u'@' + nome_attr] = _stringa(v)


class LettoreLocale(object):
    """Legge un file dal disco locale a pezzi."""

    def __init__(self, percorso):
        self.percorso = percorso
        f = open(percorso, 'rb')
        try:
            f.seek(0, 2)
            self.dimensione = f.tell()
        finally:
            f.close()
        self._f = None

    def leggi(self, posizione, quanti):
        if self._f is None:
            self._f = open(self.percorso, 'rb')
        self._f.seek(posizione)
        return self._f.read(quanti)

    def chiudi(self):
        if self._f is not None:
            try:
                self._f.close()
            except ERRORI:
                pass
            self._f = None


class FileEvtx(object):
    """Un registro eventi. 'sorgente' e' un percorso sul disco locale oppure
    un oggetto con l'attributo 'dimensione' e il metodo leggi(posizione,
    quanti), cosi' il file puo' essere letto direttamente dall'immagine."""

    def __init__(self, sorgente):
        if isinstance(sorgente, basestring):
            sorgente = LettoreLocale(sorgente)
        self.sorgente = sorgente
        self.errori = 0         # record trovati ma non decodificati
        self.letti = 0          # eventi restituiti
        self.visti = 0          # record percorsi (anche quelli che non interessavano)
        self.persi = 0          # record dichiarati dai blocchi ma non trovati: blocco rovinato
        self.blocchi_non_letti = 0      # blocchi da 64 KB la cui lettura e' fallita
        self.blocchi_danneggiati = 0    # blocchi che contengono dati ma non un'intestazione valida
        self.fuori_scala = 0    # orari impossibili (oltre domani), non usati per primo e ultimo
        self.primo = None       # orario del record piu' vecchio (dopo eventi() o estremi())
        self.ultimo = None      # orario del record piu' recente
        self.ultimo_scritto = None      # orario del record scritto per ultimo (numero piu' alto)
        self._numero_massimo = -1
        self._limite = time.time() + 86400.0
        self.record = 0         # numero di record dichiarati dalle intestazioni dei blocchi
        self.dimensione = sorgente.dimensione
        testa = sorgente.leggi(0, DIM_TESTATA)
        if len(testa) < 128 or testa[:8] != 'ElfFile\x00':
            self.chiudi()
            raise ErroreEvtx(tr(u'non \u00e8 un file evtx'))
        self.numero_chunk = max(0, (self.dimensione - DIM_TESTATA) // DIM_CHUNK)

    def chiudi(self):
        chiudi = getattr(self.sorgente, 'chiudi', None)
        if chiudi is not None:
            chiudi()

    def _chunk(self, indice):
        try:
            dati = self.sorgente.leggi(DIM_TESTATA + indice * DIM_CHUNK, DIM_CHUNK)
        except ERRORI:
            # settore danneggiato: si salta il blocco e si prosegue con gli altri
            self.blocchi_non_letti += 1
            return None
        if len(dati) < 512 or dati[:8] != 'ElfChnk\x00':
            # un blocco mai usato e' tutto a zero; se invece contiene dati
            # ma non l'intestazione, e' stato rovinato o sovrascritto
            if dati.strip('\x00'):
                self.blocchi_danneggiati += 1
            return None
        return dati

    def _estremi_chunk(self, testa, leggi_record):
        """Dall'intestazione di un chunk: (primo orario, ultimo orario,
        numero di record) oppure None se il chunk e' vuoto."""
        n1, n2 = leggi('<qq', testa, 8)
        pos_ultimo, pos_libero = leggi('<II', testa, 44)
        if pos_libero <= 512 or n1 < 0 or n2 < n1:
            return None
        primo = leggi_record(512)
        if primo is None:
            return None
        ultimo = primo
        if 512 < pos_ultimo < DIM_CHUNK - 24:
            t = leggi_record(pos_ultimo)
            if t is not None:
                ultimo = t
        quanti = int(n2 - n1 + 1)
        if quanti > DIM_CHUNK // 24:
            quanti = 0          # intestazione danneggiata: in 64 KB non ci stanno
        return primo, ultimo, quanti

    def _aggiorna_estremi(self, e):
        if e is None:
            return
        self.record += e[2]
        for t in (e[0], e[1]):
            if t <= 0:
                continue
            if t > self._limite:
                # una data nel futuro (orologio sbagliato o record alterato)
                # non deve allungare il periodo coperto dal registro
                self.fuori_scala += 1
                continue
            if self.primo is None or t < self.primo:
                self.primo = t
            if self.ultimo is None or t > self.ultimo:
                self.ultimo = t

    def _scritto(self, numero, orario):
        """Tiene l'orario del record scritto per ultimo: quello con il
        numero piu' alto, che non e' per forza quello con la data piu'
        recente (l'orologio puo' essere stato spostato)."""
        if numero > self._numero_massimo and 0 < orario <= self._limite:
            self._numero_massimo = numero
            self.ultimo_scritto = orario

    @staticmethod
    def _riprendi(dati, p, fine):
        """Dopo un record rovinato cerca nello stesso blocco il prossimo
        record integro (firma, dimensione credibile e uguale alla copia che
        chiude il record). Restituisce la sua posizione, oppure -1."""
        q = dati.find('\x2a\x2a\x00\x00', p + 1, fine)
        while 0 <= q and q + 28 <= fine:
            dim = leggi('<I', dati, q + 4)[0]
            if 28 <= dim <= DIM_CHUNK - q and leggi('<I', dati, q + dim - 4)[0] == dim:
                return q
            q = dati.find('\x2a\x2a\x00\x00', q + 1, fine)
        return -1

    def estremi(self):
        """(orario del record piu' vecchio, del piu' recente, numero di
        record), letti dalle intestazioni dei chunk senza analizzare gli
        eventi."""
        self.primo = None
        self.ultimo = None
        self.record = 0
        try:
            for i in xrange(self.numero_chunk):
                base = DIM_TESTATA + i * DIM_CHUNK
                testa = self.sorgente.leggi(base, 512 + 24)
                if len(testa) < 512 + 24 or testa[:8] != 'ElfChnk\x00':
                    continue

                def leggi_record(pos, base=base, testa=testa):
                    if pos == 512:
                        r = testa[512:536]
                    else:
                        r = self.sorgente.leggi(base + pos, 24)
                    if len(r) < 24 or r[:4] != '\x2a\x2a\x00\x00':
                        return None
                    return filetime_a_epoch(leggi('<Q', r, 16)[0])

                e = self._estremi_chunk(testa, leggi_record)
                self._aggiorna_estremi(e)
                if e is not None:
                    self._scritto(leggi('<q', testa, 16)[0], e[1])
        finally:
            self.chiudi()
        return self.primo, self.ultimo, self.record

    def eventi(self, id_voluti=None, annullato=None, filtro=None):
        """Genera gli eventi del file. Con id_voluti (un insieme di EventID)
        salta in fretta tutti gli altri. 'annullato' e' una funzione che,
        se restituisce True, interrompe la lettura. 'filtro', se indicato, e'
        una funzione (EventID, dati del blocco, posizione e dimensione del
        record) chiamata prima di decodificare l'evento: se restituisce False
        l'evento viene saltato. Serve a non decodificare milioni di eventi
        dei quali ne interessano pochi."""
        modelli_globali = {}
        self.primo = None
        self.ultimo = None
        self.record = 0
        try:
            for i in xrange(self.numero_chunk):
                if annullato is not None and annullato():
                    return
                dati = self._chunk(i)
                if dati is None:
                    continue

                def leggi_record(pos, dati=dati):
                    r = dati[pos:pos + 24]
                    if len(r) < 24 or r[:4] != '\x2a\x2a\x00\x00':
                        return None
                    return filetime_a_epoch(leggi('<Q', r, 16)[0])

                estremi = self._estremi_chunk(dati, leggi_record)
                self._aggiorna_estremi(estremi)
                attesi = estremi[2] if estremi is not None else 0
                percorsi = 0
                c = _Chunk(dati, modelli_globali)
                fine = leggi('<I', dati, 48)[0]
                if fine < 512 or fine > DIM_CHUNK:
                    fine = DIM_CHUNK
                p = 512
                while p + 28 <= fine:
                    dim = 0
                    if dati[p:p + 4] == '\x2a\x2a\x00\x00':
                        dim, numero, scritto = leggi('<IQQ', dati, p + 4)
                    if dim < 28 or p + dim > DIM_CHUNK:
                        # record rovinato: si riprende dal prossimo record
                        # integro del blocco, invece di perdere tutti gli altri
                        p = self._riprendi(dati, p, fine)
                        if p < 0:
                            break
                        continue
                    percorsi += 1
                    self._scritto(numero, filetime_a_epoch(scritto))
                    try:
                        q = p + 24
                        if ord(dati[q]) & 0x0F == 0x0F:
                            q += 4
                        if ord(dati[q]) == 0x0C:
                            istanza, _ = c._istanza(q)
                            ident = c.id_evento(istanza)
                            if (id_voluti is None or ident in id_voluti) and \
                                    (filtro is None or filtro(ident, dati, p, dim)):
                                ev = c.evento(istanza)
                                if ev['EventID'] is None:
                                    ev['EventID'] = ident
                                if not ev['Ora']:
                                    ev['Ora'] = filetime_a_epoch(scritto)
                                if ev['Record'] is None:
                                    ev['Record'] = int(numero)
                                self.letti += 1
                                yield ev
                        else:
                            self.errori += 1
                    except ERRORI:
                        self.errori += 1
                    p += dim
                self.visti += percorsi
                if attesi > percorsi:
                    self.persi += attesi - percorsi
        finally:
            self.chiudi()
