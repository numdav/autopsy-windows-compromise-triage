# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_registro - Lettore degli hive del registro di Windows (formato "regf")
in Python 2.7 puro, per il plugin "Triage compromissione" di Autopsy.

Uso:
    hive = Hive(dati, log=[dati_LOG1, dati_LOG2])      # contenuto dei file
    hive = hive_da_file(percorso, [percorso_LOG1, percorso_LOG2])
    chiave = hive.apri(u'Microsoft\\Windows\\CurrentVersion\\Run')
    for v in chiave.valori():
        v.nome, v.valore()
    for sotto in chiave.sottochiavi():
        sotto.nome, sotto.orario

Se l'hive e' "sporco" (la macchina non lo ha chiuso bene) e vengono passati
i transaction log .LOG1 e .LOG2 nel formato di Windows 8.1 e successivi, le
modifiche in sospeso vengono applicate in memoria prima della lettura.
"""

import struct

from tc_base import leggi, filetime_a_epoch, testo_sid, esadecimale, decodifica16, ERRORI
from tc_lingua import tr

BASE = 0x1000

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BE = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11


class ErroreRegistro(Exception):
    pass


class Valore(object):
    __slots__ = ('nome', 'tipo', 'dati')

    def __init__(self, nome, tipo, dati):
        self.nome = nome
        self.tipo = tipo
        self.dati = dati

    def valore(self):
        """Il dato nel tipo piu' naturale: testo, numero, lista o byte grezzi."""
        t = self.tipo
        d = self.dati
        if t == REG_SZ or t == REG_EXPAND_SZ or t == REG_LINK:
            return _testo16(d)
        if t == REG_DWORD:
            if len(d) >= 4:
                return leggi('<I', d, 0)[0]
            return 0
        if t == REG_DWORD_BE:
            if len(d) >= 4:
                return leggi('>I', d, 0)[0]
            return 0
        if t == REG_QWORD:
            if len(d) >= 8:
                return leggi('<Q', d, 0)[0]
            return 0
        if t == REG_MULTI_SZ:
            testo = decodifica16(d[:len(d) - len(d) % 2])
            parti = testo.split(u'\x00')
            while parti and parti[-1] == u'':
                parti.pop()
            return parti
        return d

    def testo(self):
        """Il dato come testo leggibile, qualunque sia il tipo."""
        v = self.valore()
        if isinstance(v, unicode):
            return v
        if isinstance(v, list):
            return u' | '.join(v)
        if isinstance(v, (int, long)):
            return unicode(v)
        if isinstance(v, str):
            return esadecimale(v, 64)
        return unicode(v)


def _testo16(d):
    d = d[:len(d) - len(d) % 2]
    testo = decodifica16(d)
    fine = testo.find(u'\x00')
    if fine >= 0:
        testo = testo[:fine]
    return testo


class Chiave(object):
    __slots__ = ('hive', 'pos', 'nome', 'orario', '_n_sotto', '_pos_sotto', '_n_valori',
                 '_pos_valori', '_pos_sicurezza')

    def __init__(self, hive, offset):
        b = hive.b
        p = hive._cella(offset)
        if b[p:p + 2] != 'nk':
            raise ErroreRegistro(tr(u'cella nk non valida a %x') % offset)
        self.hive = hive
        self.pos = offset
        flags, ft = leggi('<HQ', b, p + 2)
        (self._n_sotto, _, self._pos_sotto, _, self._n_valori, self._pos_valori,
         self._pos_sicurezza) = leggi('<7I', b, p + 20)
        lung = leggi('<H', b, p + 72)[0]
        grezzo = b[p + 76: p + 76 + lung]
        if flags & 0x20:
            self.nome = grezzo.decode('latin-1')
        else:
            self.nome = decodifica16(grezzo)
        self.orario = filetime_a_epoch(ft)

    # ---- sottochiavi ----------------------------------------------------

    def _posizioni_sottochiavi(self):
        if self._n_sotto == 0 or self._pos_sotto == 0xFFFFFFFF:
            return []
        risultato = []
        try:
            self.hive._lista_sottochiavi(self._pos_sotto, risultato, 0, set())
        except ERRORI:
            # lista danneggiata: restano le sottochiavi lette fin qui
            self.hive.danneggiate.add(self._pos_sotto)
        return risultato

    def numero_sottochiavi(self):
        return self._n_sotto

    def sottochiavi(self):
        for pos in self._posizioni_sottochiavi():
            try:
                k = Chiave(self.hive, pos)
            except ERRORI:
                self.hive.danneggiate.add(pos)
                continue
            yield k

    def sottochiave(self, nome):
        cercato = nome.lower()
        for pos in self._posizioni_sottochiavi():
            try:
                k = Chiave(self.hive, pos)
            except ERRORI:
                self.hive.danneggiate.add(pos)
                continue
            if k.nome.lower() == cercato:
                return k
        return None

    def apri(self, percorso):
        """Scende lungo un percorso relativo ('A\\B\\C'). None se non esiste."""
        k = self
        for parte in percorso.replace(u'/', u'\\').split(u'\\'):
            if not parte:
                continue
            k = k.sottochiave(parte)
            if k is None:
                return None
        return k

    def discendenti(self, massimo=20000):
        """Tutte le chiavi sotto questa, con il percorso relativo."""
        coda = [(self, u'')]
        visti = 0
        while coda:
            k, percorso = coda.pop()
            for s in k.sottochiavi():
                p = percorso + u'\\' + s.nome if percorso else s.nome
                yield s, p
                visti += 1
                if visti >= massimo:
                    return
                if s._n_sotto:
                    coda.append((s, p))

    # ---- valori ---------------------------------------------------------

    def valori(self):
        risultato = []
        n = self._n_valori
        if n == 0 or self._pos_valori == 0xFFFFFFFF or n > 100000:
            return risultato
        h = self.hive
        b = h.b
        try:
            p = h._cella(self._pos_valori)
            posizioni = leggi('<%dI' % n, b, p)
        except ERRORI:
            h.danneggiate.add(self._pos_valori)
            return risultato
        for pos in posizioni:
            try:
                risultato.append(h._valore(pos))
            except ERRORI:
                h.danneggiate.add(pos)
                continue
        return risultato

    def valore(self, nome):
        cercato = nome.lower()
        for v in self.valori():
            if v.nome.lower() == cercato:
                return v
        return None

    def dato(self, nome, predefinito=None):
        """Scorciatoia: il valore decodificato, o il predefinito se manca."""
        v = self.valore(nome)
        if v is None:
            return predefinito
        try:
            return v.valore()
        except ERRORI:
            return predefinito

    # ---- sicurezza ------------------------------------------------------

    def ace(self):
        """Le voci della DACL della chiave: lista di (tipo, maschera, sid)
        dove tipo e' 'consenti' o 'nega'."""
        h = self.hive
        b = h.b
        risultato = []
        if self._pos_sicurezza == 0xFFFFFFFF:
            return risultato
        try:
            p = h._cella(self._pos_sicurezza)
            if b[p:p + 2] != 'sk':
                return risultato
            dim = leggi('<I', b, p + 16)[0]
            sd = p + 20
            controllo, _, _, _, pos_dacl = leggi('<HIIII', b, sd + 2)
            if not (controllo & 0x0004) or pos_dacl == 0 or pos_dacl >= dim:
                return risultato
            a = sd + pos_dacl
            quante = leggi('<H', b, a + 4)[0]
            q = a + 8
            for _ in xrange(min(quante, 200)):
                tipo, _, lung, maschera = leggi('<BBHI', b, q)
                if lung < 8:
                    break
                if tipo in (0, 1):
                    sid, _ = testo_sid(b, q + 8)
                    risultato.append((u'nega' if tipo == 1 else u'consenti', maschera, sid))
                q += lung
        except ERRORI:
            pass
        return risultato


class Hive(object):
    """Un hive caricato in memoria."""

    def __init__(self, dati, log=None):
        """dati: il contenuto del file dell'hive. log: lista con il contenuto
        dei transaction log (.LOG1, .LOG2), usati solo se l'hive e' sporco."""
        if len(dati) < BASE + 32 or dati[:4] != 'regf':
            raise ErroreRegistro(tr(u'non \u00e8 un hive del registro'))
        self.b = dati
        self.seq1, self.seq2 = leggi('<II', dati, 4)
        self.pos_radice = leggi('<I', dati, 0x24)[0]
        self.dim_dati = leggi('<I', dati, 0x28)[0]
        self.versione_minore = leggi('<I', dati, 0x18)[0]
        self.orario = filetime_a_epoch(leggi('<Q', dati, 0x0C)[0])
        self.sporco = self.seq1 != self.seq2
        self.log_applicati = 0
        # posizioni delle celle che i controlli hanno trovato rovinate: se
        # non e' vuoto, l'hive e' danneggiato e qualcosa non e' stato letto
        self.danneggiate = set()
        self._blocchi = None
        if self.sporco and log:
            try:
                self._applica_log(log)
            except ERRORI:
                pass

    # ---- accesso alle celle ---------------------------------------------

    def _cella(self, offset):
        """Posizione nel file dei dati di una cella (dopo i 4 byte di dimensione)."""
        p = BASE + offset
        if offset == 0xFFFFFFFF or p + 4 > len(self.b):
            raise ErroreRegistro(tr(u'offset fuori dal file: %x') % offset)
        return p + 4

    def _dim_cella(self, offset):
        return abs(leggi('<i', self.b, BASE + offset)[0]) - 4

    def _lista_sottochiavi(self, offset, risultato, livello, viste):
        # 'viste' sono le liste gia' percorse: in un hive costruito apposta
        # una lista puo' indicare se stessa, e senza questo controllo la
        # lettura non finirebbe mai. Nessuna chiave vera ha un milione di
        # sottochiavi.
        if livello > 4 or offset in viste or len(viste) > 100000 or len(risultato) > 1000000:
            return
        viste.add(offset)
        b = self.b
        p = self._cella(offset)
        firma = b[p:p + 2]
        n = leggi('<H', b, p + 2)[0]
        if firma == 'lf' or firma == 'lh':
            dati = leggi('<%dI' % (n * 2), b, p + 4)
            risultato.extend(dati[0::2])
        elif firma == 'li':
            risultato.extend(leggi('<%dI' % n, b, p + 4))
        elif firma == 'ri':
            for sub in leggi('<%dI' % n, b, p + 4):
                try:
                    self._lista_sottochiavi(sub, risultato, livello + 1, viste)
                except ERRORI:
                    self.danneggiate.add(sub)
                    continue
        else:
            raise ErroreRegistro(tr(u'lista di sottochiavi non riconosciuta'))

    def blocchi(self):
        """Controlla la struttura dell'hive senza leggerne le chiavi: (numero
        di blocchi 'hbin' attesi, quanti sono rovinati o mancanti). Un hive
        sano ne ha zero di rovinati; un file troncato, azzerato in parte o
        sovrascritto no. Costa poco: un'intestazione ogni 4 KB o piu'."""
        if self._blocchi is None:
            b = self.b
            fine = BASE + self.dim_dati
            totale = 0
            rovinati = 0
            p = BASE
            while p < fine and totale < 4000000:
                totale += 1
                dim = 0
                if p + 32 <= len(b) and b[p:p + 4] == 'hbin':
                    dim = leggi('<I', b, p + 8)[0]
                if dim < 4096 or dim % 4096 or dim > 0x40000000:
                    rovinati += 1
                    p += 4096
                else:
                    p += dim
            self._blocchi = (totale, rovinati)
        return self._blocchi

    def _valore(self, offset):
        b = self.b
        p = self._cella(offset)
        if b[p:p + 2] != 'vk':
            raise ErroreRegistro(tr(u'cella vk non valida'))
        lung_nome, dim, pos_dati, tipo, flags = leggi('<HIIIH', b, p + 2)
        grezzo = b[p + 20: p + 20 + lung_nome]
        if flags & 1:
            nome = grezzo.decode('latin-1')
        else:
            nome = decodifica16(grezzo)
        if dim & 0x80000000:
            dim &= 0x7FFFFFFF
            dati = struct.pack('<I', pos_dati)[:min(dim, 4)]
        elif dim == 0 or pos_dati == 0xFFFFFFFF:
            dati = ''
        else:
            q = self._cella(pos_dati)
            if dim > 16344 and b[q:q + 2] == 'db':
                dati = self._dati_grandi(q, dim)
            else:
                dati = b[q: q + dim]
        return Valore(nome, tipo, dati)

    def _dati_grandi(self, q, dim):
        b = self.b
        n, pos_lista = leggi('<HI', b, q + 2)
        l = self._cella(pos_lista)
        pezzi = []
        resto = dim
        for pos in leggi('<%dI' % n, b, l):
            s = self._cella(pos)
            quanto = min(resto, 16344)
            pezzi.append(b[s: s + quanto])
            resto -= quanto
            if resto <= 0:
                break
        return ''.join(pezzi)

    # ---- navigazione -----------------------------------------------------

    def radice(self):
        return Chiave(self, self.pos_radice)

    def apri(self, percorso):
        try:
            return self.radice().apri(percorso)
        except ERRORI:
            return None

    # ---- transaction log (formato nuovo, da Windows 8.1) ----------------

    def _applica_log(self, contenuti):
        """Applica le voci dei transaction log (formato HvLE).
        In ogni file le voci valide hanno numeri di sequenza consecutivi: la
        prima che rompe la sequenza e' un residuo vecchio e chiude il file.
        Si applicano, in ordine, le voci con sequenza >= a quella dell'hive."""
        catene = []
        for d in contenuti:
            if not d:
                continue
            if len(d) < 512 + 40 or d[:4] != 'regf':
                continue
            p = 512
            voci = []
            atteso = None
            while p + 40 <= len(d) and d[p:p + 4] == 'HvLE':
                dim, _, seq, dim_dati, n_pagine = leggi('<5I', d, p + 4)
                if dim < 40 or p + dim > len(d) or n_pagine > 1000000:
                    break
                if atteso is not None and seq != atteso:
                    break
                voci.append((seq, d, p, dim, dim_dati, n_pagine))
                atteso = seq + 1
                p += dim
            if voci:
                catene.append(voci)
        if not catene:
            return
        catene.sort(key=lambda voci: voci[0][0])
        dati = None
        atteso = None
        # Le pagine arrivano dai log: l'hive non puo' crescere piu' di quanto
        # i log contengono. Senza questo limite una posizione inventata in un
        # log costruito apposta farebbe allocare gigabyte di memoria.
        massimo = len(self.b) + sum([len(x) for x in contenuti if x]) + 1024 * 1024
        for voci in catene:
            for seq, d, p, dim, dim_dati, n_pagine in voci:
                if seq < self.seq2:
                    continue
                if atteso is not None and seq != atteso:
                    break
                if dati is None:
                    dati = bytearray(self.b)
                rif = p + 40
                q = rif + 8 * n_pagine
                valido = True
                for i in xrange(n_pagine):
                    pos, lung = leggi('<II', d, rif + 8 * i)
                    if q + lung > p + dim:
                        valido = False
                        break
                    fine = BASE + pos + lung
                    if fine > massimo:
                        valido = False
                        break
                    if fine > len(dati):
                        dati.extend('\x00' * (fine - len(dati)))
                    dati[BASE + pos: fine] = d[q: q + lung]
                    q += lung
                if not valido:
                    break
                if dim_dati > self.dim_dati:
                    self.dim_dati = dim_dati
                self.log_applicati += 1
                atteso = seq + 1
        if dati is not None and self.log_applicati:
            self.b = str(dati)


def _leggi_file(percorso):
    f = open(percorso, 'rb')
    try:
        return f.read()
    finally:
        f.close()


def hive_da_file(percorso, log=None):
    """Apre un hive dal disco locale (con i suoi transaction log, se indicati)."""
    contenuti = []
    for p in (log or []):
        try:
            contenuti.append(_leggi_file(p))
        except ERRORI:
            pass
    return Hive(_leggi_file(percorso), contenuti)
