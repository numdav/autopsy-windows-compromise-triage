# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_prefetch - Lettore dei file Prefetch (.pf) in Python 2.7 puro, per il
plugin "Triage compromissione" di Autopsy.

Da Windows 8.1 i .pf sono compressi (intestazione "MAM", algoritmo Xpress
Huffman): qui vengono decompressi senza strumenti esterni.

Uso:
    pf = Prefetch(dati)              # dati = contenuto del file .pf
    pf.eseguibile     nome dell'eseguibile (dall'intestazione)
    pf.percorso       percorso completo dell'eseguibile, se trovato
    pf.esecuzioni     numero di esecuzioni
    pf.ultime         orari (epoch UTC) delle ultime esecuzioni, dal piu' recente
    pf.file           elenco dei file caricati nei primi secondi
"""

import struct

from tc_base import leggi, filetime_a_epoch, decodifica16
from tc_lingua import tr


class ErrorePrefetch(Exception):
    pass


def decomprimi_xpress_huffman(dati, dim_uscita, limite=None):
    """Decompressione Xpress Huffman (MS-XCA). 'limite' ferma la
    decompressione dopo quel numero di byte in uscita (basta per leggere
    l'inizio del file).

    Con dati rovinati o costruiti apposta non deve poter lavorare a vuoto:
    si ferma quando i dati compressi sono finiti, non scrive mai oltre la
    dimensione dichiarata e rifiuta i codici che la tabella non prevede."""
    ingresso = bytearray(dati)
    n_ingresso = len(ingresso)
    uscita = bytearray()
    if limite is None or limite > dim_uscita:
        limite = dim_uscita
    pos = 0
    while len(uscita) < limite:
        if pos + 256 > n_ingresso:
            break
        # tabella di decodifica: 512 simboli, lunghezza in 4 bit ciascuno
        lunghezze = [0] * 512
        per_lunghezza = [[] for _ in xrange(16)]
        for i in xrange(256):
            b = ingresso[pos + i]
            l1 = b & 15
            l2 = b >> 4
            if l1:
                lunghezze[2 * i] = l1
                per_lunghezza[l1].append(2 * i)
            if l2:
                lunghezze[2 * i + 1] = l2
                per_lunghezza[l2].append(2 * i + 1)
        tabella = [-1] * 32768      # -1: codice non assegnato
        indice = 0
        for l in xrange(1, 16):
            ripeti = 1 << (15 - l)
            for simbolo in per_lunghezza[l]:
                if indice + ripeti > 32768:
                    raise ErrorePrefetch(tr(u'tabella di Huffman non valida'))
                tabella[indice:indice + ripeti] = [simbolo] * ripeti
                indice += ripeti
        pos += 256
        if pos + 4 > n_ingresso:
            break
        bit = ((ingresso[pos] | (ingresso[pos + 1] << 8)) << 16) | ingresso[pos + 2] | (ingresso[pos + 3] << 8)
        pos += 4
        extra = 16
        fine_blocco = len(uscita) + 65536
        if fine_blocco > dim_uscita:
            fine_blocco = dim_uscita
        aggiungi = uscita.append
        while len(uscita) < fine_blocco:
            simbolo = tabella[bit >> 17]
            if simbolo < 0:
                raise ErrorePrefetch(tr(u'codice di Huffman non previsto dalla tabella'))
            l = lunghezze[simbolo]
            bit = (bit << l) & 0xFFFFFFFF
            extra -= l
            if extra < 0:
                if pos + 1 < n_ingresso:
                    bit |= (ingresso[pos] | (ingresso[pos + 1] << 8)) << (-extra)
                elif pos > n_ingresso + 64:
                    # i dati compressi sono finiti da un pezzo: file troncato.
                    # Si restituisce quello che c'e'.
                    return str(uscita)
                pos += 2
                extra += 16
            if simbolo < 256:
                aggiungi(simbolo)
                continue
            simbolo -= 256
            lung = simbolo & 15
            bit_offset = simbolo >> 4
            if lung == 15:
                lung = ingresso[pos]
                pos += 1
                if lung == 255:
                    lung = ingresso[pos] | (ingresso[pos + 1] << 8)
                    pos += 2
                    if lung == 0:
                        lung = (ingresso[pos] | (ingresso[pos + 1] << 8) |
                                (ingresso[pos + 2] << 16) | (ingresso[pos + 3] << 24))
                        pos += 4
                    if lung < 15:
                        raise ErrorePrefetch(tr(u'dati compressi non validi'))
                    lung -= 15
                lung += 15
            lung += 3
            if lung > dim_uscita - len(uscita):
                lung = dim_uscita - len(uscita)     # mai oltre la dimensione dichiarata
            if bit_offset:
                distanza = (bit >> (32 - bit_offset)) + (1 << bit_offset)
                bit = (bit << bit_offset) & 0xFFFFFFFF
                extra -= bit_offset
                if extra < 0:
                    if pos + 1 < n_ingresso:
                        bit |= (ingresso[pos] | (ingresso[pos + 1] << 8)) << (-extra)
                    pos += 2
                    extra += 16
            else:
                distanza = 1
            inizio = len(uscita) - distanza
            if inizio < 0:
                raise ErrorePrefetch(tr(u'riferimento prima dell\'inizio'))
            if distanza >= lung:
                uscita.extend(uscita[inizio:inizio + lung])
            else:
                pezzo = uscita[inizio:inizio + distanza]
                uscita.extend((pezzo * (lung // distanza + 1))[:lung])
    return str(uscita)


class Prefetch(object):

    def __init__(self, dati, limite=None):
        """dati: contenuto del file. limite: se indicato, per i file compressi
        decomprime solo i primi 'limite' byte (piu' veloce); in quel caso
        l'elenco dei file puo' essere incompleto."""
        self.compresso = False
        self.completo = True
        if dati[:3] == 'MAM':
            self.compresso = True
            dim = leggi('<I', dati, 4)[0]
            if dim > 50 * 1024 * 1024:
                raise ErrorePrefetch(tr(u'dimensione dichiarata non credibile'))
            inizio = 8
            if ord(dati[3]) & 0xF0:
                # con il bit di checksum ci sono 4 byte di CRC in piu'
                inizio = 12
            compressi = dati[inizio:]
            if limite is None:
                # basta arrivare alla fine dell'elenco dei nomi di file: si
                # legge l'intestazione e si decomprime solo fin li'
                testa = decomprimi_xpress_huffman(compressi, dim, 0x80)
                if len(testa) >= 0x6C and testa[4:8] == 'SCCA':
                    pos_nomi, dim_nomi = leggi('<II', testa, 0x64)
                    if 0 < pos_nomi + dim_nomi <= dim:
                        limite = max(pos_nomi + dim_nomi, 0x200)
            dati = decomprimi_xpress_huffman(compressi, dim, limite)
            if len(dati) < dim:
                self.completo = limite is not None and len(dati) >= limite
        if len(dati) < 0x100 or dati[4:8] != 'SCCA':
            raise ErrorePrefetch(tr(u'non \u00e8 un file Prefetch'))
        self.versione = leggi('<I', dati, 0)[0]
        nome = decodifica16(dati[0x10:0x10 + 60])
        fine = nome.find(u'\x00')
        if fine >= 0:
            nome = nome[:fine]
        self.eseguibile = nome
        self.hash = u'%08X' % leggi('<I', dati, 0x4C)[0]
        self.esecuzioni = 0
        self.ultime = []
        self.file = []
        self.percorso = u''
        v = self.versione
        pos_metriche, n_metriche, pos_tracce, n_tracce, pos_nomi, dim_nomi = leggi('<6I', dati, 0x54)
        if v == 17:
            tempi = [leggi('<Q', dati, 0x78)[0]]
            self.esecuzioni = leggi('<I', dati, 0x90)[0]
        elif v == 23:
            tempi = [leggi('<Q', dati, 0x80)[0]]
            self.esecuzioni = leggi('<I', dati, 0x98)[0]
        else:
            tempi = list(leggi('<8Q', dati, 0x80))
            if v >= 30 and pos_metriche == 0x128:
                self.esecuzioni = leggi('<I', dati, 0xC8)[0]
            else:
                self.esecuzioni = leggi('<I', dati, 0xD0)[0]
        self.ultime = [filetime_a_epoch(t) for t in tempi if t > 0]
        self.ultime.sort(reverse=True)
        if 0 < pos_nomi < len(dati):
            blocco = dati[pos_nomi: pos_nomi + dim_nomi]
            if len(blocco) < dim_nomi:
                self.completo = False
            blocco = blocco[:len(blocco) - len(blocco) % 2]
            testo = decodifica16(blocco)
            self.file = [x for x in testo.split(u'\x00') if x]
            cercato = u'\\' + self.eseguibile.upper()
            for f in self.file:
                if f.upper().endswith(cercato):
                    self.percorso = f
                    break
        else:
            self.completo = False

    def percorso_leggibile(self):
        """Il percorso senza il prefisso di volume (\\VOLUME{..} o \\DEVICE\\..)."""
        p = self.percorso
        if not p:
            return u''
        su = p.upper()
        if su.startswith(u'\\VOLUME{'):
            fine = p.find(u'}')
            if fine > 0:
                return p[fine + 1:]
        if su.startswith(u'\\DEVICE\\HARDDISKVOLUME'):
            resto = p[len(u'\\DEVICE\\HARDDISKVOLUME'):]
            taglio = resto.find(u'\\')
            if taglio >= 0:
                return resto[taglio:]
        return p
