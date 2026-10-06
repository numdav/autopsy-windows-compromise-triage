# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_base - Funzioni comuni del plugin "Triage compromissione" per Autopsy.
"""

import struct
import time
import calendar

from tc_lingua import tr

DIFF_FILETIME = 116444736000000000

# Le eccezioni da intercettare quando un errore non deve fermare il triage.
# In Jython un errore che nasce nel codice Java di Autopsy (per esempio un
# file illeggibile nell'immagine) NON e' una sottoclasse di Exception: senza
# Throwable passerebbe attraverso tutti gli "except Exception".
try:
    from java.lang import Throwable as _Throwable
    ERRORI = (Exception, _Throwable)
except ImportError:
    ERRORI = (Exception,)

# caratteri di controllo da togliere dai testi mostrati o salvati (restano
# tabulazione e a capo)
_DA_TOGLIERE = dict([(_i, None) for _i in range(32) if _i not in (9, 10)])
_DA_TOGLIERE[0x7f] = None
_DA_TOGLIERE[0xfffe] = None
_DA_TOGLIERE[0xffff] = None
# Caratteri che cambiano il verso di lettura del testo: in un nome di file
# servono a far sembrare "annexe.pdf" un "ann[...]fdp.exe". Diventano visibili.
for _i in (0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069):
    _DA_TOGLIERE[_i] = u'[U+%04X]' % _i
INVERSIONE = u'\u202e'     # RLO: il piu' usato per camuffare le estensioni


def pulito(testo):
    """Il testo senza caratteri di controllo: arrivano dai dati della
    macchina analizzata e darebbero fastidio nel report e nel database del
    caso. Accetta anche valori non testuali."""
    if testo is None:
        return u''
    if not isinstance(testo, unicode):
        try:
            if isinstance(testo, str):
                testo = testo.decode('latin-1')
            else:
                testo = unicode(testo)
        except ERRORI:
            return u''
    return testo.translate(_DA_TOGLIERE)

_unpack = struct.unpack
_calcsize = struct.calcsize
_DIM = {}


def leggi(formato, b, p):
    """Come struct.unpack_from. In Jython unpack_from copia l'intero buffer a
    ogni chiamata (lentissimo sui file grandi): qui si taglia prima il pezzo
    che serve."""
    d = _DIM.get(formato)
    if d is None:
        d = _calcsize(formato)
        _DIM[formato] = d
    if p < 0:
        # una posizione negativa leggerebbe dalla fine del buffer dati che
        # non c'entrano: meglio un errore che un valore sbagliato
        raise ValueError(tr(u'posizione negativa'))
    return _unpack(formato, b[p:p + d])


def decodifica16(b):
    """Testo da byte UTF-16LE, senza mai fallire.

    In Jython la decodifica UTF-16 lancia un'eccezione Java (che gli "except
    Exception" non fermano) quando l'ultimo carattere e' la prima meta' di
    una coppia di surrogati rimasta senza la seconda. Basterebbe un valore
    del registro o un evento danneggiato - o costruito apposta - per far
    saltare la lettura dell'intero file. Qui quel carattere viene sostituito
    prima di decodificare."""
    n = len(b)
    if n & 1:
        b = b[:n - 1]
        n -= 1
    if n == 0:
        return u''
    if '\xd8' <= b[n - 1] <= '\xdb':
        b = b[:n - 2] + '\xfd\xff'
    try:
        return b.decode('utf-16-le', 'replace')
    except ERRORI:
        # ultima difesa: un'unita' alla volta, sostituendo ogni surrogato
        try:
            pezzi = []
            for v in _unpack('<%dH' % (n // 2), b):
                pezzi.append(unichr(v) if (v < 0xD800 or v > 0xDFFF) else u'\ufffd')
            return u''.join(pezzi)
        except ERRORI:
            return u''


def filetime_a_epoch(valore):
    """FILETIME di Windows -> secondi epoch UTC (0 se nullo)."""
    if valore <= 0:
        return 0.0
    return (valore - DIFF_FILETIME) / 10000000.0


def testo_orario(epoch):
    """Secondi epoch -> 'AAAA-MM-GG HH:MM:SS' in UTC. Restituisce '' se il
    valore e' nullo o non e' una data scrivibile (oltre l'anno 9999: e' il
    valore "mai" di Windows, oppure un dato rovinato)."""
    try:
        if not (epoch > 0) or epoch >= 253402300800.0:
            return u''
        return unicode(time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch)))
    except ERRORI:
        return u''


def orario_da_testo(testo):
    """'AAAA-MM-GG HH:MM:SS' oppure 'AAAA-MM-GGTHH:MM:SS' -> epoch (0 se non valido)."""
    try:
        t = testo.strip().replace('T', ' ')[:19]
        return float(calendar.timegm(time.strptime(t, '%Y-%m-%d %H:%M:%S')))
    except ERRORI:
        return 0.0


def testo_sid(b, pos):
    """SID binario -> (testo 'S-1-5-...', lunghezza in byte)."""
    rev = ord(b[pos])
    n = ord(b[pos + 1])
    alto, basso = leggi('>HI', b, pos + 2)
    parti = [u'S', unicode(rev), unicode((alto << 32) | basso)]
    for i in xrange(n):
        parti.append(unicode(leggi('<I', b, pos + 8 + i * 4)[0]))
    return u'-'.join(parti), 8 + 4 * n


def esadecimale(dati, massimo=None):
    if massimo is not None and len(dati) > massimo:
        return u''.join([u'%02X' % ord(c) for c in dati[:massimo]]) + u'...'
    return u''.join([u'%02X' % ord(c) for c in dati])
