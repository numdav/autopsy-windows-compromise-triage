# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_lingua - La lingua dei testi che il plugin mostra all'analista.

Nel codice i testi sono scritti in italiano. Ogni testo ha la sua traduzione
inglese in tc_lingua_en.py, con il testo italiano come chiave:

    tr(u'testo')    restituisce il testo nella lingua dell'analisi in corso
    N_(u'testo')    lo segna soltanto come "da tradurre"; serve per le costanti
                    definite una volta sola al caricamento del modulo, che
                    vanno tradotte con tr() nel punto in cui vengono mostrate

Un testo che non ha traduzione resta in italiano. La lingua vale per il
thread che la imposta: due analisi contemporanee in lingue diverse non si
disturbano. Chi non la imposta lavora in italiano.

Per controllare che non manchino traduzioni: tools/check_translations.py.
"""

import threading

import tc_lingua_en

# Come tc_base.ERRORI (che qui non si puo' importare: tc_base usa questo
# modulo): in Jython le eccezioni Java non sono sottoclassi di Exception.
try:
    from java.lang import Throwable as _Throwable
    _ERRORI = (Exception, _Throwable)
except ImportError:
    _ERRORI = (Exception,)

ITALIANO = u'it'
INGLESE = u'en'
LINGUE = (INGLESE, ITALIANO)
NOMI = {INGLESE: u'English', ITALIANO: u'Italiano'}

_corrente = threading.local()
_EN = tc_lingua_en.TESTI


def imposta(lingua):
    """Sceglie la lingua per il thread che chiama."""
    _corrente.lingua = INGLESE if lingua == INGLESE else ITALIANO


def lingua():
    return getattr(_corrente, 'lingua', ITALIANO)


def tr(testo):
    """Il testo nella lingua corrente."""
    if getattr(_corrente, 'lingua', ITALIANO) == ITALIANO:
        return testo
    return _EN.get(testo, testo)


def tr_in(lingua, testo):
    """Il testo in una lingua precisa, senza toccare quella corrente."""
    if lingua == INGLESE:
        return _EN.get(testo, testo)
    return testo


def N_(testo):
    """Segna un testo da tradurre senza tradurlo adesso."""
    return testo


def valida(lingua):
    """La lingua indicata se e' una di quelle previste, altrimenti None."""
    try:
        lingua = unicode(lingua or u'').strip().lower()
    except _ERRORI:
        return None
    return lingua if lingua in LINGUE else None


def del_sistema():
    """La lingua da proporre: italiano se il sistema e' in italiano,
    altrimenti inglese."""
    try:
        from java.util import Locale
        if Locale.getDefault().getLanguage() == u'it':
            return ITALIANO
    except _ERRORI:
        pass
    return INGLESE
