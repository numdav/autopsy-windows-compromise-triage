# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Prove del lettore dei registri eventi (tc_evtx) su un file .evtx costruito qui, byte per byte:
#  - un evento con modello (il caso normale);
#  - due eventi senza modello, con l'XML binario tutto nel record (succede nei registri inoltrati o
#    esportati): le aperture degli elementi non hanno i 2 byte di "dependency id";
#  - un evento con modello che contiene un frammento XML annidato (valore di tipo 0x21) senza quei 2 byte;
#  - un record integro che comincia con un token che il lettore non conosce: deve contare come non
#    decodificato, senza fermare la lettura.
import struct
import sys
sys.dont_write_bytecode = True
import tc_evtx
import tc_base

esiti = {'ok': 0, 'ko': 0}


def u8(x):
    return x.encode('utf-8') if isinstance(x, unicode) else str(x)


def prova(nome, condizione, dettaglio=''):
    esiti['ok' if condizione else 'ko'] += 1
    if not condizione:
        print '  KO  %s%s' % (nome, (' -> ' + u8(dettaglio)) if dettaglio else '')
        sys.stdout.flush()


def I(x):
    return struct.pack('<I', x)


def H(x):
    return struct.pack('<H', x)


def Q(x):
    return struct.pack('<Q', x)


def nome(testo):
    """Struttura di un nome definito nel punto in cui serve."""
    return I(0) + H(0) + H(len(testo)) + testo.encode('utf-16-le') + '\x00\x00'


def testo(v):
    """Token di valore letterale (stringa)."""
    return '\x05\x01' + H(len(v)) + v.encode('utf-16-le')


def sost(indice, tipo, opzionale=False):
    return chr(0x0E if opzionale else 0x0D) + H(indice) + chr(tipo)


class E(object):
    """Un elemento XML binario. figli: altri E oppure token gia' pronti (byte)."""

    def __init__(self, nome_el, attributi=(), figli=()):
        self.nome = nome_el
        self.attributi = list(attributi)
        self.figli = list(figli)

    def byte(self, pos, dep):
        testa = 1 + (2 if dep else 0) + 4 + 4
        corpo = nome(self.nome)
        q = pos + testa + len(corpo)
        if self.attributi:
            q += 4
            ab = ''
            for i, (an, valore) in enumerate(self.attributi):
                tok = 0x46 if i < len(self.attributi) - 1 else 0x06
                ab += chr(tok) + I(q + len(ab) + 5) + nome(an) + valore
            corpo += I(len(ab)) + ab
            q += len(ab)
        if not self.figli:
            corpo += '\x03'
        else:
            corpo += '\x02'
            q += 1
            for f in self.figli:
                fb = f.byte(q, dep) if isinstance(f, E) else f
                corpo += fb
                q += len(fb)
            corpo += '\x04'
        return chr(0x41 if self.attributi else 0x01) + ('\xff\xff' if dep else '') + I(4 + len(corpo)) + \
            I(pos + testa) + corpo


def evento(v, dati=None, utente=None):
    """L'albero di un evento: v(nome, tipo, indice) restituisce il valore (letterale o sostituzione)."""
    system = E(u'System', figli=[
        E(u'Provider', attributi=[(u'Name', v(u'Provider', 0x01, None))]),
        E(u'EventID', figli=[v(u'EventID', 0x06, 0)]),
        E(u'TimeCreated', attributi=[(u'SystemTime', v(u'SystemTime', 0x11, 1))]),
        E(u'EventRecordID', figli=[v(u'EventRecordID', 0x0A, 2)]),
        E(u'Channel', figli=[v(u'Channel', 0x01, None)]),
        E(u'Computer', figli=[v(u'Computer', 0x01, 3)]),
        E(u'Security', attributi=[(u'UserID', v(u'UserID', 0x13, 4))])])
    figli = [system]
    if dati:
        figli.append(E(u'EventData', figli=[E(u'Data', attributi=[(u'Name', testo(n))], figli=[x]) for n, x in dati]))
    if utente is not None:
        figli.append(E(u'UserData', figli=[utente]))
    return E(u'Event', attributi=[(u'xmlns', testo(u'http://schemas.microsoft.com/win/2004/08/events/event'))],
             figli=figli)


EPOCA = 1714557600              # 2024-05-01 10:00:00 UTC


def filetime(epoca):
    return int((epoca + 11644473600) * 10000000)


def guid(n):
    return struct.pack('<IHH', 0x11111111 * n, n, n) + '\x00' * 8


SID_SISTEMA = '\x01\x01\x00\x00\x00\x00\x00\x05' + I(18)


def record(pos, numero, corpo_da_pos):
    """Record completo: firma, dimensione, numero, ora di scrittura, XML binario, dimensione."""
    corpo = corpo_da_pos(pos + 24)
    dim = 24 + len(corpo) + 4
    return '**\x00\x00' + I(dim) + Q(numero) + Q(filetime(EPOCA + numero)) + corpo + I(dim)


def con_modello(albero, valori, n_guid):
    """Corpo di un evento con modello: albero con le sostituzioni, valori [(tipo, byte o funzione(pos))]."""
    def corpo(q):
        q += 4                                  # testata del frammento
        pos_def = q + 10
        modello = '\x0f\x01\x01\x00' + albero.byte(pos_def + 24 + 4, True) + '\x00'
        definizione = I(0) + guid(n_guid) + I(len(modello)) + modello
        r = q + 10 + len(definizione) + 4 + 4 * len(valori)
        descr = ''
        vb = ''
        for tipo, v in valori:
            if callable(v):
                v = v(r + len(vb))
            descr += H(len(v)) + chr(tipo) + '\x00'
            vb += v
        return '\x0f\x01\x01\x00' + '\x0c\x01' + I(n_guid) + I(pos_def) + definizione + I(len(valori)) + descr + vb
    return corpo


def senza_modello(albero):
    def corpo(q):
        return '\x0f\x01\x01\x00' + albero.byte(q + 4, False) + '\x00'
    return corpo


def letterale(valori):
    def v(nome_v, tipo, indice):
        return testo(valori[nome_v])
    return v


def sostituzione(nome_v, tipo, indice):
    if indice is None:
        return testo({u'Provider': u'Microsoft-Windows-Security-Auditing', u'Channel': u'Security'}[nome_v])
    return sost(indice, tipo, nome_v == u'UserID')


# 1. con modello: 4688 con la riga di comando
albero1 = evento(sostituzione, dati=[(u'NewProcessName', sost(5, 0x01)), (u'CommandLine', sost(6, 0x01))])
valori1 = [(0x06, H(4688)), (0x11, Q(filetime(EPOCA))), (0x0A, Q(77)), (0x01, u'PC-PROVA\x00'.encode('utf-16-le')),
           (0x13, SID_SISTEMA), (0x01, u'C:\\Windows\\System32\\cmd.exe'.encode('utf-16-le')),
           (0x01, u'cmd.exe /c whoami'.encode('utf-16-le'))]
# 2. senza modello: 4688 con gli stessi valori scritti nel record, ora con i decimi di microsecondo
albero2 = evento(letterale({u'Provider': u'Microsoft-Windows-Security-Auditing', u'EventID': u'4688',
                            u'SystemTime': u'2024-05-01T10:00:00.1234567Z', u'EventRecordID': u'78',
                            u'Channel': u'Security', u'Computer': u'PC-PROVA', u'UserID': u'S-1-5-18'}),
                 dati=[(u'NewProcessName', testo(u'C:\\Windows\\System32\\cmd.exe')),
                       (u'CommandLine', testo(u'cmd.exe /c whoami'))])
# 3. senza modello: 1149 con UserData
albero3 = evento(letterale({u'Provider': u'Microsoft-Windows-TerminalServices-RemoteConnectionManager',
                            u'EventID': u'1149', u'SystemTime': u'2024-05-01T10:05:00Z', u'EventRecordID': u'79',
                            u'Channel': u'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
                            u'Computer': u'PC-PROVA', u'UserID': u'S-1-5-20'}),
                 utente=E(u'EventXML', figli=[E(u'Param1', figli=[testo(u'admin')]),
                                              E(u'Param3', figli=[testo(u'203.0.113.7')])]))
# 4. con modello e un frammento annidato (tipo 0x21) i cui elementi non hanno il "dependency id"
albero4 = evento(sostituzione, utente=sost(5, 0x21))


def frammento(pos):
    return '\x0f\x01\x01\x00' + E(u'EventXML', figli=[E(u'Param1', figli=[testo(u'operatore')])]).byte(pos + 4, False) + '\x00'


valori4 = [(0x06, H(1149)), (0x11, Q(filetime(EPOCA + 600))), (0x0A, Q(80)), (0x01, u'PC-PROVA'.encode('utf-16-le')),
           (0x13, SID_SISTEMA), (0x21, frammento)]


def costruisci():
    corpi = [con_modello(albero1, valori1, 1), senza_modello(albero2), senza_modello(albero3),
             con_modello(albero4, valori4, 2),
             lambda q: '\x0f\x01\x01\x00\x0a' + '\x00' * 40]       # token 0x0A: istruzione di elaborazione
    pos = 512
    dati = ''
    ultimo = pos
    for i, c in enumerate(corpi):
        r = record(pos, i + 1, c)
        ultimo = pos
        dati += r
        pos += len(r)
    n = len(corpi)
    testa = 'ElfChnk\x00' + Q(1) + Q(n) + Q(1) + Q(n) + I(128) + I(ultimo) + I(pos) + I(0)
    blocco = testa + '\x00' * (512 - len(testa)) + dati
    blocco += '\x00' * (65536 - len(blocco))
    file_ = 'ElfFile\x00' + '\x00' * (4096 - 8) + blocco
    return file_


class Sorgente(object):
    def __init__(self, dati):
        self.dati = dati
        self.dimensione = len(dati)

    def leggi(self, pos, quanti):
        return self.dati[pos: pos + quanti]


DATI = costruisci()
f = tc_evtx.FileEvtx(Sorgente(DATI))
eventi = list(f.eventi())
prova('quattro eventi letti, uno non decodificato, due senza modello',
      (len(eventi), f.letti, f.errori, f.senza_modello, f.visti, f.persi) == (4, 4, 1, 2, 5, 0),
      repr((len(eventi), f.letti, f.errori, f.senza_modello, f.visti, f.persi)))
per_record = dict([(e['Record'], e) for e in eventi])
e1, e2, e3, e4 = per_record.get(77), per_record.get(78), per_record.get(79), per_record.get(80)
prova('evento con modello', e1 is not None and e1['EventID'] == 4688 and e1['Ora'] == EPOCA and
      e1['Computer'] == u'PC-PROVA' and e1['SidUtente'] == u'S-1-5-18' and e1['Canale'] == u'Security' and
      e1['Dati'].get(u'CommandLine') == u'cmd.exe /c whoami', repr(e1))
prova('evento senza modello: stessi valori di quello con modello', e2 is not None and e1 is not None and
      all([e2[k] == e1[k] for k in ('EventID', 'Provider', 'Canale', 'Computer', 'SidUtente', 'Dati')]), repr(e2))
prova('evento senza modello: ora con la frazione di secondo', e2 is not None and abs(e2['Ora'] - (EPOCA + 0.1234567)) < 1e-6,
      repr(e2 and e2['Ora']))
prova('evento senza modello con UserData', e3 is not None and e3['EventID'] == 1149 and
      e3['Dati'].get(u'Param1') == u'admin' and e3['Dati'].get(u'Param3') == u'203.0.113.7' and
      e3['SidUtente'] == u'S-1-5-20', repr(e3))
prova('frammento annidato senza "dependency id"', e4 is not None and e4['EventID'] == 1149 and
      e4['Dati'].get(u'Param1') == u'operatore', repr(e4))

f = tc_evtx.FileEvtx(Sorgente(DATI))
solo = list(f.eventi(id_voluti=set([1149])))
prova('id_voluti vale anche per gli eventi senza modello', sorted([e['Record'] for e in solo]) == [79, 80] and f.errori == 1,
      repr([e['Record'] for e in solo]))
f = tc_evtx.FileEvtx(Sorgente(DATI))
visti_dal_filtro = []


def filtro(ident, dati, p, dim):
    visti_dal_filtro.append(ident)
    return False


nessuno = list(f.eventi(filtro=filtro))
prova('il filtro vale anche per gli eventi senza modello', not nessuno and sorted(visti_dal_filtro) == [1149, 1149, 4688, 4688]
      and f.errori == 1, repr(visti_dal_filtro))
f = tc_evtx.FileEvtx(Sorgente(DATI))
prova('estremi dalle intestazioni', f.estremi()[2] == 5)

# orari scritti come testo
for t, atteso in ((u'2024-05-01T10:00:00Z', EPOCA), (u'2024-05-01 10:00:00', EPOCA), (u'2024-05-01T10:00:00.5Z', EPOCA + 0.5),
                  (u'2024-05-01T10:00:00.123456789Z', EPOCA + 0.1234567), (u'xx', 0.0), (u'', 0.0)):
    r = tc_base.orario_da_testo(t)
    prova('orario_da_testo(%r)' % t, abs(r - atteso) < 1e-6, repr(r))

print 'evtx: prove riuscite %d, prove fallite %d' % (esiti['ok'], esiti['ko'])
