# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Prove unitarie della logica dei tempi: vede(), riferimento, recente(), _controlla_orari(),
# gli avvisi sulla copertura dei registri eventi, testo_orario.
import sys, time, random
sys.dont_write_bytecode = True
import tc_origine, tc_controlli, tc_c_eventi, tc_eventi, tc_base
import tc_regole as R

ORA = time.time()
G = 86400.0
esiti = {'ok': 0, 'ko': 0}


def u8(x):
    return x.encode('utf-8') if isinstance(x, unicode) else str(x)


def prova(nome, condizione, dettaglio=''):
    esiti['ok' if condizione else 'ko'] += 1
    if not condizione:
        print '  KO  %s%s' % (nome, (' -> ' + u8(dettaglio)) if dettaglio else '')
        sys.stdout.flush()


class RadiceFinta(object):
    piatta = False; unica = True; prefisso = u'/'; volume = None
    def descrizione(self): return u'/'


def nuovo(piatta=False):
    r = RadiceFinta()
    r.piatta = piatta
    return tc_controlli.Triage(r)


S, Y, A = u'security.evtx', u'system.evtx', u'application.evtx'
P4, P1, L = u'microsoft-windows-powershell%4operational.evtx', u'windows powershell.evtx', \
    u'microsoft-windows-terminalservices-localsessionmanager%4operational.evtx'
base = ORA - 400 * G

# ---- valori non validi
t = nuovo()
for v in (0, -1, -1e12, None, float('nan'), float('inf'), float('-inf'), ORA + G + 5, ORA + 400 * G, 1e300, 253402300800.0 * 10):
    try:
        t.vede(v); t.vede(v, True); t.vede(v, True, S)
    except Exception, ex:
        prova('vede(%r) senza eccezioni' % (v,), False, repr(ex))
prova('nessun valore non valido sposta il riferimento', t.riferimento == 0 and not t._voti and not t._minuti_altri,
      'rif=%r voti=%r' % (t.riferimento, t._voti))
prova('ultima_attivita() senza nulla', t.ultima_attivita() == 0)
prova('recente(nan) falso', nuovo().recente(float('nan')) is False)
t = nuovo(); t.vede(ORA - 100 * G, True)
prova('recente(nan) falso con riferimento', t.recente(float('nan')) is False)
prova('recente(inf): nessun limite in avanti', t.recente(float('inf')) is True)
prova('recente(riferimento - 30 giorni esatti)', t.recente(t.riferimento - 30 * G) is True)
prova('recente(riferimento - 30 giorni - 1 s) falso', t.recente(t.riferimento - 30 * G - 1) is False)
prova('recente(None) falso', t.recente(None) is False)
t = nuovo(); t.vede(ORA + G - 60)
prova('ora + 1 giorno - 60 s accettato', t.riferimento > 0)
t = nuovo(); t.vede(ORA + G + 60)
prova('ora + 1 giorno + 60 s ignorato', t.riferimento == 0)

# ---- solo fonti non affidabili: il terzo minuto piu' recente (il piu' vecchio se sono meno di tre)
t = nuovo(); t.vede(base)
prova('un solo valore: riferimento = quel valore', t.riferimento == base)
t = nuovo(); t.vede(base); t.vede(base + 200 * G)
prova('due valori (uno vero, uno 200 giorni dopo): riferimento = quello vero', t.riferimento == base, tc_base.testo_orario(t.riferimento))
prova('   ...e l\'attivita\' vera resta recente', t.recente(base) is True)
t = nuovo()
for i in range(50): t.vede(base - i * 3600)
t.vede(base + 200 * G); t.vede(base + 201 * G)
prova('50 veri + 2 isolati nel futuro: riferimento = ultimo vero', t.riferimento == base, tc_base.testo_orario(t.riferimento))
prova('ultima_attivita() = il piu\' recente in assoluto', t.ultima_attivita() == base + 201 * G)
valori = [base - i * 977 for i in range(500)] + [base + 100 * G + i * 61 for i in range(2)]
attesi = None
for seme in range(20):
    rnd = random.Random(seme); v = list(valori); rnd.shuffle(v)
    t = nuovo()
    for x in v: t.vede(x)
    stato = (t.riferimento, sorted(t._minuti_altri.items()))
    if attesi is None: attesi = stato
    elif attesi != stato:
        prova('risultato indipendente dall\'ordine', False, 'seme %d' % seme); break
else:
    prova('risultato indipendente dall\'ordine (20 ordini a caso, 502 valori)', attesi[0] == base, tc_base.testo_orario(attesi[0]))
t = nuovo()
for i in range(100): t.vede(base)
prova('100 valori uguali: un minuto solo, contato 100 volte', t.riferimento == base and len(t._minuti_altri) == 1
      and t._minuti_altri.values()[0][1] == 100)
t = nuovo()
for i in range(500): t.vede(base + i * 60)
prova('500 minuti diversi: se ne tengono 60', len(t._minuti_altri) == 60 and t.riferimento == base + 497 * 60, len(t._minuti_altri))

# ---- fonti affidabili
t = nuovo(); t.vede(base, True, S)
for i in range(10): t.vede(base + 50 * G + i * 3600)
prova('una fonte affidabile piu\' vecchia degli altri artefatti: vale lei', t.riferimento == base)
prova('   gli altri, successivi, sono recenti', t.recente(base + 50 * G))
t = nuovo(); t.vede(base, True, S); t.vede(base + 10, True, Y)
prova('Security e System: vale il piu\' vecchio dei due', t.riferimento == base)
t.vede(base + 300 * G, True, Y)
prova('System con un ultimo evento 300 giorni dopo: il riferimento resta al Security', t.riferimento == base)
t.vede(base + 301 * G, True, A); t.vede(base + 302 * G, True, u'spegnimento')
prova('altre fonti in avanti non contano se ci sono Security e System', t.riferimento == base)
t.vede(base + 5, True, S)
prova('il voto di una fonte e\' il suo valore piu\' recente', t.riferimento == base + 5)
t.vede(base - 500, True, S)
prova('...e non torna indietro', t.riferimento == base + 5)
t = nuovo(); t.vede(base, True, S)
prova('solo Security: vale lui', t.riferimento == base)
t.vede(base + 100 * G, True, A)
prova('Security + Application (senza System): il piu\' vecchio dei due', t.riferimento == base)
t.vede(base + 101 * G, True, P1)
prova('tre fonti senza System: la terza piu\' recente', t.riferimento == base)
t.vede(base + 102 * G, True, P4)
prova('quattro fonti senza System: la terza piu\' recente', t.riferimento == base + 100 * G, tc_base.testo_orario(t.riferimento))
t = nuovo(); t.vede(base + 3, True, u'spegnimento')
for i in range(10): t.vede(base - i * 3600)
prova('solo l\'ora di spegnimento: vale lei', t.riferimento == base + 3)
t = nuovo(); t.riferimento = 12345.0
t.vede(base, True, S)
prova('riferimento imposto da fuori (prove): non cambia', t.riferimento == 12345.0)

# ---- _controlla_orari()
def caso(ultimo_evento, altri, spegnimento=0):
    t = nuovo()
    t.ultimo_evento = ultimo_evento
    for x in altri: t.vede(x)
    if spegnimento:
        t.contesto['spegnimento'] = spegnimento
    t._controlla_orari()
    return t
t = caso(0.0, [base + i * 3600 for i in range(10)])
prova('senza registri eventi: niente avviso ne\' nota', not t.avvisi and not t.note)
t = caso(base, [base + G] * 5 + [base + G - 60, base + G - 120])
prova('altri artefatti esattamente 1 giorno dopo: niente', not t.avvisi and not t.note)
t = caso(base, [base + G + 1, base + G + 61, base + G + 121])
prova('tre minuti distinti, 1 giorno + 1 s dopo: avviso', len(t.avvisi) == 1 and not t.note, t.avvisi and t.avvisi[0][:90])
t = caso(base, [base + G + 1, base + G + 61])
prova('due minuti distinti, due orari: solo nota', not t.avvisi and len(t.note) == 1)
t = caso(base, [base + G + 1] * 5)
prova('un minuto solo ma cinque orari: avviso', len(t.avvisi) == 1)
t = caso(base, [base + G + 1] * 4)
prova('un minuto solo e quattro orari: nota', not t.avvisi and len(t.note) == 1)
t = caso(base, [base - 5 * G + i * 3600 for i in range(100)])
prova('tutto prima dell\'ultimo evento: niente', not t.avvisi and not t.note)
altri = [base + 2 * G + i * 3600 for i in range(200)] + [base + 11 * G + (i % 50) for i in range(300)]
t = caso(base, altri)
prova('200 orari su 8 giorni + 300 nello stesso minuto, dopo l\'ultimo evento: avviso', len(t.avvisi) == 1,
      'avvisi=%d note=%d' % (len(t.avvisi), len(t.note)))
t.decidi()
prova('   ...e il verdetto non e\' "nessun indizio"', t.verdetto == tc_controlli.V_DA_VERIFICARE, t.verdetto)
t = caso(base, [ORA + 2 * G, ORA + 3 * G, ORA + 4 * G])
prova('orari oltre oggi + 1 giorno: ignorati', not t.avvisi and not t.note)
t = caso(base, [], spegnimento=base + G + 5)
prova('spegnimento oltre un giorno dopo l\'ultimo evento: avviso', len(t.avvisi) == 1)
t = caso(base, [], spegnimento=base + G - 5)
prova('spegnimento entro un giorno: niente', not t.avvisi)
t = caso(base, [], spegnimento=ORA + 3 * G)
prova('spegnimento nel futuro: ignorato', not t.avvisi)

# ---- copertura dei registri eventi (tc_c_eventi._copertura)
class EvFinto(tc_origine.Elemento):
    def __init__(self, nome):
        self.nome = nome; self.cartella = u'/windows/system32/winevt/logs/'; self.dimensione = 100

SEMPRE = {A: (base - 60 * G, base, 10), P4: (base - 60 * G, base, 10), P1: (base - 60 * G, base, 10), L: (base - 60 * G, base, 10)}

def copertura(voci, piatta=False, sempre=True, scritti=None, guasti=None, installato=0, conteggi=None):
    """voci: nome -> (primo, ultimo, record). Restituisce il triage dopo _copertura."""
    t = nuovo(piatta)
    rac = tc_eventi.Raccolta()
    tutte = dict(SEMPRE) if sempre else {}
    tutte.update(voci)
    for nome, (primo, ultimo, quanti) in tutte.items():
        scritto = (scritti or {}).get(nome, ultimo)
        g = (guasti or {}).get(nome, (0, 0, 0))
        # [primo, ultimo, record, elemento, errori, ultimo_scritto, persi, fuori_scala, blocchi_danneggiati, visti]
        rac.copertura[nome] = [primo, ultimo, quanti, EvFinto(nome), g[0], scritto, g[1], 0, g[2], quanti]
        t.vede(scritto or ultimo, True, nome)
        if ultimo and ultimo > t.ultimo_evento:
            t.ultimo_evento = ultimo
    rac.conteggi = {4624: 10, 4688: 1, 5145: 1, 4698: 1} if conteggi is None else conteggi
    rac.processi_con_riga = 1
    t.raccolta = rac
    if installato:
        t.contesto['installato'] = installato
    tc_c_eventi._copertura(t, rac)
    return t

def con(t, pezzo, dove='avvisi'):
    return [x for x in getattr(t, dove) if pezzo in x]

t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base, 100)})
prova('registri normali: nessun avviso, nessuna nota', not t.avvisi and not t.note, repr(t.avvisi + t.note)[:300])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base + G, 100), A: (base - 60 * G, base + G, 100)})
prova('Security fermo esattamente 1 giorno prima di due registri: niente', not t.avvisi and not t.note, repr(t.avvisi + t.note)[:200])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base + G + 1, 100), A: (base - 60 * G, base + G + 1, 100)})
prova('Security fermo 1 giorno + 1 s prima di due registri: avviso', len(con(t, u'si ferma al')) == 1 and not t.note,
      repr(t.avvisi + t.note)[:200])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base + 20 * G, 100)})
prova('Security fermo 20 giorni prima del solo System: niente avviso, una nota', not t.avvisi and len(con(t, u'oltre il momento', 'note')) == 1,
      repr(t.avvisi + t.note)[:300])
prova('   il riferimento resta alla fine del Security', t.riferimento == base)
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base + 20 * G, 100), A: (base - 60 * G, base + 20 * G, 100)}, piatta=True)
prova('radice piatta: niente avviso sul Security fermo', not con(t, u'si ferma al'))
t = copertura({S: (base - 3600, base, 1000), Y: (base - 60 * G, base, 100)})
prova('Security che copre un\'ora: avviso "copre solo" e segnale informativo',
      len(con(t, u'copre solo')) == 1 and len([s for s in t.segnali if s.controllo == 8 and s.peso == R.INFORMATIVO]) == 1)
t = copertura({S: (base - 3600, base, 1000), Y: (base - 60 * G, base, 100)}, installato=base - 7200)
prova('Security che copre un\'ora su una macchina installata due ore prima: niente', not con(t, u'copre solo'))
t = copertura({S: (None, None, 0), Y: (base - 60 * G, base, 100)}, conteggi={})
prova('Security valido ma senza eventi: nessuna eccezione e un avviso solo, quello giusto',
      len(t.avvisi) == 1 and u'vuoto' in t.avvisi[0], repr(t.avvisi)[:300])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base, 100)}, conteggi={4688: 3})
prova('Security senza 4624: avviso sull\'audit degli accessi', len(con(t, u'nessun evento 4624')) == 1)
t = copertura({Y: (base - 60 * G, base, 100)})
prova('Security assente: avviso', len(con(t, u'Security.evtx non trovato')) == 1)
t = copertura({S: (base - 60 * G, base, 1000)})
prova('System assente: avviso', len(con(t, u'System.evtx non \u00e8 stato trovato')) == 1, repr(t.avvisi)[:300])
t = copertura({S: (base - 60 * G, base, 1000)}, piatta=True)
prova('radice piatta: i registri assenti non danno avvisi', not t.avvisi, repr(t.avvisi)[:300])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base, 100)}, sempre=False)
a = con(t, u'Windows l')
prova('mancano i quattro registri che Windows crea sempre: un avviso che li nomina',
      len(a) == 1 and u'Application.evtx' in a[0] and u'PowerShell/Operational.evtx' in a[0] and u'evento 4104' in a[0], repr(t.avvisi)[:400])
tutte = dict(SEMPRE); del tutte[P1]
t = nuovo(); rac = tc_eventi.Raccolta()
t = copertura(dict([(S, (base - 60 * G, base, 1000)), (Y, (base - 60 * G, base, 100))] + tutte.items()), sempre=False)
a = con(t, u'Windows lo crea sempre')
prova('manca solo Windows PowerShell.evtx: avviso al singolare', len(a) == 1 and u'evento 400' in a[0] and u'tolto' in a[0], repr(t.avvisi)[:300])
righe = dict([(r[0], r[1]) for r in t.tabelle[0].righe])
prova('tabella: il registro che manca e\' "non trovato", quelli facoltativi dicono che e\' normale',
      righe.get(u'Windows PowerShell') == u'non trovato' and u'normale' in righe.get(u'Sysmon/Operational', u'')
      and u'normale' in righe.get(u'TaskScheduler/Operational', u''), repr(righe)[:400])
t = copertura({S: (base - 60 * G, base + 3 * G, 1000), Y: (base - 60 * G, base + 3 * G, 100)},
              scritti={S: base, Y: base})
prova('orologio riportato indietro: nota, riferimento all\'ultimo evento scritto',
      len(con(t, u'non \u00e8 l\'ultimo scritto', 'note')) == 1 and t.riferimento == base and not con(t, u'oltre il momento', 'note'),
      repr(t.note)[:300])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base, 100)}, guasti={Y: (2, 3, 1)})
a = con(t, u'Registri eventi danneggiati')
prova('record persi e blocchi rovinati: avviso "danneggiati" con i numeri',
      len(a) == 1 and u'3 eventi non leggibili' in a[0] and u'1 blocchi rovinati' in a[0], repr(t.avvisi)[:300])
a = con(t, u'Eventi non decodificati')
prova('record integri non decodificati: avviso a parte, che non dice "danneggiati"',
      len(a) == 1 and u'System (2 su 103)' in a[0] and u'danneggiat' not in a[0], repr(t.avvisi)[:400])
t = copertura({S: (base - 60 * G, base, 1000), Y: (base - 60 * G, base, 100)}, guasti={S: (7, 0, 0)})
prova('solo record non decodificati: nessun avviso "danneggiati", uno "non decodificati"',
      not con(t, u'danneggiat') and len(con(t, u'Eventi non decodificati')) == 1, repr(t.avvisi)[:400])

# ---- testo_orario
T = tc_base.testo_orario
for v, atteso in ((0, u''), (-5, u''), (None, u''), (float('nan'), u''), (float('inf'), u''), (253402300799.0, u'9999-12-31 23:59:59'),
                  (253402300800.0, u''), (1e18, u''), (1.5, u'1970-01-01 00:00:01'), (True, u'1970-01-01 00:00:01')):
    try:
        r = T(v)
    except Exception, ex:
        r = 'ECCEZIONE %r' % ex
    prova('testo_orario(%r) = %r' % (v, atteso), r == atteso, repr(r))
for v in ('x', u'', [], {}):
    try:
        T(v)
    except BaseException, ex:
        prova('testo_orario(%r) senza eccezioni' % (v,), False, repr(ex))

print 'tempi: prove riuscite %d, fallite %d' % (esiti['ok'], esiti['ko'])
