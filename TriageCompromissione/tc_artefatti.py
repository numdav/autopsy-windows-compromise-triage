# -*- coding: utf-8 -*-
"""
tc_artefatti - Lettori dei piccoli artefatti di Windows usati dal plugin
"Triage compromissione" per Autopsy. Python 2.7 puro (Jython), nessuna
libreria esterna.

Contiene: Cestino ($I), attivita' pianificate (XML e TaskCache), ShimCache,
UserAssist, account del SAM, informazioni di versione dei file PE,
collegamenti .lnk, sottoscrizioni WMI, CryptnetUrlCache, log di AnyDesk e
TeamViewer, cronologia dei rilevamenti di Defender.
"""

import re
import time
import calendar

from tc_base import leggi, filetime_a_epoch, testo_sid, decodifica16, ERRORI


# --------------------------------------------------------------------------
# testo
# --------------------------------------------------------------------------

def testo_da_file(dati):
    """Decodifica un file di testo riconoscendo BOM e UTF-16 senza BOM."""
    if dati[:2] == '\xff\xfe':
        return decodifica16(dati[2:len(dati) - (len(dati) % 2)])
    if dati[:2] == '\xfe\xff':
        corpo = dati[2:len(dati) - (len(dati) % 2)]
        try:
            return corpo.decode('utf-16-be', 'replace')
        except ERRORI:
            return corpo[:-2].decode('utf-16-be', 'replace') if len(corpo) > 2 else u''
    if dati[:3] == '\xef\xbb\xbf':
        return dati[3:].decode('utf-8', 'replace')
    campione = dati[:400]
    if len(campione) >= 8 and campione[1::2].count('\x00') > len(campione) / 4:
        return decodifica16(dati[:len(dati) - (len(dati) % 2)])
    try:
        return dati.decode('utf-8')
    except UnicodeDecodeError:
        return dati.decode('cp1252', 'replace')


def _fino_a_zero(testo):
    fine = testo.find(u'\x00')
    if fine >= 0:
        return testo[:fine]
    return testo


_RX_PER_STRINGHE16 = {}


def stringhe_utf16(dati, minimo=6, con_spazio=True):
    """Le stringhe UTF-16LE di caratteri ASCII stampabili contenute in
    'dati', lunghe almeno 'minimo' caratteri: lista di (posizione, testo) in
    ordine di posizione. Con con_spazio=False lo spazio interrompe la stringa.

    Non usa espressioni regolari con ripetizioni di gruppi, come
    (?:[ -~]\x00){6,}: il motore di Jython le risolve in modo ricorsivo e
    sulle stringhe di qualche migliaio di caratteri esaurisce lo stack."""
    chiave = (minimo, con_spazio)
    coppia = _RX_PER_STRINGHE16.get(chiave)
    if coppia is None:
        classe = r'[\x20-\x7e]' if con_spazio else r'[\x21-\x7e]'
        coppia = (re.compile(classe + '{%d,}' % minimo), re.compile('\x00{%d,}' % minimo))
        _RX_PER_STRINGHE16[chiave] = coppia
    rx_caratteri, rx_zeri = coppia
    trovate = []
    for fase in (0, 1):
        bassi = dati[fase::2]
        alti = dati[fase + 1::2]
        for m in rx_caratteri.finditer(bassi):
            a = m.start()
            # i byte alti dei caratteri devono essere zero
            for z in rx_zeri.finditer(alti[a:m.end()]):
                trovate.append((fase + 2 * (a + z.start()), bassi[a + z.start(): a + z.end()]))
    trovate.sort()
    return trovate


# --------------------------------------------------------------------------
# Cestino: file $I
# --------------------------------------------------------------------------

def cestino(dati):
    """File $I del Cestino -> dizionario con versione, dimensione, ora di
    cancellazione (epoch UTC) e percorso originale. None se non valido."""
    if len(dati) < 28:
        return None
    versione, dimensione, ft = leggi('<qqQ', dati, 0)
    if versione == 2:
        n = leggi('<I', dati, 24)[0]
        if n > 32768:
            return None
        grezzo = dati[28: 28 + n * 2]
    elif versione == 1:
        grezzo = dati[24: 24 + 520]
    else:
        return None
    grezzo = grezzo[:len(grezzo) - (len(grezzo) % 2)]
    percorso = _fino_a_zero(decodifica16(grezzo))
    return {'versione': int(versione), 'dimensione': int(dimensione),
            'ora': filetime_a_epoch(ft), 'percorso': percorso}


# --------------------------------------------------------------------------
# Attivita' pianificate: file XML in System32\Tasks
# --------------------------------------------------------------------------

_ENTITA = {u'amp': u'&', u'lt': u'<', u'gt': u'>', u'quot': u'"', u'apos': u"'"}
_RX_ENTITA = re.compile(u'&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);')
_RX_INNESCO = re.compile(u'<(\\w+Trigger)\\b')


def _sostituisci_entita(m):
    nome = m.group(1)
    try:
        if nome.startswith(u'#x') or nome.startswith(u'#X'):
            return unichr(int(nome[2:], 16))
        if nome.startswith(u'#'):
            return unichr(int(nome[1:]))
    except ERRORI:
        return m.group(0)
    return _ENTITA.get(nome, m.group(0))


def _senza_entita(testo):
    if u'&' not in testo:
        return testo
    return _RX_ENTITA.sub(_sostituisci_entita, testo)


def _blocchi(testo, nome, massimo=64):
    """I contenuti degli elementi <nome ...>...</nome>, in ordine (al
    massimo 'massimo'). Usa solo ricerche di testo semplici: il tempo cresce
    in proporzione alla lunghezza anche quando i tag sono migliaia o non
    vengono mai chiusi (con un'espressione regolare, un file costruito
    apposta terrebbe occupata l'analisi per minuti)."""
    apri = u'<' + nome
    chiudi = u'</' + nome + u'>'
    n = len(apri)
    trovati = []
    pos = 0
    while len(trovati) < massimo:
        a = testo.find(apri, pos)
        if a < 0:
            break
        dopo = testo[a + n: a + n + 1]
        if dopo != u'>' and (dopo == u'' or dopo not in u' \t\r\n'):
            pos = a + n         # un altro nome che inizia allo stesso modo, oppure <nome/>
            continue
        b = testo.find(u'>', a + n)
        if b < 0:
            break
        if testo[b - 1: b] == u'/':
            pos = b + 1         # elemento vuoto: <nome attributo="..." />
            continue
        c = testo.find(chiudi, b + 1)
        if c < 0:
            break               # da qui in poi nessuna chiusura: inutile cercare altre aperture
        trovati.append(testo[b + 1: c])
        pos = c + len(chiudi)
    return trovati


def _tag(testo, nome):
    blocchi = _blocchi(testo, nome, 1)
    if not blocchi:
        return u''
    return _senza_entita(blocchi[0].strip())


def _tutti(testo, nome):
    return [_senza_entita(x.strip()) for x in _blocchi(testo, nome)]


def attivita_xml(dati):
    """Analizza il file XML di un'attivita' pianificata. Restituisce None se
    non e' un'attivita', altrimenti un dizionario:
    autore, data, uri, descrizione, utente, livello, nascosta, abilitata,
    azioni [(comando, argomenti)], com [classid], inneschi [nomi], avvii
    [StartBoundary]."""
    return attivita_da_testo(testo_da_file(dati))


def attivita_da_testo(t):
    """Come attivita_xml, ma parte dal testo gia' decodificato."""
    if u'<Task' not in t:
        return None
    if len(t) > 1024 * 1024:
        t = t[:1024 * 1024]     # un'attivita' vera occupa pochi KB
    r = {'autore': _tag(t, u'Author'), 'data': _tag(t, u'Date'), 'uri': _tag(t, u'URI'),
         'descrizione': _tag(t, u'Description'), 'utente': _tag(t, u'UserId') or _tag(t, u'GroupId'),
         'livello': _tag(t, u'RunLevel'), 'nascosta': False, 'abilitata': True,
         'azioni': [], 'com': [], 'inneschi': [], 'avvii': []}
    impostazioni = _blocchi(t, u'Settings', 1)
    if impostazioni:
        blocco = impostazioni[0]
        r['nascosta'] = _tag(blocco, u'Hidden').lower() == u'true'
        if _tag(blocco, u'Enabled').lower() == u'false':
            r['abilitata'] = False
    for blocco in _blocchi(t, u'Exec'):
        r['azioni'].append((_tag(blocco, u'Command'), _tag(blocco, u'Arguments')))
    for blocco in _blocchi(t, u'ComHandler'):
        r['com'].append(_tag(blocco, u'ClassId'))
    inneschi = _blocchi(t, u'Triggers', 1)
    if inneschi:
        blocco = inneschi[0]
        visti = []
        for nome in _RX_INNESCO.findall(blocco[:200000]):
            if nome not in visti:
                visti.append(nome)
                if len(visti) >= 48:
                    break
        r['inneschi'] = visti
        r['avvii'] = _tutti(blocco, u'StartBoundary')
    return r


# --------------------------------------------------------------------------
# Attivita' pianificate: valore "Actions" in TaskCache\Tasks\{GUID}
# --------------------------------------------------------------------------

def _stringa_con_lunghezza(d, p):
    n = leggi('<I', d, p)[0]
    if n > len(d) - p - 4:
        raise ValueError('lunghezza non valida')
    testo = decodifica16(d[p + 4: p + 4 + n])
    return testo, p + 4 + n


def azioni_taskcache(d):
    """Valore binario Actions -> (contesto, [(tipo, comando, argomenti)]).
    tipo e' 'exec' (comando e argomenti) oppure 'com' (comando = CLSID)."""
    azioni = []
    contesto = u''
    if len(d) < 4:
        return contesto, azioni
    versione = leggi('<H', d, 0)[0]
    p = 2
    try:
        if versione >= 2:
            contesto, p = _stringa_con_lunghezza(d, p)
        while p + 2 <= len(d):
            magia = leggi('<H', d, p)[0]
            p += 2
            if magia == 0x6666:
                _, p = _stringa_con_lunghezza(d, p)
                comando, p = _stringa_con_lunghezza(d, p)
                argomenti, p = _stringa_con_lunghezza(d, p)
                _, p = _stringa_con_lunghezza(d, p)
                if versione >= 3:
                    p += 2
                azioni.append((u'exec', comando, argomenti))
            elif magia == 0x7777:
                _, p = _stringa_con_lunghezza(d, p)
                g = d[p: p + 16]
                p += 16
                dati_com, p = _stringa_con_lunghezza(d, p)
                d1, d2, d3 = leggi('<IHH', g, 0)
                clsid = u'{%08X-%04X-%04X-%s-%s}' % (
                    d1, d2, d3, u''.join([u'%02X' % ord(c) for c in g[8:10]]),
                    u''.join([u'%02X' % ord(c) for c in g[10:16]]))
                azioni.append((u'com', clsid, dati_com))
            else:
                break
    except ERRORI:
        pass
    return contesto, azioni


# --------------------------------------------------------------------------
# ShimCache (AppCompatCache)
# --------------------------------------------------------------------------

def shimcache(d):
    """Valore AppCompatCache -> (formato, [voci]). Ogni voce e' un dizionario
    con percorso, modificato (epoch dell'ultima modifica del file) ed
    eseguito (True/False su Windows 7-8.1, None dove il dato non esiste).
    L'ordine e' quello della cache: dalla voce piu' recente."""
    voci = []
    if len(d) < 16:
        return u'', voci
    magia = leggi('<I', d, 0)[0]
    try:
        if magia == 0xBADC0FEE:
            return u'Windows 7 / Server 2008 R2', _shim_nt61(d)
        if magia == 0xBADC0FFE:
            return u'Windows Vista / Server 2008', _shim_nt60(d)
        if magia in (0x30, 0x34) and d[magia:magia + 4] == '10ts':
            return u'Windows 10 / 11 / Server 2016+', _shim_ts(d, magia, False)
        if d[0x80:0x84] in ('00ts', '10ts'):
            return u'Windows 8 / 8.1 / Server 2012', _shim_ts(d, 0x80, True)
        # ultima risorsa: cerca la prima firma
        p = d.find('10ts', 0, 0x400)
        if p > 0:
            return u'Windows 10 / 11 / Server 2016+', _shim_ts(d, p, False)
    except ERRORI:
        pass
    return u'', voci


def _shim_ts(d, p, win8):
    voci = []
    n = len(d)
    while p + 14 <= n:
        firma = d[p:p + 4]
        if firma != '10ts' and firma != '00ts':
            break
        dim = leggi('<I', d, p + 8)[0]
        fine = p + 12 + dim
        if dim < 2 or fine > n:
            break
        lung = leggi('<H', d, p + 12)[0]
        q = p + 14
        percorso = decodifica16(d[q: q + lung])
        q += lung
        if u'\t' in percorso:
            # voce di un'app dello Store: non e' un percorso di file
            p = fine
            continue
        eseguito = None
        if win8:
            pacchetto = leggi('<H', d, q)[0]
            q += 2 + pacchetto
            flag = leggi('<I', d, q)[0]
            eseguito = bool(flag & 2)
            q += 8
        modificato = 0.0
        if q + 8 <= fine:
            modificato = filetime_a_epoch(leggi('<Q', d, q)[0])
        voci.append({'percorso': percorso, 'modificato': modificato, 'eseguito': eseguito})
        p = fine
    return voci


def _shim_nt61(d):
    voci = []
    quante = leggi('<I', d, 4)[0]
    base = 0x80
    lung, massimo, riempimento = leggi('<HHI', d, base)
    a64 = (massimo - lung == 2 and riempimento == 0)
    passo = 48 if a64 else 32
    for i in xrange(min(quante, 4096)):
        p = base + i * passo
        if p + passo > len(d):
            break
        if a64:
            lung, _, _, pos, ft, flag = leggi('<HHIQQI', d, p)
        else:
            lung, _, pos, ft, flag = leggi('<HHIQI', d, p)
        if pos + lung > len(d) or lung == 0:
            continue
        percorso = decodifica16(d[pos: pos + lung])
        voci.append({'percorso': percorso, 'modificato': filetime_a_epoch(ft),
                     'eseguito': bool(flag & 2)})
    return voci


def _shim_nt60(d):
    voci = []
    quante = leggi('<I', d, 4)[0]
    base = 8
    lung, massimo, riempimento = leggi('<HHI', d, base)
    a64 = (massimo - lung == 2 and riempimento == 0)
    passo = 32 if a64 else 24
    for i in xrange(min(quante, 4096)):
        p = base + i * passo
        if p + passo > len(d):
            break
        if a64:
            lung, _, _, pos, ft, flag = leggi('<HHIQQI', d, p)
        else:
            lung, _, pos, ft, flag = leggi('<HHIQI', d, p)
        if pos + lung > len(d) or lung == 0:
            continue
        percorso = decodifica16(d[pos: pos + lung])
        voci.append({'percorso': percorso, 'modificato': filetime_a_epoch(ft),
                     'eseguito': bool(flag & 2)})
    return voci


# --------------------------------------------------------------------------
# UserAssist
# --------------------------------------------------------------------------

_ROT13 = {}
for _i in xrange(26):
    _ROT13[ord(u'a') + _i] = unichr(ord(u'a') + (_i + 13) % 26)
    _ROT13[ord(u'A') + _i] = unichr(ord(u'A') + (_i + 13) % 26)

CARTELLE_NOTE = {
    u'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}': u'C:\\Windows\\System32',
    u'{6D809377-6AF0-444B-8957-A3773F02200E}': u'C:\\Program Files',
    u'{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}': u'C:\\Program Files (x86)',
    u'{F38BF404-1D43-42F2-9305-67DE0B28FC23}': u'C:\\Windows',
    u'{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}': u'C:\\Windows\\SysWOW64',
    u'{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}': u'[Menu Start comune]',
    u'{9E3995AB-1F9C-4F13-B827-48B24B6C7174}': u'[Elementi fissati]',
    u'{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}': u'[Menu Start utente]',
}


def userassist_nome(nome):
    """Decodifica (ROT13) il nome di un valore UserAssist e sostituisce i
    GUID delle cartelle note."""
    chiaro = nome.translate(_ROT13)
    if chiaro.startswith(u'{') and len(chiaro) > 38 and chiaro[37] == u'}':
        cartella = CARTELLE_NOTE.get(chiaro[:38].upper())
        if cartella:
            chiaro = cartella + chiaro[38:]
    return chiaro


def userassist_dati(d):
    """Dati di un valore UserAssist -> (numero di avvii, ultimo avvio epoch).
    None se il formato non e' riconosciuto."""
    if len(d) >= 68:
        conteggio = leggi('<I', d, 4)[0]
        ultimo = filetime_a_epoch(leggi('<Q', d, 60)[0])
        return int(conteggio), ultimo
    if len(d) == 16:
        conteggio = leggi('<I', d, 4)[0]
        ultimo = filetime_a_epoch(leggi('<Q', d, 8)[0])
        if conteggio >= 5:
            conteggio -= 5
        return int(conteggio), ultimo
    return None


# --------------------------------------------------------------------------
# SAM: account locali e gruppi
# --------------------------------------------------------------------------

def sam_utenti(hive):
    """Account locali dall'hive SAM. Lista di dizionari: rid, nome,
    nome_completo, commento, creato, ultimo_accesso, password_impostata,
    ultimo_fallito, accessi, disattivato, senza_password."""
    utenti = []
    base = hive.apri(u'SAM\\Domains\\Account\\Users')
    if base is None:
        return utenti
    creati = {}
    nomi = base.sottochiave(u'Names')
    if nomi is not None:
        for k in nomi.sottochiavi():
            for v in k.valori():
                if v.nome == u'':
                    creati[v.tipo & 0xFFFFFFFF] = (k.nome, k.orario)
    for k in base.sottochiavi():
        if k.nome.lower() == u'names':
            continue
        try:
            rid = int(k.nome, 16)
        except ValueError:
            continue
        u = {'rid': rid, 'nome': u'', 'nome_completo': u'', 'commento': u'', 'creato': 0.0,
             'ultimo_accesso': 0.0, 'password_impostata': 0.0, 'ultimo_fallito': 0.0,
             'accessi': 0, 'disattivato': False, 'senza_password': False, 'modificato': k.orario}
        f = k.valore(u'F')
        if f is not None and len(f.dati) >= 0x44:
            d = f.dati
            u['ultimo_accesso'] = filetime_a_epoch(leggi('<Q', d, 0x08)[0])
            u['password_impostata'] = filetime_a_epoch(leggi('<Q', d, 0x18)[0])
            u['ultimo_fallito'] = filetime_a_epoch(leggi('<Q', d, 0x28)[0])
            acb = leggi('<H', d, 0x38)[0]
            u['disattivato'] = bool(acb & 0x0001)
            u['senza_password'] = bool(acb & 0x0004)
            u['accessi'] = leggi('<H', d, 0x42)[0]
        v = k.valore(u'V')
        if v is not None and len(v.dati) >= 0xCC:
            d = v.dati
            campi = []
            for inizio in (0x0C, 0x18, 0x24):
                pos, lung = leggi('<II', d, inizio)
                pezzo = d[0xCC + pos: 0xCC + pos + lung]
                campi.append(decodifica16(pezzo[:len(pezzo) - (len(pezzo) % 2)]))
            u['nome'], u['nome_completo'], u['commento'] = campi
        if rid in creati:
            if not u['nome']:
                u['nome'] = creati[rid][0]
            u['creato'] = creati[rid][1]
        utenti.append(u)
    utenti.sort(key=lambda x: x['rid'])
    return utenti


def sam_sid_macchina(hive):
    """Il SID della macchina (S-1-5-21-a-b-c), dal valore V di
    SAM\\Domains\\Account. '' se non si trova."""
    k = hive.apri(u'SAM\\Domains\\Account')
    if k is None:
        return u''
    v = k.valore(u'V')
    if v is None or len(v.dati) < 12:
        return u''
    a, b, c = leggi('<III', v.dati, len(v.dati) - 12)
    return u'S-1-5-21-%d-%d-%d' % (a, b, c)


def sam_gruppo(hive, rid):
    """Membri (SID) di un gruppo locale predefinito, per esempio 544 per
    Administrators e 555 per Remote Desktop Users. Restituisce (nome, [sid])."""
    k = hive.apri(u'SAM\\Domains\\Builtin\\Aliases\\%08X' % rid)
    if k is None:
        return u'', []
    v = k.valore(u'C')
    if v is None or len(v.dati) < 0x34:
        return u'', []
    d = v.dati
    pos_nome, lung_nome = leggi('<II', d, 0x10)
    nome = decodifica16(d[0x34 + pos_nome: 0x34 + pos_nome + lung_nome])
    pos_membri = leggi('<I', d, 0x28)[0]
    quanti = leggi('<I', d, 0x30)[0]
    sid = []
    p = 0x34 + pos_membri
    for _ in xrange(min(quanti, 500)):
        if p + 8 > len(d) or ord(d[p]) != 1 or ord(d[p + 1]) > 15:
            break
        testo, lung = testo_sid(d, p)
        sid.append(testo)
        p += lung
    return nome, sid


# --------------------------------------------------------------------------
# File PE: informazioni di versione
# --------------------------------------------------------------------------

_CHIAVI_VERSIONE = (u'CompanyName', u'ProductName', u'OriginalFilename', u'InternalName',
                    u'FileDescription')


def pe_versione(leggi_fn, dimensione):
    """Legge le stringhe di versione di un eseguibile senza caricarlo tutto.
    leggi_fn(posizione, quanti) restituisce i byte. Risultato: dizionario
    con le chiavi trovate tra CompanyName, ProductName, OriginalFilename,
    InternalName, FileDescription. None se il file non e' un PE."""
    testa = leggi_fn(0, 4096)
    if len(testa) < 0x40 or testa[:2] != 'MZ':
        return None
    e = leggi('<I', testa, 0x3C)[0]
    if e + 24 > len(testa):
        if e > dimensione or e > 0x100000:
            return None
        testa = leggi_fn(0, e + 4096)
        if e + 24 > len(testa):
            return None
    if testa[e:e + 4] != 'PE\x00\x00':
        return None
    n_sezioni = leggi('<H', testa, e + 6)[0]
    dim_opzionale = leggi('<H', testa, e + 20)[0]
    tabella = e + 24 + dim_opzionale
    risultato = {}
    for i in xrange(min(n_sezioni, 96)):
        s = tabella + 40 * i
        if s + 40 > len(testa):
            break
        if not testa[s:s + 8].startswith('.rsrc'):
            continue
        _, ind_virtuale, dim_grezza, pos_grezza = leggi('<IIII', testa, s + 8)
        try:
            blocco = _risorsa_versione(leggi_fn, pos_grezza, dim_grezza, ind_virtuale)
        except IOError:
            raise           # il file non si legge: lo deve sapere chi chiama
        except ERRORI:
            blocco = None
        if blocco:
            risultato = _stringhe_versione(blocco)
        break
    return risultato


def _risorsa_versione(leggi_fn, base, dim, ind_virtuale):
    """Scende nell'albero delle risorse fino a RT_VERSION (tipo 16)."""
    def cartella(pos_rel):
        d = leggi_fn(base + pos_rel, 16)
        if len(d) < 16:
            return []
        con_nome, con_id = leggi('<HH', d, 12)
        quante = min(con_nome + con_id, 512)
        d = leggi_fn(base + pos_rel + 16, quante * 8)
        voci = []
        for i in xrange(len(d) // 8):
            voci.append(leggi('<II', d, i * 8))
        return voci

    scelta = None
    for ident, pos in cartella(0):
        if ident == 16:
            scelta = pos
            break
    if scelta is None:
        return None
    for _ in xrange(2):
        if not (scelta & 0x80000000):
            break
        voci = cartella(scelta & 0x7FFFFFFF)
        if not voci:
            return None
        scelta = voci[0][1]
    if scelta & 0x80000000:
        return None
    d = leggi_fn(base + scelta, 16)
    if len(d) < 8:
        return None
    rva, lung = leggi('<II', d, 0)
    pos = base + (rva - ind_virtuale)
    if rva < ind_virtuale or lung > 0x40000:
        return None
    return leggi_fn(pos, lung)


def _stringhe_versione(blocco):
    risultato = {}
    for chiave in _CHIAVI_VERSIONE:
        ago = (chiave + u'\x00').encode('utf-16-le')
        p = blocco.find(ago)
        if p < 6:
            continue
        lung_valore = leggi('<H', blocco, p - 4)[0]
        if lung_valore == 0 or lung_valore > 2048:
            continue
        q = p + len(ago)
        q += (4 - (q % 4)) % 4
        grezzo = blocco[q: q + lung_valore * 2]
        testo = _fino_a_zero(decodifica16(grezzo[:len(grezzo) - (len(grezzo) % 2)])).strip()
        if testo:
            risultato[chiave] = testo
    return risultato


# --------------------------------------------------------------------------
# Collegamenti .lnk
# --------------------------------------------------------------------------

def _stringa_c(d, p):
    fine = d.find('\x00', p)
    if fine < 0:
        fine = len(d)
    return d[p:fine].decode('cp1252', 'replace')


def collegamento(d):
    """File .lnk -> dizionario con destinazione, argomenti, relativo,
    cartella, descrizione. None se non e' un collegamento."""
    if len(d) < 76 or leggi('<I', d, 0)[0] != 0x4C:
        return None
    flag = leggi('<I', d, 0x14)[0]
    r = {'destinazione': u'', 'argomenti': u'', 'relativo': u'', 'cartella': u'', 'descrizione': u''}
    p = 76
    try:
        if flag & 0x01:
            p += 2 + leggi('<H', d, p)[0]
        if flag & 0x02:
            dim, dim_testa, flag_info, _, pos_locale, pos_rete, pos_resto = leggi('<7I', d, p)
            resto = _stringa_c(d, p + pos_resto) if pos_resto else u''
            if flag_info & 1 and pos_locale:
                r['destinazione'] = _stringa_c(d, p + pos_locale) + resto
            elif flag_info & 2 and pos_rete:
                pos_nome = leggi('<I', d, p + pos_rete + 8)[0]
                rete = _stringa_c(d, p + pos_rete + pos_nome)
                r['destinazione'] = rete + (u'\\' + resto if resto else u'')
            p += dim
        for nome, bit in (('descrizione', 0x04), ('relativo', 0x08), ('cartella', 0x10),
                          ('argomenti', 0x20), (None, 0x40)):
            if not (flag & bit):
                continue
            n = leggi('<H', d, p)[0]
            p += 2
            if flag & 0x80:
                testo = decodifica16(d[p: p + n * 2])
                p += n * 2
            else:
                testo = d[p: p + n].decode('cp1252', 'replace')
                p += n
            if nome:
                r[nome] = testo
    except ERRORI:
        pass
    return r


# --------------------------------------------------------------------------
# WMI: sottoscrizioni permanenti in OBJECTS.DATA
# --------------------------------------------------------------------------

_RX_LEGAME_C = re.compile(r'([A-Za-z_0-9]{0,40}EventConsumer)\.Name="([^"\x00]{1,260})"')
_RX_LEGAME_F = re.compile(r'__EventFilter\.Name="([^"\x00]{1,260})"')
_RX_STRINGA = re.compile(r'\x00([\x09\x0a\x0d\x20-\x7e]{2,})(?=\x00)')
_RX_HASH = re.compile(r'(?:[0-9A-F]\x00){32}')     # serve solo l'inizio: nessuna ripetizione illimitata
_DIM_PEZZO = 8 * 1024 * 1024
_SOVRAPPOSIZIONE = 4096


class Elenco(list):
    """Una lista di risultati che dice anche se e' completa: completo e'
    falso quando la lettura si e' fermata a uno dei tetti (file rovinato, o
    costruito apposta per far lavorare a vuoto chi lo legge)."""
    completo = True


_AGO_LEGAME = 'EventConsumer.Name="'
_AGO_COMANDO = '\x00CommandLineEventConsumer\x00'
_AGO_SCRIPT = '\x00ActiveScriptEventConsumer\x00'
_AGO_FILTRO = '\x00__EventFilter\x00'
# Tetti: un repository normale ha poche sottoscrizioni e poche decine di
# oggetti che le riguardano. Senza tetti un file rovinato, o costruito
# apposta, terrebbe occupato il triage per ore.
_MAX_POSIZIONI = 2000       # posizioni tenute per ciascuna stringa cercata (di norma una decina)
_MAX_LEGAMI = 200           # sottoscrizioni diverse (di norma due o tre)
_MAX_OGGETTI = 200          # oggetti letti per intero, in tutto
_MAX_COPIE = 16             # copie dello stesso oggetto (il file tiene anche quelle vecchie)
_DIM_OGGETTO = 32 * 1024    # di un consumer si guardano i primi 32 KB: lo script puo' essere lungo, ma ne basta l'inizio


def _cerca_aghi(leggi_fn, dimensione, aghi, massimo=_MAX_POSIZIONI):
    """Cerca piu' stringhe in un file grande leggendolo a pezzi, una volta
    sola. Restituisce (posizioni per stringa, completo): di ogni stringa si
    tengono al massimo 'massimo' posizioni."""
    trovati = {}
    for ago in aghi:
        trovati[ago] = []
    completo = True
    pos = 0
    while pos < dimensione:
        pezzo = leggi_fn(pos, _DIM_PEZZO + _SOVRAPPOSIZIONE)
        if not pezzo:
            break
        for ago in aghi:
            lista = trovati[ago]
            p = pezzo.find(ago)
            while p >= 0:
                if p < _DIM_PEZZO:
                    if len(lista) >= massimo:
                        completo = False
                        break
                    lista.append(pos + p)
                p = pezzo.find(ago, p + 1)
        pos += _DIM_PEZZO
    return trovati, completo


def _nomi_in_testa(testa):
    """Le stringhe che stanno, per intero, tra due byte nulli all'inizio di un oggetto."""
    nomi = testa.split('\x00')
    if testa[-1:] != '\x00':
        nomi = nomi[:-1]        # l'ultima e' tagliata dalla fine della finestra
    return [n for n in nomi[1:] if n]


def wmi_sottoscrizioni(leggi_fn, dimensione):
    """Cerca in OBJECTS.DATA i legami filtro-consumer (FilterToConsumerBinding)
    e, per i consumer che eseguono comandi o script, il loro contenuto.
    Il file contiene anche oggetti gia' cancellati: una voce trovata qui puo'
    non essere piu' attiva.
    Restituisce una lista (Elenco) di dizionari: tipo, nome, filtro,
    interrogazione, testo (comando o script del consumer). Il file viene
    letto una volta sola e ogni passo ha un tetto: se uno viene raggiunto
    l'elenco ha completo = False."""
    risultato = Elenco()
    trovati, completo = _cerca_aghi(leggi_fn, dimensione, [_AGO_LEGAME, _AGO_COMANDO, _AGO_SCRIPT, _AGO_FILTRO])
    legami = {}
    for pos in trovati[_AGO_LEGAME]:
        inizio = max(0, pos - 48)
        finestra = leggi_fn(inizio, 1024)
        m = _RX_LEGAME_C.search(finestra)
        if m is None:
            continue
        tipo, nome = m.group(1), m.group(2)
        f = _RX_LEGAME_F.search(finestra, m.end())
        if f is None:
            f = _RX_LEGAME_F.search(finestra)
        filtro = f.group(1) if f is not None else ''
        chiave = (tipo, nome)
        if chiave not in legami:
            if len(legami) >= _MAX_LEGAMI:
                completo = False
                continue
            legami[chiave] = {'tipo': tipo.decode('latin-1'), 'nome': nome.decode('latin-1'),
                              'filtro': filtro.decode('latin-1'), 'interrogazione': u'', 'testo': u'',
                              'filtro_grezzo': filtro}
        elif filtro and not legami[chiave]['filtro']:
            legami[chiave]['filtro'] = filtro.decode('latin-1')
            legami[chiave]['filtro_grezzo'] = filtro
    if not legami:
        risultato.completo = completo
        return risultato
    # il contenuto dei consumer che eseguono comandi o script
    letti = 0
    copie = {}
    for ago in (_AGO_COMANDO, _AGO_SCRIPT):
        tipo = ago.strip('\x00')
        if not [1 for t, _ in legami if t == tipo]:
            continue
        for pos in trovati[ago]:
            base = pos + len(ago) - 1
            finestra = None
            for nome in _nomi_in_testa(leggi_fn(base, 200)):
                voce = legami.get((tipo, nome))
                if voce is None:
                    continue
                viste = copie.get((tipo, nome), 0)
                if viste >= _MAX_COPIE:
                    continue
                copie[(tipo, nome)] = viste + 1
                if finestra is None:
                    if letti >= _MAX_OGGETTI:
                        completo = False
                        break
                    letti += 1
                    finestra = leggi_fn(base, _DIM_OGGETTO)
                p = finestra.find('\x00' + nome + '\x00', 0, 200)
                if p < 0:
                    continue
                coda = finestra[p + len(nome) + 1:]
                taglio = _RX_HASH.search(coda)
                if taglio is not None:
                    coda = coda[:taglio.start()]
                pezzi = [x for x in _RX_STRINGA.findall(coda)]
                testo = u'\n'.join([x.decode('latin-1').strip() for x in pezzi if x.strip()])
                if len(testo) > len(voce['testo']):
                    voce['testo'] = testo
    # l'interrogazione dei filtri
    per_filtro = {}
    for voce in legami.values():
        if voce['filtro_grezzo']:
            per_filtro.setdefault(voce['filtro_grezzo'], []).append(voce)
    if per_filtro:
        letti = 0
        for pos in trovati[_AGO_FILTRO]:
            base = pos + len(_AGO_FILTRO) - 1
            finestra = None
            for nome in _nomi_in_testa(leggi_fn(base, 400)):
                voci = per_filtro.get(nome)
                if not voci or not [v for v in voci if not v['interrogazione']]:
                    continue
                if finestra is None:
                    if letti >= _MAX_OGGETTI:
                        completo = False
                        break
                    letti += 1
                    finestra = leggi_fn(base, 8192)
                p = finestra.find('\x00' + nome + '\x00', 0, 400)
                if p < 0:
                    continue
                coda = finestra[p + len(nome) + 1:]
                taglio = _RX_HASH.search(coda)
                if taglio is not None:
                    coda = coda[:taglio.start()]
                for x in _RX_STRINGA.findall(coda):
                    if 'select' in x.lower():
                        for voce in voci:
                            if not voce['interrogazione']:
                                voce['interrogazione'] = x.decode('latin-1').strip()
                        break
    for voce in legami.values():
        del voce['filtro_grezzo']
        risultato.append(voce)
    risultato.sort(key=lambda v: (v['tipo'], v['nome']))
    risultato.completo = completo
    return risultato


# --------------------------------------------------------------------------
# CryptnetUrlCache
# --------------------------------------------------------------------------

_RX_URL_IN_STRINGA = re.compile(r'(?:https?|ftp)://[\x21-\x7e]+', re.I)


def url_da_metadata(dati):
    """Dal file in CryptnetUrlCache\\MetaData: l'URL da cui e' stato
    scaricato il contenuto ('' se non trovato)."""
    for _, testo in stringhe_utf16(dati, 8, con_spazio=False):
        m = _RX_URL_IN_STRINGA.search(testo)
        if m is not None:
            return m.group(0)[:2048].decode('latin-1')
    return u''


def tipo_contenuto(inizio):
    """Riconosce dai primi byte che cosa contiene un file: 'eseguibile',
    'archivio', 'script', 'pagina HTML' oppure ''."""
    if inizio[:2] == 'MZ':
        return u'eseguibile'
    if inizio[:4] in ('PK\x03\x04', 'Rar!') or inizio[:6] == '7z\xbc\xaf\x27\x1c':
        return u'archivio'
    basso = inizio[:4000].lower()
    if inizio[:2] in ('\xff\xfe', '\xfe\xff'):
        basso = inizio[2:4000].replace('\x00', '').lower()
    testa = basso.lstrip('\xef\xbb\xbf \t\r\n')[:300]
    if testa.startswith('<!doctype html') or testa.startswith('<html'):
        # la pagina di un captive portal o di un proxy finisce spesso in questa
        # cache: conta come script solo se contiene codice che agisce sul sistema
        for segno in ('activexobject', 'wscript', 'powershell', 'createobject', 'hta:application', 'vbscript',
                      'shell.application', 'frombase64'):
            if segno in basso:
                return u'script'
        return u'pagina HTML'
    for segno in ('powershell', '<script', 'wscript.', 'createobject(', 'function ', '@echo off',
                  'invoke-', 'iex ', 'iex(', '#!/', 'cmd /c', 'cmd.exe'):
        if segno in basso[:300]:
            return u'script'
    return u''


# --------------------------------------------------------------------------
# AnyDesk
# --------------------------------------------------------------------------

_RX_AD_CONN = re.compile(u'^(Incoming|Outgoing)\\s+(\\d{4}-\\d{2}-\\d{2}),\\s*(\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+)(?:\\s+(\\S+))?')
_RX_AD_RIGA = re.compile(u'^\\s*\\w+\\s+(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})')
_RX_AD_IP = re.compile(u'Logged in from ([0-9a-fA-F.:x]+?):(\\d+) on relay')
_RX_AD_ID = re.compile(u'Client-ID: (\\d+)')


def _epoch(testo, formato):
    try:
        return float(calendar.timegm(time.strptime(testo, formato)))
    except ERRORI:
        return 0.0


def anydesk_connessioni(dati):
    """connection_trace.txt -> lista di dizionari: verso ('Incoming' o
    'Outgoing'), ora (epoch UTC), modo (User, Passwd, Token), id."""
    voci = []
    for riga in testo_da_file(dati).splitlines():
        m = _RX_AD_CONN.match(riga.strip())
        if m is None:
            continue
        voci.append({'verso': m.group(1), 'ora': _epoch(m.group(2) + u' ' + m.group(3), '%Y-%m-%d %H:%M'),
                     'modo': m.group(4), 'id': m.group(5)})
    return voci


def anydesk_traccia(dati):
    """ad.trace / ad_svc.trace -> lista di dizionari con ora, tipo e valore.
    tipo: 'ip' (indirizzo da cui si e' collegato l'altro capo), 'id'
    (Client-ID remoto), 'richiesta' (Incoming session request), 'file'
    (trasferimento di file)."""
    voci = []
    for riga in testo_da_file(dati).splitlines():
        if u'Logged in from' in riga:
            tipo, m = 'ip', _RX_AD_IP.search(riga)
        elif u'Client-ID:' in riga:
            tipo, m = 'id', _RX_AD_ID.search(riga)
        elif u'Incoming session request' in riga:
            tipo, m = 'richiesta', None
        elif u'Preparing files' in riga or u'file_transfer' in riga.lower():
            tipo, m = 'file', None
        else:
            continue
        t = _RX_AD_RIGA.match(riga)
        ora = _epoch(t.group(1), '%Y-%m-%d %H:%M:%S') if t is not None else 0.0
        if m is not None:
            valore = m.group(1)
        elif u' - ' in riga:
            valore = riga.split(u' - ', 1)[1].strip()[:200]
        else:
            valore = riga.strip()[-200:]
        voci.append({'ora': ora, 'tipo': tipo, 'valore': valore})
    return voci


# --------------------------------------------------------------------------
# TeamViewer
# --------------------------------------------------------------------------

_RX_TV_DATA = re.compile(u'^(\\d{2}-\\d{2}-\\d{4} \\d{2}:\\d{2}:\\d{2})$')
_RX_TV_PUNCH = re.compile(u'punch received a=([0-9a-fA-F.:\\[\\]]+?):(\\d+):')
_RX_TV_RIGA = re.compile(u'^(\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2})')


def teamviewer_connessioni(dati, in_entrata):
    """Connections_incoming.txt (in_entrata=True) oppure Connections.txt.
    Lista di dizionari: id, nome, inizio, fine (epoch UTC), utente, tipo."""
    voci = []
    for riga in testo_da_file(dati).splitlines():
        campi = [c.strip() for c in riga.split(u'\t')]
        campi = [c for c in campi if c != u'']
        if len(campi) < 4:
            continue
        date = [i for i, c in enumerate(campi) if _RX_TV_DATA.match(c)]
        if len(date) < 1:
            continue
        v = {'id': campi[0], 'nome': u'', 'inizio': _epoch(campi[date[0]], '%d-%m-%Y %H:%M:%S'),
             'fine': 0.0, 'utente': u'', 'tipo': u''}
        if date[0] > 1:
            v['nome'] = campi[1]
        ultimo = date[0]
        if len(date) > 1:
            v['fine'] = _epoch(campi[date[1]], '%d-%m-%Y %H:%M:%S')
            ultimo = date[1]
        resto = campi[ultimo + 1:]
        if len(resto) >= 1:
            v['utente'] = resto[0]
        if len(resto) >= 2:
            v['tipo'] = resto[1]
        voci.append(v)
    return voci


def teamviewer_log(dati):
    """TeamViewerNN_Logfile.log -> [(ora epoch (ora locale della macchina),
    indirizzo IP remoto)] dalle righe 'punch received'."""
    voci = []
    for riga in testo_da_file(dati).splitlines():
        if u'punch received' not in riga:
            continue
        m = _RX_TV_PUNCH.search(riga)
        if m is None:
            continue
        t = _RX_TV_RIGA.match(riga)
        ora = _epoch(t.group(1), '%Y/%m/%d %H:%M:%S') if t is not None else 0.0
        voci.append((ora, m.group(1)))
    return voci


# --------------------------------------------------------------------------
# Defender: file di DetectionHistory
# --------------------------------------------------------------------------

_RX_MINACCIA = re.compile(u'^[A-Za-z]{3,24}:[A-Za-z0-9_]{2,16}/[\\w.!\\-]{2,60}$')


def rilevamento_defender(dati):
    """File di DetectionHistory di Defender -> (nomi delle minacce, risorse
    coinvolte: file o righe di comando)."""
    minacce = []
    risorse = []
    for _, grezzo in stringhe_utf16(dati, 6):
        s = grezzo.decode('latin-1')
        if _RX_MINACCIA.match(s):
            if s not in minacce:
                minacce.append(s)
        elif len(s) > 3 and (s[1:3] == u':\\' or s.startswith(u'\\\\')):
            if s not in risorse:
                risorse.append(s)
    return minacce, risorse
