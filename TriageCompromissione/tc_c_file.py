# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_c_file - Controlli che leggono file del disco: Prefetch, attivita'
pianificate, cartelle di esecuzione automatica, WMI, CryptnetUrlCache,
residui di Impacket, strumenti di accesso remoto, antivirus, cartelle di
appoggio, Cestino, copie shadow.
"""

import re

import tc_prefetch
import tc_artefatti
import tc_c_registro
import tc_regole as R
import tc_origine
from tc_base import testo_orario as T, ERRORI, INVERSIONE
from tc_lingua import tr

_ESTENSIONI_PROGRAMMI = [u'exe', u'dll', u'ps1', u'bat', u'cmd', u'vbs', u'vbe', u'js', u'jse', u'hta', u'scr',
                         u'msi', u'wsf', u'com', u'pif']
_ESTENSIONI_ARCHIVI = [u'zip', u'7z', u'rar', u'tar', u'gz', u'cab', u'iso', u'img', u'vhd', u'vhdx']
_ESTENSIONI_INNOCUE = [u'txt', u'dat', u'log', u'jpg', u'jpeg', u'png', u'gif', u'bmp', u'pdf', u'doc', u'docx',
                       u'xls', u'xlsx', u'csv', u'ico', u'cfg', u'ini', u'xml', u'json', u'db', u'mp3', u'mp4']
_RX_OTTO_BAT = re.compile(u'^[A-Za-z]{8}\\.bat$')
_RX_OTTO_TMP = re.compile(u'^[A-Za-z]{8}\\.tmp$')
_RX_OTTO_EXE = re.compile(u'^[A-Za-z]{8}\\.exe$')
_RX_USCITA_WMIEXEC = re.compile(u'^__\\d{9,10}\\.\\d{1,7}$')
_PEZZO_LOG = 4 * 1024 * 1024
_GUID_SHADOW = u'{3808876b-c176-4e48-b7ae-04046e6cc752}'
_WMI_INNOCUI = set([(u'nteventlogeventconsumer', u'scm event log consumer'),
                    (u'commandlineeventconsumer', u'bvtconsumer')])
_RX_WMI_FORTE = re.compile(u'(powershell|cmd(\\.exe)?\\s+/c|wscript\\.shell|win32_process|xmlhttp|https?://'
                           u'|frombase64|base64|\\.run\\b|shellexecute|rundll32|regsvr32|mshta|certutil|bitsadmin'
                           u'|\\.terminate\\(|downloadstring|downloadfile|\\.create\\()', re.I)


def _utente_da_cartella(cartella):
    """Il nome del profilo in un percorso .../Users/<nome>/... ('' se non c'e')."""
    parti = cartella.split(u'/')
    for i, p in enumerate(parti[:-1]):
        if p.lower() == u'users' and parti[i + 1]:
            return parti[i + 1]
    return u''


def _dimensione(n):
    if n >= 1024 * 1024 * 1024:
        return u'%.1f GB' % (n / (1024.0 * 1024 * 1024))
    if n >= 1024 * 1024:
        return u'%.1f MB' % (n / (1024.0 * 1024))
    if n >= 1024:
        return u'%d KB' % (n / 1024)
    return tr(u'%d byte') % n


def _righe_con(t, e, marcatori, massimo=512 * 1024 * 1024):
    """Le righe di un log di testo che contengono almeno uno dei marcatori
    (byte, in minuscolo), riunite in un solo blocco di byte. Il file viene
    letto a pezzi, cosi' un log di centinaia di MB non finisce tutto in
    memoria; dei file piu' grandi di 'massimo' si legge solo la parte
    finale, la piu' recente. Restituisce None se il file non si legge."""
    if e.dimensione == 0:
        return None
    rx = re.compile('|'.join([re.escape(m) for m in marcatori]))
    buone = []

    def esamina(blocco):
        basso = blocco.lower()
        p = 0
        while p < len(basso):
            m = rx.search(basso, p)
            if m is None:
                break
            inizio = basso.rfind('\n', 0, m.start()) + 1
            fine = basso.find('\n', m.end())
            if fine < 0:
                fine = len(basso)
            buone.append(blocco[inizio:fine])
            p = fine + 1

    try:
        testa = e.leggi(0, 4096)
        if testa[:2] in ('\xff\xfe', '\xfe\xff') or (len(testa) >= 8 and testa[1:400:2].count('\x00') > len(testa[:400]) / 4):
            # UTF-16: i marcatori non si possono cercare nei byte. Si legge
            # il file intero, ma solo se non e' enorme.
            if e.dimensione > 48 * 1024 * 1024:
                return None
            return e.tutto()
        resto = ''
        pos = max(0, e.dimensione - massimo)
        while pos < e.dimensione:
            pezzo = e.leggi(pos, _PEZZO_LOG)
            if not pezzo:
                break
            pos += len(pezzo)
            pezzo = resto + pezzo
            taglio = pezzo.rfind('\n')
            if taglio < 0:
                # nessun a capo in piu' di 4 MB: non e' un log normale. Si
                # tiene solo la coda, per non accumulare tutto in memoria.
                resto = pezzo[-65536:]
                continue
            esamina(pezzo[:taglio])
            resto = pezzo[taglio + 1:]
        if resto:
            esamina(resto)          # l'ultima riga, senza a capo finale
        return '\n'.join(buone)
    except ERRORI, errore:
        t.non_letto(e, errore)
        return None
    finally:
        e.chiudi()


# --------------------------------------------------------------------------
# Prefetch (controllo 21)
# --------------------------------------------------------------------------

def prefetch(t):
    trovati = t.radice.file(u'windows/prefetch/', u'%.pf', ovunque=True)
    server = t.contesto.get('server')
    attivo = t.contesto.get('prefetch_attivo', True)
    if not trovati:
        if t.radice.piatta:
            t.esito(21, 'assente', tr(u'nessun file .pf trovato'))
            return
        cartella = t.radice.file(u'windows/', u'prefetch', cartelle=True)
        if not cartella:
            t.esito(21, 'assente', tr(u'cartella Windows\\Prefetch non trovata'))
        elif server:
            t.esito(21, 'fatto', tr(u'cartella vuota: sui Windows Server il Prefetch \u00e8 spento di default'))
        else:
            t.fatto(21)
            t.segnala(21, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                      tr(u'La cartella Prefetch \u00e8 vuota su un Windows client') +
                      (u'' if attivo else tr(u' (il Prefetch \u00e8 disattivato nel registro: EnablePrefetcher = 0)')),
                      tr(u'Su un client in uso la cartella contiene centinaia di file: vuota, \u00e8 stata ripulita '
                      u'oppure il Prefetch \u00e8 stato spento.'), 0, cartella[0], oggetti=(R.chiave(u'prefetch', u'svuotato'),))
        return
    letti = 0
    errori = 0
    for i, e in enumerate(trovati):
        if t.annullato():
            return
        if i % 100 == 0:
            t.avanza(tr(u'Prefetch: %d di %d') % (i, len(trovati)))
        if e.dimensione < 100:
            continue
        if e.dimensione > 8 * 1024 * 1024:
            errori += 1         # un .pf vero non arriva a 1 MB
            continue
        dati = t.contenuto(e)
        if dati is None:
            errori += 1
            continue
        try:
            pf = tc_prefetch.Prefetch(dati)
        except ERRORI:
            errori += 1
            continue
        letti += 1
        percorso = pf.percorso_leggibile() or pf.eseguibile
        ultimo = pf.ultime[0] if pf.ultime else 0
        t.esecuzione(percorso, ultimo, u'Prefetch', conteggio=pf.esecuzioni, elemento=e, orari=list(pf.ultime))
    t.contesto['prefetch'] = tr(u'%d file letti') % letti + (tr(u', %d non leggibili') % errori if errori else u'')
    t.fatto(21)
    if errori:
        testo = (tr(u'%d file del Prefetch su %d non si sono lasciati leggere o interpretare (danneggiati o in un formato '
                 u'non riconosciuto): le esecuzioni che registravano mancano.') % (errori, letti + errori))
        if errori > letti:
            t.avviso(testo)
        else:
            t.nota(testo)
    if not server and not t.radice.piatta and letti < 10:
        t.segnala(21, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                  tr(u'Il Prefetch contiene solo %d file su un Windows client') % letti,
                  tr(u'Su un client in uso ce ne sono centinaia: pochi file indicano una pulizia recente o un sistema appena installato.'),
                  0, trovati[0], oggetti=(R.chiave(u'prefetch', u'svuotato'),))
    if not attivo and not server:
        t.segnala(21, R.INFORMATIVO, R.F_ANTIFORENSE, tr(u'Il Prefetch \u00e8 disattivato nel registro (EnablePrefetcher = 0)'),
                  u'', 0, t.contesto.get('hive_system'))


# --------------------------------------------------------------------------
# Attivita' pianificate: file XML (controllo 15)
# --------------------------------------------------------------------------

def attivita(t):
    if t.radice.piatta:
        return
    trovati = t.radice.file(u'windows/system32/tasks/', u'%', sotto=True)
    da_file = {}
    segno = u'windows/system32/tasks/'
    for e in trovati:
        if t.annullato():
            return
        if e.dimensione < 40 or e.dimensione > 2 * 1024 * 1024:
            continue
        dati = t.contenuto(e)
        if dati is None:
            continue
        try:
            info = tc_artefatti.attivita_xml(dati)
        except ERRORI:
            info = None
        if info is None:
            continue
        cartella = e.cartella
        p = cartella.lower().find(segno)
        relativo = cartella[p + len(segno):] if p >= 0 else u''
        percorso = u'\\' + (relativo + e.nome).replace(u'/', u'\\')
        da_file[percorso.lower()] = {'percorso': percorso, 'azioni': info['azioni'], 'avvii': info['avvii'],
                                     'autore': info['autore'], 'creato': e.creato or e.modificato,
                                     'nascosta': info['nascosta'], 'elemento': e}
    t.contesto['attivita_file'] = da_file
    if da_file:
        t.fatto(15)


# --------------------------------------------------------------------------
# Cartelle Esecuzione automatica e tabella degli avvii automatici (controllo 19)
# --------------------------------------------------------------------------

def avvio_automatico(t):
    righe = list(t.contesto.get('righe_run') or [])
    if not t.radice.piatta:
        cartelle = [(u'users/%/appdata/roaming/microsoft/windows/start menu/programs/startup/', False),
                    (u'programdata/microsoft/windows/start menu/programs/startup/', False)]
        for e in t.radice.file(cartelle, u'%'):
            nome = e.nome.lower()
            if nome == u'desktop.ini' or e.dimensione == 0:
                continue
            dove = tr(u'Esecuzione automatica di ') + (_utente_da_cartella(e.cartella) or tr(u'tutti gli utenti'))
            peso = 0
            motivo = u''
            comando = e.nome
            if nome.endswith(u'.lnk') and e.dimensione < 1024 * 1024:
                c = None
                dati = t.contenuto(e)       # se non si legge, il file finisce tra quelli non letti
                if dati is not None:
                    try:
                        c = tc_artefatti.collegamento(dati)
                    except ERRORI:
                        c = None
                if c is not None and (c['destinazione'] or c['relativo']):
                    destinazione = c['destinazione'] or c['relativo']
                    comando = (destinazione + u' ' + c['argomenti']).strip()
                    peso, motivo = tc_c_registro.giudica_persistenza(
                        t, 19, tr(u'Collegamento in Esecuzione automatica'), e.nome, destinazione, c['argomenti'],
                        e.creato, e)
                elif c is not None and c['argomenti'].strip():
                    # La destinazione sta solo nell'elenco degli elementi della
                    # shell, che qui non viene letto. Ci sono pero' gli
                    # argomenti: si giudicano come se li ricevesse cmd.
                    g = R.valuta_comando(u'cmd.exe', c['argomenti'])
                    peso = R.DECISIVO if g.livello >= 3 else R.DA_CONFERMARE
                    motivo = tr(u'collegamento con argomenti la cui destinazione non \u00e8 leggibile')
                    if g.motivi:
                        motivo += u': ' + g.motivo()
                    comando = tr(u'(destinazione non leggibile) ') + c['argomenti']
                    t.segnala(19, peso, R.F_PERSISTENZA, u'%s: %s (%s)' % (dove, e.nome, motivo),
                              tr(u'%s\nArgomenti: %s\nCreato: %s (UTC)') % (e.percorso, c['argomenti'][:1500], T(e.creato)),
                              e.creato, e, oggetti=(R.chiave_file(t.radice.relativo(e)),))
            elif nome.rsplit(u'.', 1)[-1] in _ESTENSIONI_PROGRAMMI:
                peso = R.DA_CONFERMARE
                motivo = tr(u'programma o script messo direttamente nella cartella Esecuzione automatica')
                t.segnala(19, peso, R.F_PERSISTENZA, u'%s: %s (%s)' % (dove, e.nome, motivo),
                          tr(u'%s\nCreato: %s (UTC)') % (e.percorso, T(e.creato)), e.creato, e,
                          oggetti=(R.chiave_file(t.radice.relativo(e)),))
            righe.append([dove, u'Startup', e.nome, comando[:300], R.NOME_PESO.get(peso, u''), motivo])
    t.tabella(19, tr(u'Avvio automatico: chiavi Run e cartelle Esecuzione automatica'),
              [tr(u'Dove'), tr(u'Chiave'), tr(u'Nome'), tr(u'Comando'), tr(u'Peso'), tr(u'Motivo')], righe[:150])


# --------------------------------------------------------------------------
# WMI (controllo 20)
# --------------------------------------------------------------------------

def _giudica_consumer(testo):
    """Il testo di un consumer WMI che esegue un comando, valutato con le
    stesse regole delle altre voci di persistenza: una sottoscrizione che
    cancella il registro di sicurezza o le copie shadow non deve pesare meno
    dello stesso comando in un servizio. Il testo e' l'insieme delle stringhe
    dell'oggetto (nome, comando, cartella...): si valuta una riga alla volta
    e si tiene il giudizio piu' grave. Restituisce (peso, motivo, comando in
    chiaro)."""
    peso, motivo, chiaro = 0, u'', u''
    for riga in (testo or u'').split(u'\n')[:60]:
        riga = riga.strip()[:8000]
        if len(riga) < 6:
            continue
        g = R.valuta_comando(riga)
        peso_r = {3: R.DECISIVO, 2: R.DA_CONFERMARE}.get(g.livello, 0)
        motivo_r = g.motivo()
        for peso_c, _, cosa_c in R.comandi_noti(riga):
            if peso_c > peso_r:
                peso_r, motivo_r = peso_c, cosa_c
        if peso_r > peso:
            peso, motivo, chiaro = peso_r, motivo_r, g.decodificato
    return peso, motivo, chiaro


def wmi(t):
    trovati = t.radice.file(u'windows/system32/wbem/repository/', u'objects.data', sotto=True, ovunque=True)
    if not trovati:
        t.esito(20, 'assente', tr(u'repository WMI (OBJECTS.DATA) non trovato'))
        return
    eventi = {}
    if t.raccolta is not None:
        for w in t.raccolta.wmi:
            m = re.search(u'="([^"]+)"', w['consumer'])
            if m is not None:
                nome = m.group(1).lower()
                if nome not in eventi or w['ora'] < eventi[nome]:
                    eventi[nome] = w['ora']
    righe = []
    for e in trovati:
        if e.dimensione > 2 * 1024 * 1024 * 1024:
            t.avviso(tr(u'Il repository WMI (%s) \u00e8 di %s: troppo grande per essere letto, le sottoscrizioni WMI non '
                     u'sono state controllate.') % (e.percorso, _dimensione(e.dimensione)))
            continue
        t.avanza(tr(u'Sottoscrizioni WMI: lettura del repository (%s)') % _dimensione(e.dimensione))
        try:
            legami = tc_artefatti.wmi_sottoscrizioni(e.leggi, e.dimensione)
        except ERRORI, ex:
            t.non_letto(e, ex)
            continue
        finally:
            e.chiudi()
        if not getattr(legami, 'completo', True):
            t.avviso(tr(u'Il repository WMI (%s) contiene un numero anomalo di oggetti (file danneggiato o alterato): '
                     u'l\'elenco delle sottoscrizioni pu\u00f2 essere incompleto.') % e.percorso)
        for v in legami:
            chiave = (v['tipo'].lower(), v['nome'].lower())
            if chiave in _WMI_INNOCUI:
                continue
            ora = eventi.get(v['nome'].lower(), 0)
            esegue = v['tipo'] in (u'CommandLineEventConsumer', u'ActiveScriptEventConsumer')
            chiaro = u''
            if esegue:
                forte = _RX_WMI_FORTE.search(v['testo'] or u'')
                peso = R.DECISIVO if forte else R.DA_CONFERMARE
                cosa = tr(u'esegue %s') % (tr(u'uno script') if v['tipo'].startswith(u'Active') else tr(u'un comando'))
                if forte:
                    cosa += tr(u' (contiene \u00ab%s\u00bb)') % forte.group(1)
                peso_r, motivo_r, chiaro = _giudica_consumer(v['testo'])
                if peso_r >= R.DA_CONFERMARE and motivo_r:
                    peso = max(peso, peso_r)
                    cosa += u' (%s)' % motivo_r
            else:
                peso = R.INFORMATIVO
                cosa = tr(u'consumer di tipo %s') % v['tipo']
            t.segnala(20, peso, R.F_PERSISTENZA,
                      tr(u'Sottoscrizione WMI \u00ab%s\u00bb legata al filtro \u00ab%s\u00bb: %s') % (v['nome'], v['filtro'], cosa),
                      tr(u'Filtro: %s\n%s%s\n\nTrovata nel repository: pu\u00f2 essere una voce gi\u00e0 rimossa.%s')
                      % (v['interrogazione'] or tr(u'(interrogazione non trovata)'), (v['testo'] or u'')[:1800],
                         (tr(u'\nComando in chiaro: ') + u' '.join(chiaro.split())[:1500]) if chiaro else u'',
                         tr(u' Registrata il %s (evento 5861).') % T(ora) if ora else u''), ora, e,
                      oggetti=(R.chiave(u'wmi', v['nome']),) + R.oggetti_comando(v['testo'] or u'', u'', chiaro or u''))
            righe.append([v['nome'], v['tipo'], v['filtro'], v['interrogazione'][:200], T(ora), R.NOME_PESO[peso]])
    t.tabella(20, tr(u'Sottoscrizioni WMI permanenti'), [tr(u'Consumer'), tr(u'Tipo'), tr(u'Filtro'), tr(u'Interrogazione'), tr(u'Registrata (5861)'), tr(u'Peso')],
              righe, tr(u'Escluse le due sottoscrizioni predefinite di Windows (SCM Event Log Consumer, BVTConsumer).'))
    t.fatto(20)


# --------------------------------------------------------------------------
# CryptnetUrlCache (controllo 24)
# --------------------------------------------------------------------------

def cryptnet(t):
    if t.radice.piatta:
        t.esito(24, 'non verificabile', tr(u'serve la struttura delle cartelle'))
        return
    trovati = t.radice.file(u'%cryptneturlcache/content/', u'%')
    if not trovati:
        t.esito(24, 'assente', tr(u'nessuna cartella CryptnetUrlCache\\Content trovata'))
        return
    righe = []
    for e in trovati:
        if t.annullato():
            return
        if e.dimensione < 4:
            continue
        tipo = tc_artefatti.tipo_contenuto(t.inizio(e, 4096))
        if not tipo:
            continue
        url = u''
        try:
            base = e.cartella[:-len(u'content/')]
            for m in t.radice.origine.in_cartella([base + u'MetaData/', base + u'Metadata/', base + u'metadata/'],
                                                  e.nome, e.volume):
                url = tc_artefatti.url_da_metadata(t.inizio(m, 4096))
                break
        except ERRORI:
            pass
        if tipo == u'eseguibile':
            peso = R.DECISIVO
        elif tipo == u'pagina HTML':
            peso = R.INFORMATIVO        # di solito la pagina di un captive portal o di un proxy
        else:
            peso = R.DA_CONFERMARE
        mostrato = tr(tipo)
        t.segnala(24, peso, R.F_ESECUZIONE,
                  tr(u'%s nella cache dei download di certutil: %s') % (mostrato[0].upper() + mostrato[1:], url or e.nome),
                  tr(u'%s\nCreato: %s (UTC) - %s\nLa cartella di norma contiene solo certificati e liste di revoca: '
                  u'un programma qui \u00e8 stato scaricato con certutil o con le stesse API.') %
                  (e.percorso, T(e.creato), _dimensione(e.dimensione)), e.creato, e,
                  oggetti=(R.chiave(u'url', url),) if url else ())
        righe.append([e.percorso, mostrato, url, T(e.creato), _dimensione(e.dimensione)])
    t.tabella(24, tr(u'CryptnetUrlCache: contenuti che non sono certificati'),
              [u'File', tr(u'Contenuto'), tr(u'URL di origine'), tr(u'Creato (UTC)'), tr(u'Dimensione')], righe,
              tr(u'File esaminati: %d.') % len(trovati))
    t.fatto(24)


# --------------------------------------------------------------------------
# File residui di Impacket (controllo 30)
# --------------------------------------------------------------------------

def residui(t):
    if t.radice.piatta:
        t.esito(30, 'non verificabile', tr(u'serve la struttura delle cartelle'))
        return
    righe = []

    def segnala(e, peso, testo, extra=False, famiglia=R.F_LATERALE):
        stato = tr(u' (cancellato)') if e.cancellato else u''
        anteprima = u''
        if e.dimensione and not e.cancellato:
            try:
                inizio = t.inizio(e, 600)
                if inizio and len([c for c in inizio if 32 <= ord(c) < 127 or c in '\r\n\t']) > len(inizio) * 0.85:
                    anteprima = tr(u'\nContenuto: ') + inizio.decode('cp1252', 'replace')[:300]
                    if e.nome.lower().endswith(u'.bat') and ('__output' in inizio or '\\\\127.0.0.1\\' in inizio):
                        peso = R.DECISIVO
                        testo += tr(u'; il contenuto ridirige l\'output su __output')
            except ERRORI:
                pass
        t.segnala(30, peso, famiglia, u'%s%s: %s' % (testo, stato, t.radice.relativo(e)),
                  tr(u'Creato: %s - modificato: %s (UTC) - %s%s') % (T(e.creato), T(e.modificato), _dimensione(e.dimensione), anteprima),
                  e.creato or e.modificato, e, extra, oggetti=(R.chiave_file(t.radice.relativo(e)),))
        righe.append([t.radice.relativo(e) + stato, testo, T(e.creato), T(e.modificato), R.NOME_PESO[peso]])

    for e in t.radice.con_nome([u'__output'], cancellati=True):
        if e.nome.lower() != u'__output':
            continue
        dove = e.cartella.lower()
        if dove == t.radice.prefisso or dove.endswith(u'/windows/temp/') or dove.endswith(u'/windows/'):
            segnala(e, R.DECISIVO, tr(u'File di output di smbexec'))
        elif e.cancellato and u'$orphanfiles' in dove:
            segnala(e, R.DA_CONFERMARE, tr(u'File cancellato con il nome del file di output di smbexec '
                    u'(la cartella in cui stava non \u00e8 pi\u00f9 ricostruibile)'))
    # wmiexec e dcomexec scrivono l'output in C:\Windows\__<secondi>.<frazione>
    for e in t.radice.file(u'windows/', u'__%', cancellati=True):
        if _RX_USCITA_WMIEXEC.match(e.nome):
            segnala(e, R.DECISIVO, tr(u'File di output di wmiexec o dcomexec (Impacket)'), True)
    quanti_tmp = 0
    quanti_exe = 0
    for e in t.radice.file([(u'windows/', False), (u'windows/temp/', False)], u'%', cancellati=True,
                           estensioni=[u'bat', u'tmp', u'exe']):
        nome = e.nome.lower()
        in_temp = e.cartella.lower().endswith(u'/temp/')
        if in_temp:
            if nome == u'execute.bat':
                # il nome da solo non basta: diventa decisivo se il contenuto
                # ridirige l'output su __output (lo controlla segnala)
                segnala(e, R.DA_CONFERMARE, tr(u'File execute.bat in Windows\\Temp, il nome usato da smbexec fino al 2023'))
            elif _RX_OTTO_TMP.match(e.nome) and R.nome_casuale(e.nome[:8]) and quanti_tmp < 15:
                quanti_tmp += 1
                segnala(e, R.DA_CONFERMARE, tr(u'File .tmp con nome di 8 lettere a caso in Windows\\Temp (output di atexec)'))
            continue
        if _RX_OTTO_BAT.match(e.nome) and R.nome_casuale(e.nome[:8]):
            segnala(e, R.DA_CONFERMARE, tr(u'Batch con nome di 8 lettere a caso in C:\\Windows (smbexec dal 2023)'))
        elif _RX_OTTO_EXE.match(e.nome) and R.nome_casuale(e.nome[:8]) and quanti_exe < 15:
            quanti_exe += 1
            segnala(e, R.DA_CONFERMARE, tr(u'Eseguibile con nome di 8 lettere a caso in C:\\Windows (servizio di psexec.py o Metasploit)'),
                    True)
        elif nome in (u'psexesvc.exe', u'paexec.exe', u'remcomsvc.exe', u'csexecsvc.exe'):
            segnala(e, R.DA_CONFERMARE, tr(u'Servizio di PsExec o di un suo clone: qualcuno ha eseguito comandi da remoto su questa macchina'),
                    True, R.F_LATERALE)
    t.tabella(30, tr(u'File residui dell\'esecuzione remota'), [u'File', tr(u'Cosa'), tr(u'Creato (UTC)'), tr(u'Modificato (UTC)'), tr(u'Peso')], righe)
    t.fatto(30)


# --------------------------------------------------------------------------
# Strumenti di accesso remoto: file e log (controlli 33, 34, 35)
# --------------------------------------------------------------------------

def rmm(t):
    registri = {}
    try:
        trovati = t.radice.con_nome([u'connection_trace.txt', u'ad.trace', u'ad_svc.trace', u'file_transfer_trace.txt',
                                     u'connections_incoming.txt', u'connections.txt', u'_logfile.log', u'_logfile_old.log'])
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca dei log degli strumenti di accesso remoto non riuscita (controlli 34 e 35)'), ex)
        trovati = []
    for e in trovati:
        registri.setdefault(e.nome.lower(), []).append(e)

    def testo_di(e, massimo):
        if e.dimensione == 0:
            return None
        if e.dimensione > massimo:
            # un log enorme: se ne legge la parte finale, la piu' recente
            try:
                try:
                    dati = e.leggi(e.dimensione - massimo, massimo)
                finally:
                    e.chiudi()
            except ERRORI, errore:
                t.non_letto(e, errore)
                return None
            t.nota(tr(u'Il log %s \u00e8 molto grande (%s): ne sono stati letti gli ultimi %s.')
                   % (t.radice.relativo(e), _dimensione(e.dimensione), _dimensione(massimo)))
            return dati[dati.find('\n') + 1:]
        return t.contenuto(e)

    # --- AnyDesk
    for e in registri.get(u'connection_trace.txt', []):
        dati = testo_di(e, 32 * 1024 * 1024)
        if dati is None:
            continue
        t.prova_rmm(u'AnyDesk', tr(u'log delle connessioni'), t.radice.relativo(e), e.modificato, e, 34)
        for v in tc_artefatti.anydesk_connessioni(dati):
            t.sessione_rmm(u'AnyDesk', v['ora'],
                           tr(u'%s, autenticazione %s, ID remoto %s') % (tr(u'in entrata') if v['verso'] == u'Incoming' else tr(u'in uscita'),
                                                                    v['modo'], v['id']),
                           e, 34, v['verso'] == u'Incoming')
    for nome in (u'ad.trace', u'ad_svc.trace'):
        for e in registri.get(nome, []):
            dati = _righe_con(t, e, ['logged in from', 'client-id:', 'incoming session request', 'preparing files',
                                     'file_transfer'])
            if dati is None:
                continue
            t.prova_rmm(u'AnyDesk', tr(u'log di traccia'), t.radice.relativo(e), e.modificato, e, 34)
            visti = set()
            for v in tc_artefatti.anydesk_traccia(dati):
                if v['tipo'] == 'ip':
                    chiave = (v['valore'], int(v['ora'] / 60))
                    if chiave in visti:
                        continue
                    visti.add(chiave)
                    t.sessione_rmm(u'AnyDesk', v['ora'], tr(u'collegamento dall\'indirizzo %s') % v['valore'], e, 34)
                elif v['tipo'] == 'file':
                    t.sessione_rmm(u'AnyDesk', v['ora'], tr(u'trasferimento di file: %s') % v['valore'], e, 34, False)
                elif v['tipo'] == 'richiesta':
                    t.sessione_rmm(u'AnyDesk', v['ora'], tr(u'richiesta di sessione in entrata'), e, 34)
    for e in registri.get(u'file_transfer_trace.txt', []):
        dati = t.inizio(e, 512 * 1024)
        if not dati:
            continue
        for riga in tc_artefatti.testo_da_file(dati).splitlines()[:200]:
            if riga.strip():
                t.sessione_rmm(u'AnyDesk', 0, tr(u'trasferimento di file: %s') % riga.strip()[:300], e, 34, False)
    # --- TeamViewer
    for e in registri.get(u'connections_incoming.txt', []):
        dati = testo_di(e, 32 * 1024 * 1024)
        if dati is None:
            continue
        t.prova_rmm(u'TeamViewer', tr(u'log delle connessioni in entrata'), t.radice.relativo(e), e.modificato, e, 35)
        for v in tc_artefatti.teamviewer_connessioni(dati, True):
            t.sessione_rmm(u'TeamViewer', v['inizio'],
                           tr(u'in entrata dall\'ID %s (%s), fino alle %s, utente locale %s, tipo %s')
                           % (v['id'], v['nome'], T(v['fine']), v['utente'], v['tipo']), e, 35)
    for e in registri.get(u'connections.txt', []):
        if u'/teamviewer/' not in e.cartella.lower():
            continue
        dati = testo_di(e, 32 * 1024 * 1024)
        if dati is None:
            continue
        for v in tc_artefatti.teamviewer_connessioni(dati, False):
            t.sessione_rmm(u'TeamViewer', v['inizio'], tr(u'in uscita verso l\'ID %s, tipo %s') % (v['id'], v['tipo']),
                           e, 35, False)
    for nome, elenco in registri.items():
        if not (nome.startswith(u'teamviewer') and nome.endswith(u'.log')):
            continue
        for e in elenco:
            dati = _righe_con(t, e, ['punch received'])
            if dati is None:
                continue
            t.prova_rmm(u'TeamViewer', tr(u'log di debug'), t.radice.relativo(e), e.modificato, e, 35)
            visti = set()
            for ora, indirizzo in tc_artefatti.teamviewer_log(dati):
                if indirizzo in visti:
                    continue
                visti.add(indirizzo)
                # compare sia nelle sessioni in entrata sia in quelle in uscita:
                # e' un indirizzo utile, non la prova di una sessione in entrata
                t.sessione_rmm(u'TeamViewer', ora, tr(u'connessione diretta con l\'indirizzo %s (\u00abpunch received\u00bb, ora locale della macchina)')
                               % indirizzo, e, 35, False)
    t.fatto(34, 35)
    # --- eseguibili degli RMM e degli strumenti noti, ovunque sul disco (per nome)
    frammenti = R.frammenti_rmm() + R.FRAMMENTI_STRUMENTI
    try:
        trovati = t.radice.con_nome(frammenti, [u'exe', u'msi', u'ps1'], cancellati=True)
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca per nome degli strumenti noti non riuscita (controlli 33 e 38)'), ex)
        trovati = []
    righe = []
    visti = set()
    for numero, e in enumerate(trovati):
        if t.battito(numero, 5000, tr(u'Strumenti noti sul disco: %d file esaminati')):
            return
        nome = e.nome.lower()
        percorso = t.radice.relativo(e)
        z = R.zona(percorso)
        strumento = R.trova_rmm(nome)
        if strumento and strumento != u'Quick Assist':
            t.prova_rmm(strumento, tr(u'file sul disco') + (tr(u' (cancellato)') if e.cancellato else u''), percorso, e.creato, e, 33)
            continue
        peso, cosa = R.strumento(nome)
        if peso < R.DA_CONFERMARE or z == u'sistema' and nome in (u'psexesvc.exe',):
            continue
        if (nome, e.cartella.lower()) in visti:
            continue
        visti.add((nome, e.cartella.lower()))
        nota = u''
        if peso >= R.DECISIVO and not _versione_conferma(t, e):
            # un nome si copia: senza le informazioni di versione del file che lo
            # confermino, uno strumento trovato solo per nome resta da confermare
            peso = R.DA_CONFERMARE
            nota = u'\n' + tr(u'Solo il nome: le informazioni di versione del file non confermano lo strumento (o il file '
                               u'non le ha, o non si legge).')
        t.segnala(38, peso, R.famiglia_strumento(nome),
                  tr(u'%s sul disco%s: %s') % (cosa[0].upper() + cosa[1:], tr(u' (file cancellato)') if e.cancellato else u'', percorso),
                  tr(u'Creato: %s - modificato: %s (UTC) - %s') % (T(e.creato), T(e.modificato), _dimensione(e.dimensione)) + nota,
                  e.creato, e, oggetti=(R.chiave_file(percorso),))
        righe.append((e.creato, [percorso + (tr(u' (cancellato)') if e.cancellato else u''), cosa, T(e.creato), T(e.modificato),
                                 _dimensione(e.dimensione), R.NOME_PESO[peso]]))
    righe.sort(key=lambda x: -x[0])
    t.tabella(38, tr(u'Strumenti noti trovati sul disco (per nome)'),
              [u'File', tr(u'Tipo'), tr(u'Creato (UTC)'), tr(u'Modificato (UTC)'), tr(u'Dimensione'), tr(u'Peso')], [x[1] for x in righe[:60]])
    _rinominati(t)
    t.fatto(33)


def _versione_conferma(t, e):
    """Vero se le informazioni di versione del file (nome originale, nome
    interno, prodotto) indicano anche loro uno strumento d'attacco."""
    if e.cancellato or e.dimensione < 4096 or e.dimensione > 512 * 1024 * 1024 \
            or tc_origine.estensione(e.nome).lower() not in (u'exe', u'dll', u'sys', u'scr', u'com'):
        return False
    try:
        info = tc_artefatti.pe_versione(e.leggi, e.dimensione)
    except IOError, errore:
        t.non_letto(e, errore)
        info = None
    except ERRORI:
        info = None
    finally:
        e.chiudi()
    if not info:
        return False
    for chiave in (u'OriginalFilename', u'InternalName', u'ProductName'):
        if R.strumento(info.get(chiave, u''))[0] >= R.DECISIVO:
            return True
    return False


def _rinominati(t):
    """Eseguibili nelle cartelle di appoggio il cui nome non corrisponde
    alle informazioni di versione: RMM e strumenti rinominati."""
    if t.radice.piatta:
        return
    zone = [(u'users/%/downloads/', True), (u'users/%/desktop/', True), (u'users/public/', True),
            (u'users/%/appdata/local/temp/', False), (u'windows/temp/', False),
            (u'programdata/', False), (u'perflogs/', True), (u'tmp/', True), (u'temp/', True),
            (u'users/%/documents/', False), (u'users/%/appdata/roaming/', False)]
    try:
        candidati = t.radice.file(zone, u'%', estensioni=[u'exe', u'scr', u'com', u'dat', u'tmp', u'bin'])
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca degli eseguibili rinominati nelle cartelle di appoggio non riuscita (controlli 33 e 38)'), ex)
        candidati = []
    candidati.sort(key=lambda e: -(e.creato or e.modificato))
    if len(candidati) > 400:
        t.nota(tr(u'Nelle cartelle di appoggio ci sono %d eseguibili: per cercare quelli rinominati (controllo 38) sono '
               u'state lette le informazioni di versione dei 400 pi\u00f9 recenti.') % len(candidati))
    esaminati = 0
    for e in candidati[:400]:
        if t.annullato():
            return
        if e.dimensione < 4096 or e.dimensione > 512 * 1024 * 1024:
            continue
        try:
            info = tc_artefatti.pe_versione(e.leggi, e.dimensione)
        except IOError, errore:
            t.non_letto(e, errore)      # il file non si legge: lo si dice
            info = None
        except ERRORI:
            info = None                 # non e' un eseguibile o non ha le informazioni di versione
        finally:
            e.chiudi()
        esaminati += 1
        if not info:
            continue
        testo = u' '.join([info.get(k, u'') for k in (u'CompanyName', u'ProductName', u'OriginalFilename',
                                                     u'InternalName', u'FileDescription')])
        nome = e.nome.lower()
        percorso = t.radice.relativo(e)
        strumento = R.trova_rmm(testo)
        if strumento and strumento != u'Quick Assist' and not R.trova_rmm(nome):
            t.prova_rmm(strumento, tr(u'eseguibile rinominato'), tr(u'%s (in origine %s, %s)')
                        % (percorso, info.get(u'OriginalFilename', u'?'), info.get(u'CompanyName', u'?')), e.creato, e, 33)
            t.segnala(33, R.DA_CONFERMARE, R.F_RMM,
                      tr(u'%s rinominato: %s') % (strumento, percorso),
                      tr(u'Informazioni di versione: produttore \u00ab%s\u00bb, prodotto \u00ab%s\u00bb, nome originale \u00ab%s\u00bb.\nCreato: %s (UTC)')
                      % (info.get(u'CompanyName', u''), info.get(u'ProductName', u''), info.get(u'OriginalFilename', u''), T(e.creato)),
                      e.creato, e, oggetti=(R.chiave_file(percorso),))
            continue
        if R.strumento(nome)[0]:
            continue        # gia' riconosciuto dal nome
        for chiave in (u'OriginalFilename', u'InternalName', u'ProductName'):
            peso, cosa = R.strumento(info.get(chiave, u''))
            if peso >= R.DA_CONFERMARE:
                t.segnala(38, peso, R.famiglia_strumento(info.get(chiave, u'')),
                          tr(u'%s rinominato: %s (in origine \u00ab%s\u00bb)') % (cosa[0].upper() + cosa[1:], percorso, info.get(chiave)),
                          tr(u'Informazioni di versione: produttore \u00ab%s\u00bb, prodotto \u00ab%s\u00bb, nome originale \u00ab%s\u00bb.\nCreato: %s (UTC)')
                          % (info.get(u'CompanyName', u''), info.get(u'ProductName', u''), info.get(u'OriginalFilename', u''), T(e.creato)),
                          e.creato, e, oggetti=(R.chiave_file(percorso),))
                break
    t.contesto['pe_esaminati'] = esaminati


def _genere(prova):
    """Il genere di una prova: 'eseguito', 'installato' oppure ''. Lo scrive
    Triage.prova_rmm; per le prove costruite a mano, che non lo hanno, si
    ricava dal tipo scritto in italiano."""
    genere = prova.get('genere')
    if genere is None:
        tipo = prova.get('tipo') or u''
        if tipo.startswith(u'eseguito'):
            return 'eseguito'
        if tipo.startswith((u'programma installato', u'servizio installato', u'installazione')):
            return 'installato'
        return ''
    return genere


def riepilogo_rmm(t):
    """Controlli 32-36: un segnale per ogni strumento di accesso remoto."""
    righe_prove = []
    righe_sessioni = []
    for strumento in sorted(t.rmm.keys()):
        voce = t.rmm[strumento]
        prove = voce['prove']
        sessioni = sorted(voce['sessioni'], key=lambda s: s['ora'])
        eseguito = [p for p in prove if _genere(p) == 'eseguito']
        if strumento == u'Quick Assist' and not eseguito and not sessioni:
            continue
        tipi = []
        for p in prove:
            if p['tipo'] not in tipi:
                tipi.append(p['tipo'])
        tempi = [p['ora'] for p in prove if p['ora']] + [s['ora'] for s in sessioni if s['ora']]
        in_entrata = [s for s in sessioni if s['in_entrata']]
        autorizzato = t.opzioni.autorizzato(strumento)
        recente = [p for p in prove if t.recente(p['ora']) and _genere(p) == 'installato']
        if autorizzato:
            peso = R.INFORMATIVO
        elif in_entrata or recente:
            peso = R.DA_CONFERMARE
        else:
            peso = R.INFORMATIVO      # presente, ma senza sessioni in entrata ne' installazione recente
        controllo = 32
        if strumento == u'AnyDesk':
            controllo = 34
        elif strumento == u'TeamViewer':
            controllo = 35
        elif strumento in (u'LogMeIn', u'Pulseway'):
            controllo = 36
        elif not [p for p in prove if p['controllo'] == 32]:
            controllo = 33
        testo = u'%s: %s' % (strumento, u', '.join(tipi[:6]) or tr(u'tracce nei log'))
        if in_entrata:
            ultima = T(in_entrata[-1]['ora']) or tr(u'(data non nota)')
            if len(in_entrata) == 1:
                testo += tr(u'. 1 sessione o evento in entrata, l\'ultima il %s') % ultima
            else:
                testo += tr(u'. %d sessioni o eventi in entrata, l\'ultima il %s') % (len(in_entrata), ultima)
        if autorizzato:
            testo += tr(u' - indicato come autorizzato')
        elif in_entrata:
            testo += tr(u'. Decisivo se lo strumento non \u00e8 autorizzato')
        elif recente:
            testo += tr(u'. Installato di recente: verifica se \u00e8 autorizzato')
        else:
            testo += tr(u'. Nessuna sessione in entrata trovata: verifica se \u00e8 autorizzato')
        dettagli = [u'%s: %s%s' % (p['tipo'], p['dettaglio'], u' (%s)' % T(p['ora']) if p['ora'] else u'') for p in prove[:12]]
        if sessioni:
            dettagli.append(tr(u'Sessioni ed eventi:'))
            dettagli.extend([u'%s  %s' % (T(s['ora']) or u'-', s['dettaglio']) for s in sessioni[-15:]])
        elemento = None
        for p in prove:
            if p['elemento'] is not None:
                elemento = p['elemento']
                break
        if elemento is None and sessioni:
            elemento = sessioni[-1]['elemento']
        # se tutte le tracce vengono dalla RAM, il segnale e' della RAM (e conta solo se conta lei)
        dalla_ram = [x.get('ram') for x in prove + sessioni if x.get('ram') is not None]
        precedente = t.ram_corrente
        if dalla_ram and len(dalla_ram) == len(prove) + len(sessioni):
            t.ram_corrente = dalla_ram[0]
        try:
            t.segnala(controllo, peso, R.F_RMM, testo, u'\n'.join(dettagli)[:3000], min(tempi) if tempi else 0, elemento,
                      oggetti=(R.chiave(u'rmm', strumento),))
        finally:
            t.ram_corrente = precedente
        for p in prove[:30]:
            righe_prove.append([strumento, p['tipo'], p['dettaglio'][:300], T(p['ora'])])
        for s in sessioni[-60:]:
            righe_sessioni.append([strumento, T(s['ora']), s['dettaglio'][:400]])
    t.tabella(32, tr(u'Strumenti di accesso remoto trovati'), [tr(u'Strumento'), tr(u'Prova'), tr(u'Dettaglio'), tr(u'Quando (UTC)')], righe_prove,
              tr(u'Per ogni strumento: \u00e8 autorizzato? Quando si \u00e8 collegato qualcuno? Cosa ha fatto? Come \u00e8 arrivato?'))
    t.tabella(34, tr(u'Sessioni ed eventi degli strumenti di accesso remoto'), [tr(u'Strumento'), tr(u'Quando (UTC)'), tr(u'Dettaglio')], righe_sessioni)
    installati = sorted(t.contesto.get('righe_installati') or [], key=lambda x: -x[0])
    t.tabella(32, tr(u'Programmi installati: i 30 pi\u00f9 recenti'),
              [tr(u'Chiave scritta (UTC)'), tr(u'Programma'), tr(u'Produttore'), tr(u'Utente')],
              [[T(x[0]), x[1], x[2], x[3]] for x in installati[:30]])


# --------------------------------------------------------------------------
# Antivirus: cronologia dei rilevamenti di Defender (controllo 37)
# --------------------------------------------------------------------------

def defender(t):
    if t.radice.piatta:
        return
    trovati = t.radice.file(u'programdata/microsoft/windows defender/scans/history/service/detectionhistory/', u'%', sotto=True)
    if not trovati:
        return
    gia = set()
    if t.raccolta is not None:
        for r in t.raccolta.defender.values():
            gia.add(r['minaccia'])
    nuove = {}
    if len(trovati) > 2000:
        t.nota(tr(u'La cronologia dei rilevamenti di Defender contiene %d file: ne sono stati letti 2000.') % len(trovati))
    for e in trovati[:2000]:
        if e.dimensione < 64 or e.dimensione > 4 * 1024 * 1024:
            continue
        dati = t.contenuto(e)
        if dati is None:
            continue
        try:
            minacce, risorse = tc_artefatti.rilevamento_defender(dati)
        except ERRORI:
            continue
        for m in minacce:
            if m in gia:
                continue
            g = nuove.setdefault(m, {'n': 0, 'primo': e.creato, 'risorse': [], 'elemento': e})
            g['n'] += 1
            if e.creato and (not g['primo'] or e.creato < g['primo']):
                g['primo'] = e.creato
            for r in risorse:
                if len(g['risorse']) < 4 and r not in g['risorse']:
                    g['risorse'].append(r)
    for m, g in nuove.items():
        t.segnala(37, R.peso_minaccia(m), R.F_ANTIVIRUS,
                  tr(u'Defender ha rilevato %s (%d file nella cronologia dei rilevamenti)') % (m, g['n']),
                  tr(u'Rilevamento che non compare nel registro eventi (forse gi\u00e0 uscito dal registro).\nPrimo file: %s (UTC)\n%s')
                  % (T(g['primo']), u'\n'.join(g['risorse'])[:1500]), g['primo'], g['elemento'],
                  oggetti=(R.chiave(u'minaccia', m),))
    t.fatto(37)


# --------------------------------------------------------------------------
# Cronologia della console di PowerShell (regola in piu', controllo 25)
# --------------------------------------------------------------------------

def cronologia_powershell(t):
    trovati = t.radice.file(u'users/%/appdata/roaming/microsoft/windows/powershell/psreadline/', u'consolehost_history.txt',
                            ovunque=True)
    righe = []
    limite = 4 * 1024 * 1024
    for e in trovati:
        if e.dimensione == 0:
            continue
        utente = _utente_da_cartella(e.cartella) or u'?'
        if e.dimensione > limite:
            # PSReadLine tiene poche migliaia di comandi: un file enorme non e'
            # normale. Si legge la parte finale, la piu' recente.
            try:
                try:
                    dati = e.leggi(e.dimensione - limite, limite)
                finally:
                    e.chiudi()
            except ERRORI, errore:
                t.non_letto(e, errore)
                continue
            dati = dati[dati.find('\n') + 1:]
            t.nota(tr(u'La cronologia di PowerShell di %s \u00e8 insolitamente grande (%s): ne sono stati letti gli ultimi 4 MB.')
                   % (utente, _dimensione(e.dimensione)))
        else:
            dati = t.contenuto(e)
            if dati is None:
                continue
        try:
            testo = tc_artefatti.testo_da_file(dati)
        except ERRORI:
            continue
        segnalate = 0
        for numero, riga in enumerate(testo.splitlines()):
            if t.battito(numero, 5000, tr(u'Cronologia di PowerShell di ') + utente + tr(u': %d righe')):
                return
            riga = riga.strip()
            if not riga:
                continue
            trovato = R.riga_di_console(riga)
            if trovato is None:
                continue
            chiaro = trovato[3]
            righe.append([utente, unicode(numero + 1), riga[:400], trovato[2], R.NOME_PESO[trovato[0]]])
            if segnalate < 15 and trovato[0] >= R.DA_CONFERMARE:
                segnalate += 1
                if chiaro:
                    chiaro = tr(u'\nComando in chiaro: ') + u' '.join(chiaro.split())[:1200]
                t.segnala(25, trovato[0], trovato[1],
                          tr(u'Cronologia di PowerShell di %s, riga %d: %s') % (utente, numero + 1, trovato[2]),
                          tr(u'%s%s\nIl file non registra gli orari: l\'ultima modifica \u00e8 del %s (UTC).')
                          % (riga[:1500], chiaro, T(e.modificato)), 0, e, True,
                          oggetti=R.oggetti_comando(riga, u'', trovato[3] or u''))
    t.tabella(25, tr(u'Cronologia della console di PowerShell: righe segnalate'), [tr(u'Utente'), tr(u'Riga'), tr(u'Comando'), tr(u'Motivo'), tr(u'Peso')],
              righe[:80])


# --------------------------------------------------------------------------
# Cartelle di appoggio (controllo 38)
# --------------------------------------------------------------------------

def appoggio(t):
    if t.radice.piatta:
        t.esito(38, 'non verificabile', tr(u'serve la struttura delle cartelle'))
        return
    zone = [(u'users/public/', True), (u'perflogs/', True), (u'windows/temp/', True), (u'programdata/', False),
            (u'tmp/', True), (u'temp/', True), (u'users/%/appdata/local/temp/', True), (u'users/%/downloads/', True)]
    sospette = [z for z in zone if not z[0].startswith(u'users/%')]
    rx_blande = re.compile(u'/users/[^/]+/(appdata/local/temp|downloads)/')
    righe = []
    segnalati = 0
    grandi = 0
    mascherati = 0
    try:
        trovati = t.radice.file(zone, u'%', estensioni=_ESTENSIONI_PROGRAMMI + _ESTENSIONI_ARCHIVI)
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca dei file nelle cartelle di appoggio non riuscita (controllo 38)'), ex)
        trovati = []
    # Zone.Identifier: da dove e' stato scaricato il file (flusso alternativo di NTFS)
    provenienze = {}
    try:
        for z in t.radice.file(zone, u'%:zone.identifier'):
            provenienze[(z.cartella.lower(), z.nome.lower()[:-len(u':zone.identifier')])] = z
    except ERRORI, ex:
        # manca solo l'indicazione di dove e' stato scaricato il file
        t.registra(tr(u'Ricerca dei flussi Zone.Identifier non riuscita: %r') % (ex,))

    def provenienza(e):
        z = provenienze.get((e.cartella.lower(), e.nome.lower()))
        if z is None or z.dimensione > 8192:
            return u''
        try:
            testo = tc_artefatti.testo_da_file(t.inizio(z, 4096))
        except ERRORI:
            return u''
        trovate = []
        for riga in testo.splitlines():
            riga = riga.strip()
            if riga.lower().startswith((u'hosturl=', u'referrerurl=')):
                trovate.append(riga[:300])
        return u'; '.join(trovate)
    senza_date = t.senza_date()
    # Una data di creazione posteriore di piu' di un giorno all'ultima
    # attivita' della macchina, con una data di modifica precedente, e' la
    # data di una copia (file logici copiati prima di aggiungerli ad
    # Autopsy): in quel caso vale la modifica.
    dopo = t.ultima_attivita() + 86400.0
    for e in trovati:
        quando = max(e.creato, e.modificato)
        if e.creato > dopo >= e.modificato > 0:
            quando = e.modificato
        if not senza_date and not t.recente(quando):
            continue
        nome = e.nome.lower()
        est = nome.rsplit(u'.', 1)[-1]
        percorso = t.radice.relativo(e)
        dove = e.cartella.lower()
        sospetta = rx_blande.search(dove) is None
        archivio = est in _ESTENSIONI_ARCHIVI
        nota = u''
        da_dove = provenienza(e)
        if INVERSIONE in e.nome:
            t.segnala(38, R.DA_CONFERMARE, R.F_FILE,
                      tr(u'Nome di file con il carattere che inverte il verso del testo: %s') % percorso,
                      tr(u'Il carattere U+202E fa leggere al contrario la fine del nome e camuffa l\'estensione vera (.%s).\n'
                      u'Creato: %s - modificato: %s (UTC)') % (est, T(e.creato), T(e.modificato)), e.creato, e, True,
                      oggetti=(R.chiave_file(percorso),))
        if archivio and est in (u'vhd', u'vhdx', u'iso', u'img') and u'/hyper-v/' in dove:
            pass        # i dischi delle macchine virtuali di Hyper-V stanno li' di norma
        elif archivio and e.dimensione >= 100 * 1024 * 1024 and sospetta and grandi < 10:
            grandi += 1
            nota = tr(u'archivio di grandi dimensioni')
            t.segnala(38, R.DA_CONFERMARE, R.F_FILE,
                      tr(u'Archivio di %s in una cartella di appoggio: %s') % (_dimensione(e.dimensione), percorso),
                      tr(u'Creato: %s - modificato: %s (UTC). Un grande archivio qui pu\u00f2 essere dati pronti per l\'esfiltrazione.')
                      % (T(e.creato), T(e.modificato)), e.creato, e, oggetti=(R.chiave_file(percorso),))
        elif not archivio and sospetta and est != u'dll' and segnalati < 20:
            z = R.zona(percorso)
            in_temp_di_windows = dove.endswith(u'/windows/temp/') and est in (u'exe', u'ps1', u'bat', u'cmd', u'vbs', u'js', u'hta') \
                and not nome.startswith((u'mpsigstub', u'mpam-', u'dismhost'))
            if (z == u'sospetta' or in_temp_di_windows) and not R.strumento_forense(nome):
                segnalati += 1
                nota = tr(u'programma o script recente in una cartella di appoggio')
                t.segnala(38, R.DA_CONFERMARE, R.F_FILE, tr(u'Programma o script recente in una cartella di appoggio: %s') % percorso,
                          tr(u'Creato: %s - modificato: %s (UTC) - %s%s') % (T(e.creato), T(e.modificato), _dimensione(e.dimensione),
                                                                        tr(u'\nScaricato da: ') + da_dove if da_dove else u''),
                          e.creato, e, oggetti=(R.chiave_file(percorso),))
        righe.append((quando, [percorso, T(e.creato), T(e.modificato), _dimensione(e.dimensione), da_dove, nota]))
    # eseguibili travestiti: contenuto MZ ed estensione innocua nelle cartelle sospette
    try:
        trovati = t.radice.file(sospette, u'%', estensioni=_ESTENSIONI_INNOCUE)
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca dei programmi con un\'estensione innocua non riuscita (controllo 38)'), ex)
        trovati = []
    trovati.sort(key=lambda e: -max(e.creato, e.modificato))
    for e in trovati[:600]:
        if t.annullato():
            return
        if e.dimensione < 1024:
            continue
        inizio = t.inizio(e, 2)
        if inizio == 'MZ' and mascherati < 15:
            mascherati += 1
            percorso = t.radice.relativo(e)
            t.segnala(38, R.DA_CONFERMARE, R.F_FILE,
                      tr(u'Programma salvato con un\'estensione innocua: %s') % percorso,
                      tr(u'Il file inizia con MZ (eseguibile di Windows) ma ha estensione .%s.\nCreato: %s - modificato: %s (UTC) - %s')
                      % (e.nome.rsplit(u'.', 1)[-1], T(e.creato), T(e.modificato), _dimensione(e.dimensione)), e.creato, e,
                      oggetti=(R.chiave_file(percorso),))
            righe.append((max(e.creato, e.modificato), [percorso, T(e.creato), T(e.modificato), _dimensione(e.dimensione),
                                                         provenienza(e), tr(u'eseguibile con estensione innocua')]))
    righe.sort(key=lambda x: -x[0])
    t.tabella(38, tr(u'Programmi, script e archivi recenti nelle cartelle di appoggio (i 60 pi\u00f9 recenti)'),
              [u'File', tr(u'Creato (UTC)'), tr(u'Modificato (UTC)'), tr(u'Dimensione'), tr(u'Scaricato da (Zone.Identifier)'), tr(u'Nota')],
              [x[1] for x in righe[:60]],
              tr(u'Cartelle: Users\\Public, PerfLogs, Windows\\Temp, ProgramData, Temp e Downloads degli utenti. '
              u'Finestra: gli ultimi %d giorni di attivit\u00e0 della macchina.') % t.opzioni.giorni_recenti)
    t.fatto(38)


# --------------------------------------------------------------------------
# Cestino (controllo 39)
# --------------------------------------------------------------------------

def cestino(t):
    trovati = t.radice.file(u'$recycle.bin/%', u'$i%', tutti_i_volumi=True, ovunque=True)
    if not trovati:
        cartella = [] if t.radice.piatta else t.radice.file(u'', u'$recycle.bin', cartelle=True, tutti_i_volumi=True)
        if cartella:
            t.esito(39, 'fatto', tr(u'nessun file $I: il Cestino \u00e8 vuoto'))
        else:
            t.esito(39, 'assente', tr(u'cartella $Recycle.Bin non trovata'))
        return
    voci = []
    if len(trovati) > 20000:
        t.nota(tr(u'Nel Cestino ci sono %d elementi: ne sono stati letti 20000.') % len(trovati))
    for numero, e in enumerate(trovati[:20000]):
        if t.battito(numero, 2000, tr(u'Cestino: %d elementi letti')):
            return
        if e.dimensione < 28 or e.dimensione > 70000:
            continue
        try:
            v = tc_artefatti.cestino(e.leggi(0, min(e.dimensione, 66000)))
        except IOError, errore:
            t.non_letto(e, errore)
            v = None
        except ERRORI:
            v = None
        finally:
            e.chiudi()
        if v is None or not v['percorso']:
            continue
        parti = [p for p in e.cartella.split(u'/') if p]
        sid = parti[-1] if parti else u''
        v['utente'] = t.nome_utente(sid)
        v['elemento'] = e
        voci.append(v)
    voci.sort(key=lambda v: v['ora'])
    righe = []
    for v in voci[-50:]:
        righe.append([T(v['ora']), v['utente'], v['percorso'][:300], _dimensione(v['dimensione'])])
    righe.reverse()
    t.tabella(39, tr(u'Cestino: le 50 cancellazioni pi\u00f9 recenti'),
              [tr(u'Cancellato (UTC)'), tr(u'Utente'), tr(u'Percorso originale'), tr(u'Dimensione')], righe,
              tr(u'File $I letti: %d.') % len(voci))
    # cancellazioni in blocco
    i = 0
    n = len(voci)
    blocchi = 0
    while i < n and blocchi < 5:
        j = i
        while j < n and voci[j]['ora'] - voci[i]['ora'] <= 300:
            j += 1
        if j - i >= 50:
            while j < n and voci[j]['ora'] - voci[j - 1]['ora'] <= 120:
                j += 1
            gruppo = voci[i:j]
            recente = t.recente(gruppo[0]['ora'])
            blocchi += 1
            # svuotare una cartella lo fa chiunque: conta solo una
            # cancellazione davvero massiccia e recente
            t.segnala(39, R.DA_CONFERMARE if (recente and len(gruppo) >= 200) else R.INFORMATIVO, R.F_FILE,
                      tr(u'Cancellazione in blocco: %d elementi in %d minuti da %s')
                      % (len(gruppo), max(1, int((gruppo[-1]['ora'] - gruppo[0]['ora']) / 60) + 1), gruppo[0]['utente']),
                      tr(u'Dal %s al %s (UTC). Esempi:\n%s') % (T(gruppo[0]['ora']), T(gruppo[-1]['ora']),
                                                           u'\n'.join([g['percorso'] for g in gruppo[:8]])),
                      gruppo[0]['ora'], gruppo[0]['elemento'])
            i = j
        else:
            i += 1
    # strumenti cancellati
    for v in voci:
        # solo programmi, script e archivi: "nmap_cheatsheet.pdf" non e' nmap
        if tc_origine.estensione(R.nome_base(v['percorso'])) not in _ESTENSIONI_PROGRAMMI + _ESTENSIONI_ARCHIVI + [u'py']:
            continue
        peso, cosa = R.strumento(v['percorso'])
        if peso >= R.DA_CONFERMARE:
            # nel Cestino c'e' solo il nome: uno strumento d'attacco resta da confermare
            peso = min(peso, R.DA_CONFERMARE)
            t.segnala(39, peso, R.famiglia_strumento(v['percorso']),
                      tr(u'%s buttato nel Cestino: %s') % (cosa[0].upper() + cosa[1:], v['percorso']),
                      tr(u'Cancellato da %s il %s (UTC) - %s') % (v['utente'], T(v['ora']), _dimensione(v['dimensione'])),
                      v['ora'], v['elemento'], oggetti=(R.chiave_file(v['percorso']),))
    t.fatto(39)


# --------------------------------------------------------------------------
# Copie shadow (controllo 40)
# --------------------------------------------------------------------------

def shadow(t):
    if t.radice.piatta:
        t.esito(40, 'non verificabile', tr(u'serve la struttura delle cartelle'))
        return
    cartella = t.radice.file(u'', u'system volume information', cartelle=True, tutti_i_volumi=True)
    if not cartella:
        t.esito(40, 'assente', tr(u'cartella System Volume Information non presente nell\'origine'))
        return
    copie = [e for e in t.radice.file(u'system volume information/', u'%' + _GUID_SHADOW, tutti_i_volumi=True)
             if len(e.nome) > len(_GUID_SHADOW) + 10]
    righe = [[e.nome[:38], T(e.creato), _dimensione(e.dimensione)] for e in sorted(copie, key=lambda e: e.creato)]
    t.tabella(40, tr(u'Copie shadow presenti'), [tr(u'Identificativo'), tr(u'Creata (UTC)'), tr(u'Dimensione')], righe,
              tr(u'Le copie possono contenere file e registri cancellati dopo: montale e confrontale. '
              u'Autopsy non le apre da solo.'))
    t.contesto['copie_shadow'] = len(copie)
    t.fatto(40)
    if copie:
        return
    vssadmin = None
    for x in t.esecuzioni:
        if x['eseguito'] and R.nome_base(x['percorso']) in (u'vssadmin.exe', u'wbadmin.exe') and x['ora']:
            if vssadmin is None or x['ora'] > vssadmin['ora']:
                vssadmin = x
    if vssadmin is not None and t.contesto.get('ripristino_spento'):
        t.esito(40, 'fatto', tr(u'nessuna copia: il ripristino di sistema \u00e8 disattivato'))
    elif vssadmin is not None and not t.recente(vssadmin['ora']):
        t.esito(40, 'fatto', tr(u'nessuna copia shadow; %s \u00e8 stato eseguito l\'ultima volta il %s, fuori dal periodo recente')
                % (R.nome_base(vssadmin['percorso']), T(vssadmin['ora'])))
    elif vssadmin is not None:
        t.segnala(40, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                  tr(u'Nessuna copia shadow sul disco e %s \u00e8 stato eseguito (ultimo avvio: %s)')
                  % (R.nome_base(vssadmin['percorso']), T(vssadmin['ora'])),
                  tr(u'L\'esecuzione non prova la cancellazione: cerca \u00abdelete shadows\u00bb negli eventi 4688 e nei log di PowerShell. '
                  u'Fonte: %s.') % vssadmin['fonte'], vssadmin['ora'], vssadmin['elemento'],
                  oggetti=(R.chiave_file(vssadmin['percorso']),))
    elif t.contesto.get('ripristino_spento'):
        t.esito(40, 'fatto', tr(u'nessuna copia: il ripristino di sistema \u00e8 disattivato'))
    else:
        t.esito(40, 'fatto', tr(u'nessuna copia shadow trovata'))
