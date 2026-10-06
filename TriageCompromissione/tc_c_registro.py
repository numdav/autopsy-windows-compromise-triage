# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_c_registro - Controlli che leggono il registro di Windows: sistema,
persistenza (Run, servizi, attivita' pianificate), account, programmi
eseguiti (BAM, ShimCache, UserAssist, AmCache), artefatti disattivati.
"""

import re

import tc_registro
import tc_artefatti
import tc_regole as R
from tc_base import leggi, filetime_a_epoch, testo_orario as T, ERRORI
from tc_lingua import tr

_ACCESSIBILITA = set([u'sethc.exe', u'utilman.exe', u'osk.exe', u'narrator.exe', u'magnify.exe',
                      u'displayswitch.exe', u'atbroker.exe'])
_INTERPRETI_DI_SERVIZIO = set([u'cmd.exe', u'powershell.exe', u'pwsh.exe', u'mshta.exe', u'wscript.exe',
                               u'cscript.exe'])
# interpreti che in RunMRU meritano almeno uno sguardo quando hanno argomenti
_INTERPRETI_DA_ESEGUI = set([u'cmd.exe', u'powershell.exe', u'pwsh.exe', u'mshta.exe', u'wscript.exe', u'cscript.exe',
                             u'rundll32.exe', u'regsvr32.exe', u'wmic.exe', u'forfiles.exe', u'bash.exe', u'wsl.exe',
                             u'certutil.exe', u'bitsadmin.exe', u'curl.exe', u'msbuild.exe', u'installutil.exe',
                             u'regasm.exe', u'regsvcs.exe', u'cmstp.exe', u'odbcconf.exe', u'hh.exe', u'pcalua.exe',
                             u'scriptrunner.exe', u'at.exe', u'pythonw.exe', u'powershell_ise.exe', u'msdt.exe',
                             u'ftp.exe', u'tftp.exe'])
_RX_CONCATENA = re.compile(u'([|&^]|;\\s*\\S)')
_ACCOUNT_PREDEFINITI = set([u'administrator', u'guest', u'defaultaccount', u'wdagutilityaccount', u'krbtgt',
                            u'defaultuser0', u'homegroupuser$', u'support_388945a0'])
_CHIAVI_TRACCIATE = [
    (u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', u'RunMRU'),
    (u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist', u'UserAssist'),
    (u'Software\\Microsoft\\Windows\\Shell\\BagMRU', u'BagMRU (Shellbags)'),
    (u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs', u'RecentDocs'),
    (u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths', u'TypedPaths'),
]
_CHIAVI_TRACCIATE_CLASSI = [
    (u'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU', u'BagMRU (Shellbags)'),
    (u'Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache', u'MUICache'),
]


# --------------------------------------------------------------------------
# apertura degli hive
# --------------------------------------------------------------------------

def carica_hive(t, elemento, etichetta=None, avvisa=True):
    """Carica un hive dall'origine, con i transaction log se e' 'sporco'.
    Restituisce l'hive oppure None. Un file che esiste ma non e' un hive
    valido, o un hive con blocchi rovinati, e' una lacuna nei controlli: con
    avvisa=True lo dice (chi chiama con avvisa=False da' il suo avviso).
    'etichetta' e' il nome da mostrare ("NTUSER.DAT di mario")."""
    if elemento is None:
        return None
    etichetta = etichetta or elemento.nome
    dati = t.contenuto(elemento)
    if dati is None:
        return None             # non letto: e' gia' tra i file non letti
    valido = len(dati) >= 0x1020 and dati[:4] == 'regf'
    log = []
    h = None
    if valido:
        seq1, seq2 = leggi('<II', dati, 4)
        if seq1 != seq2:
            for suffisso in (u'.log1', u'.log2'):
                try:
                    fratelli = t.radice.origine.fratelli(elemento, elemento.nome + suffisso)
                except ERRORI, ex:
                    t.fallita(tr(u'Ricerca dei transaction log di %s non riuscita') % etichetta, ex)
                    fratelli = []
                for f in fratelli:
                    if f.dimensione > 1024:
                        dati_log = t.contenuto(f, 512 * 1024 * 1024)
                        if dati_log is not None:
                            log.append(dati_log)
                        break
        try:
            h = tc_registro.Hive(dati, log)
        except ERRORI:
            h = None
    if h is None:
        if avvisa:
            t.avviso(tr(u'%s esiste (%d byte) ma non \u00e8 un hive del registro valido: file vuoto, azzerato o '
                     u'danneggiato. I controlli che lo leggono non sono stati fatti.') % (etichetta, len(dati)))
        return None
    blocchi, rovinati = h.blocchi()
    if rovinati:
        t.avviso(tr(u'L\'hive %s \u00e8 danneggiato: %d blocchi su %d non sono validi (file troncato, azzerato in parte o '
                 u'sovrascritto). I controlli che lo leggono possono essere incompleti.') % (etichetta, rovinati, blocchi))
    t.celle_di(etichetta, h)
    if h.sporco and not h.log_applicati:
        t.registra(tr(u'Hive %s non chiuso correttamente e senza transaction log utilizzabili: '
                   u'le ultime modifiche possono mancare.') % elemento.percorso)
        if elemento.nome.lower() in (u'software', u'system', u'sam'):
            t.nota(tr(u'L\'hive %s non era stato chiuso correttamente e i suoi transaction log non sono utilizzabili: '
                   u'le ultimissime modifiche al registro possono mancare.') % elemento.nome)
    return h


def _apri(t, cartella, nome):
    e = t.radice.uno(cartella, nome)
    if e is None:
        return None, None
    return carica_hive(t, e, nome.upper(), False), e


def _prova(t, nome, funzione, *argomenti):
    """Esegue una parte di un controllo. Se si interrompe, l'errore viene
    annotato e le parti successive vengono eseguite lo stesso."""
    try:
        funzione(*argomenti)
    except ERRORI:
        import traceback
        try:
            traccia = traceback.format_exc().decode('utf-8', 'replace')
        except ERRORI:
            traccia = tr(u'(traccia non disponibile)')
        t.errori.append(u'%s: %s' % (nome, traccia[-1200:]))
        t.registra(tr(u'Errore in "%s": %s') % (nome, traccia))


def _testo(chiave, nome, predefinito=u''):
    """Il valore come testo. Il registro di una macchina compromessa (o
    danneggiato) puo' contenere tipi inattesi: qui non ci si fida."""
    v = chiave.dato(nome)
    if isinstance(v, unicode):
        return v
    if isinstance(v, list):
        return u' '.join([x for x in v if isinstance(x, unicode)])
    return predefinito


def _numero(chiave, nome, predefinito=0):
    """Il valore come numero intero; il predefinito se manca o non e' un numero."""
    v = chiave.dato(nome)
    if isinstance(v, (int, long)) and not isinstance(v, bool):
        return v
    if isinstance(v, unicode):
        try:
            return int(v.strip())
        except ValueError:
            return predefinito
    return predefinito


def giudica_persistenza(t, controllo, tipo, nome, comando, argomenti=None, ora=0, elemento=None,
                        nota=u'', extra=False, minimo=0, perche=u''):
    """Valuta una voce che fa partire qualcosa da sola (servizio, attivita',
    chiave Run...) e aggiunge il segnale se serve. Con minimo il segnale
    viene dato comunque, almeno con quel peso e con la spiegazione di
    perche. Restituisce (peso, motivo)."""
    g = R.valuta_comando(comando, argomenti)
    riga = comando if argomenti is None else (comando + u' ' + argomenti).strip()
    peso = {3: R.DECISIVO, 2: R.DA_CONFERMARE, 1: R.INFORMATIVO}.get(g.livello, 0)
    motivi = list(g.motivi)
    famiglia = R.F_PERSISTENZA
    peso_s, cosa = R.strumento(g.nome)
    if peso_s >= R.DA_CONFERMARE:
        if peso_s > peso or peso_s >= R.DECISIVO:
            famiglia = R.famiglia_strumento(g.nome)     # conta come lo strumento, non come persistenza
        peso = max(peso, peso_s)
        motivi.append(cosa)
    for peso_c, _, cosa_c in R.comandi_noti(riga):
        peso = max(peso, peso_c)
        motivi.append(cosa_c)
    strumento = R.trova_rmm(riga)
    if strumento:
        t.prova_rmm(strumento, tipo.lower(), u'%s: %s' % (nome, riga[:300]), ora, elemento, controllo)
    if peso < minimo:
        peso = minimo
        if perche:
            motivi.append(perche)
    if not peso:
        return 0, u''
    motivo = u'; '.join(motivi)
    dettagli = riga[:2000]
    if g.decodificato:
        dettagli += tr(u'\nComando in chiaro: ') + u' '.join(g.decodificato.split())[:1500]
    if nota:
        dettagli += u'\n' + nota
    t.segnala(controllo, peso, famiglia, tr(u'%s \u00ab%s\u00bb: %s') % (tipo, nome, motivo), dettagli, ora,
              elemento, extra)
    return peso, motivo


# --------------------------------------------------------------------------
# SOFTWARE
# --------------------------------------------------------------------------

def software(t):
    h, e = _apri(t, u'windows/system32/config/', u'software')
    if h is None:
        motivo = tr(u'hive SOFTWARE non trovato') if e is None else tr(u'hive SOFTWARE non leggibile o danneggiato')
        for c in (16, 19, 32):
            t.esito(c, 'assente', motivo)
        t.avviso(tr(u'%s: mancano i controlli su chiavi Run, attivit\u00e0 pianificate nel registro, programmi installati '
                 u'e impostazioni di Defender.') % (motivo[0].upper() + motivo[1:]))
        return
    t.contesto['hive_software'] = e
    cv = h.apri(u'Microsoft\\Windows NT\\CurrentVersion')
    if cv is not None:
        prodotto = _testo(cv, u'ProductName')
        build = _numero(cv, u'CurrentBuildNumber') or _numero(cv, u'CurrentBuild')
        if build >= 22000 and u'Windows 10' in prodotto:
            prodotto = prodotto.replace(u'Windows 10', u'Windows 11')
        t.contesto['prodotto'] = prodotto
        t.contesto['build'] = build
        t.contesto['versione'] = _testo(cv, u'DisplayVersion') or _testo(cv, u'ReleaseId') or _testo(cv, u'CSDVersion')
        installato = _numero(cv, u'InstallDate')
        if installato > 0:
            t.contesto['installato'] = float(installato)
        t.contesto['proprietario'] = _testo(cv, u'RegisteredOwner')
    if h.apri(u'Microsoft\\Windows\\CurrentVersion') is None:
        t.avviso(tr(u'Nell\'hive SOFTWARE non si trova la chiave Microsoft\\Windows\\CurrentVersion: l\'hive \u00e8 '
                 u'danneggiato e i controlli su chiavi Run, programmi installati e attivit\u00e0 pianificate sono '
                 u'incompleti.'))
    _prova(t, tr(u'SOFTWARE: profili'), _profili, t, h)
    _prova(t, tr(u'SOFTWARE: chiavi Run'), _run, t, h, e, u'HKLM',
           [u'Microsoft\\Windows\\CurrentVersion\\Run',
            u'Microsoft\\Windows\\CurrentVersion\\RunOnce',
            u'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
            u'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
            u'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'])
    _prova(t, u'SOFTWARE: Winlogon', _winlogon, t, h, e)
    _prova(t, tr(u'SOFTWARE: programmi installati'), _installati, t, h, e,
           [u'Microsoft\\Windows\\CurrentVersion\\Uninstall',
            u'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'], u'')
    _prova(t, tr(u'SOFTWARE: attivit\u00e0 pianificate'), _taskcache, t, h, e)
    _prova(t, u'SOFTWARE: Defender', _defender, t, h, e)
    _prova(t, tr(u'SOFTWARE: impostazioni'), _impostazioni, t, h)
    t.fatto(1, 19, 32)


def _profili(t, h):
    pl = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\ProfileList')
    if pl is None:
        return
    for k in pl.sottochiavi():
        percorso = _testo(k, u'ProfileImagePath')
        if not percorso:
            continue
        t.profili[k.nome] = {'percorso': percorso, 'nome': R.nome_base(percorso) and percorso.replace(u'/', u'\\').rstrip(u'\\').split(u'\\')[-1],
                             'ora': k.orario}


def _run(t, h, e, dove, chiavi):
    righe = t.contesto.setdefault('righe_run', [])
    for percorso in chiavi:
        k = h.apri(percorso)
        if k is None:
            continue
        for v in k.valori():
            if v.tipo not in (tc_registro.REG_SZ, tc_registro.REG_EXPAND_SZ):
                continue
            comando = v.testo()
            if not comando:
                continue
            peso, motivo = giudica_persistenza(
                t, 19, tr(u'Chiave Run'), v.nome, comando, elemento=e,
                nota=tr(u'%s\\%s - ultima scrittura della chiave: %s') % (dove, percorso, T(k.orario)))
            righe.append([dove, percorso.split(u'\\')[-1], v.nome, comando[:300],
                          R.NOME_PESO.get(peso, u''), motivo])


def _winlogon(t, h, e):
    k = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
    if k is not None:
        shell = _testo(k, u'Shell').strip()
        if shell and shell.lower() not in (u'explorer.exe', u'c:\\windows\\explorer.exe'):
            t.segnala(19, R.DA_CONFERMARE, R.F_PERSISTENZA,
                      tr(u'Winlogon\\Shell non \u00e8 explorer.exe: \u00ab%s\u00bb') % shell[:200], shell,
                      elemento=e, extra=True)
        userinit = _testo(k, u'Userinit').strip()
        if userinit:
            parti = [p.strip().strip(u'"').strip() for p in userinit.split(u',')]
            strane = []
            for p in parti:
                if not p:
                    continue
                if R.con_estensione(R.nome_base(p)) == u'userinit.exe' and R.zona(p) in (u'sistema', u'altro') \
                        and not R.fuori_posto(p):
                    continue
                strane.append(p)
            if strane:
                # Alcuni prodotti (VMware Horizon, Citrix) aggiungono qui un loro
                # programma dalla cartella Programmi: quello e' da confermare.
                # E' decisivo un interprete, o un programma in una cartella
                # scrivibile dagli utenti.
                peso = R.DA_CONFERMARE
                for p in strane:
                    g = R.valuta_comando(p)
                    if g.interprete or g.livello >= 2 or g.zona in (u'sospetta', u'temporanea', u'utente', u'rete'):
                        peso = R.DECISIVO
                t.segnala(19, peso, R.F_PERSISTENZA,
                          tr(u'Winlogon\\Userinit avvia altro oltre a userinit.exe: \u00ab%s\u00bb') % u', '.join(strane)[:200],
                          userinit, elemento=e, extra=True)
    nascosti = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList')
    if nascosti is not None:
        nomi = [v.nome for v in nascosti.valori() if v.nome and v.valore() == 0]
        if nomi:
            t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT,
                      (tr(u'Account nascosto dalla schermata di accesso: %s') if len(nomi) == 1 else
                       tr(u'Account nascosti dalla schermata di accesso: %s')) % u', '.join(nomi[:10]),
                      tr(u'Winlogon\\SpecialAccounts\\UserList - ultima scrittura della chiave: %s (UTC)\n'
                      u'L\'account esiste e pu\u00f2 collegarsi, ma non compare tra gli utenti: lo fa chi vuole tenere '
                      u'un accesso senza farsi notare (e qualche prodotto di assistenza remota).') % T(nascosti.orario),
                      nascosti.orario, e, extra=True)
    ifeo = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options')
    if ifeo is not None:
        for k in ifeo.sottochiavi():
            debugger = k.dato(u'Debugger')
            if not isinstance(debugger, unicode) or not debugger.strip():
                continue
            if k.nome.lower() in _ACCESSIBILITA:
                t.segnala(19, R.DECISIVO, R.F_PERSISTENZA,
                          tr(u'Debugger impostato su %s: si apre dalla schermata di accesso senza credenziali '
                          u'(backdoor \u00absticky keys\u00bb)') % k.nome, debugger, k.orario, e, extra=True)
            else:
                g = R.valuta_comando(debugger)
                if g.livello >= 2:
                    t.segnala(19, R.DA_CONFERMARE, R.F_PERSISTENZA,
                              tr(u'Debugger impostato su %s: %s') % (k.nome, g.motivo()), debugger, k.orario, e,
                              extra=True)
    w = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\Windows')
    if w is not None:
        dll = _testo(w, u'AppInit_DLLs')
        if dll.strip() and w.dato(u'LoadAppInit_DLLs', 0) == 1:
            peso = R.DA_CONFERMARE if R.zona(dll.split(u',')[0].split(u' ')[0]) != u'sistema' else R.INFORMATIVO
            t.segnala(19, peso, R.F_PERSISTENZA, tr(u'AppInit_DLLs carica una DLL in ogni processo: \u00ab%s\u00bb')
                      % dll[:200], dll, elemento=e, extra=True)


def _installati(t, h, e, chiavi, utente):
    righe = t.contesto.setdefault('righe_installati', [])
    for percorso in chiavi:
        base = h.apri(percorso)
        if base is None:
            continue
        for k in base.sottochiavi():
            nome = k.dato(u'DisplayName')
            if not isinstance(nome, unicode) or not nome:
                continue
            produttore = k.dato(u'Publisher', u'')
            if not isinstance(produttore, unicode):
                produttore = u''
            cartella = k.dato(u'InstallLocation', u'')
            if not isinstance(cartella, unicode):
                cartella = u''
            righe.append((k.orario, nome, produttore, utente))
            strumento = R.trova_rmm(nome + u' ' + produttore)
            if strumento:
                t.prova_rmm(strumento, tr(u'programma installato'),
                            u'%s (%s)%s' % (nome, produttore, u' in ' + cartella if cartella else u''),
                            k.orario, e, 32, genere='installato')


def _taskcache(t, h, e):
    base = u'Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\'
    albero = h.apri(base + u'Tree')
    schede = h.apri(base + u'Tasks')
    if albero is None:
        t.esito(16, 'assente', tr(u'chiave TaskCache non trovata'))
        return
    moderno = t.contesto.get('build', 0) >= 10240
    schede_per_nome = {}
    if schede is not None:
        for scheda in schede.sottochiavi():
            schede_per_nome[scheda.nome.lower()] = scheda
    for k, percorso in albero.discendenti(massimo=50000):
        valori = {}
        for v in k.valori():
            valori[v.nome.lower()] = v
        if u'id' not in valori:
            continue
        ident = valori[u'id'].valore()
        if not isinstance(ident, unicode):
            continue
        voce = {'percorso': u'\\' + percorso, 'azioni': [], 'contesto': u'', 'creato': 0.0, 'ultimo_avvio': 0.0,
                'autore': u'', 'ora_chiave': k.orario, 'nascosta': u'', 'scheda': False, 'elemento': e}
        scheda = schede_per_nome.get(ident.lower())
        if scheda is not None:
            voce['scheda'] = True
            for v in scheda.valori():
                n = v.nome.lower()
                if n == u'actions':
                    voce['contesto'], voce['azioni'] = tc_artefatti.azioni_taskcache(v.dati)
                elif n == u'author':
                    voce['autore'] = v.testo()
                elif n == u'dynamicinfo' and len(v.dati) >= 20:
                    voce['creato'] = filetime_a_epoch(leggi('<Q', v.dati, 4)[0])
                    voce['ultimo_avvio'] = filetime_a_epoch(leggi('<Q', v.dati, 12)[0])
            if not voce['creato']:
                voce['creato'] = scheda.orario
        if moderno:
            if u'sd' not in valori:
                voce['nascosta'] = tr(u'manca il valore SD (tecnica usata dal malware Tarrask di HAFNIUM)')
            elif u'index' in valori and valori[u'index'].valore() == 0 and scheda is not None:
                voce['nascosta'] = tr(u'il valore Index \u00e8 0 ma l\'attivit\u00e0 \u00e8 registrata')
        t.attivita[voce['percorso'].lower()] = voce
    if moderno:
        t.fatto(16)
    else:
        t.esito(16, 'non verificabile',
                tr(u'prima di Windows 10 il valore SD manca anche nelle attivit\u00e0 legittime'))
    t.fatto(15)


def _defender(t, h, e):
    """Esclusioni e protezioni disattivate di Defender (regola in piu'
    rispetto alle guide)."""
    for base in (u'Microsoft\\Windows Defender', u'Policies\\Microsoft\\Windows Defender'):
        esclusioni = h.apri(base + u'\\Exclusions')
        if esclusioni is not None:
            for gruppo in esclusioni.sottochiavi():
                for v in gruppo.valori():
                    cosa = v.nome
                    if not cosa:
                        continue
                    tipo = gruppo.nome.lower()
                    grave = False
                    if tipo == u'paths':
                        z = R.zona(cosa + u'\\x.exe')
                        normale = R.percorso_normale(cosa).rstrip(u'\\')
                        grave = z in (u'sospetta', u'temporanea') or normale in (u'', u'\\users', u'\\programdata',
                                                                                 u'\\windows', u'\\windows\\temp')
                        grave = grave or re.search(u'\\\\users\\\\[^\\\\]+(\\\\(appdata|downloads|desktop|documents))?$',
                                                   normale) is not None
                    elif tipo == u'extensions':
                        grave = cosa.lower().strip(u'.*') in (u'exe', u'dll', u'ps1', u'bat', u'cmd', u'vbs', u'js',
                                                               u'scr', u'hta')
                    elif tipo == u'processes':
                        grave = R.nome_base(cosa) in R.INTERPRETI or R.zona(cosa) in (u'sospetta', u'temporanea')
                    t.segnala(37, R.DA_CONFERMARE if grave else R.INFORMATIVO, R.F_ANTIFORENSE,
                              tr(u'Esclusione di Defender (%s): %s') % (gruppo.nome, cosa),
                              tr(u'%s\\Exclusions\\%s - ultima scrittura della chiave: %s') % (base, gruppo.nome, T(gruppo.orario)),
                              elemento=e, extra=True)
        k = h.apri(base)
        if k is not None and k.dato(u'DisableAntiSpyware', 0) == 1:
            t.segnala(37, R.DA_CONFERMARE, R.F_ANTIFORENSE, tr(u'Defender disattivato dal registro (DisableAntiSpyware = 1)'),
                      base, k.orario, e, extra=True)
        k = h.apri(base + u'\\Real-Time Protection')
        if k is not None and k.dato(u'DisableRealtimeMonitoring', 0) == 1:
            t.segnala(37, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                      tr(u'Protezione in tempo reale di Defender disattivata dal registro'), base, k.orario, e, extra=True)


def _impostazioni(t, h):
    k = h.apri(u'Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit')
    t.contesto['riga_di_comando'] = bool(k is not None and k.dato(u'ProcessCreationIncludeCmdLine_Enabled', 0) == 1)
    canali = h.apri(u'Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels')
    spenti = []
    if canali is not None:
        for nome in (u'Microsoft-Windows-TaskScheduler/Operational',
                     u'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                     u'Microsoft-Windows-PowerShell/Operational',
                     u'Microsoft-Windows-Windows Defender/Operational'):
            c = canali.sottochiave(nome)
            if c is not None and c.dato(u'Enabled', 1) == 0:
                spenti.append(nome)
    t.contesto['canali_spenti'] = spenti
    sr = h.apri(u'Microsoft\\Windows NT\\CurrentVersion\\SystemRestore')
    if sr is not None:
        t.contesto['ripristino_spento'] = sr.dato(u'DisableSR', 0) == 1 or sr.dato(u'RPSessionInterval', 1) == 0


# --------------------------------------------------------------------------
# SYSTEM
# --------------------------------------------------------------------------

def system(t):
    h, e = _apri(t, u'windows/system32/config/', u'system')
    if h is None:
        motivo = tr(u'hive SYSTEM non trovato') if e is None else tr(u'hive SYSTEM non leggibile o danneggiato')
        for c in (17, 22, 26):
            t.esito(c, 'assente', motivo)
        t.avviso(tr(u'%s: mancano i controlli su servizi, BAM e ShimCache.') % (motivo[0].upper() + motivo[1:]))
        return
    t.contesto['hive_system'] = e
    t.fatto(1)
    selezione = h.apri(u'Select')
    corrente = 1
    if selezione is not None:
        corrente = _numero(selezione, u'Current', 1) or 1
    ccs = u'ControlSet%03d' % corrente
    if h.apri(ccs) is None:
        ccs = u'ControlSet001'
        if h.apri(ccs) is None:
            t.avviso(tr(u'Nell\'hive SYSTEM non si trova nessun ControlSet: l\'hive \u00e8 danneggiato e i controlli su '
                     u'servizi, BAM e ShimCache non sono stati fatti.'))
    k = h.apri(ccs + u'\\Control\\ComputerName\\ComputerName')
    if k is not None:
        t.contesto['computer'] = _testo(k, u'ComputerName').strip()
    k = h.apri(ccs + u'\\Control\\TimeZoneInformation')
    if k is not None:
        t.contesto['fuso'] = _testo(k, u'TimeZoneKeyName') or _testo(k, u'StandardName')
        scarto = k.dato(u'ActiveTimeBias')
        if isinstance(scarto, (int, long)):
            if scarto >= 0x80000000:
                scarto -= 0x100000000
            t.contesto['scarto_minuti'] = -int(scarto)
    k = h.apri(ccs + u'\\Control\\Windows')
    if k is not None:
        v = k.valore(u'ShutdownTime')
        if v is not None and len(v.dati) >= 8:
            t.contesto['spegnimento'] = filetime_a_epoch(leggi('<Q', v.dati, 0)[0])
            t.vede(t.contesto['spegnimento'], True, u'spegnimento')
    k = h.apri(ccs + u'\\Control\\ProductOptions')
    if k is not None:
        tipo = _testo(k, u'ProductType')
        t.contesto['tipo_prodotto'] = tipo
        t.contesto['server'] = tipo.lower() in (u'servernt', u'lanmannt')
        t.contesto['controller_di_dominio'] = tipo.lower() == u'lanmannt'
    k = h.apri(ccs + u'\\Services\\Tcpip\\Parameters')
    if k is not None:
        t.contesto['dominio'] = _testo(k, u'Domain') or _testo(k, u'NV Domain')
    k = h.apri(ccs + u'\\Control\\Terminal Server')
    if k is not None:
        t.contesto['rdp_attivo'] = k.dato(u'fDenyTSConnections', 1) == 0
    k = h.apri(ccs + u'\\Services\\EventLog')
    if k is not None and k.dato(u'Start', 2) == 4:
        t.segnala(8, R.DA_CONFERMARE, R.F_ANTIFORENSE, tr(u'Il servizio Registro eventi \u00e8 disattivato (Start = 4)'),
                  ccs + u'\\Services\\EventLog', k.orario, e)
    k = h.apri(ccs + u'\\Control\\Session Manager\\Memory Management\\PrefetchParameters')
    if k is not None:
        t.contesto['prefetch_attivo'] = k.dato(u'EnablePrefetcher', 3) != 0
    k = h.apri(ccs + u'\\Control\\SecurityProviders\\WDigest')
    if k is not None and k.dato(u'UseLogonCredential', 0) == 1:
        t.segnala(41, R.DA_CONFERMARE, R.F_STRUMENTI,
                  tr(u'WDigest conserva le password in chiaro in memoria (UseLogonCredential = 1)'),
                  tr(u'Impostazione usata per poi leggere le password con strumenti come Mimikatz. '
                  u'Ultima scrittura della chiave: %s') % T(k.orario), k.orario, e, extra=True)
    _prova(t, tr(u'SYSTEM: inoltro di porta'), _portproxy, t, h, e, ccs)
    _prova(t, tr(u'SYSTEM: servizi'), _servizi, t, h, e, ccs)
    _prova(t, u'SYSTEM: BAM', _bam, t, h, e, ccs)
    _prova(t, u'SYSTEM: ShimCache', _shimcache, t, h, e, ccs)


def _portproxy(t, h, e, ccs):
    """Le regole di inoltro di porta ("netsh interface portproxy"): fanno
    ascoltare la macchina su una porta e girano le connessioni altrove. Chi
    attacca le usa per raggiungere macchine interne passando da questa."""
    base = h.apri(ccs + u'\\Services\\PortProxy')
    if base is None:
        return
    regole = []
    ultima = 0
    for verso in base.sottochiavi():
        for protocollo in verso.sottochiavi():
            for v in protocollo.valori():
                destinazione = v.testo()
                if v.nome and destinazione:
                    regole.append(u'%s -> %s (%s %s)' % (v.nome.replace(u'/', u':'), destinazione.replace(u'/', u':'),
                                                         verso.nome, protocollo.nome))
                    ultima = max(ultima, protocollo.orario or 0)
    if regole:
        t.segnala(17, R.DA_CONFERMARE, R.F_ESFILTRAZIONE,
                  tr(u'Inoltro di porta attivo (netsh portproxy): %s%s') % (u'; '.join(regole[:4]),
                                                                        tr(u' e altre') if len(regole) > 4 else u''),
                  tr(u'%s\nUltima scrittura della chiave: %s (UTC)\nLe connessioni che arrivano sulla prima porta vengono '
                  u'girate alla seconda destinazione. Lo usano WSL e qualche ambiente di sviluppo; su un server o su un '
                  u'client d\'ufficio va spiegato.') % (u'\n'.join(regole[:40]), T(ultima)), ultima, e, extra=True)


def giudica_servizio(nome, percorso):
    """Valuta un servizio dal nome e dalla riga di comando del suo
    programma. Restituisce (peso, controllo, famiglia, motivi)."""
    g = R.valuta_comando(percorso)
    peso = 0
    motivi = []
    controllo = 17
    famiglia = R.F_PERSISTENZA
    firma = R.firma_smbexec(nome, percorso)
    if firma:
        peso, controllo, famiglia = firma[0], 29, R.F_LATERALE
        motivi.append(firma[1])
    if g.nome in _INTERPRETI_DI_SERVIZIO:
        # Un servizio vero e' un programma scritto per esserlo. cmd o
        # PowerShell come servizio sono il trucco di chi esegue un comando
        # come SYSTEM: lo usano gli attaccanti, a volte anche un amministratore.
        # Diventa decisivo se il comando ha anche i segni di un attacco.
        peso = max(peso, R.DA_CONFERMARE)
        motivi.append(tr(u'il servizio lancia %s invece di un proprio programma') % g.nome)
    if g.livello >= 3:
        peso = R.DECISIVO
    elif g.livello == 2 and peso < R.DA_CONFERMARE:
        peso = R.DA_CONFERMARE
    elif g.livello == 1 and not peso and R.percorso_normale(g.eseguibile).startswith(u'\\users\\'):
        peso = R.DA_CONFERMARE
    if g.livello >= 2 or (g.livello == 1 and peso):
        motivi.extend(g.motivi)
    noti = R.comandi_noti(percorso)
    for peso_c, famiglia_c, cosa_c in noti:
        if peso_c > peso:
            famiglia = famiglia_c
        peso = max(peso, peso_c)
        motivi.append(cosa_c)
    if noti and g.nome in _INTERPRETI_DI_SERVIZIO and peso < R.DECISIVO:
        # cmd o PowerShell messi a fare da servizio per creare un account,
        # spegnere le protezioni o cancellare tracce girano come SYSTEM:
        # le due cose insieme non hanno una spiegazione innocente
        peso = R.DECISIVO
        motivi.append(tr(u'un servizio creato solo per eseguire questo comando come SYSTEM'))
    peso_s, cosa = R.strumento(g.nome)
    if peso_s >= R.DA_CONFERMARE:
        if peso_s > peso or peso_s >= R.DECISIVO:
            famiglia = R.famiglia_strumento(g.nome)
        peso = max(peso, peso_s)
        motivi.append(cosa)
    if R.eseguibile_casuale_in_windows(percorso):
        peso = max(peso, R.DA_CONFERMARE)
        famiglia = R.F_LATERALE
        motivi.append(tr(u'eseguibile con nome di 8 lettere a caso in C:\\Windows (tipico di psexec.py e Metasploit)'))
    return peso, controllo, famiglia, motivi


def _servizi(t, h, e, ccs):
    base = h.apri(ccs + u'\\Services')
    if base is None:
        t.esito(17, 'assente', tr(u'chiave Services non trovata'))
        t.avviso(tr(u'Nell\'hive SYSTEM non si trova la chiave dei servizi (%s\\Services): l\'hive \u00e8 danneggiato '
                 u'e i servizi non sono stati controllati.') % ccs)
        return
    righe = []
    quanti = [0]
    falliti = [0]
    for numero, s in enumerate(base.sottochiavi()):
        if t.battito(numero, 2000, tr(u'Registro: SYSTEM, %d servizi esaminati')):
            return
        try:
            _un_servizio(t, s, e, righe, quanti)
        except ERRORI:
            # un servizio con dati inattesi non deve far perdere gli altri
            falliti[0] += 1
            if falliti[0] == 1:
                import traceback
                t.errori.append(tr(u'SYSTEM: servizio %s: %s')
                                % (s.nome, traceback.format_exc().decode('utf-8', 'replace')[-800:]))
    if falliti[0] > 1:
        t.errori.append(tr(u'SYSTEM: in tutto %d servizi non valutati per un errore') % falliti[0])
    t.contesto['numero_servizi'] = quanti[0]
    t.tabella(17, tr(u'Servizi da guardare'), [tr(u'Servizio'), tr(u'Percorso'), tr(u'Ultima scrittura (UTC)'), tr(u'Peso'), tr(u'Motivo')], righe)
    t.fatto(17, 29)


def _un_servizio(t, s, e, righe, quanti):
    percorso = s.dato(u'ImagePath')
    if not isinstance(percorso, unicode) or not percorso.strip():
        return
    quanti[0] += 1
    nome = s.nome
    mostrato = _testo(s, u'DisplayName')
    peso, controllo, famiglia, motivi = giudica_servizio(nome, percorso)
    parametri = s.sottochiave(u'Parameters')
    if parametri is not None:
        dll = _testo(parametri, u'ServiceDll')
        if dll and R.zona(dll) in (u'sospetta', u'temporanea', u'utente'):
            peso = max(peso, R.DA_CONFERMARE)
            motivi.append(tr(u'la DLL del servizio sta in una cartella scrivibile dagli utenti: %s') % dll)
    if peso and peso < R.DECISIVO and R.driver_forense(nome, percorso):
        peso = R.INFORMATIVO
        motivi.append(tr(u'driver di uno strumento di acquisizione forense: probabilmente lasciato da chi ha raccolto le prove'))
    strumento = R.trova_rmm(nome + u' ' + mostrato + u' ' + percorso)
    if strumento:
        t.prova_rmm(strumento, tr(u'servizio'), u'%s: %s' % (nome, percorso[:300]), s.orario, e, 32)
    if peso:
        motivo = u'; '.join(motivi)
        avvio = {0: tr(u'all\'avvio del sistema (0)'), 1: tr(u'di sistema (1)'), 2: tr(u'automatico (2)'), 3: tr(u'manuale (3)'),
                 4: tr(u'disattivato (4)')}.get(_numero(s, u'Start', -1), tr(u'non indicato'))
        t.segnala(controllo, peso, famiglia, tr(u'Servizio \u00ab%s\u00bb: %s') % (nome, motivo),
                  tr(u'%s\nAvvio: %s - Ultima scrittura della chiave: %s') % (percorso[:1500], avvio, T(s.orario)),
                  s.orario, e)
        righe.append([nome, percorso[:300], T(s.orario), R.NOME_PESO[peso], motivo])


def _bam(t, h, e, ccs):
    trovata = False
    for percorso in (ccs + u'\\Services\\bam\\State\\UserSettings', ccs + u'\\Services\\bam\\UserSettings',
                     ccs + u'\\Services\\dam\\State\\UserSettings', ccs + u'\\Services\\dam\\UserSettings'):
        base = h.apri(percorso)
        if base is None:
            continue
        trovata = True
        for u in base.sottochiavi():
            for v in u.valori():
                if v.tipo != tc_registro.REG_BINARY or len(v.dati) < 8 or u'\\' not in v.nome:
                    continue
                ora = filetime_a_epoch(leggi('<Q', v.dati, 0)[0])
                t.esecuzione(v.nome, ora, u'BAM', t.nome_utente(u.nome), elemento=e)
    if trovata:
        t.fatto(22)
    else:
        t.esito(22, 'assente', tr(u'chiave BAM non trovata: esiste da Windows 10 1709'))


def _shimcache(t, h, e, ccs):
    k = h.apri(ccs + u'\\Control\\Session Manager\\AppCompatCache')
    v = k.valore(u'AppCompatCache') if k is not None else None
    if v is None:
        t.esito(26, 'assente', tr(u'valore AppCompatCache non trovato'))
        return
    formato, voci = tc_artefatti.shimcache(v.dati)
    if not voci:
        t.esito(26, 'non verificabile', tr(u'formato di ShimCache non riconosciuto'))
        return
    t.contesto['shimcache'] = tr(u'%d voci, formato %s') % (len(voci), formato)
    for voce in voci:
        t.esecuzione(voce['percorso'], 0, u'ShimCache', elemento=e, eseguito=bool(voce['eseguito']),
                     nota=tr(u'ultima modifica del file: %s') % T(voce['modificato']) if voce['modificato'] else u'')
    t.fatto(26)


# --------------------------------------------------------------------------
# SAM
# --------------------------------------------------------------------------

def sam(t):
    h, e = _apri(t, u'windows/system32/config/', u'sam')
    if h is None:
        motivo = tr(u'hive SAM non trovato') if e is None else tr(u'hive SAM non leggibile o danneggiato')
        t.esito(10, 'assente', motivo)
        if e is not None or not t.radice.piatta:
            t.avviso(tr(u'%s: manca l\'elenco degli account locali e dei membri del gruppo Administrators.')
                     % (motivo[0].upper() + motivo[1:]))
        return
    t.contesto['utenti_sam'] = tc_artefatti.sam_utenti(h)
    t.contesto['sid_macchina'] = tc_artefatti.sam_sid_macchina(h)
    t.contesto['amministratori'] = tc_artefatti.sam_gruppo(h, 544)[1]
    t.contesto['utenti_rdp'] = tc_artefatti.sam_gruppo(h, 555)[1]
    t.contesto['hive_sam'] = e
    t.fatto(10)


def riepilogo_account(t):
    """Controllo 10: account locali, amministratori, profili, eventi sugli
    account."""
    utenti = t.contesto.get('utenti_sam') or []
    amministratori = t.contesto.get('amministratori') or []
    e = t.contesto.get('hive_sam')
    installato = t.contesto.get('installato', 0)
    sid_macchina = t.contesto.get('sid_macchina') or u''
    righe = []
    for u in utenti:
        e_admin = (u'%s-%d' % (sid_macchina, u['rid'])) in amministratori
        stato = []
        if u['disattivato']:
            stato.append(tr(u'disattivato'))
        if e_admin:
            stato.append(tr(u'amministratore'))
        if u['senza_password']:
            stato.append(tr(u'password non richiesta'))
        righe.append([u['nome'], unicode(u['rid']), T(u['creato']), T(u['ultimo_accesso']),
                      T(u['password_impostata']), unicode(u['accessi']), u', '.join(stato)])
        t.vede(u['ultimo_accesso'])
        predefinito = u['nome'].lower() in _ACCOUNT_PREDEFINITI
        if u['rid'] == 501 and e_admin:
            t.segnala(10, R.DECISIVO, R.F_ACCOUNT,
                      tr(u'L\'account Guest \u00e8 nel gruppo Administrators') + (u'' if u['disattivato'] else tr(u' ed \u00e8 attivo')),
                      tr(u'Password impostata: %s') % T(u['password_impostata']), u['password_impostata'], e, extra=True)
        elif u['rid'] == 501 and not u['disattivato']:
            t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT, tr(u'L\'account Guest \u00e8 attivo'),
                      tr(u'Password impostata: %s') % T(u['password_impostata']), u['password_impostata'], e, extra=True)
        if not predefinito and u['nome'].endswith(u'$'):
            t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT,
                      tr(u'Account locale \u00ab%s\u00bb con nome da account macchina ($ finale)') % u['nome'],
                      tr(u'Creato: %s') % T(u['creato']), u['creato'], e)
        vicino_installazione = installato and u['creato'] and abs(u['creato'] - installato) < 6 * 3600
        if not predefinito and u['rid'] >= 1000 and t.recente(u['creato']) and not vicino_installazione:
            t.segnala(10, R.DA_CONFERMARE, R.F_ACCOUNT,
                      tr(u'Account locale \u00ab%s\u00bb creato di recente (%s)%s')
                      % (u['nome'], T(u['creato']), tr(u', amministratore') if e_admin else u''),
                      tr(u'RID %d - ultimo accesso: %s - accessi: %d') % (u['rid'], T(u['ultimo_accesso']), u['accessi']),
                      u['creato'], e)
    t.tabella(10, tr(u'Account locali (SAM)'),
              [tr(u'Nome'), tr(u'RID'), tr(u'Creato (UTC)'), tr(u'Ultimo accesso'), tr(u'Password impostata'), tr(u'Accessi'), tr(u'Stato')], righe,
              tr(u'La data di creazione \u00e8 l\'ultima scrittura della chiave Names\\<nome>. Su un controller di dominio '
              u'il SAM contiene solo gli account locali di ripristino: gli account di dominio stanno in NTDS.dit.')
              if t.contesto.get('controller_di_dominio') else
              tr(u'La data di creazione \u00e8 l\'ultima scrittura della chiave Names\\<nome>.'))
    if amministratori:
        nomi = []
        for sid in amministratori:
            nome = sid
            for u in utenti:
                if sid == u'%s-%d' % (sid_macchina, u['rid']):
                    nome = u'%s (%s)' % (u['nome'], sid)
            if sid.endswith(u'-512') and not sid.startswith(sid_macchina + u'-'):
                nome = tr(u'Domain Admins del dominio (%s)') % sid
            nomi.append([nome])
        t.tabella(10, tr(u'Membri del gruppo Administrators'), [tr(u'Membro')], nomi)
    # profili: la data di creazione della cartella approssima il primo accesso
    righe = []
    copiate = 0
    try:
        cartelle = t.radice.file(u'users/', u'%', cartelle=True)
    except ERRORI, ex:
        t.fallita(tr(u'Ricerca delle cartelle dei profili non riuscita (controllo 10)'), ex)
        cartelle = []
    for c in cartelle:
        if c.nome.lower() in (u'public', u'default', u'default user', u'all users', u'.', u'..'):
            continue
        righe.append((c.creato, [c.nome, T(c.creato), T(c.modificato)]))
        if t.date_della_copia() or c.creato > t.ultima_attivita() + 86400.0:
            # creata dopo l'ultima attivita' della macchina: e' la data di
            # una copia, non dice quando e' nato il profilo
            copiate += 1
            continue
        if t.recente(c.creato) and not (installato and abs(c.creato - installato) < 6 * 3600):
            t.segnala(10, R.INFORMATIVO, R.F_ACCOUNT,
                      tr(u'Profilo \u00ab%s\u00bb creato di recente (%s): primo accesso di quell\'utente alla macchina')
                      % (c.nome, T(c.creato)), c.percorso, c.creato, c)
    righe.sort(key=lambda x: -x[0])
    t.tabella(10, tr(u'Profili degli utenti'), [tr(u'Cartella'), tr(u'Creata (UTC)'), tr(u'Modificata')], [r[1] for r in righe[:40]],
              tr(u'Le date di creazione posteriori all\'ultima attivit\u00e0 della macchina sono quelle della copia dei file, '
              u'non quelle dei profili.') if copiate else u'')
    if utenti or righe:
        t.fatto(10)


# --------------------------------------------------------------------------
# Profili degli utenti: NTUSER.DAT e UsrClass.dat
# --------------------------------------------------------------------------

def utenti(t):
    hive_utente = t.radice.file(u'users/%', u'ntuser.dat', ovunque=True)
    if not hive_utente:
        t.esito(23, 'assente', tr(u'nessun NTUSER.DAT trovato'))
        t.esito(41, 'assente', tr(u'nessun NTUSER.DAT trovato'))
        if not t.radice.piatta:
            t.avviso(tr(u'Nessun NTUSER.DAT trovato: mancano i controlli sul registro degli utenti (comandi dalla finestra '
                     u'Esegui, UserAssist, chiavi Run degli utenti, artefatti disattivati).'))
        return
    classi = {}
    for c in t.radice.file(u'users/%', u'usrclass.dat', ovunque=True):
        classi[c.cartella.lower()] = c
    righe_mru = []
    righe_rdp = []
    righe_share = []
    fatti = 0
    for e in hive_utente:
        if t.annullato():
            return
        parti = [p for p in e.cartella.split(u'/') if p]
        if not t.radice.piatta:
            profondita = len([p for p in t.radice.prefisso.split(u'/') if p])
            if len(parti) != profondita + 2:
                continue       # non sta direttamente nella cartella del profilo
        utente = parti[-1] if parti else u'?'
        h = carica_hive(t, e, tr(u'NTUSER.DAT di %s') % utente)
        if h is None:
            continue
        fatti += 1
        try:
            _utente_ntuser(t, h, e, utente, righe_mru, righe_rdp, righe_share)
        except ERRORI:
            import traceback
            t.errori.append(tr(u'Registro dell\'utente %s (%s): %s')
                            % (utente, e.percorso, traceback.format_exc().decode('utf-8', 'replace')[-1200:]))
        del h
        c = classi.get(e.cartella.lower() + u'appdata/local/microsoft/windows/')
        if c is None and t.radice.piatta and len(classi) == 1 and len(hive_utente) == 1:
            c = classi.values()[0]
        if c is not None:
            hc = carica_hive(t, c, tr(u'UsrClass.dat di %s') % utente)
            if hc is not None:
                try:
                    _acl(t, hc, c, utente, _CHIAVI_TRACCIATE_CLASSI)
                except ERRORI, ex:
                    t.fallita(tr(u'Controllo delle ACL in UsrClass.dat di %s non riuscito (controllo 41)') % utente, ex)
    t.tabella(23, tr(u'RunMRU: comandi dalla finestra Esegui'), [tr(u'Utente'), tr(u'Ordine'), tr(u'Comando'), tr(u'Peso')], righe_mru,
              tr(u'Ordine 1 = il pi\u00f9 recente. La chiave registra solo l\'ora dell\'ultimo comando.'))
    t.tabella(13, tr(u'RDP in uscita (registro degli utenti)'), [tr(u'Utente'), tr(u'Server'), tr(u'Nome utente usato'), tr(u'Ultima scrittura (UTC)')],
              righe_rdp)
    t.tabella(13, tr(u'Condivisioni di rete usate (MountPoints2)'), [tr(u'Utente'), tr(u'Condivisione'), tr(u'Ultima scrittura (UTC)')],
              righe_share)
    if fatti:
        t.fatto(23, 41)
        if t.esiti.get(13) is None:
            t.fatto(13)


def _utente_ntuser(t, h, e, utente, righe_mru, righe_rdp, righe_share):
    dove = tr(u'HKCU di %s') % utente
    _run(t, h, e, dove, [u'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                         u'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                         u'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'])
    k = h.apri(u'Environment')
    if k is not None:
        script = k.dato(u'UserInitMprLogonScript')
        if isinstance(script, list):
            script = u' '.join(script)
        if isinstance(script, unicode) and script.strip():
            # la chiave e' usata di rado e quasi solo per la persistenza:
            # va confermata qualunque cosa lanci
            giudica_persistenza(t, 19, tr(u'Script di accesso di %s') % utente, u'UserInitMprLogonScript', script,
                                ora=k.orario, elemento=e, extra=True, minimo=R.DA_CONFERMARE,
                                perche=tr(u'la chiave si usa di rado e quasi solo per la persistenza'))
    _installati(t, h, e, [u'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'], utente)
    # RunMRU
    k = h.apri(u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU')
    if k is not None:
        valori = {}
        for v in k.valori():
            valori[v.nome] = v
        ordine = u''
        if u'MRUList' in valori:
            ordine = valori[u'MRUList'].testo()
        lettere = list(ordine) + [n for n in sorted(valori.keys()) if n not in ordine and n != u'MRUList']
        posizione = 0
        for lettera in lettere:
            v = valori.get(lettera)
            if v is None or v.tipo not in (tc_registro.REG_SZ, tc_registro.REG_EXPAND_SZ):
                continue
            posizione += 1
            comando = v.testo()
            if comando.endswith(u'\\1'):
                comando = comando[:-2]
            g = R.valuta_comando(comando, persistenza=False)
            peso = 0
            if g.livello >= 3:
                peso = R.DECISIVO
                motivo = tr(u'comando che scarica o esegue codice incollato nella finestra Esegui (schema delle finte CAPTCHA, ClickFix): ') + g.motivo()
            elif g.livello == 2 and (g.interprete or g.avvio or u'.' in R.nome_base(g.eseguibile)):
                # (senza estensione e' una cartella aperta da Esegui, non un programma)
                peso = R.DA_CONFERMARE
                motivo = tr(u'comando dalla finestra Esegui: ') + g.motivo()
            elif g.noto:
                peso = R.INFORMATIVO
                motivo = tr(u'script di installazione noto lanciato dalla finestra Esegui')
            elif g.interprete and g.argomenti.strip() and g.nome in _INTERPRETI_DA_ESEGUI:
                if R.finestra_nascosta(g.argomenti):
                    # chi scrive un comando a mano in Esegui non ha motivo di nascondere la finestra
                    peso = R.DA_CONFERMARE
                    motivo = tr(u'%s a finestra nascosta dalla finestra Esegui') % g.nome
                elif _RX_CONCATENA.search(g.argomenti):
                    # piu' comandi concatenati o passati da uno all'altro: nessuno li scrive a mano in Esegui
                    peso = R.DA_CONFERMARE
                    motivo = tr(u'%s con pi\u00f9 comandi concatenati dalla finestra Esegui') % g.nome
                else:
                    # "cmd /k ipconfig", "rundll32 sysdm.cpl,...": lo fanno anche gli amministratori
                    peso = R.INFORMATIVO
                    motivo = tr(u'%s con argomenti dalla finestra Esegui') % g.nome
            famiglia = R.F_ESECUZIONE
            for peso_c, famiglia_c, cosa in R.comandi_noti(comando):
                if peso_c > peso:
                    peso, motivo, famiglia = peso_c, cosa, famiglia_c
            # lo strumento lanciato dalla finestra Esegui ("\\\\10.0.0.5\\s\\mimikatz.exe", "psexec \\\\srv cmd")
            peso_s, cosa_s = R.strumento(g.nome)
            if peso_s >= R.DA_CONFERMARE and peso_s > peso:
                peso, motivo, famiglia = peso_s, cosa_s + tr(u' lanciato dalla finestra Esegui'), R.famiglia_strumento(g.nome)
            if peso:
                dettagli = comando[:2000]
                if g.decodificato:
                    dettagli += tr(u'\nComando in chiaro: ') + u' '.join(g.decodificato.split())[:1500]
                t.segnala(23, peso, famiglia, tr(u'RunMRU di %s: %s') % (utente, motivo), dettagli,
                          k.orario if posizione == 1 else 0, e)
            righe_mru.append([utente, unicode(posizione), comando[:400], R.NOME_PESO.get(peso, u'')])
    # UserAssist
    k = h.apri(u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
    if k is not None:
        for g in k.sottochiavi():
            conta = g.sottochiave(u'Count')
            if conta is None:
                continue
            for v in conta.valori():
                dati = tc_artefatti.userassist_dati(v.dati)
                if dati is None or not dati[1]:
                    continue
                nome = tc_artefatti.userassist_nome(v.nome)
                if u'\\' not in nome or nome.startswith(u'UEME_'):
                    continue
                if nome.lower().endswith(u'.lnk'):
                    continue
                t.esecuzione(nome, dati[1], u'UserAssist', utente, dati[0], e)
        t.fatto(26)
    # RDP in uscita
    k = h.apri(u'Software\\Microsoft\\Terminal Server Client\\Servers')
    if k is not None:
        for s in k.sottochiavi():
            suggerimento = s.dato(u'UsernameHint', u'')
            if not isinstance(suggerimento, unicode):
                suggerimento = u''
            righe_rdp.append([utente, s.nome, suggerimento, T(s.orario)])
            t.vede(s.orario)
    # condivisioni
    k = h.apri(u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2')
    if k is not None:
        for s in k.sottochiavi():
            if not s.nome.startswith(u'##'):
                continue
            condivisione = s.nome.replace(u'#', u'\\')
            righe_share.append([utente, condivisione, T(s.orario)])
            if re.search(u'\\\\(c|admin|ipc)\\$$', condivisione, re.I):
                t.segnala(13, R.INFORMATIVO, R.F_LATERALE,
                          tr(u'%s ha aperto la condivisione amministrativa %s') % (utente, condivisione),
                          tr(u'MountPoints2 - ultima scrittura della chiave: %s') % T(s.orario), s.orario, e)
    # strumenti Sysinternals accettati (EulaAccepted)
    k = h.apri(u'Software\\Sysinternals')
    if k is not None:
        for s in k.sottochiavi():
            if s.dato(u'EulaAccepted', 0) == 1:
                t.esecuzione(s.nome + u'.exe', s.orario, u'Sysinternals (EulaAccepted)', utente, elemento=e)
    _acl(t, h, e, utente, _CHIAVI_TRACCIATE)
    # Cestino disattivato, UserAssist spento
    k = h.apri(u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume')
    if k is not None:
        for v in k.sottochiavi():
            if v.dato(u'NukeOnDelete', 0) == 1:
                t.segnala(41, R.INFORMATIVO, R.F_ANTIFORENSE,
                          tr(u'%s cancella i file senza passare dal Cestino (NukeOnDelete = 1)') % utente,
                          tr(u'Volume %s - ultima scrittura della chiave: %s') % (v.nome, T(v.orario)), v.orario, e)
                break
    k = h.apri(u'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced')
    if k is not None and k.dato(u'Start_TrackProgs', 1) == 0:
        t.segnala(41, R.INFORMATIVO, R.F_ANTIFORENSE,
                  tr(u'Per %s Windows non tiene traccia dei programmi avviati (Start_TrackProgs = 0): UserAssist resta vuoto')
                  % utente, u'', 0, e)


def _acl(t, h, e, utente, chiavi):
    for percorso, nome in chiavi:
        k = h.apri(percorso)
        if k is None:
            continue
        negati = [a for a in k.ace() if a[0] == u'nega']
        if negati:
            t.segnala(41, R.DA_CONFERMARE, R.F_ANTIFORENSE,
                      tr(u'ACL Deny sulla chiave %s di %s: Windows non pu\u00f2 pi\u00f9 registrare questo artefatto')
                      % (nome, utente),
                      tr(u'%s\nVoci Deny: %s\nUltima scrittura della chiave: %s')
                      % (percorso, u', '.join([tr(u'%s (maschera 0x%x)') % (a[2], a[1]) for a in negati[:6]]), T(k.orario)),
                      k.orario, e)


# --------------------------------------------------------------------------
# AmCache
# --------------------------------------------------------------------------

def amcache(t):
    e = t.radice.uno(u'windows/appcompat/programs/', u'amcache.hve')
    if e is None:
        return
    h = carica_hive(t, e, u'Amcache.hve')
    if h is None:
        return
    quante = 0
    base = h.apri(u'Root\\InventoryApplicationFile')
    if base is not None:
        for k in base.sottochiavi():
            percorso = k.dato(u'LowerCaseLongPath')
            if not isinstance(percorso, unicode) or not percorso:
                continue
            produttore = k.dato(u'Publisher', u'')
            impronta = k.dato(u'FileId', u'')
            nota = []
            if isinstance(produttore, unicode) and produttore:
                nota.append(tr(u'produttore: ') + produttore)
            if isinstance(impronta, unicode) and len(impronta) >= 44:
                nota.append(u'SHA-1: ' + impronta[4:44])
            t.esecuzione(percorso, k.orario, u'AmCache', elemento=e, eseguito=False, nota=u', '.join(nota))
            quante += 1
    vecchio = h.apri(u'Root\\File')
    if vecchio is not None:
        for volume in vecchio.sottochiavi():
            for k in volume.sottochiavi():
                percorso = k.dato(u'15')
                if not isinstance(percorso, unicode) or not percorso:
                    continue
                impronta = k.dato(u'101', u'')
                nota = u''
                if isinstance(impronta, unicode) and len(impronta) >= 44:
                    nota = u'SHA-1: ' + impronta[4:44]
                t.esecuzione(percorso, k.orario, u'AmCache', elemento=e, eseguito=False, nota=nota)
                quante += 1
    t.contesto['amcache'] = quante


# --------------------------------------------------------------------------
# Attivita' pianificate: riepilogo di registro e file
# --------------------------------------------------------------------------

def riepilogo_attivita(t):
    """Controlli 15, 16 e 28: mette insieme le attivita' viste nel registro
    (TaskCache) e i file XML, le valuta e segnala quelle nascoste."""
    da_file = t.contesto.get('attivita_file') or {}
    righe = []
    nomi = set(t.attivita.keys()) | set(da_file.keys())
    for chiave in sorted(nomi):
        reg = t.attivita.get(chiave)
        xml = da_file.get(chiave)
        percorso = (reg or xml)['percorso']
        azioni = []
        if reg:
            azioni = [(a[1], a[2]) for a in reg['azioni'] if a[0] == u'exec']
        if not azioni and xml:
            azioni = xml['azioni']
        creato = 0
        if reg and reg['creato']:
            creato = reg['creato']
        elif xml:
            creato = xml['creato']
        elemento = xml['elemento'] if xml else (reg['elemento'] if reg else None)
        autore = (xml['autore'] if xml else u'') or (reg['autore'] if reg else u'')
        peso_massimo = 0
        motivi = []
        if reg and reg['nascosta']:
            comandi = u'\n'.join([(a + u' ' + b).strip() for a, b in azioni]) or tr(u'(nessuna azione leggibile)')
            t.segnala(16, R.DECISIVO, R.F_PERSISTENZA,
                      tr(u'Attivit\u00e0 nascosta \u00ab%s\u00bb: %s') % (percorso, reg['nascosta']),
                      tr(u'Azioni: %s\nCreata: %s - ultimo avvio: %s') % (comandi[:1500], T(creato), T(reg['ultimo_avvio'])),
                      creato, reg['elemento'])
            peso_massimo = R.DECISIVO
            motivi.append(tr(u'nascosta'))
        for comando, argomenti in azioni:
            if not comando:
                continue
            peso, motivo = giudica_persistenza(t, 15, tr(u'Attivit\u00e0 pianificata'), percorso, comando, argomenti,
                                               ora=creato, elemento=elemento,
                                               nota=tr(u'Autore: %s') % autore if autore else u'')
            if peso:
                peso_massimo = max(peso_massimo, peso)
                motivi.append(motivo)
            if comando.lower().strip(u'"').endswith(u'.lnk'):
                t.segnala(15, R.DA_CONFERMARE, R.F_PERSISTENZA,
                          tr(u'Attivit\u00e0 pianificata \u00ab%s\u00bb: lancia un collegamento .lnk') % percorso,
                          (comando + u' ' + argomenti).strip(), creato, elemento)
                peso_massimo = max(peso_massimo, R.DA_CONFERMARE)
                motivi.append(tr(u'lancia un .lnk'))
        # firme di atexec rimaste su disco
        if xml:
            firma = firma_atexec(percorso, xml['azioni'], xml['avvii'])
            if firma:
                t.segnala(28, firma[0], R.F_LATERALE, tr(u'Attivit\u00e0 \u00ab%s\u00bb: %s') % (percorso, firma[1]),
                          u'\n'.join([(a + u' ' + b).strip() for a, b in xml['azioni']])[:1500], creato, elemento)
                peso_massimo = max(peso_massimo, firma[0])
                motivi.append(firma[1])
        fuori_microsoft = not percorso.lower().startswith(u'\\microsoft\\')
        if peso_massimo or (fuori_microsoft and azioni):
            righe.append((creato, [percorso, u'\n'.join([(a + u' ' + b).strip() for a, b in azioni])[:400], autore,
                                   T(creato), R.NOME_PESO.get(peso_massimo, u''), u'; '.join(motivi)]))
    righe.sort(key=lambda r: -r[0])
    t.tabella(15, tr(u'Attivit\u00e0 pianificate: segnalate e non di Microsoft'),
              [tr(u'Attivit\u00e0'), tr(u'Azione'), tr(u'Autore'), tr(u'Creata (UTC)'), tr(u'Peso'), tr(u'Motivo')], [r[1] for r in righe[:80]],
              tr(u'Sono elencate le attivit\u00e0 fuori da \\Microsoft\\ e quelle segnalate. '
              u'In tutto: %d nel registro, %d file XML.') % (len(t.attivita), len(da_file)))
    if nomi:
        t.fatto(15, 28)


_RX_TMP_ATEXEC = re.compile(u'>\\s*%{0,2}(?:windir|systemroot)?%{0,2}\\\\temp\\\\([A-Za-z]{8})\\.tmp', re.I)


def firma_atexec(nome, azioni, avvii):
    """Riconosce atexec in un'attivita': la data fissa nel codice, oppure
    l'output in un .tmp di 8 lettere a caso in Windows\\Temp. Restituisce
    (peso, descrizione) oppure None."""
    for a in avvii or []:
        if a.startswith(u'2015-07-15T20:35:13'):
            return R.DECISIVO, tr(u'data di avvio 2015-07-15T20:35:13, fissa nel codice di atexec')
    for comando, argomenti in azioni or []:
        m = _RX_TMP_ATEXEC.search(argomenti or u'')
        if m is not None and R.con_estensione(R.nome_base(R.percorso_normale(comando))) == u'cmd.exe':
            if R.nome_casuale(m.group(1)):
                return R.DECISIVO, tr(u'output ridiretto in un file .tmp di 8 lettere a caso in Windows\\Temp (firma di atexec)')
            return R.DA_CONFERMARE, (tr(u'output ridiretto in un file .tmp di 8 lettere in Windows\\Temp: lo fa atexec, '
                                     u'ma qui il nome non sembra casuale'))
    return None


# --------------------------------------------------------------------------
# Programmi eseguiti: valutazione finale di tutte le fonti
# --------------------------------------------------------------------------

_CONTROLLO_FONTE = {u'Prefetch': 21, u'BAM': 22}


def valuta_esecuzioni(t):
    """Controlli 21, 22 e 26: mette insieme Prefetch, BAM, UserAssist,
    ShimCache, AmCache e segnala strumenti d'attacco, strumenti a doppio
    uso, programmi avviati da cartelle sospette e raffiche di ricognizione."""
    per_percorso = {}
    for x in t.esecuzioni:
        chiave = R.percorso_normale(x['percorso'])
        if not chiave:
            continue
        r = per_percorso.get(chiave)
        if r is None:
            r = {'percorso': x['percorso'], 'fonti': [], 'ultimo': 0, 'conteggio': 0, 'utenti': [],
                 'eseguito': False, 'elemento': x['elemento'], 'note': [], 'orari': []}
            per_percorso[chiave] = r
        if x['fonte'] not in r['fonti']:
            r['fonti'].append(x['fonte'])
        if x['ora'] > r['ultimo'] and x['eseguito']:
            r['ultimo'] = x['ora']
            r['elemento'] = x['elemento']
        if not r['ultimo'] and x['ora'] and not r.get('visto'):
            r['visto'] = x['ora']
        r['conteggio'] = max(r['conteggio'], x['conteggio'])
        if x['utente'] and x['utente'] not in r['utenti']:
            r['utenti'].append(x['utente'])
        if x['eseguito']:
            r['eseguito'] = True
            r['orari'].extend(x['orari'])
        if x.get('nota') and len(r['note']) < 3:
            r['note'].append(x['nota'])
    righe_strumenti = []
    righe_zone = []
    segnalati = 0
    for chiave, r in per_percorso.items():
        nome = R.nome_base(chiave)
        controllo = 26
        for fonte in r['fonti']:
            if fonte in _CONTROLLO_FONTE:
                controllo = _CONTROLLO_FONTE[fonte]
                break
        quando = r['ultimo'] or r.get('visto', 0)
        prova = tr(u'eseguito') if r['eseguito'] else tr(u'presente sul disco (non \u00e8 una prova di esecuzione)')
        dettagli = tr(u'%s\nFonti: %s%s%s%s') % (
            r['percorso'], u', '.join(r['fonti']),
            tr(u' - ultimo avvio: %s') % T(r['ultimo']) if r['ultimo'] else u'',
            tr(u' - utenti: %s') % u', '.join(r['utenti'][:5]) if r['utenti'] else u'',
            u'\n' + u'; '.join(r['note']) if r['note'] else u'')
        peso, cosa = R.strumento(nome)
        famiglia = R.famiglia_strumento(nome)
        if peso < R.DA_CONFERMARE:
            # il nome non dice nulla, ma la cartella si': "...\\mimikatz_trunk\\x64\\loader.exe"
            peso_c, cosa_c = R.strumento_nominato(chiave[:len(chiave) - len(nome)])
            if peso_c >= R.DA_CONFERMARE:
                peso, cosa = peso_c, cosa_c + tr(u' nel nome della cartella')
                famiglia = R.F_STRUMENTI if peso_c >= R.DECISIVO else R.F_DOPPIO_USO
        if peso >= R.DA_CONFERMARE:
            peso_segnale = peso
            vecchio = u''
            if peso == R.DA_CONFERMARE and quando and t.riferimento and not t.recente(quando):
                # uno strumento a doppio uso usato l'ultima volta molto prima
                # del periodo sotto esame resta nel report, ma come contesto
                peso_segnale = R.INFORMATIVO
                vecchio = tr(u' (non recente)')
            t.segnala(controllo, peso_segnale, famiglia,
                      u'%s %s%s: %s' % (cosa[0].upper() + cosa[1:], prova, vecchio, r['percorso']),
                      dettagli, quando, r['elemento'])
            righe_strumenti.append((quando, [r['percorso'], cosa, prova, T(r['ultimo']), u', '.join(r['fonti']),
                                             R.NOME_PESO[peso_segnale]]))
        strumento = R.trova_rmm(nome) or (R.trova_rmm(chiave) if u'quickassist' not in chiave else None)
        if strumento and (r['eseguito'] or strumento != u'Quick Assist'):
            t.prova_rmm(strumento, prova, u'%s (%s)' % (r['percorso'], u', '.join(r['fonti'])), quando,
                        r['elemento'], 33, genere='eseguito' if r['eseguito'] else '')
        if not r['eseguito']:
            continue
        z = R.zona(chiave)
        mascherato = R.fuori_posto(chiave)
        if (z == u'sospetta' or mascherato) and not R.strumento_forense(nome):
            motivo = tr(u'con il nome di un processo di sistema, ma fuori dalle cartelle di sistema') if mascherato else \
                tr(u'avviato da una cartella dove di norma non ci sono programmi')
            if segnalati < 25 and peso < R.DA_CONFERMARE:
                t.segnala(controllo, R.DA_CONFERMARE, R.F_ESECUZIONE,
                          tr(u'Programma %s: %s') % (motivo, r['percorso']), dettagli, quando, r['elemento'])
                segnalati += 1
        if z in (u'sospetta', u'temporanea', u'utente') and not R.noto_in_profilo(chiave):
            righe_zone.append((quando, [r['percorso'], T(r['ultimo']), unicode(r['conteggio'] or u''),
                                        u', '.join(r['utenti'][:3]), u', '.join(r['fonti']),
                                        tr(u'cartella sospetta') if z == u'sospetta' else (tr(u'temporanea') if z == u'temporanea' else u'')]))
    righe_strumenti.sort(key=lambda x: -x[0])
    righe_zone.sort(key=lambda x: -x[0])
    t.tabella(21, tr(u'Strumenti d\'attacco e a doppio uso'),
              [tr(u'Percorso'), tr(u'Tipo'), tr(u'Prova'), tr(u'Ultimo avvio (UTC)'), tr(u'Fonti'), tr(u'Peso')], [x[1] for x in righe_strumenti[:60]])
    t.tabella(21, tr(u'Programmi avviati da cartelle scrivibili dagli utenti (i 50 pi\u00f9 recenti)'),
              [tr(u'Percorso'), tr(u'Ultimo avvio (UTC)'), tr(u'Avvii'), tr(u'Utenti'), tr(u'Fonti'), tr(u'Nota')], [x[1] for x in righe_zone[:50]],
              tr(u'Elenco di contesto: molti programmi legittimi girano da queste cartelle. '
              u'Fonti: Prefetch, BAM, UserAssist.'))
    _ricognizione(t, per_percorso)


def _ricognizione(t, per_percorso):
    """Diversi comandi di ricognizione avviati in pochi minuti (dai tempi di
    Prefetch, BAM e UserAssist)."""
    momenti = []
    for chiave, r in per_percorso.items():
        nome = R.nome_base(chiave)
        if nome not in R.RICOGNIZIONE or not r['eseguito']:
            continue
        for ora in set(r['orari']):
            if ora:
                momenti.append((ora, nome, r['elemento']))
    for inizio, fine, nomi, elemento in raffiche(momenti):
        t.segnala(21, R.DA_CONFERMARE, R.F_ESECUZIONE,
                  tr(u'Ricognizione: %d comandi diversi in %d minuti (%s)')
                  % (len(nomi), max(1, int((fine - inizio) / 60) + 1), u', '.join(sorted(nomi))),
                  tr(u'Dal %s al %s (UTC). Fonte: orari di ultimo avvio in Prefetch, BAM e UserAssist.') % (T(inizio), T(fine)),
                  inizio, elemento)


def raffiche(momenti, finestra=600, minimo=4):
    """Trova i gruppi di almeno 'minimo' comandi di ricognizione diversi (di
    cui almeno uno tra quelli che un utente normale non usa) dentro
    'finestra' secondi. momenti: [(ora, nome, elemento)]. Una finestra che
    scorre: ogni momento entra ed esce una volta sola, anche se i comandi
    sono decine di migliaia."""
    momenti = sorted(momenti, key=lambda m: m[0])
    trovate = []
    n = len(momenti)
    i = 0
    j = 0
    dentro = {}         # nome -> quante volte compare nella finestra [i, j)
    while i < n and len(trovate) < 10:
        while j < n and momenti[j][0] - momenti[i][0] <= finestra:
            dentro[momenti[j][1]] = dentro.get(momenti[j][1], 0) + 1
            j += 1
        if len(dentro) >= minimo and [x for x in dentro if x in R.RICOGNIZIONE_FORTE]:
            nomi = set(dentro.keys())
            # allarga finche' i comandi continuano senza pause lunghe
            while j < n and momenti[j][0] - momenti[j - 1][0] <= finestra:
                nomi.add(momenti[j][1])
                j += 1
            trovate.append((momenti[i][0], momenti[j - 1][0], nomi, momenti[i][2]))
            i = j
            dentro = {}
        else:
            nome = momenti[i][1]
            if dentro.get(nome, 0) <= 1:
                dentro.pop(nome, None)
            else:
                dentro[nome] -= 1
            i += 1
            if j < i:
                j = i
    return trovate
