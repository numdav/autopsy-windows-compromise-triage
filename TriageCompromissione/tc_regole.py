# -*- coding: utf-8 -*-
"""
tc_regole - Regole di valutazione del plugin "Triage compromissione".

Qui stanno gli elenchi (strumenti di accesso remoto, strumenti d'attacco,
comandi di ricognizione) e le funzioni che giudicano un percorso o una riga
di comando. Per cambiare cosa viene segnalato basta modificare gli elenchi.
"""

import binascii
import re

from tc_base import decodifica16, ERRORI

# Pesi dei segnali
DECISIVO = 3        # basta da solo per trattare la macchina come compromessa
DA_CONFERMARE = 2   # conta se almeno due famiglie diverse lo segnalano
INFORMATIVO = 1     # solo contesto: compare nel report, non pesa sul verdetto

NOME_PESO = {DECISIVO: u'Decisivo', DA_CONFERMARE: u'Da confermare', INFORMATIVO: u'Informativo'}

# Famiglie di segnali (per il verdetto contano le famiglie diverse)
F_ACCESSI = u'Accessi'
F_ACCOUNT = u'Account'
F_PERSISTENZA = u'Persistenza'
F_ESECUZIONE = u'Programmi eseguiti'
F_STRUMENTI = u'Strumenti d\'attacco'
F_DOPPIO_USO = u'Strumenti a doppio uso'
F_LATERALE = u'Esecuzione remota'
F_RMM = u'Accesso remoto (RMM)'
F_FILE = u'File'
F_ANTIFORENSE = u'Anti-forensics'
F_ANTIVIRUS = u'Antivirus'
F_ESFILTRAZIONE = u'Esfiltrazione e tunnel'


# --------------------------------------------------------------------------
# Strumenti di accesso remoto (RMM)
# nome leggibile -> frammenti (minuscoli) cercati in nomi di file, servizi,
# programmi installati e produttori
# --------------------------------------------------------------------------

RMM = [
    (u'AnyDesk', [u'anydesk']),
    (u'TeamViewer', [u'teamviewer']),
    (u'LogMeIn', [u'logmein', u'lmiguardian', u'lmi_rescue']),
    (u'GoTo (GoToAssist, GoTo Resolve, GoToMyPC)', [u'gotoassist', u'goto resolve', u'gotoresolve', u'gotomypc',
                                                   u'g2ax', u'g2ac_', u'goto opener']),
    (u'Pulseway', [u'pulseway', u'pcmonitorsrv', u'pcmontask']),
    (u'ScreenConnect / ConnectWise Control', [u'screenconnect', u'connectwisecontrol', u'connectwise control']),
    (u'ConnectWise Automate (LabTech)', [u'ltsvc', u'labtech', u'connectwise automate']),
    (u'Atera', [u'ateraagent', u'atera agent', u'atera networks', u'atera']),
    (u'Splashtop', [u'splashtop', u'srservice', u'srmanager', u'strwinclt']),
    (u'RustDesk', [u'rustdesk']),
    (u'NinjaOne / NinjaRMM', [u'ninjarmm', u'ninjaone', u'ninjaremote']),
    (u'Kaseya', [u'kaseya', u'agentmon.exe']),
    (u'N-able / SolarWinds', [u'n-able', u'n-central', u'ncentral', u'take control agent', u'basupsrvc',
                              u'advanced monitoring agent', u'mspanywhere']),
    (u'Datto RMM', [u'centrastage', u'cagservice', u'datto rmm']),
    (u'Supremo', [u'supremoservice', u'supremosystem', u'supremohelper', u'supremocontrol', u'supremo remote',
                  u'nanosystems', u'supremo.exe']),
    (u'Ammyy Admin', [u'ammyy', u'aa_v3']),
    (u'VNC (Real, Tight, Ultra, Tiger)', [u'realvnc', u'tightvnc', u'ultravnc', u'tigervnc', u'winvnc',
                                          u'tvnserver', u'vncserver', u'uvnc_service']),
    (u'DWService', [u'dwagent', u'dwagsvc', u'dwservice']),
    (u'Remote Utilities', [u'remote utilities', u'rutserv', u'rfusclient', u'rutview']),
    (u'NetSupport', [u'netsupport', u'client32.exe']),
    (u'Zoho Assist', [u'zohoassist', u'zoho assist']),
    (u'ManageEngine (Endpoint Central, Remote Access Plus)', [
        u'desktopcentral', u'desktop central', u'endpoint central', u'endpointcentral', u'dcagentservice',
        u'uems_agent', u'uems agent', u'remote access plus', u'remoteaccessplus']),
    (u'ISL Light / ISL AlwaysOn', [u'isl light', u'isllight', u'islalwayson', u'isl alwayson']),
    (u'MeshCentral', [u'meshagent', u'meshcentral', u'mesh agent']),
    (u'Radmin', [u'radmin server', u'radmin viewer', u'rserver3', u'radmin']),
    (u'Chrome Remote Desktop', [u'chrome remote desktop', u'chromoting', u'remoting_host']),
    (u'Action1', [u'action1_agent', u'action1_remote', u'action1']),
    (u'SimpleHelp', [u'simplehelp', u'simple-help']),
    (u'FleetDeck', [u'fleetdeck']),
    (u'Syncro', [u'syncromsp', u'syncrolive', u'syncro']),
    (u'Bomgar', [u'bomgar']),
    (u'DameWare', [u'dameware', u'dwrcs']),
    (u'Parsec', [u'parsecd', u'parsec']),
    (u'AeroAdmin', [u'aeroadmin']),
    (u'LiteManager', [u'litemanager', u'romserver', u'romfusclient']),
    (u'Getscreen.me', [u'getscreen']),
    (u'HopToDesk', [u'hoptodesk']),
    (u'Iperius Remote', [u'iperius remote', u'iperiusremote']),
    (u'Tactical RMM', [u'tacticalrmm', u'tactical rmm', u'tacticalagent']),
    (u'PDQ Connect', [u'pdq connect', u'pdqconnect']),
    (u'Quick Assist', [u'quickassist', u'quick assist']),
    (u'ToDesk', [u'todesk_service', u'todesk']),
    (u'Sunlogin', [u'sunlogin']),
]

# Frammenti corti che sono anche l'inizio di altre parole: valgono solo se
# dopo non c'e' un'altra lettera o cifra ("syncro", non "Syncrosoft";
# "todesk", non "ToDesktop"; "atera", non "Ateralabs"; "getscreen", non
# "GetScreenshot").
_RMM_PAROLA_INTERA = set([u'atera', u'radmin', u'syncro', u'parsec', u'todesk', u'action1', u'getscreen'])
# Nomi di file che sono anche parole comuni: valgono solo come nome intero
# del file ("Supremo.exe", non "Giudice Supremo.exe").
_RMM_FILE_INTERO = set([u'supremo.exe'])

_RX_RMM = []
for _nome, _frammenti in RMM:
    _pezzi = []
    for _f in _frammenti:
        if _f in _RMM_FILE_INTERO:
            _pezzi.append(u'(?<![a-z0-9 ])' + re.escape(_f) + u'(?![a-z0-9])')
        else:
            _pezzi.append(re.escape(_f) + (u'(?![a-z0-9])' if _f in _RMM_PAROLA_INTERA else u''))
    _RX_RMM.append((_nome, re.compile(u'(?<![a-z0-9])(' + u'|'.join(_pezzi) + u')')))
_RMM_FALSI = (u'radmin vpn', u'radminvpn', u'radmin_vpn')
# il nome del profilo non conta: i programmi dell'utente "radmin" non sono Radmin
_RX_PROFILO = re.compile(u'\\\\(users|documents and settings)\\\\[^\\\\]+\\\\')


def senza_profilo(testo):
    """Il testo in minuscolo, con il nome del profilo utente tolto dai percorsi."""
    return _RX_PROFILO.sub(u'\\\\\\1\\\\*\\\\', (testo or u'').lower())


def trova_rmm(testo):
    """Nome dello strumento RMM riconosciuto nel testo (nome di file,
    servizio, programma installato, produttore), oppure None."""
    if not testo:
        return None
    basso = senza_profilo(testo)
    for falso in _RMM_FALSI:
        if falso in basso:
            return None
    for nome, rx in _RX_RMM:
        if rx.search(basso):
            return nome
    return None


# --------------------------------------------------------------------------
# Strumenti d'attacco e strumenti a doppio uso
# --------------------------------------------------------------------------

# Nomi inequivocabili: l'esecuzione o la presenza pesano come segnale decisivo
_RX_ATTACCO = re.compile(
    u'(mimikatz|mimilib|mimidrv|rubeus|sharphound|bloodhound|lazagne|winpeas|safetykatz|sharpkatz'
    u'|nanodump|pypykatz|gsecdump|pwdump|fgdump|quarkspwdump|secretsdump|crackmapexec|cobaltstrike'
    u'|meterpreter|juicypotato|roguepotato|printspoofer|godpotato|sweetpotato|badpotato|efspotato'
    u'|sharpwmi|sharpexec|sharprdp|sharpdpapi|sharpchrome|sharpview|invoke-mimikatz|powersploit'
    u'|powerview(?![a-z])|powercat|kerbrute|ligolo|smbexec|wmiexec|dcomexec|ntdsdump|hashdump|dumpert)', re.I)
_NOMI_ATTACCO_ESATTI = set([
    u'wce.exe', u'cme.exe', u'nxc.exe', u'mim.exe', u'mimi.exe', u'beacon.exe', u'artifact.exe',
    u'lsassy.exe', u'grunt.exe', u'sharpup.exe', u'seatbelt.exe', u'kekeo.exe', u'certipy.exe',
    u'inveigh.exe', u'chisel.exe', u'atexec.exe', u'responder.exe', u'nps.exe', u'frpc.exe', u'frps.exe'])

# Doppio uso: amministratori e attaccanti li usano entrambi (da confermare).
# I nomi corti valgono solo come parola a se' ("nmap", non "GarminMapInstall")
# o come inizio di parola ("sdelete64", non "SecureFilesDelete").
_RX_DOPPIO_USO = re.compile(
    u'(psexec|psexesvc|advanced[_ ]ip[_ ]scanner|masscan|megasync|megacmd'
    u'|cloudflared|procdump|processhacker|pchunter|defendercontrol|backstab|softperfect|pingcastle|adrecon'
    u'|(?<![a-z])(?:paexec|remcom|csexec|sdelete|rclone|ngrok)'
    u'|(?<![a-z])(?:nmap|ipscan|netscan|adfind)(?![a-z]))', re.I)
_NOMI_DOPPIO_ESATTI = set([u'nc.exe', u'nc64.exe', u'ncat.exe', u'netcat.exe', u'tor.exe', u'xcmd.exe',
                           u'plink.exe', u'pscp.exe', u'gmer.exe', u'dcontrol.exe'])
# binari di Windows spesso abusati: contano solo come contesto, perche'
# compaiono anche su molte macchine sane
_BINARI_DI_SISTEMA = set([u'nltest.exe', u'dsquery.exe', u'ntdsutil.exe', u'vssadmin.exe', u'wevtutil.exe',
                          u'bitsadmin.exe', u'esentutl.exe', u'wmic.exe', u'curl.exe', u'certutil.exe',
                          u'mshta.exe', u'regsvr32.exe', u'cmstp.exe', u'msbuild.exe', u'installutil.exe'])


def nome_base(percorso):
    """Ultimo componente di un percorso, in minuscolo."""
    if not percorso:
        return u''
    p = percorso.replace(u'/', u'\\').rstrip(u'\\')
    taglio = p.rfind(u'\\')
    if taglio >= 0:
        p = p[taglio + 1:]
    return p.lower()


def con_estensione(nome):
    """Il nome di un programma con l'estensione: 'cmd' -> 'cmd.exe'. In una
    riga di comando l'estensione si puo' omettere, negli elenchi c'e' sempre."""
    if nome and u'.' not in nome:
        return nome + u'.exe'
    return nome


def strumento(nome_file):
    """Classifica un nome di eseguibile: (peso, descrizione) oppure (0, '').
    DECISIVO per gli strumenti d'attacco, DA_CONFERMARE per quelli a doppio
    uso, INFORMATIVO per i binari di Windows spesso abusati."""
    nome = nome_base(nome_file).strip(u'"\' ')
    if not nome:
        return 0, u''
    intero = con_estensione(nome)
    if intero in _NOMI_ATTACCO_ESATTI:
        return DECISIVO, u'strumento d\'attacco'
    m = _RX_ATTACCO.search(nome)
    if m is not None:
        return DECISIVO, u'strumento d\'attacco (%s)' % m.group(1).lower()
    if intero in _BINARI_DI_SISTEMA:
        return INFORMATIVO, u'binario di Windows spesso abusato'
    if intero in _NOMI_DOPPIO_ESATTI:
        return DA_CONFERMARE, u'strumento a doppio uso'
    m = _RX_DOPPIO_USO.search(nome)
    if m is not None:
        return DA_CONFERMARE, u'strumento a doppio uso (%s)' % m.group(1).lower()
    return 0, u''


def _spie(*espressioni):
    """Le parole fisse che compaiono nelle alternative di una o piu'
    espressioni regolari, in minuscolo: un testo che non ne contiene nessuna
    non puo' corrispondere, e cercarle con "in" costa molto meno che provare
    l'espressione (le righe di comando da giudicare sono centinaia di
    migliaia). Restituisce None se anche una sola alternativa non e' fatta di
    testo fisso con almeno tre caratteri di fila: in quel caso la scorciatoia
    non e' sicura e l'espressione va provata sempre."""
    spie = set()
    for rx in espressioni:
        modello = re.sub(u'\\(\\?<?[!=][^)]*\\)', u'', rx.pattern.lower())    # le condizioni (?<!...) e (?!...)
        modello = modello.replace(u'(?:', u'(')
        for alternativa in re.split(u'[|()]', modello):
            if not alternativa:
                continue
            fisso = re.sub(u'\\[[^\\]]*\\]', u' ', alternativa)                # [_ ] vale un carattere qualunque
            pezzi = re.findall(u'[a-z0-9_-]{3,}', fisso)
            if not pezzi or re.search(u'[\\\\.*+?{^$]', fisso):
                return None
            spie.add(max(pezzi, key=len))
    return tuple(sorted(spie))


def _una_di(basso, parole):
    for parola in parole:
        if parola in basso:
            return True
    return False


# le parole di una riga di comando (i separatori & | ; restano parole a se')
_RX_PAROLA = re.compile(u'[^\\s"\'=,;|&<>()\\[\\]{}]+|[|&;]+')
# uno dei nomi esatti, da solo: se non c'e' e' inutile scorrere le parole una per una
_RX_NOME_ESATTO = re.compile(
    u'(?<![a-z0-9_.-])(?:'
    + u'|'.join(sorted([re.escape(_n[:-4] if _n.endswith(u'.exe') else _n)
                        for _n in _NOMI_ATTACCO_ESATTI | _NOMI_DOPPIO_ESATTI], key=len, reverse=True))
    + u')(?:\\.exe)?(?![a-z0-9_.-])', re.I)
# dopo queste parole comincia un comando: "cmd /c nc -e ...", "start /b plink ..."
_PRIMA_DI_UN_COMANDO = set([u'/c', u'/k', u'/r', u'-c', u'-command', u'start', u'call', u'&', u'&&', u'|', u'||',
                            u';', u'.'])


def strumento_nominato(testo, dal_principio=False):
    """Lo strumento d'attacco o a doppio uso nominato in un testo che non e'
    il nome del programma: gli argomenti di un comando ("cmd /c
    C:\\Tools\\Rubeus.exe kerberoast"), la cartella da cui parte, oppure - con
    dal_principio=True - una riga scritta in console. Restituisce (peso,
    descrizione) oppure (0, u'').

    I nomi inequivocabili valgono ovunque compaiano. Quelli che sono anche
    parole comuni ("nc", "tor", "beacon") solo come nome di file .exe, oppure
    senza estensione nel punto in cui comincia un comando."""
    if not testo:
        return 0, u''
    testo = testo[:20000]
    # quasi tutte le righe non nominano nessuno strumento: lo si vede in fretta
    forse = _SPIE_NOMINATI is None or _una_di(testo.lower(), _SPIE_NOMINATI)
    if forse:
        m = _RX_ATTACCO.search(testo)
        if m is not None:
            return DECISIVO, u'strumento d\'attacco (%s)' % m.group(1).lower()
        m = _RX_PS_ATTACCO.search(testo)
        if m is not None:
            return DECISIVO, u'script o comando d\'attacco (%s)' % m.group(1).lower()
    doppio = u''
    comando = dal_principio
    for m in (_RX_PAROLA.finditer(testo) if _RX_NOME_ESATTO.search(testo) is not None else ()):
        parola = m.group(0)
        if parola.lower() in _PRIMA_DI_UN_COMANDO:
            comando = True
            continue
        if parola[0] in u'-/' and u'\\' not in parola and u'/' not in parola[1:]:
            continue        # un'opzione ("start /b /min programma"): il comando viene dopo
        base = nome_base(parola)
        if base.endswith(u'.exe') or (comando and u'.' not in base):
            intero = con_estensione(base)
            if intero in _NOMI_ATTACCO_ESATTI:
                return DECISIVO, u'strumento d\'attacco (%s)' % intero
            if intero in _NOMI_DOPPIO_ESATTI and not doppio:
                doppio = intero
        comando = False
    if doppio:
        return DA_CONFERMARE, u'strumento a doppio uso (%s)' % doppio
    if forse:
        m = _RX_DOPPIO_USO.search(testo)
        if m is not None:
            return DA_CONFERMARE, u'strumento a doppio uso (%s)' % m.group(1).lower()
    return 0, u''


# Programmi, comandi e opzioni che cercano o elencano. Se il nome di uno
# strumento d'attacco viene dopo uno di questi, nello stesso comando, e' la
# cosa che si sta cercando: lo scrive chi indaga sulla macchina (o un
# antivirus), non chi lo strumento lo sta usando.
_RX_CERCA = re.compile(
    u'(?<![a-z0-9_-])(findstr|find|where|grep|rg|tasklist|yara(64)?|loki|thor(64)?(-lite)?|sigcheck(64)?|strings(64)?)'
    u'(\\.exe)?"?(?=\\s)'
    u'|(?<![a-z0-9_\\\\/.-])(dir|ls|gci|get-childitem|select-string|sls|get-winevent|get-eventlog|get-process|get-service'
    u'|get-mpthreat\\w*|get-filehash|test-path|where-object)(?=\\s)'
    u'|(?<![a-z0-9_-])reg(\\.exe)?"?\\s+query\\s|(?<![a-z0-9_-])wevtutil(\\.exe)?"?\\s+(qe|query-events)\\s'
    u'|(?<=\\s)-(pattern|match|notmatch|like|notlike|filter|include)(?=[\\s:])', re.I)
def _comandi_della_riga(testo):
    """I comandi di una riga, separati da | & ; o a capo. I separatori dentro
    le virgolette o gli apici non contano ("rubeus|sharphound" e' un testo
    da cercare, non due comandi)."""
    comandi = []
    inizio = 0
    aperta = u''
    for i, c in enumerate(testo):
        if aperta:
            if c == aperta:
                aperta = u''
        elif c in u'"\'':
            aperta = c
        elif c in u'|&;\n':
            comandi.append(testo[inizio:i])
            inizio = i + 1
    comandi.append(testo[inizio:])
    return comandi


def solo_cercato(testo):
    """Vero se nel testo i nomi degli strumenti d'attacco compaiono soltanto
    come cosa da cercare ("findstr /i mimikatz *.log", "Get-ChildItem
    -Include *rubeus*"): in ogni comando che ne nomina uno, il nome viene
    dopo un programma o un'opzione di ricerca."""
    testo = (testo or u'')[:20000]
    if _RX_CERCA.search(testo) is None or strumento_nominato(testo)[0] < DECISIVO:
        return False
    trovato = False
    for pezzo in _comandi_della_riga(testo):
        if strumento_nominato(pezzo)[0] < DECISIVO:
            continue
        cerca = _RX_CERCA.search(pezzo)
        if cerca is None:
            return False
        nome = _RX_ATTACCO.search(pezzo) or _RX_PS_ATTACCO.search(pezzo)
        if nome is not None and nome.start() < cerca.start():
            return False
        trovato = True
    return trovato


# il componente che PsExec e i suoi cloni installano sulla macchina di
# destinazione: e' la traccia di un'esecuzione remota subita
_RX_SERVIZIO_REMOTO = re.compile(u'(psexesvc|remcomsvc|csexecsvc|paexec-\\d)', re.I)
_RX_FAM_LATERALE = re.compile(u'(smbexec|wmiexec|dcomexec|atexec|sharpexec|sharpwmi|sharprdp)', re.I)
_RX_FAM_ESFILTRAZIONE = re.compile(u'(chisel|ligolo|frpc|frps|powercat)', re.I)


def famiglia_strumento(nome_file):
    """La famiglia di segnali a cui appartiene uno strumento noto.

    Gli strumenti a doppio uso stanno tutti in una famiglia sola: la raccolta
    Sysinternals sul disco di un amministratore (PsExec, ProcDump, SDelete) e'
    un fatto solo e non deve contare come tre indizi indipendenti. Fa
    eccezione il servizio che PsExec e i suoi cloni lasciano sulla macchina
    di destinazione, che e' la traccia di un'esecuzione remota."""
    nome = nome_base(nome_file)
    if _RX_SERVIZIO_REMOTO.search(nome):
        return F_LATERALE
    if strumento(nome)[0] == DA_CONFERMARE:
        return F_DOPPIO_USO
    if _RX_FAM_LATERALE.search(nome):
        return F_LATERALE
    if _RX_FAM_ESFILTRAZIONE.search(nome):
        return F_ESFILTRAZIONE
    return F_STRUMENTI


# Strumenti di chi fa analisi forense: lasciati da chi ha raccolto le prove
_RX_FORENSE = re.compile(
    u'(^g?kape\\.exe$|ftk ?imager|magnetramcapture|magnet ram|dumpit|winpmem|velociraptor|cylr|cybertriage'
    u'|ramcapture|belkasoft|^edd\\.exe$|pecmd|evtxecmd|mftecmd|amcacheparser|appcompatcacheparser|recmd'
    u'|registryexplorer|shellbagsexplorer|sbecmd|lecmd|jlecmd|rbcmd|wxtcmd|timelineexplorer|ostriage|kntdd'
    u'|autopsy|x-?ways|encase|axiom|^thor(64)?(-lite)?(\\.exe)?$|^loki\\.exe$|redline|arsenal|volatility)', re.I)


def strumento_forense(nome_file):
    """Vero se il nome e' quello di uno strumento di analisi forense o di
    raccolta delle prove."""
    return _RX_FORENSE.search(nome_base(nome_file)) is not None


# Comandi di ricognizione: contano quando ne compaiono diversi in pochi minuti
RICOGNIZIONE = set([u'whoami.exe', u'nltest.exe', u'net.exe', u'net1.exe', u'ipconfig.exe', u'systeminfo.exe',
                    u'tasklist.exe', u'quser.exe', u'qwinsta.exe', u'query.exe', u'nslookup.exe', u'arp.exe',
                    u'netstat.exe', u'route.exe', u'dsquery.exe', u'klist.exe', u'cmdkey.exe', u'nbtstat.exe',
                    u'hostname.exe', u'wmic.exe', u'netsh.exe', u'qprocess.exe', u'dsget.exe', u'csvde.exe',
                    u'ldifde.exe', u'adfind.exe', u'tracert.exe', u'gpresult.exe', u'driverquery.exe'])
# tra questi, quelli che un utente normale non lancia quasi mai
RICOGNIZIONE_FORTE = set([u'whoami.exe', u'nltest.exe', u'net1.exe', u'quser.exe', u'qwinsta.exe', u'dsquery.exe',
                          u'klist.exe', u'cmdkey.exe', u'nbtstat.exe', u'dsget.exe', u'csvde.exe', u'ldifde.exe',
                          u'adfind.exe', u'systeminfo.exe', u'qprocess.exe'])

# Nomi di processi di sistema: sospetti se eseguiti fuori dalle cartelle di sistema
PROCESSI_DI_SISTEMA = set([u'svchost.exe', u'lsass.exe', u'csrss.exe', u'winlogon.exe', u'services.exe',
                           u'smss.exe', u'wininit.exe', u'spoolsv.exe', u'taskhost.exe', u'taskhostw.exe',
                           u'dllhost.exe', u'conhost.exe', u'lsm.exe', u'explorer.exe', u'rundll32.exe',
                           u'dwm.exe', u'ctfmon.exe', u'sihost.exe', u'runtimebroker.exe', u'wmiprvse.exe',
                           u'searchindexer.exe', u'audiodg.exe', u'fontdrvhost.exe', u'userinit.exe'])


# --------------------------------------------------------------------------
# Percorsi
# --------------------------------------------------------------------------

_RX_VOLUME = re.compile(u'^\\\\(?:device\\\\harddiskvolume\\d+|volume\\{[0-9a-f\\-]+\\}|\\?\\?\\\\[a-z]:|\\?\\?\\\\volume\\{[0-9a-f\\-]+\\})', re.I)
_VARIABILI = [
    (u'%comspec%', u'\\windows\\system32\\cmd.exe'),
    (u'%systemroot%', u'\\windows'), (u'%windir%', u'\\windows'), (u'\\systemroot', u'\\windows'),
    (u'%programdata%', u'\\programdata'), (u'%allusersprofile%', u'\\programdata'),
    (u'%public%', u'\\users\\public'),
    (u'%localappdata%', u'\\users\\*\\appdata\\local'), (u'%appdata%', u'\\users\\*\\appdata\\roaming'),
    (u'%temp%', u'\\users\\*\\appdata\\local\\temp'), (u'%tmp%', u'\\users\\*\\appdata\\local\\temp'),
    (u'%userprofile%', u'\\users\\*'), (u'%homepath%', u'\\users\\*'),
    (u'%programfiles(x86)%', u'\\program files (x86)'), (u'%programfiles%', u'\\program files'),
    (u'%programw6432%', u'\\program files'), (u'%commonprogramfiles%', u'\\program files\\common files'),
    (u'%systemdrive%', u''), (u'%homedrive%', u''),
]


def percorso_normale(p):
    """Riduce un percorso a una forma confrontabile: minuscolo, senza unita'
    o volume, con le variabili d'ambiente sostituite. 'C:\\Users\\X' ->
    '\\users\\x'."""
    if not p:
        return u''
    s = p.strip().strip(u'"').replace(u'/', u'\\').lower()
    if u'%%' in s:
        s = s.replace(u'%%', u'%')      # nei registri eventi il segno % e' raddoppiato
    if s.startswith(u'\\\\?\\unc\\'):
        s = u'\\' + s[7:]               # \\?\UNC\server\share -> \\server\share
    elif s.startswith(u'\\\\?\\') or s.startswith(u'\\\\.\\'):
        s = s[4:]                       # \\?\C:\... -> C:\...
    if s.startswith(u'sysvol\\'):
        s = s[6:]
    for variabile, valore in _VARIABILI:
        if variabile in s:
            s = s.replace(variabile, valore)
    s = _RX_VOLUME.sub(u'', s)
    if len(s) >= 2 and s[1] == u':':
        s = s[2:]
    if s.startswith(u'system32\\') or s.startswith(u'syswow64\\'):
        s = u'\\windows\\' + s
    return s


# zone ad alto sospetto: di norma non ospitano programmi
_RX_ZONA_SOSPETTA = re.compile(
    u'^(\\\\users\\\\public\\\\|\\\\perflogs\\\\|\\\\\\$recycle\\.bin\\\\|\\\\recycler\\\\'
    u'|\\\\windows\\\\tasks\\\\|\\\\windows\\\\debug\\\\|\\\\windows\\\\fonts\\\\'
    u'|\\\\windows\\\\help\\\\|\\\\windows\\\\tracing\\\\|\\\\windows\\\\registration\\\\crmlog\\\\'
    # sottocartelle di System32 in cui anche un utente normale puo' scrivere
    u'|\\\\windows\\\\(system32|syswow64)\\\\(spool\\\\drivers\\\\color|spool\\\\printers|spool\\\\servers'
    u'|tasks|tasks_migrated|fxstmp|com\\\\dmp|microsoft\\\\crypto\\\\rsa\\\\machinekeys)\\\\'
    u'|\\\\intel\\\\|\\\\users\\\\default\\\\|\\\\system volume information\\\\'
    u'|\\\\programdata\\\\[^\\\\]+$'
    u'|\\\\users\\\\[^\\\\]+\\\\[^\\\\]+$'
    u'|\\\\users\\\\[^\\\\]+\\\\(music|videos|pictures|contacts|favorites|links|searches|saved games)\\\\)')
# cartelle temporanee: usate anche dagli installatori legittimi
_RX_ZONA_TEMPORANEA = re.compile(
    u'^(\\\\windows\\\\temp\\\\|\\\\tmp\\\\|\\\\temp\\\\|\\\\users\\\\[^\\\\]+\\\\appdata\\\\local\\\\temp\\\\'
    u'|\\\\windows\\\\serviceprofiles\\\\[^\\\\]+\\\\appdata\\\\local\\\\temp\\\\)')
_RX_ZONA_UTENTE = re.compile(u'^(\\\\users\\\\|\\\\programdata\\\\|\\\\documents and settings\\\\)')
_RX_ZONA_SISTEMA = re.compile(
    u'^(\\\\windows\\\\(system32|syswow64|winsxs|sysnative|microsoft\\.net|servicing|systemapps'
    u'|immersivecontrolpanel|softwaredistribution|ccm|ccmcache|assembly|installer|uus|systemresources'
    u'|shellexperiences|shellcomponents|bcastdvr|speech|speech_onecore|system|printdialog|oobe)\\\\'
    u'|\\\\windows\\\\[^\\\\]+$|\\\\program files( \\(x86\\))?\\\\|\\\\\\$windows\\.~bt\\\\|\\\\windows\\.old\\\\)')


def zona(percorso):
    """Classifica dove sta un file: 'sospetta', 'temporanea', 'utente',
    'sistema', 'rete' oppure 'altro'. Le zone sospette si guardano prima di
    quelle di sistema: alcune (spool\\drivers\\color) stanno dentro System32."""
    p = percorso_normale(percorso)
    if not p:
        return u'altro'
    if p.startswith(u'\\\\'):
        return u'rete'
    if _RX_ZONA_SOSPETTA.match(p):
        return u'sospetta'
    if _RX_ZONA_TEMPORANEA.match(p):
        return u'temporanea'
    if _RX_ZONA_SISTEMA.match(p):
        return u'sistema'
    if _RX_ZONA_UTENTE.match(p):
        return u'utente'
    return u'altro'


# Dove stanno davvero i programmi di sistema il cui nome viene imitato
_RX_POSTO_GIUSTO = re.compile(
    u'^(\\\\windows\\\\(system32|syswow64|sysnative)\\\\[^\\\\]+$|\\\\windows\\\\(winsxs|servicing|softwaredistribution)\\\\'
    u'|\\\\windows\\\\system32\\\\dllcache\\\\|\\\\\\$windows\\.~(bt|ws)\\\\|\\\\windows\\.old\\\\)')
_ALTRI_POSTI_GIUSTI = {
    u'explorer.exe': (u'\\windows\\explorer.exe',),
    u'wmiprvse.exe': (u'\\windows\\system32\\wbem\\wmiprvse.exe', u'\\windows\\syswow64\\wbem\\wmiprvse.exe'),
}


def fuori_posto(percorso):
    """Vero se il file ha il nome di un processo di sistema (svchost.exe,
    lsass.exe...) ma non sta dove Windows lo tiene. Vale solo per i percorsi
    completi: un nome da solo non dice dove sta il file."""
    p = percorso_normale(percorso)
    nome = con_estensione(nome_base(p))
    if nome not in PROCESSI_DI_SISTEMA or p.count(u'\\') < 1 or p.startswith(u'\\\\'):
        return False
    if not p.startswith(u'\\'):
        return False        # percorso relativo: non si sa dove porta
    if _RX_POSTO_GIUSTO.match(p):
        return False
    return p not in _ALTRI_POSTI_GIUSTI.get(nome, ())


# programmi legittimi che girano dalle cartelle dell'utente: non segnalati
_RX_NOTI_IN_PROFILO = re.compile(
    u'\\\\appdata\\\\local\\\\(microsoft\\\\(onedrive|teams|edge|edgeupdate|edgewebview|windowsapps|teamsmeetingaddin)'
    u'|google\\\\(update|chrome)|discord|slack|programs\\\\|whatsapp|zoom|githubdesktop|spotify|dropbox'
    u'|bravesoftware|mozilla|vivaldi|opera software|jetbrains|postman|notion|obsidian|signal-desktop'
    u'|telegram desktop|microsoft\\\\windows\\\\)'
    u'|\\\\appdata\\\\roaming\\\\(spotify|zoom\\\\bin|dropbox|telegram desktop|microsoft\\\\teams)'
    u'|\\\\programdata\\\\(microsoft\\\\windows defender|microsoft\\\\vsto|package cache|chocolatey)\\\\', re.I)


def noto_in_profilo(percorso):
    return _RX_NOTI_IN_PROFILO.search(percorso_normale(percorso)) is not None


# driver caricati da strumenti di acquisizione forense: lasciati da chi
# ha raccolto le prove, non da un attaccante
_RX_DRIVER_FORENSE = re.compile(
    u'^(ad_driver|pmem|winpmem|ramcapturedriver|dumpit|mnemosyne|magnetramcapture)(\\d{1,3}|[_-][a-z0-9]+)?$', re.I)


def driver_forense(nome_servizio, percorso):
    """Vero se il servizio e' il driver di uno strumento di acquisizione
    della memoria. Conta il nome del servizio o quello del file del driver,
    per intero: "pmem" non deve scattare su "Add-LocalGroupMember"."""
    programma = nome_base(spezza_comando(percorso or u'')[0])
    if con_estensione(programma) in INTERPRETI:
        return False        # cmd o PowerShell non sono un driver, comunque si chiami il servizio
    if _RX_DRIVER_FORENSE.match((nome_servizio or u'').strip()):
        return True
    if u'.' in programma:
        programma = programma[:programma.rfind(u'.')]
    return _RX_DRIVER_FORENSE.match(programma) is not None


# --------------------------------------------------------------------------
# Righe di comando
# --------------------------------------------------------------------------

# Windows non esegue righe di comando piu' lunghe di 32767 caratteri: quello
# che viene dopo non conta, e fermarsi li' tiene i tempi sotto controllo
# anche con righe costruite apposta.
MAX_RIGA = 32768

INTERPRETI = set([u'cmd.exe', u'powershell.exe', u'pwsh.exe', u'wscript.exe', u'cscript.exe', u'mshta.exe',
                  u'rundll32.exe', u'regsvr32.exe', u'msiexec.exe', u'wmic.exe', u'forfiles.exe', u'bash.exe',
                  u'wsl.exe', u'certutil.exe', u'bitsadmin.exe', u'curl.exe', u'msbuild.exe', u'installutil.exe',
                  u'regasm.exe', u'regsvcs.exe', u'cmstp.exe', u'odbcconf.exe', u'hh.exe', u'pcalua.exe',
                  u'scriptrunner.exe', u'schtasks.exe', u'sc.exe', u'at.exe', u'python.exe', u'pythonw.exe',
                  u'powershell_ise.exe', u'msdt.exe', u'ftp.exe', u'tftp.exe'])
# strumenti che pesano solo per quello che scaricano o creano, non per il
# solo fatto di essere usati (i download di curl, certutil, bitsadmin e
# msiexec sono giudicati anche dalle regole di COMANDI)
_SOLO_CON_DOWNLOAD = set([u'schtasks.exe', u'sc.exe', u'python.exe', u'pythonw.exe', u'msiexec.exe', u'wmic.exe',
                          u'curl.exe', u'certutil.exe', u'bitsadmin.exe', u'ftp.exe', u'tftp.exe', u'at.exe'])
# interpreti che Windows tiene solo nelle cartelle di sistema: una copia
# altrove e' sospetta di per se'
_SOLO_DI_SISTEMA = set([u'cmd.exe', u'powershell.exe', u'wscript.exe', u'cscript.exe', u'mshta.exe', u'rundll32.exe',
                        u'regsvr32.exe', u'certutil.exe', u'bitsadmin.exe', u'wmic.exe', u'schtasks.exe', u'sc.exe',
                        u'at.exe', u'forfiles.exe', u'msiexec.exe', u'cmstp.exe', u'odbcconf.exe', u'pcalua.exe'])
_ESTENSIONI = (u'.exe', u'.com', u'.bat', u'.cmd', u'.ps1', u'.vbs', u'.js', u'.dll', u'.scr', u'.msi', u'.lnk',
               u'.pif', u'.hta', u'.sys', u'.tmp', u'.dat', u'.jse', u'.vbe', u'.wsf', u'.cpl')

_RX_ESEGUIBILE = re.compile(
    u'^\\s*(.+?\\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|dll|scr|msi|lnk|pif|cpl|sys|tmp|dat))(?=\\s|$|,)', re.I)
# -e, -ec, -en, -enc ... -EncodedCommand: PowerShell accetta ogni abbreviazione
_RX_ENC = re.compile(u'\\s[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc\\w*)?\\s+["\']?[a-z0-9+/=]{20,}', re.I)
# codice costruito ed eseguito al momento (scaricato, decodificato...)
_RX_ESEGUE_CODICE = re.compile(u'(\\biex\\b|invoke-expression|\\.invoke\\(|scriptblock\\]::create|frombase64string'
                               u'|reflection\\.assembly|\\bexecute(global)?\\b|\\beval\\()', re.I)
# script di installazione noti: scaricati ed eseguiti cosi' anche dagli amministratori
_NOTI = (u'(community\\.)?chocolatey\\.org/install\\.ps1|get\\.scoop\\.sh|dot\\.net/v1/dotnet-install\\.ps1|aka\\.ms/'
         u'|win\\.rustup\\.rs|get\\.pnpm\\.io|astral\\.sh/uv|ohmyposh\\.dev|deno\\.land/install\\.ps1'
         u'|bun\\.sh/install\\.ps1|christitus\\.com/win|get\\.activated\\.win|massgrave\\.dev/get')
_RX_DOWNLOAD_NOTO = re.compile(u'https?://(' + _NOTI + u')', re.I)
_RX_NOTO_SENZA_SCHEMA = re.compile(u'(?<![a-z0-9./-])(' + _NOTI + u')', re.I)
_RX_URL = re.compile(u'(https?|ftp)://[^\\s\'"()]+', re.I)


def solo_download_noti(testo):
    """Vero se il testo scarica soltanto script di installazione noti
    (Chocolatey, Scoop...), scritti con o senza http:// davanti."""
    testo = testo or u''
    trovati = [m.group(0) for m in _RX_URL.finditer(testo)]
    for u in trovati:
        if _RX_DOWNLOAD_NOTO.match(u) is None:
            return False
    return bool(trovati) or _RX_NOTO_SENZA_SCHEMA.search(testo) is not None


# "start http://..." e url.dll aprono una pagina nel browser: non scaricano nulla
_RX_APRE_URL = re.compile(u'(\\bstart\\s+(?:"{1,2}\\s*)?https?://|url\\.dll)', re.I)
_RX_ALTRO_DOWNLOAD = re.compile(u'(powershell|pwsh|curl|certutil|bitsadmin|mshta|wscript|cscript|downloadstring'
                                u'|downloadfile|webclient|invoke-webrequest|urlcache)', re.I)
# finestra nascosta. -NoProfile ed -ExecutionPolicy Bypass non contano: li
# usano quasi tutte le attivita' pianificate legittime
_RX_NASCOSTO = re.compile(u'(-w(?:in(?:dowstyle)?)?\\s+h(?:id(?:den)?)?\\b|windowstyle\\s*=?\\s*hidden|vbhide'
                          u'|createnowindow)', re.I)
_RX_SCRIVIBILE = re.compile(
    u'(\\\\users\\\\|\\\\appdata\\\\|\\\\temp\\\\|\\\\tmp\\\\|\\\\programdata\\\\|\\\\perflogs\\\\'
    u'|%temp%|%tmp%|%appdata%|%localappdata%|%public%|%programdata%|%userprofile%|\\$env:temp'
    u'|\\$env:appdata|\\$env:public|\\$env:programdata|\\\\\\$recycle\\.bin\\\\|\\\\windows\\\\tasks\\\\'
    u'|\\\\windows\\\\debug\\\\)', re.I)
_RX_PIPE = re.compile(u'echo\\s+\\S+\\s*>\\s*\\\\\\\\\\.\\\\pipe\\\\', re.I)
# "cmd /c del /q C:\\Windows\\Temp\\*.tmp": un solo comando di cancellazione, senza altri comandi in coda
_RX_SOLO_CANCELLA = re.compile(u'^\\s*(/[a-z](:[a-z]+)?\\s+)*/c\\s+"?\\s*(del|erase|rd|rmdir)\\s[^&|<>]*$', re.I)
_RX_LOOPBACK = re.compile(u'\\\\\\\\(127\\.0\\.0\\.1|localhost)\\\\(admin\\$|c\\$|ipc\\$)', re.I)
_RX_PROGRAMMA_ARG = re.compile(u'\\.(exe|dll|com|msi|cpl|sys)\\b', re.I)
_RX_SCRIPT = re.compile(u'\\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|scr|pif|lnk)\\b', re.I)
_RX_SCRIPTLET_MSHTA = re.compile(u'(vbscript:|javascript:|\\bscript:|https?://|ftp://)', re.I)
_RX_SCRIPTLET_REGSVR32 = re.compile(u'(scrobj|/i:\\s*"?(https?|ftp)://|\\bscript:)', re.I)
_RX_SCRIPTLET_RUNDLL32 = re.compile(u'(javascript:|vbscript:|runhtmlapplication)', re.I)
_RX_WMIC_PROCESSO = re.compile(u'process\\s+call\\s+create', re.I)
# \\\\1.2.3.4\\... oppure \\\\host@80\\... (WebDAV): una condivisione indicata per indirizzo
_RX_UNC_SOSPETTO = re.compile(u'^\\\\\\\\(\\d{1,3}(\\.\\d{1,3}){3}|[^\\\\]*@)')
_RX_CURL_SALVA = re.compile(u'(?:\\s-o|--output)[\\s=]+"?([^\\s"]+)|(\\s-O\\b|--remote-name)')


def _curl_salva(argomenti):
    """Vero se curl salva quello che scarica in un file (-o file, -O).
    "-o /dev/null" e "-o NUL" buttano via il contenuto: non contano."""
    for m in _RX_CURL_SALVA.finditer(u' ' + argomenti):
        if m.group(2) or m.group(1).lower() not in (u'/dev/null', u'nul', u'-'):
            return True
    return False
_RX_TFTP_GET = re.compile(u'\\bget\\b', re.I)
# un file preso da un server WebDAV (\\\\host@80\\..., \\\\host@SSL\\..., \\\\host\\DavWWWRoot\\...)
# o da una condivisione indicata per indirizzo IP
_RX_ARG_WEBDAV = re.compile(u'\\\\\\\\[^\\\\\\s"\']{1,253}@(ssl|\\d{2,5})|\\\\davwwwroot\\\\', re.I)
_RX_ARG_UNC_IP = re.compile(u'\\\\\\\\(?!127\\.)\\d{1,3}(\\.\\d{1,3}){3}\\\\')
# l'output di un comando passato a un interprete: "finger x@host | cmd"
_RX_PIPE_INTERPRETE = re.compile(u'\\|\\s*(cmd|powershell|pwsh)(\\.exe)?(?![\\w.-])', re.I)
_RX_COMANDO_DI_RETE = re.compile(u'(?<![\\w-])(finger|nslookup|curl|wget|certutil|bitsadmin|tftp|ftp)(\\.exe)?\\s', re.I)
# un interprete nominato dentro gli argomenti di un altro programma
_RX_ANNIDATO = re.compile(u'(?<![\\w./-])(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil'
                          u'|bitsadmin|curl|msiexec)(\\.exe)?["\']?\\s+\\S', re.I)


def finestra_nascosta(testo):
    """Vero se la riga di comando chiede una finestra nascosta."""
    return _RX_NASCOSTO.search(testo or u'') is not None


# Le funzioni che scaricano davvero qualcosa. Un indirizzo tra gli argomenti
# non basta: "script.ps1 -Webhook https://..." non scarica nulla.
_RX_VERBO_DOWNLOAD = re.compile(
    u'(downloadstring|downloadfile|downloaddata|invoke-webrequest|\\biwr\\b|invoke-restmethod|\\birm\\b'
    u'|start-bitstransfer|net\\.webclient|/transfer\\b|urlcache|xmlhttp|winhttp)', re.I)
# in PowerShell curl e wget sono altri nomi di Invoke-WebRequest
_RX_ALIAS_DOWNLOAD = re.compile(u'(?<![\\w.-])(curl|wget)(?![\\w.-])', re.I)
_POWERSHELL = (u'powershell.exe', u'pwsh.exe', u'powershell_ise.exe')
_PRENDONO_URL = set([u'mshta.exe', u'regsvr32.exe', u'rundll32.exe', u'msiexec.exe', u'curl.exe', u'certutil.exe',
                     u'bitsadmin.exe', u'ftp.exe', u'tftp.exe', u'hh.exe'])
# "wmic os get /format:http://.../x.xsl": il foglio di stile e' uno script, e viene eseguito
_RX_WMIC_XSL = re.compile(u'/format:\\s*"?(https?|ftp)://', re.I)
# estensioni di cio' che si esegue: scaricare uno di questi file e' scaricare un programma
_SUFFISSI_PROGRAMMA = tuple([u'.' + x for x in (
    u'exe', u'dll', u'ps1', u'psm1', u'bat', u'cmd', u'vbs', u'vbe', u'js', u'jse', u'wsf', u'wsh', u'hta', u'msi',
    u'msp', u'scr', u'sct', u'cpl', u'com', u'pif', u'jar')])
_SUFFISSI_CERTIFICATO = (u'.crl', u'.cer', u'.crt', u'.p7b', u'.p7c', u'.der', u'.pem', u'.stl')
# dove finisce quello che viene scaricato
_RX_DESTINAZIONE = re.compile(u'(?:-outfile|--output|-destination|(?<![\\w-])-o)[\\s:=]+["\']?([^\\s"\']+)', re.I)
_RX_DOWNLOADFILE = re.compile(u'downloadfile\\s*\\(([^)]{0,800})\\)', re.I)
_RX_TRA_VIRGOLETTE = re.compile(u'["\']([^"\']{1,400})["\']')
# un blocco lungo di Base64 (i percorsi con le barre e le chiavi esadecimali hanno la stessa forma: conta se si decodifica in testo)
_RX_BLOCCO_BASE64 = re.compile(u'[A-Za-z0-9+/]{120,}={0,2}')


def _argomento_da(arg, posizione):
    """L'argomento che comincia alla posizione data, fino allo spazio o alle virgolette."""
    fine = len(arg)
    for c in u' "\'\t':
        p = arg.find(c, posizione)
        if 0 <= p < fine:
            fine = p
    return arg[posizione:fine]


def _fine_percorso(testo):
    """Il testo senza la coda che non fa parte del nome del file (query
    dell'URL, virgola e funzione di rundll32, punteggiatura finale)."""
    taglio = len(testo)
    for c in u'?#,':
        p = testo.find(c)
        if 0 <= p < taglio:
            taglio = p
    return testo[:taglio].lower().rstrip(u'/.;)\'"')


def _e_programma(testo):
    return _fine_percorso(testo).endswith(_SUFFISSI_PROGRAMMA)


# Siti dai quali solo il produttore puo' pubblicare: scaricare da li' un
# programma di installazione lo fanno ogni giorno anche gli amministratori.
# Non ci sono, apposta, i servizi dove chiunque puo' caricare un file
# (GitHub, OneDrive, Dropbox, i CDN generici) ne' Sysinternals, i cui
# strumenti servono anche a chi attacca.
_HOST_PRODUTTORI = set([
    u'download.microsoft.com', u'go.microsoft.com', u'download.visualstudio.microsoft.com', u'officecdn.microsoft.com',
    u'download.windowsupdate.com', u'dl.google.com', u'download.mozilla.org', u'download.adobe.com',
    u'ardownload2.adobe.com', u'dl.dell.com', u'downloads.dell.com', u'ftp.hp.com', u'download.lenovo.com',
    u'javadl.oracle.com', u'download.oracle.com', u'www.python.org', u'nodejs.org', u'www.7-zip.org',
    u'packages.vmware.com', u'download.vmware.com'])
_SUFFISSI_INTERNI = (u'.local', u'.lan', u'.corp', u'.internal', u'.intranet', u'.home', u'.localdomain', u'.test',
                     u'.example', u'.invalid')


_RX_AUTORITA = re.compile(u'^(?:https?|ftp)://([^/\\s?#]*)', re.I)


def host_di(indirizzo):
    """Il nome (o l'indirizzo IP) del server di un URL, in minuscolo, senza
    utente, password e porta: in "http://sito.buono:80@altro.sito/x" il
    server e' altro.sito. Restituisce u'' se non lo si ricava."""
    m = _RX_AUTORITA.match(indirizzo or u'')
    if m is None:
        return u''
    nome = m.group(1).rsplit(u'@', 1)[-1].lower()
    if nome.startswith(u'['):                       # indirizzo IPv6 tra parentesi quadre
        return nome[:nome.find(u']') + 1] if u']' in nome else u''
    if u':' in nome:
        nome = nome[:nome.find(u':')]
    return nome.strip(u'.')


def _host_degli_indirizzi(testo):
    """I nomi (o gli indirizzi IP) dei server negli URL del testo, in minuscolo."""
    return [host_di(m.group(0)) for m in _RX_URL.finditer(testo or u'')]


def solo_da_produttori(testo):
    """Vero se nel testo ci sono indirizzi e sono tutti di siti da cui solo
    il produttore puo' pubblicare."""
    nomi = _host_degli_indirizzi(testo)
    return bool(nomi) and not [n for n in nomi if n not in _HOST_PRODUTTORI]


def host_interno(nome):
    """Vero se il nome e' di una macchina della rete interna: senza dominio,
    con un dominio che su Internet non esiste, oppure un indirizzo privato."""
    nome = (nome or u'').strip().lower().rstrip(u'.')
    if not nome:
        return False
    if _RX_IPV4.match(nome):
        return not ip_pubblico(nome)
    return u'.' not in nome or nome.endswith(_SUFFISSI_INTERNI)


def _da_ip_pubblico(testo):
    """Vero se uno degli indirizzi del testo e' un indirizzo IP pubblico
    scritto al posto del nome: i programmi veri si scaricano da un nome."""
    for nome in _host_degli_indirizzi(testo):
        if ip_pubblico(nome):
            return True
    return False


def _scarica_un_programma(arg, per_posizione=False):
    """Vero se cio' che viene scaricato e' un programma o uno script:
    l'indirizzo, oppure il file in cui viene salvato, ha un'estensione
    eseguibile. Con per_posizione=True (certutil, bitsadmin, che indicano
    la destinazione senza un'opzione) conta qualunque argomento."""
    for m in _RX_URL.finditer(arg):
        if _e_programma(m.group(0)):
            return True
    for m in _RX_DESTINAZIONE.finditer(arg):
        if _e_programma(m.group(1)):
            return True
    for m in _RX_DOWNLOADFILE.finditer(arg):
        for v in _RX_TRA_VIRGOLETTE.finditer(m.group(1)):
            if _e_programma(v.group(1)):
                return True
    if per_posizione:
        for pezzo in arg.split():
            if _e_programma(pezzo.strip(u'"\'')):
                return True
    return False


def _testo_utf16_in_base64(blocco):
    """Vero se il blocco di Base64 contiene testo UTF-16, cioe' un comando
    di PowerShell codificato. Un percorso lungo, una chiave esadecimale o un
    token hanno la stessa forma ma decodificati sono byte qualunque."""
    grezzo = blocco.rstrip(u'=')[:4000]
    if len(grezzo) % 4 == 1:
        grezzo = grezzo[:-1]
    try:
        dati = binascii.a2b_base64(grezzo.encode('ascii') + '=' * (-len(grezzo) % 4))
    except ERRORI:
        return False
    if len(dati) < 40:
        return False
    alti = dati[1:400:2]
    bassi = dati[0:400:2]
    if alti.count('\x00') * 100 < len(alti) * 85:
        return False
    leggibili = len([c for c in bassi if ' ' <= c <= '~' or c in '\r\n\t'])
    return leggibili * 100 >= len(bassi) * 85


def spezza_comando(testo):
    """Divide una riga di comando in (eseguibile, argomenti)."""
    if not testo:
        return u'', u''
    s = testo.strip()
    if not s:
        return u'', u''
    if s.startswith(u'"'):
        fine = s.find(u'"', 1)
        if fine > 0:
            return s[1:fine], s[fine + 1:].strip()
    parti = s.split(None, 1)
    primo = parti[0]
    if u'\\' in primo or u'/' in primo[1:]:
        if u'\\' not in primo:
            # "cmd/c comando": l'interprete e le sue opzioni attaccati
            taglio = primo.find(u'/', 1)
            if con_estensione(primo[:taglio].lower()) in INTERPRETI:
                return primo[:taglio], s[taglio:].strip()
        # un percorso: puo' contenere spazi anche senza virgolette
        m = _RX_ESEGUIBILE.match(s)
        if m is not None:
            return m.group(1).strip(), s[m.end():].strip(u' ,')
    if len(parti) == 2:
        return primo, parti[1]
    return s, u''


# Comandi che creano una voce di avvio automatico: si giudica quello che la
# voce lancera'. Serve quando la voce e' stata poi tolta e del passaggio
# resta solo la riga di comando (eventi 4688, Sysmon, cronologia).
_RX_TR = re.compile(u'\\s/tr\\s+', re.I)
_RX_BINPATH = re.compile(u'\\bbinpath\\s*=\\s*', re.I)
_RX_SC_CREA = re.compile(u'(^|\\s)(create|config)\\s', re.I)
_RX_REG_ADD = re.compile(u'^\\s*add\\s+("[^"]*"|\\S+)', re.I)
_RX_REG_DATO = re.compile(u'\\s/d\\s+', re.I)
_RX_REG_VALORE = re.compile(u'\\s/v\\s+("[^"]*"|\\S+)', re.I)
# le chiavi da cui Windows avvia programmi, e i valori che contano (None: tutti)
_CHIAVI_AVVIO = [
    (re.compile(u'\\\\(run(once(ex)?|services(once)?)?|policies\\\\explorer\\\\run)$', re.I), None),
    (re.compile(u'\\\\winlogon$', re.I), (u'shell', u'userinit', u'taskman', u'vmapplet', u'appsetup')),
    (re.compile(u'\\\\image file execution options\\\\[^\\\\]+$', re.I), (u'debugger',)),
    (re.compile(u'^(hkcu|hkey_current_user|hku\\\\[^\\\\]+|hkey_users\\\\[^\\\\]+)\\\\environment$', re.I),
     (u'userinitmprlogonscript',)),
    (re.compile(u'\\\\windows nt\\\\currentversion\\\\windows$', re.I), (u'load', u'run', u'appinit_dlls')),
    (re.compile(u'\\\\active setup\\\\installed components\\\\[^\\\\]+$', re.I), (u'stubpath',)),
]


def _valore_da(arg, posizione):
    """Il valore che comincia alla posizione data: tra virgolette (con \\"
    per le virgolette al suo interno) oppure fino al primo spazio."""
    resto = arg[posizione:posizione + 8000]
    if resto[:1] == u'"':
        p = 1
        while True:
            p = resto.find(u'"', p)
            if p < 0:
                valore = resto[1:]
                break
            if resto[p - 1] != u'\\':
                valore = resto[1:p]
                break
            p += 1
        valore = valore.replace(u'\\"', u'"')
    else:
        valore = resto.split(None, 1)[0] if resto.strip() else u''
    valore = valore.strip()
    if valore[:1] == u"'" and valore.count(u"'") >= 2:
        valore = valore.replace(u"'", u'"')        # schtasks accetta anche gli apici per i percorsi con spazi
    return valore


def crea_avvio(nome, arg):
    """Se il comando crea una voce di avvio automatico restituisce (che cosa
    crea, il comando che la voce lancera'); altrimenti None. Riconosce
    "schtasks /create ... /tr", "sc create|config ... binPath=" e "reg add"
    sulle chiavi di avvio (Run, RunOnce, Winlogon, Image File Execution
    Options, Environment\\UserInitMprLogonScript...)."""
    if nome == u'schtasks.exe':
        if u'/create' not in arg.lower() and u'/change' not in arg.lower():
            return None
        m = _RX_TR.search(u' ' + arg)
        if m is None:
            return None
        return u'un\'attivit\u00e0 pianificata', _valore_da(u' ' + arg, m.end())
    if nome == u'sc.exe':
        m = _RX_BINPATH.search(arg)
        if m is None or _RX_SC_CREA.search(arg[:m.start()]) is None:
            return None
        return u'un servizio', _valore_da(arg, m.end())
    if nome == u'reg.exe':
        m = _RX_REG_ADD.match(arg)
        if m is None:
            return None
        chiave = m.group(1).strip(u'"').rstrip(u'\\')
        v = _RX_REG_VALORE.search(arg, m.end())
        valore = v.group(1).strip(u'"').lower() if v is not None else u''
        for rx, valori in _CHIAVI_AVVIO:
            if rx.search(chiave) is not None and (valori is None or valore in valori):
                d = _RX_REG_DATO.search(arg, m.end())
                if d is None:
                    return None
                return u'una voce di avvio automatico nel registro', _valore_da(arg, d.end())
    return None


# "p^o^w^e^r^s^h^e^l^l" e "pow""ershell": cmd toglie ^ e "" prima di eseguire,
# e chi li mette in mezzo alle parole lo fa per non farsi riconoscere
_RX_CARET_TRA_LETTERE = re.compile(u'(?<=[A-Za-z])\\^(?=[A-Za-z])')
_RX_VIRGOLETTE_TRA_LETTERE = re.compile(u'(?<=[A-Za-z])""(?=[A-Za-z])')
_RX_CARET_LETTERA = re.compile(u'\\^(?=[A-Za-z])')
_NOMI_NASCOSTI = (u'powershell', u'pwsh', u'mshta', u'wscript', u'cscript', u'rundll32', u'regsvr32', u'certutil',
                  u'bitsadmin', u'msiexec', u'vssadmin', u'wevtutil', u'bcdedit', u'schtasks', u'wmic')


def senza_offuscamento(testo):
    """Il comando come lo esegue cmd, quando ^ o "" spezzano le parole per
    non farle riconoscere; altrimenti il testo com'e'. Restituisce (testo,
    vero se era offuscato).

    Conta come offuscato un ^ tra due lettere in almeno due punti (uno solo
    davanti a una lettera c'e' anche nei comandi normali: findstr "^Errore"),
    oppure un "" tra due lettere che nasconde il nome di un interprete (le
    virgolette raddoppiate da sole sono anche un modo normale di scriverle
    dentro un testo tra virgolette)."""
    if not testo or (u'^' not in testo and u'""' not in testo):
        return testo, False
    inizio = testo[:20000]
    offuscato = len(_RX_CARET_TRA_LETTERE.findall(inizio)) >= 2
    if not offuscato and u'""' in inizio:
        prima = inizio.lower()
        dopo = _RX_CARET_LETTERA.sub(u'', _RX_VIRGOLETTE_TRA_LETTERE.sub(u'', prima))
        for nome in _NOMI_NASCOSTI:
            if nome in dopo and nome not in prima:
                offuscato = True
                break
    if not offuscato:
        return testo, False
    return _RX_CARET_LETTERA.sub(u'', _RX_VIRGOLETTE_TRA_LETTERE.sub(u'', testo)), True


class Giudizio(object):
    """Esito della valutazione di una riga di comando."""

    def __init__(self):
        self.eseguibile = u''
        self.nome = u''           # nome del programma, in minuscolo e con l'estensione ('cmd' diventa 'cmd.exe')
        self.argomenti = u''
        self.zona = u'altro'
        self.interprete = False
        self.solo_download = False   # strumento che pesa solo per quello che scarica (curl, certutil...)
        self.noto = False            # scarica solo script di installazione noti (Chocolatey, Scoop...)
        self.livello = 0          # 0 nulla, 1 debole, 2 medio, 3 forte
        # il livello 3 viene da qualcosa che non ha una spiegazione innocente
        # nemmeno quando a eseguirlo e' uno strumento di gestione (vedi valuta_comando)
        self.certo = False
        # il comando crea una voce di avvio automatico (attivita', servizio,
        # chiave Run) che a sua volta e' almeno sospetta: chi giudica i comandi
        # soltanto eseguiti lo segnala anche se il livello e' 2
        self.avvio = False
        self.decodificato = u''   # il comando passato con -EncodedCommand, in chiaro
        self.motivi = []

    def motivo(self):
        return u'; '.join(self.motivi)

    def alza(self, livello, motivo, certo=False):
        if livello > self.livello:
            self.livello = livello
        if certo:
            self.certo = True
        if motivo not in self.motivi:
            self.motivi.append(motivo)


# il valore di -EncodedCommand (con tutte le abbreviazioni che PowerShell accetta)
_RX_ENC_VALORE = re.compile(u'\\s[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc\\w*)?\\s+["\']?([a-z0-9+/]{20,}={0,2})', re.I)


def comando_decodificato(argomenti):
    """Il comando di PowerShell passato con -EncodedCommand (Base64 di testo
    UTF-16), in chiaro: il primo, se nella riga ce n'e' piu' d'uno.
    Restituisce u'' se non c'e' o se non si decodifica in un testo leggibile."""
    m = _RX_ENC_VALORE.search(u' ' + (argomenti or u''))
    if m is None:
        return u''
    return _decodifica(m.group(1))


def comandi_decodificati(argomenti):
    """Tutti i comandi passati con -EncodedCommand nella riga (possono essere
    piu' d'uno: "cmd /c powershell -enc ... & powershell -enc ..."), in
    chiaro; u'' al posto di quelli che non si decodificano."""
    return [_decodifica(m.group(1)) for m in _RX_ENC_VALORE.finditer(u' ' + (argomenti or u''))][:20]


def _decodifica(valore):
    grezzo = valore.rstrip(u'=')[:200000]
    grezzo = grezzo[:len(grezzo) - len(grezzo) % 4] if len(grezzo) % 4 == 1 else grezzo
    try:
        dati = binascii.a2b_base64(grezzo.encode('ascii') + '=' * (-len(grezzo) % 4))
    except ERRORI:
        return u''
    testo = decodifica16(dati)
    if not testo:
        return u''
    leggibili = len([c for c in testo[:2000] if u' ' <= c <= u'~' or c in u'\r\n\t'])
    if leggibili * 100 < len(testo[:2000]) * 85:
        return u''
    return testo


def valuta_comando(comando, argomenti=None, persistenza=True, _annidato=0):
    """Giudica una riga di comando (o comando + argomenti separati).
    livello 3: un interprete (cmd, PowerShell, mshta...) con un comando
               codificato, che scarica ed esegue o salva un programma, che
               esegue codice a finestra nascosta, che prende un file da un
               server WebDAV, che riceve i comandi dall'output di un comando
               di rete, o con l'output ridiretto su \\\\127.0.0.1 (Impacket);
    livello 2: un interprete che contatta la rete o lavora su una cartella
               scrivibile dagli utenti; un interprete di Windows copiato
               fuori dalle cartelle di sistema; un programma in una zona ad
               alto sospetto; un nome di processo di sistema fuori posto;
               con persistenza=True anche un programma in una cartella
               temporanea o su una condivisione di rete;
    livello 1: un programma nelle cartelle dell'utente o in ProgramData.
    Se negli argomenti c'e' un altro interprete ("conhost --headless
    powershell ...", "cmd /c rundll32 ...") viene giudicato anche quello e
    vale il livello piu' alto.

    Chi usa il giudizio distingue due casi. In una voce che parte da sola
    (servizio, attivita', chiave Run) e in un comando incollato nella finestra
    Esegui il livello 3 e' decisivo. In un comando che risulta soltanto
    eseguito (eventi 4688, Sysmon, PowerShell, cronologia della console) no:
    gli strumenti di gestione (SCCM, Intune, Ansible, gli agenti RMM) e chi
    installa programmi da riga di comando eseguono ogni giorno comandi
    codificati o che scaricano script. Li' il livello 3 e' da confermare, ed
    e' decisivo solo se g.certo e' vero: output su \\\\127.0.0.1, named pipe
    di getsystem, scriptlet di regsvr32 o rundll32, scarica ed esegue a
    finestra nascosta, comando codificato che in chiaro e' d'attacco o
    scarica ed esegue, strumento o script d'attacco nominato tra gli
    argomenti. (Uno strumento a doppio uso tra gli argomenti di un interprete
    vale il livello 2.)"""
    g = Giudizio()
    if argomenti is None:
        eseguibile, argomenti = spezza_comando((comando or u'')[:MAX_RIGA])
    else:
        eseguibile = (comando or u'').strip().strip(u'"')[:MAX_RIGA]
        argomenti = argomenti[:MAX_RIGA]
    g.eseguibile = eseguibile
    g.argomenti = argomenti or u''
    nome = nome_base(eseguibile)
    if u'%' in nome:
        nome = nome_base(percorso_normale(eseguibile)) or nome
    if nome and not nome.endswith(_ESTENSIONI):
        nome = con_estensione(nome)
    g.nome = nome
    g.zona = zona(eseguibile)
    g.interprete = nome in INTERPRETI
    arg = g.argomenti
    offuscato = False
    if nome == u'cmd.exe':
        arg, offuscato = senza_offuscamento(arg)    # da qui in poi si giudica il comando che cmd esegue davvero
    tutto = eseguibile + u' ' + arg
    basso = tutto.lower()
    con_percorso = u'\\' in eseguibile.replace(u'/', u'\\')
    if g.interprete:
        g.solo_download = nome in _SOLO_CON_DOWNLOAD
        indirizzo = _RX_URL.search(arg) is not None
        # scarica: una funzione di download, oppure un programma che va a
        # prendere l'indirizzo che riceve. Un indirizzo passato a uno script o
        # a un programma locale ("-Webhook https://...") non e' un download.
        scarica = _RX_VERBO_DOWNLOAD.search(arg) is not None or (indirizzo and nome in _PRENDONO_URL) or \
            (nome in _POWERSHELL and _RX_ALIAS_DOWNLOAD.search(arg) is not None)
        if nome == u'tftp.exe':
            scarica = scarica or _RX_TFTP_GET.search(arg) is not None
        elif nome == u'ftp.exe':
            scarica = scarica or u'-s:' in arg.lower()      # ftp -s:comandi.txt: download guidato da un file
        if nome in (u'cmd.exe', u'rundll32.exe') and _RX_APRE_URL.search(arg) and not _RX_ALTRO_DOWNLOAD.search(arg):
            scarica = False     # apre soltanto una pagina nel browser
            indirizzo = False
        if (scarica or indirizzo) and solo_download_noti(arg):
            scarica = False
            indirizzo = False
            g.noto = True
        elif not scarica and _RX_NOTO_SENZA_SCHEMA.search(arg):
            g.noto = True
        # codificato: -EncodedCommand, FromBase64String, o un blocco di Base64 che contiene testo
        codificato = u'frombase64string' in basso
        if not codificato and _RX_ENC.search(u' ' + arg) is not None:
            # Se il nome di PowerShell non compare (costruito con variabili:
            # "set a=power&&set b=shell&&!a!!b! -enc ...") conta lo stesso,
            # purche' il valore sia davvero testo codificato: "-e" seguito da
            # una parola lunga lo usano anche altri programmi.
            codificato = u'powershell' in basso or u'pwsh' in basso or bool(comando_decodificato(arg))
        if not codificato:
            for m in _RX_BLOCCO_BASE64.finditer(arg):
                if _testo_utf16_in_base64(m.group(0)):
                    codificato = True
                    break
        # esegue codice costruito al momento (iex, Invoke-Expression, ScriptBlock::Create...)
        dinamico = _RX_ESEGUE_CODICE.search(arg) is not None
        nascosto = _RX_NASCOSTO.search(arg) is not None
        if _RX_LOOPBACK.search(arg):
            g.alza(3, u'output ridiretto su \\\\127.0.0.1 (firma di Impacket)', True)
        if _RX_PIPE.search(arg):
            g.alza(3, u'scrive in una named pipe (tecnica getsystem di Meterpreter e Cobalt Strike)', True)
        if codificato:
            chiari = comandi_decodificati(arg)
            # di sola lettura se lo sono tutti i comandi codificati della riga
            sola_lettura = bool(chiari) and u'frombase64string' not in basso
            g.decodificato = u'\n'.join([c for c in chiari if c])[:4000]
            for chiaro in chiari:
                if not chiaro:
                    sola_lettura = False        # non si decodifica: non si sa che cosa fa
                    continue
                dentro = ps_sospetto(chiaro, breve=False)
                if dentro is not None and dentro[0] >= DA_CONFERMARE:
                    # codificato e, una volta in chiaro, d'attacco o "scarica ed
                    # esegue": certo. (Toccare le impostazioni di Defender con un
                    # comando codificato lo fanno anche gli strumenti di gestione.)
                    g.alza(3, u'il comando in chiaro: %s' % dentro[1], dentro[1] != _COSA_DIFESE)
                    sola_lettura = False
                elif codice_che_agisce(chiaro):
                    sola_lettura = False
            if sola_lettura:
                # Gli strumenti di gestione e di monitoraggio codificano i
                # comandi per non litigare con le virgolette. Se in chiaro il
                # comando si limita a leggere informazioni, resta insolito
                # solo in una voce che parte da sola.
                g.alza(2, u'comando codificato in Base64 che in chiaro si limita a leggere informazioni')
            else:
                g.alza(3, u'comando codificato in Base64')
        if dinamico and nascosto and not g.noto:
            # Con il download e' lo schema classico. Una finestra nascosta da
            # sola non conta: la usano i promemoria e gli script di servizio.
            g.alza(3, u'esecuzione di codice a finestra nascosta', scarica)
        if nome == u'mshta.exe' and _RX_SCRIPTLET_MSHTA.search(arg):
            g.alza(3, u'mshta.exe esegue codice in linea o preso dalla rete')
        elif nome == u'regsvr32.exe' and _RX_SCRIPTLET_REGSVR32.search(arg):
            g.alza(3, u'regsvr32.exe esegue uno scriptlet', True)
        elif nome == u'rundll32.exe' and _RX_SCRIPTLET_RUNDLL32.search(arg):
            g.alza(3, u'rundll32.exe esegue codice in linea', True)
        if scarica:
            # Dal sito di un produttore un programma di installazione lo
            # scaricano anche gli amministratori: livello 2. Da un indirizzo IP
            # pubblico scritto al posto del nome, qualunque file e' sospetto.
            produttore = solo_da_produttori(arg)
            da_ip = _da_ip_pubblico(arg)
            if nome == u'curl.exe':
                if not _curl_salva(arg):
                    g.alza(1, u'curl.exe contatta la rete')
                elif _scarica_un_programma(arg):
                    if produttore:
                        g.alza(2, u'curl.exe scarica un programma dal sito del produttore')
                    else:
                        g.alza(3, u'curl.exe scarica e salva un programma')
                elif da_ip:
                    g.alza(3, u'curl.exe scarica un file da un indirizzo IP pubblico')
                elif _RX_SCRIVIBILE.search(arg):
                    g.alza(2, u'curl.exe scarica un file in una cartella scrivibile dagli utenti')
                else:
                    g.alza(1, u'curl.exe scarica un file di dati')
            elif nome == u'certutil.exe':
                if _scarica_un_programma(arg, True):
                    if produttore:
                        g.alza(2, u'certutil.exe scarica un programma dal sito del produttore')
                    else:
                        g.alza(3, u'certutil.exe scarica un programma')
                elif [1 for m in _RX_URL.finditer(arg) if _fine_percorso(m.group(0)).endswith(_SUFFISSI_CERTIFICATO)]:
                    g.alza(1, u'certutil.exe aggiorna un certificato o una lista di revoca')
                elif da_ip:
                    g.alza(3, u'certutil.exe scarica un file da un indirizzo IP pubblico')
                else:
                    g.alza(2, u'certutil.exe scarica dalla rete')
            elif nome == u'bitsadmin.exe':
                if _scarica_un_programma(arg, True):
                    if produttore:
                        g.alza(2, u'bitsadmin.exe scarica un programma dal sito del produttore')
                    else:
                        g.alza(3, u'bitsadmin.exe scarica un programma')
                elif da_ip:
                    g.alza(3, u'bitsadmin.exe scarica un file da un indirizzo IP pubblico')
                else:
                    g.alza(2, u'bitsadmin.exe scarica dalla rete')
            elif nome == u'msiexec.exe':
                # un pacchetto .msi preso dal sito di un produttore lo installano
                # anche gli amministratori; da un indirizzo IP, o con un'altra
                # estensione, e' il modo in cui lo usa chi attacca
                strano = False
                for m in _RX_URL.finditer(arg):
                    if _RX_IPV4.match(host_di(m.group(0))) or \
                            not _fine_percorso(m.group(0)).endswith((u'.msi', u'.msp', u'.mst')):
                        strano = True
                if strano:
                    g.alza(3, u'msiexec.exe installa dalla rete un pacchetto da un indirizzo IP o senza estensione .msi')
                elif produttore:
                    g.alza(1, u'msiexec.exe installa un pacchetto preso dal sito del produttore')
                else:
                    g.alza(2, u'msiexec.exe installa un pacchetto preso dalla rete')
            elif nome in (u'ftp.exe', u'tftp.exe'):
                g.alza(2, u'%s scarica dalla rete' % nome)
            elif nome in (u'mshta.exe', u'regsvr32.exe', u'rundll32.exe', u'hh.exe'):
                g.alza(3, u'%s esegue codice preso dalla rete' % nome)
            elif dinamico:
                g.alza(3, u'scarica dalla rete ed esegue')
            elif _scarica_un_programma(arg):
                if produttore:
                    g.alza(2, u'scarica un programma dal sito del produttore')
                else:
                    g.alza(3, u'scarica dalla rete un programma')
            elif da_ip and (_RX_DESTINAZIONE.search(arg) or _RX_DOWNLOADFILE.search(arg)
                            or u'start-bitstransfer' in basso):
                g.alza(3, u'scarica un file da un indirizzo IP pubblico')
            else:
                g.alza(2, u'%s contatta la rete' % nome)
        elif indirizzo and not g.noto:
            g.alza(1, u'un indirizzo Internet tra gli argomenti')
        if nome == u'wmic.exe' and _RX_WMIC_PROCESSO.search(arg):
            g.alza(2, u'wmic.exe avvia un processo')
        if nome == u'wmic.exe' and _RX_WMIC_XSL.search(arg):
            g.alza(3, u'wmic.exe esegue un foglio di stile preso dalla rete', True)
        if nome in _POWERSHELL or u'powershell' in basso or u'pwsh' in basso:
            schema = _ps_certo(arg)
            if schema is not None:
                g.alza(3, schema[0], True)
        # file presi da un server WebDAV o da una condivisione indicata per
        # indirizzo IP. Mappare un'unita' ("net use") lo fanno tutti gli
        # uffici: conta quando da li' si esegue qualcosa.
        esegue_da_rete = nome in (u'rundll32.exe', u'regsvr32.exe', u'mshta.exe', u'msiexec.exe', u'wscript.exe',
                                  u'cscript.exe')
        m = _RX_ARG_WEBDAV.search(arg)
        if m is not None:
            if esegue_da_rete:
                g.alza(3, u'%s prende un file da un server WebDAV' % nome, nome in (u'rundll32.exe', u'regsvr32.exe'))
            elif _e_programma(_argomento_da(arg, m.start())):
                g.alza(2, u'%s esegue un file da un server WebDAV' % nome)
            else:
                g.alza(1, u'%s usa una cartella WebDAV' % nome)
        else:
            m = _RX_ARG_UNC_IP.search(arg)
            if m is not None:
                if ip_pubblico(m.group(0).strip(u'\\')):
                    g.alza(3, u'%s usa una condivisione su un indirizzo IP pubblico' % nome,
                           nome in (u'rundll32.exe', u'regsvr32.exe'))
                elif esegue_da_rete or _e_programma(_argomento_da(arg, m.start())):
                    g.alza(2, u'%s esegue un file da una condivisione indicata per indirizzo IP' % nome)
                else:
                    g.alza(1, u'%s usa una condivisione indicata per indirizzo IP' % nome)
        if _RX_PIPE_INTERPRETE.search(arg):
            if scarica or _RX_COMANDO_DI_RETE.search(u' ' + arg):
                g.alza(3, u'passa a un interprete quello che riceve dalla rete')
            else:
                g.alza(2, u'passa l\'output di un comando a un interprete')
        if not g.solo_download and g.livello < 2:
            scrivibile = _RX_SCRIVIBILE.search(arg) is not None
            if scrivibile and _RX_NOTI_IN_PROFILO.search(percorso_normale(arg)):
                scrivibile = False      # lavora nella cartella di un programma noto (OneDrive, Teams...)
            if scrivibile and nome == u'rundll32.exe' and u'advpack.dll,delnoderundll32' in basso:
                scrivibile = False      # la pulizia che gli installatori lasciano in RunOnce (wextract_cleanup)
            if scrivibile:
                if _RX_SCRIPT.search(arg):
                    g.alza(2, u'%s lancia uno script da una cartella scrivibile dagli utenti' % nome)
                elif _RX_PROGRAMMA_ARG.search(arg):
                    g.alza(2, u'%s lavora su una cartella scrivibile dagli utenti' % nome)
                elif nome == u'cmd.exe' and _RX_SOLO_CANCELLA.match(arg):
                    # la pulizia dei file temporanei: non esegue nulla
                    g.alza(1, u'cmd.exe cancella file in una cartella scrivibile dagli utenti')
                else:
                    # nessun programma tra gli argomenti: in una voce che parte
                    # da sola resta insolito; in un comando scritto a mano
                    # (salvare un output sul Desktop) e' normale
                    g.alza(2 if persistenza else 1, u'%s lavora su una cartella scrivibile dagli utenti' % nome)
        if offuscato:
            g.alza(2, u'comando offuscato (^ o "" in mezzo alle parole)')
        # l'interprete stesso in un posto dove non dovrebbe stare
        if con_percorso and (g.zona in (u'sospetta', u'temporanea') or
                             (g.zona == u'utente' and nome in _SOLO_DI_SISTEMA and not noto_in_profilo(eseguibile))):
            g.alza(2, u'%s avviato da una copia fuori dalle cartelle di sistema' % nome)
    else:
        if g.zona == u'sospetta':
            g.alza(2, u'programma in una cartella dove di norma non ce ne sono')
        elif g.zona == u'temporanea':
            g.alza(2 if persistenza else 1, u'programma in una cartella temporanea')
        elif g.zona == u'rete' and persistenza:
            if _RX_UNC_SOSPETTO.match(percorso_normale(eseguibile)):
                g.alza(2, u'programma avviato da una condivisione indicata per indirizzo IP o via WebDAV')
            else:
                g.alza(1, u'programma avviato da una condivisione di rete')
        elif g.zona == u'utente':
            if not noto_in_profilo(eseguibile):
                g.alza(1, u'programma in una cartella dell\'utente')
        if _RX_LOOPBACK.search(tutto):
            g.alza(3, u'output ridiretto su \\\\127.0.0.1 (firma di Impacket)', True)
    if fuori_posto(eseguibile):
        g.alza(2, u'nome di un processo di sistema fuori dalle cartelle di sistema')
    if u'\u202e' in tutto:
        g.alza(2, u'il nome contiene il carattere che inverte il verso del testo (camuffa l\'estensione)')
    if nome == u'conhost.exe' and u'--headless' in arg.lower():
        # lo usano gli attaccanti e anche chi vuole un'attivita' pianificata
        # senza finestra: da solo e' contesto, conta il comando che avvia
        g.alza(1, u'conhost.exe --headless avvia un comando senza finestra')
    if not _annidato and nome in (u'schtasks.exe', u'sc.exe', u'reg.exe'):
        avvio = crea_avvio(nome, arg)
        if avvio is not None and avvio[1]:
            dentro = valuta_comando(avvio[1], None, True, 1)
            peso_s, cosa_s = strumento(dentro.nome)
            if dentro.livello < 2 and peso_s < DA_CONFERMARE and nome == u'reg.exe' and u',' in avvio[1]:
                # Winlogon\Shell e Userinit elencano piu' programmi separati da virgole
                for parte in avvio[1].split(u',')[:8]:
                    altro = valuta_comando(parte.strip(), None, True, 1)
                    if altro.livello > dentro.livello:
                        dentro = altro
                        peso_s, cosa_s = strumento(dentro.nome)
            if dentro.livello >= 2 or peso_s >= DA_CONFERMARE:
                motivi = list(dentro.motivi)
                if peso_s >= DA_CONFERMARE:
                    motivi.append(cosa_s)
                # vale quanto la voce che crea: un livello 3 dentro una voce
                # di avvio e' decisivo ovunque compaia il comando
                forte = dentro.livello >= 3 or peso_s >= DECISIVO
                g.alza(3 if forte else 2, u'crea %s che lancia: %s' % (avvio[0], u'; '.join(motivi)), forte)
                g.avvio = True
                if dentro.decodificato:
                    g.decodificato = dentro.decodificato
    if not _annidato:
        # Uno strumento noto tra gli argomenti o nella cartella del programma
        # ("cmd /c C:\\Tools\\Rubeus.exe kerberoast"). Il nome del programma
        # stesso lo giudica chi chiama, con strumento(g.nome).
        cartella = u''
        if strumento(nome)[0] < DA_CONFERMARE:
            cartella = eseguibile[:max(eseguibile.rfind(u'\\'), eseguibile.rfind(u'/')) + 1]
        peso_s, cosa_s = strumento_nominato(cartella + u' ' + arg)
        if peso_s >= DECISIVO:
            if solo_cercato(tutto):
                g.alza(1, u'cerca per nome uno ' + cosa_s)
            else:
                g.alza(3, u'nomina uno ' + cosa_s, True)
        elif peso_s and g.interprete:
            g.alza(2, u'nomina uno ' + cosa_s)
    if _annidato < 2 and g.livello < 3 and arg:
        # un interprete lanciato tramite un altro programma: si giudica anche
        # lui (fino a due livelli: "launcher.exe ... cmd /c regsvr32 ...")
        m = _RX_ANNIDATO.search(arg)
        if m is not None:
            dentro = valuta_comando(arg[m.start():], None, persistenza, _annidato + 1)
            if dentro.livello >= 2 and dentro.livello > g.livello:
                for motivo in dentro.motivi:
                    g.alza(dentro.livello, motivo, dentro.certo)
                if dentro.decodificato:
                    g.decodificato = dentro.decodificato
    return g


def _rx(testo):
    return re.compile(testo, re.I)


def _in_sequenza(sequenza, testo):
    """Vero se le espressioni della sequenza compaiono nel testo una dopo
    l'altra. Equivale a cercare "a.*b.*c", ma un pezzo alla volta: il tempo
    resta proporzionale alla lunghezza del testo anche su righe lunghissime
    costruite apposta (con ".*" diventerebbe quadratico). Restituisce la
    posizione del primo pezzo, oppure -1."""
    posizione = 0
    inizio = -1
    for rx in sequenza:
        m = rx.search(testo, posizione)
        if m is None:
            return -1
        if inizio < 0:
            inizio = m.start()
        posizione = m.end()
    return inizio


# Comandi che pesano da soli quando compaiono in una riga di comando.
# Ogni regola: (alternative, peso, famiglia, descrizione); ogni alternativa e'
# una sequenza di espressioni che devono comparire in quell'ordine, oppure
# una funzione che riceve la riga e risponde vero o falso.
_COSA_SHADOW = u'cancellazione delle copie shadow o dei backup'
_COSA_CERTUTIL = u'download con certutil'
_COSA_DOWNLOAD = u'download o installazione da rete con uno strumento di Windows'
_COSA_INVIO = u'dati preparati o inviati verso l\'esterno (caricamento con curl, archivio RAR cifrato anche nei nomi)'
_COSA_LOG = u'cancellazione dei registri eventi da riga di comando'
_COSA_ATEXEC = u'firma di atexec: output in un file .tmp di 8 lettere in Windows\\Temp'
# (?<!help ): "Get-Help Clear-EventLog" e' una domanda, non una cancellazione
_RX_CANCELLA_LOG = _rx(u'wevtutil(\\.exe)?"?\\s+(cl|clear-log)\\b|(?<!help )(clear-eventlog|remove-eventlog)\\b'
                       u'|globalsession\\.clearlog\\(')
# gli argomenti di un comando: tra virgolette oppure fino allo spazio o alla virgola
_RX_ARGOMENTO = re.compile(u'"([^"]*)"|\'([^\']*)\'|([^\\s,"\']+)')
# piu' registri in un comando solo, o l'elenco di tutti i registri li' vicino
_RX_PIU_LOG = _rx(u'^[^|;&]{0,300},')
_RX_TUTTI_I_LOG = _rx(u'wevtutil(\\.exe)?"?\\s+(el|enum-logs)\\b|get-eventlog\\s+(-list\\b|-logname\\s+\\*|\\*)'
                      u'|get-winevent\\s+-listlog')
# "wbadmin delete ... -keepVersions:3" tiene gli ultimi backup: e' manutenzione
_RX_TIENE_VERSIONI = _rx(u'-keepversions:\\s*[1-9]')
# una copia shadow precisa (indicata con il suo ID) o solo la piu' vecchia: lo
# fanno i programmi di backup con la copia che hanno creato loro
_RX_SHADOW_PRECISA = _rx(u'/shadow\\s*=\\s*\\{?[0-9a-f]{8}-|\\bid\\s*(=|-eq)\\s*[\'"]{0,2}\\{?[0-9a-f]{8}-|/oldest\\b')


def _peso_cancella_log(riga):
    """Svuotare il registro Security, o piu' registri insieme, non ha
    spiegazioni innocenti; svuotarne uno solo (Application, il registro di un
    programma) lo fa anche chi sta provando un programma: come per gli eventi
    1102 e 104, da solo va confermato."""
    riga = riga or u''
    m = _RX_CANCELLA_LOG.search(riga)
    if m is None:
        return DA_CONFERMARE
    dopo = riga[m.end():m.end() + 300]
    # Conta il registro Security indicato per nome, non la parola dentro un
    # altro nome: "Microsoft-Windows-Windows Firewall With Advanced
    # Security/Firewall" e' il registro del firewall.
    comando = re.split(u'[|;&]', dopo, 1)[0]
    for a in _RX_ARGOMENTO.finditer(comando):
        nome = (a.group(1) or a.group(2) or a.group(3) or u'').strip().lower()
        if nome == u'security':
            return DECISIVO
    if _RX_PIU_LOG.search(dopo):
        return DECISIVO
    if _RX_TUTTI_I_LOG.search(riga[max(0, m.start() - 400):m.end() + 400]):
        return DECISIVO
    if _RX_CANCELLA_LOG.search(riga, m.end()) is not None:
        return DECISIVO
    return DA_CONFERMARE


_REG_ADD = _rx(u'(?<![a-z0-9_-])reg(\\.exe)?"?\\s+add\\s')
# I nomi (di servizio o di processo) degli antivirus piu' diffusi e del
# servizio dei registri eventi, per riconoscere chi li ferma o li disattiva
_NOMI_ANTIVIRUS = (
    u'windefend|msmpeng|mssense|(?<![a-z])sense(?![a-z])|wdnissvc|securityhealthservice|sophos|savservice|mcafee|mcshield'
    u'|symantec|sepmaster|ccsvchst|kaspersky|(?<![a-z])avp(?![a-z])|(?<![a-z])ekrn|crowdstrike|csfalcon|csagent'
    u'|sentinelone|sentinelagent|cylance|carbonblack|cbdefense|trend ?micro|ntrtscan|bitdefender|bdagent|malwarebytes'
    u'|mbamservice|avast|(?<![a-z])avg(?![a-z])|(?<![a-z\\\\/])webroot(?![a-z])|(?<![a-z])wrsvc|forticlient|cyserver')


def _fuori_virgolette(testo):
    """Il testo senza le parti tra virgolette (con \\" per le virgolette al
    loro interno): quello che resta sono le opzioni del comando, non i valori."""
    pezzi = []
    inizio = 0
    dentro = False
    p = testo.find(u'"')
    while p >= 0:
        if not dentro:
            pezzi.append(testo[inizio:p])
            dentro = True
        elif testo[p - 1] != u'\\':
            dentro = False
            inizio = p + 1
        p = testo.find(u'"', p + 1)
    if not dentro:
        pezzi.append(testo[inizio:])
    return u' '.join(pezzi)


_RX_SCHTASKS = _rx(u'schtasks(\\.exe)?"?(?=\\s)')
_RX_SCHTASKS_S = _rx(u'\\s/s\\s+\\S')


def _schtasks_remoto(riga):
    """Vero se la riga crea un'attivita' pianificata su un'altra macchina
    ("schtasks /create /s host ..."). Le opzioni contano solo fuori dalle
    virgolette: "/s" compare anche nei comandi che l'attivita' lancia
    (/tr "robocopy a b /s /e")."""
    m = _RX_SCHTASKS.search(riga)
    if m is None:
        return False
    opzioni = _fuori_virgolette(riga[m.end():m.end() + 4000]).lower()
    for separatore in u'&|':
        taglio = opzioni.find(separatore)
        if taglio >= 0:
            opzioni = opzioni[:taglio]
    return u'/create' in opzioni and _RX_SCHTASKS_S.search(opzioni) is not None


def _ferma(nomi):
    """Le forme con cui un servizio o un processo con uno di quei nomi viene
    fermato, tolto o disattivato: net stop, sc stop/delete, Stop-Service,
    taskkill, "sc config ... start= disabled", "Set-Service ... Disabled".
    Il nome deve stare nello stesso comando, a poca distanza dal verbo."""
    vicino = u'[^|&;\\n]{0,60}?(' + nomi + u')'
    return [(_rx(u'(?<![a-z0-9_-])(net1?(\\.exe)?"?\\s+stop|sc(\\.exe)?"?\\s+(\\\\\\\\\\S+\\s+)?(stop|delete)|stop-service'
                 u'|taskkill(\\.exe)?"?)\\s+' + vicino),),
            (_rx(u'(?<![a-z0-9_-])sc(\\.exe)?"?\\s+(\\\\\\\\\\S+\\s+)?config\\s+' + vicino + u'[^|&;\\n]{0,60}?start\\s*=\\s*disabled'),),
            (_rx(u'set-service\\s+' + vicino + u'[^|&;\\n]{0,60}?disabled'),)]


COMANDI = [
    ([(_rx(u'vssadmin(\\.exe)?"?\\s'), _rx(u'delete\\s+shadows')),
      (_rx(u'shadowcopy\\s+delete|wbadmin(\\.exe)?"?\\s+delete'),),
      # "wmic shadowcopy where ... delete", "Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }"
      (_rx(u'(?<![a-z])shadowcopy\\b'), _rx(u'\\bdelete\\b|remove-(wmiobject|ciminstance)')),
      # ridurre lo spazio delle copie a pochi MB le fa cancellare tutte;
      # fissarlo a una percentuale o a qualche GB e' manutenzione
      (_rx(u'resize\\s+shadowstorage'), _rx(u'/maxsize\\s*=\\s*\\d{1,4}\\s*mb'))],
     DA_CONFERMARE, F_ANTIFORENSE, _COSA_SHADOW),
    ([(_RX_CANCELLA_LOG,)], DECISIVO, F_ANTIFORENSE, _COSA_LOG),
    ([(_rx(u'bcdedit(\\.exe)?"?\\s'), _rx(u'recoveryenabled\\s+no|bootstatuspolicy\\s+ignoreallfailures'))],
     DA_CONFERMARE, F_ANTIFORENSE, u'ripristino di sistema disattivato'),
    ([(_rx(u'certutil(\\.exe)?"?\\s'), _rx(u'(-|/)(urlcache|verifyctl)\\b'), _rx(u'(https?|ftp)://'))],
     DA_CONFERMARE, F_ESECUZIONE, _COSA_CERTUTIL),
    ([(_rx(u'certutil(\\.exe)?"?\\s'), _rx(u'(-|/)(decode|decodehex|encode)\\b'))],
     DA_CONFERMARE, F_ESECUZIONE, u'certutil usato per codificare o decodificare un file'),
    ([(_rx(u'bitsadmin(\\.exe)?"?\\s'), _rx(u'/transfer\\b'), _rx(u'(https?|ftp)://')),
      (_rx(u'msiexec(\\.exe)?"?\\s'), _rx(u'(https?|ftp)://'))],
     DA_CONFERMARE, F_ESECUZIONE, _COSA_DOWNLOAD),
    ([(_rx(u'comsvcs(\\.dll)?[, ]+(minidump|#24)|sekurlsa::|lsadump::'),),
      (_rx(u'procdump(64)?(\\.exe)?"?\\s'), _rx(u'lsass'))],
     DECISIVO, F_STRUMENTI, u'estrazione di credenziali'),
    # passi che fanno anche gli amministratori (backup, preparazione di un
    # nuovo controller di dominio): da soli non bastano
    ([(_rx(u'reg(\\.exe)?"?\\s+save\\s+"?(hklm|hkey_local_machine)\\\\(sam|security|system)\\b'),),
      (_rx(u'ntdsutil'), _rx(u'\\b(ifm|snapshot)\\b')),
      (_rx(u'esentutl(\\.exe)?"?\\s'), _rx(u'ntds\\.dit')),
      (_rx(u'harddiskvolumeshadowcopy\\d*\\\\'), _rx(u'ntds\\.dit|\\\\config\\\\(sam|system|security)\\b'))],
     DA_CONFERMARE, F_STRUMENTI,
     u'copia del SAM, del registro SYSTEM o del database di Active Directory (passo tipico dell\'estrazione di '
     u'credenziali, ma anche di un backup)'),
    # la copia shadow la creano i backup; e' anche il primo passo per copiare
    # il database di Active Directory, ma il passo che conta e' la copia
    ([(_rx(u'vssadmin(\\.exe)?"?\\s'), _rx(u'create\\s+shadow')),
      (_rx(u'(?<![a-z])shadowcopy\\s+call\\s+create'),)],
     INFORMATIVO, F_STRUMENTI, u'creazione di una copia shadow da riga di comando'),
    ([(_rx(u'(?<![a-z0-9_-])net1?(\\.exe)?"?\\s+users?\\s'), _rx(u'/add\\b')),
      (_rx(u'(?<!help )new-localuser\\s'),)],
     DA_CONFERMARE, F_ACCOUNT, u'creazione di un account da riga di comando'),
    ([(_rx(u'(?<![a-z0-9_-])net1?(\\.exe)?"?\\s+(localgroup|group)\\s+"?(administrat\\w+|amministratori'
           u'|administradores|domain admins|remote desktop users|utenti desktop remoto)"?\\s'), _rx(u'/add\\b')),
      (_rx(u'(?<!help )add-localgroupmember\\s'),
       _rx(u'(administrat\\w+|amministratori|administradores|remote desktop users|utenti desktop remoto'
           u'|s-1-5-32-(544|555))'))],
     DA_CONFERMARE, F_ACCOUNT, u'utente aggiunto a un gruppo privilegiato da riga di comando'),
    ([(_rx(u'set-mppreference\\s'), _rx(u'-disable\\w+\\s+(\\$true|true|1)\\b')),
      (_rx(u'(set|add)-mppreference\\s'), _rx(u'-exclusion')),
      (_rx(u'netsh(\\.exe)?"?\\s+(advfirewall|firewall)\\s+set\\s+\\S+\\s+state\\s+off'),),
      (_rx(u'netsh(\\.exe)?"?\\s+firewall\\s+set\\s+opmode\\s+(mode\\s*=\\s*)?disable'),)],
     DA_CONFERMARE, F_ANTIFORENSE, u'protezioni disattivate da riga di comando'),
    ([(_rx(u'cipher(\\.exe)?"?\\s+/w|(?<![a-z])sdelete(64)?(\\.exe)?"?\\s|fsutil(\\.exe)?"?\\s+usn\\s+deletejournal'),)],
     DA_CONFERMARE, F_ANTIFORENSE, u'cancellazione sicura o del journal'),
    ([(_REG_ADD, _rx(u'\\\\wdigest\\b'), _rx(u'uselogoncredential'), _rx(u'/d\\s+"?(1|0x1)\\b')),
      (_REG_ADD, _rx(u'\\\\lsa\\b'), _rx(u'disablerestrictedadmin'), _rx(u'/d\\s+"?(0|0x0)\\b')),
      (_rx(u'findstr(\\.exe)?"?\\s'), _rx(u'cpassword')),
      (_rx(u'(?<![a-z0-9_-])reg(\\.exe)?"?\\s+query\\s'), _rx(u'/f\\s+"?passw'))],
     DA_CONFERMARE, F_STRUMENTI, u'preparazione al furto di credenziali (WDigest, Restricted Admin, ricerca di password)'),
    (_ferma(u'(?<![a-z0-9_-])eventlog\\b|windows event log|registro eventi di windows') + [
      (_rx(u'auditpol(\\.exe)?"?\\s'), _rx(u'/clear\\b|/remove\\b')),
      (_rx(u'auditpol(\\.exe)?"?\\s'), _rx(u'/category:\\s*"?\\*'), _rx(u':\\s*disable')),
      (_rx(u'wevtutil(\\.exe)?"?\\s+(sl|set-log)\\s'), _rx(u'/e(nabled)?:\\s*false')),
      (_rx(u'(remove-item|clear-content|(?<![a-z0-9_-])(del|erase|rm))\\s[^|&;\\n]{0,200}?(historysavepath|consolehost_history)'),),
      (_rx(u'set-psreadlineoption\\s'), _rx(u'savenothing'))],
     DA_CONFERMARE, F_ANTIFORENSE,
     u'registrazione delle tracce disattivata (servizio dei registri eventi, audit, cronologia di PowerShell)'),
    (_ferma(_NOMI_ANTIVIRUS) + [
      (_rx(u'mpcmdrun(\\.exe)?"?\\s'), _rx(u'-removedefinitions')),
      (_REG_ADD, _rx(u'windows defender|microsoft antimalware'), _rx(u'disable\\w+'), _rx(u'/d\\s+"?(1|0x1)\\b'))],
     DA_CONFERMARE, F_ANTIFORENSE, u'antivirus fermato o disattivato da riga di comando'),
    ([(_rx(u'wmic(\\.exe)?"?\\s'), _rx(u'/node:'), _rx(u'process\\s+call\\s+create')),
      (_rx(u'(?<![a-z0-9_-])sc(\\.exe)?"?\\s+\\\\\\\\[^\\s\\\\]+\\s+(create|config)\\s'), _rx(u'binpath\\s*=')),
      _schtasks_remoto,
      (_rx(u'(?<![a-z0-9_-])(copy|xcopy|move|robocopy)(\\.exe)?\\s'),
       _rx(u'\\\\\\\\(?!127\\.0\\.0\\.1\\\\|localhost\\\\)[^\\s\\\\"]+\\\\(admin\\$|c\\$\\\\(windows|programdata|perflogs|users\\\\public|temp)\\b)'))],
     DA_CONFERMARE, F_LATERALE,
     u'esecuzione o copia verso un\'altra macchina (wmic /node, sc o schtasks remoti, condivisione amministrativa)'),
    ([(_rx(u'netsh(\\.exe)?"?\\s'), _rx(u'portproxy\\s+add\\b')),
      (_rx(u'(?<![a-z0-9_-])ssh(\\.exe)?"?(?=\\s)'), _rx(u'\\s-R\\s*\\S'))],
     DA_CONFERMARE, F_ESFILTRAZIONE, u'tunnel verso l\'esterno (inoltro di porta con netsh, ssh -R)'),
    ([(_rx(u'curl(\\.exe)?"?(?=\\s)'), _rx(u'\\s-T\\s|--upload-file\\s|\\s(-F|--form)\\s+\\S*=@|--data-binary\\s+"?@')),
      (_rx(u'(?<![a-z0-9_-])(win)?rar(\\.exe)?"?\\s+a(?=\\s)'), _rx(u'\\s-hp\\S'))],
     DA_CONFERMARE, F_ESFILTRAZIONE, _COSA_INVIO),
    ([(_REG_ADD, _rx(u'terminal server'), _rx(u'fdenytsconnections'), _rx(u'/d\\s+"?(0|0x0)\\b')),
      (_rx(u'set-itemproperty\\s'), _rx(u'fdenytsconnections["\']?\\s+(-value\\s+)?["\']?0\\b'))],
     DA_CONFERMARE, F_ACCESSI, u'Desktop remoto abilitato da riga di comando'),
    ([(_REG_ADD, _rx(u'specialaccounts\\\\userlist'))],
     DA_CONFERMARE, F_ACCOUNT, u'account nascosto dalla schermata di accesso'),
    ([(_REG_ADD, _rx(u'image file execution options\\\\(sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\\.exe'),
       _rx(u'debugger')),
      (_rx(u'(?<![a-z0-9_-])(copy|xcopy|move)\\s'), _rx(u'(cmd|powershell)\\.exe'),
       _rx(u'\\\\(sethc|utilman|osk|narrator|magnify|displayswitch)\\.exe'))],
     DECISIVO, F_PERSISTENZA, u'porta di servizio sulla schermata di accesso (\u00absticky keys\u00bb)'),
    ([(_rx(u'installutil(\\.exe)?"?\\s'), _rx(u'logtoconsole\\s*=\\s*false')),
      (_rx(u'odbcconf(\\.exe)?"?\\s'), _rx(u'\\bregsvr\\s')),
      (_rx(u'cmstp(\\.exe)?"?\\s'), _rx(u'/ni\\b'), _rx(u'/s\\b')),
      (_rx(u'cmstp(\\.exe)?"?\\s'), _rx(u'/s\\b'), _rx(u'/ni\\b')),
      (_rx(u'mavinject(64)?(\\.exe)?"?\\s'), _rx(u'/injectrunning\\b'))],
     DA_CONFERMARE, F_ESECUZIONE,
     u'programma di Windows usato per far eseguire codice altrui (InstallUtil, odbcconf, cmstp, mavinject)'),
    ([(_rx(u'setspn(\\.exe)?"?\\s'), _rx(u'-q\\s+"?\\*/\\*'))],
     DA_CONFERMARE, F_ESECUZIONE, u'elenco di tutti gli SPN del dominio (ricognizione per il Kerberoasting)'),
    # nei registri eventi il segno % compare raddoppiato (%%windir%%)
    ([(_rx(u'cmd(\\.exe)?"?\\s+/c\\s'),
       _rx(u'>\\s*%{0,2}(windir%{0,2}|systemroot%{0,2}|c:\\\\windows)\\\\temp\\\\[A-Za-z]{8}\\.tmp\\s+2>&1'))],
     DECISIVO, F_LATERALE, _COSA_ATEXEC),
    ([(_rx(u'cmd(\\.exe)?"?\\s+/q\\s+/c\\s'), _rx(u'\\\\\\\\127\\.0\\.0\\.1\\\\(admin|c)\\$\\\\__'))],
     DECISIVO, F_LATERALE, u'firma di Impacket: output ridiretto su \\\\127.0.0.1'),
]


def comandi_noti(riga):
    """Comandi che pesano da soli: lista di (peso, famiglia, descrizione)."""
    trovati = []
    if not riga:
        return trovati
    riga = senza_offuscamento(riga[:MAX_RIGA])[0]
    for alternative, peso, famiglia, cosa in COMANDI:
        for sequenza in alternative:
            # un'alternativa e' una sequenza di espressioni oppure una funzione che giudica la riga
            if (sequenza(riga) if callable(sequenza) else _in_sequenza(sequenza, riga) >= 0):
                if cosa is _COSA_ATEXEC:
                    # atexec da' al file un nome di 8 lettere a caso: "filelist.tmp" non lo e'
                    m = _RX_TMP_ATEXEC.search(riga)
                    if m is None or not nome_casuale(m.group(1)):
                        peso = DA_CONFERMARE
                        cosa = (u'output ridiretto in un file .tmp di 8 lettere in Windows\\Temp: lo fa atexec, '
                                u'ma qui il nome non sembra casuale')
                elif cosa is _COSA_LOG:
                    peso = _peso_cancella_log(riga)
                    if peso < DECISIVO:
                        cosa = u'cancellazione di uno dei registri eventi da riga di comando (non quello di sicurezza)'
                elif cosa is _COSA_SHADOW and _RX_TIENE_VERSIONI.search(riga) \
                        and u'vssadmin' not in riga.lower() and u'shadowcopy' not in riga.lower():
                    break       # pulizia dei backup vecchi: non e' una cancellazione
                elif cosa is _COSA_SHADOW and _RX_SHADOW_PRECISA.search(riga) and u'/all' not in riga.lower():
                    break       # una copia precisa, non tutte: il backup che toglie la sua
                elif cosa is _COSA_CERTUTIL:
                    indirizzi = [m.group(0) for m in _RX_URL.finditer(riga)]
                    if indirizzi and not [u for u in indirizzi
                                          if not _fine_percorso(u).endswith(_SUFFISSI_CERTIFICATO)]:
                        break   # aggiorna un certificato o una lista di revoca: e' il suo mestiere
                    if solo_da_produttori(riga):
                        break
                elif cosa is _COSA_DOWNLOAD and solo_da_produttori(riga):
                    break       # un pacchetto preso dal sito del produttore
                elif cosa is _COSA_INVIO and u'curl' in riga.lower():
                    nomi = _host_degli_indirizzi(riga)
                    if nomi and not [n for n in nomi if not host_interno(n)]:
                        break   # il file va a un server della rete interna
                trovati.append((peso, famiglia, cosa))
                break
    return trovati


_RX_TMP_ATEXEC = re.compile(u'\\\\temp\\\\([A-Za-z]{8})\\.tmp\\s+2>&1', re.I)


_RX_SMBEXEC = re.compile(u'(__output|\\\\\\\\127\\.0\\.0\\.1\\\\(c|admin)\\$)', re.I)
_RX_EXECUTE_BAT = re.compile(u'(%temp%|\\\\temp)\\\\execute\\.bat\\b', re.I)
_RX_BAT8 = re.compile(u'(%systemroot%|%windir%|c:\\\\windows)\\\\([A-Za-z]{8})\\.bat\\b', re.I)
_RX_EXE8_WIN = re.compile(u'^"?(%systemroot%|%windir%|c:\\\\windows)\\\\([A-Za-z]{8})\\.exe"?\\s*$', re.I)


def firma_smbexec(nome_servizio, percorso):
    """Riconosce le firme di smbexec in un servizio. Restituisce (peso,
    descrizione) oppure None. Sono decisive solo le firme che un programma
    normale non produce: il nome BTOBTO, l'output su __output o su
    \\\\127.0.0.1, un batch dal nome casuale. Un batch che si chiama
    execute.bat, o con un nome di 8 lettere qualunque ("shutdown.bat"), da
    solo e' da confermare."""
    p = percorso or u''
    basso = p.lower()
    if (nome_servizio or u'').upper() == u'BTOBTO':
        return DECISIVO, u'nome di servizio BTOBTO (smbexec fino a maggio 2023)'
    m = _RX_SMBEXEC.search(p)
    if m is not None:
        return DECISIVO, u'il servizio contiene \u00ab%s\u00bb (firma di smbexec)' % m.group(1)
    con_cmd = u'comspec' in basso or u'cmd' in basso
    if con_cmd and _RX_EXECUTE_BAT.search(p):
        return DA_CONFERMARE, u'il servizio lancia execute.bat dalla cartella temporanea (come smbexec fino al 2023)'
    m = _RX_BAT8.search(p)
    if m is not None and con_cmd:
        if nome_casuale(m.group(2)):
            return DECISIVO, u'il servizio lancia un batch con nome di 8 lettere a caso in C:\\Windows (smbexec dal 2023)'
        return DA_CONFERMARE, u'il servizio lancia un batch in C:\\Windows tramite cmd'
    return None


def eseguibile_casuale_in_windows(percorso):
    """Vero se il percorso e' un .exe con nome di 8 lettere a caso nella
    cartella Windows: cosi' psexec.py di Impacket e Metasploit caricano il
    loro servizio."""
    m = _RX_EXE8_WIN.match(percorso or u'')
    return m is not None and nome_casuale(m.group(2))


# Frammenti di nome usati per cercare sul disco gli strumenti noti
FRAMMENTI_STRUMENTI = [
    u'mimikatz', u'mimilib', u'mimidrv', u'rubeus', u'sharphound', u'bloodhound', u'lazagne', u'winpeas',
    u'safetykatz', u'nanodump', u'pypykatz', u'secretsdump', u'crackmapexec', u'cobaltstrike', u'meterpreter',
    u'juicypotato', u'roguepotato', u'printspoofer', u'godpotato', u'sweetpotato', u'badpotato', u'kerbrute',
    u'ligolo', u'powercat', u'powerview', u'powersploit', u'psexec', u'psexesvc', u'paexec', u'remcom', u'adfind',
    u'netscan', u'advanced_ip_scanner', u'advanced ip scanner', u'ipscan', u'nmap', u'masscan', u'rclone',
    u'megasync', u'ngrok', u'cloudflared', u'procdump', u'sdelete', u'processhacker', u'pchunter', u'chisel',
    u'seatbelt', u'sharpup', u'kekeo', u'certipy', u'inveigh', u'plink', u'ncat', u'netcat', u'nc.exe', u'nc64',
    u'wce.exe', u'pwdump', u'fgdump', u'gsecdump', u'dumpert', u'backstab', u'defendercontrol', u'dcontrol',
    u'pingcastle', u'adrecon']


def frammenti_rmm():
    """Tutti i frammenti di nome degli strumenti RMM."""
    tutti = []
    for _, frammenti in RMM:
        for f in frammenti:
            if f not in tutti:
                tutti.append(f)
    return tutti


# Testo sospetto in PowerShell (blocchi di script 4104, cronologia della console)
_RX_PS_ATTACCO = re.compile(
    u'(invoke-mimikatz|invoke-kerberoast|invoke-bloodhound|invoke-sharphound|invoke-shellcode'
    u'|invoke-reflectivepeinjection|invoke-dllinjection|invoke-tokenmanipulation|invoke-credentialinjection'
    u'|invoke-wmiexec|invoke-smbexec|invoke-psexec|invoke-thehash|get-gpppassword|get-keystrokes'
    u'|invoke-ninjacopy|out-minidump|invoke-powershelltcp|invoke-empire|powersploit|nishang'
    u'|amsiutils|amsiinitfailed|amsiscanbuffer|sekurlsa|invoke-rubeus|invoke-seatbelt|wmibackdoor'
    u'|invoke-dcsync|invoke-smbclient|invoke-inveigh|powercat|invoke-bypassuac|invoke-psinject'
    u'|invoke-allchecks|invoke-privesccheck|minidumpwritedump)', re.I)
# le parole che devono esserci perche' una riga nomini uno strumento (vedi strumento_nominato)
_SPIE_NOMINATI = _spie(_RX_ATTACCO, _RX_PS_ATTACCO, _RX_DOPPIO_USO)
_PS_DIFESE = [(_rx(u'set-mppreference\\s'), _rx(u'-disable\\w+\\s+(\\$true|1)')),
              (_rx(u'add-mppreference\\s'), _rx(u'-exclusion')),
              (_rx(u'disable(realtimemonitoring|antispyware|behaviormonitoring|ioavprotection|scriptscanning)'
                   u'["\'\\s,=:]{1,8}(-value\\s+|/d\\s+)?["\']?(1|\\$true|true)\\b'),),
              (_rx(u'uninstall-windowsfeature'), _rx(u'defender'))]
_COSA_DIFESE = u'modifica le protezioni di Defender'
_COSA_SCRIPT = u'script d\'attacco'
# stager: codice compresso e codificato, decompresso in memoria ed eseguito
# (lo schema di Cobalt Strike, Metasploit, Empire)
_RX_PS_BASE64 = re.compile(u'frombase64string', re.I)
_RX_PS_COMPRESSO = re.compile(u'(gzipstream|deflatestream)', re.I)
_RX_PS_ESEGUE = re.compile(u'(\\biex\\b|invoke-expression|scriptblock\\]::create|reflection\\.assembly\\]::load'
                           u'|\\.invoke\\(|virtualalloc|createthread)', re.I)
_RX_PS_CULLA = re.compile(u'(downloadstring|downloadfile|downloaddata|invoke-webrequest|\\biwr\\b|net\\.webclient'
                          u'|invoke-restmethod|\\birm\\b|start-bitstransfer|\\bcurl\\b|\\bwget\\b)', re.I)
_RX_PS_IEX = re.compile(u'(\\biex\\b|invoke-expression|frombase64string)', re.I)


_RX_PS_SOCKET = re.compile(u'net\\.sockets\\.tcpclient', re.I)
_RX_PS_FLUSSO = re.compile(u'getstream\\s*\\(', re.I)
_RX_PS_ESEGUE_RICEVUTO = re.compile(u'(\\biex\\b|invoke-expression|redirectstandardinput)', re.I)


def _ps_certo(testo):
    """Gli schemi di PowerShell che non hanno una spiegazione innocente:
    (descrizione, posizione) oppure None."""
    m = _RX_PS_BASE64.search(testo)
    if m is not None and _RX_PS_COMPRESSO.search(testo) and _RX_PS_ESEGUE.search(testo):
        return u'codice compresso e codificato, decompresso in memoria ed eseguito (stager)', m.start()
    m = _RX_PS_SOCKET.search(testo)
    if m is not None and _RX_PS_FLUSSO.search(testo) and _RX_PS_ESEGUE_RICEVUTO.search(testo):
        return u'shell remota: riceve i comandi da una connessione TCP e li esegue (reverse shell)', m.start()
    return None


def ps_sospetto(testo, breve=True, culla=True):
    """Giudica un testo di PowerShell. Restituisce (peso, motivo, posizione
    del riscontro) oppure None. Con breve=True la regola 'scarica ed esegue'
    vale solo per testi corti, dove non e' una libreria; con culla=False non
    viene applicata affatto (pezzi di uno script lungo)."""
    if not testo:
        return None
    m = _RX_PS_ATTACCO.search(testo)
    if m is not None:
        return DECISIVO, u'%s (%s)' % (_COSA_SCRIPT, m.group(1)), m.start()
    schema = _ps_certo(testo)
    if schema is not None:
        return DECISIVO, schema[0], schema[1]
    for sequenza in _PS_DIFESE:
        posizione = _in_sequenza(sequenza, testo)
        if posizione >= 0:
            return DA_CONFERMARE, _COSA_DIFESE, posizione
    if culla and (not breve or len(testo) < 6000):
        m = _RX_PS_CULLA.search(testo)
        if m is not None and _RX_PS_IEX.search(testo):
            if solo_download_noti(testo):
                return INFORMATIVO, u'scarica ed esegue uno script di installazione noto', m.start()
            return DA_CONFERMARE, u'scarica ed esegue codice', m.start()
    return None


# Quello che un comando di PowerShell deve fare per non essere "di sola
# lettura": avviare programmi, caricare codice, usare la rete, scrivere o
# cancellare file, toccare registro, servizi, attivita', account o protezioni.
_RX_PS_AGISCE = re.compile(
    u'(start-process|invoke-item|invoke-command|invoke-wmimethod|invoke-cimmethod|win32_process|(\\.|::)start\\(|shellexecute'
    u'|wscript\\.shell|-comobject|add-type|dllimport|virtualalloc|marshal\\]|\\[ref\\]|reflection|scriptblock|createinstance'
    u'|&\\s*[$(]|comspec|io\\.file\\]|writeall|\\.delete\\(|\\.copyto\\('
    u'|nltest|dsquery|adsisearcher|directorysearcher|(?<![a-z])get-ad[a-z]{4,}|(?<![a-z])get-domain[a-z]{4,}'
    u'|new-service|set-service|stop-service|register-scheduledtask|new-scheduledtask|schtasks'
    u'|new-item|new-itemproperty|set-itemproperty|remove-itemproperty|(?<![a-z0-9_-])reg(\\.exe)?\\s+(add|delete|save|import)'
    u'|(?<![a-z0-9_-])sc(\\.exe)?\\s+(create|config|delete|stop)|new-localuser|add-localgroupmember'
    u'|(?<![a-z0-9_-])net1?(\\.exe)?\\s+(user|localgroup|group|use|stop|share)'
    u'|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|(?<![a-z0-9_-])cmd(\\.exe)?(?![a-z0-9_-])|msiexec|wmic'
    u'|installutil|msbuild|mppreference|wevtutil|clear-eventlog|vssadmin|bcdedit|remove-item|(?<![a-z0-9_-])(del|erase|rd|rmdir)\\s'
    u'|out-file|set-content|add-content|copy-item|move-item|rename-item|expand-archive|compress-archive'
    u'|pssession|get-credential|securestring|net\\.sockets|webclient|webrequest|restmethod|bitstransfer|\\.connect\\('
    u'|taskkill|stop-process|set-executionpolicy|import-module|\\.ps1|\\.exe|\\.dll|\\.bat|\\.vbs)', re.I)


def codice_che_agisce(testo):
    """Vero se il testo di PowerShell fa qualcosa di piu' che leggere
    informazioni e mostrarle. Nel dubbio risponde di si'."""
    if not testo or len(testo) > 20000:
        return True
    if _RX_PS_AGISCE.search(testo) or _RX_ESEGUE_CODICE.search(testo) or _RX_VERBO_DOWNLOAD.search(testo) \
            or _RX_URL.search(testo) or _RX_SCRIVIBILE.search(testo) or _RX_NASCOSTO.search(testo) \
            or _RX_ENC.search(u' ' + testo):
        return True
    if comandi_noti(testo) or strumento_nominato(testo)[0]:
        return True
    return False


def riga_di_console(riga):
    """Giudica una riga scritta in una console di PowerShell (cronologia di
    PSReadLine, blocco di script breve): mette insieme le regole sul testo di
    PowerShell, i comandi che pesano da soli, gli strumenti nominati e la
    valutazione della riga di comando. Restituisce (peso, famiglia, motivo,
    comando in chiaro se era codificato) oppure None.

    Una riga scritta in console e' un comando eseguito: il livello 3 di
    valuta_comando e' decisivo solo se il motivo e' certo (chi installa
    programmi scrive spesso "irm ... | iex")."""
    trovato = None
    chiaro = u''
    # chi indaga cerca gli strumenti per nome: quella non e' un'esecuzione
    cercato = solo_cercato(riga)
    g = ps_sospetto(riga, breve=False)
    if g is not None:
        if cercato and g[1].startswith(_COSA_SCRIPT):
            trovato = (INFORMATIVO, F_STRUMENTI, u'cerca per nome uno ' + g[1])
        else:
            trovato = (g[0], F_STRUMENTI if g[0] == DECISIVO else F_ESECUZIONE, g[1])
    for peso, famiglia, cosa in comandi_noti(riga):
        if trovato is None or peso > trovato[0]:
            trovato = (peso, famiglia, cosa)
    # uno strumento noto lanciato o nominato nella riga (".\\Rubeus.exe kerberoast", "nc -e cmd ...")
    peso, cosa = strumento_nominato(riga, True)
    if peso >= DECISIVO and cercato:
        peso, cosa = INFORMATIVO, u'cerca per nome uno ' + cosa
    if peso and (trovato is None or peso > trovato[0]):
        trovato = (peso, F_STRUMENTI if peso == DECISIVO else (F_DOPPIO_USO if peso == DA_CONFERMARE else F_STRUMENTI), cosa)
    if trovato is None or trovato[0] < DECISIVO:
        v = valuta_comando(riga, persistenza=False)
        if (v.livello >= 3 or v.avvio) and (v.certo or trovato is None):
            trovato = (DECISIVO if v.certo else DA_CONFERMARE, F_ESECUZIONE, v.motivo())
            chiaro = v.decodificato
    if trovato is None:
        return None
    return trovato[0], trovato[1], trovato[2], chiaro


# --------------------------------------------------------------------------
# Nomi casuali, indirizzi IP
# --------------------------------------------------------------------------

_RX_OTTO_LETTERE = re.compile(u'^[A-Za-z]{8}$')
_SERVIZI_NOTI_8 = set([u'ajrouter', u'wdnissvc', u'wmiprvse', u'vboxsds', u'mozillam'])
# Parole (di almeno 4 lettere) che compaiono nei nomi veri di attivita',
# servizi e file: "GPUpdate", "DBBackup" e "PowerISO" hanno le maiuscole e le
# minuscole mescolate come un nome a caso, ma contengono una parola. Otto
# lettere a caso ne contengono una per sbaglio meno di una volta su 300.
_PAROLE_NEI_NOMI = (
    u'update', u'backup', u'export', u'import', u'sync', u'daily', u'weekly', u'month', u'hour', u'power',
    u'adobe', u'admin', u'check', u'clean', u'start', u'setup', u'install', u'deploy', u'script', u'report',
    u'agent', u'monit', u'logon', u'logoff', u'login', u'patch', u'scan', u'task', u'serv', u'client', u'system',
    u'window', u'office', u'google', u'chrome', u'mozilla', u'firefox', u'edge', u'driver', u'intel', u'nvidia',
    u'realtek', u'dell', u'lenovo', u'asus', u'acer', u'apple', u'java', u'oracle', u'mysql', u'data', u'mail',
    u'exchange', u'share', u'print', u'network', u'remote', u'desktop', u'secur', u'defend', u'virus', u'cache',
    u'temp', u'test', u'user', u'group', u'policy', u'domain', u'time', u'date', u'file', u'disk', u'drive',
    u'cloud', u'drop', u'team', u'zoom', u'skype', u'steam', u'game', u'audio', u'video', u'media', u'play',
    u'read', u'write', u'host', u'help', u'manage', u'launch', u'load', u'notif', u'alert', u'health', u'status',
    u'info', u'config', u'setting', u'restore', u'recover', u'archiv', u'copy', u'move', u'delete', u'purge',
    u'rotate', u'trim', u'index', u'search', u'store', u'shop', u'licen', u'activ', u'regist', u'tool', u'util',
    u'core', u'main', u'base', u'node', u'python', u'shell', u'batch', u'cron', u'queue', u'send', u'upload',
    u'download', u'fetch', u'pull', u'push', u'build', u'debug', u'trace', u'event', u'audit', u'track', u'count',
    u'stat', u'usage', u'quota', u'limit', u'lock', u'cert', u'token', u'auth', u'pass', u'proxy', u'gate',
    u'wall', u'fire', u'wifi', u'blue', u'mouse', u'touch', u'screen', u'display', u'color', u'font', u'theme',
    u'paper', u'save', u'open', u'close', u'reset', u'boot', u'shut', u'sleep', u'wake', u'batt', u'plan',
    u'sched', u'maint', u'repair', u'fix', u'diag', u'perf', u'log', u'wsus', u'sccm', u'azure', u'micro',
    u'soft', u'ware', u'sql', u'web', u'app', u'net', u'svc', u'job', u'run',
    # italiano
    u'aggiorn', u'copia', u'salva', u'puli', u'avvi', u'controll', u'verific', u'giorn', u'settiman', u'mensil',
    u'rete', u'stampa', u'utent', u'posta', u'invi', u'scaric', u'caric', u'ripristin', u'chiud', u'apri')
_PAROLE_LUNGHE = tuple([p for p in _PAROLE_NEI_NOMI if len(p) >= 4])


def nome_casuale(nome):
    """Vero se il nome sembra fatto di 8 lettere a caso con maiuscole e
    minuscole mescolate: e' cosi' che Impacket chiama servizi e attivita'."""
    if not nome or _RX_OTTO_LETTERE.match(nome) is None:
        return False
    basso = nome.lower()
    if basso in _SERVIZI_NOTI_8:
        return False
    for parola in _PAROLE_LUNGHE:
        if parola in basso:
            return False
    maiuscole_interne = len([c for c in nome[1:] if c.isupper()])
    minuscole = len([c for c in nome if c.islower()])
    return maiuscole_interne >= 2 and minuscole >= 2


_RX_IPV4 = re.compile(u'^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$')


def ip_pubblico(indirizzo):
    """Vero se l'indirizzo IPv4 e' instradabile su Internet (non privato,
    non locale). Falso per i testi che non sono indirizzi e per gli
    indirizzi IPv6: quelli globali si usano anche dentro le reti locali, e
    dall'indirizzo soltanto non si capisce se arriva da fuori."""
    if not indirizzo:
        return False
    s = indirizzo.strip().lower()
    if s.startswith(u'::ffff:'):
        s = s[7:]
    m = _RX_IPV4.match(s)
    if m is not None:
        a, b, c, d = [int(x) for x in m.groups()]
        if a > 255 or b > 255 or c > 255 or d > 255:
            return False
        if a in (0, 10, 127) or a >= 224:
            return False
        if a == 172 and 16 <= b <= 31:
            return False
        if a == 192 and b == 168:
            return False
        if a == 169 and b == 254:
            return False
        if a == 100 and 64 <= b <= 127:
            return False
        return True
    return False


_RX_HOST_ATTACCO = re.compile(u'^(kali|parrot|blackarch|backbox|pentest[\\w-]*|commando[\\w-]*)$', re.I)


def host_di_attacco(nome):
    """Vero se il nome di computer e' quello predefinito di una
    distribuzione usata per gli attacchi (Kali, Parrot...)."""
    return bool(nome) and _RX_HOST_ATTACCO.match(nome.strip()) is not None


def indirizzo_valido(indirizzo):
    """Vero se il testo e' un indirizzo di rete utile (non '-', non locale)."""
    if not indirizzo:
        return False
    s = indirizzo.strip().lower()
    return s not in (u'-', u'', u'local', u'::1', u'127.0.0.1', u'0.0.0.0', u'localhost')


# --------------------------------------------------------------------------
# Antivirus
# --------------------------------------------------------------------------

_RX_MINACCIA_ATTACCO = re.compile(
    u'(mimikatz|mikatz|katz(?![a-z])|cobalt|beacon|meterpreter|metasploit|swrort|rozena|powercat|netcat|bloodhound'
    u'|sharphound|sharpdump|sharpup|sharpwmi|sharpview|sharpdpapi|sharpchrome|sharpexec|sharprdp|seatbelt'
    u'|rubeus|lazagne|kekeo|dumplsass|lsassdump|nanodump|dumpert|gsecdump|fgdump|credential'
    u'|accessibilityescalation|powersploit|powerview|chisel|ligolo|htran|inveigh'
    u'|bruteratel|impacket|wmiexec|smbexec|psexec|remoteexec|reverseshell|webshell|chopper|jsprat|aspxspy'
    u'|antsword|behinder'
    u'|shellcode|kerberoast|ntdsdump|secretsdump|potato|printnightmare|zerologon|petitpotam'
    u'|hashdump|pwdump|ceprolad|dcsync|goldenticket|silverticket|nishang|covenant|koadic|poshc2|qakbot'
    u'|emotet|trickbot|icedid|bumblebee|lockbit|blackcat|crackmapexec'
    # nomi corti: valgono solo come nome intero ("Clop", non "Cyclops"; "Conti", non "Continue")
    u'|(?<![a-z])(?:empire|sliver|havoc|merlin|wce|qbot|ryuk|conti|akira|royal|clop)(?![a-z]))', re.I)
# categorie del nome ("Categoria:Piattaforma/Famiglia"). HackTool e VirTool
# da sole non bastano: Defender chiama HackTool anche i recuperatori di
# password di NirSoft, gli attivatori KMS e i trucchi per i giochi.
_CATEGORIE_GRAVI = (u'backdoor', u'ransom')
_CATEGORIE_LIEVI = (u'pua', u'puabundler', u'puadlmanager', u'adware', u'program', u'joke', u'misleading',
                    u'softwarebundler', u'browsermodifier', u'unwanted', u'app', u'potentiallyunwanted', u'tool')
_RX_MINACCIA_LIEVE = re.compile(
    u'(keygen|autokms|kmsauto|kmspico|(?<![a-z])kms|activator|wpakill|patcher|crack|eicar|toolbar|bundler'
    u'|productkey|produkey|nircmd|gamehack|cheat|trainer)', re.I)


def peso_minaccia(nome):
    """Peso di un nome di minaccia rilevata dall'antivirus: decisivo per gli
    strumenti d'attacco riconosciuti dal nome e per backdoor e ransomware;
    informativo per i programmi indesiderati, i crack, gli attivatori e il
    file di prova EICAR; da confermare per tutto il resto (compresi gli
    HackTool generici e gli exploit bloccati in un documento ricevuto, che da
    soli non provano una compromissione)."""
    if not nome:
        return INFORMATIVO
    basso = nome.lower()
    categoria = basso.split(u':', 1)[0] if u':' in basso else u''
    if categoria in _CATEGORIE_LIEVI or u'eicar' in basso:
        return INFORMATIVO
    if _RX_MINACCIA_ATTACCO.search(basso):
        return DECISIVO
    if _RX_MINACCIA_LIEVE.search(basso):
        return INFORMATIVO
    if categoria in _CATEGORIE_GRAVI:
        return DECISIVO
    return DA_CONFERMARE
