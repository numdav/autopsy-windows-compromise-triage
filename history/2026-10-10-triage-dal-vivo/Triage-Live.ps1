#Requires -Version 5.1
<#
    Triage compromissione Windows - raccolta dal vivo
    =================================================
    Esegue sul posto, su una macchina Windows ACCESA, i 41 controlli della
    checklist di triage. Per ogni controllo salva l'output grezzo fuori dalla
    macchina e, dove la regola e' automatizzabile, emette un segnale con il suo
    peso e la sua famiglia. Alla fine da' un verdetto con la stessa logica del
    plugin per Autopsy (Windows Compromise Triage): un solo segnale decisivo, o
    segnali da confermare in due famiglie diverse, bastano per "compromissione
    probabile".

    NON sostituisce l'analisi: serve a decidere in fretta se approfondire. Ogni
    segnale vale solo finche' l'IT non lo spiega.

    Come il plugin, i segnali che il programma automatizza sono una parte della
    checklist: gli allarmi che richiedono la conoscenza dell'ambiente (un
    account "fuori convenzione", un host "inatteso") restano da leggere a mano
    negli output salvati. Il programma lo dice nel riepilogo.

    Impronta sulla macchina
    -----------------------
    Il triage si fa a macchina accesa e ogni comando modifica il sistema. Lo
    script limita il danno ma non lo annulla:
      - lavora dalla riga di comando (niente Esplora risorse, niente avvii da
        GUI), in sola lettura sugli artefatti;
      - salva tutto nella cartella del caso, che deve stare su un'unita'
        esterna, non sul disco sospetto;
      - copia il Prefetch per primo, prima che altri comandi lo cambino;
      - registra ogni cosa con Start-Transcript.
    Se devi isolare la macchina, scollega la rete, non la corrente: lo
    spegnimento cancella BAM, ShimCache, cache DNS, sessioni e memoria.
    Se puoi, acquisisci PRIMA la RAM con lo strumento della tua procedura: solo
    l'analisi della memoria vede cio' che un rootkit nasconde.

    Uso
    ---
    Apri Windows PowerShell COME AMMINISTRATORE e lancia:

        .\Triage-Live.ps1 -CartellaCaso E:\caso

    Parametri:
      -CartellaCaso     dove salvare tutto (default E:\caso). Mettila su
                        un'unita' esterna.
      -GiorniEventi     ampiezza della finestra per gli eventi (default 14).
      -GiorniRecenti    quanti giorni considerare "recenti" per file, account e
                        attivita' (default 30).
      -RmmAutorizzati   nomi di strumenti di accesso remoto autorizzati su
                        questa macchina, separati da virgola (es.
                        "TeamViewer, AnyDesk"): restano nel report come
                        contesto ma non diventano decisivi.
      -SenzaPreservare  non copiare alla fine registri eventi e hive (li copi
                        tu con KAPE o simili).
      -SenzaConferma    non chiedere conferma prima di iniziare (per esecuzioni
                        non presidiate).

    Provato nella sintassi e nella logica del verdetto con PowerShell 7 su
    Linux; NON e' stato eseguito su un Windows reale. Provalo prima su una
    macchina di test.

    Licenza Apache 2.0. Fornito "cosi' com'e'", senza garanzie.
#>

[CmdletBinding()]
param(
    [string]$CartellaCaso = 'E:\caso',
    [int]$GiorniEventi = 14,
    [int]$GiorniRecenti = 30,
    [string]$RmmAutorizzati = '',
    [switch]$SenzaPreservare,
    [switch]$SenzaConferma,
    # Uso interno: carica solo le funzioni (per le prove), senza raccogliere nulla.
    [switch]$CaricaSoloFunzioni
)

# ==========================================================================
#  Costanti: pesi e famiglie, identici al plugin
# ==========================================================================
$DECISIVO = 3        # basta da solo per trattare la macchina come compromessa
$DACONF   = 2        # conta se almeno due famiglie diverse lo segnalano
$INFO     = 1        # solo contesto

$F_ACCESSI       = "Accessi"
$F_ACCOUNT       = "Account"
$F_PERSISTENZA   = "Persistenza"
$F_ESECUZIONE    = "Programmi eseguiti"
$F_STRUMENTI     = "Strumenti d'attacco"
$F_DOPPIO_USO    = "Strumenti a doppio uso"
$F_LATERALE      = "Esecuzione remota"
$F_RMM           = "Accesso remoto (RMM)"
$F_FILE          = "File"
$F_ANTIFORENSE   = "Anti-forensics"
$F_ANTIVIRUS     = "Antivirus"
$F_ESFILTRAZIONE = "Esfiltrazione e tunnel"

# ==========================================================================
#  Elenchi di riconoscimento, portati da tc_regole.py del plugin
# ==========================================================================

# Strumenti di accesso remoto (RMM): nome e frammenti con cui riconoscerli.
$RMM = @(
    @{ Nome = 'AnyDesk'; Fr = @('anydesk') },
    @{ Nome = 'TeamViewer'; Fr = @('teamviewer') },
    @{ Nome = 'LogMeIn'; Fr = @('logmein','lmiguardian','lmi_rescue') },
    @{ Nome = 'GoTo'; Fr = @('gotoassist','goto resolve','gotoresolve','gotomypc','g2ax','g2ac_','goto opener') },
    @{ Nome = 'Pulseway'; Fr = @('pulseway','pcmonitorsrv','pcmontask') },
    @{ Nome = 'ScreenConnect / ConnectWise Control'; Fr = @('screenconnect','connectwisecontrol','connectwise control') },
    @{ Nome = 'ConnectWise Automate (LabTech)'; Fr = @('ltsvc','labtech','connectwise automate') },
    @{ Nome = 'Atera'; Fr = @('ateraagent','atera agent','atera networks','atera') },
    @{ Nome = 'Splashtop'; Fr = @('splashtop','srservice','srmanager','strwinclt') },
    @{ Nome = 'RustDesk'; Fr = @('rustdesk') },
    @{ Nome = 'NinjaOne / NinjaRMM'; Fr = @('ninjarmm','ninjaone','ninjaremote') },
    @{ Nome = 'Kaseya'; Fr = @('kaseya','agentmon.exe') },
    @{ Nome = 'N-able / SolarWinds'; Fr = @('n-able','n-central','ncentral','take control agent','basupsrvc','advanced monitoring agent','mspanywhere') },
    @{ Nome = 'Datto RMM'; Fr = @('centrastage','cagservice','datto rmm') },
    @{ Nome = 'Supremo'; Fr = @('supremoservice','supremosystem','supremohelper','supremocontrol','supremo remote','nanosystems','supremo.exe') },
    @{ Nome = 'Ammyy Admin'; Fr = @('ammyy','aa_v3') },
    @{ Nome = 'VNC'; Fr = @('realvnc','tightvnc','ultravnc','tigervnc','winvnc','tvnserver','vncserver','uvnc_service') },
    @{ Nome = 'DWService'; Fr = @('dwagent','dwagsvc','dwservice') },
    @{ Nome = 'Remote Utilities'; Fr = @('remote utilities','rutserv','rfusclient','rutview') },
    @{ Nome = 'NetSupport'; Fr = @('netsupport','client32.exe') },
    @{ Nome = 'Zoho Assist'; Fr = @('zohoassist','zoho assist') },
    @{ Nome = 'ManageEngine'; Fr = @('desktopcentral','desktop central','endpoint central','endpointcentral','dcagentservice','uems_agent','uems agent','remote access plus','remoteaccessplus') },
    @{ Nome = 'ISL Light / ISL AlwaysOn'; Fr = @('isl light','isllight','islalwayson','isl alwayson') },
    @{ Nome = 'MeshCentral'; Fr = @('meshagent','meshcentral','mesh agent') },
    @{ Nome = 'Radmin'; Fr = @('radmin server','radmin viewer','rserver3','radmin') },
    @{ Nome = 'Chrome Remote Desktop'; Fr = @('chrome remote desktop','chromoting','remoting_host') },
    @{ Nome = 'Action1'; Fr = @('action1_agent','action1_remote','action1') },
    @{ Nome = 'SimpleHelp'; Fr = @('simplehelp','simple-help') },
    @{ Nome = 'FleetDeck'; Fr = @('fleetdeck') },
    @{ Nome = 'Syncro'; Fr = @('syncromsp','syncrolive','syncro') },
    @{ Nome = 'Bomgar'; Fr = @('bomgar') },
    @{ Nome = 'DameWare'; Fr = @('dameware','dwrcs') },
    @{ Nome = 'Parsec'; Fr = @('parsecd','parsec') },
    @{ Nome = 'AeroAdmin'; Fr = @('aeroadmin') },
    @{ Nome = 'LiteManager'; Fr = @('litemanager','romserver','romfusclient') },
    @{ Nome = 'Getscreen.me'; Fr = @('getscreen') },
    @{ Nome = 'HopToDesk'; Fr = @('hoptodesk') },
    @{ Nome = 'Iperius Remote'; Fr = @('iperius remote','iperiusremote') },
    @{ Nome = 'Tactical RMM'; Fr = @('tacticalrmm','tactical rmm','tacticalagent') },
    @{ Nome = 'PDQ Connect'; Fr = @('pdq connect','pdqconnect') },
    @{ Nome = 'Quick Assist'; Fr = @('quickassist','quick assist') },
    @{ Nome = 'ToDesk'; Fr = @('todesk_service','todesk') },
    @{ Nome = 'Sunlogin'; Fr = @('sunlogin') }
)

# Frammenti di nome degli strumenti d'attacco noti (decisivi): cercati nei nomi
# di file, processi e nelle righe di comando.
$FR_ATTACCO = @(
    'mimikatz','mimilib','mimidrv','rubeus','sharphound','bloodhound','lazagne','winpeas',
    'safetykatz','nanodump','pypykatz','secretsdump','crackmapexec','cobaltstrike','meterpreter',
    'juicypotato','roguepotato','printspoofer','godpotato','sweetpotato','badpotato','kerbrute',
    'ligolo','powercat','powerview','powersploit','psexec','psexesvc','paexec','remcom','adfind',
    'netscan','advanced_ip_scanner','advanced ip scanner','ipscan','nmap','masscan','rclone',
    'megasync','ngrok','cloudflared','procdump','sdelete','processhacker','pchunter','chisel',
    'seatbelt','sharpup','kekeo','certipy','inveigh','plink','ncat','netcat','nc.exe','nc64',
    'wce.exe','pwdump','fgdump','gsecdump','dumpert','backstab','defendercontrol','dcontrol',
    'pingcastle','adrecon'
)

# Strumenti di ricognizione (da confermare quando eseguiti).
$FR_RICOGNIZIONE = @('whoami','nltest','net.exe','net1.exe',' net ','net group','net user',
    'net localgroup','systeminfo','ipconfig','arp -a','route print','quser','qwinsta','tasklist')

# Cartelle in cui un eseguibile "non dovrebbe" stare.
$CARTELLE_SOSPETTE = @('\appdata\local\temp\','\appdata\roaming\','\users\public\','\programdata\',
    '\downloads\','\windows\temp\','\$recycle.bin\','\perflogs\')

# Servizi di sistema con nome di 8 lettere: non sono "casuali".
$SERVIZI_NOTI_8 = @('ajrouter','wdnissvc','wmiprvse','vboxsds','mozillam','appvclient','diagtrack')

# ==========================================================================
#  Stato della raccolta
# ==========================================================================
$script:Segnali = New-Object System.Collections.ArrayList
$script:Avvisi  = New-Object System.Collections.ArrayList
$script:Note    = New-Object System.Collections.ArrayList
$script:Esiti   = @{}   # numero controllo -> 'fatto' | 'non verificabile' | 'errore'
$script:Out     = $null # cartella degli output grezzi

# ==========================================================================
#  Funzioni di supporto
# ==========================================================================

function Segnala {
    param([int]$Controllo, [int]$Peso, [string]$Famiglia, [string]$Testo, [string]$Dettagli = '')
    [void]$script:Segnali.Add([pscustomobject]@{
        Controllo = $Controllo; Peso = $Peso; Famiglia = $Famiglia; Testo = $Testo; Dettagli = $Dettagli
    })
    $et = switch ($Peso) { 3 {'DECISIVO'} 2 {'da confermare'} default {'contesto'} }
    $colore = switch ($Peso) { 3 {'Red'} 2 {'Yellow'} default {'Gray'} }
    Write-Host ("      [{0}] {1}" -f $et, $Testo) -ForegroundColor $colore
}

function Avviso {
    param([string]$Testo)
    if (-not $script:Avvisi.Contains($Testo)) { [void]$script:Avvisi.Add($Testo) }
    Write-Host ("      (copertura) {0}" -f $Testo) -ForegroundColor DarkYellow
}

function Nota {
    param([string]$Testo)
    if (-not $script:Note.Contains($Testo)) { [void]$script:Note.Add($Testo) }
}

function Salva {
    param([Parameter(ValueFromPipeline = $true)]$Dato, [string]$Nome)
    begin { $acc = New-Object System.Collections.ArrayList }
    process { if ($null -ne $Dato) { [void]$acc.Add($Dato) } }
    end {
        if ($acc.Count -eq 0) { return }
        $base = Join-Path $script:Out $Nome
        try { $acc | Format-Table -AutoSize | Out-String -Width 4000 | Set-Content -Path "$base.txt" -Encoding UTF8 } catch {}
        try { $acc | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    }
}

function Controllo {
    param([int]$Numero, [string]$Titolo, [scriptblock]$Blocco)
    Write-Host ("[{0,2}] {1}" -f $Numero, $Titolo) -ForegroundColor Cyan
    $t0 = Get-Date
    try {
        & $Blocco
        if (-not $script:Esiti.ContainsKey($Numero)) { $script:Esiti[$Numero] = 'fatto' }
    } catch {
        $script:Esiti[$Numero] = 'errore'
        Avviso ("controllo {0} interrotto da un errore: {1}" -f $Numero, $_.Exception.Message)
    }
    $dt = ((Get-Date) - $t0).TotalSeconds
    if ($dt -gt 5) { Write-Host ("      ({0:N0} s)" -f $dt) -ForegroundColor DarkGray }
}

function NonVerificabile {
    param([int]$Numero, [string]$Motivo)
    $script:Esiti[$Numero] = 'non verificabile'
    Write-Host ("      non verificabile: {0}" -f $Motivo) -ForegroundColor DarkGray
}

function NomeCasuale {
    # Vero se il nome sembra 8 lettere a caso con maiuscole e minuscole
    # mescolate: cosi' Impacket chiama servizi e attivita' temporanee.
    param([string]$Nome)
    if (-not $Nome -or $Nome -notmatch '^[A-Za-z]{8}$') { return $false }
    $basso = $Nome.ToLower()
    if ($SERVIZI_NOTI_8 -contains $basso) { return $false }
    $maiuscoleInterne = ($Nome.Substring(1).ToCharArray() | Where-Object { $_ -cmatch '[A-Z]' }).Count
    $minuscole = ($Nome.ToCharArray() | Where-Object { $_ -cmatch '[a-z]' }).Count
    return ($maiuscoleInterne -ge 2 -and $minuscole -ge 2)
}

function TrovaRmm {
    # Restituisce il nome del prodotto RMM se il testo lo nomina, altrimenti $null.
    param([string]$Testo)
    if (-not $Testo) { return $null }
    $basso = $Testo.ToLower()
    foreach ($r in $RMM) {
        foreach ($f in $r.Fr) {
            if ($basso.Contains($f)) { return $r.Nome }
        }
    }
    return $null
}

function RmmAutorizzato {
    param([string]$Nome)
    if (-not $Nome -or -not $RmmAutorizzati) { return $false }
    $basso = $Nome.ToLower()
    foreach ($a in ($RmmAutorizzati -split ',')) {
        $a = $a.Trim().ToLower()
        if ($a -and $basso.Contains($a)) { return $true }
    }
    return $false
}

function FrammentoAttacco {
    # Restituisce il frammento di strumento d'attacco trovato nel testo, o $null.
    param([string]$Testo)
    if (-not $Testo) { return $null }
    $basso = $Testo.ToLower()
    foreach ($f in $FR_ATTACCO) { if ($basso.Contains($f)) { return $f } }
    return $null
}

function Ricognizione {
    param([string]$Testo)
    if (-not $Testo) { return $false }
    $basso = ' ' + $Testo.ToLower() + ' '
    foreach ($f in $FR_RICOGNIZIONE) { if ($basso.Contains($f)) { return $true } }
    return $false
}

function InCartellaSospetta {
    param([string]$Percorso)
    if (-not $Percorso) { return $false }
    $basso = $Percorso.ToLower()
    foreach ($c in $CARTELLE_SOSPETTE) { if ($basso.Contains($c)) { return $true } }
    return $false
}

function ComandoPericoloso {
    # Riconosce i comandi che non hanno spiegazione innocente quando partono da
    # soli (chiave Run, attivita', consumer WMI) o vengono incollati in Esegui.
    param([string]$Riga)
    if (-not $Riga) { return $false }
    $b = $Riga.ToLower()
    if ($b -match '-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{30,}') { return $true }   # PowerShell codificato
    if ($b -match '(iex|invoke-expression)\b.*(downloadstring|new-object|iwr|invoke-webrequest|http)') { return $true }
    if ($b -match 'frombase64string') { return $true }
    if ($b -match '(certutil|bitsadmin|curl|wget)\b.*http') { return $true }
    if ($b -match 'mshta\s+http') { return $true }
    if ($b -match '-w(indowstyle)?\s+hidden') { return $true }
    if ($b -match 'regsvr32\s+/i:http') { return $true }
    return $false
}

function IPv4Pubblico {
    # Vero per un IPv4 instradabile. Un IPv6 non viene mai considerato pubblico
    # (come nel plugin): troppo facile sbagliare.
    param([string]$Ip)
    if (-not $Ip) { return $false }
    $m = [regex]::Match($Ip, '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    if (-not $m.Success) { return $false }
    $o = @($m.Groups[1..4] | ForEach-Object { [int]$_.Value })
    if ($o[0] -gt 255 -or $o[1] -gt 255 -or $o[2] -gt 255 -or $o[3] -gt 255) { return $false }
    if ($o[0] -eq 10) { return $false }
    if ($o[0] -eq 127) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }   # CGNAT
    if ($o[0] -eq 0 -or $o[0] -ge 224) { return $false }
    return $true
}

function DatiEvento {
    # I campi EventData di un evento come hashtable nome -> valore.
    param($Evento)
    $d = @{}
    try {
        ([xml]$Evento.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    } catch {}
    return $d
}

# ==========================================================================
#  Il verdetto: stessa logica di tc_controlli.decidi del plugin
# ==========================================================================
function Decidi {
    $decisivi = @($script:Segnali | Where-Object Peso -eq $DECISIVO)
    $conferme = @($script:Segnali | Where-Object Peso -eq $DACONF)
    $famiglie = @($conferme | Select-Object -ExpandProperty Famiglia -Unique)
    if ($decisivi.Count -ge 1) {
        $n = $decisivi.Count
        $motivo = if ($n -eq 1) {
            "1 segnale decisivo: basta uno solo per trattare la macchina come compromessa."
        } else {
            "$n segnali decisivi: basta uno solo per trattare la macchina come compromessa."
        }
        return [pscustomobject]@{ Verdetto = 'COMPROMISSIONE PROBABILE'; Motivo = $motivo }
    }
    if ($famiglie.Count -ge 2) {
        $motivo = ("Nessun segnale decisivo, ma segnali da confermare in {0} famiglie diverse ({1}): presi insieme puntano nella stessa direzione." -f $famiglie.Count, ($famiglie -join ', '))
        return [pscustomobject]@{ Verdetto = 'COMPROMISSIONE PROBABILE'; Motivo = $motivo }
    }
    if ($famiglie.Count -eq 1) {
        $motivo = ("Segnali da confermare in una sola famiglia ({0}): da soli non bastano. Cerca conferme dall'IT, dall'utente e dai log centralizzati." -f $famiglie[0])
        return [pscustomobject]@{ Verdetto = 'DA VERIFICARE'; Motivo = $motivo }
    }
    if ($script:Avvisi.Count -ge 1) {
        return [pscustomobject]@{ Verdetto = 'DA VERIFICARE'; Motivo = "Nessun segnale, ma la copertura e' insufficiente: l'assenza di tracce non esclude una compromissione." }
    }
    return [pscustomobject]@{ Verdetto = 'NESSUN INDIZIO'; Motivo = "I controlli eseguiti non hanno trovato segnali. Il triage non sostituisce l'analisi completa se ci sono altri motivi di sospetto." }
}

function ScriviRiepilogo {
    param($Esito, [string]$Computer)
    # verdetto.txt
    $righe = New-Object System.Collections.ArrayList
    [void]$righe.Add("TRIAGE COMPROMISSIONE WINDOWS - RACCOLTA DAL VIVO")
    [void]$righe.Add("Computer: $Computer")
    [void]$righe.Add("Generato: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$righe.Add("")
    [void]$righe.Add("VERDETTO: $($Esito.Verdetto)")
    [void]$righe.Add($Esito.Motivo)
    [void]$righe.Add("")
    $dec = @($script:Segnali | Where-Object Peso -eq $DECISIVO)
    $con = @($script:Segnali | Where-Object Peso -eq $DACONF)
    [void]$righe.Add("Segnali decisivi: $($dec.Count)   da confermare: $($con.Count)")
    [void]$righe.Add("")
    foreach ($s in ($script:Segnali | Sort-Object Peso -Descending)) {
        $et = switch ($s.Peso) { 3 {'DECISIVO     '} 2 {'da confermare'} default {'contesto     '} }
        [void]$righe.Add(("[{0}] c{1,2} {2} - {3}" -f $et, $s.Controllo, $s.Famiglia, $s.Testo))
    }
    if ($script:Avvisi.Count) {
        [void]$righe.Add(""); [void]$righe.Add("AVVISI DI COPERTURA (cosa il triage non ha potuto vedere):")
        foreach ($a in $script:Avvisi) { [void]$righe.Add("  - $a") }
    }
    if ($script:Note.Count) {
        [void]$righe.Add(""); [void]$righe.Add("NOTE:")
        foreach ($n in $script:Note) { [void]$righe.Add("  - $n") }
    }
    [void]$righe.Add(""); [void]$righe.Add("Ogni segnale vale solo finche' l'IT non lo spiega. Gli output grezzi di ogni")
    [void]$righe.Add("controllo sono nella cartella 'out': leggili per gli allarmi che richiedono la")
    [void]$righe.Add("conoscenza dell'ambiente e che il programma non puo' giudicare da solo.")
    $righe | Set-Content -Path (Join-Path $CartellaCaso 'verdetto.txt') -Encoding UTF8

    # segnali.csv
    if ($script:Segnali.Count) {
        $script:Segnali | Select-Object Controllo,
            @{n='Peso'; e={ switch ($_.Peso) { 3 {'Decisivo'} 2 {'Da confermare'} default {'Informativo'} } }},
            Famiglia, Testo, Dettagli |
            Export-Csv -Path (Join-Path $CartellaCaso 'segnali.csv') -NoTypeInformation -Encoding UTF8
    }
}

# Se chiamato solo per le prove, fermati qui: le funzioni sono definite.
if ($CaricaSoloFunzioni) { return }

# ==========================================================================
#  Avvio
# ==========================================================================
$amministratore = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $amministratore) {
    Write-Warning "Non sei amministratore: molti controlli daranno risultati parziali o errori. Chiudi e riapri PowerShell come amministratore."
}

Write-Host ""
Write-Host "Triage compromissione Windows - raccolta dal vivo" -ForegroundColor White
Write-Host "Questo programma esegue comandi sulla macchina ACCESA e ne modifica (poco) lo stato." -ForegroundColor White
Write-Host "Salvera' tutto in: $CartellaCaso" -ForegroundColor White
Write-Host "Se puoi, acquisisci PRIMA la RAM. Per isolare la macchina scollega la rete, non la corrente." -ForegroundColor White
if (-not $SenzaConferma) {
    $r = Read-Host "Continuare? (s/N)"
    if ($r -notmatch '^[sS]') { Write-Host "Annullato."; return }
}

New-Item -ItemType Directory -Path $CartellaCaso -Force | Out-Null
$script:Out = Join-Path $CartellaCaso 'out'
New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
try { Start-Transcript -Path (Join-Path $CartellaCaso 'sessione.txt') -Append | Out-Null } catch {}

$computer = $env:COMPUTERNAME
$inizioEventi = (Get-Date).AddDays(-$GiorniEventi)
$inizioRecenti = (Get-Date).AddDays(-$GiorniRecenti)

# ==========================================================================
#  FASE 1 - Dati volatili e contesto
# ==========================================================================
Write-Host ""; Write-Host "== Fase 1 - Dati volatili e contesto ==" -ForegroundColor Magenta

Controllo 1 "Contesto del sistema e ora" {
    $os = Get-CimInstance Win32_OperatingSystem
    $ctx = [pscustomobject]@{
        Computer = $os.CSName; SistemaOperativo = $os.Caption; Build = $os.BuildNumber
        Installato = $os.InstallDate; UltimoAvvio = $os.LastBootUpTime
        OraSistema = (Get-Date); FusoOrario = (Get-TimeZone).Id
    }
    $ctx | Salva -Nome '01_contesto'
    Nota "Confronta l'ora di sistema ($((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))) con un orologio affidabile e annota lo scarto: serve ad allineare la timeline."
}

Controllo 2 "Copia del Prefetch" {
    if (Test-Path C:\Windows\Prefetch) {
        $dest = Join-Path $script:Out 'Prefetch'
        robocopy C:\Windows\Prefetch $dest *.pf /COPY:DAT /NJH /NJS /NP /NFL /NDL | Out-Null
        $pf = @(Get-ChildItem $dest -Filter *.pf -ErrorAction SilentlyContinue)
        Write-Host ("      copiati {0} file .pf" -f $pf.Count) -ForegroundColor DarkGray
        if ($pf.Count -eq 0) { Nota "La cartella Prefetch e' vuota: sui Windows Server e' spento di default, su un client e' un indizio." }
    } else { Nota "Cartella Prefetch assente." }
}

Controllo 3 "Utenti collegati ora" {
    $q = (quser 2>$null)
    if ($q) { $q | Set-Content (Join-Path $script:Out '03_utenti_collegati.txt') -Encoding UTF8; $q | Select-Object -Skip 1 | Write-Host }
    Nota "Rivedi 03_utenti_collegati.txt: sessioni di utenti che non dovrebbero esserci, o RDP da origini sconosciute."
}

Controllo 4 "Processi con riga di comando" {
    $proc = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    $proc | Salva -Nome '04_processi'
    foreach ($p in $proc) {
        $campo = "$($p.ExecutablePath) $($p.CommandLine)"
        $fr = FrammentoAttacco $campo
        if ($fr) { Segnala 4 $DECISIVO $F_STRUMENTI ("Processo che nomina uno strumento d'attacco ({0}): {1}" -f $fr, $p.Name) $campo; continue }
        $rmm = TrovaRmm $campo
        if ($rmm -and -not (RmmAutorizzato $rmm)) { Segnala 4 $DACONF $F_RMM ("Processo di uno strumento di accesso remoto ({0}): {1}" -f $rmm, $p.Name) $campo; continue }
        if ($p.ExecutablePath -and (InCartellaSospetta $p.ExecutablePath)) {
            Segnala 4 $DACONF $F_ESECUZIONE ("Processo da una cartella di appoggio: {0}" -f $p.ExecutablePath) $p.CommandLine
        }
    }
}

Controllo 5 "Connessioni di rete" {
    $conn = Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{n='Processo'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path }}
    $conn | Salva -Nome '05_connessioni'
    foreach ($c in $conn) {
        if ($c.Processo -and (InCartellaSospetta $c.Processo) -and (IPv4Pubblico $c.RemoteAddress)) {
            Segnala 5 $DACONF $F_ESECUZIONE ("Connessione verso {0} da un processo in cartella di appoggio: {1}" -f $c.RemoteAddress, $c.Processo)
        }
    }
    Nota "Rivedi 05_connessioni.csv: connessioni verso IP esterni da processi insoliti, porte in ascolto inattese."
}

Controllo 6 "Cache DNS" {
    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Data
    $dns | Salva -Nome '06_dns'
    foreach ($d in $dns) {
        $rmm = TrovaRmm $d.Entry
        if ($rmm -and -not (RmmAutorizzato $rmm)) { Segnala 6 $DACONF $F_RMM ("La cache DNS ha un dominio di {0}: {1}" -f $rmm, $d.Entry) }
    }
}

Controllo 7 "Sessioni e connessioni SMB" {
    Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens | Salva -Nome '07_smb_sessioni'
    Get-SmbConnection -ErrorAction SilentlyContinue | Salva -Nome '07_smb_connessioni'
    Nota "Rivedi i file 07_smb_*: client o account inattesi, condivisioni C$/ADMIN$ aperte da altri host."
}

# ==========================================================================
#  FASE 2 - Account e accessi
# ==========================================================================
Write-Host ""; Write-Host "== Fase 2 - Account e accessi ==" -ForegroundColor Magenta

Controllo 8 "Copertura dei log e audit attivi" {
    $logs = Get-WinEvent -ListLog Security, System, 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -ErrorAction SilentlyContinue |
        Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes
    $logs | Salva -Nome '08_copertura'
    foreach ($l in $logs) {
        if ($l.LogName -in 'Security','System' -and -not $l.IsEnabled) { Avviso ("il registro {0} e' disattivato." -f $l.LogName) }
    }
    try {
        $vecchio = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
        $giorni = [int]((Get-Date) - $vecchio).TotalDays
        Nota ("Il registro Security parte dal {0} ({1} giorni fa)." -f $vecchio.ToString('yyyy-MM-dd'), $giorni)
        if ($giorni -lt $GiorniEventi) { Avviso ("il registro Security copre solo {0} giorni: piu' corti della finestra dei controlli." -f $giorni) }
    } catch { Avviso "impossibile leggere l'evento piu' vecchio del Security." }
    $audit = (auditpol /get /category:* 2>$null)
    if ($audit) {
        $audit | Set-Content (Join-Path $script:Out '08_auditpol.txt') -Encoding UTF8
        $riga = $audit | Where-Object { $_ -match 'Process Creation|Creazione processo' }
        if ($riga -and $riga -notmatch 'Success|Riuscito') { Nota "L'audit della creazione dei processi e' spento: l'evento 4688 (controllo 25) non ci sara'." }
    }
}

Controllo 9 "Log cancellati (1102, 104)" {
    $c = @()
    $c += Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue
    $c += Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -ErrorAction SilentlyContinue
    $c | Select-Object TimeCreated, Id, Message | Salva -Nome '09_log_cancellati'
    foreach ($e in $c) {
        Segnala 9 $DECISIVO $F_ANTIFORENSE ("Registro eventi cancellato (evento {0}) il {1}: serve l'amministratore, fuori da una manutenzione nota e' un segnale forte." -f $e.Id, $e.TimeCreated)
    }
}

Controllo 10 "Account locali, amministratori, profili" {
    Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description, SID | Salva -Nome '10_utenti'
    try {
        # l'account Guest si riconosce dal SID che finisce per -501, in ogni lingua
        $guest = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-501$' }
        $admin = @(Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue)
        $admin | Select-Object Name, PrincipalSource, ObjectClass, SID | Salva -Nome '10_amministratori'
        if ($guest -and $guest.Enabled -and @($admin | Where-Object { $_.SID.Value -match '-501$' }).Count) {
            Segnala 10 $DECISIVO $F_ACCOUNT ("L'account Guest ({0}) e' attivo ed e' nel gruppo Administrators: configurazione da backdoor." -f $guest.Name)
        }
    } catch { Nota "Get-LocalGroupMember ha dato errore (SID orfano nel gruppo). Usa la riga di riserva della checklist (net localgroup)." }
    Get-ChildItem C:\Users -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.CreationTime -gt $inizioRecenti) {
            Segnala 10 $DACONF $F_ACCOUNT ("Profilo utente creato di recente ({0}): {1}" -f $_.CreationTime.ToString('yyyy-MM-dd'), $_.Name)
        }
    }
}

Controllo 11 "Logon remoti di rete e RDP (4624)" {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$inizioEventi} -ErrorAction SilentlyContinue
    $righe = foreach ($e in $ev) {
        $d = DatiEvento $e
        if ($d.LogonType -in '3','10' -and $d.IpAddress -notin '-','::1','127.0.0.1') {
            [pscustomobject]@{ Ora=$e.TimeCreated; Utente="$($d.TargetDomainName)\$($d.TargetUserName)"; Tipo=$d.LogonType; IP=$d.IpAddress; Host=$d.WorkstationName }
        }
    }
    $righe | Salva -Nome '11_logon_remoti'
    foreach ($r in $righe) {
        if ($r.Tipo -eq '10' -and (IPv4Pubblico $r.IP)) {
            Segnala 11 $DACONF $F_ACCESSI ("Accesso RDP da un indirizzo pubblico {0} come {1}" -f $r.IP, $r.Utente)
        }
    }
    Nota "Rivedi 11_logon_remoti.csv: account senza motivo di accedere, host o orari inattesi."
}

Controllo 12 "Accessi falliti per indirizzo (4625)" {
    $ip = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$inizioEventi} -ErrorAction SilentlyContinue | ForEach-Object {
        (DatiEvento $_).IpAddress
    } | Where-Object { $_ -and $_ -notin '-','::1','127.0.0.1' } | Group-Object | Sort-Object Count -Descending
    $ip | Select-Object Count, Name | Salva -Nome '12_accessi_falliti'
    foreach ($g in ($ip | Select-Object -First 5)) {
        if ($g.Count -ge 20) { Segnala 12 $DACONF $F_ACCESSI ("Raffica di accessi falliti da {0}: {1} tentativi (possibile brute force)." -f $g.Name, $g.Count) }
    }
}

Controllo 13 "Credenziali esplicite e connessioni in uscita" {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=$inizioEventi} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Message | Salva -Nome '13_credenziali_esplicite'
    Nota "Rivedi 13_credenziali_esplicite: accessi verso host che l'utente non usa, account remoto diverso dal locale."
}

Controllo 14 "Sessioni RDP (Terminal Services)" {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,24,25} -ErrorAction SilentlyContinue
    $ev | Select-Object TimeCreated, Id, Message | Salva -Nome '14_rdp'
    foreach ($e in $ev) {
        $ip = ([regex]::Match($e.Message, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')).Groups[1].Value
        if ($ip -and (IPv4Pubblico $ip)) { Segnala 14 $DACONF $F_ACCESSI ("Sessione RDP da un indirizzo pubblico {0} (evento {1})." -f $ip, $e.Id) }
    }
}

# ==========================================================================
#  FASE 3 - Persistenza
# ==========================================================================
Write-Host ""; Write-Host "== Fase 3 - Persistenza ==" -ForegroundColor Magenta

Controllo 15 "Attivita' pianificate" {
    $task = Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskPath, TaskName, State, Author, Date,
        @{n='Azioni'; e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ' }}
    $task | Salva -Nome '15_attivita'
    foreach ($t in $task) {
        $az = $t.Azioni
        if (-not $az) { continue }
        $fr = FrammentoAttacco $az
        if ($fr) { Segnala 15 $DECISIVO $F_STRUMENTI ("Attivita' pianificata che nomina uno strumento d'attacco ({0}): {1}" -f $fr, $t.TaskName) $az; continue }
        if ($az -match 'cmd(\.exe)?|powershell|pwsh|wscript|cscript|mshta' -and (InCartellaSospetta $az)) {
            Segnala 15 $DECISIVO $F_PERSISTENZA ("Attivita' pianificata che lancia una shell da una cartella di appoggio: {0}" -f $t.TaskName) $az; continue
        }
        if (NomeCasuale ($t.TaskName -replace '.*\\','')) { Segnala 15 $DACONF $F_PERSISTENZA ("Attivita' pianificata con nome di 8 lettere casuali: {0}" -f $t.TaskName) $az; continue }
        if ($t.Date -and ([datetime]$t.Date) -gt $inizioRecenti) { Segnala 15 $DACONF $F_PERSISTENZA ("Attivita' pianificata creata di recente ({0}): {1}" -f ([datetime]$t.Date).ToString('yyyy-MM-dd'), $t.TaskName) $az }
    }
}

Controllo 16 "Attivita' nascoste" {
    $tc = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuildNumber
    if ($build -lt 10240) { NonVerificabile 16 "prima di Windows 10 questo controllo non si applica (build $build)."; return }
    Get-ChildItem "$tc\Tree" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $id = $_.GetValue('Id'); if (-not $id) { return }
        $senzaSD = $_.GetValueNames() -notcontains 'SD'
        $index0 = ($_.GetValue('Index') -eq 0) -and (Test-Path -LiteralPath "$tc\Tasks\$id")
        if ($senzaSD -or $index0) {
            $nome = $_.Name -replace '^.*?\\TaskCache\\Tree', ''
            Segnala 16 $DECISIVO $F_PERSISTENZA ("Attivita' pianificata nascosta (Tarrask): {0}" -f $nome) ("SenzaSD={0} Index0ConScheda={1}" -f $senzaSD, $index0)
        }
    }
}

Controllo 17 "Servizi" {
    $srv = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    $srv | Salva -Nome '17_servizi'
    foreach ($s in $srv) {
        $p = $s.PathName
        if (-not $p) { continue }
        if ($p -match '__output|echo cd|execute\.bat' -or $s.Name -eq 'BTOBTO') { Segnala 17 $DECISIVO $F_LATERALE ("Servizio con le firme di smbexec: {0}" -f $s.Name) $p; continue }
        if ($p -match 'cmd\.exe|%COMSPEC%|powershell|pwsh' -and (InCartellaSospetta $p)) { Segnala 17 $DECISIVO $F_PERSISTENZA ("Servizio che lancia una shell da una cartella di appoggio: {0}" -f $s.Name) $p; continue }
        if (NomeCasuale $s.Name) { Segnala 17 $DACONF $F_PERSISTENZA ("Servizio con nome di 8 lettere casuali: {0}" -f $s.Name) $p }
    }
}

Controllo 18 "Servizi installati (7045)" {
    $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue
    $righe = foreach ($e in $ev) {
        [pscustomobject]@{ Ora=$e.TimeCreated; Servizio=$e.Properties[0].Value; Percorso=$e.Properties[1].Value; Account=$e.Properties[4].Value }
    }
    $righe | Salva -Nome '18_servizi_installati'
    foreach ($r in $righe) {
        $rmm = TrovaRmm "$($r.Servizio) $($r.Percorso)"
        if ($rmm -and -not (RmmAutorizzato $rmm)) { Segnala 18 $DACONF $F_RMM ("Strumento di accesso remoto installato come servizio ({0}): {1}" -f $rmm, $r.Servizio); continue }
        if (NomeCasuale ([string]$r.Servizio)) { Segnala 18 $DACONF $F_LATERALE ("Servizio installato con nome di 8 lettere casuali: {0}" -f $r.Servizio) ([string]$r.Percorso) }
    }
    $timeout = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7009} -ErrorAction SilentlyContinue)
    if ($righe.Count -and $timeout.Count) { Nota "Ci sono eventi 7045 e 7009 (timeout all'avvio): tipico di smbexec; confronta gli orari in 18_servizi_installati." }
}

Controllo 19 "Chiavi Run e cartelle Esecuzione automatica" {
    $chiavi = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Run',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $props = Get-ItemProperty $chiavi -ErrorAction SilentlyContinue
    $props | Out-String -Width 4000 | Set-Content (Join-Path $script:Out '19_run.txt') -Encoding UTF8
    foreach ($p in $props) {
        foreach ($nome in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            $val = [string]$nome.Value
            if (ComandoPericoloso $val) { Segnala 19 $DACONF $F_PERSISTENZA ("Chiave Run con un comando sospetto ({0}): {1}" -f $nome.Name, $val); continue }
            if (InCartellaSospetta $val) { Segnala 19 $DACONF $F_PERSISTENZA ("Chiave Run verso una cartella di appoggio ({0}): {1}" -f $nome.Name, $val) }
        }
    }
    $avvio = Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp' -Force -ErrorAction SilentlyContinue
    $avvio | Select-Object FullName, CreationTime, LastWriteTime | Salva -Nome '19_avvio_automatico'
    foreach ($f in $avvio) { if ($f.CreationTime -gt $inizioRecenti) { Segnala 19 $DACONF $F_PERSISTENZA ("File recente nella cartella Esecuzione automatica: {0}" -f $f.FullName) } }
}

Controllo 20 "Sottoscrizioni WMI" {
    foreach ($ns in 'root\subscription','root\default') {
        $cons = Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue
        $cons | Select-Object @{n='Namespace';e={$ns}}, @{n='Classe';e={$_.CimClass.CimClassName}}, Name, CommandLineTemplate, ExecutablePath, ScriptText | Salva -Nome '20_wmi'
        foreach ($c in $cons) {
            $testo = "$($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText)"
            $fr = FrammentoAttacco $testo
            if ($fr) { Segnala 20 $DECISIVO $F_PERSISTENZA ("Consumer WMI che nomina uno strumento d'attacco ({0}): {1}" -f $fr, $c.Name) $testo; continue }
            if ($c.CimClass.CimClassName -in 'CommandLineEventConsumer','ActiveScriptEventConsumer') {
                if (ComandoPericoloso $testo) { Segnala 20 $DECISIVO $F_PERSISTENZA ("Consumer WMI con un comando sospetto: {0}" -f $c.Name) $testo }
                else { Segnala 20 $DACONF $F_PERSISTENZA ("Consumer WMI che esegue un comando/script: {0}" -f $c.Name) $testo }
            }
        }
    }
}

# ==========================================================================
#  FASE 4 - Programmi eseguiti
# ==========================================================================
Write-Host ""; Write-Host "== Fase 4 - Programmi eseguiti ==" -ForegroundColor Magenta

Controllo 21 "Prefetch" {
    $pf = Get-ChildItem C:\Windows\Prefetch -Filter *.pf -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    $pf | Select-Object Name, CreationTime, LastWriteTime | Salva -Nome '21_prefetch'
    foreach ($f in $pf) {
        $nome = ($f.Name -replace '-[0-9A-F]{8}\.pf$','').ToLower()
        $fr = FrammentoAttacco $nome
        if ($fr) { Segnala 21 $DECISIVO $F_STRUMENTI ("Prefetch di uno strumento d'attacco ({0}): {1}" -f $fr, $f.Name) ("Ultimo avvio: {0}" -f $f.LastWriteTime); continue }
        if (Ricognizione $nome) { Segnala 21 $DACONF $F_ESECUZIONE ("Prefetch di uno strumento di ricognizione: {0}" -f $f.Name) ("Ultimo avvio: {0}" -f $f.LastWriteTime) }
    }
    if ($pf.Count -gt 0 -and $pf.Count -lt 20) { Nota "Pochi file nel Prefetch ($($pf.Count)): su un client puo' indicare pulizia o Prefetch disattivato." }
}

Controllo 22 "BAM" {
    $chiavi = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    $righe = Get-ChildItem $chiavi -ErrorAction SilentlyContinue | ForEach-Object {
        $k = $_
        foreach ($v in $k.GetValueNames()) {
            $b = $k.GetValue($v)
            if ($b -is [byte[]] -and $b.Length -ge 8) {
                [pscustomobject]@{ SID=$k.PSChildName; Eseguibile=$v; UltimaUTC=[DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b,0)) }
            }
        }
    } | Sort-Object UltimaUTC -Descending
    $righe | Salva -Nome '22_bam'
    foreach ($r in $righe) {
        if ((InCartellaSospetta $r.Eseguibile) -and $r.UltimaUTC -gt $inizioRecenti.ToUniversalTime()) {
            Segnala 22 $DACONF $F_ESECUZIONE ("BAM: eseguibile da cartella di appoggio avviato di recente ({0} UTC): {1}" -f $r.UltimaUTC.ToString('yyyy-MM-dd HH:mm'), $r.Eseguibile)
        }
    }
}

Controllo 23 "RunMRU" {
    $mru = Get-ItemProperty 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction SilentlyContinue
    $mru | Out-String -Width 4000 | Set-Content (Join-Path $script:Out '23_runmru.txt') -Encoding UTF8
    foreach ($p in $mru) {
        foreach ($nome in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -ne 'MRUList' })) {
            $val = [string]$nome.Value
            if (ComandoPericoloso $val -or $val -match 'powershell|mshta|\\\\') {
                Segnala 23 $DACONF $F_ESECUZIONE ("Comando incollato nella finestra Esegui (ClickFix?): {0}" -f $val)
            }
        }
    }
}

Controllo 24 "Download con certutil (CryptnetUrlCache)" {
    $cartelle = 'C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content',
        'C:\Windows\*\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content',
        'C:\Windows\ServiceProfiles\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content'
    $trovati = Get-ChildItem $cartelle -File -Force -ErrorAction SilentlyContinue | Where-Object {
        try { $b = [IO.File]::ReadAllBytes($_.FullName) } catch { $b = $null }
        $b -and $b.Length -ge 2 -and $b[0] -eq 77 -and $b[1] -eq 90
    }
    $trovati | Select-Object FullName, Length, LastWriteTime | Salva -Nome '24_certutil'
    foreach ($f in $trovati) {
        Segnala 24 $DECISIVO $F_ESECUZIONE ("Eseguibile nella cache dei download di certutil (scaricato e cancellato?): {0}" -f $f.FullName) ("{0} byte, {1}" -f $f.Length, $f.LastWriteTime)
    }
}

Controllo 25 "Comandi sospetti (4688)" {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$inizioEventi} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'certutil|curl|__output|\.tmp 2>&1|vssadmin|shadowcopy|call create|whoami|\\\\127\.0\.0\.1' }
    $ev | Select-Object TimeCreated, Message | Salva -Nome '25_comandi_4688'
    foreach ($e in $ev) {
        if ($e.Message -match '__output|\\\\127\.0\.0\.1') { Segnala 25 $DECISIVO $F_LATERALE "Evento 4688 con una firma di Impacket (output remoto)." $e.Message }
        elseif ($e.Message -match 'vssadmin.*delete|shadowcopy.*delete') { Segnala 25 $DACONF $F_ANTIFORENSE "Evento 4688: cancellazione delle copie shadow da riga di comando." $e.Message }
        else { Segnala 25 $DACONF $F_ESECUZIONE "Evento 4688 con un comando sospetto (certutil/curl/whoami)." $e.Message }
    }
    if (-not $ev -and $script:Esiti[8] -ne 'errore') { Nota "Nessun 4688 utile: se l'audit della creazione processi e' spento (controllo 8), questo controllo non vede nulla." }
}

Controllo 26 "ShimCache (salvataggio hive)" {
    try { reg save HKLM\SYSTEM (Join-Path $script:Out '26_SYSTEM.hiv') /y | Out-Null
          Nota "Hive SYSTEM salvato in out\26_SYSTEM.hiv: analizzalo con AppCompatCacheParser. ShimCache prova che un file esisteva, non che e' stato eseguito." }
    catch { NonVerificabile 26 "impossibile salvare l'hive SYSTEM." }
}

# ==========================================================================
#  FASE 5 - Esecuzione remota con Impacket
# ==========================================================================
Write-Host ""; Write-Host "== Fase 5 - Esecuzione remota con Impacket ==" -ForegroundColor Magenta

Controllo 27 "Attivita' create e cancellate in pochi istanti" {
    $fonti = @(
        @{ Log='Security'; Crea=4698; Canc=4699; Nome=4 },
        @{ Log='Microsoft-Windows-TaskScheduler/Operational'; Crea=106; Canc=141; Nome=0 }
    )
    foreach ($f in $fonti) {
        $ev = Get-WinEvent -FilterHashtable @{LogName=$f.Log; Id=$f.Crea, $f.Canc} -ErrorAction SilentlyContinue
        $ev | Group-Object { $_.Properties[$f.Nome].Value } | ForEach-Object {
            $c = $_.Group | Where-Object Id -eq $f.Crea | Select-Object -Last 1
            $x = $_.Group | Where-Object Id -eq $f.Canc | Select-Object -Last 1
            if ($c -and $x) {
                $ms = [int]($x.TimeCreated - $c.TimeCreated).TotalMilliseconds
                if ($ms -ge 0 -and $ms -lt 2000) {
                    Segnala 27 $DECISIVO $F_LATERALE ("Attivita' pianificata creata e cancellata in {0} ms (atexec): {1}" -f $ms, $_.Name)
                }
            }
        }
    }
}

Controllo 28 "Firme di atexec nelle attivita' (4698)" {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[5].Value -match '2015-07-15T20:35:13|Temp\\[A-Za-z]{8}\.tmp' } | ForEach-Object {
            Segnala 28 $DECISIVO $F_LATERALE ("Attivita' pianificata con la firma di atexec: {0}" -f $_.Properties[4].Value) ("Creata: {0}" -f $_.TimeCreated)
        }
}

Controllo 29 "Firme di smbexec nei servizi" {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[1].Value -match '__output|echo cd|execute\.bat|%COMSPEC%' -or $_.Properties[0].Value -eq 'BTOBTO' } | ForEach-Object {
            Segnala 29 $DECISIVO $F_LATERALE ("Servizio con la firma di smbexec: {0}" -f $_.Properties[0].Value) ([string]$_.Properties[1].Value)
        }
}

Controllo 30 "File residui di Impacket" {
    $residui = Get-Item C:\__output, C:\Windows\Temp\__output, C:\Windows\Temp\execute.bat -Force -ErrorAction SilentlyContinue
    $residui += Get-ChildItem C:\Windows\*.bat, C:\Windows\Temp\*.tmp -Force -ErrorAction SilentlyContinue |
        Where-Object Name -match '^[A-Za-z]{8}\.(bat|tmp)$'
    $residui | Select-Object FullName, CreationTime, LastWriteTime | Salva -Nome '30_residui'
    foreach ($r in $residui) { Segnala 30 $DECISIVO $F_LATERALE ("File residuo di esecuzione remota (Impacket): {0}" -f $r.FullName) }
}

Controllo 31 "Accessi alle share (5145)" {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=$inizioEventi} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'atsvc|svcctl|__output|Temp\\[A-Za-z]{8}\.tmp' }
    $ev | Select-Object TimeCreated, Message | Salva -Nome '31_share_5145'
    foreach ($e in $ev) {
        if ($e.Message -match '__output|Temp\\[A-Za-z]{8}\.tmp') { Segnala 31 $DECISIVO $F_LATERALE "Accesso alla share verso un file di output di Impacket (5145)." $e.Message }
        else { Segnala 31 $DACONF $F_LATERALE "Accesso alle pipe atsvc/svcctl tipico dell'esecuzione remota (5145)." $e.Message }
    }
}

# ==========================================================================
#  FASE 6 - Strumenti di accesso remoto (RMM)
# ==========================================================================
Write-Host ""; Write-Host "== Fase 6 - Strumenti di accesso remoto (RMM) ==" -ForegroundColor Magenta

Controllo 32 "Programmi installati" {
    $inst = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName | Select-Object DisplayName, Publisher, InstallDate, InstallLocation
    $inst | Sort-Object InstallDate -Descending | Salva -Nome '32_installati'
    foreach ($p in $inst) {
        $rmm = TrovaRmm "$($p.DisplayName) $($p.Publisher)"
        if ($rmm -and -not (RmmAutorizzato $rmm)) { Segnala 32 $DACONF $F_RMM ("Strumento di accesso remoto installato ({0}): {1}" -f $rmm, $p.DisplayName) ("Installato: {0}" -f $p.InstallDate) }
    }
}

Controllo 33 "RMM portabili, anche rinominati" {
    $cartelle = 'C:\Users\*\Downloads', 'C:\Users\*\Desktop', 'C:\Users\Public', 'C:\Users\*\AppData\Local\Temp',
        'C:\Users\*\AppData\Roaming', 'C:\Windows\Temp'
    $exe = Get-ChildItem $cartelle -Recurse -Force -File -Filter *.exe -ErrorAction SilentlyContinue
    foreach ($f in $exe) {
        $rmm = TrovaRmm "$($f.Name) $($f.VersionInfo.CompanyName) $($f.VersionInfo.ProductName)"
        if ($rmm -and -not (RmmAutorizzato $rmm)) {
            Segnala 33 $DACONF $F_RMM ("Strumento di accesso remoto portabile ({0}): {1}" -f $rmm, $f.FullName) ("Produttore: {0}" -f $f.VersionInfo.CompanyName)
        }
    }
}

Controllo 34 "AnyDesk" {
    $log = Get-ChildItem 'C:\Users\*\AppData\Roaming\AnyDesk','C:\ProgramData\AnyDesk' -Recurse -Force -Include connection_trace.txt, file_transfer_trace.txt -ErrorAction SilentlyContinue
    $entrata = $false
    foreach ($l in $log) {
        $t = Get-Content $l.FullName -Tail 50 -ErrorAction SilentlyContinue
        $t | Set-Content (Join-Path $script:Out ("34_anydesk_" + $l.Directory.Name + "_" + $l.Name)) -Encoding UTF8
        if ($t -match 'Incoming|in entrata') { $entrata = $true }
    }
    $tracce = Get-ChildItem 'C:\Users\*\AppData\Roaming\AnyDesk','C:\ProgramData\AnyDesk' -Recurse -Force -Include *.trace -ErrorAction SilentlyContinue |
        Select-String 'Incoming session request' -ErrorAction SilentlyContinue
    if ($tracce) { $entrata = $true; $tracce | Select-Object -Last 30 Path, Line | Salva -Nome '34_anydesk_sessioni' }
    if ($log -or $tracce) {
        $aut = RmmAutorizzato 'AnyDesk'
        if ($entrata -and -not $aut) { Segnala 34 $DECISIVO $F_RMM "AnyDesk non autorizzato con sessioni in entrata: qualcuno si e' collegato da fuori." }
        elseif (-not $aut) { Segnala 34 $DACONF $F_RMM "AnyDesk presente e non indicato come autorizzato." }
    }
}

Controllo 35 "TeamViewer" {
    $log = Get-ChildItem 'C:\Users\*\AppData\Roaming\TeamViewer\Connections.txt','C:\Program Files*\TeamViewer\Connections_incoming.txt',
        'C:\Users\*\AppData\Local\Temp\TeamViewer\Connections_incoming.txt' -Force -ErrorAction SilentlyContinue
    $entrata = $false
    foreach ($l in $log) {
        $t = Get-Content $l.FullName -Tail 50 -ErrorAction SilentlyContinue
        $t | Set-Content (Join-Path $script:Out ("35_teamviewer_" + $l.Name)) -Encoding UTF8
        if ($l.Name -match 'incoming') { $entrata = $true }
    }
    if ($log) {
        $aut = RmmAutorizzato 'TeamViewer'
        if ($entrata -and -not $aut) { Segnala 35 $DECISIVO $F_RMM "TeamViewer non autorizzato con connessioni in entrata." }
        elseif (-not $aut) { Segnala 35 $DACONF $F_RMM "TeamViewer presente e non indicato come autorizzato." }
    }
}

Controllo 36 "LogMeIn e Pulseway" {
    $lmi = @(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='LogMeIn'; Id=102,104,105,202,205} -ErrorAction SilentlyContinue)
    $lmi | Select-Object TimeCreated, Id, Message | Salva -Nome '36_logmein'
    if ($lmi.Count -and -not (RmmAutorizzato 'LogMeIn')) { Segnala 36 $DACONF $F_RMM ("LogMeIn con {0} eventi di sessione: non indicato come autorizzato." -f $lmi.Count) }
    $pw = @(Get-WinEvent -FilterHashtable @{LogName='Application'; Id=24001} -ErrorAction SilentlyContinue | Where-Object Message -match 'Received Request')
    $pw | Select-Object TimeCreated, Message | Salva -Nome '36_pulseway'
    if ($pw.Count -and -not (RmmAutorizzato 'Pulseway')) { Segnala 36 $DACONF $F_RMM ("Pulseway con {0} richieste ricevute: non indicato come autorizzato." -f $pw.Count) }
}

# ==========================================================================
#  FASE 7 - File, antivirus e anti-forensics
# ==========================================================================
Write-Host ""; Write-Host "== Fase 7 - File, antivirus e anti-forensics ==" -ForegroundColor Magenta

Controllo 37 "Rilevamenti di Defender" {
    $det = @()
    try { $det = @(Get-MpThreatDetection -ErrorAction Stop) } catch {}
    $det | Select-Object InitialDetectionTime, ThreatID, ProcessName, ActionSuccess | Salva -Nome '37_defender'
    foreach ($d in $det) { Segnala 37 $DECISIVO $F_ANTIVIRUS ("Rilevamento di Defender (ThreatID {0}): anche se bloccato, va spiegato." -f $d.ThreatID) ([string]$d.Resources) }
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Message | Salva -Nome '37_defender_1116'
}

Controllo 38 "File recenti nelle cartelle di appoggio" {
    $cartelle = 'C:\Users\Public', 'C:\Windows\Temp', 'C:\Users\*\AppData\Local\Temp', 'C:\Users\*\Downloads', 'C:\ProgramData'
    $file = Get-ChildItem $cartelle -Recurse -Force -File -Include *.exe, *.dll, *.ps1, *.bat, *.vbs, *.zip, *.7z, *.rar -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -gt $inizioRecenti
    $file | Select-Object FullName, Length, CreationTime, LastWriteTime | Sort-Object CreationTime -Descending | Salva -Nome '38_file_recenti'
    foreach ($f in $file) {
        $fr = FrammentoAttacco $f.Name
        if ($fr) { Segnala 38 $DECISIVO $F_STRUMENTI ("File di uno strumento d'attacco ({0}): {1}" -f $fr, $f.FullName); continue }
    }
    $grossi = @($file | Where-Object { $_.Extension -match '\.(zip|7z|rar)$' -and $_.Length -gt 50MB })
    foreach ($a in $grossi) { Segnala 38 $DACONF $F_ESFILTRAZIONE ("Grande archivio recente (possibile esfiltrazione): {0} ({1:N0} MB)" -f $a.FullName, ($a.Length/1MB)) }
    Nota "Rivedi 38_file_recenti.csv: strumenti che nessuno sa spiegare, estensioni diverse da quelle scaricate."
}

Controllo 39 "Cestino" {
    $i = Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Get-ChildItem "$($_.Root)`$Recycle.Bin" -Recurse -Force -Filter '$I*' -ErrorAction SilentlyContinue
    }
    $i | Select-Object FullName, Length, CreationTime | Salva -Nome '39_cestino'
    $recenti = @($i | Where-Object CreationTime -gt $inizioRecenti)
    if ($recenti.Count -ge 50) { Segnala 39 $DACONF $F_ANTIFORENSE ("Molte cancellazioni recenti nel Cestino ({0} file nella finestra): possibile pulizia." -f $recenti.Count) }
}

Controllo 40 "Copie shadow" {
    $v = (vssadmin list shadows 2>$null)
    if ($v) { $v | Set-Content (Join-Path $script:Out '40_shadow.txt') -Encoding UTF8 }
    Nota "Rivedi 40_shadow.txt e il controllo 25: nessuna copia dove dovrebbero esserci, insieme a tracce di vssadmin delete, e' un indizio di anti-forensics."
}

Controllo 41 "Artefatti disattivati" {
    $acl = Get-Acl 'Registry::HKEY_USERS\*_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache',
        'Registry::HKEY_USERS\*_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' -ErrorAction SilentlyContinue |
        Where-Object { $_.AccessToString -match 'Deny' }
    foreach ($a in $acl) { Segnala 41 $DACONF $F_ANTIFORENSE ("ACL Deny su un artefatto forense ({0}): qualcuno ha impedito a Windows di registrare." -f $a.Path) }
    Get-ItemProperty 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\*' -ErrorAction SilentlyContinue |
        Where-Object NukeOnDelete -eq 1 | ForEach-Object { Segnala 41 $DACONF $F_ANTIFORENSE "NukeOnDelete attivo: i file vengono cancellati senza passare dal Cestino." }
}

# ==========================================================================
#  Preservazione (registri eventi e hive)
# ==========================================================================
if (-not $SenzaPreservare) {
    Write-Host ""; Write-Host "== Preservazione (registri eventi e hive) ==" -ForegroundColor Magenta
    $evtx = Join-Path $CartellaCaso 'evtx'
    New-Item -ItemType Directory -Path $evtx -Force | Out-Null
    foreach ($log in 'Security','System','Application','Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-PowerShell/Operational') {
        $dest = Join-Path $evtx (($log -replace '/','%4') + '.evtx')
        try { wevtutil epl $log $dest 2>$null } catch {}
    }
    Copy-Item C:\Windows\System32\winevt\Logs\Archive-* $evtx -ErrorAction SilentlyContinue
    $reg = Join-Path $CartellaCaso 'reg'
    New-Item -ItemType Directory -Path $reg -Force | Out-Null
    foreach ($h in 'SYSTEM','SOFTWARE','SAM','SECURITY') { try { reg save "HKLM\$h" (Join-Path $reg "$h.hiv") /y | Out-Null } catch {} }
    Write-Host "      registri eventi in 'evtx', hive in 'reg'." -ForegroundColor DarkGray
    Nota "Per il resto (MFT, UsnJrnl, Amcache, NTUSER.DAT, Cestino, Jump List, log RMM) usa un raccoglitore di basso livello: KAPE, il collector di Cyber Triage o Velociraptor."
}

# ==========================================================================
#  Verdetto
# ==========================================================================
$esito = Decidi
ScriviRiepilogo -Esito $esito -Computer $computer
try { Stop-Transcript | Out-Null } catch {}

Write-Host ""
$colore = switch ($esito.Verdetto) { 'COMPROMISSIONE PROBABILE' {'Red'} 'DA VERIFICARE' {'Yellow'} default {'Green'} }
Write-Host "============================================================" -ForegroundColor $colore
Write-Host ("  VERDETTO: {0}" -f $esito.Verdetto) -ForegroundColor $colore
Write-Host ("  {0}" -f $esito.Motivo) -ForegroundColor $colore
Write-Host "============================================================" -ForegroundColor $colore
$dec = @($script:Segnali | Where-Object Peso -eq $DECISIVO)
$con = @($script:Segnali | Where-Object Peso -eq $DACONF)
Write-Host ("  Segnali decisivi: {0}   da confermare: {1}   avvisi di copertura: {2}" -f $dec.Count, $con.Count, $script:Avvisi.Count)
Write-Host ("  Riepilogo in: {0}" -f (Join-Path $CartellaCaso 'verdetto.txt'))
Write-Host ("  Output grezzi in: {0}" -f $script:Out)
Write-Host ""
Write-Host "  Ogni segnale vale solo finche' l'IT non lo spiega. Questo triage non" -ForegroundColor White
Write-Host "  sostituisce l'analisi completa." -ForegroundColor White
