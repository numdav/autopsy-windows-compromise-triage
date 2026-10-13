# Windows Compromise Triage 1.3 - piano e tracciabilità

Fonte delle voci: documento "Valutazione di Windows Compromise Triage 1.2" (sezioni 7 e 18, decisioni del 12 e
13 ottobre), revisione esterna del 13 ottobre, proposte di README nel kit (compatibilita/, ram_reale/), conversazione.
Ogni voce ha un esito: FATTA (con la prova che la verifica), SOSTITUITA (da una decisione), RINVIATA (con il motivo).

Esiti scritti il 13 ottobre a prove finite. Codice del plugin provato: impronta dd27cc9f… (i 17 .py, uguale in tutte
le prove: unitarie, banchi, insieme sigillato, Autopsy). Raccoglitore: 4e3c5664…. Zip della release: 13c40254…
(commit f940170, SOURCE_DATE_EPOCH 1791923553), installato in Autopsy con gli stessi risultati delle prove (R1, R2).
Le prove sono nel registro (registro_prove_1.3.csv, 75 righe: requisito, previsione, effettivo, rispetta il requisito,
coincide con la previsione): 0 requisiti mancati, 3 previsioni mancate (H12b e T3 per la forma di un avviso; la prima
versione del controllo dei punteggi).
Sigle delle prove: AUT = Autopsy 4.23.1 (prove13.json; S1-S2 immagini, Z1-Z2 e R1-R2 zip), UNI = prove unitarie,
BAN = banchi, SIG = insieme sigillato, RAC = raccoglitore sull'immagine vera, RAM = processi delle due RAM vere,
PLA = soglie di plausibilità sugli output veri, ZIP = zip della release e controlli di GitHub Actions.

## V - Il verdetto (sezione 7)
- V1 Etichette senza probabilità: «Indicatori di compromissione», «Da verificare» (+ «priorità alta»), «Nessun indicatore trovato».
  → FATTA. UNI test_verdetto sez. 1, test_lingua (etichette nelle due lingue); AUT tutte le prove; BAN macchine (stessi verdetti della 1.2 con le etichette nuove).
- V2 Solo un segnale decisivo dà «Indicatori di compromissione»; segnali da confermare in due famiglie, da fenomeni diversi, danno «Da verificare, priorità alta».
  → FATTA. UNI test_verdetto sez. 1 e 3; SIG sig-032 (priorità alta); BAN puliti (azure senza i registri cancellati: priorità alta, non indicatori).
- V3 «Decisivo» ridefinito: di rado ha una spiegazione innocente e da solo giustifica l'esame; non è una prova (report e README).
  → FATTA. Motivo del verdetto nel report e nell'albero (AUT B5: «indicatori che di rado hanno una spiegazione innocente… Non sono una prova»); README, sezione del verdetto.
- V4 Strumenti trovati solo per nome: al massimo «da confermare», salvo prova d'esecuzione o informazioni di versione del file.
  → FATTA. UNI test_verdetto sez. 6.
- V5 Avviso quando manca Amcache.hve su Windows 8 e successivi.
  → FATTA. UNI test_verdetto sez. 7.
- V6 Intestazione nel report e nel README: «Verdetto euristico di triage: indica dove guardare prima. Non è una probabilità né una prova; la conclusione spetta all'analisi forense.»
  → FATTA. UNI test_lingua (avvertenza nel report it/en); README e README.it; messaggio nella posta in arrivo.
- V7 Punteggio di Autopsy e messaggi coerenti con le nuove etichette.
  → FATTA. Registro AUT «punteggio del verdetto»: ogni verdetto delle prove in Autopsy con il punteggio atteso (indicatori notevole; priorità e da verificare con segnali probabilmente notevole; il resto sconosciuto).

## E - Il lettore dei registri (sezione 18)
- E1 Leggere gli eventi scritti senza modello (BinXML in linea).
  → FATTA. UNI test_evtx sez. 2-3; BAN cieco: record non letti 0 su 12.812 (1.2: 1.681); SIG: 0 su 28.499.
- E2 Chiamare l'avviso con il nome giusto (oggi «danneggiato»).
  → FATTA. UNI test_evtx («non decodificato»); CHANGELOG.

## P - Falsi positivi dell'installazione (sezione 18), con la data di installazione
- P1 Account creato e aggiunto agli amministratori dall'account del computer durante il setup.
- P2 Servizio di un installer in una cartella temporanea durante l'installazione.
- P3 Comandi PowerShell in Base64 degli script che preparano la macchina (Packer) durante l'installazione.
  → P1-P3 FATTE. UNI test_verdetto sez. 4, test_tempi; BAN puliti: win11-client-2023 e win10-client senza i segnali dell'account e del Base64 di Packer, servizio di Malwarebytes come contesto.

## A - Accesso remoto (sezione 18)
- A1 TeamViewer, VNC e RDP da Internet: con V2 non portano più da soli al verdetto di compromissione (famiglie invariate).
  → FATTA. UNI test_verdetto (due famiglie da fatti diversi: priorità alta); BAN puliti: win11-client da verificare; azure senza i registri cancellati priorità alta.

## L - Lacune di rilevamento (sezione 18)
- L1 Servizi creati, manipolazione di account, offuscamento, movimento laterale RDP/DCOM/SSH, forza bruta, ricognizione: nel README come limiti. Regole nuove su questi temi solo con dati non usati per correggere (sezione 18, ultima riga; revisione: «le priorità non sono aggiungere firme»).
  → FATTA. README, Limiti (prima voce); nessuna regola nuova su questi temi.

## S - Dai registri di Silence of the RAM (sezione 18)
- S1 lsass.exe, services.exe, wininit.exe che avviano interpreti di comandi.
- S2 WerFaultSecure.exe lanciato con /pid contro un altro processo (EDR-Freeze).
- S3 Driver degli strumenti di acquisizione informativi (7045 e RAM) solo se coincidono percorso, hash del file e momento dell'acquisizione.
  → S1, S2 FATTE: UNI test_verdetto sez. 5, test_memoria; AUT B4 sui registri autentici. S3 FATTA con una riduzione: percorso e momento (mezz'ora dall'acquisizione della RAM abbinata) sì, hash no, perché il modulo non ha gli hash degli strumenti; il report chiede all'analista di controllarlo (CHANGELOG). UNI test_memoria; AUT B4 (MagnetRAMCapture da confermare con la nota).

## M - RAM su immagini vere (sezione 12)
- M1 README: che cosa è stato provato sulla RAM, limiti; Volatility 2.28.2.
  → FATTA. README, Valutazione (Memory) e Limiti; numeri da RAM processi_ram13.json.
- M2 Raccoglitore: messaggio chiaro quando Volatility non ha un plugin; avviso se la versione è più vecchia di quella provata.
  → FATTA. UNI test_collect_memory; RAC SR_241 (svcscan «NON DISPONIBILE», avviso sulla versione); AUT B2, B6, B9.
- M3 Report: spiegare il «?» delle connessioni senza processo.
  → FATTA. UNI test_memoria; AUT B1, H8.
- M4 SOSTITUITA (decisione del 12 ottobre: solo l'ultima versione di Volatility).
- M5 Regole nuove: ssh -D e -L come ssh -R («da confermare»); interprete di comandi figlio di uno strumento di rete a doppio uso; processo nella RAM con l'utente di un account appena creato o aggiunto agli amministratori.
  → FATTA. UNI test_memoria, test_verdetto sez. 5; AUT B1/B2 (shell da ncat decisiva, ssh -D), B5 (processi di servicemgmt); RAM: 3 su 11 processi d'attacco di TOTAL RECALL dalla sola RAM, 3 su 5 di Silence of the RAM con i registri, nessun benigno che conti.

## B - Abbinamento RAM-disco (sezione 13 e decisioni)
- B1 SOSTITUITA da B6. B2 SOSTITUITA da B7.
- B3 Una RAM va a una sola installazione: se ne trova più d'una, a nessuna, e il report lo dice.
  → FATTA. UNI test_memoria; AUT F5.
- B4 Nome dell'installazione dall'hive SYSTEM o dal campo Computer dei registri, mai dalla RAM; per riconoscere gli eventi della macchina, tutti i nomi che ha avuto.
  → FATTA. UNI test_verdetto sez. 4 e 8, test_memoria; AUT F3, F4.
- B5 In ogni indizio la sua origine (disco o RAM con SHA-256); nel verdetto i conteggi per origine e l'esito dei controlli; una nota per le RAM non usate.
  → FATTA. UNI test_memoria; AUT (colonne Origine e Conta del CSV in tutte le prove; note in F2, F4, F6).
- B6 L'abbinamento lo indica l'analista: stessa origine dati (una sola installazione), stesso host di Autopsy, oppure l'opzione nell'ingest del plugin. Niente abbinamento per nome fra origini diverse.
  → FATTA. UNI test_memoria; AUT B5, F2, F4, F4i, F4h, F6, F6i.
- B7 Controlli di compatibilità con gli artefatti già letti: build (famiglia di kernel), nome, avvio contro gli eventi di avvio di System, SID della macchina, ora dell'acquisizione contro il periodo dei registri. Se un controllo d'identità contraddice: avviso; gli indizi della RAM restano nel report, segnati, ma non contano per il verdetto.
  → FATTA. UNI test_memoria; AUT A3, F2i, F3, F4i, F6i, H0_12.
- B8 Nel report: quale RAM, chi l'ha indicata, l'esito di ogni controllo.
  → FATTA. AUT B5 (sezione «RAM: abbinamento e controlli»); immagini report-memory del README.

## D - Doppio conteggio (sezione 14)
- D1 Fenomeni: i segnali sullo stesso oggetto (processo, comando, file, attività, servizio, account, registro, blocco 4104) sono un fenomeno; due famiglie contano solo se vengono da fenomeni diversi.
  → FATTA. UNI test_verdetto sez. 2, 3 e 9 (visto-070: da verificare; 4104 e comando codificato; registro cancellato e wevtutil; account e 4720). Osservazione sui registri veri di Silence of the RAM (AUT B4): 12 fatti decisivi, cinque dei quali sono blocchi 4104 di stager non legati a un comando; un fatto è un oggetto, non un'azione (README, Limiti).
- D2 Per ogni fenomeno, dove è stato visto (RAM, 4688, Sysmon, Prefetch...).
  → FATTA. Tabella «Fatti» del report, colonna «Visto in» (AUT B4); colonna Fatto n. nel CSV e nell'albero.
- D3 Caratteristiche dello stesso oggetto che pesano insieme: regola esplicita con il suo peso.
  → FATTA. Le caratteristiche dello stesso oggetto non si sommano più (un fatto, D1); dove la combinazione pesa davvero è una regola con il suo peso (shell avviata da uno strumento di rete: decisiva, M5). UNI test_verdetto sez. 3 e 5.
- D4 Il report conta i fenomeni («3 fatti decisivi, 11 segnali»); le discordanze fra fonti hanno uno stato loro.
  → FATTA. UNI test_lingua (conteggi, singolare e plurale); AUT (conteggi nel verdetto; stato «discordanza fra fonti» in B6 e B10).

## H - Risultati mancanti e parziali (sezione 15)
- H1 Stato «parziale» nella tabella dei 41 controlli, con fonti usate e mancate; un controllo parziale o non verificabile per una fonte presente ma fallita conta come copertura insufficiente.
  → FATTA. UNI test_verdetto, test_memoria; AUT H0-H14, T3, T4 (H11: getsids non alimenta nessun controllo, «nessun indicatore» resta possibile; vedi deroghe13.json).
- H2 Plausibilità dell'output di Volatility: avviso «output anomalo o forse incompleto...»; gli indizi restano ma da soli non portano oltre «da verificare».
  → FATTA. UNI test_memoria; AUT B10, B11, H6; soglie sugli output veri senza falsi allarmi (registro PLA).
- H3 Righe e SHA-256 di ogni output contro il manifesto; leggere «complete».
  → FATTA. UNI test_memoria sez. 7; AUT H7, H13, H13b.
- H4 Le stesse soglie nel raccoglitore (non scrivere «10 su 10» su un'immagine dimezzata).
  → FATTA. UNI test_collect_memory (8 e 8b); RAC SR_troncata_2282 e _en («10 su 10, ma il loro output sembra anomalo», anomalie nella lingua dell'utente). Il raccoglitore definitivo corregge due difetti trovati dalla prova sull'immagine tagliata vera: il riepilogo scriveva ancora «10 su 10» da solo e le anomalie erano in inglese nel riepilogo italiano.
- H5 Nota su svcscan con il registro presente: i servizi solo in memoria non si controllano (17 e 29 parziali).
  → FATTA. AUT H10, B6, B9.

## C - Configurazioni (sezione 16 e decisioni)
- C1 README: solo le ultime versioni (Autopsy 4.23.1, Volatility 3 2.28.2).
  → FATTA. README, Requisiti e Compatibilità.
- C2 Raccoglitore: controllo preliminare (Python, Volatility, plugin caricabili, simboli, spazio), esito nel manifesto.
  → FATTA. UNI test_collect_memory; RAC SR_2282 (preflight nel manifesto); AUT B8.
- C3 CI: raccoglitore con Python 3.8 e con l'ultima; ricostruzione dello zip confrontata con quello allegato; SHA-256 nelle note di release.
  → FATTA nel repository (.github/workflows/checks.yml); qui provati gli stessi passi su una copia pulita del commit finale (Python 3.8, 3.11, 3.12, 3.13; Jython 2.7.4), e lo zip riprodotto byte per byte da un clone e dalla cronologia che crea il kit per GitHub (registro ZIP); SHA-256 nelle note di release (note-release/v1.3.md). Il flusso su GitHub gira al primo invio: da guardare la prima volta.
- C4 CHANGELOG: correggere la frase della 1.2 sull'avviso per i plugin senza risultati.
  → FATTA. CHANGELOG, 1.2.

## J - Prima dell'uso professionale (sezione 17)
- J1 Ripiego netstat: dirlo nel report e nel riepilogo del raccoglitore; 5 e 7 parziali.
  → FATTA. UNI test_memoria, test_collect_memory; AUT H12b, T3. Incoerenza di forma da uniformare dopo: questo avviso nomina i plugin per esteso (windows.netstat.NetStat), gli altri con il nome breve.
- J2 Motivo del fallimento dal manifesto; file non riconosciuto: «non è un'immagine di memoria di Windows, o mancano i simboli»; nessuna nota «risultati usati» senza risultati.
  → FATTA. UNI test_memoria; AUT B3, T5, H14.
- J3 SOSTITUITA da B6-B7.
- J4 Registro delle prove rifatto sullo zip della 1.3 con lo SHA-256 del codice; caso pulito autentico: da acquisire (SCHEDA_PULITA.txt).
  → Registro FATTO (registro_prove_1.3.csv, rifatto sullo zip finale: righe ZIP e AUT R1-R2). Caso pulito autentico RINVIATO: va acquisito su una macchina vera (SCHEDA_PULITA.txt); senza, «nessun indicatore trovato» con la RAM non ha una misura (README).

## R - Revisione esterna
- R1 = V. R2 = H, J. R3 = E. R4 = B.
- R5 Sistemi completi indipendenti e benigni difficili: non disponibili qui; procedura nel kit.
  → RINVIATA (dati non disponibili); README, Valutazione: «Not measured».
- R6 Prove su Windows: protocollo in inglese (docs/windows-test.md) per l'utente.
  → FATTA la procedura (docs/windows-test.md e la scheda CSV, anche nello zip); la prova su Windows resta da fare.
- R7 Set sigillato: controllare provenienza e sovrapposizione degli eventi prima di usarlo; usarlo una volta; poi è consumato.
  → FATTA. SIG: 37 campioni, nessun evento né nome in comune con i 2.025 file usati; protocollo scritto prima; una sola esecuzione con il codice definitivo. Ora è consumato.
- R8 Registro: colonna «requisito» separata da «previsto dal codice».
  → FATTA (registro13.py). deroghe13.json spiega le prove in cui il requisito del gruppo va letto con una nota (H8, H11) e quelle in cui la previsione non coincide ma il requisito è rispettato (H12b, T3).

## T - Strumenti e documenti (proposta di README della critica D)
- T1 tools/verify_case.py in inglese.
  → FATTA. Usato in tutte le prove in Autopsy (C1-C5).
- T2 docs/windows-test.md.
  → FATTA.
- T3 Troubleshooting: modulo non trovato dopo la rimozione; due istanze di Autopsy insieme.
  → FATTA. README, Troubleshooting.
