# Versione 1.3: correzioni e prove

13 ottobre 2026 · Davide Numelli

> Scheda «Versione 1.3» del documento di valutazione, esportata il 20 ottobre 2026: «questa valutazione» e «questo documento» sono la [valutazione della 1.2](../2026-10-11-valutazione-1.2/valutazione-1.2.md); `PIANO_1.3.md` è [piano-1.3.md](piano-1.3.md); il registro è [registro-prove-1.3.csv](registro-prove-1.3.csv).

La versione 1.3 applica le correzioni di questa valutazione (sezione 18 e decisioni del 12 e 13 ottobre). Il verdetto non suggerisce più una probabilità; i segnali sullo stesso oggetto contano come un fatto solo; la RAM si abbina al disco solo come dice l'analista, e l'abbinamento viene controllato; il report dice quando i risultati di Volatility sono parziali o non plausibili; il lettore dei registri legge gli eventi scritti senza modello. Tutte le voci del piano sono fatte, tranne quattro sostituite da una decisione (M4, B1, B2, J3) e due rinviate perché mancano i dati: un caso pulito autentico con la sua RAM e macchine intere da fonti indipendenti. Il codice del plugin è stato congelato prima delle prove (impronta `dd27cc9f…` dei 17 file .py) ed è lo stesso in tutte: prove unitarie, banchi, insieme sigillato, 45 prove pianificate dentro Autopsy 4.23.1 e lo zip della release, installato in Autopsy con gli stessi risultati. Il registro delle prove ha 75 righe: nessun requisito mancato, tre previsioni mancate solo nella forma. Windows resta da provare.

## Che cosa cambia

Tra parentesi le voci del piano; l'esito e la prova di ciascuna sono in `PIANO_1.3.md`, nel kit delle prove.

- **Verdetto** (V1-V7). «Indicatori di compromissione» con almeno un fatto decisivo; «Da verificare, priorità alta» con segnali da confermare in due famiglie, da fatti diversi; «Da verificare»; «Nessun indicatore trovato». In testa al report e nel messaggio: *Verdetto euristico di triage: indica dove guardare prima. Non è una probabilità né una prova; la conclusione spetta all'analisi forense.* «Decisivo» vuol dire che di rado ha una spiegazione innocente e da solo giustifica l'esame; il punteggio di Autopsy segue l'etichetta. Uno strumento trovato solo per nome è al massimo «da confermare»; manca Amcache.hve su Windows 8 o successivo: avviso.
- **Fatti** (D1-D4). I segnali sullo stesso oggetto (processo, comando, file, attività, servizio, account, indirizzo, registro, blocco di script) sono un fatto; due famiglie contano solo se vengono da fatti diversi. Il report conta i fatti e ha la tabella *Fatti* con dove è stato visto ciascuno. Un fatto è un oggetto, non un'azione: sui registri veri di Silence of the RAM i fatti decisivi sono 12, e cinque sono blocchi 4104 di stager che il modulo non lega al comando che li ha lanciati (scritto tra i limiti del README).
- **Registri eventi** (E1-E2). Gli eventi scritti senza modello ora si leggono: nel set cieco 0 record persi su 12.812 (la 1.2 ne perdeva 1.681); l'avviso non dice più «danneggiato».
- **Installazione di Windows e accesso remoto** (P1-P3, A1). Durante l'installazione, l'account creato dall'account del computer, il servizio temporaneo dell'installer e gli script di preparazione (Packer) sono contesto; due programmi di accesso remoto da soli non danno più il verdetto più forte.
- **Regole nuove** (S1, S2, M5). `lsass.exe` e `wininit.exe` che avviano un interprete di comandi (decisivo), `services.exe` che avvia una shell (da confermare), EDR-Freeze (`WerFaultSecure.exe /pid` contro un altro processo), shell avviata da netcat, ncat o socat (decisiva), `ssh -L` e `-D` come `ssh -R`, processi nella RAM con l'utente di un account appena creato o aggiunto agli amministratori. S3 è fatta con una riduzione: il driver di uno strumento di acquisizione è contesto solo se coincidono percorso e momento dell'acquisizione; l'hash non si confronta, perché il modulo non ha gli hash degli strumenti, e il report chiede all'analista di controllarlo.
- **RAM, abbinamento** (B3-B8). Lo indica l'analista: stessa origine dati con una sola installazione, stesso host di Autopsy, oppure l'impostazione *RAM* del modulo; nessun abbinamento per nome. Il modulo controlla build, nome, avvio, SID della macchina e ora dell'acquisizione; se build, avvio o SID contraddicono la scelta, gli indizi della RAM restano nel report ma non contano. Il report ha la sezione *RAM: abbinamento e controlli*.
- **RAM, risultati parziali e non plausibili** (H1-H5, J1, J2, M3). Stato *Parziale* nella tabella dei 41 controlli; un output sotto quello che un Windows acceso ha sempre dà l'avviso *output anomalo o forse incompleto* e non porta oltre «da verificare»; righe e SHA-256 di ogni output confrontati con il manifesto; il ripiego su netstat e la mancanza di svcscan sono detti, con i controlli parziali; il motivo di un fallimento viene dal manifesto; il «?» delle connessioni senza processo è spiegato.
- **Raccoglitore 1.3** (M2, C2, H4). Controllo preliminare registrato nel manifesto; un plugin che Volatility non ha è saltato con un messaggio chiaro; le stesse soglie del modulo, e su un'immagine dimezzata il riepilogo non scrive più «10 su 10» da solo.
- **Strumenti e documenti** (T1-T3, C1, C3, C4, L1, M1). `tools/verify_case.py`, la procedura di prova su Windows con la sua scheda, lo zip riproducibile e i controlli di GitHub Actions; il README con i numeri della 1.3, i limiti e solo le versioni provate (Autopsy 4.23.1, Volatility 3 2.28.2, Python 3.8 o successivo). Nessuna regola nuova per le lacune della sezione 4: andranno misurate su dati non usati per scriverle.

## Numeri: 1.2 contro 1.3

Stessi dati e stessi criteri della sezione 3 («nell'ambito»: il campione contiene almeno un evento letto dalle regole; intervalli di Wilson al 95%). Il codice è quello congelato.

| Che cosa | Dati | 1.2 | 1.3 |
| --- | --- | --- | --- |
| Campioni d'attacco con almeno un segnale da confermare o decisivo | 161 registri nell'ambito, set cieco | 88 (55%) | 90 (56%, 48-63%) |
| ... con un segnale per la tecnica dell'etichetta | gli stessi | 70 (43%) | 72 (45%, 37-52%) |
| ... con il verdetto più forte, per la tecnica | gli stessi | 26 (16%) | 26 (16%, 11-23%) |
| ... senza nessun segnale | gli stessi | 73 (45%) | 71 (44%, 37-52%) |
| Record che il modulo non decodifica | 12.812 record del set cieco | 1.681 (13%) | 0 |
| Set visto: campioni con almeno un segnale | 196 nell'ambito | 74 (38%) | 76 (39%, 32-46%) |
| Installazioni pulite con il verdetto più forte | 7 di evtx-baseline | 3 | 2 |
| Installazioni pulite con segnali da confermare o decisivi | le stesse | 4 | 4 |
| Processi dell'attacco segnalati, TOTAL RECALL (Windows 11), dalla sola RAM | 11 | 1 | 3 |
| Processi dell'attacco segnalati, Silence of the RAM (Windows 10) | 5 | 0 | 0 dalla sola RAM, 3 con i registri eventi |
| Processi benigni segnalati che contano, Volatility 2.28.2 | 360 | 0 | 0 |
| Processi benigni segnalati che contano, Volatility 2.4.1 | 358 | 1 | 0 |

Come leggerli. I numeri sui campioni d'attacco quasi non cambiano: la 1.3 non aggiunge regole per le tecniche che sfuggono, e la regola nuova del verdetto (solo un fatto decisivo dà «indicatori») lascia il verdetto più forte dov'era. Sulle installazioni pulite il verdetto più forte resta su due, entrambe per i registri cancellati da chi ha preparato i dati: senza quei registri non resterebbe su nessuna, e una delle due (RDP da un indirizzo pubblico e due programmi di accesso remoto) sarebbe «da verificare, priorità alta». Sulla RAM i processi segnalati in più sono la shell avviata da ncat (decisiva), ncat e il tunnel `ssh -D` (da confermare) su TOTAL RECALL, e i processi dell'account `servicemgmt` creato dall'attaccante su Silence of the RAM, che si vedono solo con i registri eventi. Con Volatility 2.4.1 il `svchost.exe` *forse nascosto* resta nel report come discordanza fra fonti e non conta. Le macchine intere della sezione 8 hanno gli stessi verdetti della 1.2 con le etichette nuove. Questi insiemi hanno guidato le correzioni: i loro numeri dicono che le correzioni funzionano lì, non come va il modulo su dati nuovi.

## Insieme sigillato

È l'unica misura su dati che non hanno guidato nessuna correzione. Sono 37 registri eventi di attacchi della raccolta hayabusa-sample-evtx (DeepBlueCLI e Yamato Security), scelti prima di qualsiasi modifica. Prima di usarli ho controllato provenienza e sovrapposizione: nessun evento e nessun nome di file in comune con i 2.025 file già usati per sviluppare o misurare. Il protocollo, con i criteri, è stato scritto prima dell'esecuzione, con il suo SHA-256 registrato; l'esecuzione è stata una sola, con il codice definitivo, e l'insieme ora è consumato.

| Che cosa | 1.3 |
| --- | --- |
| Campioni, di cui nell'ambito | 37, 33 |
| Record non decodificati | 0 su 28.499 |
| Nell'ambito con almeno un segnale da confermare o decisivo | 25 (76%, 59-87%) |
| ... con un segnale per la tecnica dell'etichetta | 16 (48%, 33-65%) |
| ... con il verdetto più forte | 20 (61%, 44-75%) |
| ... con il verdetto più forte, per la tecnica | 11 (33%, 20-50%) |
| ... «da verificare, priorità alta» | 1 (3%, 1-15%) |
| ... senza nessun segnale | 8 (24%, 13-41%) |
| Fuori dall'ambito con segnali | 0 su 4 |

Va meglio del set cieco, ma è piccolo e viene da una sola raccolta, con tre campioni molto più grandi degli altri (da 2.216 a 13.223 record). E c'è lo stesso artefatto delle installazioni pulite: un registro Security cancellato all'inizio della registrazione, che l'etichetta non nomina, basta per il verdetto più forte. Dei 20 campioni che lo ricevono, 9 lo devono solo a quello, e i numeri «per la tecnica» li lasciano fuori. Un campione su quattro nell'ambito non dà nessun segnale: il verdetto negativo continua a non escludere un attacco.

## Prove in Autopsy 4.23.1, zip e registro

Ogni prova pianificata ha il requisito, la previsione scritta prima di eseguirla e le attese che uno script controlla dopo. Ogni esecuzione installa il plugin dallo zip, crea il caso da riga di comando, esegue il modulo e controlla il caso con `verify_case.py` (modulo caricato, analisi completata, nessun errore del modulo, conteggi coerenti, report). Le 45 prove coprono l'immagine disco e i file logici con due installazioni, con i report in italiano e in inglese (nei report inglesi nessun testo italiano); le due RAM vere, da sole e con i registri, con Volatility 2.28.2 e 2.4.1; l'immagine tagliata a metà; i guasti costruiti (plugin falliti, fermati o assenti, output mancanti, troncati, vuoti o diversi dal manifesto, manifesto danneggiato, raccolte interrotte, file che Volatility non riconosce) e quelli veri (timeout, Ctrl+C, un file che non è memoria); l'abbinamento (stessa origine, stesso host, impostazione del modulo, RAM contraddetta da build, avvio e SID, una RAM per due installazioni, RAM di un altro host con lo stesso nome).

- **Esiti.** Tutte le 45 superano i controlli di `verify_case.py`; 43 rispettano tutte le attese. Nelle altre due (H12b, T3) l'avviso sul ripiego su netstat dice ciò che deve, ma nomina i plugin per esteso (`windows.netstat.NetStat`) dove l'attesa aveva il nome breve, usato dagli altri avvisi: da uniformare nella prossima versione. In tutte le 51 esecuzioni (60 verdetti) il punteggio di Autopsy segue l'etichetta.
- **Lo zip.** Rifatto da un clone del repository e dalla cronologia che il kit crea per GitHub, è identico byte per byte (`13c40254…`); i 17 .py dentro hanno l'impronta del codice provato. Installato in Autopsy (prove R1 e R2) dà gli stessi verdetti, gli stessi segnali, lo stesso CSV e lo stesso report HTML, salvo data, caso e durata, delle prove A1 e B5.
- **Il registro** (`registro-prove-1.3.csv`, 75 righe) tiene separati «rispetta il requisito» e «coincide con la previsione»: nessun requisito mancato, tre previsioni mancate (H12b e T3 per il nome del plugin; la prima versione del controllo dei punteggi, che non contava i segnali limitati di una RAM anomala).
- **Due prove da leggere con una nota.** H8: le connessioni senza processo sono un limite noto di Volatility, non un guasto, e il requisito è spiegare il «?». H11: getsids fallito dà una nota e lascia possibile «nessun indicatore trovato», perché getsids non alimenta nessuno dei 41 controlli (serve al controllo del SID nell'abbinamento, che il report dice non fattibile); era così anche nella 1.2. Letto alla lettera, il requisito del gruppo («mai nessun indicatore con un risultato della RAM fallito») vorrebbe «da verificare» anche qui: è una scelta da confermare.

## Che cosa resta

1. **La prova su Windows.** La procedura è `docs/windows-test.md` (circa mezz'ora per postazione, finisce con `verify_case.py`), con la scheda da compilare. Finché non c'è, il modulo è provato solo su Linux.
2. **Un caso pulito autentico con la sua RAM**, acquisito con il disco della stessa macchina e documentato con la scheda della sezione 17: senza, «nessun indicatore trovato» con la RAM non ha una misura.
3. **Macchine intere da fonti indipendenti**, compromesse, pulite e benigne difficili (sezione 20): il verdetto su una macchina intera non ha ancora un tasso d'errore misurato.
4. **Le lacune di rilevamento** della sezione 4 (servizi creati, manipolazione di account, offuscamento, movimento laterale, forza bruta, ricognizione): regole nuove solo con dati nuovi su cui misurarle. L'insieme sigillato è consumato: per la prossima versione ne serve un altro.
5. **La prima esecuzione dei controlli di GitHub Actions**, alla pubblicazione: i passi sono stati provati qui, ma non su GitHub, e il download di Jython da Maven Central non era raggiungibile da questo ambiente.
6. **Due scelte piccole.** Se getsids fallito debba impedire «nessun indicatore trovato» (H11); i nomi dei plugin nell'avviso sul ripiego su netstat, da rendere uguali a quelli degli altri avvisi.

## Consegna

| File | Che cos'è | SHA-256 |
| --- | --- | --- |
| `TriageCompromissione-1.3.zip` | il plugin, da allegare alla release (con il raccoglitore, `verify_case.py` e la procedura per Windows) | `13c40254bd7855316235c8fdbf07190cd936c17450a4720fcdf5027d058b82a9` |
| `collect_memory.py` | il raccoglitore 1.3 | `4e3c566401442ae0d1268a159885feaad69158afdf5f657d8608de790bbed1ba` |
| `verify_case.py` | il controllo di un caso dopo l'analisi | `873a6bfac5f73a84d55d9245e6da1c1cf3cb3bed14eea22b150b9cb6a9d009f0` |
| `autopsy-windows-compromise-triage-1.3.zip` | il repository alla versione 1.3 |  |
| `cronologia-github.zip` | il kit per GitHub con le quattro versioni, le note della release e gli allegati della v1.3 |  |
| `verifica-1.3.zip` | le prove: piano con gli esiti, registro, script, risultati |  |

Nel kit per GitHub il commit della 1.3 ha la data del 13 ottobre, 22:32:33: è la data dei file dentro lo zip, e i controlli di GitHub Actions rifanno lo zip dal tag con quella data, quindi non va cambiata. Lo script del kit, provato dallo zip estratto, crea la cronologia da cui lo zip si rifà identico. Alla release v1.3 vanno allegati anche la valutazione della 1.2 (questo documento, esportato) e il registro delle prove; il kit della valutazione 1.2 resta fuori, perché contiene copie di dati di terzi e i percorsi della macchina della misura.
