# Valutazione di Windows Compromise Triage 1.2

11 ottobre 2026 · Davide Numelli

> Il kit che il testo chiama «lo zip» (`valutazione-1.2.zip`: script del banco, dati e risultati caso per caso) non è pubblicato: contiene copie di dati di terzi e i percorsi della macchina su cui è stata fatta la misura.

Su registri di eventi con etichette scritte da altri, il plugin segnala per la tecnica giusta 70 dei 161 campioni d'attacco che contengono almeno un evento letto dalle sue regole (43%) e arriva al verdetto «compromissione probabile» in 26 (16%). Sulle 7 installazioni pulite nuove dà 3 verdetti di compromissione sbagliati. Sui dati mai visti va peggio che su quelli dello sviluppo: il lettore dei registri perde il 13% dei record e compaiono falsi positivi che le correzioni non prevedevano. È veloce e finisce anche con l'heap Java limitato a 512 MB (il processo arriva a circa 690 MB), ma il suo verdetto negativo non basta a escludere un attacco, e quello positivo è un giudizio euristico di triage, non una probabilità (sezione 7). Dentro Autopsy dà gli stessi risultati in tutte le versioni dalla 4.19.0 alla 4.23.1, ma l'ho provato solo su Linux (sezioni 11 e 16); sulla RAM di due macchine vere riporta fedelmente i dati di Volatility, ma segnala poco (sezione 12), e la abbina al disco solo per nome, così può unire macchine diverse (sezione 13). Il verdetto non somma punteggi, ma la regola delle due famiglie a volte conta due volte lo stesso fatto (sezione 14). I risultati della RAM falliti sono segnalati, quelli parziali no (sezione 15). Per usare la RAM nel lavoro mancano ancora un caso pulito autentico, un abbinamento che non si fermi al nome e l'avviso per due guasti che oggi passano in silenzio (sezione 17).

## 1. La critica è fondata

Prima di oggi non c'era un numero di attacchi rilevati, sfuggiti o di falsi positivi. C'erano test di regressione: dicono se il comportamento cambia tra una versione e l'altra, non quanto il plugin rileva.

In più c'era un problema che la critica non nomina. Molti casi di prova li ho scritti io, insieme alle regole che dovevano scattare su quei casi. Un numero calcolato lì sarebbe stato ottimista per costruzione.

Per questo ho misurato su dati con etichette scritte da altri:

- 571 registri di eventi d'attacco, di cui 293 mai usati nello sviluppo;
- 7 installazioni pulite di Windows;
- 9 macchine ricostruite da artefatti pubblici, già usate nello sviluppo e quindi tenute a parte.

Il plugin è la versione 1.2, senza modifiche: né le regole né il lettore dei registri sono stati toccati durante la misura. I criteri di rilevamento li ho fissati prima di guardare i risultati (sezione 3).

## 2. Dati e verità di riferimento

Le etichette (attacco o pulito, tattica, tecnica) le hanno scritte gli autori dei dataset, non io.

| Insieme | Che cosa contiene | Etichette | Usato nello sviluppo | Casi |
| --- | --- | --- | --- | --- |
| Set cieco: [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | Registri di eventi, uno per tecnica d'attacco | Tattica e tecnica ATT&CK, dall'autore | No | 293 |
| Set visto: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Registri di eventi d'attacco | Tattica, dall'autore | Sì: per provare il lettore dei registri; 3 file sono nella regressione | 278 |
| Sistemi puliti: [evtx-baseline](https://github.com/NextronSystems/evtx-baseline) di Nextron | Tutti i registri di 7 installazioni pulite (Windows 7, 10, 11, Server 2022) con software installato e un po' di uso | Puliti per costruzione | No | 7 |
| Macchine: [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) e caso Stolen Szechuan Sauce di DFIR Madness | Registro di sistema, eventi, Prefetch, Amcache, attività di 9 macchine | Dal nome e dalla descrizione del caso | Sì: sono la regressione | 9 |
| Scenari della RAM | Uscite di Volatility costruite da me | Mie | Sì | 7, solo per i tempi |

Ogni campione d'attacco è stato esaminato da solo, come origine dati a sé, con un nome neutro (`campione.evtx`): il nome originale descrive l'attacco e non doveva poter influire sul risultato.

## 3. Quanti attacchi vengono rilevati

Nel set mai visto il plugin segnala 70 dei 161 campioni che può leggere per la tecnica giusta, e dà il verdetto di compromissione in 26.

Criteri, fissati prima della misura:

- **Segnalato:** almeno un segnale *da confermare* o *decisivo*.
- **Verdetto:** il plugin conclude «compromissione probabile».
- **Nell'ambito:** il campione contiene almeno un evento che le regole del plugin leggono. Gli eventi li ho contati con un lettore EVTX indipendente, non con quello del plugin. I campioni fuori ambito (eventi Kerberos, firewall, replica di Active Directory, Sysmon diversi dalla creazione di processi) il plugin non può rilevarli per costruzione.
- **Per la tecnica:** 34 campioni del set cieco contengono un evento di log cancellato e il plugin lo segnala; in 32 non fa parte della tecnica dell'etichetta, è probabilmente la pulizia fatta da chi ha preparato il campione. Se il campione non riguarda proprio la cancellazione dei log, quel segnale non conta.

|  | Set cieco (mai visto) | Set visto |
| --- | --- | --- |
| Campioni | 293 | 278 |
| Nell'ambito delle regole | 161 | 196 |
| Segnalati | 88 (55%, IC95 47–62%) | 74 (38%, 31–45%) |
| Segnalati per la tecnica | **70 (43%, 36–51%)** | **54 (28%, 22–34%)** |
| Verdetto di compromissione | 51 (32%, 25–39%) | 50 (26%, 20–32%) |
| Verdetto di compromissione per la tecnica | **26 (16%, 11–23%)** | **28 (14%, 10–20%)** |
| Segnalati tra i fuori ambito | 0 su 132 | 0 su 82 |

Percentuali sui campioni nell'ambito; gli intervalli sono di Wilson al 95%. Contando anche i fuori ambito, il set cieco scende a 70 su 293 (24%). «Nell'ambito» vuol dire che il campione contiene almeno un evento letto dalle regole, non che la tecnica si veda in quegli eventi: queste percentuali misurano la copertura sul corpus, non la sensibilità sulle tecniche che il plugin dichiara. Gli intervalli misurano l'incertezza del conteggio, non la rappresentatività: i campioni vengono da poche raccolte e da pochi autori.

Il set visto va peggio del cieco. Era servito a provare il lettore, non le regole, e ha molti campioni di Sysmon in cui l'attacco sta in eventi che il plugin non legge (accesso a processi, modifiche al registro), accanto a creazioni di processi innocue.

*Per tattica: bene l’esecuzione, male ricognizione, movimento laterale e privilegi.* Campioni del set cieco nell’ambito segnalati per la tecnica, con l’intervallo di Wilson al 95%. Nel documento originale questi numeri sono un grafico.

| Tattica | Segnalati per la tecnica | Quota | IC95 |
| --- | --- | --- | --- |
| Impatto (TA0040) | 3 su 3 | 100% | 44–100% |
| Comando e controllo (TA0011) | 1 su 1 | 100% | 21–100% |
| Catena APT completa (11 passi) | 8 su 9 | 89% | 56–98% |
| Esecuzione (TA0002) | 12 su 18 | 67% | 44–84% |
| Persistenza (TA0003) | 20 su 40 | 50% | 35–65% |
| Elusione delle difese (TA0005) | 12 su 25 | 48% | 30–67% |
| Accesso alle credenziali (TA0006) | 8 su 21 | 38% | 21–59% |
| Movimento laterale (TA0008) | 2 su 12 | 17% | 5–45% |
| Ricognizione (TA0007) | 3 su 20 | 15% | 5–36% |
| Escalation dei privilegi (TA0004) | 1 su 9 | 11% | 2–44% |
| Accesso iniziale (TA0001) | 0 su 2 | 0% | 0–66% |
| Antivirus | 0 su 1 | 0% | 0–79% |
| **Tutte le tattiche** | **70 su 161** | **43%** | 36–51% |

Le tattiche con pochi campioni hanno intervalli larghi: Impatto e Comando e controllo sono al 100% su 3 campioni e su 1, e dicono poco.

## 4. Quanti sfuggono e perché

Nel set cieco 73 dei 161 campioni nell'ambito non danno nessun segnale. Altri 18 sono segnalati solo per log cancellati che con la tecnica non c'entrano: non sono un silenzio, ma nemmeno un rilevamento, perché il plugin ha visto qualcosa ma non l'attacco. Per la tecnica sfuggono quindi 91 campioni. I 73 senza segnale hanno due cause:

- **Il lettore dei registri (9 campioni).** Alcuni file scrivono gli eventi senza modello, con l'XML binario in linea: è un formato valido, ma il lettore del plugin gestisce solo gli eventi con modello. Nel set cieco perde 1.681 record su 12.812 (13%) in 15 campioni. Il plugin avvisa e non conclude «nessun indizio», ma chiama il file «danneggiato», e non lo è. Nel set visto, usato per provare il lettore, i record persi sono zero: è l'effetto di averlo provato su quei file.
- **Le regole (64 campioni).** Gli eventi ci sono e il plugin li legge, ma nessuna regola li giudica sospetti. In 19 di questi il report mostra comunque i dati nelle sue tabelle (accessi, servizi, attività), senza un segnale.

Le tecniche dove sfugge di più, contando i campioni nell'ambito:

| Tecnica (ATT&CK) | Sfuggiti / nell'ambito |
| --- | --- |
| Servizi creati o modificati (T1543.003) | 7 / 16 |
| Manipolazione di account (T1098) | 5 / 9 |
| File o comandi offuscati (T1027) | 5 / 5 |
| Ricognizione di account e gruppi (T1087, T1069) | 7 / 10 |
| Movimento laterale con RDP, DCOM e SSH (T1021.001, .003, .004) | 6 / 6 |
| Furto di credenziali (T1003) | 5 / 13 |
| Forza bruta (T1110) | 2 / 3 |

Il dettaglio di tutte le 69 tecniche è nella seconda scheda, *Per tecnica (set cieco)*.

## 5. Quanti sistemi puliti vengono segnalati

Sulle 7 installazioni pulite di evtx-baseline, mai usate nello sviluppo, il plugin dà 3 verdetti di compromissione sbagliati e segnali da confermare o decisivi in 4. Le altre 3 macchine della tabella le avevo già usate nello sviluppo, e di loro si sa solo che non hanno attacchi documentati: servono come controllo di regressione, non come misura. Le esecuzioni ripetute danno lo stesso risultato, quindi i falsi positivi per esecuzione coincidono con quelli per sistema.

| Sistema | Registri | Eventi | Segnali da confermare o decisivi | Verdetto | Da che cosa vengono |
| --- | --- | --- | --- | --- | --- |
| Windows 7 x86 | 138 MB | 130.028 | 0 | Da verificare | — |
| Server 2022 | 303 MB | 242.133 | 0 | Da verificare | — |
| Server 2022, controller di dominio | 584 MB | 451.934 | 0 | Da verificare | — |
| Windows 10 client | 836 MB | 784.156 | 3 | **Compromissione probabile** | Account creato e aggiunto agli amministratori durante l'installazione; log di Sysmon cancellato |
| Windows 11 client | 1,7 GB | 1.758.047 | 1 | Da verificare | TeamViewer installato |
| Server 2022 su Azure | 2,2 GB | 1.450.883 | 4 | **Compromissione probabile** | Log cancellati dall'amministratore; sessione RDP da un indirizzo pubblico; VNC e TeamViewer installati |
| Windows 11 client (2023) | 2,5 GB | 1.794.003 | 7 | **Compromissione probabile** | Log cancellati, anche il Security; account creato all'installazione; servizio di un installer in una cartella temporanea; comandi PowerShell in Base64 degli script di Packer che hanno preparato la macchina; TeamViewer |
| RathbunVM, Windows 10 | 190 MB, macchina intera | — | 0 | Da verificare | — |
| RathbunVM, Windows 11 | 194 MB, macchina intera | — | 0 | Nessun indizio | — |
| Hive di prova di Windows 7 | 64 MB, solo registro | — | 0 | Da verificare | — |

I primi 7 sono le installazioni di evtx-baseline, gli ultimi 3 le macchine senza attacchi documentati del DFIR Artifact Museum e degli strumenti di Eric Zimmerman. Nei sistemi di soli registri di eventi il verdetto «da verificare» viene dagli avvisi di copertura (manca il registro di sistema), non da un segnale.

In tutti e tre i verdetti sbagliati ci sono log cancellati da chi ha preparato i dati. Il plugin considera decisiva la cancellazione dei registri principali, e su una macchina reale andrebbe comunque spiegata. Togliendo quei segnali, il Windows 10 scende a «da verificare» e restano 2 verdetti sbagliati su 7: il server su Azure (RDP da Internet e due programmi di accesso remoto) e il Windows 11 del 2023.

## 6. Il verdetto è affidabile?

Il verdetto positivo è un'indicazione utile ma non infallibile; quello negativo non basta a escludere un attacco. Le misure sono separate, perché contano cose diverse: un campione d'attacco è un registro di pochi minuti con una tecnica, un'installazione pulita sono ore o giorni di registri. Tra parentesi i valori per la tecnica: senza i log cancellati estranei sugli attacchi e senza i log cancellati dai preparatori sui sistemi puliti.

| Misura | Su che cosa | Con segnali | «Compromissione probabile» |
| --- | --- | --- | --- |
| Rilevamento | 161 campioni EVTX d'attacco nell'ambito | 88 (70): 55% (43%) | 51 (26): 32% (16%) |
| Falsi allarmi | 7 installazioni pulite nuove | 4 su 7 (4) | 3 su 7 (2) |
| Regressione | 3 macchine pulite già usate nello sviluppo | 0 | 0 |
| Verdetto su macchine intere | sistemi completi indipendenti, compromessi e puliti | da misurare | da misurare |

Gli intervalli di Wilson al 95% sono 47–62% (36–51%) e 25–39% (11–23%) per il rilevamento; 25–84% e 16–75% (8–64%) per i falsi allarmi. Misurano l'incertezza del conteggio, non la rappresentatività: i campioni vengono da poche raccolte e da pochi autori, e non sono indipendenti.

Come leggerle:

- Su un solo registro di eventi con una sola tecnica, il verdetto di compromissione scatta raramente. Il verdetto è fatto per sommare prove di tipi diversi (registro di sistema, file, eventi), e un campione ne offre poche. È però proprio il caso di un attacco che lascia poche tracce.
- «Nessun indizio» e «da verificare» non escludono un attacco: il 45% dei campioni d'attacco nell'ambito non porta a nessun segnale, il 57% se si guarda la tecnica. Il README lo deve dire con questi numeri.
- I falsi positivi sui sistemi puliti hanno cause precise e correggibili (sezione 18), ma 7 installazioni sono poche per stimarne la frequenza.
- La precisione non la calcolo: dipende da quanti sistemi compromessi ci sono nella realtà, e qui il rapporto fra campioni d'attacco e installazioni pulite è arbitrario.
- Il verdetto su una macchina intera, compromessa o pulita, non è ancora misurato: serve un insieme di sistemi completi indipendenti (sezione 20).

## 7. Che cosa significa il verdetto

Il verdetto è un giudizio euristico di triage: dice quali macchine esaminare per prime, non la probabilità che siano compromesse. Nessuna calibrazione lo sostiene, e i dati di questa misura mostrano che l'etichetta attuale, «compromissione probabile», promette troppo.

| Principio | Che cosa fa il plugin oggi | Esito |
| --- | --- | --- |
| Un nome non prova l'esecuzione | Il testo distingue «eseguito» da «presente sul disco (non è una prova di esecuzione)», ma il peso no: uno strumento trovato solo per nome sul disco può valere «decisivo» da solo | Da correggere |
| Un comando non prova il successo | I comandi visti negli eventi di avvio dei processi e negli script contano «da confermare»; resta «decisivo» solo ciò che non ha usi amministrativi | Coerente |
| Un'attività anomala può essere legittima | Due segnali «da confermare» in famiglie diverse bastano per «compromissione probabile». Senza i log cancellati dai preparatori, i 2 verdetti sbagliati sui sistemi puliti nascono proprio così | Da correggere |
| «Decisivo» non vuol dire certo | Il README lo definisce «nessuna spiegazione innocente credibile», ma la cancellazione dei registri, decisiva, compare su due sistemi puliti, fatta da chi li ha preparati | Da correggere nel testo |
| L'assenza di indicatori non prova che il sistema sia pulito | Su 12 artefatti tolti o resi illeggibili, 11 portano a «da verificare»; uno no | Da completare |

**Prove di copertura.** Su una macchina pulita intera, il Windows 11 del DFIR Artifact Museum (verdetto «nessun indizio»), ho tolto o reso illeggibile un artefatto alla volta:

| Variante | Verdetto | Avviso |
| --- | --- | --- |
| Macchina intera | Nessun indizio | — |
| Senza Security.evtx | Da verificare | Security.evtx non trovato |
| Senza nessun registro di eventi | Da verificare | Nessun registro di eventi |
| Security.evtx illeggibile | Da verificare | Non è un registro valido |
| Security.evtx che finisce 7 giorni prima degli altri registri | Da verificare | Il Security si ferma prima degli altri |
| Senza hive SYSTEM | Da verificare | Hive SYSTEM non trovato |
| Hive SYSTEM illeggibile | Da verificare | Hive SYSTEM illeggibile |
| Senza hive SOFTWARE | Da verificare | Hive SOFTWARE non trovato |
| Senza NTUSER.DAT | Da verificare | Nessun NTUSER.DAT |
| Solo il registro di sistema, senza eventi, Prefetch e Amcache | Da verificare | Nessun registro di eventi |
| Prefetch vuoto | Da verificare | Nessun avviso, ma un segnale «da confermare»: Prefetch vuoto |
| Amcache.hve illeggibile | Da verificare | Amcache non valido |
| **Senza Amcache.hve** | **Nessun indizio** | **Nessuno** |

Senza Amcache il plugin tace: manca una fonte di prove d'esecuzione e il verdetto resta «nessun indizio». Senza l'hive SOFTWARE, invece, tre account creati durante l'installazione diventano segnali «da confermare»: senza contesto il plugin sospetta di più.

**Regole più prudenti, calcolate sugli stessi dati della misura:**

| Regola | Attacchi con verdetto di compromissione (set cieco, per la tecnica) | Sistemi puliti con verdetto di compromissione (grezzi; senza log cancellati dai preparatori) |
| --- | --- | --- |
| Attuale: un segnale decisivo, o segnali da confermare in due famiglie | 26 su 161 | 3 su 7; 2 su 7 |
| Solo un segnale decisivo; due famiglie danno «da verificare, priorità alta» | 25 su 161 | 2 su 7; 0 su 7 |

La regola delle due famiglie porta un solo attacco in più. Sui sistemi puliti aggiunge un verdetto sbagliato nel confronto grezzo (3 contro 2) e due senza i log cancellati dai preparatori (2 contro 0). Conviene farne una priorità, non un verdetto. Limitare a «da confermare» gli strumenti trovati solo per nome sul disco non cambia il verdetto di nessuna macchina attaccata: dove c'erano, c'erano anche altri segnali decisivi. Queste scelte le ho calcolate su dati ormai visti: vanno confermate sull'insieme sigillato.

**Correzioni proposte per la versione 1.3:**

1. Verdetti senza linguaggio di probabilità: «indicatori di compromissione», «da verificare» (con «priorità alta» quando i segnali da confermare sono in due famiglie), «nessun indicatore trovato».
2. «Decisivo» ridefinito: un indicatore che di rado ha una spiegazione innocente e che da solo giustifica l'esame della macchina. Non una prova.
3. Strumenti trovati solo per nome: al massimo «da confermare», salvo una prova d'esecuzione o le informazioni di versione del file.
4. Un avviso quando manca Amcache.hve su Windows 8 e successivi.
5. In testa al report e nel README: «Verdetto euristico di triage: indica dove guardare prima. Non è una probabilità né una prova; la conclusione spetta all'analisi forense.»

Una probabilità vera richiederebbe una calibrazione su sistemi rappresentativi, con una quota nota di compromessi: qui non c'è. Finché manca, il plugin non deve presentare nessun numero o etichetta come probabilità.

## 8. Le macchine ricostruite

Sulle 9 macchine con più tipi di artefatti il plugin dà compromissione a tutte e 5 quelle attaccate e a nessuna delle 3 senza attacchi documentati, ma sono i dati su cui l'ho sviluppato. Non valgono come misura di efficacia: confermano che il percorso completo funziona.

| Macchina | Fonte | Etichetta della fonte | Verdetto | Decisivi / da confermare |
| --- | --- | --- | --- | --- |
| apt10 | DFIR Artifact Museum, APTSimulatorVM, Windows 10 | Attacco simulato con APT Simulator | Compromissione probabile | 20 / 17 |
| apt22 | DFIR Artifact Museum, APTSimulatorVM, Server 2022 | Attacco simulato con APT Simulator | Compromissione probabile | 30 / 18 |
| szechuan | DFIR Madness, The Stolen Szechuan Sauce, controller di dominio | Compromessa | Compromissione probabile | 5 / 4 |
| due | Il controller di Szechuan e un Windows 11 nella stessa origine dati | Compromessa una delle due | Compromissione probabile; nessun indizio | 5 / 4 |
| attacchi | 3 campioni di movimento laterale di EVTX-ATTACK-SAMPLES | Compromessa | Compromissione probabile | 4 / 4 |
| belka | Belkasoft CTF, Insider Threat | Abuso di un dipendente, non un attacco esterno | Da verificare | 0 / 1 |
| rath10 | DFIR Artifact Museum, RathbunVM, Windows 10 | Nessun attacco documentato | Da verificare | 0 / 0 |
| rath11 | DFIR Artifact Museum, RathbunVM, Windows 11 | Nessun attacco documentato | Nessun indizio | 0 / 0 |
| ez7 | Hive di prova di Windows 7 (Eric Zimmerman) | Nessun attacco documentato | Da verificare | 0 / 0 |

Nella macchina *due* il verdetto è separato per ciascun Windows: compromissione per il controller, nessun indizio per il Windows 11.

## 9. Prestazioni

Il triage di un sistema intero con 2,5 GB di registri dura meno di un minuto. Finisce anche con l'heap Java limitato a 512 MB, ma il processo intero arriva a circa 690 MB: 512 MB non è la memoria che serve ad Autopsy.

| Famiglia | Casi | Input | Tempo del triage | Picco di memoria del processo |
| --- | --- | --- | --- | --- |
| Campioni d'attacco | 571 | Fino a 10 MB (mediana 0,07 MB); 50.176 eventi in tutto | Mediana 0,01 s; 95% entro 0,09 s; massimo 3,8 s | 514–621 MB per lotto |
| Sistemi puliti | 7 | Da 138 MB a 2,5 GB; da 130 mila a 1,8 milioni di eventi | Da 5,6 a 49 s | 438–587 MB |
| Macchine ricostruite | 9 | Da 0,2 a 316 MB | Da 0,8 a 26 s | 365 MB – 1,7 GB |
| Scenari della RAM (sintetici) | 7 | Da 0,1 a 194 MB | Da 0,4 a 18 s | 377 MB – 1,4 GB |
| Dentro Autopsy 4.21 e 4.23 (prove precedenti) | 32 esecuzioni | apt10, due, Windows 11 con la RAM | Mediana 13 s (da 1 a 31 s), dal registro del caso | — |

- Ambiente: 2 vCPU, OpenJDK 21, lo stesso Jython 2.7.4 incluso in Autopsy 4.23.1, memoria massima della JVM 3 GB. Il tempo del triage è misurato dentro la JVM e non comprende l'avvio.
- Memoria: i picchi oltre 1 GB vengono dalla JVM che usa la memoria che ha, non da un bisogno. Con l'heap massimo della JVM a 512 MB il sistema pulito più grande (2,5 GB, 1,8 milioni di eventi) e la macchina più grande finiscono con risultati identici, con un picco del processo di 690 MB.
- Velocità: circa 36.000 eventi al secondo sul sistema pulito più grande.
- Determinismo: ho eseguito due volte i 293 campioni del set cieco e i risultati sono identici.

## 10. Quanto generalizza fuori dai dati di sviluppo

Sui dati mai visti il plugin va peggio che su quelli dello sviluppo: il rischio di sovradattamento è reale, e la misura lo mostra in due punti precisi.

| Misura | Dati usati nello sviluppo | Dati indipendenti |
| --- | --- | --- |
| Record che il lettore dei registri non decodifica | 0 su 37.364 (set visto, usato per provare il lettore) | 1.681 su 12.812, il 13% (set cieco) |
| Verdetti di compromissione su sistemi puliti | 0 su 3 (macchine del museo senza attacchi) | 3 su 7 (evtx-baseline) |
| Verdetto di compromissione sugli attacchi | 5 macchine attaccate su 5 | 26 campioni su 161 nell'ambito (16%) |

- **Il lettore** è il caso più netto: perfetto sui file su cui l'ho provato, perde il 13% dei record sui file di un altro autore.
- **I falsi positivi:** le correzioni fatte durante lo sviluppo funzionano sui casi da cui vengono. Sui sistemi puliti nuovi sono comparse cause che non avevo visto: account creati durante l'installazione, script che preparano la macchina, programmi di accesso remoto installati da chi ha preparato i dati.
- **Il rilevamento:** la terza riga confronta macchine intere, con molte prove, e singoli registri di pochi minuti. Mescola il sovradattamento con la quantità di prove e non dice quanto pesa ciascuno: per separarli servono macchine intere indipendenti.
- **Il tipo di regola:** quelle che riconoscono nomi e percorsi noti sono le più esposte, perché per costruzione riconoscono ciò che conoscono; quelle basate sulla struttura e sulla sequenza degli eventi dipendono meno dal singolo esempio.
- **I campioni recenti:** i 20 campioni entrati nel set cieco dal 2022 in poi non vanno peggio degli altri (4 su 7 nell'ambito, contro il 47% di quelli del 2020 e il 40% di quelli del 2021), ma sono troppo pochi per escludere un calo.

Per i registri di eventi c'è una validazione su dati mai usati: il set cieco non è mai servito a scrivere o correggere regole. Non è però una valutazione indipendente: le etichette sono di altri, ma la scelta dei dati, il banco di misura, l'interpretazione e le correzioni vengono dallo stesso percorso di sviluppo. Per sistemi interi, incidenti veri e configurazioni aziendali manca del tutto: le 9 macchine sono dati di sviluppo, e le 7 installazioni pulite sono poche e preparate in laboratorio.

**Insieme sigillato.** Ho messo da parte 37 campioni d'attacco, 21 di DeepBlueCLI e 16 di Yamato Security, dalla raccolta [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx). Nessuno coincide con i 1.177 file usati finora, ma l'ho verificato solo con gli SHA-256, che escludono i file identici, non le varianti dello stesso episodio: prima di usarlo vanno controllati provenienza, scenario ed eventi in comune con i dati già usati. 33 contengono eventi che le regole leggono. Non ci ho eseguito il plugin: serve a validare le correzioni delle sezioni 7 e 18, una volta sola, riportando i risultati comunque escano. Da solo è piccolo e va affiancato dalle immagini disco e dai sistemi aziendali della sezione 20.

Per non sovradattare le prossime versioni:

1. Tre insiemi separati e registrati con gli hash: sviluppo, validazione, test sigillato. Il test sigillato si usa una volta sola: appena i suoi risultati guidano una correzione diventa un insieme di validazione, e per la versione successiva ne serve uno nuovo.
2. Le etichette del test le scrive qualcun altro, prima che il plugin giri.
3. Ogni regola nuova o corretta porta con sé la fonte e i casi di prova, compresi quelli puliti che non devono farla scattare. Prima di ogni release si ripete il controllo sui sistemi puliti.
4. Dopo le correzioni il set cieco diventa un dato di sviluppo, e il README lo dice.
5. Per le configurazioni aziendali: una prova su macchine reali gestite dall'IT e note come pulite, facendo uscire dall'azienda solo i risultati aggregati; e una prova a posteriori su incidenti chiusi, con il rapporto finale dell'indagine come verità.

## 11. Su quali versioni funziona

Il pacchetto 1.2, installato come dice il README, funziona dall'inizio alla fine in Autopsy 4.19.0, 4.20.0, 4.21.0, 4.22.1 e 4.23.1 su Linux, con gli stessi segnali e gli stessi verdetti in tutte le versioni. Gli arresti visti vengono da Autopsy e dall'ambiente, e compaiono anche senza il plugin. Su Windows non l'ho provato: lì il supporto resta da dimostrare, con la prova descritta in fondo alla sezione.

**Prima di questa prova la critica era fondata.** Durante lo sviluppo Autopsy era partito 66 volte (53 da riga di comando, 13 analisi avviate dall'interfaccia), solo con 4.21.0 e 4.23.1, su Linux e come root. Il database di ogni caso registra ogni analisi e il suo stato: le 63 analisi partite sono arrivate tutte in fondo, 3 esecuzioni sono state rifiutate prima di partire. La 1.2 era stata provata in Autopsy 12 volte, tutte su file logici: l'immagine disco solo con la 1.0 e la 1.1. Dell'arresto della 4.21.0 non resta traccia, perché il log è stato sovrascritto dalla ripetizione. Per 4.19, 4.20 e 4.22 c'era solo la lettura del codice di Autopsy.

| Esecuzione | Autopsy | Che cosa è successo | Causa | Di chi |
| --- | --- | --- | --- | --- |
| v421a | 4.21.0 | analisi rifiutata all'avvio | erano abilitati aLEAPP, iLEAPP e YARA, che esistono solo per Windows, e Solr non era eseguibile | ambiente |
| agg423\_1, agg421\_1 | 4.23.1, 4.21.0 | analisi rifiutata all'avvio | prova voluta: impostazioni che nominano ancora il modulo della 1.0 | comportamento di Autopsy, spiegato nel README |

**Come ho rifatto la prova.** Ho scritto il protocollo prima di eseguire le prove; ogni cambiamento successivo è aggiunto in fondo, con ora e motivo, compresi gli errori del mio banco di prova. Ogni versione viene dall'archivio ufficiale su GitHub, con il Java e la Sleuth Kit che chiede, una cartella utente nuova e il pacchetto controllato per SHA-256. Autopsy gira come utente normale, una versione alla volta, da riga di comando. Le origini dati sono tre: un'immagine raw NTFS di una macchina compromessa (D1), una cartella con una macchina compromessa e una sana (D2), una macchina con la raccolta della memoria (D3).

Una prova è superata se Autopsy finisce da solo con codice 0 e lo script verifica\_caso.py trova nel caso il modulo 1.2, l'analisi completata, nessun errore del modulo, conteggi coerenti e il report HTML e CSV registrato. In P4 e P5 la memoria massima è 3 GB per Autopsy e 1 GB per Solr: con i valori predefiniti il container da 8 GB esauriva la memoria.

| Autopsy | Java · Sleuth Kit · Jython | P1 immagine | P2 file logici, italiano | P3 file logici e memoria | P4 con tutti i moduli | P5 come P4, senza plugin | P6, P7 ripetizioni di P1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4.19.0 | 8 · 4.11.0 · 2.7.2 | superata | superata | superata | superata | arresto alla chiusura | superate |
| 4.20.0 | 8 · 4.12.0 · 2.7.2 | superata | superata | superata | risultati completi, arresto alla chiusura | arresto durante l'analisi | superate |
| 4.21.0 | 17 · 4.12.1 · 2.7.2 | superata | superata | superata | superata | superata | superate |
| 4.22.1 | 17 · 4.14.0 · 2.7.4 | superata | superata | superata | risultati completi, arresto alla chiusura | arresto alla chiusura | superate |
| 4.23.1 | 21 · 4.15.0 · 2.7.4 | superata | superata | superata | superata | superata | superate |

Java 8 è BellSoft Liberica 8 Full, come chiedono le istruzioni di 4.19 e 4.20: con OpenJDK 8 senza JavaFX la 4.19.0 non crea nemmeno il caso. La 4.23.1 vuole Java 21 anche se le sue istruzioni dicono 17, perché il suo jar della Sleuth Kit è compilato per Java 21.

In tutte le versioni P1 dà 57 segnali, P2 17 e P3 14, con gli stessi verdetti. Segnale per segnale (file, controllo, peso, testo, ora, punteggio) gli elenchi sono identici fra le cinque versioni, fra le tre ripetizioni e fra P1 e P4, cioè anche quando girano gli altri 17 moduli. P2 e P3 coincidono anche con il motore eseguito fuori da Autopsy con Jython 2.7.2 e 2.7.4: i numeri delle sezioni precedenti valgono per il plugin installato. Un'analisi con il solo plugin dura da 1 a 2,5 minuti, con tutti i moduli da 3,5 a 7,5.

**Le anomalie e la loro causa.** Nessuna viene dal plugin: in nessuna prova il log contiene un errore del modulo o un traceback Python, e ogni tipo di arresto compare anche senza il plugin. Con una sola istanza di Autopsy alla volta, gli arresti riguardano solo le analisi con tutti i moduli: 5 su 10 (2 su 5 con il plugin, 3 su 5 senza); nessuno nelle 25 analisi con il solo plugin.

| Anomalia | Dove | Che cosa mostrano il log e il rapporto della JVM | Di chi |
| --- | --- | --- | --- |
| Arresto alla chiusura: «pure virtual method called» | 4.19.0 P5, 4.20.0 P4 | arriva dopo «Job processing task finished», con l'analisi completata; anche senza plugin | Autopsy, codice nativo |
| Arresto alla chiusura: SIGSEGV in getenv dentro libgnutls | 4.22.1 P4 e P5 | analisi completata; lo stesso rapporto con e senza plugin | Autopsy, codice nativo |
| Arresto durante l'analisi: SIGSEGV in getenv mentre Tika avvia un programma per estrarre il testo | 4.20.0 P5 | senza plugin; l'analisi resta incompleta | Autopsy con Java 8 |
| Errori di altri moduli: prefetch di Recent Activity, immagini HEIC, PhotoRec | 4.20.0-4.23.1, P4 e P5 | gli stessi con e senza plugin | Autopsy su Linux |

Durante la preparazione ho trovato e corretto anche problemi del mio banco di prova, tutti annotati nel protocollo. Il più utile da sapere: Solr non parte come root, ed è la causa degli errori «Local Solr server is not running» in tutte le prove dello sviluppo. Gli altri: la memoria del container, la finestra del Central Repository al primo avvio, le impostazioni che la 4.19 legge in un posto diverso.

**Gli arresti con due versioni avviate insieme.** È la condizione in cui si era arrestata la 4.21.0 durante lo sviluppo. Ho avviato 4.21.0 e 4.23.1 nello stesso momento sull'immagine D1, tre volte per ciascuna condizione: senza il plugin una delle due si arresta in tutte e tre le coppie, esattamente come con il plugin.

| Condizione | Coppie | Coppie con un arresto | Esito |
| --- | --- | --- | --- |
| A1 senza plugin | 3 | 3 | 2 volte si arresta la 4.21.0, una la 4.23.1 |
| A2 con il plugin | 3 | 3 | 2 volte la 4.21.0, una la 4.23.1 |
| A3 con il plugin, libreria della Sleuth Kit separata | 3 | 3 | una volta la 4.21.0, due la 4.23.1 |
| A4 con il plugin, cartella temporanea di Java separata | 3 | 0 | analisi superate in entrambe le versioni |

I 9 rapporti della JVM mostrano tutti l'arresto nel caricatore dinamico (ld-linux), mentre il processo carica una libreria nativa. Le due versioni copiano librerie con lo stesso nome nella stessa cartella temporanea dell'utente; la più probabile è 7-Zip-JBinding, ma la prova dimostra la cartella in comune, non il singolo file. La mia ipotesi del protocollo, la sola libreria della Sleuth Kit, era troppo stretta: separarla non basta, separare tutta la cartella temporanea sì. In pratica: una sola istanza di Autopsy per utente alla volta, oppure una cartella temporanea diversa per ogni installazione. Su Windows un file in uso non si può riscrivere, quindi il meccanismo è diverso, e non l'ho provato.

**Che cosa resta da provare.** Su Windows nessuna prova. Il protocollo per le postazioni (PROTOCOLLO\_WINDOWS.txt nello zip, con verifica\_caso.py e la scheda degli esiti) chiede una prova per ogni coppia di Windows e Autopsy in uso: il modulo da solo, poi con il profilo di moduli abituale, poi senza il plugin se qualcosa fallisce. Lo script legge il caso chiuso e dice superata o no, criterio per criterio. Restano fuori anche l'interfaccia grafica su 4.19, 4.20 e 4.22 (provata solo su 4.21.0 e 4.23.1, durante lo sviluppo), le immagini E01, VHD e VMDK, i casi multiutente, macOS, le versioni intermedie (4.19.1-4.19.3, 4.22.0, 4.23.0) e quelle future. Il README va corretto di conseguenza (sezione 18).

## 12. La RAM su immagini vere

Il terzo livello ora è fatto: due immagini di memoria autentiche con la soluzione pubblicata, Volatility vero in due versioni, il plugin dentro Autopsy 4.23.1. Il plugin riporta fedelmente quello che Volatility estrae: 1.606 righe e 3 segnali controllati uno per uno, nessuna discrepanza. Questo prova l'importazione, non che Volatility abbia letto tutto: versioni diverse danno risultati diversi, e un'immagine troncata passa per completa (sezione 15). Dalla RAM però segnala poco: su TOTAL RECALL solo ncat.exe, e il verdetto resta «da verificare» su una macchina compromessa. La critica era fondata: fino a oggi il README stesso diceva che la RAM non era stata provata su un'immagine vera.

| Livello | Che cosa dimostra | Prima | Adesso |
| --- | --- | --- | --- |
| 1. Regole su dati preparati | il motore giudica bene processi, connessioni e servizi già strutturati | provato, con scenari sintetici | invariato |
| 2. Raccoglitore e formato | collect\_memory.py, Volatility e il plugin si passano i dati e gestiscono gli errori | provato con un Volatility simulato e con Volatility 2.28.2 su un file che non è un'immagine | provato anche con Volatility vero su immagini vere, con e senza i simboli giusti |
| 3. Immagine autentica | Volatility estrae i dati da una memoria vera e il plugin li usa nel verdetto | non provato | provato su 2 immagini, con Volatility 2.28.2 e 2.4.1 |

| Prova | Volatility | Plugin di Volatility riusciti | Righe controllate, tutte fedeli | Segnali dalla RAM | Verdetto |
| --- | --- | --- | --- | --- | --- |
| TOTAL RECALL, sola RAM | 2.28.2 | 10 su 10 | 339 | ncat.exe, da confermare | da verificare |
| TOTAL RECALL, sola RAM | 2.4.1 | 9 su 10, manca svcscan | 326 | ncat.exe, da confermare | da verificare |
| Silence of the RAM, RAM e registri | 2.28.2 | 10 su 10 | 314 | nessuno | compromissione probabile, 11 decisivi, tutti dai registri |
| Silence of the RAM, RAM e registri | 2.4.1 | 9 su 10, manca svcscan | 313 | un processo «forse nascosto»: falso positivo | compromissione probabile |
| Silence of the RAM, sola RAM | 2.28.2 | 10 su 10 | 314 | nessuno | da verificare: nessun segnale, copertura insufficiente |

Le righe controllate sono quelle delle tabelle della RAM nel report: sessioni, processi, connessioni. Entrambe le macchine sono compromesse.

**Come l'ho misurato.** Le immagini sono due sfide pubblicate da SecurityNik su GitHub con la soluzione: TOTAL RECALL (Windows 11, kernel 22621, 4,3 GB) e Silence of the RAM (Windows 10 22H2, 8,6 GB), con gli SHA-256 pubblicati. Le tabelle dei simboli del kernel, assenti dalle raccolte pubbliche, sono state generate con pdbconv dal server dei simboli di Microsoft. Protocollo e previsioni sono scritti prima di eseguire il plugin. Uno script confronta ogni segnale e ogni riga delle tabelle con il JSON di Volatility, nei due sensi; provato con 15 alterazioni del report, le trova tutte.

**Il caso dei simboli mancanti, provato davvero.** Il raccoglitore con Volatility 2.28.2 offline si ferma al primo plugin con un messaggio chiaro, codice 2, nessun plugin riuscito. Dentro Autopsy il plugin dà «da verificare», elenca i plugin di Volatility senza risultati e segna i controlli 3, 4, 5 e 7 come «non verificabile». Una RAM non analizzata non si può scambiare per una macchina pulita.

**TOTAL RECALL: le previsioni scritte prima sono tutte giuste.** Il plugin segnala ncat.exe (PID 896) come strumento a doppio uso, da confermare. Nelle tabelle si vedono, senza segnale: il cmd.exe figlio di ncat; ssh -D 9999, un proxy SOCKS verso la macchina dell'attaccante; le connessioni verso 10.0.0.110 e 10.0.0.101; vmtoolsd.exe che avvia cmd.exe. Il codice iniettato in vmtoolsd.exe e powershell.exe non c'è, perché il raccoglitore non esegue malfind. Nessuna mancanza viene da un errore di lettura: sono regole che non ci sono (ssh copre solo -R, la rete solo gli indirizzi pubblici) o dati che non si raccolgono.

**I registri autentici di Silence of the RAM, da soli.** Il verdetto è «compromissione probabile», con 11 segnali decisivi e 11 da confermare. Il plugin prende l'account servicemgmt creato e aggiunto agli amministratori, i comandi net user e il PowerShell codificato. Manca però i passi centrali dell'attacco, che pure sono nel registro di Sysmon: lsass.exe che avvia cmd.exe e net.exe, WerFaultSecure.exe usato per fermare l'EDR, l'eseguibile scaricato e avviato da Downloads. Segnala inoltre come «da confermare» il driver di Magnet RAM Capture, uno strumento di acquisizione della memoria avviato alle 07:06, subito dopo DumpIt.

**Silence of the RAM: la RAM mostra l'attaccante collegato, ma non lo segnala.** L'immagine è delle 07:05, fatta con DumpIt dopo il riavvio delle 06:49. Nelle tabelle c'è la sessione SSH dell'account creato dall'attaccante: la connessione da 10.0.0.118 a sshd.exe e, come servicemgmt, sshd.exe (PID 9772), conhost.exe e cmd.exe. Nessuna regola della RAM la segnala: il verdetto «compromissione probabile» viene tutto dai registri, con gli stessi 22 segnali della prova sui soli registri.

Con la sola RAM il verdetto è «da verificare» per copertura insufficiente, non «pulito». Delle altre previsioni, una partiva da un presupposto sbagliato: il driver di Magnet RAM Capture è stato installato alle 07:06:48, dopo l'immagine, quindi non può esserci.

**La versione di Volatility conta più del plugin.** Con la 2.4.1, la minima dichiarata nel README, le stesse immagini danno meno dati e un falso positivo:

| Che cosa | Volatility 2.4.1, la minima del README | Volatility 2.28.2, l'ultima |
| --- | --- | --- |
| Servizi (controlli 17 e 29) | svcscan non si carica senza yara-python; il report dice che i controlli sono incompleti | presenti |
| Connessioni TCP su Windows 11 (kernel 22621), porte in ascolto escluse | assenti, anche quelle dell'attaccante | presenti, ma senza processo né ora di creazione |
| Processi attivi su Silence of the RAM | pslist ne perde uno, che il plugin segnala come «forse nascosto» | tutti |

Volatility non ha le strutture di rete della build 22621 e usa le più vicine che conosce: la 19041 nella 2.4.1, la 20348 nella 2.28.2. Il plugin legge bene in tutti i casi; cambia quello che gli arriva. Le connessioni senza processo compaiono nel report con «?», senza spiegazione.

**Per l'uso forense.** La RAM è affidabile come raccolta ordinata dei dati di Volatility nel report, non come rivelatore. Nel README va scritto che cosa è stato provato e con quali limiti; la versione minima di Volatility deve diventare quella provata.

## 13. RAM e disco: l'abbinamento

La critica è fondata: il plugin attribuisce la RAM a un'installazione di Windows solo in base al nome del computer. In cinque prove con dati veri ha sbagliato quattro volte: tre volte ha unito la RAM di un'altra macchina, una volta ha ignorato quella giusta. Un prototipo che confronta anche build, avvio e SID della macchina decide bene in tutti i casi.

| Dove sta la RAM | Che cosa fa il plugin 1.2 |
| --- | --- |
| Nella stessa origine dati, con i due nomi | la usa se il nome è uguale |
| Nella stessa origine dati, senza il nome del disco | la usa, con una nota, se l'origine ha una sola installazione; il nome dell'installazione lo prende dalla RAM |
| Nella stessa origine dati, con più installazioni con lo stesso nome | la usa in ognuna |
| In un'altra origine dati del caso | la usa se il nome è uguale, con una nota; se è diverso la ignora senza dirlo |

Il nome della RAM è il valore più frequente di COMPUTERNAME fra i processi; quello del disco viene dall'hive SYSTEM. Build, ora di avvio, SID e periodo non si guardano.

| Prova | Che cosa c'è nel caso | Che cosa fa il plugin | Effetto sul verdetto | Prototipo |
| --- | --- | --- | --- | --- |
| F2 | rath11, pulita; in un'altra origine, la RAM di un'altra macchina con lo stesso nome | la unisce per il nome | da «nessun indizio» a «da verificare» per ncat.exe, che non è di rath11 | contraddetta: build e SID diversi |
| F3 | i registri di Silence of the RAM e, nella stessa origine, la RAM di TOTAL RECALL | la unisce senza confronto e chiama l'installazione SECURITYNIK-WIN | entra ncat.exe ed esce un indizio vero, la creazione di servicemgmt | contraddetta: build e SID diversi |
| F4 | i registri di Silence of the RAM con il computer rinominato; in un'altra origine, la sua RAM | la ignora senza dirlo | perso l'abbinamento giusto | alta: build, avvio e SID concordano |
| F5 | due copie di rath11 e, nella stessa origine, la RAM della prova F2 | la unisce a entrambe | da «nessun indizio» a «da verificare», due volte | contraddetta, due volte |
| F6, controllo | i registri di Silence of the RAM con il nome giusto; in un'altra origine, la sua RAM | la unisce per il nome | giusto | alta |

**Come l'ho provato.** Dati veri: rath11 del DFIR Artifact Museum (Windows 11, nessun attacco documentato, «nessun indizio» da sola nella prova F1), i registri e la RAM di Silence of the RAM, la RAM di TOTAL RECALL. Simulati solo il nome nella RAM di TOTAL RECALL, cambiato in quello di rath11 come per un clone o una macchina reinstallata, e due hive SYSTEM con il solo nome del computer. Plugin 1.2 senza modifiche dentro Autopsy 4.23.1; le previsioni, scritte prima, sono tutte confermate.

**Il nome sbagliato cambia anche gli indizi del disco.** Il nome serve pure a decidere quali eventi sono di questa macchina. In F3 il nome preso dalla RAM ha fatto scartare l'evento 4720 con cui è stato creato servicemgmt, perché porta il nome DESKTOP-4S97VHS. In F4 succede lo stesso senza RAM: dopo un cambio di nome, l'hive SYSTEM ha il nome nuovo e gli eventi di prima quello vecchio.

**La provenienza c'è, ma non dove serve.** Ogni indizio della RAM dice nei dettagli da quale immagine viene, e la sezione Sistema del report elenca le RAM usate, con SHA-256 e origine dati. Il verdetto però non dice che poggia anche sulla RAM, né quanto è sicuro l'abbinamento. Se una RAM viene ignorata (F4) o data a due installazioni (F5), il report non lo dice.

**Che cosa servirebbe.** Il prototipo confronta build, avvio e SID della macchina. Una build diversa, salvo un aggiornamento fra le due acquisizioni, o SID senza nulla in comune indicano macchine diverse. Un avvio nel registro System entro 2 minuti da quello della RAM indica la stessa macchina nella stessa sessione.

Un clone vero però ha nome, build e SID uguali: lo distingue solo l'avvio, e solo se i registri del disco coprono quell'ora. Per questo l'abbinamento dovrebbe partire da una scelta dell'analista. In Autopsy, dalla 4.19, ogni origine dati appartiene a un host, e il plugin può leggerlo.

## 14. Il doppio conteggio

Il plugin non somma punteggi, ma il rischio c'è lo stesso, nella regola delle due famiglie. Due segnali «da confermare» di famiglie diverse valgono come conferma reciproca anche quando descrivono lo stesso oggetto. Nei verdetti già misurati è successo 4 volte su 7, tutte su campioni d'attacco; nella RAM vera non è mai successo, ma può succedere.

| Categoria della critica | Che cosa fa la 1.2 | Che cosa manca |
| --- | --- | --- |
| Altre rappresentazioni dello stesso indicatore | nella RAM unisce pslist, pstree, psscan e cmdline in un solo processo; nei registri raggruppa lo stesso comando («11 volte») | fra controlli diversi lo stesso oggetto dà più segnali, anche in famiglie diverse |
| Evidenze indipendenti che si confermano | la regola delle due famiglie | le famiglie sono delle regole, non dei fatti: una sola cosa può toccarne due |
| Evidenze discordanti | nessuna regola generale: alcune discordanze diventano segnali (processo solo in psscan, servizio nella RAM ma non nel registro), altre si ignorano (nome della RAM diverso da quello dei registri) | uno stato «discordante», con la sua regola |
| Risultati incerti per dati mancanti | avvisi di copertura, controlli «non verificabili», plugin di Volatility falliti; senza segnali il verdetto resta «da verificare» | niente di essenziale |

**Come l'ho misurato.** Nessuna nuova esecuzione: ho riletto i 595 verdetti già registrati (set cieco e visto, sistemi puliti, macchine, scenari della RAM). Ho riunito in un «fenomeno» i segnali che nominano lo stesso oggetto: comando o programma, PID, attività pianificata, servizio, account, registro cancellato. Poi ho ricalcolato il verdetto contando i fenomeni; con la regola attuale il ricalcolo riproduce tutti i 595 verdetti.

| Caso | Oggetto | I due segnali | Oggi | Contando i fenomeni |
| --- | --- | --- | --- | --- |
| cieco-025 | attività pianificata \\smbservice | persistenza (programma in una cartella temporanea) ed esecuzione remota (creata e cancellata in 93 ms) | compromissione probabile | da verificare |
| visto-070 e visto-071 | nc.exe 127.0.0.1 1337 | programma in una cartella insolita e strumento a doppio uso | compromissione probabile | da verificare |
| visto-222 | attività pianificata \\FullPowersTask | persistenza ed esecuzione remota | compromissione probabile | da verificare |

I quattro campioni sono attacchi: il verdetto era giusto, ma per una ragione sbagliata. Contando i fenomeni, nel set cieco i verdetti «compromissione probabile» scendono da 26 a 25 su 161 e nel set visto tre in meno; sui sistemi puliti non cambia nulla, perché l'unico verdetto di quel tipo viene da due fatti distinti.

**Nella RAM.** Sulle due immagini vere, 386 processi: solo ncat.exe ha un riscontro, in una famiglia. La regola sui processi è però la stessa di 4688 e Sysmon, e può dare due famiglie a un processo solo: procdump64.exe in C:\\Users\\Public è «strumento a doppio uso» e «programma in una cartella insolita», quindi «compromissione probabile» da solo. Lo stesso processo visto anche nei registri dà le stesse famiglie: raddoppia il conteggio, non il verdetto.

**I numeri del report.** In media un fenomeno produce poco più di un segnale (da 1,01 a 1,10: è un limite inferiore), ma il caso singolo può ingannare. Sui registri di Silence of the RAM gli 11 segnali decisivi sono tre fatti: i registri cancellati e due esecuzioni di uno stager PowerShell, alle 06:53 e alle 07:01, ciascuna vista sia nei blocchi 4104 sia nel comando decodificato. Il report però scrive «11 segnali decisivi».

## 15. Risultati mancanti e parziali

Il report distingue bene ciò che è fallito, non ciò che è parziale. Un plugin di Volatility fallito, un file mancante o illeggibile e un manifesto danneggiato danno un avviso e impediscono il verdetto «nessun indizio». Un output vuoto o incompleto ma finito «ok» passa invece come «nulla da segnalare», e un'immagine troncata produce indizi falsi invece di un avviso.

| Prova | Che cosa manca nella RAM | Che cosa dice il report | Verdetto |
| --- | --- | --- | --- |
| H0 | nulla | 10 plugin su 10 con risultati | nessun indizio |
| H1, H2, H3 | netscan fallito, file mancante, JSON illeggibile | avviso «controlli incompleti: 5, 7»; controlli 5 e 7 «non verificabile» | da verificare |
| H9 | manifesto danneggiato | avviso: la RAM non si può usare | da verificare |
| H4 | netscan finito con 0 righe | 10 plugin su 10; controllo 5 «nulla da segnalare» | nessun indizio |
| H7 | netscan con 2 righe, il manifesto ne dichiara 10 | come H4 | nessun indizio |
| H8 | connessioni senza processo | come H4 | nessun indizio |
| H6 | nessuna riga di comando leggibile | controllo 4 «nulla da segnalare» | nessun indizio |
| H5 | nessun processo | controllo 4 «non verificabile», ma nessun avviso | nessun indizio |
| H10 | svcscan fallito, registro presente | nota «i controlli non ne risentono» | nessun indizio |
| H11 | getsids fallito | nota «i controlli non ne risentono» | nessun indizio |

Tutte le varianti partono dal disco vero di rath11 e da una RAM pulita costruita durante lo sviluppo, nella stessa origine dati; ognuna cambia una cosa sola. Le previsioni, scritte prima leggendo il codice, sono tutte confermate.

**Un'immagine incompleta, con dati veri.** Ho tagliato a metà l'immagine di Silence of the RAM, come una copia interrotta. Volatility 2.28.2 finisce tutti i plugin senza errori, e il raccoglitore scrive «Plugin completati: 10 su 10». Ma pslist trova 2 processi su 166, netscan 0 connessioni su 145, svcscan 0 servizi su 1.520, envars nulla, quindi nemmeno il nome del computer.

Il plugin non dà nessun avviso sulla RAM e segna 30 processi normali di Windows come «forse nascosti», perché psscan ne trova 35 dove pslist si ferma a 2. Da sola la raccolta dà «da verificare» per 30 indizi falsi. Basterebbe un indizio «da confermare» di un'altra famiglia sul disco, anche innocuo, per arrivare a «compromissione probabile».

**Dove il report si contraddice.** Con svcscan fallito l'avviso dice «controlli incompleti: 17, 29», ma nella tabella dei 41 controlli il 29 risulta «nulla da segnalare» quando i registri di eventi l'hanno fatto in parte (SR\_241). Con il registro presente la nota dice che i controlli «non ne risentono», ma senza svcscan non si cercano più i servizi rimasti solo in memoria, come quelli di smbexec. E un controllo «non verificabile» non impedisce da solo il verdetto «nessun indizio» (H5).

## 16. Configurazioni verificate

Uno zip e due versioni di Autopsy non dimostrano la compatibilità con ogni installazione: l'osservazione è giusta. La tabella riunisce le prove delle sezioni 11-15 e quelle sulla release fatte qui. Vale come elenco di configurazioni verificate; fuori da queste, il plugin e il raccoglitore non sono garantiti.

| Componente | Verificato | Con limiti | Non verificato |
| --- | --- | --- | --- |
| Plugin in Autopsy | 4.19.0, 4.20.0, 4.21.0, 4.22.1, 4.23.1 su Ubuntu 24.04, ciascuna con il suo Java; report in inglese e italiano | — | Windows, macOS, 4.19.1-4.19.3, 4.22.0, 4.23.0, casi multiutente |
| Origini dati | immagine disco raw con NTFS, file logici, RAM nella stessa origine | RAM in un'altra origine: abbinata solo per nome | E01, VHD, VMDK |
| Motore | Jython 2.7.2 e 2.7.4 | — | — |
| Raccoglitore | Python da 3.8 a 3.14 con le prove del repository; 3.8 e 3.11 con Volatility vero, output identici; Ubuntu 24.04 | — | Windows, macOS |
| Volatility | 2.28.2, installazione semplice | 2.4.1: svcscan solo con yara-python; su Windows 11 (kernel 22621) nessuna connessione TCP | 2.4.0 e da 2.5 a 2.27 |
| Simboli | tabelle ISF locali con --offline; se mancano, errore chiaro | — | download dal server dei simboli di Microsoft |
| Immagini della RAM | crash dump di DumpIt di Windows 11 (kernel 22621) e Windows 10 22H2 | immagine troncata: nessun errore, risultati parziali non segnalati | raw o .mem, .vmem, hiberfil, AFF4; altre build, Windows Server, 32 bit |
| Release | zip del plugin ricostruito dal repository: 33 file identici; raccoglitore uguale nei tre artefatti; passi della CI eseguiti qui | — | l'esecuzione della CI su GitHub |

**Che cosa ho verificato oggi.** Ho eseguito qui i passi della CI: catalogo inglese (1.003 testi), prove del raccoglitore (48), compilazione e prove con Jython 2.7.2 e 2.7.4; nessun errore. Le versioni delle azioni di GitHub che la CI usa esistono. Al 12 ottobre 2026 le ultime versioni pubblicate sono Autopsy 4.23.1 e Volatility 2.28.2: non c'è nulla di più recente di ciò che ho provato, ma restano fuori le versioni intermedie e Windows.

**Python e risorse.** Il README chiede Python 3.8, ma la CI prova solo l'ultima versione. Le prove del raccoglitore passano da Python 3.8 a 3.14, e la stessa immagine vera di 8 GB, raccolta con Python 3.8 e 3.11, dà output identici. La raccolta ha richiesto circa 130 secondi e circa 200 MB di memoria, con 2,3 MB di output.

**Dove la documentazione va oltre le prove.** I requisiti del README 1.2 dicono «Autopsy 4.19 o successive», «Python 3.8 o successive» e «Volatility 2.4 o successive»: la prima regge solo su Linux e per le versioni provate, la seconda regge, la terza no (sezione 12). Il changelog promette un avviso per ogni plugin di Volatility senza risultati, ma arriva solo se il plugin fallisce, non se finisce con 0 righe (sezione 15).

## 17. Prima di usare la RAM nel lavoro

Ho fatto le tre prove proposte, con il risultato atteso scritto prima, i log e l'impronta del codice. La RAM riporta fedelmente Volatility e quasi tutti i guasti veri li dichiara. Per un impiego professionale mancano ancora tre cose: un caso pulito autentico, un abbinamento che non si fermi al nome e l'avviso per due guasti che oggi passano in silenzio.

**Prima prova: due immagini documentate, nessuna pulita.** Ogni immagine della sezione 12 ha ora una scheda con SHA-256, repository e commit da cui viene, impronta pubblicata dall'autore (uguale a quella scaricata), versione di Windows e strumento di acquisizione. TOTAL RECALL è Windows 11 con kernel 22621; Silence of the RAM è Windows 10 22H2 (build 19045 nel registro System). Entrambe sono state acquisite con DumpIt, che si vede nella memoria con l'ora d'avvio. La scheda riporta anche i risultati attesi, scritti prima di eseguire il plugin. Ha corretto un'imprecisione: dalla RAM non si distingue Windows 11 22H2 da 23H2, che hanno lo stesso kernel. Entrambe le macchine sono compromesse.

| Immagine | Volatility | Processi benigni | Segnalati | Processi dell'attacco | Segnalati |
| --- | --- | --- | --- | --- | --- |
| TOTAL RECALL | 2.28.2 | 198 | 0 | 11 | 1 (ncat.exe) |
| TOTAL RECALL | 2.4.1 | 197 | 0 | 11 | 1 (ncat.exe) |
| Silence of the RAM | 2.28.2 | 162 | 0 | 5 | 0 |
| Silence of the RAM | 2.4.1 | 161 | 1 (svchost.exe «forse nascosto») | 5 | 0 |

I processi dell'attacco li ho fissati prima del conto, dalle soluzioni pubblicate e dall'albero dei processi. Ho escluso come ambigui i 12 processi di Chrome che usano il proxy dell'attaccante. Con Volatility 2.28.2 nessuno dei 360 processi benigni è segnalato. Vengono da due macchine sole: è una descrizione dei casi provati, non una stima del tasso di falsi positivi. L'unico falso positivo nasce da pslist di 2.4.1, che non elenca un processo attivo. Dei 16 processi dell'attacco ne è segnalato uno.

**Il caso pulito manca.** Non ho trovato immagini pubbliche di macchine pulite documentate raggiungibili da qui. I processi benigni di due macchine compromesse non lo sostituiscono: il verdetto «nessun indizio» richiede anche il disco, e su una macchina pulita intera, con la RAM vera, non l'ho mai visto. Nello zip c'è la procedura per acquisirne una, con la RAM e il disco presi nella stessa sessione, e la scheda da compilare.

**Seconda prova: l'abbinamento, contato.** Ho messo insieme tutte le coppie disponibili: 77 coppie RAM-disco, 12 della stessa macchina. Oltre alle RAM e ai dischi della sezione 13 ci sono tre RAM vere con il solo nome cambiato e la raccolta vera interrotta della terza prova, senza nome né SID. Ci sono anche due dischi con il solo hive SYSTEM. La regola del plugin l'ho riscritta dal codice: nelle cinque coppie eseguite anche in Autopsy (F2–F6) decide allo stesso modo. Quando unisce in modo incerto, il plugin lo dice con una nota («stesso nome» oppure «nome non confrontabile»), mai nel verdetto; quando scarta una RAM di un'altra origine, non lo dice.

| Chi decide | Coppie vere unite | Coppie false unite |
| --- | --- | --- |
| Plugin 1.2, RAM in un'altra origine dati | 2 su 12 | 5 su 65 |
| Plugin 1.2, RAM nella stessa origine dati | 8 su 12 | 26 su 65 |
| Prototipo, unione solo con fiducia «alta» | 9 su 12 | 0 su 65 |

Sono prove di funzionamento, non una stima di affidabilità: le coppie vengono da due sole RAM vere e dalle loro copie, quindi non sono casi indipendenti, e un clone vero non c'è. «0 su 65» descrive queste coppie, non il prototipo in generale.

**Dove il prototipo si ferma.** Le 3 coppie vere che il prototipo non unisce hanno un disco con il solo hive SYSTEM: niente build, avvio o SID da confrontare. Una ha il nome in comune («solo nome»), due nemmeno quello («insufficiente»). Lì decide l'analista. La raccolta interrotta, senza nome, il prototipo la riconosce dalla build e dall'avvio, con fiducia «alta» con i tre dischi giusti. Il plugin invece la usa con qualunque disco, purché stia nella stessa origine dati.

**Il punteggio cambia senza motivo.** Delle 26 unioni sbagliate nella stessa origine, 18 portano nel verdetto del disco l'indizio «da confermare» di ncat.exe, che non è di quella macchina. Come in F2, basta per passare da «nessun indizio» a «da verificare»; con un altro indizio sul disco si arriva a «compromissione probabile». Le altre 8 non cambiano il punteggio, ma attribuiscono al disco processi, connessioni e sessioni di un'altra macchina.

**Terza prova: i guasti.** Timeout, interruzione e dump non supportato li ho prodotti davvero, con il raccoglitore della release su Silence of the RAM. Poi ho riprodotto gli stessi casi nel manifesto, sulla base pulita della sezione 15, che da sola dà «nessun indizio». Simboli mancanti, plugin falliti e output incompleti erano già nelle sezioni 12 e 15.

| Prova | Che cosa succede | Che cosa dice il report | Verdetto |
| --- | --- | --- | --- |
| T3, timeout vero di 18 s per plugin | si fermano psscan, netscan e svcscan; netstat, il ripiego, finisce | avviso per psscan e svcscan, niente su netscan; controllo 4 «nulla da segnalare» | da verificare (solo RAM) |
| T4, Ctrl+C vero | si ferma durante netscan: 5 plugin su 10 | avviso, controlli 3, 5, 7, 17 e 29 incompleti; nota sull'interruzione | da verificare (solo RAM) |
| T5, un file che non è memoria | Volatility non trova un kernel e il raccoglitore si ferma | avviso, 0 plugin su 10, senza il motivo | da verificare (solo RAM) |
| H12 | netscan e netstat fermati | avviso; 5 e 7 «non verificabile» | da verificare |
| H12b | netscan fermato, netstat riuscito | nessun avviso | nessun indizio |
| H13 | raccolta interrotta dopo sessions | solo note | nessun indizio |
| H13b | raccolta interrotta durante netscan | avviso; 3, 5 e 7 «non verificabile» | da verificare |
| H14 | dump non supportato | avviso; 3, 4, 5 e 7 «non verificabile» | da verificare |

**Due guasti passano in silenzio.** Quando netscan si ferma, il raccoglitore passa a netstat e il plugin conta la rete come riuscita: niente avviso, «8 plugin su 10» e il nome di netstat sotto la tabella. Ma netstat non vede le connessioni chiuse. Su Silence of the RAM mancano 46 righe su 145, fra cui 11 connessioni chiuse verso indirizzi pubblici: proprio quelle che guarda il controllo 5. Con il disco, questo dà «nessun indizio» (H12b). L'altro guasto è quello della sezione 15: senza svcscan e con il registro presente, una nota dice che i controlli non ne risentono, e il verdetto resta «nessun indizio» anche dopo un'interruzione (H13).

**Le previsioni.** Le ho scritte prima di ogni esecuzione. Alle 22:20 avevo previsto un avviso anche per H13; alle 22:30, rileggendo il codice e prima di eseguire, ho corretto la previsione e aggiunto H12b. Tutti gli esiti coincidono con le previsioni corrette, ma prevedere un guasto leggendo il codice e poi osservarlo conferma il difetto, non lo rende accettabile. Conta il requisito: il criterio del protocollo, «nessuna prova dà nessun indizio», non è rispettato in H12b e H13.

**Registro e codice.** Ogni verifica sulla RAM delle sezioni 12, 13, 15 e di questa è una riga di un registro unico, di 196 righe. Ogni riga riporta l'atteso con la fonte e l'ora, l'effettivo, lo scostamento, l'errore rispetto alla verità, i log e il codice. Il plugin installato nelle cinque versioni di Autopsy è identico, file per file, al pacchetto della release (SHA-256 b4ee4e0f…), e Jython ne ha compilato le classi dopo il sorgente. Il raccoglitore è quello del repository (0153c7eb…).

**Pronta per il lavoro? Non ancora.** Come visore dei risultati di Volatility sì: tabelle e indizi sono fedeli, e dei guasti veri provati solo il timeout di netscan passa inosservato. Come fonte del verdetto no. Prima servono un caso pulito autentico, l'abbinamento indicato dall'analista e controllato dal plugin (sezione 18) e l'avviso per i due guasti silenziosi.

## 18. Che cosa va corretto

La misura ha trovato cinque problemi; quelli sul significato del verdetto sono nella sezione 7. Non li ho corretti, per non toccare il plugin mentre lo misuravo.

1. **Lettore dei registri:** leggere anche gli eventi scritti senza modello e chiamare l'avviso con il nome giusto. Recupera fino a 9 dei 73 campioni sfuggiti.
2. **Falsi positivi dell'installazione:** l'account creato e aggiunto agli amministratori dall'account del computer durante il setup, il servizio di un installer in una cartella temporanea, i comandi PowerShell in Base64 degli script di Packer che hanno preparato la macchina. Il plugin conosce già la data di installazione e può usarla.
3. **Accesso remoto:** TeamViewer, VNC e un RDP da Internet restano «da confermare» per scelta, ma insieme bastano per il verdetto di compromissione. Va deciso se contarli come una sola famiglia.
4. **Lacune di rilevamento:** servizi creati, manipolazione di account, offuscamento, movimento laterale con RDP, DCOM e SSH, forza bruta, ricognizione (sezione 4).
5. **README:** scrivere questi numeri, che cosa significa un verdetto negativo e dove il plugin è stato provato: Autopsy 4.19.0-4.23.1 su Linux, Windows no (sezione 11; il testo proposto è nello zip, in compatibilita/proposta\_README.md).

Dai registri autentici di Silence of the RAM (sezione 12) vengono altre tre correzioni: segnalare lsass.exe, services.exe e wininit.exe che avviano interpreti di comandi; segnalare WerFaultSecure.exe lanciato con /pid contro un altro processo (la tecnica EDR-Freeze); trattare come informativi i driver degli strumenti di acquisizione, negli eventi 7045 e nella RAM (dove oggi basta il nome), solo se coincidono anche percorso, hash del file e momento dell'acquisizione: un nome si copia.

Dalla RAM su immagini vere (sezione 12) ne vengono altre cinque:

1. Nel README, dire che cosa è stato provato sulla RAM e con quali limiti, e portare la versione minima di Volatility a quella provata, la 2.28.2.
2. Nel raccoglitore, dire in chiaro quando Volatility non ha un plugin: oggi il messaggio è tagliato e mostra solo la coda dell'elenco dei plugin. Avvisare se la versione è più vecchia di quella provata.
3. Nel report, spiegare il «?» delle connessioni senza processo.
4. Con una versione di Volatility più vecchia di quella provata, abbassare a informativi i processi «forse nascosti».
5. Regole nuove, da provare sull'insieme sigillato prima di adottarle: ssh -D e -L come ssh -R, cioè «da confermare», provate anche su attività amministrativa autorizzata; un interprete di comandi figlio di uno strumento di rete a doppio uso, come ncat; un processo attivo nella RAM con l'utente di un account che i registri mostrano appena creato o aggiunto agli amministratori.

Dall'abbinamento fra RAM e disco (sezione 13) ne vengono altre cinque:

1. Unire RAM e disco di origini diverse solo se l'analista le ha messe nello stesso host di Autopsy. Con lo stesso nome ma host diversi, dirlo senza unirle.
2. Dare all'abbinamento un livello di fiducia con build, avvio, SID e distanza nel tempo. Se qualcosa contraddice, non unire e spiegare perché; se gli elementi non bastano, mostrare la RAM a parte, fuori dal verdetto.
3. Una RAM va a una sola installazione: se ne trova più d'una, non va a nessuna, e il report lo dice.
4. Il nome dell'installazione dall'hive SYSTEM o dal campo Computer dei registri, mai dalla RAM. Per riconoscere gli eventi della macchina, tutti i nomi che ha avuto.
5. In ogni indizio la sua origine, disco o RAM con lo SHA-256 dell'immagine; nel verdetto i conteggi per origine e la fiducia dell'abbinamento; una nota anche per le RAM non usate.

Dal doppio conteggio (sezione 14) ne vengono altre quattro:

1. Riunire in un fenomeno i segnali che riguardano lo stesso oggetto: processo (PID e ora di avvio, o ProcessGuid di Sysmon), comando, file, attività pianificata, servizio, account, registro; i blocchi 4104 per ScriptBlockId. Nel verdetto, due famiglie contano solo se vengono da fenomeni diversi.
2. Per ogni fenomeno, mostrare dove è stato visto (RAM, 4688, Sysmon, Prefetch): fonti indipendenti confermano che il fatto è avvenuto, non che sia più grave.
3. Se due caratteristiche dello stesso oggetto devono pesare di più insieme, come uno strumento a doppio uso in una cartella insolita, scriverlo come regola con il suo peso, invece di lasciarlo alla somma delle famiglie.
4. Nel report contare i fenomeni, non i segnali («3 fatti decisivi, 11 segnali»), e dare alle discordanze fra fonti uno stato loro.

Dai risultati mancanti e parziali (sezione 15) ne vengono altre cinque:

1. Uno stato «parziale» nella tabella dei 41 controlli, con le fonti usate e quelle mancate per ogni controllo. Un controllo parziale o non verificabile conta come copertura insufficiente: niente «nessun indizio».
2. Controlli di plausibilità sull'output di Volatility: un Windows acceso ha decine di processi, fra cui System, smss, csrss, wininit, services e lsass, porte in ascolto, centinaia di servizi e variabili d'ambiente. Sotto queste soglie, o se psscan trova molti più processi di pslist, un avviso: «output anomalo o forse incompleto: non si distingue fra un problema di acquisizione, di estrazione o un occultamento». Gli indizi restano nel report, ma da soli non portano oltre «da verificare».
3. Confrontare righe e SHA-256 di ogni output con quelli del manifesto, e leggere il campo «complete».
4. Le stesse soglie nel raccoglitore, così chi acquisisce lo sa subito e può ripetere l'acquisizione: oggi scrive «10 su 10» anche su un'immagine dimezzata.
5. Correggere la nota su svcscan con il registro presente: il controllo dei servizi rimasti solo in memoria non si fa.

Dalle configurazioni verificate (sezione 16) ne vengono altre quattro:

1. Nel README, al posto di «o successive», la tabella delle configurazioni verificate e un elenco breve di quelle che dovrebbero funzionare ma non sono provate.
2. Nel raccoglitore, un controllo prima della raccolta: versioni di Python e Volatility rispetto a quelle provate, i dieci plugin caricabili, i simboli del kernel dell'immagine disponibili o il server raggiungibile, lo spazio per gli output. L'esito va nel manifesto.
3. Nella CI, il raccoglitore con Python 3.8 oltre che con l'ultima versione, e la ricostruzione dello zip della release confrontata con quello allegato; nelle note della release, lo SHA-256 dei tre artefatti.
4. Nel changelog, correggere la frase sull'avviso per i plugin senza risultati: vale solo per quelli falliti.

Dalle prove prima dell'uso professionale (sezione 17) ne vengono altre quattro:

1. Quando la rete viene da netstat perché netscan si è fermato o è fallito, dirlo nel report e nel riepilogo del raccoglitore, e contare i controlli 5 e 7 come parziali: netstat non vede le connessioni chiuse.
2. Nel report, il motivo del fallimento preso dal manifesto. Per un file che Volatility non riconosce: «non è un'immagine di memoria di Windows, o mancano i simboli», senza chiamarlo RAM. Nessuna nota «risultati usati» quando non ce n'è nessuno.
3. Una RAM senza nome, come quella di una raccolta interrotta prima di envars, va riconosciuta da build, avvio e SID, come fa il prototipo, e non usata solo perché sta nella stessa origine dati.
4. Prima di dichiarare la RAM pronta: un'immagine pulita autentica, documentata con la scheda, e il registro delle prove rifatto sullo zip di ogni release, con lo SHA-256 del codice provato.

Come deciso il 12 ottobre, le modifiche al README delle sezioni 11 e 12 si fanno nella 1.3, insieme a queste correzioni.

**Decisioni del 12 e 13 ottobre per la 1.3.** Versioni: si dichiarano e si provano solo le ultime, Autopsy 4.23.1 e Volatility 3 2.28.2, al posto di «Autopsy 4.19 or later» e «Volatility 3 2.4 or later» del README 1.2. Le prove sulle versioni vecchie (sezioni 11, 12 e 16) restano come informazione. Non servono più la tabella delle configurazioni nel README né i processi «forse nascosti» abbassati con le versioni vecchie. Abbinamento: quale RAM va con quale macchina lo indica l'analista, nell'ingest del plugin o con l'host di Autopsy, e il plugin non lo deduce più dal nome. Il 13 ottobre: il plugin controlla la scelta con gli artefatti che già legge e, se qualcosa la contraddice, dà un avviso di compatibilità, che come ogni avviso impedisce «nessun indizio». I controlli sono quelli del prototipo della sezione 13, usati per avvisare e non per decidere: la build della RAM contro quella del registro, per famiglia di kernel; il nome del computer; l'avvio della RAM contro gli eventi di avvio del registro System; il SID della macchina; l'ora dell'acquisizione contro il periodo coperto dai registri. Se un controllo contraddice la scelta, gli indizi di quella RAM restano nel report, segnati, ma non contano per il verdetto finché l'analista non corregge la scelta. Il riconoscimento della RAM senza nome (sezione 17) non serve. Restano una RAM per una sola installazione, il nome dell'installazione mai dalla RAM e, nel report, quale RAM è stata usata, chi l'ha scelta e l'esito di ogni controllo.

Dopo le correzioni il set cieco non è più cieco. La nuova misura va fatta su dati non usati per correggere: per esempio [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) e le parti di [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) che non vengono dai due set usati qui.

## 19. Limiti della misura

I numeri valgono per la parte del plugin che lavora sui registri di eventi; il resto non è ancora misurato con una verità indipendente. E non è una valutazione indipendente: le etichette sono di altri, ma dati, banco, interpretazione e correzioni no.

- **Solo registri di eventi.** I controlli su registro di sistema, file, Prefetch, Amcache, attività pianificate e WMI li ho visti all'opera solo sulle 9 macchine dello sviluppo.
- **Campioni brevi.** Ogni campione d'attacco è un registro di pochi minuti con una tecnica. In un caso reale le tracce sono di più e di più tipi, e il verdetto può sommarle.
- **Ambito largo.** Basta un evento letto dalle regole perché un campione sia nell'ambito, anche se la tecnica sta in altri eventi. Questo abbassa la sensibilità misurata: il 43% è la copertura sul corpus, non la sensibilità sulle tecniche che il plugin dichiara.
- **Dataset pensati per i SIEM.** Alcuni campioni (ricognizione, accessi negati) sono spunti per un SIEM, non indicatori di compromissione per un triage.
- **Pochi sistemi puliti.** 7 installazioni con registri di ore o giorni, preparate da ricercatori che hanno installato software apposta e cancellato registri, più 3 macchine già usate nello sviluppo: bastano per trovare le cause dei falsi positivi, non per stimarne la frequenza.
- **Fuori da Autopsy.** Ho misurato il motore con lo stesso Jython di Autopsy ma senza Autopsy. Dentro Autopsy il plugin installato dà gli stessi segnali del motore in cinque versioni (sezione 11), ma tutte le prove dentro Autopsy sono su Linux.
- **RAM.** Due sole immagini vere, entrambe di sfide pubbliche: mostrano che la lettura è fedele e quali regole mancano, non quanto spesso la RAM trova un attacco. Gli scenari sintetici servono solo per i tempi. Nessuna delle due è di una macchina pulita. L'abbinamento con il disco l'ho contato su 77 coppie fatte da due sole RAM vere e dalle loro copie, non su un clone vero. Le varianti dei risultati mancanti partono da una RAM costruita durante lo sviluppo; l'immagine troncata invece è vera.

## 20. Come misurare il resto

Per i controlli che non stanno nei registri di eventi servono immagini disco complete con una soluzione pubblicata. Da qui non posso scaricarle; il protocollo è questo.

1. **Scegli i casi prima di guardare i risultati.** Compromessi: casi didattici con soluzione pubblicata, per esempio le immagini complete di [DFIR Madness](https://dfirmadness.com/) e i casi di [NIST CFReDS](https://cfreds.nist.gov/). Puliti di due tipi: macchine installate da zero e usate per alcuni giorni, per provare la catena; e benigni difficili, con attività legittime che somigliano a un attacco: RMM autorizzati, amministrazione con PowerShell, backup, provisioning, manutenzione, acquisizioni forensi. In entrambi l'etichetta «pulito» va documentata, non dedotta dall'assenza di attacchi noti.
2. **Scrivi le etichette prima di eseguire il plugin**, e falle scrivere a chi non ha scritto le regole: compromessa sì o no, tecniche presenti, prova attesa per ciascuna.
3. **Congela il plugin:** stessa versione e stessa impronta dei file per tutta la misura.
4. **Esegui in Autopsy** e salva il CSV dei segnali di ogni caso, oppure usa il banco di misura allegato.
5. **Calcola le stesse tabelle** di questo documento, ma separate: rilevati e sfuggiti per tecnica, con gli sfuggiti divisi in quattro gruppi (tecnica visibile e coperta da una regola: errore della regola; visibile ma senza regola: lacuna; prova assente dal campione: non valutabile; prova persa dal lettore: difetto di estrazione), riportando anche il dato sull'intero corpus; falsi positivi per sistema; intervalli che tengano conto della fonte dei campioni; tempi e memoria.
6. **Dopo ogni modifica alle regole** rifai la misura su casi non usati per modificarle.

Su Windows, prima di usare il plugin su un caso vero: una prova per ogni postazione e versione di Autopsy, con il protocollo e lo script dello zip (sezione 11).

Per la RAM, prima di usarla nel lavoro: un'immagine pulita acquisita insieme al disco della stessa macchina e documentata con la scheda, e almeno un caso benigno difficile (la procedura è nello zip, in validazione/SCHEDA\_PULITA.txt), poi il registro delle prove rifatto sullo zip di ogni release (sezione 17).

## 21. Riproducibilità e fonti

Tutto quello che serve per rifare la misura è in `valutazione-1.2.zip`: gli script del banco, i risultati caso per caso e le tabelle in CSV.

- **Plugin:** versione 1.2, i 17 file `.py` della release senza modifiche; Jython 2.7.4 di Autopsy 4.23.1; OpenJDK 21.
- **Lettore indipendente** usato per contare gli eventi e per stabilire l'ambito: [evtx](https://github.com/omerbenamram/pyevtx-rs), in Rust.
- **Set cieco:** [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack), commit `4748560` del 21 maggio 2026.
- **Set visto:** [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), commit `4ceed2f` del 24 gennaio 2023.
- **Sistemi puliti:** [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline), i 7 archivi dell'ultima release (`win7-x86`, `win2022-evtx`, `win2022-ad`, `win10-client`, `win11-client`, `win2022-0-20348-azure`, `win11-client-2023`); gli SHA-256 sono nello zip.
- **Macchine:** [AndrewRathbun/DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum), commit `fdcb1fa`, e gli artefatti già usati nella regressione.
- **Intervalli:** di Wilson al 95%.

L'insieme sigillato della sezione 10 è nello zip, in `sigillato/`: l'elenco dei 37 campioni con gli SHA-256, presi da [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) al commit `0845333`. Lo script `tempo.py` ricava l'anno di ingresso di ogni campione del set cieco dalla storia del suo repository.

**Compatibilità.** Nello zip, in `compatibilita/`: il protocollo con le aggiunte datate, gli script, gli esiti di ogni prova (`esecuzioni.jsonl`, `esiti.csv`, `sintesi.json`), i log di Autopsy e i rapporti di errore della JVM. Archivi usati, con gli SHA-256 nello zip: Autopsy 4.19.0, 4.20.0 e 4.22.1 da [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy/releases), più 4.21.0 e 4.23.1 dello sviluppo; sleuthkit-java 4.11.0, 4.12.0, 4.12.1 e 4.14.0 da [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit/releases); Liberica JRE 8u462+11 Full da [bell-sw/Liberica](https://github.com/bell-sw/Liberica/releases).

**RAM su immagini vere.** Nello zip, in `ram_reale/`: il protocollo con le aggiunte datate, i fatti delle soluzioni con le previsioni, gli script (`verifica_ram.py`, `mutazioni_r3.py`), le raccolte di Volatility, i report del plugin e le diagnosi sulle versioni. Le immagini sono nel repository [SecurityNik/CTF](https://github.com/SecurityNik/CTF); le soluzioni: [TOTAL RECALL](https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html), [Silence of the RAM](https://www.securitynik.com/2026/01/ctf-silence-of-ram-tushars-write-up.html).

**Abbinamento fra RAM e disco.** Nello zip, in `abbinamento/`: il protocollo con le previsioni, gli script delle prove (`prepara_abbinamento.py`, `abbinamento.py`), il prototipo `identita.py`, gli esiti per prova e i report. rath11 viene dal DFIR Artifact Museum, come nella sezione 8.

**Doppio conteggio.** Nello zip, in `conteggio/`: `aggregazione.py`, che rilegge i 595 verdetti e li ricalcola contando i fenomeni, gli esiti per verdetto e `giudica_jy.py`, che applica la regola sui processi ai 386 processi delle due RAM vere.

**Risultati mancanti e parziali.** Nello zip, in `mancanti/`: il protocollo con le previsioni, gli script delle varianti, gli esiti e i report. La raccolta dell'immagine troncata è in `ram_reale/raccolte/SR_troncata_2282`; l'immagine si rifà dal 7z pubblicato, tagliandola a 4.294.688.768 byte.

**Configurazioni verificate.** Nello zip, in `configurazioni/`: la tabella completa, con lo stato e la prova di ogni configurazione; `verifica_release.sh`, che rifà le verifiche sulla release, e il suo output; le prove del raccoglitore con Python da 3.8 a 3.14 e la misura di durata e memoria. La raccolta con Python 3.8 è in `ram_reale/raccolte/SR_py38_2282`.

**Prove prima dell'uso professionale.** Nello zip, in validazione/: il protocollo con le aggiunte datate; le schede delle due immagini e la procedura per quella pulita; il conto dei processi; le matrici delle coppie con il prototipo; i guasti veri, con le raccolte di T3, T4 e T5, e le varianti H12–H14 con i report. Ci sono anche l'impronta del codice provato e il registro unico di tutte le prove sulla RAM.

---

## Appendice: dettaglio per tecnica (set cieco)

Tutte le 69 tecniche del set cieco: 70 dei 161 campioni nell'ambito segnalati per la tecnica, 73 sfuggiti, di cui 9 per il lettore dei registri. I criteri sono quelli della sezione 3 della scheda principale; il dettaglio campione per campione è in `campioni_cieco.csv` dentro `valutazione-1.2.zip`.

| Tattica | Tecnica (nome del dataset) | Campioni | Nell'ambito | Segnalati | Per la tecnica | Sfuggiti | Di cui per il lettore |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Antivirus | — | 2 | 1 | 0 | 0 | 1 | 1 |
| Catena APT completa | — | 11 | 9 | 8 | 8 | 1 | 0 |
| TA0001 Accesso iniziale | T1078-Valid accounts | 3 | 2 | 0 | 0 | 2 | 1 |
| TA0002 Esecuzione | T1047-Windows Management Instrumentation | 4 | 3 | 1 | 1 | 2 | 0 |
| TA0002 Esecuzione | T1053.005-Scheduled Task | 6 | 6 | 4 | 4 | 2 | 0 |
| TA0002 Esecuzione | T1059.001-PowerShell | 3 | 3 | 2 | 2 | 1 | 1 |
| TA0002 Esecuzione | T1059.003-Windows Command Shell | 1 | 1 | 1 | 1 | 0 | 0 |
| TA0002 Esecuzione | T1204-User execution | 1 | 1 | 1 | 1 | 0 | 0 |
| TA0002 Esecuzione | T1569.002-Service execution | 4 | 4 | 3 | 3 | 1 | 0 |
| TA0003 Persistenza | T1098.xxx-Account manipulation | 30 | 9 | 4 | 4 | 5 | 0 |
| TA0003 Persistenza | T1136-Create account | 11 | 7 | 5 | 5 | 2 | 0 |
| TA0003 Persistenza | T1197-BITS jobs | 4 | 2 | 1 | 1 | 1 | 0 |
| TA0003 Persistenza | T1505-Server Software Component | 2 | 0 | 0 | 0 | 0 | 0 |
| TA0003 Persistenza | T1505.001-SQL Stored Procedures | 5 | 2 | 0 | 0 | 2 | 0 |
| TA0003 Persistenza | T1543.003-Create or Modify System Process-Windows Service | 17 | 16 | 9 | 8 | 7 | 0 |
| TA0003 Persistenza | T1546-Event Triggered Execution | 6 | 2 | 1 | 1 | 1 | 1 |
| TA0003 Persistenza | T1547-Boot or Logon Autostart Execution | 3 | 0 | 0 | 0 | 0 | 0 |
| TA0003 Persistenza | T1574-Hijack Execution Flow | 4 | 2 | 1 | 1 | 1 | 1 |
| TA0004 Escalation dei privilegi | T1068-Exploitation for Privilege Escalation | 2 | 1 | 0 | 0 | 1 | 0 |
| TA0004 Escalation dei privilegi | T1134-Access Token Manipulation | 5 | 3 | 3 | 0 | 0 | 0 |
| TA0004 Escalation dei privilegi | T1134.005-Access Token Manipulation SID-History Injection | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0004 Escalation dei privilegi | T1484-Domain or Tenant Policy Modification | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0004 Escalation dei privilegi | T1484.001-Domain Policy Modification-Group Policy Modification | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0004 Escalation dei privilegi | T1546-Image File Execution Options Injection | 5 | 3 | 2 | 1 | 1 | 0 |
| TA0004 Escalation dei privilegi | T1574-DLL side-loading | 4 | 2 | 1 | 0 | 1 | 0 |
| TA0005 Elusione delle difese | T1027-Obfuscated Files or Information | 5 | 5 | 0 | 0 | 5 | 0 |
| TA0005 Elusione delle difese | T1070.001-Clear Windows event logs | 4 | 4 | 4 | 4 | 0 | 0 |
| TA0005 Elusione delle difese | T1070.006-Timestomp | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1078.002-Valid accounts-Domain accounts | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1112-Modify registry | 3 | 2 | 1 | 0 | 1 | 0 |
| TA0005 Elusione delle difese | T1140-Deobfuscate-Decode Files or Information | 1 | 1 | 1 | 1 | 0 | 0 |
| TA0005 Elusione delle difese | T1202- Indirect Command Execution | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1207-Rogue domain controller | 2 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1222.001-File and Directory Permissions Modification | 6 | 1 | 0 | 0 | 1 | 0 |
| TA0005 Elusione delle difese | T1553- Subvert Trust Controls | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1555.004-Windows Credential Manager | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0005 Elusione delle difese | T1562.001-Impair Defenses-Disable or Modify tool | 9 | 6 | 4 | 4 | 2 | 0 |
| TA0005 Elusione delle difese | T1562.002-Disable Windows Event Logging | 13 | 2 | 2 | 2 | 0 | 0 |
| TA0005 Elusione delle difese | T1562.004-Impair Defenses-Disable or Modify System Firewall | 6 | 3 | 1 | 1 | 2 | 2 |
| TA0005 Elusione delle difese | T1564-Hide artifacts | 1 | 1 | 0 | 0 | 1 | 0 |
| TA0006 Accesso alle credenziali | T1003-Credential dumping | 19 | 13 | 8 | 7 | 5 | 0 |
| TA0006 Accesso alle credenziali | T1040-Traffic sniffing | 1 | 1 | 0 | 0 | 1 | 0 |
| TA0006 Accesso alle credenziali | T1110.xxx-Brut force | 12 | 3 | 1 | 0 | 2 | 0 |
| TA0006 Accesso alle credenziali | T1552.004-Unsecured Credentials-Private Keys | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0006 Accesso alle credenziali | T1555-Credentials from Password Stores | 2 | 1 | 1 | 1 | 0 | 0 |
| TA0006 Accesso alle credenziali | T1557-Man in the middle | 2 | 1 | 0 | 0 | 1 | 0 |
| TA0006 Accesso alle credenziali | T1558-Steal or Forge Kerberos Tickets | 5 | 1 | 0 | 0 | 1 | 0 |
| TA0006 Accesso alle credenziali | T1649- Steal or Forge Authentication Certificates | 5 | 1 | 1 | 0 | 0 | 0 |
| TA0007 Ricognizione | T1016-System Network Configuration Discovery | 5 | 4 | 4 | 1 | 0 | 0 |
| TA0007 Ricognizione | T1018-Remote System Discovery | 1 | 1 | 0 | 0 | 1 | 0 |
| TA0007 Ricognizione | T1046-Network Service Scanning | 2 | 1 | 0 | 0 | 1 | 0 |
| TA0007 Ricognizione | T1069-Permission Groups Discovery | 7 | 4 | 1 | 0 | 3 | 1 |
| TA0007 Ricognizione | T1087-Account discovery | 8 | 6 | 2 | 2 | 4 | 0 |
| TA0007 Ricognizione | T1135.xxx-Network Share Discovery | 3 | 2 | 1 | 0 | 1 | 1 |
| TA0007 Ricognizione | T1201-Password Policy Discovery | 2 | 1 | 1 | 0 | 0 | 0 |
| TA0007 Ricognizione | T1482-Domain Trust Discovery | 1 | 1 | 0 | 0 | 1 | 0 |
| TA0008 Movimento laterale | — | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0008 Movimento laterale | T1021.001-Remote Desktop Protocol | 3 | 2 | 0 | 0 | 2 | 0 |
| TA0008 Movimento laterale | T1021.002-SMB Windows Admin Shares | 7 | 5 | 3 | 2 | 2 | 0 |
| TA0008 Movimento laterale | T1021.003-Distributed Component Object Model (DCOM) | 2 | 2 | 0 | 0 | 2 | 0 |
| TA0008 Movimento laterale | T1021.004-Remote Service SSH | 3 | 2 | 0 | 0 | 2 | 0 |
| TA0008 Movimento laterale | T1021.006-Windows Remote Management | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0008 Movimento laterale | T1550-Use Alternate Authentication Material | 1 | 1 | 1 | 0 | 0 | 0 |
| TA0009 Raccolta | T1125-Video capture | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0011 Comando e controllo | T1090-Proxy | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0011 Comando e controllo | T1572-Protocol tunneling | 1 | 1 | 1 | 1 | 0 | 0 |
| TA0040 Impatto | T1486-Data Encrypted for Impact | 1 | 0 | 0 | 0 | 0 | 0 |
| TA0040 Impatto | T1490-Inhibit System Recovery | 3 | 3 | 3 | 3 | 0 | 0 |
| TA0040 Impatto | T1565-Data manipulation | 1 | 0 | 0 | 0 | 0 | 0 |
| **Totale** |  | **293** | **161** | **88** | **70** | **73** | **9** |
