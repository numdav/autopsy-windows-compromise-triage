# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_lingua_en - Le traduzioni inglesi dei testi del plugin "Triage
compromissione" (English translations).

TESTI associa a ogni testo italiano scritto nel codice dentro tr(u'...'),
N_(u'...') o _ui(u'...') la sua traduzione inglese. Vedi tc_lingua.py.

Regole per chi aggiunge o corregge una traduzione:
  - la chiave e' il testo italiano identico a quello del codice, compresi
    gli spazi iniziali e finali, gli a capo e le maiuscole;
  - i segnaposto (%s, %d, %.1f, %02x, %%...) devono essere gli stessi e
    nello stesso ordine: i valori vengono inseriti per posizione;
  - i tag HTML e le entita' (&gt;) restano come sono;
  - niente caratteri non ASCII scritti direttamente: si usano gli escape
    Unicode (barra rovesciata, u e quattro cifre esadecimali).

Le traduzioni sono divise in piu' funzioni (una o piu' per ogni modulo che
contiene i testi) perche' Jython non compila funzioni piu' grandi di 64 KB.
Un testo usato in piu' moduli sta nel primo che lo usa.

Per controllare che non manchi nulla:  python3 tools/check_translations.py
"""


def _modulo():
    # TriageCompromissione.py
    return {
        u'(traccia non disponibile)':
            u'(traceback not available)',
        u'errore non descrivibile':
            u'error cannot be described',
        u'lettura non riuscita (posizione %d): %s':
            u'read failed (position %d): %s',
        u'interrogazione del database del caso non riuscita: %s':
            u'query to the case database failed: %s',
        u'Le impostazioni devono essere di tipo GenericIngestModuleJobSettings':
            u'The settings must be of type GenericIngestModuleJobSettings',
        u'Giorni da considerare \u00abrecenti\u00bb:':
            u'Days to treat as "recent":',
        u'Contati dall\'ultima attivit\u00e0 della macchina.':
            u'Counted back from the machine\'s last activity.',
        u'Accesso remoto autorizzato (RMM):':
            u'Authorized remote access (RMM):',
        u'Nomi separati da virgola: TeamViewer, AnyDesk':
            u'Comma-separated names: TeamViewer, AnyDesk',
        u'Restano nel report ma non pesano sul verdetto.':
            u'Reported, but they do not affect the verdict.',
        u'Lingua dei risultati:':
            u'Results language:',
        u'Vale per il messaggio, l\'albero e il report.':
            u'Applies to the message, the tree and the report.',
        u'Legge soltanto: non modifica l\'origine dati.':
            u'Read-only: it does not modify the data source.',
        u'Il report va nella cartella Reports del caso.':
            u'The report goes to the case\'s Reports folder.',
        u'Impostazione "giorni recenti" non valida: uso 30':
            u'Invalid "recent days" setting: using 30',
        u'Impostazione "RMM autorizzati" non leggibile: ignorata':
            u'Unreadable "authorized RMM" setting: ignored',
        u'Triage non riuscito: ':
            u'Triage failed: ',
        u'Triage non riuscito su %s':
            u'Triage failed on %s',
        u'origine dati':
            u'data source',
        u'Cerco le installazioni di Windows':
            u'Looking for Windows installations',
        u'[%d di %d] ':
            u'[%d of %d] ',
        u'Nell\'origine ci sono anche altre installazioni di Windows, non analizzate: %s.':
            u'The data source also contains other Windows installations, which were not analyzed: %s.',
        u'Triage: nessun artefatto di Windows in %s':
            u'Triage: no Windows artifacts in %s',
        u'Non ho trovato n\u00e9 registro di sistema n\u00e9 registri eventi: il triage non \u00e8 stato eseguito.':
            u'Neither the registry nor the event logs were found: the triage was not run.',
        u'Controllo non riuscito: ':
            u'Check failed: ',
        u'Scrivo il report e i risultati':
            u'Writing the report and the results',
        u'Report non scritto: ':
            u'Report not written: ',
        u'Risultati non pubblicati: ':
            u'Results not published: ',
        u'Fatto':
            u'Done',
        u'Triage completato in %.1f s':
            u'Triage completed in %.1f s',
        u'Ricerca dei risultati della RAM non riuscita: ':
            u'Search for the memory results failed: ',
        u'Elenco delle origini dati del caso non riuscito: ':
            u'Listing the data sources of the case failed: ',
        u'<i>1 controllo non riuscito: i dettagli sono nel report e nel log di Autopsy.</i>':
            u'<i>1 check failed: the details are in the report and in the Autopsy log.</i>',
        u'<i>%d controlli non riusciti: i dettagli sono nel report e nel log di Autopsy.</i>':
            u'<i>%d checks failed: the details are in the report and in the Autopsy log.</i>',
        u'Report: %s':
            u'Report: %s',
        u'<b>Il report non \u00e8 stato scritto</b>: vedi il log di Autopsy (Help &gt; Open Log Folder).':
            u'<b>The report was not written</b>: see the Autopsy log (Help &gt; Open Log Folder).',
        u'Nell\'albero: Analysis Results &gt; Triage compromissione.':
            u'In the tree: Analysis Results &gt; Compromise Triage.',
        u'Nell\'albero: Analysis Results &gt; Triage compromissione. <b>1 segnale non \u00e8 stato scritto '
        u'nell\'albero</b> (vedi il log di Autopsy): il report li contiene tutti.':
            u'In the tree: Analysis Results &gt; Compromise Triage. <b>1 finding was not written to the '
            u'tree</b> (see the Autopsy log): the report contains them all.',
        u'Nell\'albero: Analysis Results &gt; Triage compromissione. <b>%d segnali non sono stati scritti '
        u'nell\'albero</b> (vedi il log di Autopsy): il report li contiene tutti.':
            u'In the tree: Analysis Results &gt; Compromise Triage. <b>%d findings were not written to the '
            u'tree</b> (see the Autopsy log): the report contains them all.',
        u'<b>I risultati non sono stati scritti nell\'albero</b>: il report \u00e8 completo, il motivo \u00e8 nel '
        u'log di Autopsy (Help &gt; Open Log Folder). I risultati nell\'albero vengono scritti da Autopsy '
        u'4.19 in poi.':
            u'<b>The results were not written to the tree</b>: the report is complete, the reason is in the '
            u'Autopsy log (Help &gt; Open Log Folder). Results are written to the tree from Autopsy 4.19 '
            u'onwards.',
        u'Triage di %s: %s':
            u'Triage of %s: %s',
        u'Triage di %s: %s (%.1f s, %d interrogazioni al database)':
            u'Triage of %s: %s (%.1f s, %d database queries)',
        u'origine':
            u'source',
        u'File CSV non scritto: ':
            u'CSV file not written: ',
        u'Triage compromissione: %s (%s) - %s':
            u'Compromise Triage: %s (%s) - %s',
        u'Report scritto ma non registrato nel caso: ':
            u'Report written but not registered in the case: ',
        u'Triage compromissione: segnali':
            u'Compromise Triage: findings',
        u'Triage compromissione: verdetto':
            u'Compromise Triage: verdict',
        u'Peso':
            u'Weight',
        u'Controllo':
            u'Check',
        u'Famiglia':
            u'Family',
        u'Segnale':
            u'Finding',
        u'Dettagli':
            u'Details',
        u'Verdetto':
            u'Verdict',
        u'Motivo':
            u'Reason',
        u'Risultati precedenti non elencati (resteranno accanto ai nuovi): ':
            u'Previous results could not be listed (they will stay next to the new ones): ',
        u'Triage: risultati precedenti non rimossi':
            u'Triage: previous results not removed',
        u'Non \u00e8 stato possibile elencare i risultati dell\'analisi precedente: restano nell\'albero accanto '
        u'a quelli nuovi. Il report pi\u00f9 recente \u00e8 quello valido.':
            u'The results of the previous analysis could not be listed: they stay in the tree next to the new '
            u'ones. The most recent report is the valid one.',
        u'Risultato scritto ma non annunciato: ':
            u'Result written but not announced: ',
        u' (regola in pi\u00f9)':
            u' (extra rule)',
        u'Controllo %d':
            u'Check %d',
        u'Segnale non scritto: ':
            u'Finding not written: ',
        u'In tutto %d segnali non scritti':
            u'%d findings not written in total',
        u'Risultato precedente non rimosso: ':
            u'Previous result not removed: ',
        u'%d risultati dell\'analisi precedente non rimossi: restano accanto ai nuovi':
            u'%d results of the previous analysis not removed: they stay next to the new ones',
        u'%d risultati dell\'analisi precedente non sono stati rimossi e restano nell\'albero accanto a '
        u'quelli nuovi. Il report pi\u00f9 recente \u00e8 quello valido.':
            u'%d results of the previous analysis were not removed and stay in the tree next to the new ones. '
            u'The most recent report is the valid one.',
    }


def _controlli_1():
    # tc_controlli.py
    return {
        u'DA VERIFICARE':
            u'NEEDS REVIEW',
        u'Contesto e dati volatili':
            u'Context and volatile data',
        u'Account e accessi':
            u'Accounts and logons',
        u'Persistenza':
            u'Persistence',
        u'Programmi eseguiti':
            u'Program execution',
        u'Esecuzione remota con Impacket':
            u'Remote execution with Impacket',
        u'Strumenti di accesso remoto (RMM)':
            u'Remote access tools (RMM)',
        u'File, antivirus e anti-forensics':
            u'Files, antivirus and anti-forensics',
        u'Contesto del sistema':
            u'System context',
        u'Copia del Prefetch':
            u'Prefetch copy',
        u'Utenti collegati ora':
            u'Users logged on now',
        u'Processi con riga di comando e processo padre':
            u'Processes with command line and parent process',
        u'Connessioni di rete con il processo proprietario':
            u'Network connections with their owning process',
        u'Cache DNS':
            u'DNS cache',
        u'Sessioni e connessioni SMB':
            u'SMB sessions and connections',
        u'Copertura dei log e audit attivi':
            u'Log coverage and active auditing',
        u'Log cancellati':
            u'Cleared logs',
        u'Account locali, amministratori, profili':
            u'Local accounts, administrators, profiles',
        u'Logon remoti di rete e RDP':
            u'Remote network and RDP logons',
        u'Accessi falliti per indirizzo':
            u'Failed logons by address',
        u'Credenziali esplicite e connessioni in uscita':
            u'Explicit credentials and outbound connections',
        u'Sessioni RDP (Terminal Services)':
            u'RDP sessions (Terminal Services)',
        u'Attivit\u00e0 pianificate':
            u'Scheduled tasks',
        u'Attivit\u00e0 nascoste':
            u'Hidden tasks',
        u'Servizi':
            u'Services',
        u'Servizi installati (evento 7045)':
            u'Installed services (event 7045)',
        u'Chiavi Run e cartelle Esecuzione automatica':
            u'Run keys and Startup folders',
        u'Sottoscrizioni WMI':
            u'WMI subscriptions',
        u'Download con certutil':
            u'Downloads with certutil',
        u'Comandi sospetti (eventi 4688, Sysmon, PowerShell)':
            u'Suspicious commands (events 4688, Sysmon, PowerShell)',
        u'ShimCache, AmCache, UserAssist':
            u'ShimCache, AmCache, UserAssist',
        u'Attivit\u00e0 create e cancellate in pochi istanti':
            u'Tasks created and deleted within moments',
        u'Firme di atexec nelle attivit\u00e0':
            u'Signatures of atexec in tasks',
        u'Firme di smbexec nei servizi':
            u'Signatures of smbexec in services',
        u'File residui':
            u'Leftover files',
        u'Accessi alle share (evento 5145)':
            u'Share access (event 5145)',
        u'Programmi installati':
            u'Installed programs',
        u'RMM portabili, anche rinominati':
            u'Portable RMM tools, including renamed ones',
        u'LogMeIn e Pulseway':
            u'LogMeIn and Pulseway',
        u'Rilevamenti dell\'antivirus':
            u'Antivirus detections',
        u'File recenti nelle cartelle di appoggio':
            u'Recent files in staging folders',
        u'Cestino':
            u'Recycle Bin',
        u'Copie shadow':
            u'Shadow copies',
        u'Artefatti disattivati':
            u'Disabled artifacts',
        u'%d ore':
            u'%d h',
        u'%d giorni':
            u'%d days',
        u'Non riuscito: %s':
            u'Failed: %s',
        u'File non letto: %s (%s)':
            u'File not read: %s (%s)',
        u'Hive del registro con chiavi o valori non leggibili (tra parentesi quanti): %s%s. Sono '
        u'danneggiati: i controlli che li leggono possono essere incompleti.':
            u'Registry hives with unreadable keys or values (how many in brackets): %s%s. They are damaged: '
            u'the checks that read them may be incomplete.',
        u' e altri':
            u' and others',
        u'I registri eventi si fermano al %s UTC, ma gli altri artefatti (Prefetch, BAM, UserAssist, '
        u'AmCache, registro) mostrano attivit\u00e0 fino al %s UTC, %s dopo: i controlli sugli eventi non '
        u'coprono quel periodo. O la registrazione degli eventi \u00e8 stata fermata, o l\'orologio \u00e8 stato '
        u'spostato, oppure i file raccolti vengono da momenti diversi.':
            u'The event logs stop at %s UTC, but the other artifacts (Prefetch, BAM, UserAssist, AmCache, '
            u'registry) show activity until %s UTC, %s later: the event checks do not cover that period. '
            u'Either event logging was stopped, or the clock was changed, or the collected files come from '
            u'different moments.',
        u'Negli altri artefatti c\'\u00e8 un orario (fino al %s UTC) posteriore di %s all\'ultimo evento dei '
        u'registri (%s UTC): un orologio sbagliato o un orario alterato. Non sposta la finestra dei '
        u'controlli recenti.':
            u'The other artifacts contain one timestamp (up to %s UTC) that is %s later than the last event '
            u'in the logs (%s UTC): a wrong clock or an altered timestamp. It does not move the window of the '
            u'recent checks.',
        u'Negli altri artefatti ci sono %d orari (fino al %s UTC) posteriori di %s all\'ultimo evento dei '
        u'registri (%s UTC): un orologio sbagliato o un orario alterato. Non spostano la finestra dei '
        u'controlli recenti.':
            u'The other artifacts contain %d timestamps (up to %s UTC) that are %s later than the last event '
            u'in the logs (%s UTC): a wrong clock or an altered timestamp. They do not move the window of the '
            u'recent checks.',
        u'L\'ultimo spegnimento di Windows (%s UTC) \u00e8 posteriore di %s all\'ultimo evento dei registri (%s '
        u'UTC). Windows scrive sempre eventi quando si spegne: o la registrazione era ferma, o i registri '
        u'raccolti vengono da un momento precedente.':
            u'The last Windows shutdown (%s UTC) is %s later than the last event in the logs (%s UTC). '
            u'Windows always writes events when it shuts down: either logging was stopped, or the collected '
            u'logs come from an earlier moment.',
        u'(traccia dell\'errore non disponibile)':
            u'(error traceback not available)',
        u'Errore in "%s": %s':
            u'Error in "%s": %s',
        u'dato volatile: serve il triage dal vivo o la RAM analizzata con Volatility (vedi il README)':
            u'volatile data: it needs live triage or the memory analyzed with Volatility (see the README)',
        u'non serve su un\'immagine: il Prefetch viene letto dal controllo 21':
            u'not needed on an image: Prefetch is read by check 21',
        u'Registro: SOFTWARE':
            u'Registry: SOFTWARE',
        u'Registro: SYSTEM':
            u'Registry: SYSTEM',
        u'Registro: SAM':
            u'Registry: SAM',
        u'Registri eventi':
            u'Event logs',
        u'Registro: profili degli utenti':
            u'Registry: user profiles',
        u'Registro: AmCache':
            u'Registry: AmCache',
        u'Esecuzione automatica':
            u'Startup folders',
        u'File residui di Impacket':
            u'Impacket leftover files',
        u'Strumenti di accesso remoto':
            u'Remote access tools',
        u'Cronologia di PowerShell':
            u'PowerShell history',
    }


def _controlli_2():
    # tc_controlli.py
    return {
        u'Cartelle di appoggio':
            u'Staging folders',
        u'Memoria (RAM)':
            u'Memory (RAM)',
        u'Analisi degli eventi':
            u'Event analysis',
        u'Attivit\u00e0 pianificate: riepilogo':
            u'Scheduled tasks: summary',
        u'Strumenti di accesso remoto: riepilogo':
            u'Remote access tools: summary',
        u'Account: riepilogo':
            u'Accounts: summary',
        u'Tra gli strumenti di accesso remoto autorizzati c\'\u00e8 \u00ab%s\u00bb, che non corrisponde a nessuno '
        u'strumento conosciuto: non ha effetto. I nomi riconosciuti sono nell\'elenco RMM del file '
        u'tc_regole.py.':
            u'The authorized remote access tools include "%s", which does not match any known tool: it has no '
            u'effect. The recognized names are in the RMM list of the tc_regole.py file.',
        u'1 controllo interrotto da un errore: i risultati sono incompleti (i dettagli sono qui sotto e '
        u'nel log di Autopsy).':
            u'1 check interrupted by an error: the results are incomplete (the details are below and in the '
            u'Autopsy log).',
        u'%d controlli interrotti da un errore: i risultati sono incompleti (i dettagli sono qui sotto e '
        u'nel log di Autopsy).':
            u'%d checks interrupted by an error: the results are incomplete (the details are below and in the '
            u'Autopsy log).',
        u'L\'origine dati non riporta le date dei file (succede con i file logici aggiunti ad Autopsy '
        u'senza spuntare le date). Il controllo 38 non pu\u00f2 distinguere i file recenti da quelli vecchi e '
        u'li considera tutti; ai segnali che vengono dai file manca l\'orario.':
            u'The data source does not report file dates (this happens with logical files added to Autopsy '
            u'without ticking the timestamp options). Check 38 cannot tell recent files from old ones and '
            u'considers them all; the findings that come from files have no time.',
        u'Le date di creazione dei file dell\'origine sono posteriori all\'ultima attivit\u00e0 della macchina: '
        u'sono le date della copia, non quelle originali. Per i controlli sui file (38 e profili degli '
        u'utenti) \u00e8 stata usata la data di modifica.':
            u'The creation dates of the files in the data source are later than the machine\'s last activity: '
            u'they are the dates of the copy, not the original ones. The file checks (38 and user profiles) '
            u'used the modification date instead.',
        u'1 file non letto per errori di lettura (immagine danneggiata o file non accessibili): %s. I '
        u'controlli che ne dipendono sono incompleti.':
            u'1 file not read because of read errors (damaged image or inaccessible files): %s. The checks '
            u'that depend on it are incomplete.',
        u'%d file non letti per errori di lettura (immagine danneggiata o file non accessibili): %s%s. I '
        u'controlli che ne dipendono sono incompleti.':
            u'%d files not read because of read errors (damaged image or inaccessible files): %s%s. The '
            u'checks that depend on them are incomplete.',
        u'Segnali da confermare in una sola famiglia (%s): da soli non bastano. Cerca conferme dall\'IT, '
        u'dall\'utente e dai log centralizzati.':
            u'Findings to confirm in a single family (%s): on their own they are not enough. Look for '
            u'confirmation from IT, from the user and from centralized logs.',
        u'Segnale decisivo':
            u'Decisive finding',
        u'Da confermare':
            u'To confirm',
        u'Solo contesto':
            u'Context only',
        u'Non eseguito':
            u'Not run',
        u'Nulla da segnalare':
            u'Nothing to report',
        u'Artefatto non trovato':
            u'Artifact not found',
        u'Non verificabile':
            u'Cannot be verified',
    }


def _report_1():
    # tc_report.py
    return {
        u'Regola che non viene dalle 32 guide':
            u'Rule that does not come from the 32 guides',
        u'regola in pi\u00f9':
            u'extra rule',
        u'<details><summary>dettagli</summary><pre>%s</pre></details>':
            u'<details><summary>details</summary><pre>%s</pre></details>',
        u'Sistema operativo':
            u'Operating system',
        u'Ruolo':
            u'Role',
        u'controller di dominio':
            u'domain controller',
        u'Dominio':
            u'Domain',
        u'Installato il':
            u'Installed on',
        u' (UTC%s%02d:%02d al momento dell\'acquisizione)':
            u' (UTC%s%02d:%02d at acquisition time)',
        u'Fuso orario della macchina':
            u'Machine time zone',
        u'Ultimo spegnimento registrato':
            u'Last recorded shutdown',
        u'Ultima attivit\u00e0 trovata':
            u'Last activity found',
        u'Finestra dei controlli \u00abrecenti\u00bb':
            u'Window of the "recent" checks',
        u'dai %d giorni prima del %s UTC in poi':
            u'from %d days before %s UTC onwards',
        u'Desktop remoto':
            u'Remote Desktop',
        u'attivo':
            u'enabled',
        u'non attivo':
            u'not enabled',
        u'Origine dati':
            u'Data source',
        u'Cartella di Windows nell\'origine':
            u'Windows folder in the data source',
        u'Caso':
            u'Case',
        u'registri eventi letti: %d':
            u'event logs read: %d',
        u'servizi: %d':
            u'services: %d',
        u'attivit\u00e0 pianificate: %d':
            u'scheduled tasks: %d',
        u'Artefatti letti':
            u'Artifacts read',
        u'RAM (Volatility)':
            u'Memory (Volatility)',
        u'RMM indicati come autorizzati':
            u'RMM tools declared as authorized',
        u'Voce':
            u'Item',
        u'Valore':
            u'Value',
        u'<title>Triage compromissione - %s</title><style>%s</style></head><body><div class="pagina">':
            u'<title>Compromise Triage - %s</title><style>%s</style></head><body><div class="pagina">',
        u'<h1>Triage compromissione: %s</h1>':
            u'<h1>Compromise Triage: %s</h1>',
        u'origine senza nome':
            u'unnamed data source',
        u'<div class="sotto">Report generato il %s UTC dal plugin Triage compromissione %s per Autopsy. '
        u'Tutti gli orari sono in UTC.</div>':
            u'<div class="sotto">Report generated on %s UTC by the Windows Compromise Triage plugin %s for '
            u'Autopsy. All times are in UTC.</div>',
        u'<div class="scheda"><div class="numero">%d</div><div class="nome">Famiglie di '
        u'segnali</div></div>':
            u'<div class="scheda"><div class="numero">%d</div><div class="nome">Finding families</div></div>',
        u'<div class="avviso"><b>Copertura:</b> %s</div>':
            u'<div class="avviso"><b>Coverage:</b> %s</div>',
        u'<div class="osservazione"><b>Nota:</b> %s</div>':
            u'<div class="osservazione"><b>Note:</b> %s</div>',
        u'<div class="errore"><b>Un controllo non \u00e8 riuscito:</b><pre>%s</pre></div>':
            u'<div class="errore"><b>A check failed:</b><pre>%s</pre></div>',
        u'<a href="#fase%d">Fase %d</a>':
            u'<a href="#fase%d">Phase %d</a>',
        u'<a href="#metodo">Come leggere il report</a></p>':
            u'<a href="#metodo">How to read the report</a></p>',
        u'<h2>Sistema</h2>':
            u'<h2>System</h2>',
        u'<h2 id="segnali">Segnali</h2>':
            u'<h2 id="segnali">Findings</h2>',
        u'Quando (UTC)':
            u'When (UTC)',
        u'<h3>Decisivi (%d)</h3>':
            u'<h3>Decisive (%d)</h3>',
        u'<h3>Da confermare (%d)</h3>':
            u'<h3>To confirm (%d)</h3>',
        u'<p>Nessun segnale decisivo o da confermare.</p>':
            u'<p>No decisive findings and none to confirm.</p>',
        u'<details><summary>Solo contesto (%d): voci che non pesano sul verdetto</summary>':
            u'<details><summary>Context only (%d): items that do not affect the verdict</summary>',
        u'<p class="nota">Per non allungare il report, alcuni controlli mostrano solo i primi segnali: '
        u'%s.</p>':
            u'<p class="nota">To keep the report short, some checks show only their first findings: %s.</p>',
        u'controllo %d, %d in tutto':
            u'check %d, %d in total',
        u'<h2 id="cronologia">Cronologia dei segnali</h2>':
            u'<h2 id="cronologia">Timeline of the findings</h2>',
        u'<p class="nota">Solo i segnali decisivi e da confermare che hanno un orario. Per le chiavi del '
        u'registro l\'orario \u00e8 l\'ultima scrittura della chiave.</p>':
            u'<p class="nota">Only the decisive findings and the findings to confirm that have a time. For '
            u'registry keys the time is the last write of the key.</p>',
        u'<p>Nessun segnale con un orario.</p>':
            u'<p>No findings with a time.</p>',
        u'<h2 id="controlli">I 41 controlli della checklist</h2>':
            u'<h2 id="controlli">The 41 checks of the checklist</h2>',
        u'Fase %d':
            u'Phase %d',
        u'N.':
            u'No.',
        u'Fase':
            u'Phase',
        u'Esito':
            u'Outcome',
        u'Nota':
            u'Note',
        u'<h2 id="fase%d">Fase %d \u2014 %s</h2>':
            u'<h2 id="fase%d">Phase %d \u2014 %s</h2>',
        u'<p>I controlli 3, 4, 5 e 7 vengono dalla RAM analizzata con Volatility (vedi Sistema). La cache '
        u'DNS (controllo 6) e la copia del Prefetch (2) richiedono il triage dal vivo.</p>':
            u'<p>Checks 3, 4, 5 and 7 come from the memory analyzed with Volatility (see System). The DNS '
            u'cache (check 6) and the copy of Prefetch (2) need live triage.</p>',
        u'<p>I controlli da 2 a 7 riguardano dati volatili (sessioni, processi, connessioni, cache DNS): '
        u'su un\'immagine del disco non ci sono. Servono il triage dal vivo o un dump della RAM.</p>':
            u'<p>Checks 2 to 7 concern volatile data (sessions, processes, connections, DNS cache): a disk '
            u'image does not contain them. They need live triage or a RAM dump.</p>',
        u'<p class="nota">Nessuna tabella per questa fase.</p>':
            u'<p class="nota">No tables for this phase.</p>',
        u'<div class="fase"><h3>%d. %s <span class="sotto">(%d righe)</span></h3>':
            u'<div class="fase"><h3>%d. %s <span class="sotto">(%d rows)</span></h3>',
        u'<details%s><summary>mostra o nascondi</summary>':
            u'<details%s><summary>show or hide</summary>',
        u'<h2 id="metodo">Come leggere il report</h2>':
            u'<h2 id="metodo">How to read the report</h2>',
        u'<p><b>Recente.</b> Alcuni controlli pesano di pi\u00f9 ci\u00f2 che \u00e8 recente. La finestra si conta '
        u'all\'indietro da un riferimento: il pi\u00f9 vecchio tra l\'ultimo evento scritto nel registro '
        u'Security e l\'ultimo scritto nel System (o, se mancano, gli ultimi eventi degli altri registri e '
        u'l\'ora di spegnimento). Non \u00e8 l\'orario pi\u00f9 recente trovato: un solo orario sbagliato o alterato '
        u'sposterebbe la finestra. Tutto ci\u00f2 che viene dopo il riferimento \u00e8 recente.</p>':
            u'<p><b>Recent.</b> Some checks give more weight to what is recent. The window is counted back '
            u'from a reference time: the older of the last event written to the Security log and the last one '
            u'written to the System log (or, if they are missing, the last events of the other logs and the '
            u'shutdown time). It is not the most recent timestamp found: a single wrong or altered timestamp '
            u'would move the window. Everything after the reference time is recent.</p>',
        u'<p><b>Ogni segnale vale solo se l\'IT non lo spiega:</b> un amministratore o uno strumento di '
        u'assistenza autorizzato lasciano tracce simili. Il triage serve a decidere se approfondire, non '
        u'sostituisce l\'analisi.</p>':
            u'<p><b>Every finding counts only if IT cannot explain it:</b> an administrator or an authorized '
            u'support tool leaves similar traces. Triage helps decide whether to dig deeper; it does not '
            u'replace the analysis.</p>',
        u'<p><b>Regole in pi\u00f9.</b> I segnali con questa etichetta vengono da regole note che non fanno '
        u'parte delle 32 guide su cui \u00e8 costruita la checklist (per esempio: backdoor \u00absticky keys\u00bb, '
        u'esclusioni di Defender, cronologia di PowerShell).</p>':
            u'<p><b>Extra rules.</b> The findings with this label come from well-known rules that are not '
            u'part of the 32 guides the checklist is built on (for example: the "sticky keys" backdoor, '
            u'Defender exclusions, PowerShell history).</p>',
    }


def _report_2():
    # tc_report.py
    return {
        u'<p class="sotto">Analisi completata in %.1f secondi.</p>':
            u'<p class="sotto">Analysis completed in %.1f seconds.</p>',
        u'Titolo del controllo':
            u'Check title',
        u'Regola in pi\u00f9':
            u'Extra rule',
        u's\u00ec':
            u'yes',
    }


def _regole_1():
    # tc_regole.py
    return {
        u'Decisivo':
            u'Decisive',
        u'Informativo':
            u'Informational',
        u'Accessi':
            u'Logons',
        u'Account':
            u'Accounts',
        u'Strumenti d\'attacco':
            u'Attack tools',
        u'Strumenti a doppio uso':
            u'Dual-use tools',
        u'Esecuzione remota':
            u'Remote execution',
        u'Accesso remoto (RMM)':
            u'Remote access (RMM)',
        u'File':
            u'Files',
        u'Anti-forensics':
            u'Anti-forensics',
        u'Antivirus':
            u'Antivirus',
        u'Esfiltrazione e tunnel':
            u'Exfiltration and tunneling',
        u'strumento d\'attacco':
            u'attack tool',
        u'strumento d\'attacco (%s)':
            u'attack tool (%s)',
        u'binario di Windows spesso abusato':
            u'frequently abused Windows binary',
        u'strumento a doppio uso':
            u'dual-use tool',
        u'strumento a doppio uso (%s)':
            u'dual-use tool (%s)',
        u'script o comando d\'attacco (%s)':
            u'attack script or command (%s)',
        u'un\'attivit\u00e0 pianificata':
            u'a scheduled task',
        u'un servizio':
            u'a service',
        u'una voce di avvio automatico nel registro':
            u'an autostart entry in the registry',
        u'output ridiretto su \\\\127.0.0.1 (firma di Impacket)':
            u'output redirected to \\\\127.0.0.1 (Impacket signature)',
        u'scrive in una named pipe (tecnica getsystem di Meterpreter e Cobalt Strike)':
            u'writes to a named pipe (getsystem technique of Meterpreter and Cobalt Strike)',
        u'il comando in chiaro: %s':
            u'the decoded command: %s',
        u'comando codificato in Base64 che in chiaro si limita a leggere informazioni':
            u'Base64-encoded command that, once decoded, only reads information',
        u'comando codificato in Base64':
            u'Base64-encoded command',
        u'esecuzione di codice a finestra nascosta':
            u'code execution in a hidden window',
        u'mshta.exe esegue codice in linea o preso dalla rete':
            u'mshta.exe runs inline code or code fetched from the network',
        u'regsvr32.exe esegue uno scriptlet':
            u'regsvr32.exe runs a scriptlet',
        u'rundll32.exe esegue codice in linea':
            u'rundll32.exe runs inline code',
        u'curl.exe contatta la rete':
            u'curl.exe contacts the network',
        u'curl.exe scarica un programma dal sito del produttore':
            u'curl.exe downloads a program from the vendor\'s site',
        u'curl.exe scarica e salva un programma':
            u'curl.exe downloads and saves a program',
        u'curl.exe scarica un file da un indirizzo IP pubblico':
            u'curl.exe downloads a file from a public IP address',
        u'curl.exe scarica un file in una cartella scrivibile dagli utenti':
            u'curl.exe downloads a file into a user-writable folder',
        u'curl.exe scarica un file di dati':
            u'curl.exe downloads a data file',
        u'certutil.exe scarica un programma dal sito del produttore':
            u'certutil.exe downloads a program from the vendor\'s site',
        u'certutil.exe scarica un programma':
            u'certutil.exe downloads a program',
        u'certutil.exe aggiorna un certificato o una lista di revoca':
            u'certutil.exe updates a certificate or a revocation list',
        u'certutil.exe scarica un file da un indirizzo IP pubblico':
            u'certutil.exe downloads a file from a public IP address',
        u'certutil.exe scarica dalla rete':
            u'certutil.exe downloads from the network',
        u'bitsadmin.exe scarica un programma dal sito del produttore':
            u'bitsadmin.exe downloads a program from the vendor\'s site',
        u'bitsadmin.exe scarica un programma':
            u'bitsadmin.exe downloads a program',
        u'bitsadmin.exe scarica un file da un indirizzo IP pubblico':
            u'bitsadmin.exe downloads a file from a public IP address',
        u'bitsadmin.exe scarica dalla rete':
            u'bitsadmin.exe downloads from the network',
        u'msiexec.exe installa dalla rete un pacchetto da un indirizzo IP o senza estensione .msi':
            u'msiexec.exe installs from the network a package from an IP address or without the .msi extension',
        u'msiexec.exe installa un pacchetto preso dal sito del produttore':
            u'msiexec.exe installs a package taken from the vendor\'s site',
        u'msiexec.exe installa un pacchetto preso dalla rete':
            u'msiexec.exe installs a package taken from the network',
        u'%s scarica dalla rete':
            u'%s downloads from the network',
        u'%s esegue codice preso dalla rete':
            u'%s runs code fetched from the network',
        u'scarica dalla rete ed esegue':
            u'downloads from the network and executes',
        u'scarica un programma dal sito del produttore':
            u'downloads a program from the vendor\'s site',
        u'scarica dalla rete un programma':
            u'downloads a program from the network',
        u'scarica un file da un indirizzo IP pubblico':
            u'downloads a file from a public IP address',
        u'%s contatta la rete':
            u'%s contacts the network',
        u'un indirizzo Internet tra gli argomenti':
            u'an Internet address among the arguments',
        u'wmic.exe avvia un processo':
            u'wmic.exe starts a process',
        u'wmic.exe esegue un foglio di stile preso dalla rete':
            u'wmic.exe runs a stylesheet fetched from the network',
        u'%s prende un file da un server WebDAV':
            u'%s fetches a file from a WebDAV server',
        u'%s esegue un file da un server WebDAV':
            u'%s runs a file from a WebDAV server',
        u'%s usa una cartella WebDAV':
            u'%s uses a WebDAV folder',
        u'%s usa una condivisione su un indirizzo IP pubblico':
            u'%s uses a share on a public IP address',
        u'%s esegue un file da una condivisione indicata per indirizzo IP':
            u'%s runs a file from a share given by IP address',
        u'%s usa una condivisione indicata per indirizzo IP':
            u'%s uses a share given by IP address',
        u'passa a un interprete quello che riceve dalla rete':
            u'pipes into an interpreter what it receives from the network',
        u'passa l\'output di un comando a un interprete':
            u'pipes the output of a command into an interpreter',
        u'%s lancia uno script da una cartella scrivibile dagli utenti':
            u'%s launches a script from a user-writable folder',
        u'%s lavora su una cartella scrivibile dagli utenti':
            u'%s works on a user-writable folder',
        u'cmd.exe cancella file in una cartella scrivibile dagli utenti':
            u'cmd.exe deletes files in a user-writable folder',
        u'comando offuscato (^ o "" in mezzo alle parole)':
            u'obfuscated command (^ or "" in the middle of words)',
    }


def _regole_2():
    # tc_regole.py
    return {
        u'%s avviato da una copia fuori dalle cartelle di sistema':
            u'%s started from a copy outside the system folders',
        u'programma in una cartella dove di norma non ce ne sono':
            u'program in a folder that normally holds none',
        u'programma in una cartella temporanea':
            u'program in a temporary folder',
        u'programma avviato da una condivisione indicata per indirizzo IP o via WebDAV':
            u'program started from a share given by IP address or over WebDAV',
        u'programma avviato da una condivisione di rete':
            u'program started from a network share',
        u'programma in una cartella dell\'utente':
            u'program in a user folder',
        u'nome di un processo di sistema fuori dalle cartelle di sistema':
            u'system process name outside the system folders',
        u'il nome contiene il carattere che inverte il verso del testo (camuffa l\'estensione)':
            u'the name contains the character that reverses the text direction (it disguises the extension)',
        u'conhost.exe --headless avvia un comando senza finestra':
            u'conhost.exe --headless starts a command without a window',
        u'crea %s che lancia: %s':
            u'creates %s that launches: %s',
        u'cerca per nome uno ':
            u'searches by name for ',
        u'nomina uno ':
            u'mentions ',
        u'cancellazione delle copie shadow o dei backup':
            u'deletion of shadow copies or backups',
        u'download con certutil':
            u'download with certutil',
        u'download o installazione da rete con uno strumento di Windows':
            u'download or installation from the network with a Windows tool',
        u'dati preparati o inviati verso l\'esterno (caricamento con curl, archivio RAR cifrato anche nei '
        u'nomi)':
            u'data staged or sent outside (upload with curl, RAR archive encrypted including the file names)',
        u'cancellazione dei registri eventi da riga di comando':
            u'event logs cleared from the command line',
        u'firma di atexec: output in un file .tmp di 8 lettere in Windows\\Temp':
            u'atexec signature: output to an 8-letter .tmp file in Windows\\Temp',
        u'output ridiretto in un file .tmp di 8 lettere in Windows\\Temp: lo fa atexec, ma qui il nome non '
        u'sembra casuale':
            u'output redirected to an 8-letter .tmp file in Windows\\Temp: atexec does this, but here the name '
            u'does not look random',
        u'cancellazione di uno dei registri eventi da riga di comando (non quello di sicurezza)':
            u'one of the event logs cleared from the command line (not the security log)',
        u'registrazione delle tracce disattivata (servizio dei registri eventi, audit, cronologia di '
        u'PowerShell)':
            u'trace recording disabled (event log service, auditing, PowerShell history)',
        u'ripristino di sistema disattivato':
            u'system recovery disabled',
        u'certutil usato per codificare o decodificare un file':
            u'certutil used to encode or decode a file',
        u'estrazione di credenziali':
            u'credential dumping',
        u'copia del SAM, del registro SYSTEM o del database di Active Directory (passo tipico '
        u'dell\'estrazione di credenziali, ma anche di un backup)':
            u'copy of the SAM, of the SYSTEM hive or of the Active Directory database (a typical step of '
            u'credential dumping, but also of a backup)',
        u'creazione di una copia shadow da riga di comando':
            u'shadow copy created from the command line',
        u'creazione di un account da riga di comando':
            u'account created from the command line',
        u'utente aggiunto a un gruppo privilegiato da riga di comando':
            u'user added to a privileged group from the command line',
        u'protezioni disattivate da riga di comando':
            u'protections disabled from the command line',
        u'cancellazione sicura o del journal':
            u'secure deletion or journal deletion',
        u'preparazione al furto di credenziali (WDigest, Restricted Admin, ricerca di password)':
            u'preparation for credential theft (WDigest, Restricted Admin, password search)',
        u'antivirus fermato o disattivato da riga di comando':
            u'antivirus stopped or disabled from the command line',
        u'esecuzione o copia verso un\'altra macchina (wmic /node, sc o schtasks remoti, condivisione '
        u'amministrativa)':
            u'execution on or copy to another machine (wmic /node, remote sc or schtasks, administrative '
            u'share)',
        u'Desktop remoto abilitato da riga di comando':
            u'Remote Desktop enabled from the command line',
        u'account nascosto dalla schermata di accesso':
            u'account hidden from the logon screen',
        u'porta di servizio sulla schermata di accesso (\u00absticky keys\u00bb)':
            u'backdoor on the logon screen ("sticky keys")',
        u'programma di Windows usato per far eseguire codice altrui (InstallUtil, odbcconf, cmstp, '
        u'mavinject)':
            u'Windows program used to run someone else\'s code (InstallUtil, odbcconf, cmstp, mavinject)',
        u'elenco di tutti gli SPN del dominio (ricognizione per il Kerberoasting)':
            u'listing of all the SPNs of the domain (reconnaissance for Kerberoasting)',
        u'firma di Impacket: output ridiretto su \\\\127.0.0.1':
            u'Impacket signature: output redirected to \\\\127.0.0.1',
        u'nome di servizio BTOBTO (smbexec fino a maggio 2023)':
            u'service name BTOBTO (smbexec until May 2023)',
        u'il servizio contiene \u00ab%s\u00bb (firma di smbexec)':
            u'the service contains "%s" (smbexec signature)',
        u'il servizio lancia execute.bat dalla cartella temporanea (come smbexec fino al 2023)':
            u'the service launches execute.bat from the temporary folder (like smbexec until 2023)',
        u'il servizio lancia un batch con nome di 8 lettere a caso in C:\\Windows (smbexec dal 2023)':
            u'the service launches a batch file with a random 8-letter name in C:\\Windows (smbexec since 2023)',
        u'il servizio lancia un batch in C:\\Windows tramite cmd':
            u'the service launches a batch file in C:\\Windows through cmd',
        u'modifica le protezioni di Defender':
            u'changes Defender protections',
        u'script d\'attacco':
            u'attack script',
        u'codice compresso e codificato, decompresso in memoria ed eseguito (stager)':
            u'compressed and encoded code, decompressed in memory and executed (stager)',
        u'shell remota: riceve i comandi da una connessione TCP e li esegue (reverse shell)':
            u'remote shell: receives commands over a TCP connection and executes them (reverse shell)',
        u'scarica ed esegue uno script di installazione noto':
            u'downloads and runs a well-known installation script',
        u'scarica ed esegue codice':
            u'downloads and runs code',
    }


def _controlli_registro_1():
    # tc_c_registro.py
    return {
        u'Ricerca dei transaction log di %s non riuscita':
            u'Search for the transaction logs of %s failed',
        u'%s esiste (%d byte) ma non \u00e8 un hive del registro valido: file vuoto, azzerato o danneggiato. I '
        u'controlli che lo leggono non sono stati fatti.':
            u'%s exists (%d bytes) but is not a valid registry hive: empty, zeroed or damaged file. The '
            u'checks that read it were not performed.',
        u'L\'hive %s \u00e8 danneggiato: %d blocchi su %d non sono validi (file troncato, azzerato in parte o '
        u'sovrascritto). I controlli che lo leggono possono essere incompleti.':
            u'Hive %s is damaged: %d blocks out of %d are not valid (file truncated, partly zeroed or '
            u'overwritten). The checks that read it may be incomplete.',
        u'Hive %s non chiuso correttamente e senza transaction log utilizzabili: le ultime modifiche '
        u'possono mancare.':
            u'Hive %s was not closed cleanly and has no usable transaction logs: the latest changes may be '
            u'missing.',
        u'L\'hive %s non era stato chiuso correttamente e i suoi transaction log non sono utilizzabili: le '
        u'ultimissime modifiche al registro possono mancare.':
            u'Hive %s had not been closed cleanly and its transaction logs are not usable: the very latest '
            u'registry changes may be missing.',
        u'\nComando in chiaro: ':
            u'\nDecoded command: ',
        u'%s \u00ab%s\u00bb: %s':
            u'%s "%s": %s',
        u'hive SOFTWARE non trovato':
            u'SOFTWARE hive not found',
        u'hive SOFTWARE non leggibile o danneggiato':
            u'SOFTWARE hive unreadable or damaged',
        u'%s: mancano i controlli su chiavi Run, attivit\u00e0 pianificate nel registro, programmi installati '
        u'e impostazioni di Defender.':
            u'%s: the checks on Run keys, scheduled tasks in the registry, installed programs and Defender '
            u'settings are missing.',
        u'Nell\'hive SOFTWARE non si trova la chiave Microsoft\\Windows\\CurrentVersion: l\'hive \u00e8 '
        u'danneggiato e i controlli su chiavi Run, programmi installati e attivit\u00e0 pianificate sono '
        u'incompleti.':
            u'The SOFTWARE hive has no Microsoft\\Windows\\CurrentVersion key: the hive is damaged and the '
            u'checks on Run keys, installed programs and scheduled tasks are incomplete.',
        u'SOFTWARE: profili':
            u'SOFTWARE: profiles',
        u'SOFTWARE: chiavi Run':
            u'SOFTWARE: Run keys',
        u'SOFTWARE: programmi installati':
            u'SOFTWARE: installed programs',
        u'SOFTWARE: attivit\u00e0 pianificate':
            u'SOFTWARE: scheduled tasks',
        u'SOFTWARE: impostazioni':
            u'SOFTWARE: settings',
        u'Chiave Run':
            u'Run key',
        u'%s\\%s - ultima scrittura della chiave: %s':
            u'%s\\%s - key last written: %s',
        u'Winlogon\\Shell non \u00e8 explorer.exe: \u00ab%s\u00bb':
            u'Winlogon\\Shell is not explorer.exe: "%s"',
        u'Winlogon\\Userinit avvia altro oltre a userinit.exe: \u00ab%s\u00bb':
            u'Winlogon\\Userinit starts something besides userinit.exe: "%s"',
        u'Account nascosto dalla schermata di accesso: %s':
            u'Account hidden from the logon screen: %s',
        u'Account nascosti dalla schermata di accesso: %s':
            u'Accounts hidden from the logon screen: %s',
        u'Winlogon\\SpecialAccounts\\UserList - ultima scrittura della chiave: %s (UTC)\nL\'account esiste e '
        u'pu\u00f2 collegarsi, ma non compare tra gli utenti: lo fa chi vuole tenere un accesso senza farsi '
        u'notare (e qualche prodotto di assistenza remota).':
            u'Winlogon\\SpecialAccounts\\UserList - key last written: %s (UTC)\nThe account exists and can log '
            u'on, but it is not shown among the users: this is done by someone who wants to keep access '
            u'without being noticed (and by a few remote support products).',
        u'Debugger impostato su %s: si apre dalla schermata di accesso senza credenziali (backdoor '
        u'\u00absticky keys\u00bb)':
            u'Debugger set on %s: it opens from the logon screen without credentials ("sticky keys" backdoor)',
        u'Debugger impostato su %s: %s':
            u'Debugger set on %s: %s',
        u'AppInit_DLLs carica una DLL in ogni processo: \u00ab%s\u00bb':
            u'AppInit_DLLs loads a DLL into every process: "%s"',
        u'programma installato':
            u'installed program',
        u'chiave TaskCache non trovata':
            u'TaskCache key not found',
        u'manca il valore SD (tecnica usata dal malware Tarrask di HAFNIUM)':
            u'the SD value is missing (technique used by HAFNIUM\'s Tarrask malware)',
        u'il valore Index \u00e8 0 ma l\'attivit\u00e0 \u00e8 registrata':
            u'the Index value is 0 but the task is registered',
        u'prima di Windows 10 il valore SD manca anche nelle attivit\u00e0 legittime':
            u'before Windows 10 the SD value is missing in legitimate tasks too',
        u'Esclusione di Defender (%s): %s':
            u'Defender exclusion (%s): %s',
        u'%s\\Exclusions\\%s - ultima scrittura della chiave: %s':
            u'%s\\Exclusions\\%s - key last written: %s',
        u'Defender disattivato dal registro (DisableAntiSpyware = 1)':
            u'Defender disabled through the registry (DisableAntiSpyware = 1)',
        u'Protezione in tempo reale di Defender disattivata dal registro':
            u'Defender real-time protection disabled through the registry',
        u'hive SYSTEM non trovato':
            u'SYSTEM hive not found',
        u'hive SYSTEM non leggibile o danneggiato':
            u'SYSTEM hive unreadable or damaged',
        u'%s: mancano i controlli su servizi, BAM e ShimCache.':
            u'%s: the checks on services, BAM and ShimCache are missing.',
        u'Nell\'hive SYSTEM non si trova nessun ControlSet: l\'hive \u00e8 danneggiato e i controlli su servizi, '
        u'BAM e ShimCache non sono stati fatti.':
            u'The SYSTEM hive has no ControlSet: the hive is damaged and the checks on services, BAM and '
            u'ShimCache were not performed.',
        u'Il servizio Registro eventi \u00e8 disattivato (Start = 4)':
            u'The Event Log service is disabled (Start = 4)',
        u'WDigest conserva le password in chiaro in memoria (UseLogonCredential = 1)':
            u'WDigest keeps cleartext passwords in memory (UseLogonCredential = 1)',
        u'Impostazione usata per poi leggere le password con strumenti come Mimikatz. Ultima scrittura '
        u'della chiave: %s':
            u'Setting used to later read the passwords with tools such as Mimikatz. Key last written: %s',
        u'SYSTEM: inoltro di porta':
            u'SYSTEM: port forwarding',
        u'SYSTEM: servizi':
            u'SYSTEM: services',
        u'Inoltro di porta attivo (netsh portproxy): %s%s':
            u'Port forwarding active (netsh portproxy): %s%s',
        u' e altre':
            u' and others',
        u'%s\nUltima scrittura della chiave: %s (UTC)\nLe connessioni che arrivano sulla prima porta '
        u'vengono girate alla seconda destinazione. Lo usano WSL e qualche ambiente di sviluppo; su un '
        u'server o su un client d\'ufficio va spiegato.':
            u'%s\nKey last written: %s (UTC)\nConnections arriving on the first port are forwarded to the '
            u'second destination. WSL and a few development environments use it; on a server or on an office '
            u'client it needs an explanation.',
        u'il servizio lancia %s invece di un proprio programma':
            u'the service launches %s instead of a program of its own',
        u'un servizio creato solo per eseguire questo comando come SYSTEM':
            u'a service created only to run this command as SYSTEM',
        u'eseguibile con nome di 8 lettere a caso in C:\\Windows (tipico di psexec.py e Metasploit)':
            u'executable with a random 8-letter name in C:\\Windows (typical of psexec.py and Metasploit)',
        u'chiave Services non trovata':
            u'Services key not found',
        u'Nell\'hive SYSTEM non si trova la chiave dei servizi (%s\\Services): l\'hive \u00e8 danneggiato e i '
        u'servizi non sono stati controllati.':
            u'The SYSTEM hive has no services key (%s\\Services): the hive is damaged and the services were '
            u'not checked.',
        u'Registro: SYSTEM, %d servizi esaminati':
            u'Registry: SYSTEM, %d services examined',
        u'SYSTEM: servizio %s: %s':
            u'SYSTEM: service %s: %s',
        u'SYSTEM: in tutto %d servizi non valutati per un errore':
            u'SYSTEM: %d services in total not evaluated because of an error',
        u'Servizi da guardare':
            u'Services to look at',
        u'Servizio':
            u'Service',
        u'Percorso':
            u'Path',
        u'Ultima scrittura (UTC)':
            u'Last write (UTC)',
        u'la DLL del servizio sta in una cartella scrivibile dagli utenti: %s':
            u'the service DLL is in a user-writable folder: %s',
        u'servizio':
            u'service',
        u'all\'avvio del sistema (0)':
            u'boot (0)',
        u'di sistema (1)':
            u'system (1)',
        u'automatico (2)':
            u'automatic (2)',
        u'manuale (3)':
            u'manual (3)',
        u'disattivato (4)':
            u'disabled (4)',
        u'non indicato':
            u'not set',
        u'Servizio \u00ab%s\u00bb: %s':
            u'Service "%s": %s',
        u'%s\nAvvio: %s - Ultima scrittura della chiave: %s':
            u'%s\nStart: %s - Key last written: %s',
    }


def _controlli_registro_2():
    # tc_c_registro.py
    return {
        u'chiave BAM non trovata: esiste da Windows 10 1709':
            u'BAM key not found: it was introduced in Windows 10 1709',
        u'valore AppCompatCache non trovato':
            u'AppCompatCache value not found',
        u'formato di ShimCache non riconosciuto':
            u'ShimCache format not recognized',
        u'%d voci, formato %s':
            u'%d entries, format %s',
        u'ultima modifica del file: %s':
            u'file last modified: %s',
        u'hive SAM non trovato':
            u'SAM hive not found',
        u'hive SAM non leggibile o danneggiato':
            u'SAM hive unreadable or damaged',
        u'%s: manca l\'elenco degli account locali e dei membri del gruppo Administrators.':
            u'%s: the list of the local accounts and of the members of the Administrators group is missing.',
        u'disattivato':
            u'disabled',
        u'amministratore':
            u'administrator',
        u'password non richiesta':
            u'password not required',
        u'L\'account Guest \u00e8 nel gruppo Administrators':
            u'The Guest account is in the Administrators group',
        u' ed \u00e8 attivo':
            u' and is enabled',
        u'Password impostata: %s':
            u'Password set: %s',
        u'L\'account Guest \u00e8 attivo':
            u'The Guest account is enabled',
        u'Account locale \u00ab%s\u00bb con nome da account macchina ($ finale)':
            u'Local account "%s" with a machine account name (trailing $)',
        u'Creato: %s':
            u'Created: %s',
        u'Account locale \u00ab%s\u00bb creato di recente (%s)%s':
            u'Local account "%s" created recently (%s)%s',
        u', amministratore':
            u', administrator',
        u'RID %d - ultimo accesso: %s - accessi: %d':
            u'RID %d - last logon: %s - logons: %d',
        u'Account locali (SAM)':
            u'Local accounts (SAM)',
        u'Nome':
            u'Name',
        u'RID':
            u'RID',
        u'Creato (UTC)':
            u'Created (UTC)',
        u'Ultimo accesso':
            u'Last logon',
        u'Password impostata':
            u'Password set',
        u'Stato':
            u'Status',
        u'La data di creazione \u00e8 l\'ultima scrittura della chiave Names\\<nome>. Su un controller di '
        u'dominio il SAM contiene solo gli account locali di ripristino: gli account di dominio stanno in '
        u'NTDS.dit.':
            u'The creation date is the last write of the Names\\<name> key. On a domain controller the SAM '
            u'holds only the local recovery accounts: the domain accounts are in NTDS.dit.',
        u'La data di creazione \u00e8 l\'ultima scrittura della chiave Names\\<nome>.':
            u'The creation date is the last write of the Names\\<name> key.',
        u'Domain Admins del dominio (%s)':
            u'Domain Admins of the domain (%s)',
        u'Membri del gruppo Administrators':
            u'Members of the Administrators group',
        u'Membro':
            u'Member',
        u'Ricerca delle cartelle dei profili non riuscita (controllo 10)':
            u'Search for the profile folders failed (check 10)',
        u'Profilo \u00ab%s\u00bb creato di recente (%s): primo accesso di quell\'utente alla macchina':
            u'Profile "%s" created recently (%s): first logon of that user on the machine',
        u'Profili degli utenti':
            u'User profiles',
        u'Cartella':
            u'Folder',
        u'Creata (UTC)':
            u'Created (UTC)',
        u'Modificata':
            u'Modified',
        u'Le date di creazione posteriori all\'ultima attivit\u00e0 della macchina sono quelle della copia dei '
        u'file, non quelle dei profili.':
            u'Creation dates later than the machine\'s last activity are those of the file copy, not those of '
            u'the profiles.',
        u'nessun NTUSER.DAT trovato':
            u'no NTUSER.DAT found',
        u'Nessun NTUSER.DAT trovato: mancano i controlli sul registro degli utenti (comandi dalla '
        u'finestra Esegui, UserAssist, chiavi Run degli utenti, artefatti disattivati).':
            u'No NTUSER.DAT found: the checks on the users\' registry are missing (commands from the Run '
            u'dialog, UserAssist, user Run keys, disabled artifacts).',
        u'NTUSER.DAT di %s':
            u'NTUSER.DAT of %s',
        u'Registro dell\'utente %s (%s): %s':
            u'Registry of user %s (%s): %s',
        u'UsrClass.dat di %s':
            u'UsrClass.dat of %s',
        u'Controllo delle ACL in UsrClass.dat di %s non riuscito (controllo 41)':
            u'ACL check in the UsrClass.dat of %s failed (check 41)',
        u'RunMRU: comandi dalla finestra Esegui':
            u'RunMRU: commands from the Run dialog',
        u'Utente':
            u'User',
        u'Ordine':
            u'Order',
        u'Comando':
            u'Command',
        u'Ordine 1 = il pi\u00f9 recente. La chiave registra solo l\'ora dell\'ultimo comando.':
            u'Order 1 = the most recent. The key records only the time of the last command.',
        u'RDP in uscita (registro degli utenti)':
            u'Outbound RDP (users\' registry)',
        u'Server':
            u'Server',
        u'Nome utente usato':
            u'User name used',
        u'Condivisioni di rete usate (MountPoints2)':
            u'Network shares used (MountPoints2)',
        u'Condivisione':
            u'Share',
        u'HKCU di %s':
            u'HKCU of %s',
        u'Script di accesso di %s':
            u'Logon script of %s',
        u'la chiave si usa di rado e quasi solo per la persistenza':
            u'the key is rarely used, and almost only for persistence',
        u'comando che scarica o esegue codice incollato nella finestra Esegui (schema delle finte '
        u'CAPTCHA, ClickFix): ':
            u'command that downloads or runs code pasted into the Run dialog (fake CAPTCHA scheme, ClickFix): ',
        u'comando dalla finestra Esegui: ':
            u'command from the Run dialog: ',
        u'script di installazione noto lanciato dalla finestra Esegui':
            u'well-known installation script launched from the Run dialog',
        u'%s a finestra nascosta dalla finestra Esegui':
            u'%s with a hidden window from the Run dialog',
        u'%s con pi\u00f9 comandi concatenati dalla finestra Esegui':
            u'%s with several chained commands from the Run dialog',
        u'%s con argomenti dalla finestra Esegui':
            u'%s with arguments from the Run dialog',
        u' lanciato dalla finestra Esegui':
            u' launched from the Run dialog',
        u'RunMRU di %s: %s':
            u'RunMRU of %s: %s',
        u'%s ha aperto la condivisione amministrativa %s':
            u'%s opened the administrative share %s',
        u'MountPoints2 - ultima scrittura della chiave: %s':
            u'MountPoints2 - key last written: %s',
        u'%s cancella i file senza passare dal Cestino (NukeOnDelete = 1)':
            u'%s deletes files without going through the Recycle Bin (NukeOnDelete = 1)',
        u'Volume %s - ultima scrittura della chiave: %s':
            u'Volume %s - key last written: %s',
    }


def _controlli_registro_3():
    # tc_c_registro.py
    return {
        u'Per %s Windows non tiene traccia dei programmi avviati (Start_TrackProgs = 0): UserAssist resta '
        u'vuoto':
            u'For %s Windows does not keep track of the programs started (Start_TrackProgs = 0): UserAssist '
            u'stays empty',
        u'ACL Deny sulla chiave %s di %s: Windows non pu\u00f2 pi\u00f9 registrare questo artefatto':
            u'Deny ACL on the %s key of %s: Windows can no longer record this artifact',
        u'%s\nVoci Deny: %s\nUltima scrittura della chiave: %s':
            u'%s\nDeny entries: %s\nKey last written: %s',
        u'%s (maschera 0x%x)':
            u'%s (mask 0x%x)',
        u'produttore: ':
            u'publisher: ',
        u'(nessuna azione leggibile)':
            u'(no readable action)',
        u'Attivit\u00e0 nascosta \u00ab%s\u00bb: %s':
            u'Hidden task "%s": %s',
        u'Azioni: %s\nCreata: %s - ultimo avvio: %s':
            u'Actions: %s\nCreated: %s - last run: %s',
        u'nascosta':
            u'hidden',
        u'Attivit\u00e0 pianificata':
            u'Scheduled task',
        u'Autore: %s':
            u'Author: %s',
        u'Attivit\u00e0 pianificata \u00ab%s\u00bb: lancia un collegamento .lnk':
            u'Scheduled task "%s": launches a .lnk shortcut',
        u'lancia un .lnk':
            u'launches a .lnk',
        u'Attivit\u00e0 \u00ab%s\u00bb: %s':
            u'Task "%s": %s',
        u'Attivit\u00e0 pianificate: segnalate e non di Microsoft':
            u'Scheduled tasks: the flagged ones and the non-Microsoft ones',
        u'Attivit\u00e0':
            u'Task',
        u'Azione':
            u'Action',
        u'Autore':
            u'Author',
        u'Sono elencate le attivit\u00e0 fuori da \\Microsoft\\ e quelle segnalate. In tutto: %d nel registro, '
        u'%d file XML.':
            u'The tasks outside \\Microsoft\\ and the flagged ones are listed. In total: %d in the registry, %d '
            u'XML files.',
        u'data di avvio 2015-07-15T20:35:13, fissa nel codice di atexec':
            u'start date 2015-07-15T20:35:13, hard-coded in atexec',
        u'output ridiretto in un file .tmp di 8 lettere a caso in Windows\\Temp (firma di atexec)':
            u'output redirected to a random 8-letter .tmp file in Windows\\Temp (atexec signature)',
        u'eseguito':
            u'executed',
        u'presente sul disco (non \u00e8 una prova di esecuzione)':
            u'present on disk (not proof of execution)',
        u'%s\nFonti: %s%s%s%s':
            u'%s\nSources: %s%s%s%s',
        u' - ultimo avvio: %s':
            u' - last run: %s',
        u' - utenti: %s':
            u' - users: %s',
        u' nel nome della cartella':
            u' in the folder name',
        u' (non recente)':
            u' (not recent)',
        u'con il nome di un processo di sistema, ma fuori dalle cartelle di sistema':
            u'with the name of a system process, but outside the system folders',
        u'avviato da una cartella dove di norma non ci sono programmi':
            u'started from a folder that normally holds no programs',
        u'Programma %s: %s':
            u'Program %s: %s',
        u'cartella sospetta':
            u'suspicious folder',
        u'temporanea':
            u'temporary',
        u'Strumenti d\'attacco e a doppio uso':
            u'Attack tools and dual-use tools',
        u'Tipo':
            u'Type',
        u'Prova':
            u'Evidence',
        u'Ultimo avvio (UTC)':
            u'Last run (UTC)',
        u'Fonti':
            u'Sources',
        u'Programmi avviati da cartelle scrivibili dagli utenti (i 50 pi\u00f9 recenti)':
            u'Programs started from user-writable folders (the 50 most recent)',
        u'Avvii':
            u'Runs',
        u'Utenti':
            u'Users',
        u'Elenco di contesto: molti programmi legittimi girano da queste cartelle. Fonti: Prefetch, BAM, '
        u'UserAssist.':
            u'Context list: many legitimate programs run from these folders. Sources: Prefetch, BAM, '
            u'UserAssist.',
        u'Ricognizione: %d comandi diversi in %d minuti (%s)':
            u'Reconnaissance: %d different commands within %d min (%s)',
        u'Dal %s al %s (UTC). Fonte: orari di ultimo avvio in Prefetch, BAM e UserAssist.':
            u'From %s to %s (UTC). Source: last-run times in Prefetch, BAM and UserAssist.',
    }


def _controlli_eventi_1():
    # tc_c_eventi.py
    return {
        u'account creato':
            u'account created',
        u'account attivato':
            u'account enabled',
        u'password reimpostata':
            u'password reset',
        u'account cancellato':
            u'account deleted',
        u'aggiunto a un gruppo globale':
            u'added to a global group',
        u'aggiunto a un gruppo locale':
            u'added to a local group',
        u'aggiunto a un gruppo universale':
            u'added to a universal group',
        u'rete (3)':
            u'network (3)',
        u'sblocco (7)':
            u'unlock (7)',
        u'i comandi di PowerShell (evento 400)':
            u'PowerShell commands (event 400)',
        u'gli script di PowerShell (evento 4104)':
            u'PowerShell scripts (event 4104)',
        u'le sessioni RDP (eventi 21, 22, 25)':
            u'RDP sessions (events 21, 22, 25)',
        u'nessun registro eventi (.evtx) trovato':
            u'no event log (.evtx) found',
        u'Nessun registro eventi trovato: i controlli sugli accessi e sull\'esecuzione remota non sono '
        u'possibili.':
            u'No event logs found: the checks on logons and on remote execution are not possible.',
        u'Registri eventi: %s (%d di %d)':
            u'Event logs: %s (%d of %d)',
        u'Registri eventi: %s (%d di %d), %d%%':
            u'Event logs: %s (%d of %d), %d%%',
        u'%d blocchi da 64 KB non letti':
            u'%d chunks of 64 KB not read',
        u'nessun registro eventi leggibile':
            u'no readable event log',
        u'Nessun registro eventi leggibile (file danneggiati, vuoti o non accessibili): i controlli sugli '
        u'accessi e sull\'esecuzione remota non sono possibili.':
            u'No readable event log (damaged, empty or inaccessible files): the checks on logons and on '
            u'remote execution are not possible.',
        u'Analisi degli eventi (%s): %s':
            u'Event analysis (%s): %s',
        u'%d minuti':
            u'%d min',
        u' (%d non leggibili)':
            u' (%d unreadable)',
        u'esiste (%d byte) ma non \u00e8 un registro eventi valido':
            u'exists (%d bytes) but is not a valid event log',
        u'non \u00e8 stato letto per un errore di lettura':
            u'was not read because of a read error',
        u'non \u00e8 stato trovato':
            u'was not found',
        u'System.evtx %s: mancano i servizi installati (7045), i registri cancellati (104) e gli altri '
        u'eventi di sistema.':
            u'System.evtx %s: installed services (7045), cleared logs (104) and the other system events are '
            u'missing.',
        u' Mancano %s.':
            u' Missing: %s.',
        u'%s non trovato: Windows lo crea sempre, quindi \u00e8 stato tolto oppure i file raccolti sono solo '
        u'una parte.%s':
            u'%s not found: Windows always creates it, so either it was removed or the collected files are '
            u'only a subset.%s',
        u'%s non trovati: Windows li crea sempre, quindi sono stati tolti oppure i file raccolti sono '
        u'solo una parte.%s':
            u'%s not found: Windows always creates them, so either they were removed or the collected files '
            u'are only a subset.%s',
        u'1 registro eventi esiste ma non \u00e8 valido (vuoto, azzerato o con l\'intestazione danneggiata): '
        u'%s. I suoi eventi non sono stati controllati.':
            u'1 event log exists but is not valid (empty, zeroed or with a damaged header): %s. Its events '
            u'were not checked.',
        u'%d registri eventi esistono ma non sono validi (vuoti, azzerati o con l\'intestazione '
        u'danneggiata): %s%s. I loro eventi non sono stati controllati.':
            u'%d event logs exist but are not valid (empty, zeroed or with a damaged header): %s%s. Their '
            u'events were not checked.',
        u'%d eventi non leggibili su %d':
            u'%d unreadable events out of %d',
        u'%d blocchi rovinati':
            u'%d damaged chunks',
        u'Registri eventi danneggiati: %s%s. Gli eventi che mancano non sono stati controllati.':
            u'Damaged event logs: %s%s. The missing events were not checked.',
        u'Eventi non decodificati: %s%s. I record ci sono, ma il lettore del plugin non ne ha saputo leggere '
        u'il contenuto: possono essere rovinati oppure scritti in una forma che il lettore non conosce. Questi '
        u'eventi non sono stati controllati; si possono aprire con un altro strumento (per esempio il '
        u'Visualizzatore eventi di Windows).':
            u'Events not decoded: %s%s. The records are there, but the plugin\'s reader could not read their '
            u'content: they may be damaged or written in a form the reader does not know. These events were not '
            u'checked; they can be opened with another tool (for example the Windows Event Viewer).',
        u'In 1 registro eventi l\'evento con la data pi\u00f9 recente non \u00e8 l\'ultimo scritto: in %s si arriva '
        u'al %s UTC, ma l\'ultimo evento scritto \u00e8 del %s UTC. L\'orologio della macchina \u00e8 stato riportato '
        u'indietro (o corretto) di %s. La finestra dei controlli recenti si conta dall\'ultimo evento '
        u'scritto.':
            u'In 1 event log the event with the most recent date is not the last one written: %s reaches %s '
            u'UTC, but the last event written is dated %s UTC. The machine clock was set back (or corrected) '
            u'by %s. The window of the recent checks is counted from the last event written.',
        u'In %d registri eventi l\'evento con la data pi\u00f9 recente non \u00e8 l\'ultimo scritto: in %s si arriva '
        u'al %s UTC, ma l\'ultimo evento scritto \u00e8 del %s UTC. L\'orologio della macchina \u00e8 stato riportato '
        u'indietro (o corretto) di %s. La finestra dei controlli recenti si conta dall\'ultimo evento '
        u'scritto.':
            u'In %d event logs the event with the most recent date is not the last one written: %s reaches %s '
            u'UTC, but the last event written is dated %s UTC. The machine clock was set back (or corrected) '
            u'by %s. The window of the recent checks is counted from the last event written.',
        u'Nei registri eventi ci sono eventi con una data nel futuro rispetto a oggi (almeno %d): '
        u'orologio sbagliato o record alterati. Non sono stati usati per calcolare i periodi coperti.':
            u'The event logs contain events dated in the future relative to today (at least %d): wrong clock '
            u'or altered records. They were not used to compute the periods covered.',
        u'; lo stesso vale per un altro registro':
            u'; the same goes for one more log',
        u'; lo stesso vale per altri %d registri':
            u'; the same goes for %d more logs',
        u'%s arriva al %s UTC, %s oltre il momento da cui si conta la finestra dei controlli recenti (%s '
        u'UTC)%s. Le date dei registri non tornano tra loro: un registro ha continuato a scrivere mentre '
        u'gli altri erano fermi, oppure l\'orologio era sbagliato, oppure i file vengono da momenti '
        u'diversi. Confronta le date nella tabella della copertura.':
            u'%s reaches %s UTC, %s beyond the moment from which the window of the recent checks is counted '
            u'(%s UTC)%s. The log dates do not agree with each other: one log kept writing while the others '
            u'were stopped, or the clock was wrong, or the files come from different moments. Compare the '
            u'dates in the coverage table.',
        u'non valido (%d byte)':
            u'not valid (%d bytes)',
        u'non letto (errore di lettura)':
            u'not read (read error)',
        u'non trovato':
            u'not found',
        u'non trovato (normale se il canale non ha mai scritto)':
            u'not found (normal if the channel never wrote anything)',
        u'Security.evtx esiste (%d byte) ma non \u00e8 un registro eventi valido: file vuoto, azzerato o con '
        u'l\'intestazione danneggiata. Mancano gli accessi (4624, 4625) e le firme di Impacket nel '
        u'Security.':
            u'Security.evtx exists (%d bytes) but is not a valid event log: empty, zeroed or with a damaged '
            u'header. Logons (4624, 4625) and the Impacket signatures in the Security log are missing.',
        u'Security.evtx non letto per un errore di lettura: mancano gli accessi (4624, 4625) e le firme '
        u'di Impacket nel Security.':
            u'Security.evtx not read because of a read error: logons (4624, 4625) and the Impacket signatures '
            u'in the Security log are missing.',
        u'Security.evtx non trovato: mancano gli accessi (4624, 4625) e le firme di Impacket nel Security.':
            u'Security.evtx not found: logons (4624, 4625) and the Impacket signatures in the Security log '
            u'are missing.',
        u'Il registro Security copre solo %s (dal %s al %s): gli eventi pi\u00f9 vecchi sono andati persi o '
        u'sono stati cancellati.':
            u'The Security log covers only %s (from %s to %s): the older events were lost or were cleared.',
        u'Il registro Security copre solo %s':
            u'The Security log covers only %s',
        u'Dal %s al %s (UTC). Su una macchina in uso da tempo \u00e8 poco: o il registro \u00e8 piccolo, o \u00e8 stato '
        u'cancellato.':
            u'From %s to %s (UTC). On a machine that has been in use for some time this is not much: either '
            u'the log is small, or it was cleared.',
        u'Il registro Security si ferma al %s UTC, mentre altri %d registri arrivano fino al %s UTC (%s '
        u'dopo): in quel periodo gli eventi di sicurezza non sono stati registrati (audit spento, '
        u'registro pieno o registrazione manomessa) e i controlli su accessi ed esecuzione remota non lo '
        u'coprono.':
            u'The Security log stops at %s UTC, while %d other logs go on until %s UTC (%s later): in that '
            u'period security events were not recorded (auditing off, log full or logging tampered with) and '
            u'the checks on logons and on remote execution do not cover it.',
        u'Il registro Security \u00e8 vuoto (nessun evento): \u00e8 stato svuotato o sostituito, oppure l\'audit \u00e8 '
        u'spento del tutto. Mancano gli accessi (4624, 4625) e le firme di Impacket nel Security.':
            u'The Security log is empty (no events): it was emptied or replaced, or auditing is completely '
            u'off. Logons (4624, 4625) and the Impacket signatures in the Security log are missing.',
        u'Nel Security non c\'\u00e8 nessun evento 4624: l\'audit degli accessi non \u00e8 attivo.':
            u'The Security log has no 4624 event: logon auditing is not active.',
        u'Nessun evento 4688: l\'audit della creazione dei processi non \u00e8 attivo (\u00e8 spento di default).':
            u'No 4688 event: process creation auditing is not active (it is off by default).',
        u'Gli eventi 4688 ci sono (%d) ma senza riga di comando.':
            u'4688 events are present (%d) but without the command line.',
        u'Eventi 4688 con riga di comando: presenti (%d).':
            u'4688 events with the command line: present (%d).',
        u'Nessun evento 5145: l\'audit dettagliato delle condivisioni non \u00e8 attivo (\u00e8 spento di default).':
            u'No 5145 event: detailed file share auditing is not active (it is off by default).',
        u'Nessun evento 4698 n\u00e9 106: la creazione delle attivit\u00e0 pianificate non \u00e8 registrata.':
            u'No 4698 or 106 event: scheduled task creation is not recorded.',
        u'Canali disattivati nel registro di sistema: %s.':
            u'Channels disabled in the registry: %s.',
        u'Copertura dei registri eventi':
            u'Event log coverage',
        u'Registro':
            u'Log',
        u'Primo evento (UTC)':
            u'First event (UTC)',
        u'Ultimo evento (UTC)':
            u'Last event (UTC)',
        u'Eventi':
            u'Events',
        u'Periodo':
            u'Period',
        u' (a ridosso dell\'installazione di Windows: probabilmente fa parte della preparazione '
        u'dell\'immagine)':
            u' (right around the Windows installation: probably part of the image preparation)',
        u'1 registro cancellato da %s%s: %s':
            u'1 log cleared by %s%s: %s',
        u'%d registri cancellati da %s%s: %s':
            u'%d logs cleared by %s%s: %s',
        u'Eventi %s. Servono diritti di amministratore.':
            u'Events %s. Administrator rights are required.',
        u'Registri cancellati':
            u'Cleared logs',
    }


def _controlli_eventi_2():
    # tc_c_eventi.py
    return {
        u'Da chi':
            u'By whom',
        u'Registri':
            u'Logs',
        u'indirizzo pubblico':
            u'public address',
        u'Logon remoti riusciti (4624 di tipo 3, 7 e 10): i 50 pi\u00f9 recenti':
            u'Successful remote logons (4624 of type 3, 7 and 10): the 50 most recent',
        u'Indirizzo':
            u'Address',
        u'Host':
            u'Host',
        u'Volte':
            u'Count',
        u'Primo (UTC)':
            u'First (UTC)',
        u'Ultimo (UTC)':
            u'Last (UTC)',
        u'Esclusi gli account macchina e ANONYMOUS LOGON. In tutto %d combinazioni di utente e origine.':
            u'Machine accounts and ANONYMOUS LOGON excluded. %d combinations of user and source in total.',
        u'Primo: %s - ultimo: %s (UTC). Verifica se quell\'utente si collega davvero da l\u00ec.':
            u'First: %s - last: %s (UTC). Check whether that user really connects from there.',
        u' (la macchina stessa)':
            u' (the machine itself)',
        u'%s il %s':
            u'%s at %s',
        u'Accessi falliti per origine (4625): le 30 origini con pi\u00f9 tentativi':
            u'Failed logons by source (4625): the 30 sources with the most attempts',
        u'Origine':
            u'Source',
        u'Tentativi':
            u'Attempts',
        u'Utenti provati':
            u'Users tried',
        u'Massimo in 10 minuti':
            u'Maximum in 10 minutes',
        u'Accesso riuscito subito dopo':
            u'Successful logon right after',
        u'Origini diverse: %d, di cui %d indirizzi pubblici.':
            u'Different sources: %d, of which %d are public addresses.',
        u' (nome predefinito di una distribuzione usata per gli attacchi)':
            u' (default name of a distribution used for attacks)',
        u'Raffica di %d accessi falliti da %s%s seguita da un accesso riuscito come %s':
            u'Burst of %d failed logons from %s%s followed by a successful logon as %s',
        u'Raffica di %d accessi falliti da %s%s':
            u'Burst of %d failed logons from %s%s',
        u'Dal %s al %s (UTC), fino a %d tentativi in 10 minuti. Utenti provati: %s.%s':
            u'From %s to %s (UTC), up to %d attempts in 10 minutes. Users tried: %s.%s',
        u' Primo accesso riuscito dopo l\'inizio della raffica (%s): %s.':
            u' First successful logon after the start of the burst (%s): %s.',
        u'Accesso riuscito da un computer chiamato \u00ab%s\u00bb come %s':
            u'Successful logon from a computer named "%s" as %s',
        u'Accessi falliti da %d indirizzi pubblici diversi: la macchina \u00e8 esposta a Internet':
            u'Failed logons from %d different public addresses: the machine is exposed to the Internet',
        u'\u00c8 il rumore di fondo dei tentativi automatici: conta se uno di questi indirizzi poi entra.':
            u'It is the background noise of automated attempts: it matters if one of these addresses then '
            u'gets in.',
        u'Primo: %s - ultimo: %s (UTC). Fonte: %s.%s':
            u'First: %s - last: %s (UTC). Source: %s.%s',
        u' Lo stesso indirizzo compare anche nei 4624.':
            u' The same address also appears in the 4624 events.',
        u'Sessioni RDP in entrata (Terminal Services)':
            u'Inbound RDP sessions (Terminal Services)',
        u'Fonte':
            u'Source',
        u'registri di Terminal Services non trovati':
            u'Terminal Services logs not found',
        u'Credenziali esplicite verso %s: %s usa l\'account %s da %s':
            u'Explicit credentials towards %s: %s uses the account %s from %s',
        u'Credenziali esplicite (4648): le 30 combinazioni pi\u00f9 recenti':
            u'Explicit credentials (4648): the 30 most recent combinations',
        u'Chi':
            u'Who',
        u'Account usato':
            u'Account used',
        u'Verso':
            u'To',
        u'Processo':
            u'Process',
        u'RDP in uscita (registro RDPClient)':
            u'Outbound RDP (RDPClient log)',
        u'System.evtx non valido':
            u'System.evtx not valid',
        u'System.evtx non trovato':
            u'System.evtx not found',
        u'seguito dal timeout 7009: il programma non si comporta da servizio':
            u'followed by the 7009 timeout: the program does not behave like a service',
        u'servizio installato (evento %s)':
            u'installed service (event %s)',
        u' (%d volte)':
            u' (%d times)',
        u'Servizio installato \u00ab%s\u00bb%s: %s':
            u'Installed service "%s"%s: %s',
        u'%s\nTipo: %s - avvio: %s - account: %s\nPrimo: %s - ultimo: %s (UTC) - evento %s':
            u'%s\nType: %s - start: %s - account: %s\nFirst: %s - last: %s (UTC) - event %s',
        u'Servizi installati (eventi 7045 e 4697): i 40 pi\u00f9 recenti':
            u'Installed services (events 7045 and 4697): the 40 most recent',
        u'Installato (UTC)':
            u'Installed (UTC)',
        u'nessun evento 4698 n\u00e9 106: la creazione delle attivit\u00e0 non \u00e8 registrata':
            u'no 4698 or 106 event: task creation is not recorded',
        u'Attivit\u00e0 \u00ab%s\u00bb creata e cancellata in %d ms%s':
            u'Task "%s" created and deleted within %d ms%s',
        u': nome di 8 lettere a caso nella cartella radice, come fa atexec':
            u': random 8-letter name in the root folder, as atexec does',
        u'Creata da %s il %s (UTC). Azione: %s\nFonte: %s':
            u'Created by %s at %s (UTC). Action: %s\nSource: %s',
        u'(non registrata)':
            u'(not recorded)',
        u'Attivit\u00e0 create e cancellate entro un minuto':
            u'Tasks created and deleted within a minute',
        u'Cancellata (UTC)':
            u'Deleted (UTC)',
        u'Durata':
            u'Duration',
        u'Creata da %s il %s (UTC).\n%s':
            u'Created by %s at %s (UTC).\n%s',
        u'Attivit\u00e0 pianificata non pi\u00f9 presente':
            u'Scheduled task no longer present',
        u'Attivit\u00e0 pianificata, azione di una versione precedente':
            u'Scheduled task, action of an earlier version',
        u'Creata da %s (evento 4698 o 4702).':
            u'Created by %s (event 4698 or 4702).',
        u'nessun evento 5145: l\'audit dettagliato delle condivisioni non \u00e8 attivo':
            u'no 5145 event: detailed file share auditing is not active',
        u'accesso al file di output di Impacket (__output di smbexec o __<numeri> di wmiexec)':
            u'access to the Impacket output file (__output of smbexec or __<numbers> of wmiexec)',
        u'lettura di un file .tmp di 8 lettere in Temp tramite ADMIN$ (output di atexec)':
            u'read of an 8-letter .tmp file in Temp through ADMIN$ (atexec output)',
        u'gestione remota dei servizi (pipe svcctl): la usano smbexec e PsExec, ma anche gli '
        u'amministratori':
            u'remote service management (svcctl pipe): used by smbexec and PsExec, but also by administrators',
    }


def _controlli_eventi_3():
    # tc_c_eventi.py
    return {
        u'attivit\u00e0 pianificate remote (pipe atsvc): la usa atexec, ma anche gli amministratori':
            u'remote scheduled tasks (atsvc pipe): used by atexec, but also by administrators',
        u'lettura tramite ADMIN$ di un file .tmp di 8 lettere in Temp: lo fa atexec, ma qui il nome non '
        u'sembra casuale':
            u'read through ADMIN$ of an 8-letter .tmp file in Temp: atexec does this, but here the name does '
            u'not look random',
        u'PsExec o un suo clone da remoto':
            u'PsExec or one of its clones, used remotely',
        u'caricamento in ADMIN$ di un .exe con nome di 8 lettere a caso (tipico di psexec.py)':
            u'upload to ADMIN$ of an .exe with a random 8-letter name (typical of psexec.py)',
        u'Primo: %s - ultimo: %s (UTC)\n%s':
            u'First: %s - last: %s (UTC)\n%s',
        u'Accessi alle share tipici dell\'esecuzione remota (5145)':
            u'Share accesses typical of remote execution (5145)',
        u'Oggetto':
            u'Object',
        u'nessun evento 4688 n\u00e9 Sysmon: l\'audit della creazione dei processi non \u00e8 attivo':
            u'no 4688 or Sysmon event: process creation auditing is not active',
        u'comando segnalato':
            u'flagged command',
        u' (a ridosso dell\'installazione di Windows)':
            u' (right around the Windows installation)',
        u'%s%s\nProcesso padre: %s - utente: %s\nPrimo: %s - ultimo: %s (UTC) - fonte: %s':
            u'%s%s\nParent process: %s - user: %s\nFirst: %s - last: %s (UTC) - source: %s',
        u'blocco di script (4104)':
            u'script block (4104)',
        u'avvio di PowerShell (400)':
            u'engine start (400)',
        u'Dal %s al %s (UTC).\n%s':
            u'From %s to %s (UTC).\n%s',
        u'ricognizione':
            u'reconnaissance',
        u'Comandi segnalati (4688, Sysmon, PowerShell)':
            u'Flagged commands (4688, Sysmon, PowerShell)',
        u'Padre':
            u'Parent',
        u'Processi registrati: %d, di cui %d con riga di comando.':
            u'Processes recorded: %d, of which %d with the command line.',
        u' (%d eventi)':
            u' (%d events)',
        u'Account \u00ab%s\u00bb creato da %s%s':
            u'Account "%s" created by %s%s',
        u'Evento 4720 del %s (UTC).':
            u'Event 4720 at %s (UTC).',
        u'L\'account Guest \u00e8 stato aggiunto al gruppo Administrators da %s':
            u'The Guest account was added to the Administrators group by %s',
        u'%s aggiunto al gruppo %s da %s':
            u'%s added to the group %s by %s',
        u'Evento %d del %s (UTC).':
            u'Event %d at %s (UTC).',
        u'Eventi sugli account (creazione, gruppi, password): gli ultimi 60':
            u'Account events (creation, groups, passwords): the last 60',
        u'Evento':
            u'Event',
        u'Su':
            u'Target',
        u'Segnalato':
            u'Flagged',
        u'registro di Windows Defender non trovato':
            u'Windows Defender log not found',
        u'non registrata':
            u'not recorded',
        u'Defender ha rilevato %s (1 volta)':
            u'Defender detected %s (1 time)',
        u'Defender ha rilevato %s (%d volte)':
            u'Defender detected %s (%d times)',
        u'Primo: %s - ultimo: %s (UTC) - utente: %s\n%s\n%s':
            u'First: %s - last: %s (UTC) - user: %s\n%s\n%s',
        u'Azione di rimozione registrata (evento 1117).':
            u'Removal action recorded (event 1117).',
        u'Nessuna azione di rimozione registrata per almeno un rilevamento.':
            u'No removal action recorded for at least one detection.',
        u'Rilevamenti di Windows Defender (eventi 1116 e 1117)':
            u'Windows Defender detections (events 1116 and 1117)',
        u'Minaccia':
            u'Threat',
        u'Gravit\u00e0':
            u'Severity',
        u'Dove':
            u'Where',
        u'Rimozione':
            u'Removal',
        u'evento %s: %s':
            u'event %s: %s',
        u'installazione (MsiInstaller)':
            u'installation (MsiInstaller)',
        u'Application.evtx non trovato':
            u'Application.evtx not found',
    }


def _controlli_file_1():
    # tc_c_file.py
    return {
        u'%d byte':
            u'%d bytes',
        u'nessun file .pf trovato':
            u'no .pf file found',
        u'cartella Windows\\Prefetch non trovata':
            u'Windows\\Prefetch folder not found',
        u'cartella vuota: sui Windows Server il Prefetch \u00e8 spento di default':
            u'empty folder: on Windows Server Prefetch is off by default',
        u'La cartella Prefetch \u00e8 vuota su un Windows client':
            u'The Prefetch folder is empty on a Windows client',
        u' (il Prefetch \u00e8 disattivato nel registro: EnablePrefetcher = 0)':
            u' (Prefetch is disabled in the registry: EnablePrefetcher = 0)',
        u'Su un client in uso la cartella contiene centinaia di file: vuota, \u00e8 stata ripulita oppure il '
        u'Prefetch \u00e8 stato spento.':
            u'On a client in use the folder holds hundreds of files: if it is empty, it was cleaned up or '
            u'Prefetch was turned off.',
        u'Prefetch: %d di %d':
            u'Prefetch: %d of %d',
        u'%d file letti':
            u'%d files read',
        u', %d non leggibili':
            u', %d unreadable',
        u'%d file del Prefetch su %d non si sono lasciati leggere o interpretare (danneggiati o in un '
        u'formato non riconosciuto): le esecuzioni che registravano mancano.':
            u'%d Prefetch files out of %d could not be read or parsed (damaged or in an unrecognized format): '
            u'the executions they recorded are missing.',
        u'Il Prefetch contiene solo %d file su un Windows client':
            u'Prefetch holds only %d files on a Windows client',
        u'Su un client in uso ce ne sono centinaia: pochi file indicano una pulizia recente o un sistema '
        u'appena installato.':
            u'On a client in use there are hundreds: few files point to a recent cleanup or to a freshly '
            u'installed system.',
        u'Il Prefetch \u00e8 disattivato nel registro (EnablePrefetcher = 0)':
            u'Prefetch is disabled in the registry (EnablePrefetcher = 0)',
        u'Esecuzione automatica di ':
            u'Startup folder of ',
        u'tutti gli utenti':
            u'all users',
        u'Collegamento in Esecuzione automatica':
            u'Shortcut in the Startup folder',
        u'collegamento con argomenti la cui destinazione non \u00e8 leggibile':
            u'shortcut with arguments whose target cannot be read',
        u'(destinazione non leggibile) ':
            u'(target not readable) ',
        u'%s\nArgomenti: %s\nCreato: %s (UTC)':
            u'%s\nArguments: %s\nCreated: %s (UTC)',
        u'programma o script messo direttamente nella cartella Esecuzione automatica':
            u'program or script placed directly in the Startup folder',
        u'%s\nCreato: %s (UTC)':
            u'%s\nCreated: %s (UTC)',
        u'Avvio automatico: chiavi Run e cartelle Esecuzione automatica':
            u'Autostart: Run keys and Startup folders',
        u'Chiave':
            u'Key',
        u'repository WMI (OBJECTS.DATA) non trovato':
            u'WMI repository (OBJECTS.DATA) not found',
        u'Il repository WMI (%s) \u00e8 di %s: troppo grande per essere letto, le sottoscrizioni WMI non sono '
        u'state controllate.':
            u'The WMI repository (%s) is %s: too large to be read, the WMI subscriptions were not checked.',
        u'Sottoscrizioni WMI: lettura del repository (%s)':
            u'WMI subscriptions: reading the repository (%s)',
        u'Il repository WMI (%s) contiene un numero anomalo di oggetti (file danneggiato o alterato): '
        u'l\'elenco delle sottoscrizioni pu\u00f2 essere incompleto.':
            u'The WMI repository (%s) contains an abnormal number of objects (damaged or altered file): the '
            u'list of subscriptions may be incomplete.',
        u'esegue %s':
            u'runs %s',
        u'uno script':
            u'a script',
        u'un comando':
            u'a command',
        u' (contiene \u00ab%s\u00bb)':
            u' (contains "%s")',
        u'consumer di tipo %s':
            u'consumer of type %s',
        u'Sottoscrizione WMI \u00ab%s\u00bb legata al filtro \u00ab%s\u00bb: %s':
            u'WMI subscription "%s" bound to the filter "%s": %s',
        u'Filtro: %s\n%s%s\n\nTrovata nel repository: pu\u00f2 essere una voce gi\u00e0 rimossa.%s':
            u'Filter: %s\n%s%s\n\nFound in the repository: it may be an entry that was already removed.%s',
        u'(interrogazione non trovata)':
            u'(query not found)',
        u' Registrata il %s (evento 5861).':
            u' Registered at %s (event 5861).',
        u'Sottoscrizioni WMI permanenti':
            u'Permanent WMI subscriptions',
        u'Consumer':
            u'Consumer',
        u'Filtro':
            u'Filter',
        u'Interrogazione':
            u'Query',
        u'Registrata (5861)':
            u'Registered (5861)',
        u'Escluse le due sottoscrizioni predefinite di Windows (SCM Event Log Consumer, BVTConsumer).':
            u'The two default Windows subscriptions are excluded (SCM Event Log Consumer, BVTConsumer).',
        u'serve la struttura delle cartelle':
            u'the folder structure is needed',
        u'nessuna cartella CryptnetUrlCache\\Content trovata':
            u'no CryptnetUrlCache\\Content folder found',
        u'%s nella cache dei download di certutil: %s':
            u'%s in the certutil download cache: %s',
        u'%s\nCreato: %s (UTC) - %s\nLa cartella di norma contiene solo certificati e liste di revoca: un '
        u'programma qui \u00e8 stato scaricato con certutil o con le stesse API.':
            u'%s\nCreated: %s (UTC) - %s\nThe folder normally holds only certificates and revocation lists: a '
            u'program here was downloaded with certutil or with the same APIs.',
        u'CryptnetUrlCache: contenuti che non sono certificati':
            u'CryptnetUrlCache: contents that are not certificates',
        u'Contenuto':
            u'Content',
        u'URL di origine':
            u'Source URL',
        u'Dimensione':
            u'Size',
        u'File esaminati: %d.':
            u'Files examined: %d.',
        u' (cancellato)':
            u' (deleted)',
        u'\nContenuto: ':
            u'\nContent: ',
        u'; il contenuto ridirige l\'output su __output':
            u'; the content redirects the output to __output',
        u'Creato: %s - modificato: %s (UTC) - %s%s':
            u'Created: %s - modified: %s (UTC) - %s%s',
        u'File di output di smbexec':
            u'Output file of smbexec',
        u'File cancellato con il nome del file di output di smbexec (la cartella in cui stava non \u00e8 pi\u00f9 '
        u'ricostruibile)':
            u'Deleted file with the name of the smbexec output file (the folder it was in can no longer be '
            u'reconstructed)',
        u'File di output di wmiexec o dcomexec (Impacket)':
            u'Output file of wmiexec or dcomexec (Impacket)',
        u'File execute.bat in Windows\\Temp, il nome usato da smbexec fino al 2023':
            u'File execute.bat in Windows\\Temp, the name used by smbexec until 2023',
        u'File .tmp con nome di 8 lettere a caso in Windows\\Temp (output di atexec)':
            u'Temp file (.tmp) with a random 8-letter name in Windows\\Temp (atexec output)',
        u'Batch con nome di 8 lettere a caso in C:\\Windows (smbexec dal 2023)':
            u'Batch file with a random 8-letter name in C:\\Windows (smbexec since 2023)',
        u'Eseguibile con nome di 8 lettere a caso in C:\\Windows (servizio di psexec.py o Metasploit)':
            u'Executable with a random 8-letter name in C:\\Windows (service of psexec.py or Metasploit)',
        u'Servizio di PsExec o di un suo clone: qualcuno ha eseguito comandi da remoto su questa macchina':
            u'Service of PsExec or of one of its clones: someone ran commands remotely on this machine',
        u'File residui dell\'esecuzione remota':
            u'Leftover files of remote execution',
        u'Cosa':
            u'What',
        u'Modificato (UTC)':
            u'Modified (UTC)',
        u'Ricerca dei log degli strumenti di accesso remoto non riuscita (controlli 34 e 35)':
            u'Search for the logs of the remote access tools failed (checks 34 and 35)',
        u'Il log %s \u00e8 molto grande (%s): ne sono stati letti gli ultimi %s.':
            u'The log %s is very large (%s): only its last %s were read.',
        u'log delle connessioni':
            u'connection log',
    }


def _controlli_file_2():
    # tc_c_file.py
    return {
        u'%s, autenticazione %s, ID remoto %s':
            u'%s, authentication %s, remote ID %s',
        u'in entrata':
            u'inbound',
        u'in uscita':
            u'outbound',
        u'log di traccia':
            u'trace log',
        u'collegamento dall\'indirizzo %s':
            u'connection from the address %s',
        u'trasferimento di file: %s':
            u'file transfer: %s',
        u'richiesta di sessione in entrata':
            u'inbound session request',
        u'log delle connessioni in entrata':
            u'inbound connection log',
        u'in entrata dall\'ID %s (%s), fino alle %s, utente locale %s, tipo %s':
            u'inbound from ID %s (%s), until %s, local user %s, type %s',
        u'in uscita verso l\'ID %s, tipo %s':
            u'outbound to ID %s, type %s',
        u'log di debug':
            u'debug log',
        u'connessione diretta con l\'indirizzo %s (\u00abpunch received\u00bb, ora locale della macchina)':
            u'direct connection with the address %s ("punch received", local time of the machine)',
        u'Ricerca per nome degli strumenti noti non riuscita (controlli 33 e 38)':
            u'Search by name for the known tools failed (checks 33 and 38)',
        u'Strumenti noti sul disco: %d file esaminati':
            u'Known tools on disk: %d files examined',
        u'file sul disco':
            u'file on disk',
        u'%s sul disco%s: %s':
            u'%s on disk%s: %s',
        u' (file cancellato)':
            u' (deleted file)',
        u'Creato: %s - modificato: %s (UTC) - %s':
            u'Created: %s - modified: %s (UTC) - %s',
        u'Strumenti noti trovati sul disco (per nome)':
            u'Known tools found on disk (by name)',
        u'Ricerca degli eseguibili rinominati nelle cartelle di appoggio non riuscita (controlli 33 e 38)':
            u'Search for renamed executables in the staging folders failed (checks 33 and 38)',
        u'Nelle cartelle di appoggio ci sono %d eseguibili: per cercare quelli rinominati (controllo 38) '
        u'sono state lette le informazioni di versione dei 400 pi\u00f9 recenti.':
            u'The staging folders hold %d executables: to look for the renamed ones (check 38) the version '
            u'information of the 400 most recent was read.',
        u'eseguibile rinominato':
            u'renamed executable',
        u'%s (in origine %s, %s)':
            u'%s (originally %s, %s)',
        u'%s rinominato: %s':
            u'%s renamed: %s',
        u'Informazioni di versione: produttore \u00ab%s\u00bb, prodotto \u00ab%s\u00bb, nome originale \u00ab%s\u00bb.\nCreato: %s (UTC)':
            u'Version information: company "%s", product "%s", original name "%s".\nCreated: %s (UTC)',
        u'%s rinominato: %s (in origine \u00ab%s\u00bb)':
            u'%s renamed: %s (originally "%s")',
        u'tracce nei log':
            u'traces in the logs',
        u'(data non nota)':
            u'(date unknown)',
        u'. 1 sessione o evento in entrata, l\'ultima il %s':
            u'. 1 inbound session or event, the last one at %s',
        u'. %d sessioni o eventi in entrata, l\'ultima il %s':
            u'. %d inbound sessions or events, the last one at %s',
        u' - indicato come autorizzato':
            u' - declared as authorized',
        u'. Decisivo se lo strumento non \u00e8 autorizzato':
            u'. Decisive if the tool is not authorized',
        u'. Installato di recente: verifica se \u00e8 autorizzato':
            u'. Installed recently: check whether it is authorized',
        u'. Nessuna sessione in entrata trovata: verifica se \u00e8 autorizzato':
            u'. No inbound session found: check whether it is authorized',
        u'Sessioni ed eventi:':
            u'Sessions and events:',
        u'Strumenti di accesso remoto trovati':
            u'Remote access tools found',
        u'Strumento':
            u'Tool',
        u'Dettaglio':
            u'Detail',
        u'Per ogni strumento: \u00e8 autorizzato? Quando si \u00e8 collegato qualcuno? Cosa ha fatto? Come \u00e8 '
        u'arrivato?':
            u'For each tool: is it authorized? When did someone connect? What did they do? How did it get '
            u'there?',
        u'Sessioni ed eventi degli strumenti di accesso remoto':
            u'Sessions and events of the remote access tools',
        u'Programmi installati: i 30 pi\u00f9 recenti':
            u'Installed programs: the 30 most recent',
        u'Chiave scritta (UTC)':
            u'Key written (UTC)',
        u'Programma':
            u'Program',
        u'Produttore':
            u'Publisher',
        u'La cronologia dei rilevamenti di Defender contiene %d file: ne sono stati letti 2000.':
            u'The Defender detection history holds %d files: 2000 of them were read.',
        u'Defender ha rilevato %s (%d file nella cronologia dei rilevamenti)':
            u'Defender detected %s (files in the detection history: %d)',
        u'Rilevamento che non compare nel registro eventi (forse gi\u00e0 uscito dal registro).\nPrimo file: %s '
        u'(UTC)\n%s':
            u'Detection that does not appear in the event log (it may have already rolled out of the '
            u'log).\nFirst file: %s (UTC)\n%s',
        u'La cronologia di PowerShell di %s \u00e8 insolitamente grande (%s): ne sono stati letti gli ultimi 4 '
        u'MB.':
            u'The PowerShell history of %s is unusually large (%s): only its last 4 MB were read.',
        u'Cronologia di PowerShell di ':
            u'PowerShell history of ',
        u': %d righe':
            u': %d lines',
        u'Cronologia di PowerShell di %s, riga %d: %s':
            u'PowerShell history of %s, line %d: %s',
        u'%s%s\nIl file non registra gli orari: l\'ultima modifica \u00e8 del %s (UTC).':
            u'%s%s\nThe file does not record times: its last modification is dated %s (UTC).',
        u'Cronologia della console di PowerShell: righe segnalate':
            u'PowerShell console history: flagged lines',
        u'Riga':
            u'Line',
        u'Ricerca dei file nelle cartelle di appoggio non riuscita (controllo 38)':
            u'Search for the files in the staging folders failed (check 38)',
        u'Ricerca dei flussi Zone.Identifier non riuscita: %r':
            u'Search for the Zone.Identifier streams failed: %r',
        u'Nome di file con il carattere che inverte il verso del testo: %s':
            u'File name with the character that reverses the text direction: %s',
        u'Il carattere U+202E fa leggere al contrario la fine del nome e camuffa l\'estensione vera '
        u'(.%s).\nCreato: %s - modificato: %s (UTC)':
            u'The U+202E character makes the end of the name read backwards and disguises the real extension '
            u'(.%s).\nCreated: %s - modified: %s (UTC)',
        u'archivio di grandi dimensioni':
            u'large archive',
        u'Archivio di %s in una cartella di appoggio: %s':
            u'%s archive in a staging folder: %s',
        u'Creato: %s - modificato: %s (UTC). Un grande archivio qui pu\u00f2 essere dati pronti per '
        u'l\'esfiltrazione.':
            u'Created: %s - modified: %s (UTC). A large archive here may be data staged for exfiltration.',
        u'programma o script recente in una cartella di appoggio':
            u'recent program or script in a staging folder',
        u'Programma o script recente in una cartella di appoggio: %s':
            u'Recent program or script in a staging folder: %s',
        u'\nScaricato da: ':
            u'\nDownloaded from: ',
        u'Ricerca dei programmi con un\'estensione innocua non riuscita (controllo 38)':
            u'Search for programs with a harmless extension failed (check 38)',
        u'Programma salvato con un\'estensione innocua: %s':
            u'Program saved with a harmless extension: %s',
        u'Il file inizia con MZ (eseguibile di Windows) ma ha estensione .%s.\nCreato: %s - modificato: %s '
        u'(UTC) - %s':
            u'The file starts with MZ (Windows executable) but has the extension .%s.\nCreated: %s - modified: '
            u'%s (UTC) - %s',
        u'eseguibile con estensione innocua':
            u'executable with a harmless extension',
        u'Programmi, script e archivi recenti nelle cartelle di appoggio (i 60 pi\u00f9 recenti)':
            u'Recent programs, scripts and archives in the staging folders (the 60 most recent)',
        u'Scaricato da (Zone.Identifier)':
            u'Downloaded from (Zone.Identifier)',
    }


def _controlli_file_3():
    # tc_c_file.py
    return {
        u'Cartelle: Users\\Public, PerfLogs, Windows\\Temp, ProgramData, Temp e Downloads degli utenti. '
        u'Finestra: gli ultimi %d giorni di attivit\u00e0 della macchina.':
            u'Folders: Users\\Public, PerfLogs, Windows\\Temp, ProgramData, the users\' Temp and Downloads. '
            u'Window: the last %d days of machine activity.',
        u'nessun file $I: il Cestino \u00e8 vuoto':
            u'no $I file: the Recycle Bin is empty',
        u'cartella $Recycle.Bin non trovata':
            u'$Recycle.Bin folder not found',
        u'Nel Cestino ci sono %d elementi: ne sono stati letti 20000.':
            u'The Recycle Bin holds %d items: 20000 of them were read.',
        u'Cestino: %d elementi letti':
            u'Recycle Bin: %d items read',
        u'Cestino: le 50 cancellazioni pi\u00f9 recenti':
            u'Recycle Bin: the 50 most recent deletions',
        u'Cancellato (UTC)':
            u'Deleted (UTC)',
        u'Percorso originale':
            u'Original path',
        u'File $I letti: %d.':
            u'$I files read: %d.',
        u'Cancellazione in blocco: %d elementi in %d minuti da %s':
            u'Bulk deletion: %d items within %d min by %s',
        u'Dal %s al %s (UTC). Esempi:\n%s':
            u'From %s to %s (UTC). Examples:\n%s',
        u'%s buttato nel Cestino: %s':
            u'%s sent to the Recycle Bin: %s',
        u'Cancellato da %s il %s (UTC) - %s':
            u'Deleted by %s at %s (UTC) - %s',
        u'cartella System Volume Information non presente nell\'origine':
            u'System Volume Information folder not present in the data source',
        u'Copie shadow presenti':
            u'Shadow copies present',
        u'Identificativo':
            u'Identifier',
        u'Le copie possono contenere file e registri cancellati dopo: montale e confrontale. Autopsy non '
        u'le apre da solo.':
            u'The copies may contain files and logs that were deleted later: mount them and compare. Autopsy '
            u'does not open them by itself.',
        u'nessuna copia: il ripristino di sistema \u00e8 disattivato':
            u'no copies: System Restore is disabled',
        u'nessuna copia shadow; %s \u00e8 stato eseguito l\'ultima volta il %s, fuori dal periodo recente':
            u'no shadow copy; %s was last run at %s, outside the recent period',
        u'Nessuna copia shadow sul disco e %s \u00e8 stato eseguito (ultimo avvio: %s)':
            u'No shadow copy on the disk and %s was run (last run: %s)',
        u'L\'esecuzione non prova la cancellazione: cerca \u00abdelete shadows\u00bb negli eventi 4688 e nei log di '
        u'PowerShell. Fonte: %s.':
            u'Execution does not prove deletion: look for "delete shadows" in the 4688 events and in the '
            u'PowerShell logs. Source: %s.',
        u'nessuna copia shadow trovata':
            u'no shadow copy found',
    }


def _eventi():
    # tc_eventi.py
    return {
        u'Esclusione aggiunta: ':
            u'Exclusion added: ',
        u'Protezione disattivata: ':
            u'Protection disabled: ',
        u'Protezione in tempo reale disattivata':
            u'Real-time protection disabled',
        u'Analisi antimalware disattivata':
            u'Antimalware scanning disabled',
    }


def _artefatti():
    # tc_artefatti.py
    return {
        u'lunghezza non valida':
            u'invalid length',
        u'[Menu Start comune]':
            u'[Common Start Menu]',
        u'[Elementi fissati]':
            u'[Pinned items]',
        u'[Menu Start utente]':
            u'[User Start Menu]',
        u'eseguibile':
            u'executable',
        u'archivio':
            u'archive',
        u'script':
            u'script',
        u'pagina HTML':
            u'HTML page',
    }


def _origine():
    # tc_origine.py
    return {
        u'file sparsi (nessuna cartella Windows riconosciuta)':
            u'loose files (no Windows folder recognized)',
        u'[altro volume]':
            u'[other volume]',
    }


def _evtx():
    # tc_evtx.py
    return {
        u'valore letterale di tipo %d non gestito':
            u'literal value of type %d not handled',
        u'token %02x non gestito':
            u'token %02x not handled',
        u'atteso fine apertura elemento, trovato %02x':
            u'expected end of element start, found %02x',
        u'troppe sostituzioni: %d':
            u'too many substitutions: %d',
        u'non \u00e8 un file evtx':
            u'not an evtx file',
    }


def _prefetch():
    # tc_prefetch.py
    return {
        u'tabella di Huffman non valida':
            u'invalid Huffman table',
        u'codice di Huffman non previsto dalla tabella':
            u'Huffman code not in the table',
        u'dati compressi non validi':
            u'invalid compressed data',
        u'riferimento prima dell\'inizio':
            u'reference before the start',
        u'dimensione dichiarata non credibile':
            u'declared size not credible',
        u'non \u00e8 un file Prefetch':
            u'not a Prefetch file',
    }


def _registro():
    # tc_registro.py
    return {
        u'cella nk non valida a %x':
            u'invalid nk cell at %x',
        u'non \u00e8 un hive del registro':
            u'not a registry hive',
        u'offset fuori dal file: %x':
            u'offset outside the file: %x',
        u'lista di sottochiavi non riconosciuta':
            u'unrecognized subkey list',
        u'cella vk non valida':
            u'invalid vk cell',
    }


def _base():
    # tc_base.py
    return {
        u'posizione negativa':
            u'negative position',
    }


def _memoria_1():
    # tc_memoria.py
    return {
        u'manifesto non leggibile (%s)':
            u'manifest not readable (%s)',
        u'%s danneggiato: non \u00e8 un testo JSON valido':
            u'%s damaged: it is not valid JSON',
        u'%s non \u00e8 un manifesto dello script di raccolta':
            u'%s is not a manifest of the collection script',
        u'il manifesto \u00e8 di una versione pi\u00f9 recente dello script di raccolta (formato %d): aggiorna il '
        u'plugin':
            u'the manifest comes from a newer version of the collection script (format %d): update the plugin',
        u'dalla RAM: nome del computer e ora dell\'acquisizione':
            u'from memory: computer name and acquisition time',
        u'Volatility 3 non ha un plugin per la cache DNS: serve il triage dal vivo':
            u'Volatility 3 has no plugin for the DNS cache: it needs live triage',
        u'non riuscito':
            u'failed',
        u'fermato dopo il tempo massimo':
            u'stopped after the time limit',
        u'non eseguito':
            u'not run',
        u'file non trovato':
            u'file not found',
        u'output illeggibile':
            u'unreadable output',
        u'output troppo grande':
            u'output too large',
        u'RAM %s, plugin di Volatility senza risultati: %s. Controlli incompleti: %s.':
            u'Memory %s, Volatility plugins without results: %s. Incomplete checks: %s.',
        u'RAM %s: la raccolta con Volatility \u00e8 stata interrotta prima della fine.':
            u'Memory %s: the collection with Volatility was interrupted before the end.',
        u'Riga di comando: %s':
            u'Command line: %s',
        u'Programma: %s':
            u'Program: %s',
        u'Processo padre: %s (PID %d)':
            u'Parent process: %s (PID %d)',
        u'Processo padre: PID %d, non pi\u00f9 attivo':
            u'Parent process: PID %d, no longer running',
        u'Utente: %s':
            u'User: %s',
        u'Avviato: %s (UTC)':
            u'Started: %s (UTC)',
        u'Terminato: %s (UTC)':
            u'Ended: %s (UTC)',
        u'Trovato solo dalla scansione della memoria (psscan), non nell\'elenco dei processi attivi.':
            u'Found only by the memory scan (psscan), not in the list of active processes.',
        u'Fonte: RAM %s, %s':
            u'Source: memory %s, %s',
        u'la RAM c\'\u00e8, ma Volatility non ha prodotto l\'elenco dei processi':
            u'the memory is there, but Volatility produced no process list',
        u'processo nella RAM':
            u'process in memory',
        u'Processo nella memoria ma non nell\'elenco dei processi attivi, forse nascosto: %s (PID %d)':
            u'Process in memory but not in the list of active processes, maybe hidden: %s (PID %d)',
        u'%s con un processo padre insolito: %s (PID %d) invece di %s':
            u'%s with an unusual parent process: %s (PID %d) instead of %s',
        u'%d processi %s attivi nello stesso momento: di norma ce n\'\u00e8 uno solo (PID %s)':
            u'%d %s processes running at the same time: normally there is only one (PID %s)',
        u'%s avviato da %s (PID %d): un programma per documenti o un server web di norma non apre '
        u'interpreti di comandi':
            u'%s started by %s (PID %d): a document program or a web server does not normally open command '
            u'interpreters',
        u'solo psscan':
            u'psscan only',
        u'Tutti i processi trovati da Volatility (%s), in ordine di avvio. \u00abSolo psscan\u00bb: trovato dalla '
        u'scansione della memoria ma non nell\'elenco dei processi attivi (terminato, oppure nascosto se '
        u'non ha l\'ora di fine).':
            u'All the processes found by Volatility (%s), in order of start. "psscan only": found by the '
            u'memory scan but not in the list of active processes (ended, or hidden if it has no end time).',
        u' Sono mostrati i primi 400 di %d.':
            u' The first 400 of %d are shown.',
        u'Processi nella RAM (%s)':
            u'Processes in memory (%s)',
        u'Riga di comando o programma':
            u'Command line or program',
        u'Sessione':
            u'Session',
        u'Avviato (UTC)':
            u'Started (UTC)',
        u'Terminato (UTC)':
            u'Ended (UTC)',
        u'RAM %s: senza l\'elenco dei processi attivi (pslist e pstree) non si possono cercare i processi '
        u'nascosti.':
            u'Memory %s: without the list of active processes (pslist and pstree) hidden processes cannot be '
            u'searched for.',
        u'la RAM c\'\u00e8, ma Volatility non ha prodotto le connessioni (%s)':
            u'the memory is there, but Volatility produced no connections (%s)',
        u'solo le connessioni sulla porta 445: le sessioni SMB richiedono il triage dal vivo':
            u'only the connections on port 445: SMB sessions need live triage',
        u'Connessione verso %s da un processo gi\u00e0 segnalato: %s (PID %d, %s)':
            u'Connection to %s from a process already reported: %s (PID %d, %s)',
        u'Locale %s - remoto %s - stato %s - creata %s (UTC)\nFonte: RAM %s, %s':
            u'Local %s - remote %s - state %s - created %s (UTC)\nSource: memory %s, %s',
        u'%s ha una connessione verso l\'indirizzo pubblico %s (PID %d, %s): di norma non si collega a '
        u'Internet':
            u'%s has a connection to the public address %s (PID %d, %s): it does not normally connect to the '
            u'Internet',
        u'Le connessioni trovate da %s: prima quelle verso indirizzi pubblici, poi le altre, poi le porte '
        u'in ascolto.':
            u'The connections found by %s: first those to public addresses, then the others, then the '
            u'listening ports.',
        u' Sono mostrate le prime 300 di %d.':
            u' The first 300 of %d are shown.',
        u'Connessioni di rete nella RAM (%s)':
            u'Network connections in memory (%s)',
        u'Protocollo':
            u'Protocol',
        u'Locale':
            u'Local',
        u'Remoto':
            u'Remote',
        u'Processo (PID)':
            u'Process (PID)',
        u'Connessioni SMB (porta 445) nella RAM (%s)':
            u'SMB connections (port 445) in memory (%s)',
        u'Direzione':
            u'Direction',
        u'Dalla RAM si vedono le connessioni sulla porta 445, non le sessioni SMB con l\'utente e le '
        u'condivisioni aperte: per quelle serve il triage dal vivo.':
            u'Memory shows the connections on port 445, not the SMB sessions with the user and the open '
            u'shares: those need live triage.',
        u'la RAM c\'\u00e8, ma Volatility non ha prodotto le sessioni (%s)':
            u'the memory is there, but Volatility produced no sessions (%s)',
        u'Sessione di Desktop remoto aperta al momento dell\'acquisizione: %s (sessione %d, %s)':
            u'Remote Desktop session open at the time of acquisition: %s (session %d, %s)',
        u'Processi nella sessione: %d; il primo avviato il %s (UTC).\nFonte: RAM %s, %s':
            u'Processes in the session: %d; the first started at %s (UTC).\nSource: memory %s, %s',
        u'Sessioni nella RAM (%s)':
            u'Sessions in memory (%s)',
        u'Processi':
            u'Processes',
        u'Primo processo (UTC)':
            u'First process (UTC)',
        u'Il tipo viene dalla variabile SESSIONNAME dei processi: Console per chi sta davanti al '
        u'computer, RDP-Tcp#N per il Desktop remoto. Senza utente: sessione dei servizi.':
            u'The type comes from the SESSIONNAME variable of the processes: Console for whoever sits at the '
            u'computer, RDP-Tcp#N for Remote Desktop. No user: the services session.',
        u'servizio nella RAM':
            u'service in memory',
        u'nella RAM ma non nel registro':
            u'in memory but not in the registry',
        u'%s\nStato: %s - avvio: %s - PID: %s\nFonte: RAM %s, %s':
            u'%s\nState: %s - start: %s - PID: %s\nSource: memory %s, %s',
        u'(programma non leggibile nella RAM)':
            u'(program not readable in memory)',
        u'solo i servizi trovati nella RAM':
            u'only the services found in memory',
    }


def _memoria_2():
    # tc_memoria.py
    return {
        u'Servizi segnalati nella RAM (%s)':
            u'Services reported in memory (%s)',
        u'Servizi nella RAM che non sono nel registro (%s)':
            u'Services in memory that are not in the registry (%s)',
        u'Avvio':
            u'Start',
        u'computer: %s':
            u'computer: %s',
        u'ora di sistema nella RAM: %s UTC':
            u'system time in memory: %s UTC',
        u'Windows build %s':
            u'Windows build %s',
        u'Volatility %s: %d plugin su %d con risultati':
            u'Volatility %s: %d of %d plugins with results',
        u'cartella: %s':
            u'folder: %s',
        u' (origine dati \u00ab%s\u00bb)':
            u' (data source "%s")',
    }


def _versione_13():
    # i testi nuovi della versione 1.3
    return {
        u'Triage rapido: indica quali macchine Windows esaminare per prime. Cerca indicatori di compromissione'
        u' nei registri eventi, nel registro di sistema, nel Prefetch, negli altri artefatti e nella RAM anali'
        u'zzata con Volatility; produce un verdetto euristico, i segnali e un report HTML.':
            u'Quick triage: points out which Windows machines to examine first. Looks for indicators of compromise'
            u' in the event logs, the registry, the Prefetch, the other artifacts and the memory analyzed with Vol'
            u'atility; produces a heuristic verdict, the signals and an HTML report.',
        u'RAM (risultati di Volatility):':
            u'Memory (Volatility results):',
        u'Automatica: stessa origine o stesso host':
            u'Automatic: same data source or same host',
        u'Nessuna':
            u'None',
        u'Scelta prima, non trovata in questo caso':
            u'Chosen before, not found in this case',
        u'Quale RAM va con questa macchina lo dici tu:':
            u'You say which memory goes with this machine:',
        u'il plugin controlla la scelta e avvisa.':
            u'the module checks the choice and warns.',
        u'Nell\'origine dati ci sono risultati di Volatility, ma nelle impostazioni dell\'ingest la RAM \u00e8'
        u' esclusa: i controlli sui dati volatili non sono stati fatti.':
            u'The data source contains Volatility results, but the ingest settings exclude the memory: the checks '
            u'on volatile data were not done.',
        u'La RAM scelta nelle impostazioni dell\'ingest non si trova in questo caso: i controlli sui dati vola'
        u'tili non sono stati fatti. Sceglila di nuovo.':
            u'The memory chosen in the ingest settings is not in this case: the checks on volatile data were not d'
            u'one. Choose it again.',
        u'RAM scelta non leggibile: ':
            u'Chosen memory not readable: ',
        u'La RAM scelta nelle impostazioni dell\'ingest non si legge: i controlli sui dati volatili non sono s'
        u'tati fatti.':
            u'The memory chosen in the ingest settings cannot be read: the checks on volatile data were not done.',
        u'durante l\'installazione di Windows: di solito \u00e8 il servizio temporaneo di un programma di inst'
        u'allazione':
            u'during the installation of Windows: usually the temporary service of a setup program',
        u' (durante l\'installazione di Windows: uno script di preparazione della macchina)':
            u' (during the installation of Windows: a script that prepared the machine)',
        u'creato il %s UTC (evento 4720)':
            u'created on %s UTC (event 4720)',
        u'aggiunto al gruppo Administrators il %s UTC (evento %d)':
            u'added to the Administrators group on %s UTC (event %d)',
        u'Solo il nome: le informazioni di versione del file non confermano lo strumento (o il file non le ha,'
        u' o non si legge).':
            u'Only the name: the version information of the file does not confirm the tool (or the file has none, '
            u'or cannot be read).',
        u'Driver di uno strumento di acquisizione della memoria: %s risulta eseguito dalla stessa cartella e i'
        u'l driver \u00e8 stato installato a %d minuti dall\'acquisizione della RAM. \u00c8 di chi ha raccolto'
        u' le prove; l\'hash del file, che il plugin non pu\u00f2 confrontare, va controllato.':
            u'Driver of a memory acquisition tool: %s was run from the same folder and the driver was installed %d'
            u' minutes from the memory acquisition. It belongs to whoever collected the evidence; the hash of the '
            u'file, which the module cannot compare, should be checked.',
        u'lo strumento eseguito dalla stessa cartella':
            u'the tool run from the same folder',
        u'un\'acquisizione della RAM di questa macchina entro mezz\'ora':
            u'a memory acquisition of this machine within half an hour',
        u'Ha il nome del driver di uno strumento di acquisizione della memoria, ma mancano %s: il nome da solo'
        u' non basta, perch\u00e9 si copia.':
            u'It has the name of the driver of a memory acquisition tool, but %s are missing: the name alone is no'
            u't enough, because it can be copied.',
        u' e ':
            u' and ',
        u'Amcache.hve non trovato su Windows %s (build %d), che lo crea sempre: manca una fonte delle prove di'
        u' esecuzione e il controllo 26 \u00e8 parziale.':
            u'Amcache.hve not found on Windows %s (build %d), which always creates it: a source of execution evide'
            u'nce is missing and check 26 is partial.',
        u'nome originale: ':
            u'original name: ',
        u'Solo il nome: nessuna prova di esecuzione e nessuna informazione di versione del file che confermi l'
        u'o strumento.':
            u'Only the name: no evidence of execution and no version information of the file confirming the tool.',
        u'INDICATORI DI COMPROMISSIONE':
            u'INDICATORS OF COMPROMISE',
        u'DA VERIFICARE, PRIORIT\u00c0 ALTA':
            u'NEEDS REVIEW, HIGH PRIORITY',
        u'NESSUN INDICATORE TROVATO':
            u'NO INDICATORS FOUND',
        u'Verdetto euristico di triage: indica dove guardare prima. Non \u00e8 una probabilit\u00e0 n\u00e9 un'
        u'a prova; la conclusione spetta all\'analisi forense.':
            u'Heuristic triage verdict: it points out where to look first. It is neither a probability nor proof; '
            u'the conclusion is up to the forensic analysis.',
        u'Driver degli strumenti di acquisizione: %s':
            u'Drivers of the acquisition tools: %s',
        u'disco':
            u'disk',
        u'Controlli parziali o non verificabili perch\u00e9 una fonte presente non \u00e8 riuscita: %s.':
            u'Checks partial or not verifiable because a source that is there did not work: %s.',
        u'1 fatto decisivo: un indicatore che di rado ha una spiegazione innocente e che da solo giustifica l'
        u'\'esame della macchina. Non \u00e8 una prova.':
            u'1 decisive fact: an indicator that rarely has an innocent explanation and alone justifies examining '
            u'the machine. It is not proof.',
        u'%d fatti decisivi: indicatori che di rado hanno una spiegazione innocente e che da soli giustificano'
        u' l\'esame della macchina. Non sono una prova.':
            u'%d decisive facts: indicators that rarely have an innocent explanation and alone justify examining t'
            u'he machine. They are not proof.',
        u'Nessun fatto decisivo, ma segnali da confermare in %d famiglie (%s) da fatti diversi: puntano nella '
        u'stessa direzione e vanno verificati per primi.':
            u'No decisive fact, but signals to confirm in %d families (%s) from different facts: they point the sa'
            u'me way and should be checked first.',
        u'Segnali da confermare in %d famiglie (%s), ma tutti sullo stesso oggetto: contano come un fatto solo'
        u'. Cerca conferme dall\'IT, dall\'utente e dai log centralizzati.':
            u'Signals to confirm in %d families (%s), but all about the same object: they count as one fact. Look '
            u'for confirmation from IT, the user and the central logs.',
        u'Segnali da una RAM con l\'output anomalo o da fonti che non concordano: da soli non portano oltre '
        u'\u00abda verificare\u00bb.':
            u'Signals from a memory with anomalous output or from sources that disagree: alone they do not go beyo'
            u'nd "needs review".',
        u'Nessun indicatore, ma la copertura \u00e8 insufficiente: l\'assenza di indicatori non esclude una co'
        u'mpromissione.':
            u'No indicators, but the coverage is insufficient: the absence of indicators does not rule out a compr'
            u'omise.',
        u'I controlli eseguiti non hanno trovato indicatori. Non vuol dire che il sistema sia pulito: il triag'
        u'e non vede tutto (i limiti sono nel README).':
            u'The checks that were run found no indicators. It does not mean the system is clean: the triage does '
            u'not see everything (the limits are in the README).',
        u' %d segnali vengono da una RAM che il disco contraddice: restano nel report ma non contano.':
            u' %d signals come from a memory that the disk contradicts: they stay in the report but do not count.',
        u'parziale, manca: %s':
            u'partial, missing: %s',
        u'Parziale':
            u'Partial',
        u'avviato da %s, un processo di sistema che non avvia mai programmi come questo: codice estraneo dentr'
        u'o un processo di sistema':
            u'started by %s, a system process that never starts programs like this: foreign code inside a system p'
            u'rocess',
        u'interprete di comandi avviato direttamente da services.exe: un servizio che esegue un comando, come '
        u'fanno PsExec e smbexec':
            u'command interpreter started directly by services.exe: a service that runs a command, as PsExec and s'
            u'mbexec do',
        u'shell avviata da %s: comandata a distanza attraverso uno strumento di rete':
            u'shell started by %s: controlled remotely through a network tool',
        u'WerFaultSecure.exe lanciato da %s contro un altro processo (/pid): la tecnica EDR-Freeze per sospend'
        u'ere l\'antivirus o l\'EDR':
            u'WerFaultSecure.exe launched by %s against another process (/pid): the EDR-Freeze technique to suspen'
            u'd the antivirus or the EDR',
        u'WerFaultSecure.exe lanciato contro un altro processo (/pid) da un processo che non si conosce: pu'
        u'\u00f2 essere la tecnica EDR-Freeze':
            u'WerFaultSecure.exe launched against another process (/pid) by an unknown process: it may be the EDR-'
            u'Freeze technique',
        u'scelta nelle impostazioni dell\'ingest':
            u'chosen in the ingest settings',
        u'origine dati \u00ab%s\u00bb dello stesso host di Autopsy':
            u'data source "%s" of the same Autopsy host',
        u'origine dati \u00ab%s\u00bb di un altro host':
            u'data source "%s" of another host',
        u'nella stessa origine dati':
            u'in the same data source',
        u'RAM %s: i risultati di Volatility in %s non si possono usare: %s. I controlli sui dati volatili non '
        u'sono stati fatti.':
            u'Memory %s: the Volatility results in %s cannot be used: %s. The checks on volatile data were not don'
            u'e.',
        u'La RAM %s (%s) \u00e8 indicata per un\'origine dati con %d installazioni di Windows: non si sa a qua'
        u'le appartiene e non \u00e8 stata usata per nessuna. Per usarla, metti l\'installazione giusta in un'
        u'\'origine dati a s\u00e9.':
            u'The memory %s (%s) is designated for a data source with %d Windows installations: it is not known wh'
            u'ich one it belongs to, and it was used for none. To use it, put the right installation in a data sou'
            u'rce of its own.',
        u'Nell\'origine dati ci sono anche i risultati di Volatility di un altro computer (%s, in %s): non son'
        u'o stati usati, perch\u00e9 mescolarli darebbe un verdetto che non riguarda nessuna macchina.':
            u'The data source also contains the Volatility results of another computer (%s, in %s): they were not '
            u'used, because mixing them would give a verdict about no machine.',
        u'Nell\'origine dati \u00ab%s\u00bb, di un altro host di Autopsy, c\'\u00e8 una RAM con lo stesso nome'
        u' di computer (%s, in %s): non \u00e8 stata usata. Se \u00e8 di questa macchina, metti le due origini'
        u' dati nello stesso host oppure indicala nelle impostazioni dell\'ingest.':
            u'The data source "%s", of another Autopsy host, contains a memory with the same computer name (%s, in'
            u' %s): it was not used. If it belongs to this machine, put the two data sources in the same host or c'
            u'hoose it in the ingest settings.',
        u'output diverso da quello registrato nel manifesto (righe o SHA-256)':
            u'output different from the one recorded in the manifest (rows or SHA-256)',
        u'%s: Volatility non l\'ha riconosciuto (%s). Non \u00e8 un\'immagine della memoria di Windows, oppure'
        u' mancano i simboli del suo kernel. I controlli sui dati volatili non sono stati fatti.':
            u'%s: Volatility did not recognize it (%s). It is not a Windows memory image, or the symbols of its ke'
            u'rnel are missing. The checks on volatile data were not done.',
        u'RAM %s: nessun plugin di Volatility ha dato risultati (%s). I controlli sui dati volatili non sono s'
        u'tati fatti.':
            u'Memory %s: no Volatility plugin gave results (%s). The checks on volatile data were not done.',
        u'nessun risultato di Volatility in %s':
            u'no Volatility results in %s',
        u'i servizi rimasti solo in memoria non si controllano':
            u'the services left only in memory are not checked',
        u'RAM %s, plugin di Volatility senza risultati: %s. I controlli non ne risentono; i controlli sull\'ab'
        u'binamento della RAM che ne dipendono non si possono fare.':
            u'Memory %s, Volatility plugins without results: %s. The checks are not affected; the checks on the me'
            u'mory pairing that depend on them cannot be done.',
        u'%s; usato %s, che non vede le connessioni gi\u00e0 chiuse':
            u'%s; %s used instead, which does not see the connections already closed',
        u'RAM %s: %s %s; le connessioni vengono da %s, che non vede quelle gi\u00e0 chiuse. I controlli 5 e 7 '
        u'sono parziali.':
            u'Memory %s: %s %s; the connections come from %s, which does not see those already closed. Checks 5 an'
            u'd 7 are partial.',
        u'RAM %s: il manifesto non dichiara completa la raccolta con Volatility (fermata prima della fine).':
            u'Memory %s: the manifest does not declare the Volatility collection complete (stopped before the end)'
            u'.',
        u'concorda':
            u'agrees',
        u'contraddice':
            u'contradicts',
        u'non verificabile':
            u'not verifiable',
        u'build di Windows':
            u'Windows build',
        u'RAM %d, disco %d':
            u'memory %d, disk %d',
        u'manca la build della RAM o del disco':
            u'the build of the memory or of the disk is missing',
        u'nome del computer':
            u'computer name',
        u'RAM %s, disco %s':
            u'memory %s, disk %s',
        u'manca il nome nella RAM o sul disco':
            u'the name is missing in the memory or on the disk',
        u'avvio di Windows':
            u'Windows boot',
        u'avvio della RAM %s UTC, nel registro System alle %s UTC':
            u'memory boot %s UTC, in the System log at %s UTC',
        u'avvio della RAM %s UTC: nessun avvio entro 2 minuti nel registro System, che copre quel momento':
            u'memory boot %s UTC: no boot within 2 minutes in the System log, which covers that moment',
        u'il registro System non copre l\'avvio della RAM, o manca uno dei due':
            u'the System log does not cover the memory boot, or one of the two is missing',
        u'SID della macchina':
            u'machine SID',
        u'mancano i SID della RAM o del disco':
            u'the SIDs of the memory or of the disk are missing',
        u'ora dell\'acquisizione':
            u'acquisition time',
        u'RAM %s UTC, registri dal %s al %s UTC':
            u'memory %s UTC, logs from %s to %s UTC',
        u'manca l\'ora della RAM o il periodo dei registri':
            u'the memory time or the period of the logs is missing',
        u'La RAM %s (%s) non sembra di questa installazione di Windows: %s. I suoi indizi restano nel report, '
        u'segnati, ma non contano per il verdetto finch\u00e9 l\'abbinamento non viene corretto.':
            u'The memory %s (%s) does not seem to belong to this Windows installation: %s. Its findings stay in th'
            u'e report, marked, but do not count for the verdict until the pairing is corrected.',
        u'Abbinamento della RAM %s (%s) da verificare: %s. I suoi indizi contano per il verdetto.':
            u'Pairing of the memory %s (%s) to be checked: %s. Its findings count for the verdict.',
        u'solo %d processi attivi in pslist':
            u'only %d active processes in pslist',
        u'mancano processi che un Windows acceso ha sempre: %s':
            u'processes that a running Windows always has are missing: %s',
        u'psscan trova %d processi attivi che pslist non elenca':
            u'psscan finds %d active processes that pslist does not list',
        u'nessuna porta in ascolto in %s':
            u'no listening port in %s',
        u'solo %d servizi in svcscan':
            u'only %d services in svcscan',
        u'solo %d variabili d\'ambiente in envars':
            u'only %d environment variables in envars',
        u'RAM %s: output anomalo o forse incompleto (%s). Non si distingue fra un problema di acquisizione, di'
        u' estrazione o un occultamento. Gli indizi della RAM restano nel report, ma non portano il verdetto o'
        u'ltre \u00abda verificare\u00bb.':
            u'Memory %s: anomalous or possibly incomplete output (%s). An acquisition problem, an extraction probl'
            u'em and concealment cannot be told apart. The findings of the memory stay in the report, but they do '
            u'not take the verdict beyond "needs review".',
        u'Processi attivi nella RAM con l\'utente %s, %s':
            u'Processes active in the memory with the user %s, %s',
        u'%s\nFonte: RAM %s':
            u'%s\nSource: memory %s',
        u'PID %d: %s (avviato %s UTC)':
            u'PID %d: %s (started %s UTC)',
        u' \u00ab?\u00bb: Volatility non ha attribuito la connessione a un processo. Succede con le build di W'
        u'indows di cui conosce meno le strutture di rete (per esempio Windows 11 22H2 e 23H2) e con le connes'
        u'sioni gi\u00e0 chiuse; non \u00e8 un indizio.':
            u' "?": Volatility did not attribute the connection to a process. It happens with the Windows builds w'
            u'hose network structures it knows less well (for example Windows 11 22H2 and 23H2) and with connectio'
            u'ns already closed; it is not a finding.',
        u'la RAM c\'\u00e8, ma Volatility non ha prodotto i servizi (%s)':
            u'the memory is there, but Volatility did not produce the services (%s)',
        u'driver di %s, lo strumento che ha acquisito la memoria (gira dalla stessa cartella, PID %d)':
            u'driver of %s, the tool that acquired the memory (running from the same folder, PID %d)',
        u'ha il nome del driver di uno strumento di acquisizione della memoria, ma lo strumento non gira nella'
        u' RAM dalla stessa cartella: il nome da solo non basta':
            u'it has the name of the driver of a memory acquisition tool, but the tool is not running in the memor'
            u'y from the same folder: the name alone is not enough',
        u'tunnel o proxy verso l\'esterno (inoltro di porta con netsh, ssh -R, -L o -D)':
            u'tunnel or proxy to the outside (port forwarding with netsh, ssh -R, -L or -D)',
        u'fatto %d':
            u'fact %d',
        u'RAM contraddetta dal disco: non conta':
            u'memory contradicted by the disk: does not count',
        u'RAM con output anomalo: non oltre \u00abda verificare\u00bb':
            u'memory with anomalous output: not beyond "needs review"',
        u'discordanza fra fonti':
            u'disagreement between sources',
        u' (dai registri eventi)':
            u' (from the event logs)',
        u'%s (solo nella RAM: non \u00e8 il nome dell\'installazione)':
            u'%s (only in the memory: not the name of the installation)',
        u'Installazione secondo i registri eventi':
            u'Installation according to the event logs',
        u'preparazione dal %s UTC, nome definitivo dal %s UTC':
            u'preparation from %s UTC, final name from %s UTC',
        u'%d segnali da una RAM anomala o da fonti discordanti':
            u'%d signals from an anomalous memory or from sources that disagree',
        u'%d segnali da una RAM contraddetta, esclusi':
            u'%d signals from a contradicted memory, excluded',
        u'Abbinamento della RAM %s: %s.':
            u'Pairing of the memory %s: %s.',
        u'contraddetto (%s): i suoi indizi non contano':
            u'contradicted (%s): its findings do not count',
        u'da verificare (%s)':
            u'to be checked (%s)',
        u'concorda (%s)':
            u'agrees (%s)',
        u'non verificabile con gli artefatti del disco':
            u'not verifiable with the disk artifacts',
        u'; output anomalo, i suoi indizi non portano oltre \u00abda verificare\u00bb':
            u'; anomalous output, its findings do not go beyond "needs review"',
        u'SHA-256 dell\'immagine':
            u'SHA-256 of the image',
        u'Indicata':
            u'Designated',
        u'Esito dell\'abbinamento':
            u'Pairing outcome',
        u'Output anomalo':
            u'Anomalous output',
        u'no':
            u'no',
        u'Identit\u00e0':
            u'Identity',
        u'<p class="nota">L\'abbinamento lo indica l\'analista (stessa origine dati con una sola installazione'
        u', stesso host di Autopsy o scelta nelle impostazioni dell\'ingest); il plugin lo controlla con gli a'
        u'rtefatti del disco. Se un controllo d\'identit\u00e0 (build, avvio, SID) lo contraddice, gli indizi '
        u'della RAM restano qui, segnati, ma non contano per il verdetto; il nome e l\'ora danno solo un avvis'
        u'o.</p>':
            u'<p class="nota">The analyst designates the pairing (same data source with a single installation, sam'
            u'e Autopsy host, or chosen in the ingest settings); the module checks it with the disk artifacts. If '
            u'an identity check (build, boot, SID) contradicts it, the findings of the memory stay here, marked, b'
            u'ut do not count for the verdict; the name and the time give only a warning.</p>',
        u'escluso':
            u'excluded',
        u'incerto':
            u'uncertain',
        u'Fatti decisivi':
            u'Decisive facts',
        u'Fatti da confermare':
            u'Facts to confirm',
        u'Segnali che contano':
            u'Signals that count',
        u'<p class="indice"><a href="#segnali">Segnali</a><a href="#fatti">Fatti</a><a href="#cronologia">Cron'
        u'ologia</a><a href="#controlli">I 41 controlli</a>':
            u'<p class="indice"><a href="#segnali">Signals</a><a href="#fatti">Facts</a><a href="#cronologia">Time'
            u'line</a><a href="#controlli">The 41 checks</a>',
        u'<h2 id="ram">RAM: abbinamento e controlli</h2>':
            u'<h2 id="ram">Memory: pairing and checks</h2>',
        u'<h3>Discordanze fra fonti e RAM con output anomalo (%d)</h3>':
            u'<h3>Disagreements between sources and memory with anomalous output (%d)</h3>',
        u'<p class="nota">Possono venire da un occultamento come da un problema di acquisizione o di estrazion'
        u'e: portano il verdetto a \u00abda verificare\u00bb, non oltre.</p>':
            u'<p class="nota">They can come from concealment as well as from an acquisition or extraction problem:'
            u' they take the verdict to "needs review", not beyond.</p>',
        u'<h3>Dalla RAM contraddetta dal disco (%d): non contano</h3>':
            u'<h3>From the memory contradicted by the disk (%d): they do not count</h3>',
        u'<h2 id="fatti">Fatti</h2>':
            u'<h2 id="fatti">Facts</h2>',
        u'Famiglie':
            u'Families',
        u'Visto in':
            u'Seen in',
        u'Segnali':
            u'Signals',
        u'Primo segnale':
            u'First signal',
        u'<p class="nota">Un fatto riunisce i segnali sullo stesso oggetto (processo, comando, file, attivit'
        u'\u00e0, servizio, account, indirizzo, registro, blocco di script). Pi\u00f9 fonti che lo vedono conf'
        u'ermano che \u00e8 avvenuto, non che sia pi\u00f9 grave; per il verdetto due famiglie contano solo se'
        u' vengono da fatti diversi.</p>':
            u'<p class="nota">A fact groups the signals about the same object (process, command, file, task, servi'
            u'ce, account, address, log, script block). More sources seeing it confirm that it happened, not that '
            u'it is more serious; for the verdict two families count only if they come from different facts.</p>',
        u'<p>Nessun fatto decisivo o da confermare.</p>':
            u'<p>No decisive facts or facts to confirm.</p>',
        u'<p class="nota">\u00abParziale\u00bb: il controllo \u00e8 stato fatto, ma una sua fonte manca o '
        u'\u00e8 incompleta (la nota dice quale). Un controllo parziale o non verificabile per una fonte che c'
        u'\'\u00e8 ma non \u00e8 riuscita impedisce il verdetto \u00abnessun indicatore trovato\u00bb.</p>':
            u'<p class="nota">"Partial": the check was done, but one of its sources is missing or incomplete (the '
            u'note says which). A check that is partial or not verifiable because a source that is there did not w'
            u'ork prevents the verdict "no indicators found".</p>',
        u'<p><b>Verdetto.</b> Contano i fatti, non i segnali: i segnali sullo stesso oggetto sono un fatto sol'
        u'o. Un fatto <i>decisivo</i> d\u00e0 \u00abIndicatori di compromissione\u00bb: un indicatore che di r'
        u'ado ha una spiegazione innocente e che da solo giustifica l\'esame della macchina, non una prova. Se'
        u'gnali <i>da confermare</i> in due famiglie diverse, da fatti diversi, danno \u00abDa verificare, pri'
        u'orit\u00e0 alta\u00bb (famiglie: accessi, account, persistenza, programmi eseguiti, strumenti d\'att'
        u'acco, strumenti a doppio uso, esecuzione remota, RMM, file, anti-forensics, antivirus, esfiltrazione'
        u' e tunnel). Una sola famiglia, o un fatto solo, d\u00e0 \u00abDa verificare\u00bb; cos\u00ec anche l'
        u'e discordanze fra fonti e gli indizi di una RAM con l\'output anomalo, e un avviso di copertura senz'
        u'a segnali: registri o hive assenti, danneggiati o troppo corti, file che non si sono lasciati legger'
        u'e, controlli parziali, registri che si fermano prima del resto, controlli interrotti da un errore. '
        u'\u00abNessun indicatore trovato\u00bb non vuol dire che la macchina sia pulita.</p>':
            u'<p><b>Verdict.</b> Facts count, not signals: signals about the same object are one fact. A <i>decisi'
            u've</i> fact gives "Indicators of compromise": an indicator that rarely has an innocent explanation a'
            u'nd alone justifies examining the machine, not proof. Signals <i>to confirm</i> in two different fami'
            u'lies, from different facts, give "Needs review, high priority" (families: logons, accounts, persiste'
            u'nce, program execution, attack tools, dual-use tools, remote execution, RMM, files, anti-forensics, '
            u'antivirus, exfiltration and tunnels). A single family, or a single fact, gives "Needs review"; so do'
            u' disagreements between sources, the findings of a memory with anomalous output, and a coverage warni'
            u'ng without signals: logs or hives missing, damaged or too short, files that could not be read, parti'
            u'al checks, logs that stop before the rest, checks interrupted by an error. "No indicators found" doe'
            u's not mean that the machine is clean.</p>',
        u'<p><b>Limiti.</b> Un\'immagine del disco non contiene i dati volatili (controlli 2-7). ShimCache e A'
        u'mCache provano che un file esisteva, non che \u00e8 stato eseguito: uno strumento trovato solo per n'
        u'ome resta da confermare. Le sottoscrizioni WMI vengono cercate anche tra gli oggetti cancellati del '
        u'repository. Le copie shadow non vengono aperte. I limiti noti del rilevamento sono nel README.</p>':
            u'<p><b>Limits.</b> A disk image does not contain volatile data (checks 2-7). ShimCache and AmCache pr'
            u'ove that a file existed, not that it was run: a tool found only by name stays to be confirmed. WMI s'
            u'ubscriptions are also searched among the deleted objects of the repository. Shadow copies are not op'
            u'ened. The known detection gaps are in the README.</p>',
        u'<p><b>RAM.</b> La RAM fotografa un istante: un processo gi\u00e0 terminato si vede solo se la sua me'
        u'moria non \u00e8 ancora stata riusata (psscan), e per i processi la cui memoria era nel file di pagi'
        u'ng mancano la riga di comando e l\'utente. Un processo \u00abforse nascosto\u00bb \u00e8 una discord'
        u'anza fra due fonti: a volte la scansione trova i resti di un processo appena terminato. L\'output di'
        u' Volatility si controlla contro il manifesto (righe e SHA-256) e contro quello che un Windows acceso'
        u' ha sempre; quale RAM va con questa macchina lo indica l\'analista e il plugin lo controlla (vedi '
        u'\u00abRAM: abbinamento e controlli\u00bb).</p>':
            u'<p><b>Memory.</b> The memory captures one instant: a process that has already ended is seen only if '
            u'its memory has not been reused yet (psscan), and for processes whose memory was in the paging file t'
            u'he command line and the user are missing. A "possibly hidden" process is a disagreement between two '
            u'sources: sometimes the scan finds the remains of a process that has just ended. The Volatility outpu'
            u't is checked against the manifest (rows and SHA-256) and against what a running Windows always has; '
            u'the analyst designates which memory goes with this machine and the module checks it (see "Memory: pa'
            u'iring and checks").</p>',
        u'Conta':
            u'Counts',
        u'RAM con output anomalo':
            u'memory with anomalous output',
        u'Secondo i registri eventi la cancellazione \u00e8 avvenuta durante la preparazione della macchina (n'
        u'ome %s, poi sostituito): se fa parte della preparazione dell\'immagine, chi l\'ha preparata lo pu'
        u'\u00f2 confermare.':
            u'According to the event logs the clearing happened while the machine was being prepared (name %s, rep'
            u'laced later): if it is part of the preparation of the image, whoever prepared it can confirm it.',
        u'non disponibile nel Volatility usato (il plugin manca o non si carica)':
            u'not available in the Volatility used (the plugin is missing or cannot be loaded)',
        u'RAM %s: raccolta con Volatility %s, pi\u00f9 vecchio della versione provata (%s): alcuni plugin poss'
        u'ono dare meno dati.':
            u'RAM %s: collected with Volatility %s, older than the version tested (%s): some plugins may give less'
            u' data.',
        u'Fatto n.':
            u'Fact no.',
        u'nessuna riga di comando leggibile in cmdline (processi: %d)':
            u'no readable command line in cmdline (processes: %d)',
        u'Fatti decisivi: %d (segnali: %d) - fatti da confermare: %d (segnali: %d)':
            u'Decisive facts: %d (signals: %d) - facts to confirm: %d (signals: %d)',
        u'Accesso riuscito da un indirizzo pubblico: %s come %s (%s, %s)':
            u'Successful logon from a public address: %s as %s (%s, %s)',
        u'Nome predefinito di una distribuzione usata per gli attacchi. %s, primo: %s - ultimo: %s (UTC).':
            u'Default name of a distribution used for attacks. %s, first: %s - last: %s (UTC).',
        u'Evento 4648, %s. Primo: %s - ultimo: %s (UTC).':
            u'Event 4648, %s. First: %s - last: %s (UTC).',
        u'%s%s\nPrimo: %s (UTC) - %s':
            u'%s%s\nFirst: %s (UTC) - %s',
        u'%d fatto decisivo':
            u'%d decisive fact',
        u'%d fatti decisivi':
            u'%d decisive facts',
        u'%d segnale':
            u'%d signal',
        u'%d segnali':
            u'%d signals',
        u'%d fatto da confermare':
            u'%d fact to confirm',
        u'%d fatti da confermare':
            u'%d facts to confirm',
        u'1 volta':
            u'1 time',
        u'%d volte':
            u'%d times',
        u'%d segnale da una RAM anomala o da fonti discordanti':
            u'%d signal from an anomalous memory or from sources that disagree',
        u'%d segnale da una RAM contraddetta, escluso':
            u'%d signal from a contradicted memory, excluded',
        u'%s: decisivi %d, da confermare %d, di contesto %d.':
            u'%s: decisive %d, to confirm %d, context %d.',
        u'%d minuto':
            u'%d minute',
        u'%d ora':
            u'%d hour',
        u' %d segnale viene da una RAM che il disco contraddice: resta nel report ma non conta.':
            u' %d signal comes from a memory that the disk contradicts: it stays in the report but does not count.',
        u'Sessione RDP da un indirizzo pubblico: %s come %s (%s)':
            u'RDP session from a public address: %s as %s (%s)',
        u'Da %s come %s: %s (%s)':
            u'From %s as %s: %s (%s)',
        u'%d evento':
            u'%d event',
        u'%d eventi':
            u'%d events',
    }


TESTI = {}
for _parte in (_modulo,
               _controlli_1,
               _controlli_2,
               _report_1,
               _report_2,
               _regole_1,
               _regole_2,
               _controlli_registro_1,
               _controlli_registro_2,
               _controlli_registro_3,
               _controlli_eventi_1,
               _controlli_eventi_2,
               _controlli_eventi_3,
               _controlli_file_1,
               _controlli_file_2,
               _controlli_file_3,
               _eventi,
               _artefatti,
               _origine,
               _evtx,
               _prefetch,
               _registro,
               _base,
               _memoria_1,
               _memoria_2,
               _versione_13):
    TESTI.update(_parte())
del _parte
