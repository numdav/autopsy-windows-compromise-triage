# Storia del progetto

*History of the project: the study and the checklist the module was built from, the live triage script, the
evaluation of version 1.2 and the verification of version 1.3. The documents are in Italian.*

Windows Compromise Triage è nato da uno studio e da una checklist, prima di diventare un modulo per Autopsy. Questa
cartella conserva quei documenti e le valutazioni che hanno guidato le versioni. La cronologia del repository mette
tutto nell'ordine in cui è stato fatto: ogni passo è un commit con la data del lavoro, e ogni versione del plugin ha
il suo tag e la sua [release](../../../releases).

| Data | Passo | Dove |
| --- | --- | --- |
| 30 settembre 2026 | Documento di studio: le 32 guide di Cyber Triage sugli artefatti Windows, rielaborate in italiano | [guide-forensi-artefatti-windows.md](2026-09-30-studio/guide-forensi-artefatti-windows.md) |
| 30 settembre 2026 | Checklist di triage: 41 controlli su una macchina Windows accesa, ricavati dallo studio | [checklist-triage.md](2026-09-30-studio/checklist-triage.md) |
| 5 ottobre 2026 | Versione 1.0: la checklist applicata da un modulo di Autopsy a un'immagine del disco, solo in italiano | tag [`v1.0`](../../../tree/v1.0) |
| 6 ottobre 2026 | Versione 1.1: risultati in inglese e in italiano, README, licenza, prove automatiche | tag [`v1.1`](../../../tree/v1.1) |
| 10 ottobre 2026 | Checklist corretta nei controlli 9 (log cancellati) e 16 (attività nascoste) | la cronologia di [checklist-triage.md](../../../commits/main/history/2026-09-30-studio/checklist-triage.md) |
| 10 ottobre 2026 | Triage dal vivo: la checklist come script PowerShell, con lo stesso verdetto del plugin | [Triage-Live.ps1](2026-10-10-triage-dal-vivo/Triage-Live.ps1) |
| 11 ottobre 2026 | Versione 1.2: la memoria RAM, analizzata con Volatility 3 | tag [`v1.2`](../../../tree/v1.2) |
| 11-13 ottobre 2026 | Valutazione della 1.2 su dati con etichette scritte da altri, con l'elenco delle correzioni | [valutazione-1.2.md](2026-10-11-valutazione-1.2/valutazione-1.2.md) |
| 13 ottobre 2026 | Versione 1.3: le correzioni della valutazione | tag [`v1.3`](../../../tree/v1.3) |
| 13 ottobre 2026 | Verifica della 1.3: sintesi, piano con l'esito di ogni voce, registro delle prove | [verifica-1.3.md](2026-10-13-verifica-1.3/verifica-1.3.md), [piano-1.3.md](2026-10-13-verifica-1.3/piano-1.3.md), [registro-prove-1.3.csv](2026-10-13-verifica-1.3/registro-prove-1.3.csv) |

## Come leggerla

- **I passi uno dopo l'altro**: la pagina dei [commit](../../../commits/main) li mostra dal più recente; ogni commit
  dice che cosa aggiunge e perché.
- **Il progetto com'era a una versione**: i tag `v1.0`-`v1.3` (link nella tabella) aprono il repository a quel punto.
- **Che cosa è cambiato fra due versioni**: per esempio [dalla 1.2 alla 1.3](../../../compare/v1.2...v1.3); il
  `CHANGELOG.md` lo dice in breve.
- **Il plugin da provare**: lo zip di ogni versione è nella sua release, con lo SHA-256 nelle note.

## Note

- Le date dei commit sono quelle in cui ogni lavoro è stato chiuso. Fanno eccezione le correzioni della checklist:
  sono state fatte fra la prima stesura e il 10 ottobre, ma l'ora esatta non è registrata, e il commit porta quella
  in cui la checklist corretta è servita a scrivere lo script dal vivo.
- I documenti sono stati scritti come documenti condivisi ed esportati in Markdown. Due figure sono diventate testo:
  la decisione della checklist è un diagramma Mermaid e il grafico per tattica della valutazione è una tabella.
- Lo script dal vivo è stato provato nella sintassi e nella logica del verdetto con PowerShell 7 su Linux, mai su un
  Windows reale. Dopo il 10 ottobre non è stato aggiornato: il suo verdetto usa la regola e le etichette di allora
  («compromissione probabile»).
- I kit delle prove (script dei banchi, risultati caso per caso, output di Volatility delle immagini pubbliche) non
  sono pubblicati: contengono copie di dati di terzi e i percorsi della macchina su cui sono stati usati. I numeri
  sono nei documenti e nel registro delle prove.
- Il progetto è stato sviluppato da Davide Numelli che si è avvalso di assistenza IA per scrivere
  parte del codice e dei documenti, sotto la sua direzione e revisione.
