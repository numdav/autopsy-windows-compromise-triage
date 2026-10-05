# -*- coding: utf-8 -*-
"""
tc_report - Report HTML e CSV del plugin "Triage compromissione".

Il report e' un unico file HTML senza dipendenze esterne: si apre con
qualunque browser e si puo' stampare o allegare.
"""

import time

import tc_controlli
import tc_regole as R
from tc_base import testo_orario as T, pulito, ERRORI

_CSS = u'''
*{box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;font-size:14px;line-height:1.45;
color:#1c2430;background:#f3f5f8;margin:0}
.pagina{max-width:1280px;margin:0 auto;padding:24px 28px 60px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid #d5dbe5}
h3{font-size:15px;margin:20px 0 6px}
p{margin:6px 0}
.sotto{color:#5b6676;font-size:13px}
.verdetto{border-radius:10px;padding:18px 22px;margin:18px 0;color:#fff}
.verdetto .titolo{font-size:26px;font-weight:700;letter-spacing:.3px}
.verdetto .motivo{font-size:15px;margin-top:4px}
.v-rosso{background:#b42318}.v-giallo{background:#b25e09}.v-verde{background:#1f7a45}
.schede{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}
.scheda{background:#fff;border:1px solid #d5dbe5;border-radius:8px;padding:10px 16px;min-width:150px}
.scheda .numero{font-size:26px;font-weight:700}
.scheda .nome{color:#5b6676;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.n-rosso{color:#b42318}.n-giallo{color:#b25e09}.n-grigio{color:#5b6676}
table{border-collapse:collapse;width:100%;background:#fff;margin:6px 0 4px;font-size:13px}
th,td{border:1px solid #d5dbe5;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#e9edf3;font-weight:600;white-space:nowrap}
td{overflow-wrap:anywhere}
tr:nth-child(even) td{background:#fafbfc}
td.ora{white-space:nowrap;font-variant-numeric:tabular-nums}
.contesto td:first-child{width:260px;color:#5b6676}
.etichetta{display:inline-block;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}
.e-decisivo{background:#fde7e4;color:#8f1c13}.e-conferma{background:#fdecd2;color:#8a4706}
.e-info{background:#e6ebf2;color:#44505f}.e-ok{background:#dff3e6;color:#17603a}.e-na{background:#eef0f3;color:#6a7482}
.extra{font-size:11px;color:#6a7482;border:1px solid #c5ccd8;border-radius:8px;padding:0 6px;margin-left:6px;white-space:nowrap}
details{margin:2px 0}
summary{cursor:pointer;color:#2a5db0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;border:1px solid #d5dbe5;border-radius:6px;
padding:8px;margin:6px 0;font-family:Consolas,"Cascadia Mono",monospace;font-size:12px}
.file{color:#5b6676;font-size:12px}
.avviso{background:#fff7e0;border:1px solid #e7c873;border-radius:8px;padding:10px 14px;margin:8px 0}
.errore{background:#fde7e4;border:1px solid #e3a199;border-radius:8px;padding:10px 14px;margin:8px 0}
.osservazione{background:#eef3fb;border:1px solid #b9c8e3;border-radius:8px;padding:10px 14px;margin:8px 0}
.nota{color:#5b6676;font-size:12.5px;margin:2px 0 14px}
.indice a{margin-right:14px;color:#2a5db0;text-decoration:none;white-space:nowrap}
.fase{background:#fff;border:1px solid #d5dbe5;border-radius:8px;padding:4px 16px 12px;margin:12px 0}
@media print{body{background:#fff}.pagina{padding:0}details{display:block}summary{display:none}}
'''


def _e(testo):
    """Testo sicuro per l'HTML."""
    testo = pulito(testo)       # i testi vengono dalla macchina analizzata: via i caratteri di controllo
    return (testo.replace(u'&', u'&amp;').replace(u'<', u'&lt;').replace(u'>', u'&gt;')
            .replace(u'"', u'&quot;').replace(u"'", u'&#39;'))


def _classe_peso(peso):
    return {R.DECISIVO: u'e-decisivo', R.DA_CONFERMARE: u'e-conferma', R.INFORMATIVO: u'e-info'}.get(peso, u'e-na')


def _etichetta(testo, classe):
    return u'<span class="etichetta %s">%s</span>' % (classe, _e(testo))


def _tabella(colonne, righe, classe=u''):
    parti = [u'<table%s><thead><tr>' % (u' class="%s"' % classe if classe else u'')]
    for c in colonne:
        parti.append(u'<th>%s</th>' % _e(c))
    parti.append(u'</tr></thead><tbody>')
    for riga in righe:
        parti.append(u'<tr>')
        for cella in riga:
            if isinstance(cella, tuple):          # (html gia' pronto,)
                parti.append(u'<td>%s</td>' % cella[0])
            else:
                testo = _e(cella)
                if u'\n' in testo:
                    testo = testo.replace(u'\n', u'<br>')
                parti.append(u'<td>%s</td>' % testo)
        parti.append(u'</tr>')
    parti.append(u'</tbody></table>')
    return u''.join(parti)


def _riga_segnale(t, s):
    titolo = u'%d. %s' % (s.controllo, tc_controlli.TITOLO_CONTROLLO.get(s.controllo, u''))
    descrizione = _e(s.descrizione)
    if s.extra:
        descrizione += u'<span class="extra" title="Regola che non viene dalle 32 guide">regola in pi\u00f9</span>'
    if s.dettagli:
        descrizione += u'<details><summary>dettagli</summary><pre>%s</pre></details>' % _e(s.dettagli)
    if s.elemento is not None:
        try:
            descrizione += u'<div class="file">%s</div>' % _e(s.elemento.percorso)
        except ERRORI:
            pass
    return [(_etichetta(R.NOME_PESO[s.peso], _classe_peso(s.peso)),), (u'<span class="ora">%s</span>' % (_e(T(s.ora)) or u'&ndash;'),),
            titolo, s.famiglia, (descrizione,)]


def _contesto(t, info):
    c = t.contesto
    righe = []

    def aggiungi(nome, valore):
        if valore not in (None, u'', 0):
            righe.append([nome, valore])

    aggiungi(u'Computer', c.get('computer'))
    sistema = u' '.join([x for x in (c.get('prodotto'), c.get('versione')) if x])
    if c.get('build'):
        sistema += u' (build %s)' % c.get('build')
    aggiungi(u'Sistema operativo', sistema.strip())
    if c.get('controller_di_dominio'):
        aggiungi(u'Ruolo', u'controller di dominio')
    elif c.get('server'):
        aggiungi(u'Ruolo', u'server')
    elif 'server' in c:
        aggiungi(u'Ruolo', u'client')
    aggiungi(u'Dominio', c.get('dominio'))
    aggiungi(u'Installato il', T(c.get('installato', 0)) and T(c.get('installato', 0)) + u' UTC')
    fuso = c.get('fuso') or u''
    if 'scarto_minuti' in c:
        m = c['scarto_minuti']
        fuso += u' (UTC%s%02d:%02d al momento dell\'acquisizione)' % (u'+' if m >= 0 else u'-', abs(m) // 60, abs(m) % 60)
    aggiungi(u'Fuso orario della macchina', fuso)
    aggiungi(u'Ultimo spegnimento registrato', T(c.get('spegnimento', 0)) and T(c.get('spegnimento', 0)) + u' UTC')
    ultima = t.ultima_attivita()
    aggiungi(u'Ultima attivit\u00e0 trovata', T(ultima) and T(ultima) + u' UTC')
    if t.riferimento:
        aggiungi(u'Finestra dei controlli \u00abrecenti\u00bb',
                 u'dai %d giorni prima del %s UTC in poi' % (t.opzioni.giorni_recenti, T(t.riferimento)))
    if 'rdp_attivo' in c:
        aggiungi(u'Desktop remoto', u'attivo' if c['rdp_attivo'] else u'non attivo')
    aggiungi(u'Origine dati', info.get('origine'))
    aggiungi(u'Cartella di Windows nell\'origine', t.radice.descrizione())
    aggiungi(u'Caso', info.get('caso'))
    artefatti = []
    for nome, chiave in ((u'Prefetch', 'prefetch'), (u'ShimCache', 'shimcache'), (u'AmCache', 'amcache')):
        if c.get(chiave):
            artefatti.append(u'%s: %s' % (nome, c.get(chiave)))
    if c.get('registri_letti'):
        artefatti.append(u'registri eventi letti: %d' % c['registri_letti'])
    if c.get('numero_servizi'):
        artefatti.append(u'servizi: %d' % c['numero_servizi'])
    if t.attivita:
        artefatti.append(u'attivit\u00e0 pianificate: %d' % len(t.attivita))
    aggiungi(u'Artefatti letti', u'; '.join(artefatti))
    if t.opzioni.rmm_autorizzati:
        aggiungi(u'RMM indicati come autorizzati', u', '.join(t.opzioni.rmm_autorizzati))
    return _tabella([u'Voce', u'Valore'], righe, u'contesto')


def html(t, info=None):
    """Il report completo di un triage, come testo HTML."""
    info = info or {}
    decisivi = [s for s in t.segnali if s.peso == R.DECISIVO]
    conferme = [s for s in t.segnali if s.peso == R.DA_CONFERMARE]
    informativi = [s for s in t.segnali if s.peso == R.INFORMATIVO]
    classe = {tc_controlli.V_COMPROMESSA: u'v-rosso', tc_controlli.V_DA_VERIFICARE: u'v-giallo'}.get(t.verdetto, u'v-verde')
    computer = t.contesto.get('computer') or info.get('origine') or u''
    o = []
    o.append(u'<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">')
    o.append(u'<meta name="viewport" content="width=device-width, initial-scale=1">')
    o.append(u'<title>Triage compromissione - %s</title><style>%s</style></head><body><div class="pagina">' % (_e(computer), _CSS))
    o.append(u'<h1>Triage compromissione: %s</h1>' % _e(computer or u'origine senza nome'))
    o.append(u'<div class="sotto">Report generato il %s UTC dal plugin Triage compromissione %s per Autopsy. Tutti gli orari sono in UTC.</div>'
             % (_e(T(info.get('generato') or time.time())), _e(tc_controlli.VERSIONE)))
    o.append(u'<div class="verdetto %s"><div class="titolo">%s</div><div class="motivo">%s</div></div>'
             % (classe, _e(t.verdetto), _e(t.motivo_verdetto)))
    o.append(u'<div class="schede">')
    for numero, nome, colore in ((len(decisivi), u'Segnali decisivi', u'n-rosso'), (len(conferme), u'Da confermare', u'n-giallo'),
                                 (len(informativi), u'Solo contesto', u'n-grigio')):
        o.append(u'<div class="scheda"><div class="numero %s">%d</div><div class="nome">%s</div></div>' % (colore, numero, _e(nome)))
    famiglie = []
    for s in decisivi + conferme:
        if s.famiglia not in famiglie:
            famiglie.append(s.famiglia)
    o.append(u'<div class="scheda"><div class="numero">%d</div><div class="nome">Famiglie di segnali</div></div>' % len(famiglie))
    o.append(u'</div>')
    for a in t.avvisi:
        o.append(u'<div class="avviso"><b>Copertura:</b> %s</div>' % _e(a))
    for a in t.note:
        o.append(u'<div class="osservazione"><b>Nota:</b> %s</div>' % _e(a))
    for e in t.errori:
        o.append(u'<div class="errore"><b>Un controllo non \u00e8 riuscito:</b><pre>%s</pre></div>' % _e(e))
    o.append(u'<p class="indice"><a href="#segnali">Segnali</a><a href="#cronologia">Cronologia</a>'
             u'<a href="#controlli">I 41 controlli</a>')
    for numero, nome in tc_controlli.FASI:
        o.append(u'<a href="#fase%d">Fase %d</a>' % (numero, numero))
    o.append(u'<a href="#metodo">Come leggere il report</a></p>')

    o.append(u'<h2>Sistema</h2>')
    o.append(_contesto(t, info))

    # ---- segnali
    o.append(u'<h2 id="segnali">Segnali</h2>')
    colonne = [u'Peso', u'Quando (UTC)', u'Controllo', u'Famiglia', u'Segnale']
    if decisivi:
        o.append(u'<h3>Decisivi (%d)</h3>' % len(decisivi))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(decisivi, key=lambda s: (s.controllo, s.ora))]))
    if conferme:
        o.append(u'<h3>Da confermare (%d)</h3>' % len(conferme))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(conferme, key=lambda s: (s.controllo, s.ora))]))
    if not decisivi and not conferme:
        o.append(u'<p>Nessun segnale decisivo o da confermare.</p>')
    if informativi:
        o.append(u'<details><summary>Solo contesto (%d): voci che non pesano sul verdetto</summary>' % len(informativi))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(informativi, key=lambda s: (s.controllo, s.ora))]))
        o.append(u'</details>')
    tagliati = [(n, q) for n, q in sorted(t._per_controllo.items()) if q > len([s for s in t.segnali if s.controllo == n])]
    if tagliati:
        o.append(u'<p class="nota">Per non allungare il report, alcuni controlli mostrano solo i primi segnali: %s.</p>'
                 % _e(u'; '.join([u'controllo %d, %d in tutto' % (n, q) for n, q in tagliati])))

    # ---- cronologia
    cronologia = t.cronologia()
    o.append(u'<h2 id="cronologia">Cronologia dei segnali</h2>')
    if cronologia:
        righe = []
        for s in cronologia:
            righe.append([(u'<span class="ora">%s</span>' % _e(T(s.ora)),), (_etichetta(R.NOME_PESO[s.peso], _classe_peso(s.peso)),),
                          unicode(s.controllo), s.descrizione])
        o.append(_tabella([u'Quando (UTC)', u'Peso', u'Controllo', u'Segnale'], righe))
        o.append(u'<p class="nota">Solo i segnali decisivi e da confermare che hanno un orario. '
                 u'Per le chiavi del registro l\'orario \u00e8 l\'ultima scrittura della chiave.</p>')
    else:
        o.append(u'<p>Nessun segnale con un orario.</p>')

    # ---- i 41 controlli
    o.append(u'<h2 id="controlli">I 41 controlli della checklist</h2>')
    righe = []
    for numero, fase, titolo in tc_controlli.CONTROLLI:
        etichetta, peso, quanti, nota = t.stato_controllo(numero)
        if peso > 0:
            classe_e = _classe_peso(peso)
            testo = u'%s (%d)' % (etichetta, quanti)
        elif peso == 0 and etichetta == u'Nulla da segnalare':
            classe_e = u'e-ok'
            testo = etichetta
        else:
            classe_e = u'e-na'
            testo = etichetta
        righe.append([unicode(numero), u'Fase %d' % fase, titolo, (_etichetta(testo, classe_e),), nota])
    o.append(_tabella([u'N.', u'Fase', u'Controllo', u'Esito', u'Nota'], righe))

    # ---- fasi con le tabelle di contesto
    for numero, nome in tc_controlli.FASI:
        o.append(u'<h2 id="fase%d">Fase %d \u2014 %s</h2>' % (numero, numero, _e(nome)))
        mie = [x for x in t.tabelle if tc_controlli.FASE_CONTROLLO.get(x.controllo) == numero]
        if numero == 1:
            o.append(u'<p>I controlli da 2 a 7 riguardano dati volatili (sessioni, processi, connessioni, cache DNS): '
                     u'su un\'immagine del disco non ci sono. Servono il triage dal vivo o un dump della RAM.</p>')
        if not mie:
            if numero != 1:
                o.append(u'<p class="nota">Nessuna tabella per questa fase.</p>')
            continue
        mie.sort(key=lambda x: x.controllo)
        for tab in mie:
            o.append(u'<div class="fase"><h3>%d. %s <span class="sotto">(%d righe)</span></h3>'
                     % (tab.controllo, _e(tab.titolo), len(tab.righe)))
            aperto = u' open' if len(tab.righe) <= 12 else u''
            o.append(u'<details%s><summary>mostra o nascondi</summary>' % aperto)
            o.append(_tabella(tab.colonne, tab.righe))
            o.append(u'</details>')
            if tab.nota:
                o.append(u'<div class="nota">%s</div>' % _e(tab.nota))
            o.append(u'</div>')

    # ---- metodo
    o.append(u'<h2 id="metodo">Come leggere il report</h2>')
    o.append(u'<p><b>Verdetto.</b> Un solo segnale <i>decisivo</i> basta per trattare la macchina come compromessa. '
             u'I segnali <i>da confermare</i> contano quando arrivano da almeno due famiglie diverse '
             u'(accessi, account, persistenza, programmi eseguiti, strumenti d\'attacco, strumenti a doppio uso, esecuzione remota, '
             u'RMM, file, anti-forensics, antivirus, esfiltrazione e tunnel). '
             u'Una sola famiglia d\u00e0 \u00abDa verificare\u00bb. Lo stesso vale quando non ci sono segnali ma c\'\u00e8 un avviso '
             u'di copertura: registri o hive assenti, danneggiati o troppo corti, file che non si sono lasciati leggere, '
             u'registri che si fermano prima del resto, controlli interrotti da un errore.</p>')
    o.append(u'<p><b>Recente.</b> Alcuni controlli pesano di pi\u00f9 ci\u00f2 che \u00e8 recente. La finestra si conta '
             u'all\'indietro da un riferimento: il pi\u00f9 vecchio tra l\'ultimo evento scritto nel registro Security e '
             u'l\'ultimo scritto nel System (o, se mancano, gli ultimi eventi degli altri registri e l\'ora di spegnimento). '
             u'Non \u00e8 l\'orario pi\u00f9 recente trovato: un solo orario sbagliato o alterato sposterebbe la finestra. '
             u'Tutto ci\u00f2 che viene dopo il riferimento \u00e8 recente.</p>')
    o.append(u'<p><b>Ogni segnale vale solo se l\'IT non lo spiega:</b> un amministratore o uno strumento di assistenza autorizzato '
             u'lasciano tracce simili. Il triage serve a decidere se approfondire, non sostituisce l\'analisi.</p>')
    o.append(u'<p><b>Regole in pi\u00f9.</b> I segnali con questa etichetta vengono da regole note che non fanno parte delle 32 guide '
             u'su cui \u00e8 costruita la checklist (per esempio: named pipe di Meterpreter, backdoor \u00absticky keys\u00bb, '
             u'esclusioni di Defender, cronologia di PowerShell).</p>')
    o.append(u'<p><b>Limiti.</b> Un\'immagine del disco non contiene i dati volatili (controlli 2-7). '
             u'ShimCache e AmCache provano che un file esisteva, non che \u00e8 stato eseguito. '
             u'Le sottoscrizioni WMI vengono cercate anche tra gli oggetti cancellati del repository. '
             u'Le copie shadow non vengono aperte.</p>')
    o.append(u'<p class="sotto">Analisi completata in %.1f secondi.</p>' % t.durata)
    o.append(u'</div></body></html>')
    return u'\n'.join(o)


def _csv(valore):
    valore = pulito(valore).replace(u'\n', u' | ').replace(u'\t', u' ')
    # Una riga di comando che inizia con = + - @ verrebbe letta da Excel come
    # formula: l'apostrofo davanti la fa restare testo.
    if valore[:1] in (u'=', u'+', u'-', u'@'):
        valore = u"'" + valore
    return u'"%s"' % valore.replace(u'"', u'""')


def csv(t):
    """I segnali in formato CSV (separatore punto e virgola, per Excel)."""
    righe = [u';'.join([_csv(x) for x in (u'Peso', u'Quando (UTC)', u'Controllo', u'Titolo del controllo', u'Famiglia',
                                         u'Segnale', u'Dettagli', u'File', u'Regola in pi\u00f9')])]
    for s in t.segnali_ordinati():
        percorso = u''
        if s.elemento is not None:
            try:
                percorso = s.elemento.percorso
            except ERRORI:
                pass
        righe.append(u';'.join([_csv(x) for x in (R.NOME_PESO[s.peso], T(s.ora), s.controllo, s.titolo(), s.famiglia,
                                                  s.descrizione, s.dettagli, percorso, u's\u00ec' if s.extra else u'')]))
    return u'\r\n'.join(righe) + u'\r\n'
