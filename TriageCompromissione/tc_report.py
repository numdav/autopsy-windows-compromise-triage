# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_report - Report HTML e CSV del plugin "Triage compromissione".

Il report e' un unico file HTML senza dipendenze esterne: si apre con
qualunque browser e si puo' stampare o allegare.
"""

import re
import time

import tc_controlli
import tc_memoria
import tc_regole as R
from tc_base import testo_orario as T, pulito, ERRORI
from tc_lingua import tr, N_, lingua, quanti, ITALIANO

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
.v-rosso{background:#b42318}.v-arancio{background:#c2410c}.v-giallo{background:#a16207}.v-neutro{background:#3d5a73}
.avvertenza{border-left:4px solid #3d5a73;background:#fff;padding:8px 14px;margin:14px 0 0;font-size:14px}
.conteggi{font-size:13.5px;margin-top:8px;opacity:.95}
.schede{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}
.scheda{background:#fff;border:1px solid #d5dbe5;border-radius:8px;padding:10px 16px;min-width:150px}
.scheda .numero{font-size:26px;font-weight:700}
.scheda .nome{color:#5b6676;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.n-rosso{color:#b42318}.n-giallo{color:#b25e09}.n-grigio{color:#5b6676}
table{border-collapse:collapse;width:100%;background:#fff;margin:6px 0 4px;font-size:13px}
th,td{border:1px solid #d5dbe5;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#e9edf3;font-weight:600;white-space:nowrap}
td{overflow-wrap:anywhere}
td.parole{overflow-wrap:normal}
tr:nth-child(even) td{background:#fafbfc}
td.ora{white-space:nowrap;font-variant-numeric:tabular-nums}
.contesto td:first-child{width:260px;color:#5b6676}
.etichetta{display:inline-block;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}
.e-decisivo{background:#fde7e4;color:#8f1c13}.e-conferma{background:#fdecd2;color:#8a4706}
.e-info{background:#e6ebf2;color:#44505f}.e-ok{background:#dff3e6;color:#17603a}.e-na{background:#eef0f3;color:#6a7482}
.e-parziale{background:#fff1c7;color:#7a5200}.e-escluso{background:#eef0f3;color:#6a7482;text-decoration:line-through}
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


# Una cella fatta di poche parole corte (un peso, un nome, una data). Le celle
# vanno a capo anche a meta' parola, perche' un percorso o una riga di comando
# non allarghino la tabella; queste no, altrimenti in una colonna stretta si
# leggerebbe "Decisiv" e, sotto, "o".
_RX_PAROLE_CORTE = re.compile(u'^[^\\s\\\\/]{1,16}(?:\\s[^\\s\\\\/]{1,16}){0,5}$')


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
                if _RX_PAROLE_CORTE.match(pulito(cella)):
                    parti.append(u'<td class="parole">%s</td>' % testo)
                else:
                    parti.append(u'<td>%s</td>' % testo)
        parti.append(u'</tr>')
    parti.append(u'</tbody></table>')
    return u''.join(parti)


def origine(s):
    """Da dove viene un segnale: il disco, oppure la RAM con lo SHA-256 dell'immagine."""
    if s.ram is None:
        return tr(u'disco')
    sha = s.ram.get('sha256') or u''
    return u'RAM %s%s' % (s.ram.get('immagine') or u'', (u' (SHA-256 %s\u2026)' % sha[:16]) if sha else u'')


def _riga_segnale(t, s):
    titolo = u'%d. %s' % (s.controllo, s.titolo())
    descrizione = _e(s.descrizione)
    stati = []
    if s.fenomeno:
        stati.append(tr(u'fatto %d') % s.fenomeno)
    stati.append(origine(s))
    if not s.conta:
        stati.append(tr(u'RAM contraddetta dal disco: non conta'))
    elif s.limitato:
        stati.append(tr(u'RAM con output anomalo: non oltre \u00abda verificare\u00bb'))
    if s.discordante:
        stati.append(tr(u'discordanza fra fonti'))
    descrizione += u'<div class="file">%s</div>' % _e(u' \u00b7 '.join(stati))
    if s.extra:
        descrizione += u'<span class="extra" title="%s">%s</span>' % (_e(tr(u'Regola che non viene dalle 32 guide')),
                                                                       _e(tr(u'regola in pi\u00f9')))
    if s.dettagli:
        descrizione += tr(u'<details><summary>dettagli</summary><pre>%s</pre></details>') % _e(s.dettagli)
    if s.elemento is not None:
        try:
            descrizione += u'<div class="file">%s</div>' % _e(s.elemento.percorso)
        except ERRORI:
            pass
    return [(_etichetta(tr(R.NOME_PESO[s.peso]), _classe_peso(s.peso)),), (u'<span class="ora">%s</span>' % (_e(T(s.ora)) or u'&ndash;'),),
            titolo, tr(s.famiglia), (descrizione,)]


def _contesto(t, info):
    c = t.contesto
    righe = []

    def aggiungi(nome, valore):
        if valore not in (None, u'', 0):
            righe.append([nome, valore])

    nome = c.get('computer') or u''
    if nome and c.get('computer_fonte') == u'eventi':
        nome += tr(u' (dai registri eventi)')
    if c.get('computer_ram') and not c.get('computer'):
        nome = tr(u'%s (solo nella RAM: non \u00e8 il nome dell\'installazione)') % c['computer_ram']
    aggiungi(u'Computer', nome)
    sistema = u' '.join([x for x in (c.get('prodotto'), c.get('versione')) if x])
    if c.get('build'):
        sistema += u' (build %s)' % c.get('build')
    aggiungi(tr(u'Sistema operativo'), sistema.strip())
    if c.get('controller_di_dominio'):
        aggiungi(tr(u'Ruolo'), tr(u'controller di dominio'))
    elif c.get('server'):
        aggiungi(tr(u'Ruolo'), u'server')
    elif 'server' in c:
        aggiungi(tr(u'Ruolo'), u'client')
    aggiungi(tr(u'Dominio'), c.get('dominio'))
    aggiungi(tr(u'Installato il'), T(c.get('installato', 0)) and T(c.get('installato', 0)) + u' UTC')
    if c.get('preparazione'):
        aggiungi(tr(u'Installazione secondo i registri eventi'),
                 tr(u'preparazione dal %s UTC, nome definitivo dal %s UTC') % (T(c['preparazione'][0]), T(c['preparazione'][1])))
    fuso = c.get('fuso') or u''
    if 'scarto_minuti' in c:
        m = c['scarto_minuti']
        fuso += tr(u' (UTC%s%02d:%02d al momento dell\'acquisizione)') % (u'+' if m >= 0 else u'-', abs(m) // 60, abs(m) % 60)
    aggiungi(tr(u'Fuso orario della macchina'), fuso)
    aggiungi(tr(u'Ultimo spegnimento registrato'), T(c.get('spegnimento', 0)) and T(c.get('spegnimento', 0)) + u' UTC')
    ultima = t.ultima_attivita()
    aggiungi(tr(u'Ultima attivit\u00e0 trovata'), T(ultima) and T(ultima) + u' UTC')
    if t.riferimento:
        aggiungi(tr(u'Finestra dei controlli \u00abrecenti\u00bb'),
                 tr(u'dai %d giorni prima del %s UTC in poi') % (t.opzioni.giorni_recenti, T(t.riferimento)))
    if 'rdp_attivo' in c:
        aggiungi(tr(u'Desktop remoto'), tr(u'attivo') if c['rdp_attivo'] else tr(u'non attivo'))
    aggiungi(tr(u'Origine dati'), info.get('origine'))
    aggiungi(tr(u'Cartella di Windows nell\'origine'), t.radice.descrizione())
    aggiungi(tr(u'Caso'), info.get('caso'))
    artefatti = []
    for nome, chiave in ((u'Prefetch', 'prefetch'), (u'ShimCache', 'shimcache'), (u'AmCache', 'amcache')):
        if c.get(chiave):
            artefatti.append(u'%s: %s' % (nome, c.get(chiave)))
    if c.get('registri_letti'):
        artefatti.append(tr(u'registri eventi letti: %d') % c['registri_letti'])
    if c.get('numero_servizi'):
        artefatti.append(tr(u'servizi: %d') % c['numero_servizi'])
    if t.attivita:
        artefatti.append(tr(u'attivit\u00e0 pianificate: %d') % len(t.attivita))
    aggiungi(tr(u'Artefatti letti'), u'; '.join(artefatti))
    for memoria in c.get('memorie') or []:
        aggiungi(tr(u'RAM (Volatility)'), tc_memoria.descrizione(memoria))
    if t.opzioni.rmm_autorizzati:
        aggiungi(tr(u'RMM indicati come autorizzati'), u', '.join(t.opzioni.rmm_autorizzati))
    return _tabella([tr(u'Voce'), tr(u'Valore')], righe, u'contesto')


def _conteggi(t):
    """I numeri sotto il verdetto: fatti e segnali, per origine, e l'esito
    dell'abbinamento di ogni RAM."""
    c = t.conteggi or {}
    parti = [tc_controlli.testo_conteggi(c)]
    if c.get('incerti'):
        parti.append(quanti(c['incerti'], N_(u'%d segnale da una RAM anomala o da fonti discordanti'),
                            N_(u'%d segnali da una RAM anomala o da fonti discordanti')))
    if c.get('esclusi'):
        parti.append(quanti(c['esclusi'], N_(u'%d segnale da una RAM contraddetta, escluso'),
                            N_(u'%d segnali da una RAM contraddetta, esclusi')))
    righe = [u'; '.join(parti) + u'.']
    for nome, decisivi, conferme, informativi in c.get('per_origine') or []:
        righe.append(tr(u'%s: decisivi %d, da confermare %d, di contesto %d.') % (nome, decisivi, conferme, informativi))
    for m in t.contesto.get('memorie') or []:
        righe.append(tr(u'Abbinamento della RAM %s: %s.') % (m.get('immagine') or u'', _esito_abbinamento(m)))
    return u'<br>'.join([_e(x) for x in righe])


def _esito_abbinamento(m):
    controlli = m.get('controlli') or []
    contrari = [tr(x[0]) for x in controlli if x[1] == tc_memoria.CONTRADDICE]
    concordi = [tr(x[0]) for x in controlli if x[1] == tc_memoria.CONCORDA]
    if not m.get('conta', True):
        testo = tr(u'contraddetto (%s): i suoi indizi non contano') % u', '.join(contrari)
    elif contrari:
        testo = tr(u'da verificare (%s)') % u', '.join(contrari)
    elif concordi:
        testo = tr(u'concorda (%s)') % u', '.join(concordi)
    else:
        testo = tr(u'non verificabile con gli artefatti del disco')
    if m.get('limitata'):
        testo += tr(u'; output anomalo, i suoi indizi non portano oltre \u00abda verificare\u00bb')
    return testo


def _sezione_ram(t):
    """Quale RAM e' stata usata, chi l'ha indicata e l'esito di ogni controllo."""
    o = []
    for m in t.contesto.get('memorie') or []:
        o.append(u'<h3>%s</h3>' % _e(m.get('immagine') or u''))
        righe = [[tr(u'SHA-256 dell\'immagine'), m.get('sha256') or tr(u'non indicato')],
                 [tr(u'Indicata'), m.get('chi') or u''], [tr(u'Cartella'), m.get('cartella') or u''],
                 [tr(u'Esito dell\'abbinamento'), _esito_abbinamento(m)]]
        if m.get('anomalie'):
            righe.append([tr(u'Output anomalo'), u'; '.join(m['anomalie'])])
        o.append(_tabella([tr(u'Voce'), tr(u'Valore')], righe, u'contesto'))
        controlli = [[tr(nome), (_etichetta(tr(esito), {tc_memoria.CONCORDA: u'e-ok', tc_memoria.CONTRADDICE: u'e-decisivo'}
                                            .get(esito, u'e-na')),), dettaglio,
                      tr(u's\u00ec') if identita else tr(u'no')]
                     for nome, esito, dettaglio, identita in m.get('controlli') or []]
        if controlli:
            o.append(_tabella([tr(u'Controllo'), tr(u'Esito'), tr(u'Dettaglio'), tr(u'Identit\u00e0')], controlli))
    if o:
        o.append(tr(u'<p class="nota">L\'abbinamento lo indica l\'analista (stessa origine dati con una sola installazione, '
                    u'stesso host di Autopsy o scelta nelle impostazioni dell\'ingest); il plugin lo controlla con gli '
                    u'artefatti del disco. Se un controllo d\'identit\u00e0 (build, avvio, SID) lo contraddice, gli indizi '
                    u'della RAM restano qui, segnati, ma non contano per il verdetto; il nome e l\'ora danno solo un '
                    u'avviso.</p>'))
    return o


def _fatti(t):
    """Una riga per ogni fatto con segnali decisivi o da confermare: dove e'
    stato visto e quanti segnali lo ripetono."""
    righe = []
    for g in t.fenomeni_elenco:
        peso = max([s.peso for s in g])
        if peso < R.DA_CONFERMARE:
            continue
        famiglie = []
        fonti = []
        for s in g:
            if tr(s.famiglia) not in famiglie:
                famiglie.append(tr(s.famiglia))
            f = s.fonte() or u'?'
            if f not in fonti:
                fonti.append(f)
        stato = u''
        if not [s for s in g if s.conta]:
            stato = tr(u'escluso')
        elif [s for s in g if s.discordante or s.limitato] and not [s for s in g if not (s.discordante or s.limitato)]:
            stato = tr(u'incerto')
        righe.append([unicode(g[0].fenomeno), (_etichetta(tr(R.NOME_PESO[peso]), _classe_peso(peso)),), u', '.join(famiglie),
                      u', '.join(fonti), unicode(len(g)), g[0].descrizione[:300], stato])
    return righe


def html(t, info=None):
    """Il report completo di un triage, come testo HTML."""
    info = info or {}
    contano = [s for s in t.segnali if s.conta and not s.discordante and not s.limitato]
    decisivi = [s for s in contano if s.peso == R.DECISIVO]
    conferme = [s for s in contano if s.peso == R.DA_CONFERMARE]
    informativi = [s for s in t.segnali if s.peso == R.INFORMATIVO]
    incerti = [s for s in t.segnali if s.conta and (s.discordante or s.limitato) and s.peso >= R.DA_CONFERMARE]
    esclusi = [s for s in t.segnali if not s.conta and s.peso >= R.DA_CONFERMARE]
    classe = {tc_controlli.V_INDICATORI: u'v-rosso', tc_controlli.V_PRIORITA: u'v-arancio',
              tc_controlli.V_DA_VERIFICARE: u'v-giallo'}.get(t.verdetto, u'v-neutro')
    computer = t.contesto.get('computer') or t.contesto.get('computer_ram') or info.get('origine') or u''
    o = []
    o.append(u'<!DOCTYPE html><html lang="%s"><head><meta charset="utf-8">' % lingua())
    o.append(u'<meta name="viewport" content="width=device-width, initial-scale=1">')
    o.append(tr(u'<title>Triage compromissione - %s</title><style>%s</style></head><body><div class="pagina">') % (_e(computer), _CSS))
    o.append(tr(u'<h1>Triage compromissione: %s</h1>') % _e(computer or tr(u'origine senza nome')))
    o.append(tr(u'<div class="sotto">Report generato il %s UTC dal plugin Triage compromissione %s per Autopsy. Tutti gli orari sono in UTC.</div>')
             % (_e(T(info.get('generato') or time.time())), _e(tc_controlli.VERSIONE)))
    o.append(u'<div class="avvertenza">%s</div>' % _e(tr(tc_controlli.AVVERTENZA)))
    o.append(u'<div class="verdetto %s"><div class="titolo">%s</div><div class="motivo">%s</div><div class="conteggi">%s</div></div>'
             % (classe, _e(tr(t.verdetto)), _e(t.motivo_verdetto), _conteggi(t)))
    o.append(u'<div class="schede">')
    c = t.conteggi or {}
    for numero, nome, colore in ((c.get('fatti_decisivi', 0), tr(u'Fatti decisivi'), u'n-rosso'),
                                 (c.get('fatti_da_confermare', 0), tr(u'Fatti da confermare'), u'n-giallo'),
                                 (len(decisivi) + len(conferme), tr(u'Segnali che contano'), u'n-grigio'),
                                 (len(informativi), tr(u'Solo contesto'), u'n-grigio')):
        o.append(u'<div class="scheda"><div class="numero %s">%d</div><div class="nome">%s</div></div>' % (colore, numero, _e(nome)))
    famiglie = []
    for s in decisivi + conferme:
        if s.famiglia not in famiglie:
            famiglie.append(s.famiglia)
    o.append(tr(u'<div class="scheda"><div class="numero">%d</div><div class="nome">Famiglie di segnali</div></div>') % len(famiglie))
    o.append(u'</div>')
    for a in t.avvisi:
        o.append(tr(u'<div class="avviso"><b>Copertura:</b> %s</div>') % _e(a))
    for a in t.note:
        o.append(tr(u'<div class="osservazione"><b>Nota:</b> %s</div>') % _e(a))
    for e in t.errori:
        o.append(tr(u'<div class="errore"><b>Un controllo non \u00e8 riuscito:</b><pre>%s</pre></div>') % _e(e))
    o.append(tr(u'<p class="indice"><a href="#segnali">Segnali</a><a href="#fatti">Fatti</a><a href="#cronologia">Cronologia</a>'
                u'<a href="#controlli">I 41 controlli</a>'))
    for numero, nome in tc_controlli.FASI:
        o.append(tr(u'<a href="#fase%d">Fase %d</a>') % (numero, numero))
    o.append(tr(u'<a href="#metodo">Come leggere il report</a></p>'))

    o.append(tr(u'<h2>Sistema</h2>'))
    o.append(_contesto(t, info))
    ram = _sezione_ram(t)
    if ram:
        o.append(tr(u'<h2 id="ram">RAM: abbinamento e controlli</h2>'))
        o.extend(ram)

    # ---- segnali
    o.append(tr(u'<h2 id="segnali">Segnali</h2>'))
    colonne = [tr(u'Peso'), tr(u'Quando (UTC)'), tr(u'Controllo'), tr(u'Famiglia'), tr(u'Segnale')]
    if decisivi:
        o.append(tr(u'<h3>Decisivi (%d)</h3>') % len(decisivi))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(decisivi, key=lambda s: (s.controllo, s.ora))]))
    if conferme:
        o.append(tr(u'<h3>Da confermare (%d)</h3>') % len(conferme))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(conferme, key=lambda s: (s.controllo, s.ora))]))
    if not decisivi and not conferme:
        o.append(tr(u'<p>Nessun segnale decisivo o da confermare.</p>'))
    if incerti:
        o.append(tr(u'<h3>Discordanze fra fonti e RAM con output anomalo (%d)</h3>') % len(incerti))
        o.append(tr(u'<p class="nota">Possono venire da un occultamento come da un problema di acquisizione o di estrazione: '
                    u'portano il verdetto a \u00abda verificare\u00bb, non oltre.</p>'))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(incerti, key=lambda s: (s.controllo, s.ora))]))
    if esclusi:
        o.append(tr(u'<h3>Dalla RAM contraddetta dal disco (%d): non contano</h3>') % len(esclusi))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(esclusi, key=lambda s: (s.controllo, s.ora))]))
    if informativi:
        o.append(tr(u'<details><summary>Solo contesto (%d): voci che non pesano sul verdetto</summary>') % len(informativi))
        o.append(_tabella(colonne, [_riga_segnale(t, s) for s in sorted(informativi, key=lambda s: (s.controllo, s.ora))]))
        o.append(u'</details>')
    tagliati = [(n, q) for n, q in sorted(t._per_controllo.items()) if q > len([s for s in t.segnali if s.controllo == n])]
    if tagliati:
        o.append(tr(u'<p class="nota">Per non allungare il report, alcuni controlli mostrano solo i primi segnali: %s.</p>')
                 % _e(u'; '.join([tr(u'controllo %d, %d in tutto') % (n, q) for n, q in tagliati])))

    # ---- fatti
    o.append(tr(u'<h2 id="fatti">Fatti</h2>'))
    righe = _fatti(t)
    if righe:
        o.append(_tabella([tr(u'Fatto n.'), tr(u'Peso'), tr(u'Famiglie'), tr(u'Visto in'), tr(u'Segnali'), tr(u'Primo segnale'),
                           tr(u'Stato')], righe))
        o.append(tr(u'<p class="nota">Un fatto riunisce i segnali sullo stesso oggetto (processo, comando, file, attivit\u00e0, '
                    u'servizio, account, indirizzo, registro, blocco di script). Pi\u00f9 fonti che lo vedono confermano che '
                    u'\u00e8 avvenuto, non che sia pi\u00f9 grave; per il verdetto due famiglie contano solo se vengono da '
                    u'fatti diversi.</p>'))
    else:
        o.append(tr(u'<p>Nessun fatto decisivo o da confermare.</p>'))

    # ---- cronologia
    cronologia = t.cronologia()
    o.append(tr(u'<h2 id="cronologia">Cronologia dei segnali</h2>'))
    if cronologia:
        righe = []
        for s in cronologia:
            righe.append([(u'<span class="ora">%s</span>' % _e(T(s.ora)),), (_etichetta(tr(R.NOME_PESO[s.peso]), _classe_peso(s.peso)
                          if s.conta else u'e-escluso'),), unicode(s.controllo), s.descrizione, origine(s)])
        o.append(_tabella([tr(u'Quando (UTC)'), tr(u'Peso'), tr(u'Controllo'), tr(u'Segnale'), tr(u'Origine')], righe))
        o.append(tr(u'<p class="nota">Solo i segnali decisivi e da confermare che hanno un orario. '
                 u'Per le chiavi del registro l\'orario \u00e8 l\'ultima scrittura della chiave.</p>'))
    else:
        o.append(tr(u'<p>Nessun segnale con un orario.</p>'))

    # ---- i 41 controlli
    o.append(tr(u'<h2 id="controlli">I 41 controlli della checklist</h2>'))
    righe = []
    for numero, fase, titolo in tc_controlli.CONTROLLI:
        etichetta, peso, quanti, nota = t.stato_controllo(numero)
        if peso > 0:
            classe_e = _classe_peso(peso)
            testo = u'%s (%d)' % (etichetta, quanti)
        elif peso == 0 and etichetta == tr(u'Nulla da segnalare'):
            classe_e = u'e-ok'
            testo = etichetta
        elif etichetta == tr(u'Parziale'):
            classe_e = u'e-parziale'
            testo = etichetta
        else:
            classe_e = u'e-na'
            testo = etichetta
        righe.append([unicode(numero), tr(u'Fase %d') % fase, tr(titolo), (_etichetta(testo, classe_e),), nota])
    o.append(_tabella([tr(u'N.'), tr(u'Fase'), tr(u'Controllo'), tr(u'Esito'), tr(u'Nota')], righe))
    o.append(tr(u'<p class="nota">\u00abParziale\u00bb: il controllo \u00e8 stato fatto, ma una sua fonte manca o \u00e8 '
                u'incompleta (la nota dice quale). Un controllo parziale o non verificabile per una fonte che c\'\u00e8 ma '
                u'non \u00e8 riuscita impedisce il verdetto \u00abnessun indicatore trovato\u00bb.</p>'))

    # ---- fasi con le tabelle di contesto
    for numero, nome in tc_controlli.FASI:
        o.append(tr(u'<h2 id="fase%d">Fase %d \u2014 %s</h2>') % (numero, numero, _e(tr(nome))))
        mie = [x for x in t.tabelle if tc_controlli.FASE_CONTROLLO.get(x.controllo) == numero]
        if numero == 1 and t.contesto.get('memorie'):
            o.append(tr(u'<p>I controlli 3, 4, 5 e 7 vengono dalla RAM analizzata con Volatility (vedi Sistema). La cache '
                     u'DNS (controllo 6) e la copia del Prefetch (2) richiedono il triage dal vivo.</p>'))
        elif numero == 1:
            o.append(tr(u'<p>I controlli da 2 a 7 riguardano dati volatili (sessioni, processi, connessioni, cache DNS): '
                     u'su un\'immagine del disco non ci sono. Servono il triage dal vivo o un dump della RAM.</p>'))
        if not mie:
            if numero != 1:
                o.append(tr(u'<p class="nota">Nessuna tabella per questa fase.</p>'))
            continue
        mie.sort(key=lambda x: x.controllo)
        for tab in mie:
            o.append(tr(u'<div class="fase"><h3>%d. %s <span class="sotto">(%d righe)</span></h3>')
                     % (tab.controllo, _e(tab.titolo), len(tab.righe)))
            aperto = u' open' if len(tab.righe) <= 12 else u''
            o.append(tr(u'<details%s><summary>mostra o nascondi</summary>') % aperto)
            o.append(_tabella(tab.colonne, tab.righe))
            o.append(u'</details>')
            if tab.nota:
                o.append(u'<div class="nota">%s</div>' % _e(tab.nota))
            o.append(u'</div>')

    # ---- metodo
    o.append(tr(u'<h2 id="metodo">Come leggere il report</h2>'))
    o.append(u'<p><b>%s</b></p>' % _e(tr(tc_controlli.AVVERTENZA)))
    o.append(tr(u'<p><b>Verdetto.</b> Contano i fatti, non i segnali: i segnali sullo stesso oggetto sono un fatto solo. '
                u'Un fatto <i>decisivo</i> d\u00e0 \u00abIndicatori di compromissione\u00bb: un indicatore che di rado ha una '
                u'spiegazione innocente e che da solo giustifica l\'esame della macchina, non una prova. Segnali <i>da '
                u'confermare</i> in due famiglie diverse, da fatti diversi, danno \u00abDa verificare, priorit\u00e0 alta\u00bb '
                u'(famiglie: accessi, account, persistenza, programmi eseguiti, strumenti d\'attacco, strumenti a doppio uso, '
                u'esecuzione remota, RMM, file, anti-forensics, antivirus, esfiltrazione e tunnel). Una sola famiglia, o un '
                u'fatto solo, d\u00e0 \u00abDa verificare\u00bb; cos\u00ec anche le discordanze fra fonti e gli indizi di una RAM '
                u'con l\'output anomalo, e un avviso di copertura senza segnali: registri o hive assenti, danneggiati o '
                u'troppo corti, file che non si sono lasciati leggere, controlli parziali, registri che si fermano prima del '
                u'resto, controlli interrotti da un errore. \u00abNessun indicatore trovato\u00bb non vuol dire che la macchina '
                u'sia pulita.</p>'))
    o.append(tr(u'<p><b>Recente.</b> Alcuni controlli pesano di pi\u00f9 ci\u00f2 che \u00e8 recente. La finestra si conta '
             u'all\'indietro da un riferimento: il pi\u00f9 vecchio tra l\'ultimo evento scritto nel registro Security e '
             u'l\'ultimo scritto nel System (o, se mancano, gli ultimi eventi degli altri registri e l\'ora di spegnimento). '
             u'Non \u00e8 l\'orario pi\u00f9 recente trovato: un solo orario sbagliato o alterato sposterebbe la finestra. '
             u'Tutto ci\u00f2 che viene dopo il riferimento \u00e8 recente.</p>'))
    o.append(tr(u'<p><b>Ogni segnale vale solo se l\'IT non lo spiega:</b> un amministratore o uno strumento di assistenza autorizzato '
             u'lasciano tracce simili. Il triage serve a decidere se approfondire, non sostituisce l\'analisi.</p>'))
    o.append(tr(u'<p><b>Regole in pi\u00f9.</b> I segnali con questa etichetta vengono da regole note che non fanno parte delle 32 guide '
             u'su cui \u00e8 costruita la checklist (per esempio: backdoor \u00absticky keys\u00bb, '
             u'esclusioni di Defender, cronologia di PowerShell).</p>'))
    o.append(tr(u'<p><b>Limiti.</b> Un\'immagine del disco non contiene i dati volatili (controlli 2-7). '
                u'ShimCache e AmCache provano che un file esisteva, non che \u00e8 stato eseguito: uno strumento trovato solo per '
                u'nome resta da confermare. Le sottoscrizioni WMI vengono cercate anche tra gli oggetti cancellati del '
                u'repository. Le copie shadow non vengono aperte. I limiti noti del rilevamento sono nel README.</p>'))
    if t.contesto.get('memorie'):
        o.append(tr(u'<p><b>RAM.</b> La RAM fotografa un istante: un processo gi\u00e0 terminato si vede solo se la sua '
                    u'memoria non \u00e8 ancora stata riusata (psscan), e per i processi la cui memoria era nel file di '
                    u'paging mancano la riga di comando e l\'utente. Un processo \u00abforse nascosto\u00bb \u00e8 una '
                    u'discordanza fra due fonti: a volte la scansione trova i resti di un processo appena terminato. '
                    u'L\'output di Volatility si controlla contro il manifesto (righe e SHA-256) e contro quello che un '
                    u'Windows acceso ha sempre; quale RAM va con questa macchina lo indica l\'analista e il plugin lo '
                    u'controlla (vedi \u00abRAM: abbinamento e controlli\u00bb).</p>'))
    o.append(tr(u'<p class="sotto">Analisi completata in %.1f secondi.</p>') % t.durata)
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
    """I segnali in formato CSV, per Excel. Il separatore segue la lingua:
    punto e virgola in italiano (e' quello che Excel si aspetta con le
    impostazioni italiane), virgola in inglese."""
    separatore = u';' if lingua() == ITALIANO else u','
    righe = [separatore.join([_csv(x) for x in (tr(u'Peso'), tr(u'Quando (UTC)'), tr(u'Controllo'), tr(u'Titolo del controllo'),
                                                tr(u'Famiglia'), tr(u'Segnale'), tr(u'Dettagli'), u'File',
                                                tr(u'Regola in pi\u00f9'), tr(u'Fatto n.'), tr(u'Origine'), tr(u'Conta'),
                                                tr(u'Stato'))])]
    for s in t.segnali_ordinati():
        percorso = u''
        if s.elemento is not None:
            try:
                percorso = s.elemento.percorso
            except ERRORI:
                pass
        stato = []
        if s.discordante:
            stato.append(tr(u'discordanza fra fonti'))
        if s.limitato:
            stato.append(tr(u'RAM con output anomalo'))
        righe.append(separatore.join([_csv(x) for x in (tr(R.NOME_PESO[s.peso]), T(s.ora), s.controllo, s.titolo(),
                                                        tr(s.famiglia), s.descrizione, s.dettagli, percorso,
                                                        tr(u's\u00ec') if s.extra else u'', s.fenomeno, origine(s),
                                                        tr(u's\u00ec') if s.conta else tr(u'no'), u', '.join(stato))]))
    return u'\r\n'.join(righe) + u'\r\n'
