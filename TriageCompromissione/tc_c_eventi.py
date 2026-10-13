# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
tc_c_eventi - Controlli basati sui registri eventi: copertura, log
cancellati, accessi, servizi installati, attivita' pianificate, firme di
Impacket, comandi sospetti, antivirus.
"""

import bisect
import re
import time

import tc_eventi
import tc_regole as R
import tc_c_registro
import tc_memoria
from tc_base import testo_orario as T, ERRORI
from tc_lingua import tr, N_, quanti
from tc_lingua import volte as quante_volte

_BASATI_SUGLI_EVENTI = (8, 9, 11, 12, 13, 14, 18, 25, 27, 31, 36)
_PROCESSI_LATERALI = set([u'wmic.exe', u'powershell.exe', u'pwsh.exe', u'cmd.exe', u'net.exe', u'net1.exe',
                          u'schtasks.exe', u'sc.exe', u'winrs.exe', u'wsmprovhost.exe', u'python.exe',
                          u'psexec.exe', u'psexec64.exe', u'reg.exe', u'at.exe'])
_GRUPPI_PRIVILEGIATI = {u'S-1-5-32-544': u'Administrators', u'S-1-5-32-555': u'Remote Desktop Users',
                        u'S-1-5-32-551': u'Backup Operators', u'S-1-5-32-548': u'Account Operators'}
_NOME_EVENTO_ACCOUNT = {4720: N_(u'account creato'), 4722: N_(u'account attivato'), 4724: N_(u'password reimpostata'),
                        4726: N_(u'account cancellato'), 4728: N_(u'aggiunto a un gruppo globale'),
                        4732: N_(u'aggiunto a un gruppo locale'), 4756: N_(u'aggiunto a un gruppo universale')}
_TIPO_LOGON = {3: N_(u'rete (3)'), 7: N_(u'sblocco (7)'), 10: u'RDP (10)'}
# I registri che Windows crea all'installazione e tiene sempre: se mancano
# sono stati tolti, oppure la raccolta dei file e' parziale. Gli altri
# registri principali (TaskScheduler, RemoteConnectionManager, Defender,
# Sysmon) nascono solo quando il loro canale scrive il primo evento.
_SEMPRE_PRESENTI = [
    (u'application.evtx', u''),
    (u'windows powershell.evtx', N_(u'i comandi di PowerShell (evento 400)')),
    (u'microsoft-windows-powershell%4operational.evtx', N_(u'gli script di PowerShell (evento 4104)')),
    (u'microsoft-windows-terminalservices-localsessionmanager%4operational.evtx', N_(u'le sessioni RDP (eventi 21, 22, 25)')),
]
# i nomi che Windows da' al computer durante l'installazione, prima di quello definitivo
_RX_NOME_PROVVISORIO = re.compile(u'^(minwinpc|win-[a-z0-9]{11})$')


# --------------------------------------------------------------------------
# lettura
# --------------------------------------------------------------------------

def leggi(t):
    rac = tc_eventi.Raccolta()
    t.raccolta = rac
    if t.radice.piatta:
        trovati = t.radice.file(u'', u'%.evtx', ovunque=True)
    else:
        trovati = t.radice.file(u'windows/system32/winevt/logs/', u'%.evtx')
    if not trovati:
        for c in _BASATI_SUGLI_EVENTI:
            t.esito(c, 'assente', tr(u'nessun registro eventi (.evtx) trovato'))
        t.avviso(tr(u'Nessun registro eventi trovato: i controlli sugli accessi e sull\'esecuzione remota non sono possibili.'))
        return
    scelti = []
    for e in trovati:
        nome = e.nome.lower()
        noto = nome in tc_eventi.ID_PER_FILE or nome.startswith(u'archive-')
        if noto or t.radice.piatta:
            scelti.append((e, not noto))
    scelti.sort(key=lambda x: x[0].dimensione)
    for i, (e, tutti) in enumerate(scelti):
        if t.annullato():
            return
        t.avanza(tr(u'Registri eventi: %s (%d di %d)') % (e.nome, i + 1, len(scelti)))

        def controlla(blocchi=[0], e=e, i=i):
            # chiamata dal lettore a ogni blocco da 64 KB: aggiorna la barra
            # di avanzamento nei registri grandi e sente se l'utente ha annullato
            blocchi[0] += 1
            if blocchi[0] % 320 == 0:
                t.avanza(tr(u'Registri eventi: %s (%d di %d), %d%%')
                         % (e.nome, i + 1, len(scelti), min(99, 100 * blocchi[0] * 65536 // max(1, e.dimensione))))
            return t.annullato()

        try:
            rac.leggi_file(e, annullato=controlla, tutti=tutti)
        except ERRORI, ex:
            t.non_letto(e, ex)
        finally:
            e.chiudi()
    for e, blocchi in rac.non_letti:
        t.non_letto(e, tr(u'%d blocchi da 64 KB non letti') % blocchi)
    for nome, voce in rac.copertura.items():
        # Per il riferimento conta l'ultimo evento scritto in ogni registro,
        # non quello con la data piu' recente: se l'orologio e' stato spostato
        # le due cose non coincidono (vedi Triage._calcola_riferimento).
        t.vede(voce[5] or voce[1], True, nome)
        if voce[1] and voce[1] > t.ultimo_evento:
            t.ultimo_evento = voce[1]
    t.contesto['registri_letti'] = len(scelti)
    if rac.nomi and not t.contesto.get('computer'):
        # senza l'hive SYSTEM il nome dell'installazione viene dai suoi registri
        # eventi: quello degli eventi piu' recenti di Security e System
        v = max(rac.nomi.values(), key=lambda x: x[1])
        t.contesto['computer'] = v[3]
        t.contesto['computer_fonte'] = u'eventi'
    _fase_installazione(t, rac)


# --------------------------------------------------------------------------
# analisi
# --------------------------------------------------------------------------

def analizza(t):
    rac = t.raccolta
    if rac is None:
        return
    if not rac.copertura:
        if t.contesto.get('registri_letti'):
            # i file .evtx ci sono, ma nessuno si e' lasciato leggere
            for c in _BASATI_SUGLI_EVENTI:
                t.esito(c, 'assente', tr(u'nessun registro eventi leggibile'))
            t.avviso(tr(u'Nessun registro eventi leggibile (file danneggiati, vuoti o non accessibili): i controlli '
                     u'sugli accessi e sull\'esecuzione remota non sono possibili.'))
        return
    for funzione in (_copertura, _cancellati, _accessi, _espliciti, _servizi, _attivita, _condivisioni,
                     _processi, _account, _defender, _rmm):
        try:
            funzione(t, rac)
        except ERRORI:
            import traceback
            t.errori.append(tr(u'Analisi degli eventi (%s): %s')
                            % (funzione.__name__, traceback.format_exc().decode('utf-8', 'replace')[-1200:]))


def _vicino_installazione(t, ora, ore=48):
    installato = t.contesto.get('installato', 0)
    return bool(installato and ora and abs(ora - installato) < ore * 3600)


def _fase_installazione(t, rac):
    """Quando questa copia di Windows e' stata installata o distribuita,
    secondo i registri eventi: serve quando manca l'hive SOFTWARE (registri
    raccolti da soli) e quando gli eventi della preparazione dell'immagine sono
    molto piu' vecchi della data di installazione del registro (che e' quella
    della distribuzione). Si riconosce dal cambio di nome del computer: gli
    eventi della preparazione portano un altro nome (WIN-XXXXXXXXXXX, MINWINPC
    o quello della macchina su cui e' stata preparata l'immagine), poi compare
    il nome definitivo. Il nome vecchio deve durare poco (una preparazione, non
    mesi di uso): un computer rinominato dopo mesi non e' un'installazione.
    Senza un cambio di nome cosi' non si sa nulla e non si suppone nulla."""
    if len(rac.nomi) < 2:
        return
    definitivo = (t.contesto.get('computer') or u'').split(u'.')[0].lower()
    if definitivo not in rac.nomi:
        definitivo = max(rac.nomi.items(), key=lambda x: x[1][1])[0]
    comparso = rac.nomi[definitivo][0]
    prima = [v for k, v in rac.nomi.items() if k != definitivo and v[0] and v[0] < comparso]
    if not prima or not comparso:
        return
    inizio = min([v[0] for v in prima])
    fine_vecchi = max([v[1] for v in prima])
    if fine_vecchi - inizio > 86400.0:
        return
    t.contesto['preparazione'] = (inizio, comparso)
    # i nomi della preparazione: gli eventi scritti con questi nomi (anche in registri
    # che non sono stati svuotati con gli altri) sono della preparazione
    t.contesto['nomi_preparazione'] = set([k for k, v in rac.nomi.items() if k != definitivo and v[0] and v[0] < comparso])


def _in_preparazione(t, ora, ore, computer=u''):
    """Vero se l'evento e' dell'installazione di Windows: entro 'ore' dalla
    data di installazione del registro, oppure tra l'inizio della preparazione
    e 'ore' dopo la comparsa del nome definitivo, oppure scritto con un nome
    della preparazione (vedi _fase_installazione)."""
    if _vicino_installazione(t, ora, ore):
        return True
    if computer and computer in (t.contesto.get('nomi_preparazione') or ()):
        return True
    fase = t.contesto.get('preparazione')
    return bool(fase and ora and fase[0] - 3600 <= ora <= fase[1] + ore * 3600)


def _nomi_macchina(t, rac):
    """Tutti i nomi che la macchina ha avuto: quello del registro e quelli dei
    suoi eventi di Security e System."""
    nomi = set([x.lower() for x in rac.computer]) | set(rac.nomi.keys())
    if t.contesto.get('computer'):
        nomi.add(t.contesto['computer'].split(u'.')[0].lower())
    return nomi


def _eventi(n):
    return quanti(n, N_(u'%d evento'), N_(u'%d eventi'))


def _durata(secondi):
    if secondi < 3600:
        return quanti(max(1, int(secondi / 60)), N_(u'%d minuto'), N_(u'%d minuti'))
    if secondi < 2 * 86400:
        return quanti(int(secondi / 3600), N_(u'%d ora'), N_(u'%d ore'))
    return tr(u'%d giorni') % int(secondi / 86400)


def _quanti(v):
    """Il numero di eventi di un registro, con quelli che non si sono lasciati leggere."""
    testo = unicode(v[2])
    guasti = v[6] + v[4]
    if guasti:
        testo += tr(u' (%d non leggibili)') % guasti
    return testo


def _nome_registro(nome):
    for interno, leggibile in tc_eventi.REGISTRI_PRINCIPALI:
        if interno == nome:
            return leggibile
    return nome


def _stato_dei_registri(t, rac, non_validi, non_letti):
    """Le lacune che i controlli sugli eventi non vedono da soli: il System
    che manca, i registri che esistono ma non sono validi, quelli con record
    rovinati, gli orari che non tornano. Senza questi avvisi un registro
    danneggiato darebbe "nulla da segnalare" come uno sano."""
    if u'system.evtx' not in rac.copertura and not t.radice.piatta:
        if u'system.evtx' in non_validi:
            motivo = tr(u'esiste (%d byte) ma non \u00e8 un registro eventi valido') % non_validi[u'system.evtx'].dimensione
        elif u'system.evtx' in non_letti:
            motivo = tr(u'non \u00e8 stato letto per un errore di lettura')
        else:
            motivo = tr(u'non \u00e8 stato trovato')
        t.avviso(tr(u'System.evtx %s: mancano i servizi installati (7045), i registri cancellati (104) e gli altri '
                 u'eventi di sistema.') % motivo)
    if not t.radice.piatta:
        mancano = [(n, cosa) for n, cosa in _SEMPRE_PRESENTI
                   if n not in rac.copertura and n not in non_validi and n not in non_letti]
        if mancano:
            perde = [tr(cosa) for _, cosa in mancano if cosa]
            nomi = u', '.join([_nome_registro(n) + u'.evtx' for n, _ in mancano])
            coda = (tr(u' Mancano %s.') % u', '.join(perde)) if perde else u''
            if len(mancano) == 1:
                t.avviso(tr(u'%s non trovato: Windows lo crea sempre, quindi \u00e8 stato tolto oppure i file raccolti '
                         u'sono solo una parte.%s') % (nomi, coda))
            else:
                t.avviso(tr(u'%s non trovati: Windows li crea sempre, quindi sono stati tolti oppure i file raccolti '
                         u'sono solo una parte.%s') % (nomi, coda))
    altri = sorted([n for n in non_validi if n not in (u'security.evtx', u'system.evtx')])
    if altri:
        if len(altri) == 1:
            t.avviso(tr(u'1 registro eventi esiste ma non \u00e8 valido (vuoto, azzerato o con l\'intestazione danneggiata): '
                     u'%s. I suoi eventi non sono stati controllati.') % _nome_registro(altri[0]))
        else:
            t.avviso(tr(u'%d registri eventi esistono ma non sono validi (vuoti, azzerati o con l\'intestazione '
                     u'danneggiata): %s%s. I loro eventi non sono stati controllati.')
                     % (len(altri), u', '.join([_nome_registro(n) for n in altri[:6]]),
                        tr(u' e altri') if len(altri) > 6 else u''))
    # Due cose diverse: i blocchi rovinati e i record che i blocchi dichiarano
    # ma non contengono (il file e' danneggiato), e i record integri che il
    # lettore non ha saputo decodificare (il file non e' per forza danneggiato:
    # il record puo' essere rovinato dentro o scritto in una forma che il
    # lettore non conosce).
    rovinati = []
    non_decodificati = []
    for nome, v in sorted(rac.copertura.items()):
        totale = max(v[2], v[9] + v[6])
        if v[6] or v[8]:
            pezzi = []
            if v[6]:
                pezzi.append(tr(u'%d eventi non leggibili su %d') % (v[6], totale))
            if v[8]:
                pezzi.append(tr(u'%d blocchi rovinati') % v[8])
            rovinati.append(u'%s (%s)' % (_nome_registro(nome), u', '.join(pezzi)))
        if v[4]:
            non_decodificati.append(u'%s (%d su %d)' % (_nome_registro(nome), v[4], totale))
    if rovinati:
        t.avviso(tr(u'Registri eventi danneggiati: %s%s. Gli eventi che mancano non sono stati controllati.')
                 % (u'; '.join(rovinati[:6]), tr(u' e altri') if len(rovinati) > 6 else u''))
    if non_decodificati:
        t.avviso(tr(u'Eventi non decodificati: %s%s. I record ci sono, ma il lettore del plugin non ne ha saputo leggere '
                 u'il contenuto: possono essere rovinati oppure scritti in una forma che il lettore non conosce. Questi '
                 u'eventi non sono stati controllati; si possono aprire con un altro strumento (per esempio il '
                 u'Visualizzatore eventi di Windows).')
                 % (u'; '.join(non_decodificati[:6]), tr(u' e altri') if len(non_decodificati) > 6 else u''))
    # orologio spostato: l'evento con la data piu' recente non e' l'ultimo scritto
    spostati = [(v[1] - v[5], nome, v) for nome, v in rac.copertura.items() if v[1] and v[5] and v[1] - v[5] > 86400.0]
    if spostati:
        spostati.sort(reverse=True)
        scarto, nome, v = spostati[0]
        if len(spostati) == 1:
            t.nota(tr(u'In 1 registro eventi l\'evento con la data pi\u00f9 recente non \u00e8 l\'ultimo scritto: in %s si '
                   u'arriva al %s UTC, ma l\'ultimo evento scritto \u00e8 del %s UTC. L\'orologio della macchina \u00e8 '
                   u'stato riportato indietro (o corretto) di %s. La finestra dei controlli recenti si conta dall\'ultimo '
                   u'evento scritto.') % (_nome_registro(nome), T(v[1]), T(v[5]), _durata(scarto)))
        else:
            t.nota(tr(u'In %d registri eventi l\'evento con la data pi\u00f9 recente non \u00e8 l\'ultimo scritto: in %s si '
                   u'arriva al %s UTC, ma l\'ultimo evento scritto \u00e8 del %s UTC. L\'orologio della macchina \u00e8 '
                   u'stato riportato indietro (o corretto) di %s. La finestra dei controlli recenti si conta dall\'ultimo '
                   u'evento scritto.') % (len(spostati), _nome_registro(nome), T(v[1]), T(v[5]), _durata(scarto)))
    futuri = sum([v[7] for v in rac.copertura.values()])
    if futuri:
        t.nota(tr(u'Nei registri eventi ci sono eventi con una data nel futuro rispetto a oggi (almeno %d): orologio '
               u'sbagliato o record alterati. Non sono stati usati per calcolare i periodi coperti.') % futuri)


def _registri_in_avanti(t, rac):
    """Un registro che arriva molto oltre il momento di riferimento: la
    finestra dei controlli recenti non ne risente (parte dal riferimento e non
    ha un limite in avanti), ma le date dei registri non tornano tra loro e chi
    legge il report deve saperlo. I registri in cui l'orologio risulta
    riportato indietro hanno gia' la loro nota."""
    riferimento = t.riferimento
    if not riferimento:
        return
    avanti = []
    for nome, v in rac.copertura.items():
        scritto = v[5] or v[1]
        if v[1] and scritto > riferimento + 86400.0 and v[1] - scritto <= 86400.0:
            avanti.append((v[1], nome))
    if not avanti:
        return
    avanti.sort(reverse=True)
    ultimo, nome = avanti[0]
    if len(avanti) == 2:
        anche = tr(u'; lo stesso vale per un altro registro')
    elif len(avanti) > 2:
        anche = tr(u'; lo stesso vale per altri %d registri') % (len(avanti) - 1)
    else:
        anche = u''
    t.nota(tr(u'%s arriva al %s UTC, %s oltre il momento da cui si conta la finestra dei controlli recenti (%s UTC)%s. '
           u'Le date dei registri non tornano tra loro: un registro ha continuato a scrivere mentre gli altri erano '
           u'fermi, oppure l\'orologio era sbagliato, oppure i file vengono da momenti diversi. Confronta le date '
           u'nella tabella della copertura.')
           % (_nome_registro(nome), T(ultimo), _durata(ultimo - riferimento), T(riferimento),
              anche))


def _copertura(t, rac):
    righe = []
    non_validi = {}
    for e in rac.non_validi:
        non_validi[e.nome.lower()] = e
    non_letti = set([x[0].rstrip(u'/').split(u'/')[-1].lower() for x in t.non_letti])
    for nome, leggibile in tc_eventi.REGISTRI_PRINCIPALI:
        v = rac.copertura.get(nome)
        if v is None:
            if nome in non_validi:
                righe.append([leggibile, tr(u'non valido (%d byte)') % non_validi[nome].dimensione, u'', u'', u''])
            elif nome in non_letti:
                righe.append([leggibile, tr(u'non letto (errore di lettura)'), u'', u'', u''])
            elif not t.radice.piatta:
                sempre = nome in (u'security.evtx', u'system.evtx') or nome in [n for n, _ in _SEMPRE_PRESENTI]
                righe.append([leggibile, tr(u'non trovato') if sempre else
                              tr(u'non trovato (normale se il canale non ha mai scritto)'), u'', u'', u''])
            continue
        primo, ultimo = v[0], v[1]
        righe.append([leggibile, T(primo), T(ultimo), _quanti(v),
                      _durata(ultimo - primo) if primo and ultimo else u''])
    if t.radice.piatta:
        for nome, v in sorted(rac.copertura.items()):
            if nome not in tc_eventi.ID_PER_FILE:
                righe.append([nome, T(v[0]), T(v[1]), _quanti(v), _durata(v[1] - v[0]) if v[0] and v[1] else u''])
    note = []
    _stato_dei_registri(t, rac, non_validi, non_letti)
    sicurezza = rac.copertura.get(u'security.evtx')
    fermo = False       # vero se e' gia' stato detto che il Security si ferma prima degli altri
    if sicurezza is None:
        if u'security.evtx' in non_validi:
            t.avviso(tr(u'Security.evtx esiste (%d byte) ma non \u00e8 un registro eventi valido: file vuoto, azzerato o con '
                     u'l\'intestazione danneggiata. Mancano gli accessi (4624, 4625) e le firme di Impacket nel Security.')
                     % non_validi[u'security.evtx'].dimensione)
        elif u'security.evtx' in non_letti:
            t.avviso(tr(u'Security.evtx non letto per un errore di lettura: mancano gli accessi (4624, 4625) e le firme '
                     u'di Impacket nel Security.'))
        elif not t.radice.piatta:
            t.avviso(tr(u'Security.evtx non trovato: mancano gli accessi (4624, 4625) e le firme di Impacket nel Security.'))
    else:
        primo, ultimo = sicurezza[0], sicurezza[1]
        installato = t.contesto.get('installato', 0)
        if primo and ultimo:
            giorni = (ultimo - primo) / 86400.0
            giovane = installato and (primo - installato) < 3 * 86400
            if giorni < 3 and not giovane:
                t.avviso(tr(u'Il registro Security copre solo %s (dal %s al %s): gli eventi pi\u00f9 vecchi sono andati '
                         u'persi o sono stati cancellati.') % (_durata(ultimo - primo), T(primo), T(ultimo)))
                t.segnala(8, R.INFORMATIVO, R.F_ANTIFORENSE,
                          tr(u'Il registro Security copre solo %s') % _durata(ultimo - primo),
                          tr(u'Dal %s al %s (UTC). Su una macchina in uso da tempo \u00e8 poco: o il registro \u00e8 piccolo, '
                          u'o \u00e8 stato cancellato.') % (T(primo), T(ultimo)), primo, sicurezza[3])
        if ultimo and not t.radice.piatta:
            # Su una macchina accesa il Security riceve eventi di continuo. Se
            # si ferma mentre gli altri registri vanno avanti, da quel momento
            # i controlli sugli accessi e sull'esecuzione remota sono ciechi.
            oltre = [v[1] for n, v in rac.copertura.items()
                     if n != u'security.evtx' and v[1] and v[1] > ultimo + 86400.0 and v[1] <= time.time() + 86400]
            if len(oltre) >= 2:
                fermo = True
                t.avviso(tr(u'Il registro Security si ferma al %s UTC, mentre altri %d registri arrivano fino al %s UTC '
                         u'(%s dopo): in quel periodo gli eventi di sicurezza non sono stati registrati (audit spento, '
                         u'registro pieno o registrazione manomessa) e i controlli su accessi ed esecuzione remota '
                         u'non lo coprono.') % (T(ultimo), len(oltre), T(max(oltre)), _durata(max(oltre) - ultimo)))
        if not sicurezza[2] and not sicurezza[9]:
            t.avviso(tr(u'Il registro Security \u00e8 vuoto (nessun evento): \u00e8 stato svuotato o sostituito, oppure '
                     u'l\'audit \u00e8 spento del tutto. Mancano gli accessi (4624, 4625) e le firme di Impacket nel '
                     u'Security.'))
        elif not rac.conteggi.get(4624):
            t.avviso(tr(u'Nel Security non c\'\u00e8 nessun evento 4624: l\'audit degli accessi non \u00e8 attivo.'))
        if not rac.conteggi.get(4688):
            note.append(tr(u'Nessun evento 4688: l\'audit della creazione dei processi non \u00e8 attivo (\u00e8 spento di default).'))
        elif not rac.processi_con_riga:
            note.append(tr(u'Gli eventi 4688 ci sono (%d) ma senza riga di comando.') % rac.conteggi.get(4688, 0))
        else:
            note.append(tr(u'Eventi 4688 con riga di comando: presenti (%d).') % rac.conteggi.get(4688, 0))
        if not rac.conteggi.get(5145):
            note.append(tr(u'Nessun evento 5145: l\'audit dettagliato delle condivisioni non \u00e8 attivo (\u00e8 spento di default).'))
        if not rac.conteggi.get(4698) and not rac.attivita_registrate:
            note.append(tr(u'Nessun evento 4698 n\u00e9 106: la creazione delle attivit\u00e0 pianificate non \u00e8 registrata.'))
    spenti = t.contesto.get('canali_spenti') or []
    if spenti:
        note.append(tr(u'Canali disattivati nel registro di sistema: %s.') % u', '.join(spenti))
    if not fermo:
        _registri_in_avanti(t, rac)
    t.tabella(8, tr(u'Copertura dei registri eventi'), [tr(u'Registro'), tr(u'Primo evento (UTC)'), tr(u'Ultimo evento (UTC)'), tr(u'Eventi'), tr(u'Periodo')],
              righe, u' '.join(note))
    t.contesto['note_copertura'] = note
    t.fatto(8)


def _cancellati(t, rac):
    t.fatto(9)
    if not rac.cancellazioni:
        return
    gruppi = []
    for c in sorted(rac.cancellazioni, key=lambda x: x['ora']):
        if gruppi and c['ora'] - gruppi[-1][-1]['ora'] < 120 and gruppi[-1][0]['utente'] == c['utente']:
            gruppi[-1].append(c)
        else:
            gruppi.append([c])
    righe = []
    for g in gruppi:
        registri = []
        for c in g:
            if c['registro'] not in registri:
                registri.append(c['registro'])
        primo = g[0]
        vicino = _vicino_installazione(t, primo['ora'])
        importanti = [r for r in registri if r in (u'Security', u'System', u'Application') or u'PowerShell' in r
                      or u'TaskScheduler' in r or u'TerminalServices' in r or u'Sysmon' in r or u'Defender' in r]
        if vicino:
            peso = R.INFORMATIVO
            nota = tr(u' (a ridosso dell\'installazione di Windows: probabilmente fa parte della preparazione dell\'immagine)')
        elif u'Security' in registri or len(importanti) >= 2:
            # il Security, o piu' registri importanti insieme: non e' manutenzione
            peso = R.DECISIVO
            nota = u''
        else:
            # un solo registro diverso dal Security: lo fa anche chi sta
            # risolvendo un problema, ma va chiesto chi e' stato
            peso = R.DA_CONFERMARE
            nota = u''
        dettagli = tr(u'Eventi %s. Servono diritti di amministratore.') % u', '.join(sorted(set([unicode(c['id']) for c in g])))
        if not vicino and _in_preparazione(t, primo['ora'], 48, primo.get('computer') or u''):
            # non cambia il peso: chi prepara un'immagine svuota i registri, ma va comunque spiegato
            dettagli += u'\n' + tr(u'Secondo i registri eventi la cancellazione \u00e8 avvenuta durante la preparazione della '
                                    u'macchina (nome %s, poi sostituito): se fa parte della preparazione dell\'immagine, '
                                    u'chi l\'ha preparata lo pu\u00f2 confermare.') % (primo.get('computer') or u'?')
        t.segnala(9, peso, R.F_ANTIFORENSE,
                  (tr(u'1 registro cancellato da %s%s: %s') % (primo['utente'], nota, registri[0])) if len(registri) == 1 else
                  (tr(u'%d registri cancellati da %s%s: %s')
                   % (len(registri), primo['utente'], nota,
                      u', '.join(registri[:8]) + (u'...' if len(registri) > 8 else u''))),
                  dettagli, primo['ora'], primo['elemento'], oggetti=R.chiavi_tempo(u'pulizia', primo['ora']))
        righe.append([T(primo['ora']), primo['utente'], u', '.join(registri), R.NOME_PESO[peso]])
    t.tabella(9, tr(u'Registri cancellati'), [tr(u'Quando (UTC)'), tr(u'Da chi'), tr(u'Registri'), tr(u'Peso')], righe)


def _accessi(t, rac):
    # --- controllo 11: logon remoti riusciti
    righe = []
    pubblici = {}
    for chiave, v in rac.logon.items():
        utente, ip, host, tipo = chiave
        pubblico = R.ip_pubblico(ip)
        righe.append((v[2], [utente, ip, host, tr(_TIPO_LOGON.get(tipo, unicode(tipo))), unicode(v[0]), T(v[1]), T(v[2]),
                             tr(u'indirizzo pubblico') if pubblico else u'']))
        if pubblico:
            r = pubblici.setdefault((ip, utente), [0, v[1], v[2], set()])
            r[0] += v[0]
            r[1] = min(r[1], v[1])
            r[2] = max(r[2], v[2])
            r[3].add(tr(_TIPO_LOGON.get(tipo, unicode(tipo))))
    righe.sort(key=lambda x: (x[1][7] == u'', -x[0]))
    t.tabella(11, tr(u'Logon remoti riusciti (4624 di tipo 3, 7 e 10): i 50 pi\u00f9 recenti'),
              [tr(u'Utente'), tr(u'Indirizzo'), tr(u'Host'), tr(u'Tipo'), tr(u'Volte'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)'), tr(u'Nota')],
              [x[1] for x in righe[:50]],
              tr(u'Esclusi gli account macchina e ANONYMOUS LOGON. In tutto %d combinazioni di utente e origine.') % len(rac.logon))
    segnalati = set()
    sicurezza = rac.copertura.get(u'security.evtx')
    elemento = sicurezza[3] if sicurezza else None
    for (ip, utente), r in sorted(pubblici.items(), key=lambda x: -x[1][2])[:15]:
        t.segnala(11, R.DA_CONFERMARE, R.F_ACCESSI,
                  tr(u'Accesso riuscito da un indirizzo pubblico: %s come %s (%s, %s)')
                  % (ip, utente, u', '.join(sorted(r[3])), quante_volte(r[0])),
                  tr(u'Primo: %s - ultimo: %s (UTC). Verifica se quell\'utente si collega davvero da l\u00ec.') % (T(r[1]), T(r[2])),
                  r[1], elemento, oggetti=(R.chiave(u'ip', ip),))
        segnalati.add(ip)
    if sicurezza is not None:
        t.fatto(11, 12)
    # --- controllo 12: accessi falliti
    righe = []
    pubbliche = 0
    candidati = []
    locali = _nomi_macchina(t, rac)
    for origine, v in rac.falliti.items():
        n, primo, ultimo, provati, massimo = v[0], v[1], v[2], v[3], v[6]
        inizio_raffica = v[8] if len(v) > 8 else 0
        if R.ip_pubblico(origine):
            pubbliche += 1
        if origine.lower() in locali or origine == u'-':
            # tentativi fatti alla tastiera o da servizi della macchina stessa
            righe.append((n, [origine + tr(u' (la macchina stessa)'), unicode(n),
                              u', '.join(sorted(provati)[:6]), T(primo), T(ultimo), unicode(massimo), u'']))
            continue
        # Un accesso riuscito conta se arriva dopo l'inizio della raffica (dopo
        # il primo fallito, se una raffica non c'e') e non oltre un'ora
        # dall'ultimo fallito: e' l'attaccante che ha trovato la password, non
        # l'utente che il giorno prima aveva sbagliato a scriverla.
        da = inizio_raffica or primo
        provati_bassi = set([x.lower() for x in provati])
        riuscito = 0
        chi = u''
        for ora_ok, basso, nome in rac.riusciti.get(origine, ()):
            if not (da <= ora_ok <= ultimo + 3600):
                continue
            if basso in provati_bassi or len(provati) >= 30:
                if not riuscito or ora_ok < riuscito:
                    riuscito = ora_ok
                    chi = nome
        righe.append((n, [origine, unicode(n), u', '.join(sorted(provati)[:6]) + (u'...' if len(provati) > 6 else u''),
                          T(primo), T(ultimo), unicode(massimo),
                          tr(u'%s il %s') % (chi, T(riuscito)) if riuscito else u'']))
        if n >= 20 and massimo >= 10:
            candidati.append((n, origine, primo, ultimo, provati, massimo, riuscito, chi, inizio_raffica))
    righe.sort(key=lambda x: -x[0])
    t.tabella(12, tr(u'Accessi falliti per origine (4625): le 30 origini con pi\u00f9 tentativi'),
              [tr(u'Origine'), tr(u'Tentativi'), tr(u'Utenti provati'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)'), tr(u'Massimo in 10 minuti'),
               tr(u'Accesso riuscito subito dopo')], [x[1] for x in righe[:30]],
              tr(u'Origini diverse: %d, di cui %d indirizzi pubblici.') % (len(rac.falliti), pubbliche))
    candidati.sort(key=lambda x: (not x[6], -x[0]))
    for n, origine, primo, ultimo, provati, massimo, riuscito, chi, inizio_raffica in candidati[:15]:
        pubblico = R.ip_pubblico(origine)
        attacco = R.host_di_attacco(origine)
        nota = tr(u' (nome predefinito di una distribuzione usata per gli attacchi)') if attacco else u''
        if riuscito:
            peso = R.DECISIVO if (pubblico or attacco) else R.DA_CONFERMARE
            testo = (tr(u'Raffica di %d accessi falliti da %s%s seguita da un accesso riuscito come %s')
                     % (n, origine, nota, chi))
        else:
            peso = R.DA_CONFERMARE if (pubblico or attacco or len(provati) >= 5) else R.INFORMATIVO
            testo = tr(u'Raffica di %d accessi falliti da %s%s') % (n, origine, nota)
        t.segnala(12, peso, R.F_ACCESSI, testo,
                  tr(u'Dal %s al %s (UTC), fino a %d tentativi in 10 minuti. Utenti provati: %s.%s')
                  % (T(primo), T(ultimo), massimo, u', '.join(sorted(provati)[:10]),
                     tr(u' Primo accesso riuscito dopo l\'inizio della raffica (%s): %s.') % (T(inizio_raffica), T(riuscito))
                     if riuscito else u''),
                  inizio_raffica or primo, elemento, attacco, oggetti=(R.chiave(u'ip', origine),))
    for chiave, v in rac.logon.items():
        if R.host_di_attacco(chiave[2]) and chiave[2].lower() not in [c[1].lower() for c in candidati]:
            t.segnala(11, R.DA_CONFERMARE, R.F_ACCESSI,
                      tr(u'Accesso riuscito da un computer chiamato \u00ab%s\u00bb come %s') % (chiave[2], chiave[0]),
                      tr(u'Nome predefinito di una distribuzione usata per gli attacchi. %s, primo: %s - ultimo: %s (UTC).')
                      % (quante_volte(v[0]), T(v[1]), T(v[2])), v[1], elemento, True,
                      oggetti=(R.chiave(u'host', chiave[2]), R.chiave(u'ip', chiave[1])))
    if pubbliche >= 20:
        t.segnala(12, R.INFORMATIVO, R.F_ACCESSI,
                  tr(u'Accessi falliti da %d indirizzi pubblici diversi: la macchina \u00e8 esposta a Internet') % pubbliche,
                  tr(u'\u00c8 il rumore di fondo dei tentativi automatici: conta se uno di questi indirizzi poi entra.'), 0, elemento)
    # --- controllo 14: sessioni RDP
    righe = []
    tutte = {}
    for (utente, indirizzo), v in rac.rdp.items():
        tutte[(utente, indirizzo, u'LocalSessionManager 21/22/25')] = v
    for (utente, indirizzo), v in rac.rdp_autenticati.items():
        tutte[(utente, indirizzo, u'RemoteConnectionManager 1149')] = v
    visti = set()
    for (utente, indirizzo, fonte), v in sorted(tutte.items(), key=lambda x: -x[1][2]):
        pubblico = R.ip_pubblico(indirizzo)
        righe.append((not pubblico, -v[2], [utente, indirizzo, unicode(v[0]), T(v[1]), T(v[2]), fonte,
                                            tr(u'indirizzo pubblico') if pubblico else u'']))
        if pubblico and indirizzo not in visti and len(visti) < 15:
            visti.add(indirizzo)
            t.segnala(14, R.DA_CONFERMARE, R.F_ACCESSI,
                      tr(u'Sessione RDP da un indirizzo pubblico: %s come %s (%s)') % (indirizzo, utente, _eventi(v[0])),
                      tr(u'Primo: %s - ultimo: %s (UTC). Fonte: %s.%s')
                      % (T(v[1]), T(v[2]), fonte,
                         tr(u' Lo stesso indirizzo compare anche nei 4624.') if indirizzo in segnalati else u''),
                      v[1], v[3] if len(v) > 3 else None, oggetti=(R.chiave(u'ip', indirizzo),))
    righe.sort()
    t.tabella(14, tr(u'Sessioni RDP in entrata (Terminal Services)'),
              [tr(u'Utente'), tr(u'Indirizzo'), tr(u'Eventi'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)'), tr(u'Fonte'), tr(u'Nota')],
              [x[2] for x in righe[:50]])
    if (u'microsoft-windows-terminalservices-localsessionmanager%4operational.evtx' in rac.copertura
            or u'microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx' in rac.copertura
            or rac.rdp or rac.rdp_autenticati):
        t.fatto(14)
    else:
        t.esito(14, 'assente', tr(u'registri di Terminal Services non trovati'))


def _espliciti(t, rac):
    righe = []
    nomi = _nomi_macchina(t, rac)
    sicurezza = rac.copertura.get(u'security.evtx')
    elemento = sicurezza[3] if sicurezza else None
    segnalati = 0
    for chiave, v in sorted(rac.espliciti.items(), key=lambda x: -x[1][2]):
        soggetto, bersaglio, server, processo, ip = chiave
        righe.append([soggetto, bersaglio, server, processo, unicode(v[0]), T(v[1]), T(v[2])])
        basso = server.lower().rstrip(u'$')
        remoto = basso and basso not in (u'localhost', u'-') and basso.split(u'.')[0] not in nomi
        if remoto and processo in _PROCESSI_LATERALI and segnalati < 10 and not soggetto.endswith(u'$'):
            segnalati += 1
            t.segnala(13, R.DA_CONFERMARE, R.F_LATERALE,
                      tr(u'Credenziali esplicite verso %s: %s usa l\'account %s da %s') % (server, soggetto, bersaglio, processo),
                      tr(u'Evento 4648, %s. Primo: %s - ultimo: %s (UTC).') % (quante_volte(v[0]), T(v[1]), T(v[2])), v[1], elemento,
                      oggetti=(R.chiave(u'host', server.rstrip(u'$')),))
    t.tabella(13, tr(u'Credenziali esplicite (4648): le 30 combinazioni pi\u00f9 recenti'),
              [tr(u'Chi'), tr(u'Account usato'), tr(u'Verso'), tr(u'Processo'), tr(u'Volte'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)')], righe[:30])
    righe = []
    for server, v in sorted(rac.rdp_uscita.items(), key=lambda x: -x[1][2]):
        righe.append([server, unicode(v[0]), T(v[1]), T(v[2])])
    t.tabella(13, tr(u'RDP in uscita (registro RDPClient)'), [tr(u'Server'), tr(u'Eventi'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)')], righe[:30])
    if sicurezza is not None:
        t.fatto(13)


def _servizi(t, rac):
    sistema = rac.copertura.get(u'system.evtx')
    if sistema is None and not rac.servizi:
        t.esito(18, 'assente', tr(u'System.evtx non valido') if u'system.evtx' in [e.nome.lower() for e in rac.non_validi]
                else tr(u'System.evtx non trovato'))
        return
    gruppi = {}
    for s in rac.servizi:
        chiave = (s['nome'], s['percorso'])
        g = gruppi.get(chiave)
        if g is None:
            g = {'n': 0, 'primo': s['ora'], 'ultimo': s['ora'], 's': s, 'fonti': set()}
            gruppi[chiave] = g
        g['n'] += 1
        g['primo'] = min(g['primo'], s['ora'])
        g['ultimo'] = max(g['ultimo'], s['ora'])
        g['fonti'].add(s['fonte'])
    righe = []
    scadenze = {}
    for ora, n in rac.timeout:
        scadenze.setdefault(n, []).append(ora)
    for elenco in scadenze.values():
        elenco.sort()
    for (nome, percorso), g in gruppi.items():
        s = g['s']
        peso, controllo, famiglia, motivi = tc_c_registro.giudica_servizio(nome, percorso)
        if controllo == 17:
            controllo = 18
        # il primo timeout dopo l'installazione, cercato con la bisezione:
        # con migliaia di servizi omonimi un ciclo su tutti sarebbe quadratico
        elenco = scadenze.get(nome, ())
        k = bisect.bisect_left(elenco, g['primo'])
        scaduto = k < len(elenco) and elenco[k] - g['primo'] <= 120
        if scaduto:
            motivi.append(tr(u'seguito dal timeout 7009: il programma non si comporta da servizio'))
            if not peso:
                peso = R.INFORMATIVO
        if peso == R.DA_CONFERMARE and len(motivi) == 1 and R.zona(R.spezza_comando(percorso)[0]) == u'temporanea' \
                and _in_preparazione(t, g['primo'], 48, s.get('computer') or u''):
            # il servizio di un programma di installazione, durante l'installazione di Windows
            peso = R.INFORMATIVO
            motivi.append(tr(u'durante l\'installazione di Windows: di solito \u00e8 il servizio temporaneo di un '
                             u'programma di installazione'))
        strumento = R.trova_rmm(nome + u' ' + percorso)
        if strumento:
            t.prova_rmm(strumento, tr(u'servizio installato (evento %s)') % u'/'.join(sorted(g['fonti'])),
                        u'%s: %s' % (nome, percorso[:300]), g['primo'], s['elemento'], 32, genere='installato')
        motivo = u'; '.join(motivi)
        if peso:
            volte = tr(u' (%d volte)') % g['n'] if g['n'] > 1 else u''
            segnale = t.segnala(controllo, peso, famiglia, tr(u'Servizio installato \u00ab%s\u00bb%s: %s') % (nome, volte, motivo),
                      tr(u'%s\nTipo: %s - avvio: %s - account: %s\nPrimo: %s - ultimo: %s (UTC) - evento %s')
                      % (percorso[:1500], s['tipo'], s['avvio'], s['account'], T(g['primo']), T(g['ultimo']),
                         u'/'.join(sorted(g['fonti']))), g['primo'], s['elemento'],
                      oggetti=(R.chiave(u'servizio', nome), R.chiave_programma(percorso, True)))
        riga = [T(g['primo']), nome, percorso[:300], s['tipo'], s['account'], unicode(g['n']), R.NOME_PESO.get(peso, u''), motivo]
        if peso:
            tc_c_registro.candidato_acquisizione(t, segnale, nome, percorso, g['primo'], riga, 6)
        righe.append((g['ultimo'], riga))
    righe.sort(key=lambda x: -x[0])
    t.tabella(18, tr(u'Servizi installati (eventi 7045 e 4697): i 40 pi\u00f9 recenti'),
              [tr(u'Installato (UTC)'), tr(u'Nome'), tr(u'Percorso'), tr(u'Tipo'), u'Account', tr(u'Volte'), tr(u'Peso'), tr(u'Motivo')],
              [x[1] for x in righe[:40]])
    t.fatto(18, 29)


def _coppie(create, cancellate):
    """Abbina ogni creazione alla prima cancellazione successiva della
    stessa attivita'. Restituisce [(creazione, cancellazione, secondi)]."""
    per_nome = {}
    for c in cancellate:
        per_nome.setdefault(c['nome'], []).append(c)
    for elenco in per_nome.values():
        elenco.sort(key=lambda x: x['ora'])
    prossima = {}       # nome -> indice della prima cancellazione non ancora usata
    coppie = []
    for c in sorted(create, key=lambda x: x['ora']):
        elenco = per_nome.get(c['nome'])
        if not elenco:
            continue
        k = prossima.get(c['nome'], 0)
        # le cancellazioni precedenti a questa creazione non serviranno
        # nemmeno alle creazioni successive: si saltano una volta per tutte
        while k < len(elenco) and elenco[k]['ora'] < c['ora'] - 0.001:
            k += 1
        if k < len(elenco):
            d = elenco[k]
            coppie.append((c, d, max(0.0, d['ora'] - c['ora'])))
            k += 1
        prossima[c['nome']] = k
    return coppie


def _azione_da_atexec(azioni):
    """Vero se tra le azioni dell'attivita' ce n'e' una che puo' essere di
    atexec o di un attaccante: un interprete, oppure un programma che la
    valutazione delle righe di comando trova almeno sospetto."""
    for comando, argomenti in azioni:
        g = R.valuta_comando(comando, argomenti)
        if g.interprete or g.livello >= 2 or R.strumento(g.nome)[0] >= R.DA_CONFERMARE:
            return True
    return False


def _attivita(t, rac):
    if not (rac.attivita_create or rac.attivita_registrate or rac.conteggi.get(4698)):
        t.esito(27, 'non verificabile',
                tr(u'nessun evento 4698 n\u00e9 106: la creazione delle attivit\u00e0 non \u00e8 registrata'))
    else:
        t.fatto(27, 28)
    righe = []
    viste = set()
    for fonte, create, cancellate in ((u'Security 4698/4699', rac.attivita_create, rac.attivita_cancellate),
                                      (u'TaskScheduler 106/141', rac.attivita_registrate, rac.attivita_rimosse)):
        for c, d, secondi in _coppie(create, cancellate):
            if secondi >= 60:
                continue
            nome = c['nome']
            base = nome.split(u'\\')[-1]
            in_radice = nome.count(u'\\') <= 1
            azioni = c.get('azioni') or []
            azione = u'; '.join([(a + u' ' + b).strip() for a, b in azioni])
            if not azione and nome in rac.attivita_azioni:
                azione = u'; '.join(sorted(rac.attivita_azioni[nome]))
            chiave = (nome, int(c['ora']))
            if secondi < 2 and in_radice:
                casuale = R.nome_casuale(base)
                if casuale and azioni and not _azione_da_atexec(azioni):
                    # l'evento riporta l'azione ed e' un programma qualunque:
                    # la forma del nome da sola non fa una firma
                    casuale = False
                peso = R.DECISIVO if casuale else R.DA_CONFERMARE
                if chiave not in viste:
                    t.segnala(27, peso, R.F_LATERALE,
                              tr(u'Attivit\u00e0 \u00ab%s\u00bb creata e cancellata in %d ms%s')
                              % (nome, int(secondi * 1000),
                                 tr(u': nome di 8 lettere a caso nella cartella radice, come fa atexec') if casuale else u''),
                              tr(u'Creata da %s il %s (UTC). Azione: %s\nFonte: %s')
                              % (c['utente'], T(c['ora']), azione or tr(u'(non registrata)'), fonte), c['ora'], c['elemento'],
                              oggetti=(R.chiave(u'attivita', nome),))
            else:
                peso = R.INFORMATIVO
            viste.add(chiave)
            righe.append((c['ora'], [nome, T(c['ora']), T(d['ora']), u'%.3f s' % secondi, c['utente'], azione[:300],
                                     fonte, R.NOME_PESO[peso]]))
    righe.sort(key=lambda x: -x[0])
    t.tabella(27, tr(u'Attivit\u00e0 create e cancellate entro un minuto'),
              [tr(u'Attivit\u00e0'), tr(u'Creata (UTC)'), tr(u'Cancellata (UTC)'), tr(u'Durata'), tr(u'Utente'), tr(u'Azione'), tr(u'Fonte'), tr(u'Peso')],
              [x[1] for x in righe[:50]])
    # firme di atexec e azioni sospette nelle attivita' create (4698) o modificate (4702)
    presenti = set(t.attivita.keys()) | set((t.contesto.get('attivita_file') or {}).keys())
    gia = set()
    for c in rac.attivita_create + rac.attivita_aggiornate:
        firma = tc_c_registro.firma_atexec(c['nome'], c['azioni'], c['avvii'])
        comandi = u'\n'.join([(a + u' ' + b).strip() for a, b in c['azioni']])
        if firma:
            if (c['nome'], firma[1]) in gia:
                continue
            gia.add((c['nome'], firma[1]))
            t.segnala(28, firma[0], R.F_LATERALE, tr(u'Attivit\u00e0 \u00ab%s\u00bb: %s') % (c['nome'], firma[1]),
                      tr(u'Creata da %s il %s (UTC).\n%s') % (c['utente'], T(c['ora']), comandi[:1500]), c['ora'], c['elemento'],
                      oggetti=(R.chiave(u'attivita', c['nome']),))
            continue
        # Un'attivita' puo' essere creata innocua e poi ricreata o modificata
        # con un'altra azione: si giudica ogni versione diversa. Quella che
        # esiste ancora, con l'azione che ha adesso, la valuta il controllo 15.
        versione = (c['nome'].lower(), tuple(c['azioni']))
        if versione in gia or (c['nome'].lower() in presenti and not _azione_diversa(t, c)):
            continue
        gia.add(versione)
        etichetta = tr(u'Attivit\u00e0 pianificata non pi\u00f9 presente')
        if c['nome'].lower() in presenti:
            etichetta = tr(u'Attivit\u00e0 pianificata, azione di una versione precedente')
        for comando, argomenti in c['azioni']:
            if comando:
                tc_c_registro.giudica_persistenza(
                    t, 15, etichetta, c['nome'], comando, argomenti, ora=c['ora'],
                    elemento=c['elemento'], nota=tr(u'Creata da %s (evento 4698 o 4702).') % c['utente'])


def _azione_diversa(t, c):
    """Vero se l'attivita' vista nell'evento ha azioni diverse da quelle
    che la stessa attivita' ha oggi sul disco."""
    oggi = set()
    voce = t.attivita.get(c['nome'].lower())
    if voce:
        oggi |= set([((a[1] or u'').strip().lower(), (a[2] or u'').strip().lower()) for a in voce['azioni'] if a[0] == u'exec'])
    voce = (t.contesto.get('attivita_file') or {}).get(c['nome'].lower())
    if voce:
        oggi |= set([((a or u'').strip().lower(), (b or u'').strip().lower()) for a, b in voce['azioni']])
    allora = set([((a or u'').strip().lower(), (b or u'').strip().lower()) for a, b in c['azioni']])
    return bool(allora - oggi)


def _condivisioni(t, rac):
    if not rac.conteggi.get(5145):
        t.esito(31, 'non verificabile', tr(u'nessun evento 5145: l\'audit dettagliato delle condivisioni non \u00e8 attivo'))
        return
    t.fatto(31)
    gruppi = {}
    for (classe, ip, utente, share, bersaglio), v in rac.condivisioni.items():
        g = gruppi.setdefault((classe, ip, utente), {'n': 0, 'primo': v[1], 'ultimo': v[2], 'esempi': [],
                                                      'elemento': v[3] if len(v) > 3 else None})
        g['n'] += v[0]
        g['primo'] = min(g['primo'], v[1])
        g['ultimo'] = max(g['ultimo'], v[2])
        if len(g['esempi']) < 5:
            g['esempi'].append(u'%s\\%s' % (share, bersaglio))
    testi = {
        u'output': (R.DECISIVO, R.F_LATERALE, tr(u'accesso al file di output di Impacket (__output di smbexec o __<numeri> di wmiexec)'), False),
        u'tmp': (R.DECISIVO, R.F_LATERALE, tr(u'lettura di un file .tmp di 8 lettere in Temp tramite ADMIN$ (output di atexec)'), False),
        u'svcctl': (R.DA_CONFERMARE, R.F_LATERALE, tr(u'gestione remota dei servizi (pipe svcctl): la usano smbexec e PsExec, ma anche gli amministratori'), False),
        u'atsvc': (R.DA_CONFERMARE, R.F_LATERALE, tr(u'attivit\u00e0 pianificate remote (pipe atsvc): la usa atexec, ma anche gli amministratori'), False),
        u'tmp8': (R.DA_CONFERMARE, R.F_LATERALE, tr(u'lettura tramite ADMIN$ di un file .tmp di 8 lettere in Temp: lo fa atexec, ma qui il nome non sembra casuale'), False),
        u'psexec': (R.DA_CONFERMARE, R.F_LATERALE, tr(u'PsExec o un suo clone da remoto'), True),
        u'exe8': (R.DA_CONFERMARE, R.F_LATERALE, tr(u'caricamento in ADMIN$ di un .exe con nome di 8 lettere a caso (tipico di psexec.py)'), True),
    }
    righe = []
    for (classe, ip, utente), g in sorted(gruppi.items(), key=lambda x: x[1]['primo']):
        peso, famiglia, testo, extra = testi[classe]
        t.segnala(31, peso, famiglia, tr(u'Da %s come %s: %s (%s)') % (ip, utente, testo, _eventi(g['n'])),
                  tr(u'Primo: %s - ultimo: %s (UTC)\n%s') % (T(g['primo']), T(g['ultimo']), u'\n'.join(g['esempi'])),
                  g['primo'], g['elemento'], extra, oggetti=(R.chiave(u'ip', ip),))
        righe.append([ip, utente, u'; '.join(g['esempi'][:3]), unicode(g['n']), T(g['primo']), T(g['ultimo']), R.NOME_PESO[peso]])
    t.tabella(31, tr(u'Accessi alle share tipici dell\'esecuzione remota (5145)'),
              [tr(u'Indirizzo'), tr(u'Utente'), tr(u'Oggetto'), tr(u'Eventi'), tr(u'Primo (UTC)'), tr(u'Ultimo (UTC)'), tr(u'Peso')], righe)


def _processi(t, rac):
    if not rac.processi_totali and not rac.powershell:
        t.esito(25, 'non verificabile',
                tr(u'nessun evento 4688 n\u00e9 Sysmon: l\'audit della creazione dei processi non \u00e8 attivo'))
        return
    t.fatto(25)
    righe = []
    for r in sorted(rac.processi.values(), key=lambda x: (-x['peso'], x['primo'])):
        volte = tr(u' (%d volte)') % r['n'] if r['n'] > 1 else u''
        motivo = r['motivo'] or tr(u'comando segnalato')
        if R.sui_registri(motivo) and _vicino_installazione(t, r['primo']):
            # come per gli eventi 1102 e 104: chi prepara un'immagine di
            # Windows svuota i registri prima di distribuirla
            r['peso'] = R.INFORMATIVO
            motivo += tr(u' (a ridosso dell\'installazione di Windows)')
            r['motivo'] = motivo
        elif r['peso'] == R.DA_CONFERMARE and r.get('chiaro') and _in_preparazione(t, r['primo'], 48, r.get('computer') or u''):
            # i comandi codificati degli script che preparano la macchina (Packer e simili)
            r['peso'] = R.INFORMATIVO
            motivo += tr(u' (durante l\'installazione di Windows: uno script di preparazione della macchina)')
            r['motivo'] = motivo
        mostrato = r['riga'] if len(r['righe']) <= 1 else r['processo']
        chiaro = u''
        if r.get('chiaro'):
            chiaro = tr(u'\nComando in chiaro: ') + u' '.join(r['chiaro'].split())[:1200]
        t.segnala(25, r['peso'], r['famiglia'], u'%s%s: %s' % (motivo[0].upper() + motivo[1:], volte, mostrato[:160]),
                  tr(u'%s%s\nProcesso padre: %s - utente: %s\nPrimo: %s - ultimo: %s (UTC) - fonte: %s')
                  % (u'\n'.join(r['righe'])[:2500], chiaro, r['padre'] or u'-', r['utente'], T(r['primo']),
                     T(r['ultimo']), r['fonte']),
                  r['primo'], r['elemento'], oggetti=_oggetti_processo(r))
        righe.append((r['primo'], [T(r['primo']), unicode(r['n']), r['riga'][:400], R.nome_base(r['padre']), r['utente'],
                                   r['motivo'], R.NOME_PESO[r['peso']]]))
    for r in sorted(rac.powershell.values(), key=lambda x: (-x['peso'], x['ora'])):
        famiglia = r.get('famiglia') or (R.F_STRUMENTI if r['peso'] == R.DECISIVO else R.F_ESECUZIONE)
        if r['peso'] == R.DA_CONFERMARE and r.get('codificato') and _in_preparazione(t, r['ora'], 48, r.get('computer') or u''):
            r['peso'] = R.INFORMATIVO
            r['motivo'] += tr(u' (durante l\'installazione di Windows: uno script di preparazione della macchina)')
        dove = tr(u'blocco di script (4104)') if r['fonte'] == u'4104' else tr(u'avvio di PowerShell (400)')
        oggetti = tuple(r.get('oggetti') or ())
        account = R.account_del_comando(r['estratto'])
        if account:
            # il blocco che crea un account e l'evento 4720 di quell'account sono un fatto solo
            oggetti += (R.chiave(u'account', account),)
        if R.sui_registri(r['motivo'] or u''):
            oggetti += R.chiavi_tempo(u'pulizia', r['ora'])
        t.segnala(25, r['peso'], famiglia, u'PowerShell, %s: %s' % (dove, r['motivo']),
                  tr(u'%s%s\nPrimo: %s (UTC) - %s') % (u'File: %s\n' % r['percorso'] if r['percorso'] else u'',
                                                      r['estratto'][:1500], T(r['ora']), quante_volte(r['n'])),
                  r['ora'], r['elemento'], True, oggetti=oggetti)
        righe.append((r['ora'], [T(r['ora']), unicode(r['n']), r['estratto'][:400], u'PowerShell', r['utente'], r['motivo'],
                                 R.NOME_PESO[r['peso']]]))
    momenti = [(ora, nome, None) for ora, nome, utente, riga in rac.ricognizione]
    righe_r = {}
    for ora, nome, utente, riga in rac.ricognizione:
        righe_r.setdefault(int(ora), []).append(riga or nome)
    sicurezza = rac.copertura.get(u'security.evtx')
    for inizio, fine, nomi, _ in tc_c_registro.raffiche(momenti):
        esempi = []
        for ora in sorted(righe_r.keys()):
            if inizio - 1 <= ora <= fine + 1:
                esempi.extend(righe_r[ora])
        t.segnala(25, R.DA_CONFERMARE, R.F_ESECUZIONE,
                  tr(u'Ricognizione: %d comandi diversi in %d minuti (%s)')
                  % (len(nomi), max(1, int((fine - inizio) / 60) + 1), u', '.join(sorted(nomi))),
                  tr(u'Dal %s al %s (UTC).\n%s') % (T(inizio), T(fine), u'\n'.join(esempi[:25])), inizio,
                  sicurezza[3] if sicurezza else None)
        righe.append((inizio, [T(inizio), unicode(len(esempi)), u'; '.join(esempi[:8])[:400], u'', u'',
                               tr(u'ricognizione'), R.NOME_PESO[R.DA_CONFERMARE]]))
    righe.sort(key=lambda x: x[0])
    t.tabella(25, tr(u'Comandi segnalati (4688, Sysmon, PowerShell)'),
              [tr(u'Primo (UTC)'), tr(u'Volte'), tr(u'Comando'), tr(u'Padre'), tr(u'Utente'), tr(u'Motivo'), tr(u'Peso')], [x[1] for x in righe[:80]],
              tr(u'Processi registrati: %d, di cui %d con riga di comando.') % (rac.processi_totali, rac.processi_con_riga))


def _account(t, rac):
    righe = []
    dc = t.contesto.get('controller_di_dominio')
    computer = (t.contesto.get('computer') or u'').lower()
    creati = {}
    aggiunti = {}
    for a in sorted(rac.account, key=lambda x: x['ora']):
        ident = a['id']
        nome = a['bersaglio'].split(u'\\')[-1]
        di_sistema = a['soggetto'].endswith(u'$') or a['soggetto'].lower().endswith(u'anonymous logon') \
            or a['soggetto'].lower().endswith(u'\\system')
        # eventi scritti durante l'installazione di Windows o la promozione a
        # controller di dominio: li fa il sistema, spesso con il nome
        # provvisorio del computer
        # durante l'installazione l'orologio puo' essere sfasato di un fuso
        # orario intero, e l'account macchina porta ancora il nome provvisorio
        chi = a['soggetto'].split(u'\\')[-1].lower()
        provvisorio = chi.endswith(u'$') and _RX_NOME_PROVVISORIO.match(chi[:-1]) is not None \
            and chi[:-1] != (a.get('computer') or computer)
        # Un evento con un nome di computer diverso da quello attuale non e' per
        # questo dell'installazione: il computer puo' essere stato rinominato dopo
        # (gli eventi di prima hanno il nome vecchio). Conta solo il momento.
        vicino = di_sistema and (_in_preparazione(t, a['ora'], 15, a.get('computer') or u'') or provvisorio or
                                 a['soggetto'].lower().endswith(u'anonymous logon'))
        segno = u''
        if ident == 4720:
            if nome.lower() not in tc_c_registro._ACCOUNT_PREDEFINITI and not nome.endswith(u'$') and not vicino:
                g = creati.setdefault(a['bersaglio'], {'n': 0, 'primo': a, 'ultimo': a})
                g['n'] += 1
                g['ultimo'] = a
                segno = u'*'
        elif ident in (4728, 4732, 4756):
            sid = a['sid_bersaglio']
            gruppo = _GRUPPI_PRIVILEGIATI.get(sid, u'')
            if not gruppo and sid.endswith((u'-512', u'-519', u'-518')):
                gruppo = {u'512': u'Domain Admins', u'519': u'Enterprise Admins', u'518': u'Schema Admins'}[sid[-3:]]
            if gruppo and not vicino:
                membro = a['nome_membro'] if a['nome_membro'] not in (u'', u'-') else a['membro']
                aggiunti.setdefault((membro, gruppo, a['membro']), a)
                segno = u'*'
        righe.append([T(a['ora']), u'%d %s' % (ident, tr(_NOME_EVENTO_ACCOUNT.get(ident, u''))), a['soggetto'], a['bersaglio'],
                      a['nome_membro'] if a['nome_membro'] not in (u'', u'-') else a['membro'], segno])
    sospetti = {}         # account appena creati o aggiunti agli amministratori: nome -> come
    nomi_sid = dict([(a['sid_bersaglio'], a['bersaglio'].split(u'\\')[-1]) for a in rac.account
                     if a['id'] == 4720 and a['sid_bersaglio']])
    for bersaglio, g in creati.items():
        a = g['primo']
        if dc:
            peso = R.INFORMATIVO      # su un controller di dominio creare utenti e' ordinaria amministrazione
        else:
            peso = R.DA_CONFERMARE if t.recente(a['ora']) else R.INFORMATIVO
        if peso >= R.DA_CONFERMARE:
            sospetti[bersaglio.split(u'\\')[-1].lower()] = tr(u'creato il %s UTC (evento 4720)') % T(a['ora'])
        volte = tr(u' (%d eventi)') % g['n'] if g['n'] > 1 else u''
        t.segnala(10, peso, R.F_ACCOUNT, tr(u'Account \u00ab%s\u00bb creato da %s%s') % (bersaglio, a['soggetto'], volte),
                  tr(u'Evento 4720 del %s (UTC).') % T(a['ora']), a['ora'], a['elemento'],
                  oggetti=(R.chiave(u'account', bersaglio.split(u'\\')[-1]), R.chiave(u'sid', a.get('sid_bersaglio'))))
    for (membro, gruppo, sid), a in aggiunti.items():
        if sid.endswith(u'-501') and gruppo == u'Administrators':
            peso = R.DECISIVO
            testo = tr(u'L\'account Guest \u00e8 stato aggiunto al gruppo Administrators da %s') % a['soggetto']
        else:
            peso = R.DA_CONFERMARE if t.recente(a['ora']) else R.INFORMATIVO
            testo = tr(u'%s aggiunto al gruppo %s da %s') % (membro, gruppo, a['soggetto'])
        nome = nomi_sid.get(sid) or membro.split(u'\\')[-1]
        if peso >= R.DA_CONFERMARE and gruppo == u'Administrators' and not nome.upper().startswith(u'S-1-'):
            sospetti.setdefault(nome.lower(), tr(u'aggiunto al gruppo Administrators il %s UTC (evento %d)') % (T(a['ora']), a['id']))
        t.segnala(10, peso, R.F_ACCOUNT, testo, tr(u'Evento %d del %s (UTC).') % (a['id'], T(a['ora'])),
                  a['ora'], a['elemento'], peso == R.DECISIVO,
                  oggetti=(R.chiave(u'account', membro.split(u'\\')[-1]), R.chiave(u'sid', sid)))
    if sospetti:
        # nella RAM, processi attivi con l'utente di uno di questi account: l'account e' in uso
        tc_memoria.account_in_memoria(t, sospetti)
    t.tabella(10, tr(u'Eventi sugli account (creazione, gruppi, password): gli ultimi 60'),
              [tr(u'Quando (UTC)'), tr(u'Evento'), tr(u'Da chi'), tr(u'Su'), tr(u'Membro'), tr(u'Segnalato')], righe[-60:])


def _senza_prefisso(percorso):
    """Il percorso di un rilevamento di Defender senza il tipo davanti
    ("file:_C:\\Users\\...", "containerfile:_...")."""
    if u':_' in percorso[:20]:
        return percorso.split(u':_', 1)[1]
    return percorso


def _oggetti_processo(r):
    """Le chiavi di un comando segnalato dagli eventi 4688 o Sysmon: ogni riga
    di comando del gruppo, il programma (se non e' di Windows), il comando in
    chiaro."""
    chiavi = list(R.oggetti_comando(r['riga'], r['processo'], r.get('chiaro') or u''))
    for riga in r['righe']:
        k = R.chiave_comando(riga)
        if k and k not in chiavi:
            chiavi.append(k)
    if R.sui_registri(r['motivo'] or u''):
        # il comando che cancella i registri e gli eventi 1102 e 104 della cancellazione sono lo stesso fatto
        chiavi.extend(R.chiavi_tempo(u'pulizia', r['primo']))
    return tuple(chiavi)


def _defender(t, rac):
    presente = u'microsoft-windows-windows defender%4operational.evtx' in rac.copertura
    if not presente and not rac.defender:
        t.esito(37, 'assente', tr(u'registro di Windows Defender non trovato'))
    else:
        t.fatto(37)
    per_minaccia = {}
    righe = []
    for r in sorted(rac.defender.values(), key=lambda x: x['ora']):
        g = per_minaccia.setdefault(r['minaccia'], {'n': 0, 'primo': r['ora'], 'ultimo': r['ora'], 'esempi': [],
                                                    'azione': True, 'elemento': r['elemento'], 'utente': r['utente']})
        g['n'] += 1
        g['ultimo'] = max(g['ultimo'], r['ora'])
        if not r['azione']:
            g['azione'] = False
        if len(g['esempi']) < 4 and r['percorso'] not in g['esempi']:
            g['esempi'].append(r['percorso'])
        righe.append([T(r['ora']), r['minaccia'], r['gravita'], r['percorso'][:300], r['utente'],
                      R.nome_base(r['processo']), tr(u's\u00ec') if r['azione'] else tr(u'non registrata')])
    viste = t.contesto.setdefault('minacce_viste', set())
    for minaccia, g in per_minaccia.items():
        peso = R.peso_minaccia(minaccia)
        viste.add(minaccia)
        t.segnala(37, peso, R.F_ANTIVIRUS,
                  (tr(u'Defender ha rilevato %s (1 volta)') % minaccia) if g['n'] == 1 else
                  (tr(u'Defender ha rilevato %s (%d volte)') % (minaccia, g['n'])),
                  tr(u'Primo: %s - ultimo: %s (UTC) - utente: %s\n%s\n%s')
                  % (T(g['primo']), T(g['ultimo']), g['utente'], u'\n'.join(g['esempi'])[:1500],
                     tr(u'Azione di rimozione registrata (evento 1117).') if g['azione'] else
                     tr(u'Nessuna azione di rimozione registrata per almeno un rilevamento.')),
                  g['primo'], g['elemento'],
                  oggetti=(R.chiave(u'minaccia', minaccia),) + tuple([R.chiave_file(_senza_prefisso(x)) for x in g['esempi']]))
    t.tabella(37, tr(u'Rilevamenti di Windows Defender (eventi 1116 e 1117)'),
              [tr(u'Quando (UTC)'), tr(u'Minaccia'), tr(u'Gravit\u00e0'), tr(u'Dove'), tr(u'Utente'), tr(u'Processo'), tr(u'Rimozione')], righe[-80:])
    for m in rac.defender_modifiche:
        grave = m['id'] == 5007
        if grave and m.get('esclusione', u'Esclusione' in m['testo']):
            basso = m['testo'].lower()
            grave = any([x in basso for x in (u'\\users\\public', u'\\temp', u'\\tmp', u'\\programdata =', u'\\appdata',
                                              u'paths\\c:\\ =', u'extensions\\', u'processes\\', u'\\perflogs',
                                              u'\\windows =', u'\\downloads')])
        if _vicino_installazione(t, m['ora'], 2):
            grave = False
        t.segnala(37, R.DA_CONFERMARE if grave else R.INFORMATIVO, R.F_ANTIFORENSE,
                  u'Defender: %s' % m['testo'][:300], tr(u'Evento %d del %s (UTC).') % (m['id'], T(m['ora'])), m['ora'],
                  m['elemento'], True)


def _rmm(t, rac):
    for r in rac.rmm:
        strumento = u'Pulseway' if r['strumento'].startswith(u'Pulseway') else r['strumento']
        t.sessione_rmm(strumento, r['ora'], tr(u'evento %s: %s') % (r['id'], r['testo'][:400]), r['elemento'], 36)
    for r in rac.installazioni:
        t.prova_rmm(r['strumento'], tr(u'installazione (MsiInstaller)'), r['prodotto'], r['ora'], r['elemento'], 32,
                    genere='installato')
    applicazioni = rac.copertura.get(u'application.evtx')
    if applicazioni is not None:
        t.fatto(36)
    else:
        t.esito(36, 'assente', tr(u'Application.evtx non trovato'))
