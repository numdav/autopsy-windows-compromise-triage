# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# I nomi degli strumenti d'attacco usati come cosa da cercare (da chi indaga) non sono un'esecuzione
import tc_regole as R, tc_eventi
rac = tc_eventi.Raccolta()
sb = [0]
def prova(nome, ottenuto, atteso):
    if ottenuto != atteso:
        sb[0] += 1
        print 'NO  %s: atteso %r, ottenuto %r' % (nome, atteso, ottenuto)
def eseguito(riga):
    eseguibile, arg = R.spezza_comando(riga)
    return max([0] + [x[0] for x in rac._giudica_processo(eseguibile, R.con_estensione(R.nome_base(eseguibile)), riga)])
# (riga, e' solo una ricerca?, peso tra i comandi eseguiti, peso nella cronologia di PowerShell)
CASI = [
 (u'findstr /s /i mimikatz C:\\Logs\\*.log', True, 0, 1),
 (u'C:\\Windows\\System32\\findstr.exe /i "rubeus" C:\\Temp\\out.txt', True, 0, 1),
 (u'cmd /c dir /s /b C:\\*mimikatz*', True, 0, 1),
 (u'where /r C:\\ mimikatz.exe', True, 0, 1),
 (u'powershell -c "Get-ChildItem C:\\ -Recurse -Include *mimikatz* -ErrorAction SilentlyContinue"', True, 0, 1),
 (u'Get-ChildItem C:\\Users -Recurse | Select-String -Pattern "Invoke-Mimikatz"', True, 0, 1),
 (u'Get-Process | Where-Object { $_.Name -match "rubeus|sharphound" }', True, 0, 1),
 (u'Get-WinEvent -LogName Security | Where-Object { $_.Message -like "*mimikatz*" }', True, 0, 1),
 (u'reg query HKLM\\SOFTWARE /s /f mimikatz', True, 0, 1),
 (u'wevtutil qe Security /q:"*[EventData[Data=\'mimikatz.exe\']]"', True, 0, 1),
 (u'tasklist /fi "imagename eq mimikatz.exe"', True, 0, 1),
 (u'yara64.exe -r regole.yar C:\\Users\\Public\\mimikatz', True, 0, 1),
 # non sono ricerche
 (u'C:\\Tools\\mimikatz.exe privilege::debug', False, 3, 3),
 (u'cmd /c C:\\Tools\\Rubeus.exe kerberoast', False, 3, 3),
 (u'cmd /c dir C:\\Users\\Public & C:\\Users\\Public\\mimikatz.exe', False, 3, 3),
 (u'type C:\\Temp\\mimikatz.log', False, 3, 3),
 (u'cmd /c type C:\\Temp\\mimikatz.log | findstr Password', False, 3, 3),
 (u'cd C:\\dir\\mimikatz', False, 3, 3),
 (u'powershell -c "if ($x -eq 1) { .\\mimikatz.exe }"', False, 3, 3),
 (u'Rubeus.exe asktgt /user:a /filter x', False, 3, 3),
 (u'del C:\\Tools\\mimikatz.exe', False, 3, 3),
 (u'powershell -c "Invoke-Mimikatz -DumpCreds"', False, 3, 3),
 (u'ipconfig /all', False, 0, 0),
 (u'', False, 0, 0),
]
for riga, cerca, e, h in CASI:
    prova('solo_cercato  ' + riga[:60].encode('utf-8'), R.solo_cercato(riga), cerca)
    prova('eseguito      ' + riga[:60].encode('utf-8'), eseguito(riga) if riga else 0, e)
    r = R.riga_di_console(riga) if riga else None
    prova('cronologia    ' + riga[:60].encode('utf-8'), r[0] if r else 0, h)
prova('solo_cercato(None)', R.solo_cercato(None), False)
# uno strumento a doppio uso cercato per nome resta quello che era (da confermare nella cronologia)
r = R.riga_di_console(u'where psexec.exe')
prova('doppio uso cercato', r[0] if r else 0, 2)
print 'ricerche: prove fallite %d' % sb[0]
