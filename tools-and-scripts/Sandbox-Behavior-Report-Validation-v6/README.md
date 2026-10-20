# Windows Sandbox Behavior & Report Validation – V6

## Ziel
Ein eigenständiges, möglichst gut beobachtbares Windows-PowerShell-Testskript, das ausschließlich harmlose Aktionen ausführt. Anschließend kannst du den *gesamten Sandbox-Analysebericht* mit der dazugehörigen Soll-Checkliste vergleichen: Prozesse, Dateien, Registry, Netzwerk, zeitliche Ketten, erkannte Artefakte, ATT&CK-Zuordnungen und die Qualität der Interpretation.

## Dateien
- `Sandbox-Behavior-Validation.ps1`: Ausführbare PowerShell-Einzeldatei (PowerShell 5.1)
- `Sandbox-Report-Checkliste.md`: nach Themen gegliederte, manuell ausfüllbare Checkliste
- `Report-Checkliste.csv`: dieselbe Checkliste für Excel/LibreOffice
- `Soll-Katalog.json`: strukturierte Soll-Matrix für spätere Auswertung
- `Pruefe-Sandbox-Report.py`: optionaler, *vorsichtiger* Textsuch-Vorabgleich

## Start
```powershell
powershell.exe -NoProfile -File .\Sandbox-Behavior-Validation.ps1
```

Mit genehmigtem HTTPS-Testserver:
```powershell
.\Sandbox-Behavior-Validation.ps1 -GetUri 'https://example.com/' -PostUri 'https://DEIN-LAB-SERVER.example/ingest' -EnableSyntheticPost -BeaconCount 3 -DelaySeconds 2
```

Der GET-Standardendpunkt ist `https://example.com/`. Der POST erfolgt nur nach expliziter Aktivierung und sendet ausschließlich synthetische Markerdaten. Wenn du gar keinen Netzwerkverkehr möchtest: `-SkipNetwork` (und kein POST-Flag angeben). Nur HTTPS oder Loopback-HTTP; kein Credential-Zugriff, kein verstecktes Ausführen und kein Sicherheits-Bypass.

## Report-Auswertung
1. Im PowerShell-Arbeitsordner `%TEMP%\SandboxBehaviorTest\<Run-ID>\` `summary.json` und `events.jsonl` prüfen. `END/SUCCESS` ist der lokale Ausführungsnachweis; nicht jedes erfolgreich ausgeführte Kommando muss im Drittanbieter-Report stehen.
2. Sandbox-Report exportieren.
3. `Sandbox-Report-Checkliste.md` oder CSV öffnen und *jede* Soll-Aktion gegen die Reportdaten bewerten. Synthetische SIM-Fälle sind nur nachzuweisende Datei-Artefakte.
4. Optional Kandidaten vorfiltern:
```bash
python Pruefe-Sandbox-Report.py --report sandbox-report.json --ground-truth events.jsonl --output Review-Ergebnis.csv
```
5. Verhaltensinformationen, Zusammenhänge, Artefakte/IOCs, ATT&CK-Zuordnung und Gesamteinschätzung **getrennt** bewerten. Textsuche allein beweist keine Sandbox-Erkennung.

## Sicherheits- und Qualitätsgrenzen
- Nur Laborschlüssel in `HKCU:\Software\SandboxBehaviorTest\<Run-ID>`; Cleanup standardmäßig aktiviert. Keine echte Persistenz, Injection, Credential-Zugriffe, Fremddateiveränderung oder EDR-Umgehung.
- Manche Schritte benötigen Windows-spezifische Komponenten (z.B. NTFS ADS), bestimmte Rechte oder Internetzugang. Ein `ERROR` ist nicht gleich ein fehlender Sandbox-Eintrag.
- Die neuen CHAIN-Schritte messen Reihenfolge/Relationen, nicht bösartige Absicht.
- Klassifizierung und ATT&CK-Mapping sind **Analystenbewertungen**, keine Pflichtalarme. Eine gute Sandbox darf harmloses Verhalten als harmlos bewerten.
- Das Projekt ist hier statisch geprüft, aber **nicht** auf Windows ausgeführt worden.
