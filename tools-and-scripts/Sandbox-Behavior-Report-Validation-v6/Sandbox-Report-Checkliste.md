# Soll-Checkliste zur Sandbox-Report-Validierung

**118 konkrete Testschritte**, davon **8 rein synthetisch**. Nicht jede Aktion muss zwingend im Report stehen; manche Produkte aggregieren Ereignisse oder benötigen spezifische Erfassung.

## Bewertung

- **Gefunden**: korrekte Aktivität mit belastbarem Nachweis.
- **Teilweise**: nur allgemeines Ereignis ohne entscheidende Details.
- **Fehlt**: Aktion laut lokaler Ground Truth erfolgreich, im Report aber nicht belegt.
- **Nicht ausgeführt**: Test fehlgeschlagen oder deaktiviert.
- **Nicht unterstützt**: Produkt bietet den entsprechenden Reportbereich nicht an.

Bewerte separat **Verhalten**, **zeitliche Zusammenhänge**, **Artefakte/IOCs**, **Einordnung**, **ATT&CK-Mapping**, **Unsicherheit** und **Gesamtbewertung**. Ein fehlender Alarm ist nicht gleich fehlendes Verhalten. Synthetische Tests zählen ausschließlich als Dateiereignisse.

## Übergreifende Qualitätskriterien

- [ ] Hauptprozess, Start-/Endzeit und Kommandozeile vorhanden
- [ ] Parent-Child-Verknüpfungen korrekt
- [ ] Datei- und Registry-Pfade korrekt, inklusive Änderungen/Löschungen soweit unterstützt
- [ ] Netzwerk-Ziele, Zeit, Protokoll und HTTP-Methode soweit erfassbar
- [ ] Verhaltensketten CHAIN-01..03 in richtiger Reihenfolge zuordenbar
- [ ] Report grenzt harmloses von auffälligem Verhalten ab statt pauschal Malware zu melden
- [ ] IOC-Liste enthält nur tatsächlich beobachtete Werte
- [ ] ATT&CK-Zuordnungen werden nicht für SIM-Testartefakte als ausgeführte Technik behauptet
- [ ] Nicht erfasste Daten und Unsicherheit transparent gekennzeichnet


## Umgebungs-/Systemanalyse

- [ ] **DISC-01 – Windows version and OS information**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-02 – Computer hardware summary**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-03 – Process inventory**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-04 – Service inventory**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-05 – Current user and security context**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-06 – IP configuration**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-07 – Environment characteristics (no sandbox avoidance)**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Prozess- und Kommandoausfuehrung

- [ ] **PROC-01 – cmd.exe child process**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-02 – Nested PowerShell child process**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-03 – whoami.exe system-user query**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-04 – ipconfig.exe subprocess**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Dateioperation

- [ ] **FILE-01 – Create directories and marker text file**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-02 – Generate 64KiB deterministic binary sample**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-03 – Copy, rename and hash benign file**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-04 – Create benign ZIP archive**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-05 – NTFS alternate data stream**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-06 – Change file attributes inside lab directory**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-07 – Write-delete short-lived temporary marker**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-08 – Read file content and enumerate files**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Registry

- [ ] **REG-01 – Create HKCU test key and string property**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-02 – Modify registry marker string**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-03 – Create REG_DWORD and REG_BINARY values**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-04 – Read values and enumerate lab key**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-05 – Delete one registry marker**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Zeitverhalten

- [ ] **TIME-01 – Single timed delay**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **TIME-02 – Three short jitter-measurement samples**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Netzwerk

- [ ] **NET-01 – Resolve GET endpoint hostname using Windows DNS resolver**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.
- [ ] **NET-02 – Bounded HTTP(S) GET request with distinct lab user agent**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.
- [ ] **NET-03 – Repeated GET beacon-like requests with fixed intervals**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.
- [ ] **NET-04 – Synthetic-only JSON POST to explicitly approved HTTPS endpoint**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.

## Nur synthetisches Testartefakt

- [ ] **SIM-01 – Inert autorun registry example as JSON file only**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIM-02 – Inert scheduled-task example as JSON file only**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Signatur- und Dateimetadaten

- [ ] **SIGN-01 – Read Authenticode signature status of this script**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIGN-02 – Hash this script for report identity**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Umgebungs-/Systemanalyse

- [ ] **DISC-08 – Query OS installation and boot times**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-09 – Enumerate logical volumes**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-10 – Enumerate scheduled task names (read-only)**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-11 – List Windows hotfix metadata**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-12 – List limited local group descriptions**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-13 – Collect network route table metadata**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-14 – Read current proxy settings without modifying them**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-15 – Collect installed application metadata via uninstall registry**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-16 – List active Windows services with process IDs**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-17 – Read process architecture and execution context**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Prozess- und Kommandoausfuehrung

- [ ] **PROC-05 – Launch cmd child with redirected stdout**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-06 – Create sequential command-shell executions**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-07 – Spawn PowerShell child with non-sensitive test output**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-08 – Invoke hostname utility as child process**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-09 – Invoke tasklist utility as child process**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-10 – Invoke netstat for current local connections**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-11 – Create a short-lived background PowerShell job**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-12 – Inspect current PowerShell module list**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Dateioperation

- [ ] **FILE-09 – Generate deterministic 32 KB binary artifact**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-10 – Write Unicode and ASCII encoded markers**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-11 – Append to existing lab file**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-12 – Generate directory tree with files**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-13 – Create then rename a lab-owned directory**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-14 – Write and update isolated file attributes**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-15 – Modify then restore lab file timestamp**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-16 – Create NTFS alternate data stream where supported**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-17 – Compute SHA-256 and SHA-1 for own artifact**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-18 – Search own test files for unique marker**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-19 – Read own binary and create Base64 text copy**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-20 – Compress lab-owned marker files into second archive**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-21 – Expand lab-owned archive into run folder**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-22 – Create then remove temporary lab marker**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-23 – Inspect own file access control list**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Registry

- [ ] **REG-07 – Create and update nested lab registry subkey**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-08 – Create multiple string value under lab key**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-09 – Create expandable string without execution**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-10 – Change lab DWORD repeatedly**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-11 – Export lab registry key to REG file using reg.exe**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-12 – Delete nested lab registry subkey**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Signatur- und Dateimetadaten

- [ ] **SIGN-03 – Verify Authenticode status of Windows PowerShell executable**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIGN-04 – Hash built-in system executable as reference**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIGN-05 – Write harmless signature-enforcement test plan**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Zeitverhalten

- [ ] **TIME-03 – Measure short repeat intervals**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **TIME-04 – Measure bounded CPU calculation time**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **TIME-05 – Measure file I/O duration inside run directory**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **TIME-06 – Record UTC time and monotonic clock progression**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Netzwerk

- [ ] **NET-05 – Create loopback TCP listener and connect to it**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.
- [ ] **NET-06 – Transmit fixed benign payload over loopback UDP**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.
- [ ] **NET-07 – Inspect local connection summary after transport tests**  
  *Soll:* DNS/Verbindung/HTTP falls instrumentiert. *Klasse:* beobachtbare Aktion. *Bedingung:* nur wenn Netzwerk aktiv.

## Nur synthetisches Testartefakt

- [ ] **SIM-03 – Write inert injection scenario data (no injection)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIM-04 – Write inert service creation data (no service installed)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIM-05 – Write inert credential-access case (no credentials accessed)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIM-06 – Write inert defense-evasion case (no protection bypass)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Umgebungs-/Systemanalyse

- [ ] **DISC-18 – Read PowerShell host and execution configuration**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-19 – List bounded local TCP listeners**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-20 – Read installed Windows Defender status if available**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-21 – Read code integrity policy metadata if exposed**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-22 – Inspect bounded local DNS cache where supported**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **DISC-23 – Read system uptime and physical memory summary**  
  *Soll:* PowerShell-/WMI-Aktivitaet oder abgelegte Ergebnisse. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Prozess- und Kommandoausfuehrung

- [ ] **PROC-13 – Multi-level cmd.exe shell lineage**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess; cmd.exe -> cmd.exe mit LAB_NESTED_SHELL_MARKER. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-14 – PowerShell child writes bounded marker file**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-15 – PowerShell child writes standard error output**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-16 – Use certutil to hash lab-owned benign file**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess; certutil.exe mit -hashfile auf Labordatei. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **PROC-17 – Read limited command line and parent process details**  
  *Soll:* Prozessbaum / Kommandozeile / Kindprozess. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Dateioperation

- [ ] **FILE-24 – Create many small numbered benign artifacts**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-25 – Copy artifact through multiple lab directories**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-26 – Create harmless script and configuration file as artifacts only**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-27 – Create and inspect file hash manifest**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-28 – Write and read newline-delimited JSON records**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **FILE-29 – Create and delete isolated empty directories**  
  *Soll:* Dateiänderung, Dateiname, Hash oder Artefakt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Registry

- [ ] **REG-13 – Create short-lived Boolean-style lab configuration**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-14 – Read back own lab key and serialize values**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-15 – Update own key value in short series**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **REG-16 – Write and delete temporary string registry value**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Zeitverhalten

- [ ] **TIME-07 – Measure jitter for a sequence of bounded delays**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **TIME-08 – Compare wall-clock and monotonic elapsed time**  
  *Soll:* Zeitliche Folge und lokale Messdatei. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Signatur- und Dateimetadaten

- [ ] **SIGN-06 – Check signature of built-in Windows command shell**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIGN-07 – Read trusted file timestamp and checksum metadata**  
  *Soll:* Signatur- oder Hashinformation, soweit reportiert. *Klasse:* indirekt/optional. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Nur synthetisches Testartefakt

- [ ] **SIM-07 – Describe inert scheduled task example (not created)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **SIM-08 – Describe inert network lateral movement example (not executed)**  
  *Soll:* Nur Erstellung einer lokalen Simulationsdatei. *Klasse:* synthetisch. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Mehrstufige Verhaltenskette

- [ ] **CHAIN-01 – Sequence A: child-process then marker-file change**  
  *Soll:* Korrelation und zeitliche Abfolge mehrerer Aktionen; cmd.exe vor chain-a.txt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **CHAIN-02 – Sequence B: registry configuration then local file**  
  *Soll:* Korrelation und zeitliche Abfolge mehrerer Aktionen; HKCU-Änderung ChainB vor chain-b.txt. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
- [ ] **CHAIN-03 – Sequence C: archive generation after several file writes**  
  *Soll:* Korrelation und zeitliche Abfolge mehrerer Aktionen; vier Dateien vor chain-c.zip. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.

## Registry

- [ ] **REG-06 – Remove only this run HKCU key**  
  *Soll:* Registry-Pfad, Name und Änderung. *Klasse:* beobachtbare Aktion. *Bedingung:* Standard, vorbehaltlich Windows-Funktion und Optionen.
