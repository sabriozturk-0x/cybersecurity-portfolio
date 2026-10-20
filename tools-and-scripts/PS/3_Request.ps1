# Nur für den Test, niemals mit echtem Key im Skript
$env:IT_API_KEY = "TRAINING_KEY_123"

$date = Get-Date -Format "yyyy-MM-dd"

try {
    # API-Key prüfen
    if ([string]::IsNullOrWhiteSpace($env:IT_API_KEY)) {
        throw "API-Key fehlt!"
    }

    # Header vorbereiten
    $headers = @{
        Authorization = "Bearer $env:IT_API_KEY"
        Accept        = "application/json"
    }

    # API-Aufruf
    $response = Invoke-RestMethod `
        -Uri "https://httpbin.org/bearer" `
        -Method Get `
        -Headers $headers `
        -ErrorAction Stop

    # Antwort prüfen
    if ($null -eq $response) {
        throw "API hat keine Antwortdaten geliefert!"
    }

    # Authentifizierung prüfen
    if ($response.authenticated -ne $true) {
        throw "Authentifizierung fehlgeschlagen!"
    }

    Write-Output "Authentifizierung erfolgreich!"

    # Nur unkritische Daten exportieren
    $response | Select-Object authenticated | Export-Csv `
            -Path ".\response-$date.csv" `
            -NoTypeInformation `
            -Delimiter ";" `
            -Encoding utf8 `
            -ErrorAction Stop

    Write-Output "CSV erfolgreich erstellt."
}
catch {
    Write-Error "API-Verarbeitung fehlgeschlagen."
    exit 1
}
