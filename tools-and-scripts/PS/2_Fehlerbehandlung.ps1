
$date = Get-Date -Format "yyyy-MM-dd"
$apiUrl = "https://jsonplaceholder.typicode.com/todos"

try {
    # 1. API-Daten abrufen
    $response = Invoke-RestMethod `
        -Uri $apiUrl `
        -Method Get `
        -ErrorAction Stop

    # 2. Antwort prüfen
    if ($null -eq $response) {
        throw "API hat keine gültigen Daten geliefert."
    }

    # 3. Daten filtern
    $selectedResponse = @(
        $response | Where-Object {
            $_.userId -eq 1 -and
            $_.completed -eq $false
        } | Select-Object Id, Title, Completed
    )

    # 4. Ergebnisse prüfen und exportieren
    if ($selectedResponse.Count -eq 0) {
        Write-Output "Keine passenden Aufgaben vorhanden."
    }
    else {
        $selectedResponse | Export-Csv `
            -Path ".\selected-tickets-$date.csv" `
            -NoTypeInformation `
            -Delimiter ";" `
            -Encoding utf8 `
            -ErrorAction Stop

        Write-Output "Export erfolgreich."
        Write-Output "Anzahl Aufgaben: $($selectedResponse.Count)"
    }
}
catch {
    Write-Error "API-Fehler: $($_.Exception.Message)"
    exit 1
}
