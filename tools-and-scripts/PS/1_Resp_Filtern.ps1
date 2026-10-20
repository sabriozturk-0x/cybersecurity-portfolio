$date = Get-Date -Format "yyyy-MM-dd"
$apiUrl = "https://jsonplaceholder.typicode.com/todos"

$tickets = @(
    [PSCustomObject]@{
        Id         = 1001
        Titel      = "VPN funktioniert nicht"
        Prioritaet = "Hoch"
        Status     = "Offen"
    },
    [PSCustomObject]@{
        Id         = 1002
        Titel      = "Monitor austauschen"
        Prioritaet = "Niedrig"
        Status     = "Offen"
    },
    [PSCustomObject]@{
        Id         = 1003
        Titel      = "Server nicht erreichbar"
        Prioritaet = "Hoch"
        Status     = "Geschlossen"
    }
)

# Dringende und offene Tickets filtern
$dringendeTickets = @(
    $tickets | Where-Object {
        $_.Prioritaet -eq "Hoch" -and
        $_.Status -eq "Offen"
    } | Select-Object Id, Titel
)

# Nur bei Treffern exportieren
if ($dringendeTickets.Count -gt 0) {

    $dringendeTickets | Export-Csv `
        -Path ".\dringende-tickets-$date.csv" `
        -NoTypeInformation `
        -Delimiter ";" `
        -Encoding utf8 `
        -ErrorAction Stop

    Write-Output "Dringende Tickets: $($dringendeTickets.Count)"
}
else {
    Write-Output "Keine dringenden Tickets vorhanden."
}