#requires -Version 5.1
<#
.SYNOPSIS
  Safe and bounded Windows telemetry / sandbox evaluation harness.
.DESCRIPTION
  Generates real but non-destructive Windows actions. No persistence, injection,
  credential collection, service/task changes, external network traffic, or evasion.
  Only writes under -Root and HKCU:\Software\SandboxTTPLab\<RunId>.
  Tests are mapped to ATT&CK where applicable; mappings are behavioral analogies.
.EXAMPLE
  .\Sandbox-TTP-Lab.ps1 -Profile Full
.EXAMPLE
  .\Sandbox-TTP-Lab.ps1 -Profile Full -Cleanup
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick','Full')][string]$Profile = 'Full',
    [ValidateRange(0,10)][int]$DelaySeconds = 2,
    [ValidateRange(1,20)][int]$BeaconCount = 3,
    [string]$Root = (Join-Path $env:TEMP 'SandboxTTPLab'),
    [switch]$Cleanup
)
$ErrorActionPreference = 'Stop'
$runId = ([guid]::NewGuid()).ToString('N').Substring(0,12)
$work = Join-Path $Root $runId
$reg = "HKCU:\Software\SandboxTTPLab\$runId"
$started = Get-Date
New-Item -Path $work -ItemType Directory -Force | Out-Null
$eventFile = Join-Path $work 'events.jsonl'
$summaryFile = Join-Path $work 'summary.json'
$tests = New-Object 'System.Collections.Generic.List[object]'

function Emit([string]$kind, [string]$name, [object]$details) {
    $rec = [ordered]@{ ts=(Get-Date).ToUniversalTime().ToString('o'); run=$runId; kind=$kind; test=$name; detail=$details }
    ($rec | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath $eventFile -Encoding UTF8
}
function SaveJson([string]$file, [object]$value) {
    $value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $work $file) -Encoding UTF8
}
function TestCase([string]$id, [string]$name, [string]$technique, [string]$expected, [scriptblock]$action) {
    $start = Get-Date
    Emit 'start' $id @{ label=$name; attack=$technique; expected=$expected }
    $status = 'PASS'; $note = ''
    try { $r = & $action; if ($null -ne $r) { $note = [string]($r | Out-String).Trim() } }
    catch { $status = 'FAIL'; $note = $_.Exception.Message }
    $duration = [math]::Round(((Get-Date)-$start).TotalMilliseconds, 1)
    $entry = [pscustomobject]@{ id=$id; name=$name; technique=$technique; status=$status; duration_ms=$duration; detail=$note; expected=$expected }
    $tests.Add($entry)
    Emit 'result' $id @{ status=$status; ms=$duration; message=$note }
    Write-Host ('[{0}] {1} - {2}' -f $status,$id,$name)
}
function RunChild([string]$executable, [string]$arguments) {
    $p = Start-Process -FilePath $executable -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "$executable exited with $($p.ExitCode)" }
    return "child pid=$($p.Id) exit=$($p.ExitCode)"
}
function GetFreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

Emit 'run' 'configuration' @{ profile=$Profile; root=$work; cleanup=[bool]$Cleanup; uid=[Environment]::UserName; host=[Environment]::MachineName }

TestCase 'DISC-01' 'Operating system query' 'T1082' 'CIM Win32_OperatingSystem query' {
    $x = Get-CimInstance Win32_OperatingSystem; SaveJson 'os.json' ($x | Select-Object Caption,Version,BuildNumber,OSArchitecture); $x.Caption
}
TestCase 'DISC-02' 'Process enumeration' 'T1057' 'PowerShell process enumeration' {
    $p = @(Get-Process | Select-Object -First 30 ProcessName,Id); SaveJson 'processes.json' $p; "count=$($p.Count)"
}
TestCase 'DISC-03' 'Current identity' 'T1033' 'User identity query without token access' {
    "username=$([Environment]::UserName)"
}
TestCase 'DISC-04' 'IP configuration' 'T1016' 'Get-NetIPConfiguration / net adapter inspection' {
    $items = @(Get-NetIPConfiguration | Select-Object -First 10 InterfaceAlias,InterfaceIndex,IPv4Address); SaveJson 'network.json' $items; "interfaces=$($items.Count)"
}
TestCase 'DISC-05' 'Running services inventory' 'T1007' 'Query service metadata without modification' {
    $items = @(Get-Service | Select-Object -First 20 Name,Status); SaveJson 'services.json' $items; "services=$($items.Count)"
}
TestCase 'DISC-06' 'Environment metadata' 'T1497.001 (observation only)' 'CIM vendor/model and resource checks' {
    $c=Get-CimInstance Win32_ComputerSystem; $d=[ordered]@{manufacturer=$c.Manufacturer; model=$c.Model; ram_bytes=$c.TotalPhysicalMemory; logical_processors=$c.NumberOfLogicalProcessors}; SaveJson 'environment.json' $d; "$($c.Manufacturer) / $($c.Model)"
}
TestCase 'EXEC-01' 'CMD child process' 'T1059.003' 'Sysmon 1 (if configured)' {
    RunChild "$env:SystemRoot\System32\cmd.exe" '/d /c echo SandboxTTPLab'
}
TestCase 'EXEC-02' 'PowerShell child process' 'T1059.001' 'Sysmon 1 (if configured)' {
    RunChild "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" '-NoProfile -NonInteractive -Command "Write-Output SandboxTTPLab"'
}
TestCase 'FILE-01' 'Write binary marker' 'T1074 (analog only)' 'Sysmon 11 file creation' {
    $b=New-Object byte[] 8192; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    $p=Join-Path $work 'marker.bin'; [IO.File]::WriteAllBytes($p,$b)
    "bytes=$((Get-Item $p).Length) sha256=$((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash)"
}
TestCase 'FILE-02' 'Copy and rename marker' 'File operations (no direct ATT&CK mapping)' 'Sysmon 11/23/26 depending on rules' {
    $p=Join-Path $work 'marker.bin'; $q=Join-Path $work 'copy.tmp'; $r=Join-Path $work 'renamed.dat'; Copy-Item -LiteralPath $p -Destination $q; Rename-Item -LiteralPath $q -NewName 'renamed.dat'; if (!(Test-Path -LiteralPath $r)) { throw 'Rename failed' }; 'copy/rename completed'
}
TestCase 'FILE-03' 'Local archive creation' 'T1560.001 (benign sample)' 'ZIP containing only a generated test marker' {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $p=Join-Path $work 'marker.bin'; $z=Join-Path $work 'sample.zip'
    $archive=[IO.Compression.ZipFile]::Open($z,[IO.Compression.ZipArchiveMode]::Create)
    try { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$p,'marker.bin') } finally { $archive.Dispose() }
    "zip_bytes=$((Get-Item $z).Length)"
}
TestCase 'REG-01' 'Create HKCU lab registry key' 'T1112' 'Sysmon 12/13 if registry monitored' {
    New-Item -Path $reg -Force | Out-Null
    New-ItemProperty -Path $reg -Name 'RunMarker' -PropertyType String -Value 'created' -Force | Out-Null
    "key=$reg"
}
TestCase 'REG-02' 'Change HKCU lab registry value' 'T1112' 'Sysmon 13 if registry monitored' {
    Set-ItemProperty -Path $reg -Name 'RunMarker' -Value 'updated'; (Get-ItemProperty -Path $reg -Name 'RunMarker').RunMarker
}
TestCase 'REG-03' 'Create REG_DWORD value' 'T1112' 'Second registry value event' {
    New-ItemProperty -Path $reg -Name 'Count' -PropertyType DWord -Value 42 -Force | Out-Null; 'DWORD 42'
}
TestCase 'REG-04' 'Remove only own value' 'T1112' 'Registry value deletion' {
    Remove-ItemProperty -Path $reg -Name 'Count'; 'removed Count'
}
TestCase 'SIM-01' 'Persistence IOC simulation' 'T1547.001 (simulation ONLY)' 'Detection fixture; NO autorun key changed' {
    SaveJson 'autorun-simulation.json' @{ simulated_registry_path='HKCU\Software\Microsoft\Windows\CurrentVersion\Run'; would_write='SandboxTTPLab'; executed=$false }; 'fixture only'
}
TestCase 'SIM-02' 'Scheduled task IOC simulation' 'T1053.005 (simulation ONLY)' 'Detection fixture; NO task created' {
    SaveJson 'task-simulation.json' @{ simulated_task_name='SandboxTTPLab'; scheduled=$false; executed=$false }; 'fixture only'
}

if ($Profile -eq 'Full') {
    TestCase 'FILE-04' 'Alternate data stream marker' 'T1564.004 (benign sample)' 'NTFS ADS write; may be unsupported on filesystem' {
        $p=Join-Path $work 'marker.bin'; $stream=Join-Path $work 'ads-host.txt'; 'host' | Set-Content -LiteralPath $stream
        Set-Content -LiteralPath $stream -Stream 'LabNote' -Value 'SandboxTTPLab harmless stream' -ErrorAction Stop
        $v=Get-Content -LiteralPath $stream -Stream 'LabNote' -ErrorAction Stop; "ads=$v"
    }
    TestCase 'FILE-05' 'Set file last write time within lab' 'T1070.006 (partial analogy)' 'Only test file metadata changed' {
        $p=Join-Path $work 'renamed.dat'; $t=(Get-Item -LiteralPath $p); $t.LastWriteTime= (Get-Date).AddDays(-1); "last_write=$($t.LastWriteTime.ToString('o'))"
    }
    TestCase 'FILE-06' 'Create then delete ephemeral file' 'File operations (no direct ATT&CK mapping)' 'Sysmon 11 and optional 23/26' {
        $p=Join-Path $work 'ephemeral.txt'; 'delete-me' | Set-Content -LiteralPath $p; Remove-Item -LiteralPath $p -Force; "deleted=$(!(Test-Path -LiteralPath $p))"
    }
    TestCase 'EXEC-03' 'Two nested child processes' 'T1059.003' 'CMD launches second CMD' {
        RunChild "$env:SystemRoot\System32\cmd.exe" '/d /c cmd.exe /d /c echo nested-lab'
    }
    TestCase 'EXEC-04' 'CIM query in child PowerShell' 'T1059.001 / T1082' 'Process creation followed by CIM call' {
        RunChild "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" '-NoProfile -NonInteractive -Command "Get-CimInstance Win32_OperatingSystem | Out-Null"'
    }
    TestCase 'NET-01' 'Loopback TCP client and server' 'T1095 (local analogy)' 'Sysmon 3 if enabled and loopback captured' {
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $listener.Start()
        $client=$null; $server=$null
        try {
            $port=([Net.IPEndPoint]$listener.LocalEndpoint).Port
            $client=[Net.Sockets.TcpClient]::new(); $async=$client.BeginConnect([Net.IPAddress]::Loopback,$port,$null,$null)
            if (!$async.AsyncWaitHandle.WaitOne(2000)) { throw 'Loopback connection timed out' }
            $client.EndConnect($async); $server=$listener.AcceptTcpClient()
            $bytes=[Text.Encoding]::UTF8.GetBytes('SandboxTTPLab')
            $client.GetStream().Write($bytes,0,$bytes.Length)
            "127.0.0.1:$port bytes=$($bytes.Length)"
        } finally { if ($server) {$server.Close()}; if ($client) {$client.Close()}; $listener.Stop() }
    }
    TestCase 'NET-02' 'Local HTTP loopback request sequence' 'T1071.001 (local analogy)' 'HTTP requests to 127.0.0.1 only; ephemeral listener' {
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $listener.Start(); $client=$null
        try {
            $port=([Net.IPEndPoint]$listener.LocalEndpoint).Port
            # Start an asynchronous HTTP request without a second PowerShell runspace.
            $request=[Net.HttpWebRequest][Net.WebRequest]::Create("http://127.0.0.1:$port/ping")
            $request.Timeout=2500
            $request.ReadWriteTimeout=2500
            $requestAsync=$request.BeginGetResponse($null,$null)
            $pending=$listener.BeginAcceptTcpClient($null,$null)
            if (!$pending.AsyncWaitHandle.WaitOne(2500)) { throw 'HTTP accept timeout' }
            $client=$listener.EndAcceptTcpClient($pending)
            $reader=New-Object IO.StreamReader($client.GetStream(),[Text.Encoding]::ASCII,$false,1024,$true)
            $requestLine=$reader.ReadLine()
            $body='OK'; $response="HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: close`r`n`r`n$body"
            $data=[Text.Encoding]::ASCII.GetBytes($response); $client.GetStream().Write($data,0,$data.Length); $client.Close();$client=$null
            if (!$requestAsync.AsyncWaitHandle.WaitOne(2500)) { throw 'HTTP client timeout' }
            $httpResponse=$request.EndGetResponse($requestAsync)
            try { "request=$requestLine http_status=$([int]$httpResponse.StatusCode)" }
            finally { $httpResponse.Close() }
        } finally { if ($client) {$client.Close()}; $listener.Stop() }
    }
    TestCase 'NET-03' 'Resolve loopback hostname' 'DNS resolution (no external destination)' 'Host-based name resolution; may not generate DNS event' {
        $ip=@([Net.Dns]::GetHostAddresses('localhost') | ForEach-Object { $_.ToString() }); $ip -join ','
    }
    TestCase 'TIME-01' 'Short bounded sleep and measure elapsed time' 'T1497.003 (observation only)' 'No behavior gated by environment or delay' {
        $timer=[Diagnostics.Stopwatch]::StartNew(); Start-Sleep -Seconds $DelaySeconds; $timer.Stop(); "requested=$DelaySeconds measured_ms=$($timer.ElapsedMilliseconds)"
    }
    TestCase 'TIME-02' 'Bounded periodic markers' 'T1071.001 (timing analogy only)' 'No network: produces observable telemetry cadence' {
        for ($i=1;$i -le $BeaconCount;$i++) { Emit 'heartbeat' 'TIME-02' @{number=$i; total=$BeaconCount}; Start-Sleep -Milliseconds 250 }
        "heartbeats=$BeaconCount"
    }
    TestCase 'SIM-03' 'Encoded-looking fixture without execution' 'T1027 (simulation ONLY)' 'Base64 marker saved as inert content; never decoded or executed' {
        $sample=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('harmless telemetry fixture'))
        Set-Content -LiteralPath (Join-Path $work 'encoding-fixture.txt') -Value $sample; 'encoded data only'
    }
    TestCase 'SIM-04' 'Process injection IOC fixture' 'T1055 (simulation ONLY)' 'No handle opens, memory writes or injection' {
        SaveJson 'injection-simulation.json' @{ kind='synthetic-event'; technique='T1055'; executed=$false }; 'fixture only'
    }
}

$report=[ordered]@{
    schema='SandboxTTPLab/1.0'; run_id=$runId; started_utc=$started.ToUniversalTime().ToString('o'); finished_utc=(Get-Date).ToUniversalTime().ToString('o');
    profile=$Profile; root=$work; pass=@($tests | Where-Object status -eq 'PASS').Count; fail=@($tests | Where-Object status -eq 'FAIL').Count;
    total=$tests.Count; tests=@($tests.ToArray()); cleanup_requested=[bool]$Cleanup;
    important='PASS means the action completed, NOT that an EDR or sandbox detected it. Review Sysmon/EDR telemetry separately.'
}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryFile -Encoding UTF8
Write-Host "`nRun: $runId  Tests: $($report.total)  Passed: $($report.pass)  Failed: $($report.fail)"
Write-Host "Summary: $summaryFile"
Write-Host "Event timeline: $eventFile"

if ($Cleanup) {
    try { if (Test-Path $reg) { Remove-Item -Path $reg -Recurse -Force } } catch { Write-Warning "Registry cleanup failed: $($_.Exception.Message)" }
    # Preserve reports; remove generated marker/fixture files only.
    @('marker.bin','copy.tmp','renamed.dat','sample.zip','ads-host.txt','ephemeral.txt','encoding-fixture.txt') | ForEach-Object {
        $p=Join-Path $work $_; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction Continue }
    }
    Write-Host 'Cleanup requested: lab registry key and temporary marker files removed. Reports preserved.'
} else {
    Write-Host "Lab artifacts preserved for inspection. Registry key: $reg"
}
