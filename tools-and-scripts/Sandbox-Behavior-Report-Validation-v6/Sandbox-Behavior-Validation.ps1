#requires -Version 5.1
<#
.SYNOPSIS
  Safe Windows sandbox behavior and report validation test. No persistence, injection, credential access,
  security-tool manipulation, destructive actions, or external data collection.
.DESCRIPTION
  Performs observable discovery, process, file, HKCU registry, timing and network
  actions. Network GET defaults to https://example.com; synthetic POST requires
  explicit -PostUri plus -EnableSyntheticPost. No machine/user data transmitted.
.EXAMPLE
  powershell.exe -NoProfile -File .\Sandbox-Behavior-Test.ps1
.EXAMPLE
  .\Sandbox-Behavior-Test.ps1 -GetUri https://example.com/ -PostUri https://lab.example.net/ingest -EnableSyntheticPost
#>
[CmdletBinding()]
param(
    [string]$WorkRoot = (Join-Path $env:TEMP 'SandboxBehaviorTest'),
    [uri]$GetUri = 'https://example.com/',
    [uri]$PostUri,
    [switch]$EnableSyntheticPost,
    [ValidateRange(1,5)][int]$BeaconCount = 3,
    [ValidateRange(1,10)][int]$DelaySeconds = 2,
    [switch]$KeepRegistry,
    [switch]$SkipNetwork
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$runId = [guid]::NewGuid().ToString('N')
$root = Join-Path $WorkRoot $runId
$null = New-Item -ItemType Directory -Path $root -Force
$global:LabEvents = Join-Path $root 'events.jsonl'
$global:LabResults = New-Object System.Collections.ArrayList
$global:LabRunId = $runId
$global:LabScriptPath = $MyInvocation.MyCommand.Path
$global:LabRoot = $root
$global:LabReg = 'HKCU:\Software\SandboxBehaviorTest\' + $runId
$startUtc = (Get-Date).ToUniversalTime()

function LogEvent([string]$Id,[string]$Phase,[string]$Status,[string]$Detail) {
    $o = [ordered]@{time=(Get-Date).ToUniversalTime().ToString('o');run_id=$global:LabRunId;
        test_id=$Id;phase=$Phase;status=$Status;detail=$Detail;pid=$PID}
    $o | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $global:LabEvents -Encoding UTF8
    [void]$global:LabResults.Add([pscustomobject]$o)
    Write-Host ('[{0}] {1} {2}: {3}' -f $Id,$Phase,$Status,$Detail)
}
function TestStep([string]$Id,[string]$Description,[scriptblock]$Action) {
    LogEvent $Id 'START' 'STARTED' $Description
    try { & $Action; LogEvent $Id 'END' 'SUCCESS' $Description }
    catch { LogEvent $Id 'END' 'ERROR' $_.Exception.Message }
}
function SaveJson([string]$Name,$Data) {
    $path = Join-Path $global:LabRoot $Name
    ConvertTo-Json -InputObject $Data -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
}
function IsSafeEndpoint([uri]$Uri) {
    if ($null -eq $Uri -or !$Uri.IsAbsoluteUri) { return $false }
    if ($Uri.Scheme -ne 'https' -and !($Uri.Scheme -eq 'http' -and
       ($Uri.Host -eq '127.0.0.1' -or $Uri.Host -eq 'localhost' -or $Uri.Host -eq '[::1]'))) {return $false}
    if ($Uri.UserInfo -or $Uri.Fragment) { return $false }
    return $true
}
if (!$SkipNetwork -and !(IsSafeEndpoint $GetUri)) { throw 'GetUri must be HTTPS or loopback HTTP, without credentials/fragments.' }
if ($EnableSyntheticPost -and (!(IsSafeEndpoint $PostUri))) {throw 'Explicit PostUri must be HTTPS or loopback HTTP.'}
if ($PostUri -and !$EnableSyntheticPost) { Write-Warning 'PostUri supplied but POST disabled unless -EnableSyntheticPost.' }
LogEvent 'META-01' 'START' 'SUCCESS' "Started safe lab run $runId"

# ----- Discovery: local only; collected outputs never sent over network -----
TestStep 'DISC-01' 'Windows version and OS information' {
    $v=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
    SaveJson 'os.json' $v
}
TestStep 'DISC-02' 'Computer hardware summary' {
    $v=Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors
    SaveJson 'hardware.json' $v
}
TestStep 'DISC-03' 'Process inventory' {
    $v=Get-Process | Select-Object -First 40 Name,Id,CPU,Handles
    SaveJson 'processes.json' @($v)
}
TestStep 'DISC-04' 'Service inventory' {
    $v=Get-Service | Select-Object -First 40 Name,Status,StartType
    SaveJson 'services.json' @($v)
}
TestStep 'DISC-05' 'Current user and security context' {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    SaveJson 'identity.json' @{name=$identity.Name;authentication=$identity.AuthenticationType}
}
TestStep 'DISC-06' 'IP configuration' {
    $v=Get-NetIPConfiguration | Select-Object -First 8 InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address
    SaveJson 'interfaces.json' @($v)
}
TestStep 'DISC-07' 'Environment characteristics (no sandbox avoidance)' {
    $v=@{locale=(Get-Culture).Name;timezone=(Get-TimeZone).Id;
      tick_count=[Environment]::TickCount64;ps_version=$PSVersionTable.PSVersion.ToString()}
    SaveJson 'environment.json' $v
}

# ----- Process tree and command lines -----
TestStep 'PROC-01' 'cmd.exe child process' {
    $p=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c echo SANDBOX_LAB_CMD_MARKER' -Wait -PassThru -WindowStyle Hidden
    LogEvent 'PROC-01' 'ARTIFACT' 'SUCCESS' "cmd.exe child PID=$($p.Id) ExitCode=$($p.ExitCode)"
}
TestStep 'PROC-02' 'Nested PowerShell child process' {
    $cmd='Write-Output SANDBOX_LAB_PS_MARKER; Get-Date | Out-Null'
    $p=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
      -ArgumentList @('-NoProfile','-NonInteractive','-Command',('"'+$cmd+'"')) -Wait -PassThru -WindowStyle Hidden
    LogEvent 'PROC-02' 'ARTIFACT' 'SUCCESS' "powershell.exe child PID=$($p.Id) ExitCode=$($p.ExitCode)"
}
TestStep 'PROC-03' 'whoami.exe system-user query' {
    $out=& "$env:SystemRoot\System32\whoami.exe" 2>&1
    SaveJson 'whoami.json' @{output=($out | Out-String).Trim()}
}
TestStep 'PROC-04' 'ipconfig.exe subprocess' {
    $out=& "$env:SystemRoot\System32\ipconfig.exe" '/all' 2>&1
    $out | Set-Content -LiteralPath (Join-Path $root 'ipconfig.txt') -Encoding UTF8
}

# ----- File behavior: all inside the unique run directory -----
TestStep 'FILE-01' 'Create directories and marker text file' {
    $null=New-Item -ItemType Directory -Path (Join-Path $root 'stage\nested') -Force
    'SANDBOX_LAB_TEST_DATA_NOT_SENSITIVE' | Set-Content (Join-Path $root 'stage\marker.txt') -Encoding UTF8
}
TestStep 'FILE-02' 'Generate 64KiB deterministic binary sample' {
    $data=New-Object byte[] 65536
    for ($i=0;$i -lt $data.Length;$i++) {$data[$i]=[byte]($i % 251)}
    [IO.File]::WriteAllBytes((Join-Path $root 'stage\payload-test.bin'),$data)
}
TestStep 'FILE-03' 'Copy, rename and hash benign file' {
    $src=Join-Path $root 'stage\payload-test.bin'
    $dst=Join-Path $root 'stage\nested\copied.bin'
    Copy-Item -LiteralPath $src -Destination $dst
    Rename-Item -LiteralPath $dst -NewName 'renamed.bin'
    $h=Get-FileHash (Join-Path $root 'stage\nested\renamed.bin') -Algorithm SHA256
    SaveJson 'artifact-hash.json' @{sha256=$h.Hash;relative_path='stage/nested/renamed.bin'}
}
TestStep 'FILE-04' 'Create benign ZIP archive' {
    Compress-Archive -Path (Join-Path $root 'stage\marker.txt'),(Join-Path $root 'stage\payload-test.bin') `
       -DestinationPath (Join-Path $root 'sample.zip') -Force
}
TestStep 'FILE-05' 'NTFS alternate data stream' {
    $target=Join-Path $root 'stage\marker.txt'
    if ((Get-Item -LiteralPath $target).PSDrive.Provider.Name -ne 'FileSystem') {throw 'Not filesystem'}
    'BENIGN_TEST_STREAM' | Set-Content -LiteralPath $target -Stream 'SandboxLab' -ErrorAction Stop
}
TestStep 'FILE-06' 'Change file attributes inside lab directory' {
    $path=Join-Path $root 'stage\nested\renamed.bin'
    $f=Get-Item -LiteralPath $path
    $f.Attributes=$f.Attributes -bor [IO.FileAttributes]::Hidden
    $f.Attributes=$f.Attributes -band (-bnot [IO.FileAttributes]::Hidden)
}
TestStep 'FILE-07' 'Write-delete short-lived temporary marker' {
    $path=Join-Path $root 'stage\ephemeral.tmp'
    'EPHEMERAL_SANDBOX_TEST' | Set-Content -LiteralPath $path
    Start-Sleep -Milliseconds 300
    Remove-Item -LiteralPath $path -Force
}
TestStep 'FILE-08' 'Read file content and enumerate files' {
    $null=Get-Content (Join-Path $root 'stage\marker.txt')
    $listing=Get-ChildItem (Join-Path $root 'stage') -File -Recurse |
      Select-Object Name,Length,FullName
    SaveJson 'file-listing.json' @($listing)
}

# ----- HKCU-only registry keys, no autorun locations -----
TestStep 'REG-01' 'Create HKCU test key and string property' {
    $null=New-Item -Path $global:LabReg -Force
    $null=New-ItemProperty -Path $global:LabReg -Name 'LabMarker' -Value 'INITIAL_LAB_VALUE' -PropertyType String -Force
}
TestStep 'REG-02' 'Modify registry marker string' {
    Set-ItemProperty -Path $global:LabReg -Name 'LabMarker' -Value 'UPDATED_LAB_VALUE'
}
TestStep 'REG-03' 'Create REG_DWORD and REG_BINARY values' {
    $null=New-ItemProperty -Path $global:LabReg -Name 'Counter' -Value 42 -PropertyType DWord -Force
    $null=New-ItemProperty -Path $global:LabReg -Name 'Bytes' -Value ([byte[]](1,2,3,4)) -PropertyType Binary -Force
}
TestStep 'REG-04' 'Read values and enumerate lab key' {
    $v=Get-ItemProperty -Path $global:LabReg
    SaveJson 'registry-values.json' @{LabMarker=$v.LabMarker;Counter=$v.Counter;Bytes=@($v.Bytes)}
}
TestStep 'REG-05' 'Delete one registry marker' {
    Remove-ItemProperty -Path $global:LabReg -Name 'Bytes'
}

# ----- Timing; never gate behavior on VM state or timer results -----
TestStep 'TIME-01' 'Single timed delay' {
    $sw=[Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds $DelaySeconds
    $sw.Stop()
    SaveJson 'timing-single.json' @{requested_ms=($DelaySeconds*1000);elapsed_ms=$sw.Elapsed.TotalMilliseconds}
}
TestStep 'TIME-02' 'Three short jitter-measurement samples' {
    $times=@()
    foreach($ms in @(150,300,450)) {
        $sw=[Diagnostics.Stopwatch]::StartNew(); Start-Sleep -Milliseconds $ms; $sw.Stop()
        $times+=@{requested_ms=$ms;elapsed_ms=$sw.Elapsed.TotalMilliseconds}
    }
    SaveJson 'timing-series.json' $times
}

# ----- Network: HTTPS GET or loopback HTTP, bounded traffic, fixed synthetic payload -----
if (!$SkipNetwork) {
    TestStep 'NET-01' 'Resolve GET endpoint hostname using Windows DNS resolver' {
        $hostName=$GetUri.DnsSafeHost
        if ($hostName -ne 'localhost' -and $hostName -ne '127.0.0.1' -and $hostName -ne '::1') {
            $addresses=[Net.Dns]::GetHostAddresses($hostName) | ForEach-Object { $_.IPAddressToString }
            SaveJson 'dns-results.json' @{hostname=$hostName;addresses=@($addresses)}
        } else { SaveJson 'dns-results.json' @{hostname=$hostName;addresses=@('loopback')} }
    }
    TestStep 'NET-02' 'Bounded HTTP(S) GET request with distinct lab user agent' {
        $headers=@{'X-Sandbox-Test'='BENIGN';'Cache-Control'='no-cache'}
        $res=Invoke-WebRequest -Uri $GetUri -Method Get -Headers $headers -UserAgent 'SandboxBehaviorTest/1.0' `
            -TimeoutSec 8 -MaximumRedirection 0 -UseBasicParsing
        SaveJson 'http-get.json' @{url=$GetUri.AbsoluteUri;status=[int]$res.StatusCode;length=$res.RawContentLength}
    }
    TestStep 'NET-03' 'Repeated GET beacon-like requests with fixed intervals' {
        $beacons=@()
        for($i=1;$i -le $BeaconCount;$i++) {
            $timer=[Diagnostics.Stopwatch]::StartNew()
            try {
                $r=Invoke-WebRequest -Uri $GetUri -Method Get -Headers @{'X-Sandbox-Test'='BENIGN_BEACON'} `
                   -UserAgent 'SandboxBehaviorTest/1.0' -TimeoutSec 8 -MaximumRedirection 0 -UseBasicParsing
                $status=[int]$r.StatusCode
            } catch {$status='REQUEST_FAILED'}
            $timer.Stop()
            $beacons+=@{sequence=$i;time=(Get-Date).ToUniversalTime().ToString('o');status=$status;duration_ms=$timer.Elapsed.TotalMilliseconds}
            LogEvent 'NET-03' 'ARTIFACT' 'SUCCESS' "GET beacon $i of $BeaconCount: $status"
            if($i -lt $BeaconCount){Start-Sleep -Seconds $DelaySeconds}
        }
        SaveJson 'beacons.json' $beacons
    }
    if($EnableSyntheticPost) {
        TestStep 'NET-04' 'Synthetic-only JSON POST to explicitly approved HTTPS endpoint' {
            # Deliberately fixed data; no system, hostname, user or file content is transmitted.
            $body='{"type":"sandbox-safe-test","version":1,"message":"SYNTHETIC_ONLY_NO_USER_DATA"}'
            $r=Invoke-WebRequest -Uri $PostUri -Method Post -Body $body -ContentType 'application/json' `
               -Headers @{'X-Sandbox-Test'='BENIGN'} -TimeoutSec 8 -MaximumRedirection 0 -UseBasicParsing
            SaveJson 'http-post.json' @{url=$PostUri.AbsoluteUri;status=[int]$r.StatusCode;sent_body=$body}
        }
    }
}

# ----- Explicitly simulated behaviors; no real persistence / credential access -----
TestStep 'SIM-01' 'Inert autorun registry example as JSON file only' {
    SaveJson 'simulated-autorun.json' @{technique='T1547.001';mode='SIMULATED_ONLY';
      proposed_location='HKCU\Software\Microsoft\Windows\CurrentVersion\Run';created=$false}
}
TestStep 'SIM-02' 'Inert scheduled-task example as JSON file only' {
    SaveJson 'simulated-task.json' @{technique='T1053.005';mode='SIMULATED_ONLY';created=$false}
}
TestStep 'SIGN-01' 'Read Authenticode signature status of this script' {
    $sig=Get-AuthenticodeSignature -FilePath $global:LabScriptPath
    SaveJson 'signature.json' @{status=$sig.Status.ToString();status_message=$sig.StatusMessage;
        signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''}}
}
TestStep 'SIGN-02' 'Hash this script for report identity' {
    $h=Get-FileHash -LiteralPath $global:LabScriptPath -Algorithm SHA256
    SaveJson 'script-hash.json' @{sha256=$h.Hash}
}


# ===== Extended observable behaviors: scoped, reversible, no stealth =====
# These test cases add traces for sandbox reporting, not real offensive capability.

# ---- Additional system and security-context inventory ----
TestStep 'DISC-08' 'Query OS installation and boot times' {
    $os=Get-CimInstance Win32_OperatingSystem
    SaveJson 'boot.json' @{install=$os.InstallDate;boot=$os.LastBootUpTime;build=$os.BuildNumber}
}
TestStep 'DISC-09' 'Enumerate logical volumes' {
    $v=Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,Size,FreeSpace
    SaveJson 'volumes.json' @($v)
}
TestStep 'DISC-10' 'Enumerate scheduled task names (read-only)' {
    $v=Get-ScheduledTask -ErrorAction Stop | Select-Object -First 30 TaskName,TaskPath,State
    SaveJson 'task-inventory.json' @($v)
}
TestStep 'DISC-11' 'List Windows hotfix metadata' {
    $v=Get-HotFix | Select-Object -First 25 HotFixID,InstalledOn,Description
    SaveJson 'hotfixes.json' @($v)
}
TestStep 'DISC-12' 'List limited local group descriptions' {
    $v=Get-CimInstance Win32_Group -Filter "LocalAccount=True" |
       Select-Object -First 15 Name,Description
    SaveJson 'local-groups.json' @($v)
}
TestStep 'DISC-13' 'Collect network route table metadata' {
    $v=Get-NetRoute -AddressFamily IPv4 | Select-Object -First 30 DestinationPrefix,NextHop,RouteMetric
    SaveJson 'routes.json' @($v)
}
TestStep 'DISC-14' 'Read current proxy settings without modifying them' {
    $key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $v=Get-ItemProperty -Path $key
    SaveJson 'proxy.json' @{enabled=$v.ProxyEnable;server=$v.ProxyServer}
}
TestStep 'DISC-15' 'Collect installed application metadata via uninstall registry' {
    $v=Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
       Where-Object DisplayName | Select-Object -First 30 DisplayName,DisplayVersion,Publisher
    SaveJson 'app-inventory.json' @($v)
}
TestStep 'DISC-16' 'List active Windows services with process IDs' {
    $v=Get-CimInstance Win32_Service | Where-Object {$_.State -eq 'Running'} |
       Select-Object -First 30 Name,ProcessId,StartMode
    SaveJson 'active-services.json' @($v)
}
TestStep 'DISC-17' 'Read process architecture and execution context' {
    SaveJson 'process-context.json' @{pid=$PID;process64=[Environment]::Is64BitProcess;os64=[Environment]::Is64BitOperatingSystem;psedition=$PSVersionTable.PSEdition}
}

# ---- Parent/child processes and command-line visibility ----
TestStep 'PROC-05' 'Launch cmd child with redirected stdout' {
    $out=Join-Path $root 'cmd-output.txt'
    $p=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c echo LAB_REDIRECTED_CHILD' -Wait -PassThru -RedirectStandardOutput $out
    LogEvent 'PROC-05' 'ARTIFACT' 'SUCCESS' "PID=$($p.Id) Exit=$($p.ExitCode)"
}
TestStep 'PROC-06' 'Create sequential command-shell executions' {
    $paths=@()
    for($i=1;$i -le 3;$i++) {
        $f=Join-Path $root ("seq-$i.txt")
        $p=Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/d /c echo LAB_SEQUENCE_$i" -Wait -PassThru -RedirectStandardOutput $f
        $paths+=@{sequence=$i;pid=$p.Id;exit=$p.ExitCode}
    }
    SaveJson 'sequential-processes.json' $paths
}
TestStep 'PROC-07' 'Spawn PowerShell child with non-sensitive test output' {
    $out=Join-Path $root 'ps-child-output.txt'
    $p=Start-Process "$PSHOME\powershell.exe" -ArgumentList '-NoProfile -NonInteractive -Command "Write-Output LAB_CHILD_OK"' -Wait -PassThru -RedirectStandardOutput $out
    LogEvent 'PROC-07' 'ARTIFACT' 'SUCCESS' "PID=$($p.Id)"
}
TestStep 'PROC-08' 'Invoke hostname utility as child process' {
    $v=& "$env:SystemRoot\System32\hostname.exe"
    SaveJson 'hostname-command.json' @{output=@($v)}
}
TestStep 'PROC-09' 'Invoke tasklist utility as child process' {
    $v=& "$env:SystemRoot\System32\tasklist.exe" '/fo' 'csv' '/nh'
    ($v | Select-Object -First 15) | Set-Content (Join-Path $root 'tasklist-sample.txt')
}
TestStep 'PROC-10' 'Invoke netstat for current local connections' {
    $v=& "$env:SystemRoot\System32\netstat.exe" '-ano'
    ($v | Select-Object -First 40) | Set-Content (Join-Path $root 'netstat-sample.txt')
}
TestStep 'PROC-11' 'Create a short-lived background PowerShell job' {
    $job=Start-Job -ScriptBlock {Start-Sleep -Milliseconds 150; 'LAB_JOB_OK'}
    $result=Receive-Job -Job $job -Wait
    SaveJson 'job-result.json' @{id=$job.Id;result=@($result)}
    Remove-Job -Job $job -Force
}
TestStep 'PROC-12' 'Inspect current PowerShell module list' {
    $v=Get-Module | Select-Object Name,Version,ModuleType
    SaveJson 'loaded-modules.json' @($v)
}

# ---- File artifacts, metadata, archive, strings, streams ----
TestStep 'FILE-09' 'Generate deterministic 32 KB binary artifact' {
    $bytes=New-Object byte[] 32768
    for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte]($i % 251)}
    [IO.File]::WriteAllBytes((Join-Path $root 'deterministic.dat'),$bytes)
}
TestStep 'FILE-10' 'Write Unicode and ASCII encoded markers' {
    'SANDBOX_UNICODE_ÄÖÜ' | Set-Content (Join-Path $root 'unicode.txt') -Encoding Unicode
    'SANDBOX_ASCII_MARKER' | Set-Content (Join-Path $root 'ascii.txt') -Encoding Ascii
}
TestStep 'FILE-11' 'Append to existing lab file' {
    $f=Join-Path $root 'append.log'
    'start' | Set-Content $f
    1..5 | ForEach-Object { "sample $_" | Add-Content $f }
}
TestStep 'FILE-12' 'Generate directory tree with files' {
    foreach($i in 1..4){
      $d=Join-Path $root ("tree\branch$i")
      New-Item -ItemType Directory -Path $d -Force | Out-Null
      foreach($j in 1..3){ "LAB_CONTENT_$i`_$j" | Set-Content (Join-Path $d "leaf$j.txt") }
    }
}
TestStep 'FILE-13' 'Create then rename a lab-owned directory' {
    $a=Join-Path $root 'rename-directory-A';$b=Join-Path $root 'rename-directory-B'
    New-Item -Path $a -ItemType Directory -Force | Out-Null
    Rename-Item -LiteralPath $a -NewName 'rename-directory-B'
    if(!(Test-Path $b)){throw 'Renamed directory missing'}
}
TestStep 'FILE-14' 'Write and update isolated file attributes' {
    $f=Join-Path $root 'attribute-marker.txt'
    'LAB_HIDDEN_MARKER' | Set-Content $f
    $item=Get-Item $f
    $item.Attributes=$item.Attributes -bor [IO.FileAttributes]::Hidden
    $item.Attributes=$item.Attributes -band (-bnot [IO.FileAttributes]::Hidden)
}
TestStep 'FILE-15' 'Modify then restore lab file timestamp' {
    $f=Join-Path $root 'timestamp-marker.txt'; 'LAB_TIMESTAMP' | Set-Content $f
    $item=Get-Item $f; $original=$item.LastWriteTimeUtc
    $item.LastWriteTimeUtc=$original.AddMinutes(-3)
    $item.LastWriteTimeUtc=$original
    SaveJson 'timestamp-test.json' @{original=$original;restored=$item.LastWriteTimeUtc}
}
TestStep 'FILE-16' 'Create NTFS alternate data stream where supported' {
    $f=Join-Path $root 'ads-carrier.txt'; 'LAB_CARRIER' | Set-Content $f
    Set-Content -LiteralPath $f -Stream 'LabMetadata' -Value 'BENIGN_ADS_MARKER' -ErrorAction Stop
    $stream=Get-Item -LiteralPath $f -Stream LabMetadata
    SaveJson 'ads.json' @{path=$f;stream=$stream.Stream;length=$stream.Length}
}
TestStep 'FILE-17' 'Compute SHA-256 and SHA-1 for own artifact' {
    $f=Join-Path $root 'deterministic.dat'
    $sha256=(Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    $sha1=(Get-FileHash -LiteralPath $f -Algorithm SHA1).Hash
    SaveJson 'artifact-hashes.json' @{sha256=$sha256;sha1=$sha1}
}
TestStep 'FILE-18' 'Search own test files for unique marker' {
    $v=Get-ChildItem -Path $root -Filter '*.txt' -File -Recurse |
       Select-String -Pattern 'LAB_' -SimpleMatch | Select-Object -First 25 Path,LineNumber,Line
    SaveJson 'marker-search.json' @($v)
}
TestStep 'FILE-19' 'Read own binary and create Base64 text copy' {
    $bytes=[IO.File]::ReadAllBytes((Join-Path $root 'deterministic.dat'))
    [Convert]::ToBase64String($bytes) | Set-Content (Join-Path $root 'sample-base64.txt')
}
TestStep 'FILE-20' 'Compress lab-owned marker files into second archive' {
    $files=@((Join-Path $root 'ascii.txt'),(Join-Path $root 'unicode.txt'))
    Compress-Archive -LiteralPath $files -DestinationPath (Join-Path $root 'markers.zip') -Force
}
TestStep 'FILE-21' 'Expand lab-owned archive into run folder' {
    Expand-Archive -LiteralPath (Join-Path $root 'markers.zip') -DestinationPath (Join-Path $root 'unpacked') -Force
}
TestStep 'FILE-22' 'Create then remove temporary lab marker' {
    $f=Join-Path $root 'ephemeral.tmp'
    'LAB_EPHEMERAL' | Set-Content $f
    Remove-Item -LiteralPath $f -Force
}
TestStep 'FILE-23' 'Inspect own file access control list' {
    $f=Join-Path $root 'ascii.txt'
    $acl=Get-Acl -LiteralPath $f
    SaveJson 'own-file-acl.json' @{owner=$acl.Owner;rule_count=@($acl.Access).Count}
}

# ---- Further registry value types and reversible lifecycle ----
TestStep 'REG-07' 'Create and update nested lab registry subkey' {
    $path=Join-Path $global:LabReg 'Nested\Subkey'
    New-Item -Path $path -Force | Out-Null
    New-ItemProperty -Path $path -Name 'Stage' -PropertyType String -Value 'initial' -Force | Out-Null
    Set-ItemProperty -Path $path -Name 'Stage' -Value 'updated'
}
TestStep 'REG-08' 'Create multiple string value under lab key' {
    New-ItemProperty -Path $global:LabReg -Name 'LabMulti' -PropertyType MultiString -Value @('alpha','beta','gamma') -Force | Out-Null
}
TestStep 'REG-09' 'Create expandable string without execution' {
    New-ItemProperty -Path $global:LabReg -Name 'LabExpand' -PropertyType ExpandString -Value '%TEMP%\LabMarker' -Force | Out-Null
}
TestStep 'REG-10' 'Change lab DWORD repeatedly' {
    foreach($value in @(10,20,30)){Set-ItemProperty -Path $global:LabReg -Name Counter -Value $value;Start-Sleep -Milliseconds 100}
}
TestStep 'REG-11' 'Export lab registry key to REG file using reg.exe' {
    $native='HKCU\Software\SandboxBehaviorTest\'+$runId
    $out=Join-Path $root 'lab-export.reg'
    & "$env:SystemRoot\System32\reg.exe" export $native $out /y | Out-Null
    if($LASTEXITCODE -ne 0){throw "reg export exit=$LASTEXITCODE"}
}
TestStep 'REG-12' 'Delete nested lab registry subkey' {
    $path=Join-Path $global:LabReg 'Nested'
    Remove-Item -Path $path -Recurse -Force
}

# ---- Certificate/file trust metadata, no signing-policy bypass ----
TestStep 'SIGN-03' 'Verify Authenticode status of Windows PowerShell executable' {
    $file=Join-Path $PSHOME 'powershell.exe'
    $sig=Get-AuthenticodeSignature -LiteralPath $file
    SaveJson 'windows-exe-signature.json' @{file=$file;status=$sig.Status.ToString();subject=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{''}}
}
TestStep 'SIGN-04' 'Hash built-in system executable as reference' {
    $file="$env:SystemRoot\System32\whoami.exe"
    $h=Get-FileHash -LiteralPath $file -Algorithm SHA256
    SaveJson 'trusted-file-hash.json' @{file=$file;sha256=$h.Hash}
}
TestStep 'SIGN-05' 'Write harmless signature-enforcement test plan' {
    SaveJson 'signature-enforcement-plan.json' @{mode='INFORMATIONAL_ONLY';cases=@('unsigned benign script','trusted signed utility','invalid signature reference');note='Code-integrity enforcement is not tested by this read-only check.'}
}

# ---- Timing measurements without environment-dependent behavior ----
TestStep 'TIME-03' 'Measure short repeat intervals' {
    $samples=@()
    foreach($n in 1..7){$sw=[Diagnostics.Stopwatch]::StartNew();Start-Sleep -Milliseconds 200;$sw.Stop();$samples+=@{n=$n;actual_ms=$sw.Elapsed.TotalMilliseconds}}
    SaveJson 'time-repeat.json' $samples
}
TestStep 'TIME-04' 'Measure bounded CPU calculation time' {
    $sw=[Diagnostics.Stopwatch]::StartNew();$sum=0L
    for($n=1;$n -le 200000;$n++){$sum+=($n % 13)}
    $sw.Stop();SaveJson 'cpu-benchmark.json' @{iterations=200000;sum=$sum;elapsed_ms=$sw.Elapsed.TotalMilliseconds}
}
TestStep 'TIME-05' 'Measure file I/O duration inside run directory' {
    $f=Join-Path $root 'io-timing.dat';$data=New-Object byte[] 65536
    $sw=[Diagnostics.Stopwatch]::StartNew()
    [IO.File]::WriteAllBytes($f,$data);[void][IO.File]::ReadAllBytes($f)
    $sw.Stop();SaveJson 'io-benchmark.json' @{bytes=$data.Length;elapsed_ms=$sw.Elapsed.TotalMilliseconds}
}
TestStep 'TIME-06' 'Record UTC time and monotonic clock progression' {
    $a=[Diagnostics.Stopwatch]::GetTimestamp();$start=(Get-Date).ToUniversalTime()
    Start-Sleep -Milliseconds 300
    $b=[Diagnostics.Stopwatch]::GetTimestamp();$end=(Get-Date).ToUniversalTime()
    SaveJson 'dual-clock.json' @{wall_elapsed_ms=($end-$start).TotalMilliseconds;mono_ticks=($b-$a);frequency=[Diagnostics.Stopwatch]::Frequency}
}

# ---- Controlled local transport. No external data, injection or credentials ----
if(!$SkipNetwork) {
    TestStep 'NET-05' 'Create loopback TCP listener and connect to it' {
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
        $listener.Start()
        try {
            $port=([Net.IPEndPoint]$listener.LocalEndpoint).Port
            $client=New-Object Net.Sockets.TcpClient
            try {$client.Connect('127.0.0.1',$port);$server=$listener.AcceptTcpClient();$server.Close()}
            finally {$client.Close()}
            SaveJson 'loopback-tcp.json' @{host='127.0.0.1';port=$port;connected=$true}
        } finally {$listener.Stop()}
    }
    TestStep 'NET-06' 'Transmit fixed benign payload over loopback UDP' {
        $receiver=New-Object Net.Sockets.UdpClient(0)
        $sender=New-Object Net.Sockets.UdpClient
        try {
            $port=([Net.IPEndPoint]$receiver.Client.LocalEndPoint).Port
            $payload=[Text.Encoding]::ASCII.GetBytes('BENIGN_SANDBOX_UDP')
            [void]$sender.Send($payload,$payload.Length,'127.0.0.1',$port)
            $receiver.Client.ReceiveTimeout=1500
            $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
            $received=$receiver.Receive([ref]$remote)
            SaveJson 'loopback-udp.json' @{port=$port;bytes=$received.Length;marker='BENIGN_SANDBOX_UDP'}
        } finally {$sender.Close();$receiver.Close()}
    }
    TestStep 'NET-07' 'Inspect local connection summary after transport tests' {
        $v=Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 50 State,LocalAddress,LocalPort,RemoteAddress,RemotePort
        SaveJson 'tcp-connections.json' @($v)
    }
}

# ---- Clearly synthetic high-risk cases: observable local files, NOT ATT&CK execution ----
TestStep 'SIM-03' 'Write inert injection scenario data (no injection)' {
    SaveJson 'simulated-injection.json' @{mode='INERT_TEST_DATA';executed=$false;technique='T1055';label='Process injection was NOT performed'}
}
TestStep 'SIM-04' 'Write inert service creation data (no service installed)' {
    SaveJson 'simulated-service.json' @{mode='INERT_TEST_DATA';executed=$false;technique='T1543.003';label='No service was created'}
}
TestStep 'SIM-05' 'Write inert credential-access case (no credentials accessed)' {
    SaveJson 'simulated-credentials.json' @{mode='INERT_TEST_DATA';executed=$false;technique='T1003';label='No credential sources accessed'}
}
TestStep 'SIM-06' 'Write inert defense-evasion case (no protection bypass)' {
    SaveJson 'simulated-evasion.json' @{mode='INERT_TEST_DATA';executed=$false;technique='T1562';label='No logging, AV or EDR controls modified'}
}


# ----- Additional observable benign behavior scenarios; lab-owned resources only -----
TestStep 'DISC-18' 'Read PowerShell host and execution configuration' {
    SaveJson 'ps-host.json' @{host=$Host.Name;ps_edition=$PSVersionTable.PSEdition;language_mode=$ExecutionContext.SessionState.LanguageMode.ToString()}
}
TestStep 'DISC-19' 'List bounded local TCP listeners' {
    $v=Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -First 25 LocalAddress,LocalPort,OwningProcess
    SaveJson 'tcp-listeners.json' @($v)
}
TestStep 'DISC-20' 'Read installed Windows Defender status if available' {
    if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $v=Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
        SaveJson 'defender-status.json' $v
    } else {SaveJson 'defender-status.json' @{available=$false}}
}
TestStep 'DISC-21' 'Read code integrity policy metadata if exposed' {
    SaveJson 'execution-policy.json' @{policy=(Get-ExecutionPolicy -List | Out-String)}
}
TestStep 'DISC-22' 'Inspect bounded local DNS cache where supported' {
    if(Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
        $v=Get-DnsClientCache | Select-Object -First 25 Entry,RecordType,Status
        SaveJson 'dns-cache.json' @($v)
    }
}
TestStep 'DISC-23' 'Read system uptime and physical memory summary' {
    $os=Get-CimInstance Win32_OperatingSystem
    SaveJson 'system-profile.json' @{last_boot=$os.LastBootUpTime;free_physical_kb=$os.FreePhysicalMemory;total_visible_kb=$os.TotalVisibleMemorySize}
}
TestStep 'PROC-13' 'Multi-level cmd.exe shell lineage' {
    $p=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c cmd.exe /d /c echo LAB_NESTED_SHELL_MARKER' -WindowStyle Hidden -PassThru -Wait
    SaveJson 'nested-shell.json' @{root_child_pid=$p.Id;exit_code=$p.ExitCode;marker='LAB_NESTED_SHELL_MARKER'}
}
TestStep 'PROC-14' 'PowerShell child writes bounded marker file' {
    $target=Join-Path $global:LabRoot 'child-written.txt'
    $quoted=$target.Replace("'","''")
    $args='-NoProfile -Command "Set-Content -LiteralPath '''+$quoted+''' -Value LAB_CHILD_FILE_MARKER"'
    $p=Start-Process -FilePath 'powershell.exe' -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if(!(Test-Path -LiteralPath $target)) {throw 'Child marker file not created'}
}
TestStep 'PROC-15' 'PowerShell child writes standard error output' {
    $stdout=Join-Path $global:LabRoot 'child-stdout.txt'
    $stderr=Join-Path $global:LabRoot 'child-stderr.txt'
    $p=Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -Command "[Console]::Error.WriteLine(''LAB_STDERR_MARKER''); Write-Output LAB_STDOUT_MARKER"' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
}
TestStep 'PROC-16' 'Use certutil to hash lab-owned benign file' {
    $file=Join-Path $global:LabRoot 'hash-input.txt'
    Set-Content -LiteralPath $file -Value 'LAB_CERTUTIL_HASH_ONLY' -Encoding ASCII
    $output=& "$env:SystemRoot\System32\certutil.exe" -hashfile $file SHA256 2>&1
    SaveJson 'certutil-hash-output.json' @{output=($output | Out-String)}
}
TestStep 'PROC-17' 'Read limited command line and parent process details' {
    $v=Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Select-Object ProcessId,ParentProcessId,Name,CommandLine
    SaveJson 'own-process-lineage.json' $v
}
TestStep 'FILE-24' 'Create many small numbered benign artifacts' {
    $dir=Join-Path $global:LabRoot 'batch-files'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
    1..12 | ForEach-Object {Set-Content -LiteralPath (Join-Path $dir ('marker-{0:D2}.txt' -f $_)) -Value ('LAB_BATCH_{0:D2}' -f $_)}
}
TestStep 'FILE-25' 'Copy artifact through multiple lab directories' {
    $a=Join-Path $global:LabRoot 'stage-a';$b=Join-Path $global:LabRoot 'stage-b'
    New-Item -ItemType Directory -Path $a,$b -Force | Out-Null
    $one=Join-Path $a 'payload-benign.txt';Set-Content $one 'LAB_STAGE_CONTENT'
    Copy-Item -LiteralPath $one -Destination (Join-Path $b 'payload-benign.txt')
}
TestStep 'FILE-26' 'Create harmless script and configuration file as artifacts only' {
    Set-Content -LiteralPath (Join-Path $global:LabRoot 'inert-example.cmd') -Value '@echo OFF' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $global:LabRoot 'inert-example.ini') -Value '[Lab]`nEnabled=true' -Encoding UTF8
}
TestStep 'FILE-27' 'Create and inspect file hash manifest' {
    $files=Get-ChildItem -LiteralPath $global:LabRoot -File | Select-Object -First 15
    $manifest=@($files | ForEach-Object { [pscustomobject]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    SaveJson 'file-hash-manifest.json' $manifest
}
TestStep 'FILE-28' 'Write and read newline-delimited JSON records' {
    $path=Join-Path $global:LabRoot 'synthetic-records.jsonl'
    foreach($n in 1..8) { @{synthetic=$true;index=$n;marker='LAB_ONLY'} | ConvertTo-Json -Compress | Add-Content -LiteralPath $path }
    $count=@(Get-Content -LiteralPath $path).Count; SaveJson 'synthetic-record-count.json' @{count=$count}
}
TestStep 'FILE-29' 'Create and delete isolated empty directories' {
    $dir=Join-Path $global:LabRoot 'empty-tree'; New-Item -ItemType Directory -Path (Join-Path $dir 'nested') -Force | Out-Null
    Remove-Item -LiteralPath $dir -Recurse -Force
}
TestStep 'REG-13' 'Create short-lived Boolean-style lab configuration' {
    New-Item -Path $global:LabReg -Force | Out-Null
    New-ItemProperty -Path $global:LabReg -Name 'LabFeatureEnabled' -PropertyType DWord -Value 1 -Force | Out-Null
}
TestStep 'REG-14' 'Read back own lab key and serialize values' {
    $r=Get-ItemProperty -Path $global:LabReg -ErrorAction Stop
    SaveJson 'lab-registry-readback.json' @{LabFeatureEnabled=$r.LabFeatureEnabled}
}
TestStep 'REG-15' 'Update own key value in short series' {
    foreach($n in 2..5) {Set-ItemProperty -Path $global:LabReg -Name 'LabFeatureEnabled' -Value $n;Start-Sleep -Milliseconds 120}
}
TestStep 'REG-16' 'Write and delete temporary string registry value' {
    New-ItemProperty -Path $global:LabReg -Name 'TransientMarker' -Value 'LAB_TRANSIENT' -PropertyType String -Force | Out-Null
    Remove-ItemProperty -Path $global:LabReg -Name 'TransientMarker'
}
TestStep 'TIME-07' 'Measure jitter for a sequence of bounded delays' {
    $samples=@();foreach($i in 1..12){$timer=[Diagnostics.Stopwatch]::StartNew();Start-Sleep -Milliseconds 150;$timer.Stop();$samples+=$timer.Elapsed.TotalMilliseconds}
    SaveJson 'delay-jitter.json' @{target_ms=150;measurements_ms=$samples}
}
TestStep 'TIME-08' 'Compare wall-clock and monotonic elapsed time' {
    $start=[DateTime]::UtcNow;$clock=[Diagnostics.Stopwatch]::StartNew();Start-Sleep -Milliseconds 400;$clock.Stop()
    SaveJson 'clock-comparison.json' @{wall_ms=([DateTime]::UtcNow-$start).TotalMilliseconds;monotonic_ms=$clock.Elapsed.TotalMilliseconds}
}
TestStep 'SIGN-06' 'Check signature of built-in Windows command shell' {
    $s=Get-AuthenticodeSignature -FilePath "$env:SystemRoot\System32\cmd.exe"
    SaveJson 'signature-cmd.json' @{status=$s.Status.ToString();signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null}}
}
TestStep 'SIGN-07' 'Read trusted file timestamp and checksum metadata' {
    $p="$env:SystemRoot\System32\cmd.exe";$item=Get-Item -LiteralPath $p
    SaveJson 'reference-metadata.json' @{name=$item.Name;length=$item.Length;last_write=$item.LastWriteTimeUtc;sha256=(Get-FileHash $p -Algorithm SHA256).Hash}
}
TestStep 'SIM-07' 'Describe inert scheduled task example (not created)' {
    SaveJson 'inert-task.json' @{simulation=$true;executed=$false;note='No scheduled task is registered';example_action='write marker only'}
}
TestStep 'SIM-08' 'Describe inert network lateral movement example (not executed)' {
    SaveJson 'inert-remote-action.json' @{simulation=$true;executed=$false;note='No remote access, login, or credential use'}
}
# ----- Sequences: report must show causal order rather than only raw counts -----
TestStep 'CHAIN-01' 'Sequence A: child-process then marker-file change' {
    $p=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c echo LAB_CHAIN_A' -Wait -PassThru -WindowStyle Hidden
    Set-Content -LiteralPath (Join-Path $global:LabRoot 'chain-a.txt') -Value "child=$($p.Id);marker=LAB_CHAIN_A"
}
TestStep 'CHAIN-02' 'Sequence B: registry configuration then local file' {
    New-Item -Path $global:LabReg -Force | Out-Null
    New-ItemProperty -Path $global:LabReg -Name 'ChainB' -PropertyType String -Value 'LAB_CHAIN_B' -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $global:LabRoot 'chain-b.txt') -Value 'LAB_CHAIN_B'
}
TestStep 'CHAIN-03' 'Sequence C: archive generation after several file writes' {
    $d=Join-Path $global:LabRoot 'chain-c-input';New-Item -Path $d -ItemType Directory -Force | Out-Null
    foreach($n in 1..4){Set-Content -LiteralPath (Join-Path $d "item-$n.txt") -Value "LAB_CHAIN_C_$n"}
    Compress-Archive -Path (Join-Path $d '*.txt') -DestinationPath (Join-Path $global:LabRoot 'chain-c.zip') -Force
}

# ----- Cleanup key only; retain run artifacts for analysis -----
if (!$KeepRegistry) {
    TestStep 'REG-06' 'Remove only this run HKCU key' {
        if(Test-Path $global:LabReg) {Remove-Item -Path $global:LabReg -Recurse -Force}
    }
}
$endUtc=(Get-Date).ToUniversalTime()
$ends=@($global:LabResults | Where-Object {$_.phase -eq 'END'})
$report=[ordered]@{
    title='Sandbox Behavior & Report Validation';version='6.0';run_id=$runId;
    start_utc=$startUtc.ToString('o');end_utc=$endUtc.ToString('o');
    root=$root;powershell_pid=$PID;test_count=$ends.Count;
    succeeded=@($ends | Where-Object {$_.status -eq 'SUCCESS'}).Count;
    failed=@($ends | Where-Object {$_.status -eq 'ERROR'}).Count;
    network_get=if($SkipNetwork){'disabled'}else{$GetUri.AbsoluteUri};
    network_post=if($EnableSyntheticPost){$PostUri.AbsoluteUri}else{'disabled'};
    security_notes='No security bypass; no autorun persistence; no credential collection; no exfiltration.'
}
SaveJson 'summary.json' $report
LogEvent 'META-02' 'END' 'SUCCESS' 'Lab finished; read summary.json and events.jsonl'
Write-Host "`nFinished. Artifacts: $root"
