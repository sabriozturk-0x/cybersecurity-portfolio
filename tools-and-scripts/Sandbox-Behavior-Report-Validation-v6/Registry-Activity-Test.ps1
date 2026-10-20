# Registry Activity Test - benign sandbox validation
# Runs only inside HKCU\Software\SandboxRegistryActivityLab\<RunId>.
# No autostart, policy, service, security-product or system registry changes.
[CmdletBinding()]
param(
    [ValidateRange(1,100)][int]$Batches = 20,
    [ValidateRange(1,50)][int]$ValuesPerBatch = 10,
    [ValidateRange(0,2000)][int]$PauseMs = 25,
    [switch]$Cleanup,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = 'Stop'
$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$Base = 'HKCU:\Software\SandboxRegistryActivityLab'
$Root = Join-Path $Base $RunId
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $env:TEMP ('RegistryActivityLab-' + $RunId) }
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
$Jsonl = Join-Path $OutputDirectory 'events.jsonl'
$SummaryFile = Join-Path $OutputDirectory 'summary.json'
$Counters = [ordered]@{attempted=0;success=0;failed=0;created_keys=0;created_values=0;updated_values=0;deleted_values=0;deleted_keys=0;read_values=0;enumerations=0}
$Failures = New-Object 'System.Collections.Generic.List[string]'

function Record-Event {
    param([string]$Operation,[string]$Path,[string]$Name,[string]$Status,[string]$Detail='')
    $obj = [ordered]@{time=(Get-Date).ToUniversalTime().ToString('o');run_id=$RunId;operation=$Operation;path=$Path;name=$Name;status=$Status;detail=$Detail}
    $obj | ConvertTo-Json -Compress -Depth 4 | Add-Content -LiteralPath $Jsonl -Encoding UTF8
}
function Invoke-LabAction {
    param([string]$Counter,[string]$Operation,[string]$Path,[string]$Name,[scriptblock]$Action)
    $Counters.attempted++
    try {
        & $Action | Out-Null
        $Counters.success++
        $Counters[$Counter]++
        Record-Event $Operation $Path $Name 'SUCCESS'
    } catch {
        $Counters.failed++
        $message = $_.Exception.Message
        $Failures.Add("${Operation}: ${Path}: ${message}")
        Record-Event $Operation $Path $Name 'ERROR' $message
    }
}

Write-Host "RunId: $RunId"
Write-Host "Registry scope: $Root"
Write-Host "Log directory: $OutputDirectory"

Invoke-LabAction 'created_keys' 'CreateKey' $Base '' { New-Item -Path $Base -Force }
Invoke-LabAction 'created_keys' 'CreateKey' $Root '' { New-Item -Path $Root -Force }
for ($b=1; $b -le $Batches; $b++) {
    $key = Join-Path $Root ('Batch-{0:D3}' -f $b)
    $nested = Join-Path $key 'Nested'
    Invoke-LabAction 'created_keys' 'CreateKey' $key '' { New-Item -Path $key -Force }
    Invoke-LabAction 'created_keys' 'CreateKey' $nested '' { New-Item -Path $nested -Force }
    for ($i=1; $i -le $ValuesPerBatch; $i++) {
        $name = ('Marker-{0:D3}' -f $i)
        $value = "SANDBOX_REG_TEST_${RunId}_${b}_${i}"
        Invoke-LabAction 'created_values' 'CreateValue:String' $key $name {
            New-ItemProperty -LiteralPath $key -Name $name -PropertyType String -Value $value -Force
        }
        Invoke-LabAction 'updated_values' 'UpdateValue:String' $key $name {
            Set-ItemProperty -LiteralPath $key -Name $name -Value ($value + '_UPDATED')
        }
        Invoke-LabAction 'read_values' 'ReadValue' $key $name {
            $p = Get-ItemProperty -LiteralPath $key -Name $name
            if ($null -eq $p.$name) { throw 'Missing value' }
        }
    }
    $dwordName = 'BatchCount'
    Invoke-LabAction 'created_values' 'CreateValue:DWord' $key $dwordName {
        New-ItemProperty -LiteralPath $key -Name $dwordName -PropertyType DWord -Value $b -Force
    }
    Invoke-LabAction 'updated_values' 'UpdateValue:DWord' $key $dwordName {
        Set-ItemProperty -LiteralPath $key -Name $dwordName -Value ($b * 2)
    }
    Invoke-LabAction 'created_values' 'CreateValue:Binary' $nested 'BinaryMarker' {
        [byte[]]$bytes = @(0x53,0x41,0x4E,0x44,0x42,0x4F,0x58,($b % 256))
        New-ItemProperty -LiteralPath $nested -Name 'BinaryMarker' -PropertyType Binary -Value $bytes -Force
    }
    Invoke-LabAction 'created_values' 'CreateValue:MultiString' $nested 'MultiMarker' {
        [string[]]$arr = @('Sandbox','Registry','Test',"Batch-$b")
        New-ItemProperty -LiteralPath $nested -Name 'MultiMarker' -PropertyType MultiString -Value $arr -Force
    }
    Invoke-LabAction 'enumerations' 'EnumerateValues' $key '' {
        Get-ItemProperty -LiteralPath $key
    }
    Invoke-LabAction 'enumerations' 'EnumerateSubkeys' $key '' {
        Get-ChildItem -LiteralPath $key
    }
    # Intentional short-lived key and value provide deletion telemetry.
    $temporary = Join-Path $key 'Temporary'
    Invoke-LabAction 'created_keys' 'CreateKey' $temporary '' { New-Item -Path $temporary -Force }
    Invoke-LabAction 'created_values' 'CreateValue:String' $temporary 'Ephemeral' {
        New-ItemProperty -LiteralPath $temporary -Name 'Ephemeral' -PropertyType String -Value 'DELETE_ME_TEST' -Force
    }
    Invoke-LabAction 'deleted_values' 'DeleteValue' $temporary 'Ephemeral' {
        Remove-ItemProperty -LiteralPath $temporary -Name 'Ephemeral' -Force
    }
    Invoke-LabAction 'deleted_keys' 'DeleteKey' $temporary '' {
        Remove-Item -LiteralPath $temporary -Force
    }
    if ($PauseMs -gt 0) { Start-Sleep -Milliseconds $PauseMs }
}

$ExistsBeforeCleanup = Test-Path -LiteralPath $Root
if ($Cleanup) {
    Invoke-LabAction 'deleted_keys' 'CleanupRoot' $Root '' {
        Remove-Item -LiteralPath $Root -Recurse -Force
    }
}
$summary = [ordered]@{
    run_id=$RunId
    registry_path=$Root
    output_directory=$OutputDirectory
    batches=$Batches
    values_per_batch=$ValuesPerBatch
    counters=$Counters
    registry_existed_before_optional_cleanup=$ExistsBeforeCleanup
    registry_exists_after_run=(Test-Path -LiteralPath $Root)
    errors=@($Failures.ToArray())
    finished_at=(Get-Date).ToUniversalTime().ToString('o')
}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $SummaryFile -Encoding UTF8
Write-Host "`nOperations: $($Counters.attempted) attempted, $($Counters.success) succeeded, $($Counters.failed) failed"
Write-Host "Registry key remains: $(Test-Path -LiteralPath $Root)"
Write-Host "Summary: $SummaryFile"
Write-Host "Events: $Jsonl"
