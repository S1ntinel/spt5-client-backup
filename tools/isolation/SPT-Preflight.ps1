param([string]$SPT_DEPLOY_ROOT = $env:SPT_DEPLOY_ROOT)
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null
$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$env:SPT_GUARD_ROOT = $SPT_DEPLOY_ROOT
try {
    $processes = @(Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath)
    $processes | ConvertTo-Json -Depth 3 -Compress | & python (Join-Path $PSScriptRoot 'guard.py') launch
    exit $LASTEXITCODE
} catch {
    Write-Error $_
    exit 1
}
