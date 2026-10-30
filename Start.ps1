[CmdletBinding()]
param([string]$Runtime, [switch]$Software)
$ErrorActionPreference = 'Stop'
try {
    if (-not $Runtime) { $Runtime = Join-Path (Split-Path -Parent $PSScriptRoot) 'NBT-Emulator-Private' }
    $state = Join-Path $Runtime 'runtime.json'
    if (-not (Test-Path -LiteralPath $state)) { throw 'Prepare a private runtime first; see README.md.' }
    $settings = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
    $python = $settings.python
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Python moved. Run prepare.py again using your current Python installation.' }
    $arguments = @((Join-Path $PSScriptRoot 'nbt_emulator.py'), 'run', '--runtime', $Runtime)
    if ($Software) { $arguments += '--software' }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw "NBT Emulator exited with code $LASTEXITCODE." }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    Read-Host 'Press Enter to close' | Out-Null
    exit 1
}
