# Interactive console for vaultctl, opened by the desktop shortcut. Puts
# vaultctl on PATH for this window, shows current status, and leaves the
# prompt open so you can run more commands.

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$exeDir = Join-Path $repo "target\release"
$exe = Join-Path $exeDir "vaultctl.exe"
Set-Location $repo

if (-not (Test-Path $exe)) {
    Write-Host ""
    Write-Host "  vaultctl is not built yet." -ForegroundColor Yellow
    Write-Host "  Build it:  cargo build --release -p vaultctl" -ForegroundColor Yellow
    Write-Host ""
    return
}

$env:Path = "$exeDir;$env:Path"

Write-Host ""
Write-Host "  PasswordManager vault console" -ForegroundColor Cyan
Write-Host "  ---------------------------------------------------------------"
Write-Host "  vaultctl up        public (Google gate + funnel 8443)"
Write-Host "  vaultctl tailnet   private (tailnet only)"
Write-Host "  vaultctl down      stop everything"
Write-Host "  vaultctl status    what's running and exposed"
Write-Host "  vaultctl funnel on|off | token | doctor | logs vault|gate"
Write-Host "  ---------------------------------------------------------------"
Write-Host ""
vaultctl status
Write-Host ""
