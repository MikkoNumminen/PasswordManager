# Start the public-path processes for the vault: the vault server bound to
# localhost, and the oauth2-proxy Google gate in front of it. This does NOT
# open the funnel; use the control panel (funnel-control.ps1) to expose the
# 'vault' resource once these are running and Google credentials are filled
# in. Stop with Ctrl+C (stops the proxy; stop the vault window separately).
#
# On demand, not always-on. Run it when you want the vault reachable.

param(
    [string]$DataDir = "$env:APPDATA\PasswordManager"
)

$ErrorActionPreference = "Stop"
$repo = Join-Path $PSScriptRoot ".."
$vaultExe = Join-Path $repo "target\release\password-manager-server.exe"
$proxyExe = Join-Path $DataDir "tools\oauth2-proxy.exe"
$cfg = Join-Path $PSScriptRoot "oauth2-proxy.cfg"
$secretsEnv = Join-Path $DataDir "secrets\oauth2.env"
$emailsFile = Join-Path $DataDir "secrets\allowed-emails.txt"
$webDir = Join-Path $repo "web\static"
$db = Join-Path $DataDir "server.db"

foreach ($p in @($vaultExe, $proxyExe, $cfg, $secretsEnv, $emailsFile)) {
    if (-not (Test-Path $p)) { throw "missing required file: $p" }
}

# Load Google client id/secret and cookie secret from the out-of-repo file.
Get-Content $secretsEnv | ForEach-Object {
    if ($_ -match '^\s*([A-Z0-9_]+)\s*=\s*(.+)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
if ($env:OAUTH2_PROXY_CLIENT_ID -like "REPLACE_*") {
    throw "Google client id/secret not set. Edit $secretsEnv (see ops/README.md)."
}

# Vault server on localhost only: nothing reaches it except through the gate.
Write-Host "starting vault server on 127.0.0.1:7787 (localhost only)"
$vault = Start-Process -FilePath $vaultExe `
    -ArgumentList @("--db", $db, "serve", "--bind", "127.0.0.1:7787", "--web-dir", $webDir) `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 1
Write-Host "starting oauth2-proxy Google gate on 127.0.0.1:4180"
Write-Host "public URL once funnel is on: https://paskamyrsky.tail6ed53b.ts.net:8443"
try {
    & $proxyExe --config $cfg --authenticated-emails-file $emailsFile
}
finally {
    if ($vault -and -not $vault.HasExited) {
        Write-Host "stopping vault server"
        Stop-Process -Id $vault.Id -Force -ErrorAction SilentlyContinue
    }
}
