# Start the password manager sync server on the private tailnet path.
#
# Binds to the machine's Tailscale IP so other tailnet devices reach it
# directly over the encrypted tailnet. This path touches nothing in the
# shared Tailscale serve/funnel config, so it never affects other services
# (the RAGs) on this node. The public, Google-gated path is separate.
#
# The server is meant to run on demand, not as an always-on service. Start
# it with this script when you need to sync; stop it with Ctrl+C.

param(
    [string]$DataDir = "$env:APPDATA\PasswordManager",
    [int]$Port = 7787,
    [switch]$Web  # also serve the browser client (reveal works; copy needs the https funnel path)
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $PSScriptRoot "..\target\release\password-manager-server.exe"
if (-not (Test-Path $exe)) {
    throw "server binary not found at $exe. Build it: cargo build --release -p password-manager-server"
}

$tailscale = "C:\Program Files\Tailscale\tailscale.exe"
$tailnetIp = (& $tailscale ip -4).Trim()
if (-not $tailnetIp) { throw "no Tailscale IPv4 address; is Tailscale up?" }

$db = Join-Path $DataDir "server.db"
$bind = "${tailnetIp}:${Port}"

$serverArgs = @("--db", $db, "serve", "--bind", $bind)
if ($Web) {
    $webDir = Join-Path $PSScriptRoot "..\web\static"
    $serverArgs += @("--web-dir", $webDir)
}

Write-Host "Serving vault on the tailnet at http://$bind"
Write-Host "Clients: password-manager sync --server http://$bind"
& $exe @serverArgs
