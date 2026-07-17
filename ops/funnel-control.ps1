# Funnel control panel (shared node paskamyrsky.tail6ed53b.ts.net).
#
# This node runs three funnel-capable services. Two are GPU-bound RAGs that
# both use port 443, run one at a time, and are each driven by their own tool
# (ragctl for mikkonumminen.dev, feedctl for feedback-intelligence). This
# panel does NOT touch their funnel: it shows their status read-only and
# points at their tools. It owns only the vault, which needs no GPU and sits
# on port 8443 so it coexists with whichever RAG holds 443.
#
# Safety: backs up the serve config before any change, scopes every change to
# a single port, and NEVER runs `tailscale funnel reset` - the same rule
# ragctl and feedctl follow, because one reset would wipe all three services.

param(
    [string]$DataDir = "$env:APPDATA\PasswordManager",
    [string]$ResourcesFile = (Join-Path $PSScriptRoot "resources.json")
)

$ErrorActionPreference = "Stop"
$ts = "C:\Program Files\Tailscale\tailscale.exe"
if (-not (Test-Path $ts)) { throw "tailscale not found at $ts" }
if (-not (Test-Path $ResourcesFile)) { throw "resources file not found: $ResourcesFile" }

$resources = (Get-Content $ResourcesFile -Raw | ConvertFrom-Json).resources
$dnsName = ((& $ts status --json | ConvertFrom-Json).Self.DNSName).TrimEnd('.')

function Get-ServeConfig {
    $raw = & $ts serve status --json 2>$null
    if (-not $raw) { return [pscustomobject]@{} }
    return ($raw | ConvertFrom-Json)
}

# Current public state of a funnel port: on/off and the local target.
function Get-PortState($cfg, [int]$port) {
    $key = "${dnsName}:${port}"
    $on = $false
    if ($cfg.AllowFunnel -and $cfg.AllowFunnel.PSObject.Properties.Name -contains $key) {
        $on = [bool]$cfg.AllowFunnel.$key
    }
    $target = $null
    if ($cfg.Web -and $cfg.Web.PSObject.Properties.Name -contains $key) {
        $h = $cfg.Web.$key.Handlers
        if ($h -and $h.PSObject.Properties.Name -contains "/") { $target = $h."/".Proxy }
    }
    return [pscustomobject]@{ On = $on; Target = $target }
}

function Backup-Config {
    $dir = Join-Path $DataDir "funnel-backups"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $path = Join-Path $dir ("serve-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")
    (& $ts serve status --json 2>$null) | Set-Content -Path $path -Encoding utf8
    return $path
}

function Show-Panel {
    $cfg = Get-ServeConfig
    Write-Host ""
    Write-Host "  funnel control  ($dnsName)" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------"
    for ($i = 0; $i -lt $resources.Count; $i++) {
        $r = $resources[$i]
        $state = Get-PortState $cfg $r.funnel_port
        $mark = if ($state.On) { "[ ON  ]" } else { "[ off ]" }
        $color = if ($state.On) { "Green" } else { "DarkGray" }
        $own = if ($r.owned) { " " } else { "*" }
        Write-Host ("  {0}){1}{2,-26} :{3,-5} {4}" -f ($i + 1), $own, $r.label, $r.funnel_port, $mark) -ForegroundColor $color
        if (-not $r.owned) {
            $who = if ($state.On -and $state.Target) { "-> $($state.Target)" } else { "" }
            Write-Host ("        managed by: {0}   {1}" -f $r.tool, $who) -ForegroundColor DarkGray
        }
        elseif ($state.On -and $state.Target) {
            Write-Host "        -> $($state.Target)" -ForegroundColor DarkGray
        }
    }
    Write-Host "  ----------------------------------------------------------"
    $on443 = Get-PortState $cfg 443
    $p443 = if ($on443.On) { "in use ($($on443.Target))" } else { "free" }
    $on8443 = Get-PortState $cfg 8443
    $p8443 = if ($on8443.On) { "in use" } else { "free" }
    Write-Host ("  port 443 (RAGs): {0}    port 8443 (vault): {1}" -f $p443, $p8443)
    Write-Host "  * = managed by its own tool; this panel shows it read-only"
    Write-Host "  number = act on that resource,  r = refresh,  q = quit"
    Write-Host ""
}

function Toggle-Owned($r) {
    $cfg = Get-ServeConfig
    $state = Get-PortState $cfg $r.funnel_port

    if ($state.On) {
        Write-Host "Turning OFF funnel for '$($r.label)' on port $($r.funnel_port)..."
        $b = Backup-Config; Write-Host "  (backed up to $b)"
        & $ts funnel --https=$($r.funnel_port) off
        if ($LASTEXITCODE -eq 0) { Write-Host "  off." -ForegroundColor Yellow } else { Write-Host "  failed (exit $LASTEXITCODE)" -ForegroundColor Red }
        return
    }
    if ($state.Target -and $state.Target -ne $r.target) {
        Write-Host "REFUSING: port $($r.funnel_port) already serves $($state.Target) (not $($r.target))." -ForegroundColor Red
        return
    }
    Write-Host "Have you started the gate (ops\serve-public.ps1)? It must be running on :4180." -ForegroundColor Yellow
    Write-Host "This exposes '$($r.label)' to the PUBLIC internet at" -ForegroundColor Yellow
    Write-Host "  https://$dnsName`:$($r.funnel_port)" -ForegroundColor Yellow
    if ((Read-Host "Type 'yes' to confirm") -ne "yes") { Write-Host "  cancelled."; return }
    $b = Backup-Config; Write-Host "  (backed up to $b)"
    & $ts funnel --bg --https=$($r.funnel_port) $r.target
    if ($LASTEXITCODE -eq 0) { Write-Host "  ON -> https://$dnsName`:$($r.funnel_port)" -ForegroundColor Green }
    else { Write-Host "  failed (exit $LASTEXITCODE)" -ForegroundColor Red }
}

function Show-External($r) {
    Write-Host ""
    Write-Host "'$($r.label)' is managed by its own tool, not this panel." -ForegroundColor Cyan
    Write-Host "  local:   $($r.local)   funnel port: $($r.funnel_port)"
    Write-Host "  control: $($r.tool)"
    Write-Host "  dir:     $($r.dir)"
    Write-Host "  It is GPU-bound and shares port 443 with the other RAG (one at a time)."
    Write-Host ""
}

while ($true) {
    Show-Panel
    $choice = Read-Host "choice"
    switch -Regex ($choice) {
        '^[qQ]$' { Write-Host "bye."; return }
        '^[rR]$' { continue }
        '^\d+$' {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $resources.Count) {
                $r = $resources[$idx]
                if ($r.owned) { Toggle-Owned $r } else { Show-External $r }
            }
            else { Write-Host "no such resource." -ForegroundColor Red }
        }
        default { Write-Host "?" -ForegroundColor Red }
    }
}
