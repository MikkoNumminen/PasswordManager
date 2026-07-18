# Build the extension's bundled assets: the wasm crypto (the same core crate
# the CLI and web page use) and the public suffix list used for domain
# matching. Both land in extension/vendor/ and are gitignored; run this once
# before loading the extension, and again after changing the core crate.

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$vendor = Join-Path $PSScriptRoot "vendor"
New-Item -ItemType Directory -Force $vendor | Out-Null

# Resolve the Rust tools, falling back to the default rustup location.
function Resolve-Tool($name) {
    $onPath = Get-Command $name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $fallback = Join-Path $env:USERPROFILE ".cargo\bin\$name.exe"
    if (Test-Path $fallback) { return $fallback }
    throw "$name not found on PATH or in ~/.cargo/bin. Install Rust and wasm-bindgen-cli."
}
$cargo = Resolve-Tool "cargo"
$wasmBindgen = Resolve-Tool "wasm-bindgen"

# 1. wasm: reuse the web crate's wasm-bindgen output verbatim (one crypto
#    implementation, no second path). Native commands write progress to
#    stderr, so check exit codes rather than trusting error records.
Write-Host "building wasm (password-manager-web)..."
& $cargo build -p password-manager-web --target wasm32-unknown-unknown --release --manifest-path (Join-Path $repo "Cargo.toml")
if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

& $wasmBindgen --target web --no-typescript --out-dir (Join-Path $vendor "pkg") `
    (Join-Path $repo "target\wasm32-unknown-unknown\release\password_manager_web.wasm")
if ($LASTEXITCODE -ne 0) { throw "wasm-bindgen failed ($LASTEXITCODE)" }

# 2. public suffix list, for registrable-domain (eTLD+1) matching. Bundled
#    because the extension may only connect to the configured server origin,
#    so it cannot fetch this at runtime.
$psl = Join-Path $vendor "public_suffix_list.dat"
if (-not (Test-Path $psl)) {
    Write-Host "downloading public suffix list..."
    curl.exe -sSfL -o $psl "https://publicsuffix.org/list/public_suffix_list.dat"
    if ($LASTEXITCODE -ne 0) { throw "public suffix list download failed ($LASTEXITCODE)" }
}

# 3. Verify: every file the extension needs to load, by name. If this passes,
#    Load unpacked will work; if a file is missing, say which one and fail.
$needed = @(
    "manifest.json", "popup.html", "options.html", "offscreen.html",
    "src\background.js", "src\popup.js", "src\options.js", "src\offscreen.js", "src\psl.js",
    "src\rank.js", "src\savepolicy.js",
    "src\content\detect.js", "src\content\dropdown.js", "src\content\banner.js", "src\content\main.js",
    "vendor\pkg\password_manager_web.js", "vendor\pkg\password_manager_web_bg.wasm",
    "vendor\public_suffix_list.dat"
)
$missing = $needed | Where-Object { -not (Test-Path (Join-Path $PSScriptRoot $_)) }
if ($missing) { throw "build incomplete, missing: $($missing -join ', ')" }

Write-Host "done: all $($needed.Count) files present."
Write-Host "Load this folder unpacked in chrome://extensions (Developer mode): $PSScriptRoot"
