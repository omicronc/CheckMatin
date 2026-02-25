param(
    [string]$OutDir = "dist"
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (Test-Path $OutDir) {
    Remove-Item -Recurse -Force $OutDir
}

New-Item -ItemType Directory -Force -Path "$OutDir/chrome" | Out-Null
New-Item -ItemType Directory -Force -Path "$OutDir/firefox" | Out-Null

$commonFiles = @(
    "background.js",
    "options.html",
    "options.js",
    "popup.html",
    "popup.js",
    "styles.css"
)

foreach ($f in $commonFiles) {
    Copy-Item $f "$OutDir/chrome/$f"
    Copy-Item $f "$OutDir/firefox/$f"
}

Copy-Item "manifest_chrome.json" "$OutDir/chrome/manifest.json"
Copy-Item "manifest_firefox.json" "$OutDir/firefox/manifest.json"

Copy-Item "manifest_chrome.json" "$OutDir/manifest_chrome.json"
Copy-Item "manifest_firefox.json" "$OutDir/manifest_firefox.json"

Copy-Item "assets" "$OutDir/chrome" -Recurse
Copy-Item "assets" "$OutDir/firefox" -Recurse

Write-Host "Build terminé :"
Write-Host " - $OutDir/chrome"
Write-Host " - $OutDir/firefox"
