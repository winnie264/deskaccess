param(
  [string]$Version = "dev-standalone",
  [string]$OutDir = "dist",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $root $OutDir
$stageRoot = Join-Path $out "stage"
$stage = Join-Path $stageRoot "DeskAccess-windows-amd64-portable"
$packages = Join-Path $out "packages"
$pkg = ".\cmd\deskaccess"
$sidecarManifest = Join-Path $root "sidecars\iroh-sidecar\Cargo.toml"
$deskaccessExe = Join-Path $stage "DeskAccess.exe"
$sidecarExe = Join-Path $stage "deskaccess-iroh-sidecar.exe"
$zip = Join-Path $packages "DeskAccess-$Version-windows-amd64-portable.zip"
$shaFile = Join-Path $packages "SHA256SUMS.txt"

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE"
  }
}

function Write-TextFile {
  param(
    [string]$Path,
    [string[]]$Lines
  )

  Set-Content -Path $Path -Value $Lines -Encoding ascii
}

Push-Location $root
try {
  Write-Host "Packaging DeskAccess portable Windows build v$Version"

  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  New-Item -ItemType Directory -Force -Path $packages | Out-Null
  Remove-Item -Force $zip -ErrorAction SilentlyContinue

  if (-not $SkipBuild) {
    Write-Host "==> Building Windows GUI executable"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
    Invoke-Checked "go" @(
      "build",
      "-buildvcs=false",
      "-ldflags", "-s -w -H=windowsgui -X main.version=$Version",
      "-o", $deskaccessExe,
      $pkg
    )

    Write-Host "==> Building Windows iroh sidecar"
    Invoke-Checked "cargo" @(
      "build",
      "--manifest-path", $sidecarManifest,
      "--release",
      "--target", "x86_64-pc-windows-msvc"
    )

    Copy-Item -Force `
      (Join-Path $root "sidecars\iroh-sidecar\target\x86_64-pc-windows-msvc\release\deskaccess-iroh-sidecar.exe") `
      $sidecarExe
  } else {
    Write-Host "==> Reusing existing staged binaries"
    if (-not (Test-Path $deskaccessExe)) {
      throw "Missing $deskaccessExe. Re-run without -SkipBuild."
    }
    if (-not (Test-Path $sidecarExe)) {
      throw "Missing $sidecarExe. Re-run without -SkipBuild."
    }
  }

  Copy-Item -Force (Join-Path $root "resources\deskview.ico") (Join-Path $stage "DeskAccess.ico")

  Write-TextFile -Path (Join-Path $stage "Start-DeskAccess.cmd") -Lines @(
    "@echo off",
    "setlocal",
    "cd /d ""%~dp0""",
    "start """" ""%~dp0DeskAccess.exe"" --standalone"
  )

  Write-TextFile -Path (Join-Path $stage "Start-DeskAccess-Foreground.cmd") -Lines @(
    "@echo off",
    "setlocal",
    "cd /d ""%~dp0""",
    """%~dp0DeskAccess.exe"" --standalone",
    "pause"
  )

  Write-TextFile -Path (Join-Path $stage "README-standalone.txt") -Lines @(
    "DeskAccess Portable for Windows",
    "",
    "How to run:",
    "1. Extract this folder anywhere you can write files.",
    "2. Double-click Start-DeskAccess.cmd.",
    "3. Open http://127.0.0.1:18080 if the dashboard does not open automatically.",
    "",
    "This package does not install a Windows service or write installer state.",
    "Keep DeskAccess.exe and deskaccess-iroh-sidecar.exe in the same folder.",
    "Closing DeskAccess also stops the bundled iroh sidecar."
  )

  Write-Host "==> Creating portable zip"
  Compress-Archive -Force -Path (Join-Path $stage "*") -DestinationPath $zip

  Get-ChildItem $packages -File |
    Where-Object { $_.Extension -in ".zip", ".msi" } |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content -Path $shaFile -Encoding ascii

  Write-Host ""
  Write-Host "Portable package written to $zip"
  Write-Host "Checksums written to $shaFile"
} finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
}
