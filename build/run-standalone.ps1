param(
  [string]$Version = "dev-standalone",
  [switch]$NoLaunch,
  [switch]$Foreground
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $root "build"
$deskaccessExe = Join-Path $out "DeskAccess.exe"
$sidecarExe = Join-Path $out "deskaccess-iroh-sidecar.exe"
$sidecarManifest = Join-Path $root "sidecars\iroh-sidecar\Cargo.toml"
$sidecarBuiltExe = Join-Path $root "sidecars\iroh-sidecar\target\release\deskaccess-iroh-sidecar.exe"

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

Push-Location $root
try {
  New-Item -ItemType Directory -Force -Path $out | Out-Null

  Write-Host "==> Building DeskAccess"
  Invoke-Checked "go" @(
    "build",
    "-buildvcs=false",
    "-ldflags", "-s -w -X main.version=$Version",
    "-o", $deskaccessExe,
    ".\cmd\deskaccess"
  )

  Write-Host "==> Building iroh sidecar"
  Invoke-Checked "cargo" @(
    "build",
    "--manifest-path", $sidecarManifest,
    "--release"
  )

  Write-Host "==> Staging standalone binaries"
  Copy-Item -Force $sidecarBuiltExe $sidecarExe

  Write-Host ""
  Write-Host "Standalone build ready:"
  Write-Host "  $deskaccessExe"
  Write-Host "  $sidecarExe"

  if (-not $NoLaunch) {
    Write-Host ""
    Write-Host "==> Launching DeskAccess"
    if ($Foreground) {
      Push-Location $out
      try {
        & $deskaccessExe --standalone
      } finally {
        Pop-Location
      }
    } else {
      Start-Process -FilePath $deskaccessExe -ArgumentList @("--standalone") -WorkingDirectory $out
    }
  }
} finally {
  Pop-Location
}
