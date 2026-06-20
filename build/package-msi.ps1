param(
  [string]$Version = "0.1.0",
  [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $root $OutDir
$stage = Join-Path $out "stage\DeskAccess-msi"
$packages = Join-Path $out "packages"
$pkg = "./cmd/deskaccess"
$wxs = Join-Path $PSScriptRoot "windows\DeskAccess.wxs"

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

function Resolve-Wix {
  $cmd = Get-Command wix -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }

  $dotnetTool = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
  if (Test-Path $dotnetTool) {
    return $dotnetTool
  }

  throw "WiX Toolset CLI was not found. Install it with: dotnet tool install --global wix --version 6.*"
}

Push-Location $root
try {
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  New-Item -ItemType Directory -Force -Path $packages | Out-Null
  Remove-Item -Force (Join-Path $packages "DeskAccess-$Version-windows-amd64.msi") -ErrorAction SilentlyContinue
  Remove-Item -Force (Join-Path $packages "SHA256SUMS.txt") -ErrorAction SilentlyContinue

  $exe = Join-Path $stage "DeskAccess.exe"
  $msi = Join-Path $packages "DeskAccess-$Version-windows-amd64.msi"
  $wix = Resolve-Wix

  Write-Host "==> Building Windows GUI executable"
  $env:GOOS = "windows"
  $env:GOARCH = "amd64"
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
  Invoke-Checked "go" @(
    "build",
    "-ldflags", "-s -w -H=windowsgui -X main.version=$Version",
    "-o", $exe,
    $pkg
  )
  Copy-Item -Force (Join-Path $root "resources\deskview.ico") (Join-Path $stage "DeskAccess.ico")

  Write-Host "==> Building MSI"
  Invoke-Checked $wix @(
    "build",
    $wxs,
    "-d", "Version=$Version",
    "-d", "SourceDir=$stage",
    "-o", $msi
  )

  Get-ChildItem $packages -File | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content (Join-Path $packages "SHA256SUMS.txt")

  Write-Host ""
  Write-Host "MSI written to $msi"
} finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
}
