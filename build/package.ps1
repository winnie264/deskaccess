param(
  [string]$Version = "0.1.1",
  [string]$OutDir = "dist",
  [switch]$IncludeLinux
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$out = Join-Path $root $OutDir
$stage = Join-Path $out "stage"
$packages = Join-Path $out "packages"
$pkg = "./cmd/deskaccess"

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $packages | Out-Null
Remove-Item -Force (Join-Path $packages "DeskAccess-*") -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $packages "SHA256SUMS.txt") -ErrorAction SilentlyContinue

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

function Build-App {
  param(
    [string]$Goos,
    [string]$Goarch,
    [string]$Output,
    [string]$ExtraLdflags = ""
  )

  $env:GOOS = $Goos
  $env:GOARCH = $Goarch
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue

  $ldflags = "-s -w -X main.version=$Version"
  if ($ExtraLdflags) {
    $ldflags = "$ldflags $ExtraLdflags"
  }

  Invoke-Checked "go" @("build", "-ldflags", $ldflags, "-o", $Output, $pkg)
}

function Build-LinuxArm {
  param(
    [string]$Goarm,
    [string]$Output
  )

  $env:GOOS = "linux"
  $env:GOARCH = "arm"
  $env:GOARM = $Goarm
  Invoke-Checked "go" @("build", "-ldflags", "-s -w -X main.version=$Version", "-o", $Output, $pkg)
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
}

Push-Location $root
try {
  Write-Host "Packaging DeskAccess v$Version"

  $winStage = Join-Path $stage "DeskAccess-windows-amd64"
  New-Item -ItemType Directory -Force -Path $winStage | Out-Null
  Build-App -Goos "windows" -Goarch "amd64" -Output (Join-Path $winStage "DeskAccess.exe") -ExtraLdflags "-H=windowsgui"
  Copy-Item (Join-Path $PSScriptRoot "windows\install.ps1") $winStage
  Copy-Item (Join-Path $PSScriptRoot "windows\uninstall.ps1") $winStage
  Copy-Item (Join-Path $root "resources\deskview.ico") (Join-Path $winStage "DeskAccess.ico")
  Compress-Archive -Force -Path (Join-Path $winStage "*") -DestinationPath (Join-Path $packages "DeskAccess-$Version-windows-amd64.zip")

  if ($IncludeLinux) {
    Write-Warning "Linux builds may require Linux native CGO/toolchain dependencies. Prefer build/package-linux.sh on Linux."

    $linuxTargets = @(
      @{ Name = "linux-amd64"; Goarch = "amd64"; Goarm = "" },
      @{ Name = "linux-arm64"; Goarch = "arm64"; Goarm = "" },
      @{ Name = "linux-armv7"; Goarch = "arm"; Goarm = "7" }
    )

    foreach ($target in $linuxTargets) {
      $linuxStage = Join-Path $stage "deskaccess-$($target.Name)"
      New-Item -ItemType Directory -Force -Path $linuxStage | Out-Null
      $bin = Join-Path $linuxStage "deskaccess-$($target.Name)"
      if ($target.Goarm) {
        Build-LinuxArm -Goarm $target.Goarm -Output $bin
      } else {
        Build-App -Goos "linux" -Goarch $target.Goarch -Output $bin
      }
      Copy-Item (Join-Path $PSScriptRoot "linux\install.sh") $linuxStage
      Copy-Item (Join-Path $PSScriptRoot "linux\deskaccess.service") $linuxStage
      Copy-Item (Join-Path $PSScriptRoot "linux\deskaccess.desktop") $linuxStage
      Copy-Item (Join-Path $root "resources\deskview-256.png") (Join-Path $linuxStage "deskaccess.png")
      Invoke-Checked "tar" @("-C", $linuxStage, "-czf", (Join-Path $packages "deskaccess-$Version-$($target.Name).tar.gz"), ".")
    }
  }

  Get-ChildItem $packages -File | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content (Join-Path $packages "SHA256SUMS.txt")

  Write-Host ""
  Write-Host "Packages written to $packages"
  Get-ChildItem $packages
} finally {
  Pop-Location
  Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
  Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
}
