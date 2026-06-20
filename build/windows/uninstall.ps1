param(
  [string]$InstallDir = "$env:ProgramFiles\DeskAccess",
  [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell window."
  }
}

Assert-Admin

Remove-Item -Recurse -Force "HKLM:\Software\Classes\deskaccess" -ErrorAction SilentlyContinue

$targetExe = Join-Path $InstallDir "DeskAccess.exe"
if (Get-Service DeskAccess -ErrorAction SilentlyContinue) {
  Stop-Service DeskAccess -ErrorAction SilentlyContinue
}

if (Test-Path $targetExe) {
  & $targetExe --uninstall
}

$shortcutPath = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\DeskAccess.lnk"
Remove-Item -Force $shortcutPath -ErrorAction SilentlyContinue

if (-not $KeepFiles) {
  Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}

Write-Host "DeskAccess uninstalled."
