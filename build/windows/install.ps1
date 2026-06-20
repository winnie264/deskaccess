param(
  [string]$InstallDir = "$env:ProgramFiles\DeskAccess",
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell window."
  }
}

Assert-Admin

function Register-UrlProtocol {
  param(
    [string]$Scheme,
    [string]$ExePath
  )

  $base = "HKLM:\Software\Classes\$Scheme"
  $command = "`"$ExePath`" `"%1`""
  New-Item -Force -Path $base | Out-Null
  (Get-Item $base).SetValue("", "URL:DeskAccess Invite Link")
  New-ItemProperty -Force -Path $base -Name "URL Protocol" -Value "" -PropertyType String | Out-Null
  New-Item -Force -Path "$base\DefaultIcon" | Out-Null
  (Get-Item "$base\DefaultIcon").SetValue("", "`"$ExePath`",0")
  New-Item -Force -Path "$base\shell\open\command" | Out-Null
  (Get-Item "$base\shell\open\command").SetValue("", $command)
}

$sourceExe = Join-Path $PSScriptRoot "DeskAccess.exe"
if (-not (Test-Path $sourceExe)) {
  throw "Missing DeskAccess.exe next to install.ps1"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$targetExe = Join-Path $InstallDir "DeskAccess.exe"
Copy-Item -Force $sourceExe $targetExe
Register-UrlProtocol -Scheme "deskaccess" -ExePath $targetExe

& $targetExe --install

if (-not $NoStart) {
  Start-Service DeskAccess
}

$shortcutDir = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $shortcutDir "DeskAccess.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetExe
$shortcut.WorkingDirectory = $InstallDir
$shortcut.IconLocation = $targetExe
$shortcut.Save()

Write-Host "DeskAccess installed."
Write-Host "Service: DeskAccess"
Write-Host "App: $targetExe"
Write-Host "Start menu shortcut: $shortcutPath"
Write-Host "URL protocol: deskaccess://"
