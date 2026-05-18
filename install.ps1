# install.ps1 — installs chat on Windows
# Usage: irm https://raw.githubusercontent.com/JonathanInTheClouds/go-chat/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo    = "JonathanInTheClouds/go-chat"
$Binary  = "chat"

# Detect architecture
$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { "arm64" } else { "amd64" }

# Fetch latest version
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Version = $Release.tag_name
$Ver     = $Version.TrimStart('v')

$Url     = "https://github.com/$Repo/releases/download/$Version/${Binary}_${Ver}_windows_${Arch}.zip"
$Tmp     = Join-Path $env:TEMP "chat_install"

Write-Host "Installing $Binary $Version (windows/$Arch)..."

# Download and extract
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
Invoke-WebRequest -Uri $Url -OutFile "$Tmp\chat.zip" -UseBasicParsing
Expand-Archive -Path "$Tmp\chat.zip" -DestinationPath $Tmp -Force

# Install to WindowsApps (on PATH for all users, no admin required)
$InstallDir = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps"
Move-Item -Force "$Tmp\$Binary.exe" "$InstallDir\$Binary.exe"
Remove-Item -Recurse -Force $Tmp

Write-Host "Installed to $InstallDir\$Binary.exe"
Write-Host ""
Write-Host "Enable tab completion (add to your `$PROFILE):"
Write-Host "  Invoke-Expression (& chat completion powershell)"
