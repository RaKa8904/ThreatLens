# ThreatLens Windows Desktop & Workspace Shortcut Generator
$ProjectDir = $PSScriptRoot
if (-not $ProjectDir) { $ProjectDir = Get-Location }

$TargetBat = Join-Path $ProjectDir "ThreatLens.bat"
$IconFile = Join-Path $ProjectDir "ThreatLens.ico"

$WshShell = New-Object -ComObject WScript.Shell

# 1. Create shortcut in project directory
$ProjectLnkPath = Join-Path $ProjectDir "ThreatLens.lnk"
$ProjectShortcut = $WshShell.CreateShortcut($ProjectLnkPath)
$ProjectShortcut.TargetPath = $TargetBat
$ProjectShortcut.WorkingDirectory = $ProjectDir
$ProjectShortcut.IconLocation = "$IconFile,0"
$ProjectShortcut.Description = "Launch ThreatLens Passive SOC Enclave"
$ProjectShortcut.Save()
Write-Host "[*] Created workspace shortcut: $ProjectLnkPath"

# 2. Create shortcut on User's Windows Desktop
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
if ($DesktopPath -and (Test-Path $DesktopPath)) {
    $DesktopLnkPath = Join-Path $DesktopPath "ThreatLens.lnk"
    $DesktopShortcut = $WshShell.CreateShortcut($DesktopLnkPath)
    $DesktopShortcut.TargetPath = $TargetBat
    $DesktopShortcut.WorkingDirectory = $ProjectDir
    $DesktopShortcut.IconLocation = "$IconFile,0"
    $DesktopShortcut.Description = "Launch ThreatLens Passive SOC Enclave"
    $DesktopShortcut.Save()
    Write-Host "[*] Created Desktop shortcut: $DesktopLnkPath"
}
