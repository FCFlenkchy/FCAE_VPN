# PowerShell script to build and embed hev-socks5-tunnel resources for Windows
# This script:
# 1. Builds hev-socks5-tunnel.dll from source
# 2. Downloads wintun.dll if needed
# 3. Copies everything to the target directory

param(
    [string]$TargetDir = "..\target\release",
    [string]$HevSrcDir = "..\hev-socks5-tunnel"
)

Write-Host "[*] Building hev-socks5-tunnel for Windows..." -ForegroundColor Cyan

# Check if MSYS2 is available
$msysPath = "C:\msys64\usr\bin\bash.exe"
if (-not (Test-Path $msysPath)) {
    Write-Host "[-] MSYS2 not found at $msysPath" -ForegroundColor Red
    Write-Host "[+] Please install MSYS2 from https://www.msys2.org/" -ForegroundColor Yellow
    Write-Host "[+] Then run: pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-libevent" -ForegroundColor Yellow
    exit 1
}

# Build using MSYS2
$HevSrcFull = Resolve-Path $HevSrcDir
Write-Host "[+] Building from: $HevSrcFull" -ForegroundColor Green

# Build command
$buildCmd = "cd `"$HevSrcFull`" && make shared"
$env:MSYS2_PATH_TYPE = "inherit"
$process = Start-Process -FilePath $msysPath -ArgumentList "-c `"$buildCmd`"" -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Host "[-] Build failed with exit code: $($process.ExitCode)" -ForegroundColor Red
    exit 1
}

# Find the built DLL
$dllPath = Join-Path $HevSrcFull "hev-socks5-tunnel.dll"
if (-not (Test-Path $dllPath)) {
    $dllPath = Join-Path $HevSrcFull "src\hev-socks5-tunnel.dll"
}

if (-not (Test-Path $dllPath)) {
    Write-Host "[-] Could not find hev-socks5-tunnel.dll" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Found hev-socks5-tunnel.dll at: $dllPath" -ForegroundColor Green

# Create target directory
$TargetFull = Resolve-Path $TargetDir -ErrorAction SilentlyContinue
if (-not $TargetFull) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    $TargetFull = Resolve-Path $TargetDir
}

# Copy DLL
Copy-Item -Path $dllPath -Destination $TargetFull -Force
Write-Host "[+] Copied hev-socks5-tunnel.dll to $TargetFull" -ForegroundColor Green

# Download wintun.dll (required for Windows TUN)
$wintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$wintunZip = Join-Path $env:TEMP "wintun.zip"
$wintunExtract = Join-Path $env:TEMP "wintun"

Write-Host "[*] Downloading wintun.dll..." -ForegroundColor Cyan

# Remove old files
if (Test-Path $wintunZip) { Remove-Item $wintunZip -Force }
if (Test-Path $wintunExtract) { Remove-Item $wintunExtract -Recurse -Force }

# Download
Invoke-WebRequest -Uri $wintunUrl -OutFile $wintunZip
if (-not (Test-Path $wintunZip)) {
    Write-Host "[-] Failed to download wintun.dll" -ForegroundColor Red
    Write-Host "[+] Please download manually from: $wintunUrl" -ForegroundColor Yellow
} else {
    # Extract
    Expand-Archive -Path $wintunZip -DestinationPath $wintunExtract -Force
    
    # Find wintun.dll
    $wintunDll = Get-ChildItem -Path $wintunExtract -Recurse -Filter "wintun.dll" | Select-Object -First 1
    if ($wintunDll) {
        Copy-Item -Path $wintunDll.FullName -Destination $TargetFull -Force
        Write-Host "[+] Copied wintun.dll to $TargetFull" -ForegroundColor Green
    } else {
        Write-Host "[-] Could not find wintun.dll in the archive" -ForegroundColor Red
    }
    
    # Cleanup
    Remove-Item $wintunZip -Force
    Remove-Item $wintunExtract -Recurse -Force
}

# Create a config file for hev-socks5-tunnel
$configContent = @"
tunnel:
  name: aether-tun0
  mtu: 1500
  multi-queue: false
  ipv4: 198.18.0.1/24
  ipv6: 'fc00::1/64'
  icmp: 'off'

socks5:
  port: 1080
  address: 127.0.0.1
  udp: 'udp'

misc:
  log-level: info
  log-file: null
"@

$configPath = Join-Path $TargetFull "hev-socks5-tunnel.yml"
$configContent | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "[+] Created config at: $configPath" -ForegroundColor Green

# Create a wrapper script to set environment
$wrapperContent = @"
@echo off
set HEV_SOCKS5_TUNNEL_LIB=%~dp0hev-socks5-tunnel.dll
set AETHER_MODE=tun
set AETHER_SOCKS=127.0.0.1:1080
%~dp0fcaevpn.exe %*
"@

$wrapperPath = Join-Path $TargetFull "run-with-tun.bat"
$wrapperContent | Out-File -FilePath $wrapperPath -Encoding ASCII
Write-Host "[+] Created wrapper script at: $wrapperPath" -ForegroundColor Green

Write-Host "[*] Embedding complete!" -ForegroundColor Cyan
Write-Host "[+] Resources in: $TargetFull" -ForegroundColor Green
Write-Host "[+] To use TUN mode, run: run-with-tun.bat" -ForegroundColor Yellow
