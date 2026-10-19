[CmdletBinding()]
param(
    [ValidatePattern('^v\d+\.\d+\.\d+$')][string]$Version = 'latest',
    [ValidateSet('cli', 'gui')][string]$Component = 'cli',
    [string]$Repository = 'Karmanya03/Cinder',
    [string]$InstallDirectory = $(Join-Path $env:LOCALAPPDATA 'Cinder\bin')
)
$ErrorActionPreference = 'Stop'

if ($Version -eq 'latest') {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest" -Headers @{ 'User-Agent' = 'Cinder-installer' }
    $Version = $release.tag_name
}
$asset = "cinder-$Component-windows-x86_64.exe"
$base = "https://github.com/$Repository/releases/download/$Version"
$temp = Join-Path ([IO.Path]::GetTempPath()) ("cinder-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $temp $asset)
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $temp 'SHA256SUMS')
    $expected = ((Get-Content (Join-Path $temp 'SHA256SUMS') | Where-Object { $_ -match "\s$([regex]::Escape($asset))$" }) -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $temp $asset)).Hash.ToLowerInvariant()
    if ($expected.ToLowerInvariant() -ne $actual) { throw 'Checksum verification failed.' }
    New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
    Copy-Item -LiteralPath (Join-Path $temp $asset) -Destination (Join-Path $InstallDirectory 'cinder.exe') -Force
    Write-Output "Installed Cinder $Version ($Component) to $InstallDirectory\cinder.exe"
    Write-Output "Add $InstallDirectory to your user PATH if it is not already present."
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
