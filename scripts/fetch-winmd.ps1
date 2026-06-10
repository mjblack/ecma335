#!/usr/bin/env pwsh
[CmdletBinding()]
param(
  [string]$Version = "",
  [string]$OutputPath = "winmd/Windows.Win32.winmd"
)

$ErrorActionPreference = "Stop"
$packageId = "microsoft.windows.sdk.win32metadata"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$versionFile = Join-Path $repoRoot "winmd.version"

if ([string]::IsNullOrWhiteSpace($Version)) {
  if (-not (Test-Path $versionFile)) {
    throw "No version specified and version file not found: $versionFile"
  }

  $Version = Get-Content -Path $versionFile |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") } |
    Select-Object -First 1

  if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Version file is empty: $versionFile"
  }
}

$outputFullPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
  $OutputPath
} else {
  Join-Path $repoRoot $OutputPath
}

$outputDir = Split-Path -Path $outputFullPath -Parent
if (-not (Test-Path $outputDir)) {
  New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ecma335-winmd-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  $nupkg = Join-Path $tmpDir "$packageId.$Version.nupkg"
  $uri = "https://api.nuget.org/v3-flatcontainer/$packageId/$Version/$packageId.$Version.nupkg"

  Write-Host "Downloading $packageId $Version..."
  Invoke-WebRequest -Uri $uri -OutFile $nupkg

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
  try {
    $entry = $zip.Entries | Where-Object { $_.FullName -eq "Windows.Win32.winmd" } | Select-Object -First 1
    if ($null -eq $entry) {
      throw "Windows.Win32.winmd not found in package $packageId $Version"
    }

    $source = $entry.Open()
    try {
      $target = [System.IO.File]::Create($outputFullPath)
      try {
        $source.CopyTo($target)
      } finally {
        $target.Dispose()
      }
    } finally {
      $source.Dispose()
    }
  } finally {
    $zip.Dispose()
  }
} finally {
  if (Test-Path $tmpDir) {
    Remove-Item -Path $tmpDir -Recurse -Force
  }
}

Write-Host "Saved Windows.Win32.winmd to $outputFullPath"
Write-Host "Version: $Version"
