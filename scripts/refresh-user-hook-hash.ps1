<#
.SYNOPSIS
    Refresh SHA256 hash for a user-written hook embedded in setup-claude.ps1.
.DESCRIPTION
    Computes SHA256 of the embedded here-string content for the given user hook,
    then updates the corresponding entry in the $CHECKSUMS hash table in setup-claude.ps1.
    The hash matches what is written to disk during deployment (UTF-8 no BOM).

    The setup-claude.ps1 deployment path is:
        [System.IO.File]::WriteAllText($dest, $content, $utf8NoBom)
    where $content is the here-string value (PowerShell strips the leading/trailing
    newlines around @'...'@ markers). This script mirrors that behavior.
.PARAMETER HookName
    File name of the user hook (e.g., "verify_on_stop.py").
.EXAMPLE
    .\scripts\refresh-user-hook-hash.ps1 -HookName verify_on_stop.py
.NOTES
    PowerShell 5.1 on Chinese Windows reads files with the system codepage
    (GBK/CP936) by default, which mangles UTF-8 content. This script uses
    [System.IO.File]::ReadAllText with explicit UTF-8 to read correctly.
    PowerShell's -replace operator's $1/$2 backreference behavior is unreliable
    when the replacement is a string expression; this script bypasses that
    by matching the entire pattern with a MatchEvaluator (script block).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HookName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootDir    = Split-Path $PSScriptRoot -Parent
$setupPath  = Join-Path $rootDir 'setup-claude.ps1'
$sourcePath = Join-Path $rootDir (Join-Path 'hooks' $HookName)

if (-not (Test-Path $setupPath)) {
    throw "setup-claude.ps1 not found at $setupPath"
}
if (-not (Test-Path $sourcePath)) {
    throw "source hook not found at $sourcePath"
}

# Read setup-claude.ps1 as UTF-8 (NOT the system default codepage!)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$setupContent = [System.IO.File]::ReadAllText($setupPath, $utf8NoBom)

# Extract the here-string content for the given hook
$escapedHook = [regex]::Escape($HookName)
$extractPattern = "(?ms)'\s*$escapedHook'\s*=\s*@'\r?\n(.*?)\r?\n'@"
$extractMatch = [regex]::Match($setupContent, $extractPattern)
if (-not $extractMatch.Success) {
    throw "embedded block for $HookName not found in setup-claude.ps1"
}
$embedded = $extractMatch.Groups[1].Value

# Write the embedded content with UTF-8 no BOM to mimic deployment
$tmpFile = Join-Path $env:TEMP "refresh-hash-$HookName"
[System.IO.File]::WriteAllText($tmpFile, $embedded, $utf8NoBom)

# Compute SHA256
$hash = (Get-FileHash -Path $tmpFile -Algorithm SHA256).Hash.ToUpper()
Write-Host "  embedded hash: $hash"

# Cross-check against the source file
$sourceHash = (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash.ToUpper()
Write-Host "  source file  : $sourceHash"
if ($hash -ne $sourceHash) {
    Write-Warning "  embedded content and source file differ; double-check the embedded block"
}

# Replace the hash in $CHECKSUMS using a script-block match evaluator
# (avoids the $1/$2 unreliability in string-based -replace)
$checkPattern = "('\s*$escapedHook'\s*=\s*')[A-F0-9]{64}(')"
$regex = [regex]$checkPattern
$evaluator = {
    param($m)
    return $m.Groups[1].Value + $hash + $m.Groups[2].Value
}
$newContent = $regex.Replace($setupContent, $evaluator)
if ($newContent -eq $setupContent) {
    throw "no $CHECKSUMS entry found for $HookName"
}
[System.IO.File]::WriteAllText($setupPath, $newContent, $utf8NoBom)
Write-Host "  [OK] setup-claude.ps1 updated"

Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
