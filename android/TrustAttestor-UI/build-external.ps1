[CmdletBinding()]
param(
    [string]$BuildRoot,
    [ValidateSet('debug', 'release')]
    [string]$Variant = 'debug'
)

$ErrorActionPreference = 'Stop'
$uiRoot = (Resolve-Path (Join-Path $PSScriptRoot '.')).Path
$repoRoot = if ((Split-Path (Split-Path $uiRoot -Parent) -Leaf) -eq 'android') {
    Split-Path (Split-Path $uiRoot -Parent) -Parent
} else {
    $uiRoot
}
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $projectParent = Split-Path (Split-Path (Split-Path $uiRoot -Parent) -Parent) -Parent
    $BuildRoot = Join-Path $projectParent 'TrustAttestor-build/ui'
}
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
if ($BuildRoot.TrimEnd('\', '/') -eq $repoRoot.TrimEnd('\', '/') -or
    $BuildRoot.StartsWith($repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "BuildRoot must be outside the repository: $BuildRoot"
}

$env:TRUST_ATTESTOR_BUILD_ROOT = $BuildRoot
$env:GRADLE_USER_HOME = Join-Path $BuildRoot 'gradle-user'
$env:ANDROID_USER_HOME = Join-Path $BuildRoot 'android-user'
$env:TEMP = Join-Path $BuildRoot 'temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Force -Path @(
    $BuildRoot,
    $env:GRADLE_USER_HOME,
    $env:ANDROID_USER_HOME,
    $env:TEMP,
    (Join-Path $BuildRoot 'java-user')
) | Out-Null

$task = ":app:assemble$($Variant.Substring(0, 1).ToUpperInvariant())$($Variant.Substring(1))"
Push-Location $uiRoot
try {
    & (Join-Path $uiRoot 'gradlew.bat') '--no-daemon' '--console=plain' "-PtrustAttestorBuildRoot=$BuildRoot" $task
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $unexpectedBuildState = Get-ChildItem -LiteralPath $repoRoot -Directory -Recurse -Force |
        Where-Object { $_.Name -in @('build', '.gradle', '.kotlin', '.cxx') }
    if ($unexpectedBuildState) {
        throw "Build state found inside the repository: $($unexpectedBuildState.FullName -join ', ')"
    }
    Write-Output "Build completed outside the repository: $BuildRoot"
} finally {
    Pop-Location
}
