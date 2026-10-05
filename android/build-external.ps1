[CmdletBinding()]
param(
    [string]$BuildRoot,
    [string]$SigningProperties,
    [ValidateSet('debug', 'release')]
    [string]$Variant = 'release'
)

$ErrorActionPreference = 'Stop'
$androidRoot = (Resolve-Path (Join-Path $PSScriptRoot '.')).Path
$repoRoot = (Resolve-Path (Join-Path $androidRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path (Split-Path $repoRoot -Parent) "$([IO.Path]::GetFileName($repoRoot))-build"
}
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
if ($BuildRoot.TrimEnd('\', '/') -eq $repoRoot.TrimEnd('\', '/') -or
    $BuildRoot.StartsWith($repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "BuildRoot must be outside the repository: $BuildRoot"
}

if ([string]::IsNullOrWhiteSpace($SigningProperties)) {
    throw "${Variant} builds require -SigningProperties pointing to the external release keystore.properties file."
}
if ($SigningProperties) {
    $SigningProperties = [IO.Path]::GetFullPath($SigningProperties)
    if (-not (Test-Path -LiteralPath $SigningProperties -PathType Leaf)) {
        throw "Signing properties file does not exist: $SigningProperties"
    }
    if ($SigningProperties.StartsWith($repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Signing properties must be outside the repository.'
    }
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

$arguments = @(
    '--no-daemon',
    '--console=plain',
    "-PtrustAttestorBuildRoot=$BuildRoot"
)
if ($SigningProperties) {
    $arguments += "-PtrustAttestorSigningProperties=$SigningProperties"
}
$arguments += ":app:assemble$($Variant.Substring(0, 1).ToUpperInvariant())$($Variant.Substring(1))"

Push-Location $androidRoot
try {
    & (Join-Path $androidRoot 'gradlew.bat') @arguments
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
