[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string]$Variant = 'debug',
    [string]$BuildRoot,
    [string]$SigningProperties,
    [switch]$SkipSdkInstall
)

$ErrorActionPreference = 'Stop'
$androidRoot = (Resolve-Path $PSScriptRoot).Path
$repoRoot = (Resolve-Path (Join-Path $androidRoot '..')).Path

if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    $BuildRoot = Join-Path (Split-Path $repoRoot -Parent) "$([IO.Path]::GetFileName($repoRoot))-build"
}
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
$repoPrefix = $repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if ($BuildRoot.TrimEnd('\', '/') -eq $repoRoot.TrimEnd('\', '/') -or
    $BuildRoot.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "BuildRoot must be outside the repository: $BuildRoot"
}

$properties = @{}
Get-Content -LiteralPath (Join-Path $androidRoot 'gradle.properties') | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#') -or -not $line.Contains('=')) { return }
    $parts = $line.Split('=', 2)
    $properties[$parts[0].Trim()] = $parts[1].Trim()
}

$requiredProperties = @(
    'trustAttestor.java.version',
    'trustAttestor.android.compileSdk',
    'trustAttestor.android.buildTools',
    'trustAttestor.android.d8BuildTools',
    'trustAttestor.android.ndk',
    'trustAttestor.android.cmake'
)
foreach ($name in $requiredProperties) {
    if (-not $properties.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($properties[$name])) {
        throw "Missing required Gradle property: $name"
    }
}

$javaVersion = $properties['trustAttestor.java.version']
$compileSdk = $properties['trustAttestor.android.compileSdk']
$buildTools = $properties['trustAttestor.android.buildTools']
$d8BuildTools = $properties['trustAttestor.android.d8BuildTools']
$ndkVersion = $properties['trustAttestor.android.ndk']
$cmakeVersion = $properties['trustAttestor.android.cmake']

$javaLine = (& java -version 2>&1 | Select-Object -First 1).ToString()
if ($javaLine -notmatch 'version "(?<major>\d+)') {
    throw "Unable to determine Java version: $javaLine"
}
if ($Matches.major -ne $javaVersion) {
    throw "Expected Java $javaVersion, got: $javaLine"
}
if (-not (Get-Command keytool -ErrorAction SilentlyContinue)) {
    throw 'keytool is required.'
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is required.'
}

& git -C $repoRoot submodule update --init --recursive
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

function Find-SdkManager {
    $fromPath = Get-Command sdkmanager.bat -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $fromPath = Get-Command sdkmanager -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    $roots = @($env:ANDROID_SDK_ROOT, $env:ANDROID_HOME, (Join-Path $HOME 'AppData\Local\Android\Sdk')) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($root in $roots) {
        foreach ($candidate in @(
            (Join-Path $root 'cmdline-tools\latest\bin\sdkmanager.bat'),
            (Join-Path $root 'cmdline-tools\bin\sdkmanager.bat'),
            (Join-Path $root 'tools\bin\sdkmanager.bat')
        )) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    return $null
}

$sdkManager = Find-SdkManager
if (-not $sdkManager) {
    throw 'sdkmanager not found; install Android SDK command-line tools or use the GitHub Actions workflow.'
}

if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT)) {
    $sdkRoot = [IO.Path]::GetFullPath($env:ANDROID_SDK_ROOT)
} elseif (-not [string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
    $sdkRoot = [IO.Path]::GetFullPath($env:ANDROID_HOME)
} else {
    $marker = [IO.Path]::DirectorySeparatorChar + 'cmdline-tools' + [IO.Path]::DirectorySeparatorChar
    $index = $sdkManager.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase)
    if ($index -lt 0) { throw "Cannot derive Android SDK root from: $sdkManager" }
    $sdkRoot = $sdkManager.Substring(0, $index)
}
$env:ANDROID_SDK_ROOT = $sdkRoot
$env:ANDROID_HOME = $sdkRoot

if (-not $SkipSdkInstall) {
    1..20 | ForEach-Object { 'y' } | & $sdkManager --licenses | Out-Null

    $packages = @(
        'platform-tools',
        "platforms;android-$compileSdk",
        "build-tools;$buildTools",
        "ndk;$ndkVersion",
        "cmake;$cmakeVersion"
    )
    if ($d8BuildTools -ne $buildTools) {
        $packages += "build-tools;$d8BuildTools"
    }

    $installed = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & $sdkManager --install @packages
        if ($LASTEXITCODE -eq 0) {
            $installed = $true
            break
        }
        if ($attempt -lt 3) { Start-Sleep -Seconds ($attempt * 5) }
    }
    if (-not $installed) {
        throw 'Android SDK package installation failed after 3 attempts.'
    }
}

$cmakeBin = Join-Path $sdkRoot "cmake\$cmakeVersion\bin"
$env:PATH = "$cmakeBin;$env:PATH"
New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null

if (-not [string]::IsNullOrWhiteSpace($SigningProperties)) {
    $SigningProperties = [IO.Path]::GetFullPath($SigningProperties)
    if (-not (Test-Path -LiteralPath $SigningProperties -PathType Leaf)) {
        throw "Signing properties file does not exist: $SigningProperties"
    }
} else {
    if ($Variant -ne 'debug') {
        throw 'Release builds require -SigningProperties.'
    }

    $signingDir = Join-Path $BuildRoot 'signing'
    New-Item -ItemType Directory -Force -Path $signingDir | Out-Null
    $developmentKeystore = Join-Path $signingDir 'cli-debug.jks'
    $SigningProperties = Join-Path $signingDir 'cli-debug.properties'

    if (-not (Test-Path -LiteralPath $developmentKeystore -PathType Leaf)) {
        $keytoolArgs = @(
            '-genkeypair',
            '-storetype', 'JKS',
            '-keystore', $developmentKeystore,
            '-storepass', 'android',
            '-keypass', 'android',
            '-alias', 'androiddebugkey',
            '-dname', 'CN=TrustAttestor CLI Debug,O=TrustAttestor,C=US',
            '-keyalg', 'RSA',
            '-keysize', '2048',
            '-validity', '10000'
        )
        & keytool @keytoolArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    $keystorePropertyPath = $developmentKeystore.Replace('\', '/')
    @"
androidStoreFile=$keystorePropertyPath
androidStorePassword=android
androidKeyAlias=androiddebugkey
androidKeyPassword=android
"@ | Set-Content -LiteralPath $SigningProperties -Encoding UTF8
}

& (Join-Path $androidRoot 'build-external.ps1') -BuildRoot $BuildRoot -SigningProperties $SigningProperties -Variant $Variant
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$outputDir = Join-Path $BuildRoot "android\app\outputs\apk\$Variant"
$apks = @(Get-ChildItem -LiteralPath $outputDir -Filter '*.apk' -File)
if ($apks.Count -ne 1) {
    throw "Expected exactly one APK in $outputDir, found $($apks.Count)."
}
$apk = $apks[0]

$apksigner = Join-Path $sdkRoot "build-tools\$buildTools\apksigner.bat"
if (-not (Test-Path -LiteralPath $apksigner -PathType Leaf)) {
    throw "apksigner not found: $apksigner"
}
$apksignerOutput = (& $apksigner verify --print-certs $apk.FullName) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output $apksignerOutput

$signerMatch = [regex]::Match(
    $apksignerOutput,
    '(?m)^\s*Signer #1 certificate SHA-256 digest:\s*([0-9A-Fa-f:]+)\s*$'
)
if (-not $signerMatch.Success) {
    throw 'Could not extract APK signer SHA-256.'
}
$signerSha256 = $signerMatch.Groups[1].Value.Replace(':', '').ToLowerInvariant()
$apkSha256 = (Get-FileHash -LiteralPath $apk.FullName -Algorithm SHA256).Hash.ToLowerInvariant()

$artifactDir = Join-Path $BuildRoot 'artifacts'
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
$artifactApk = Join-Path $artifactDir $apk.Name
Copy-Item -LiteralPath $apk.FullName -Destination $artifactApk -Force
"$apkSha256  $($apk.Name)" | Set-Content -LiteralPath (Join-Path $artifactDir 'SHA256SUMS.txt') -Encoding ASCII
@"
variant=$Variant
abi=arm64-v8a
compileSdk=$compileSdk
buildTools=$buildTools
d8BuildTools=$d8BuildTools
ndk=$ndkVersion
cmake=$cmakeVersion
signerSha256=$signerSha256
apkSha256=$apkSha256
apk=$artifactApk
"@ | Set-Content -LiteralPath (Join-Path $artifactDir 'BUILD-INFO.txt') -Encoding UTF8

Write-Output ''
Write-Output 'TrustAttestor build completed'
Write-Output "  Variant:       $Variant"
Write-Output "  APK:           $artifactApk"
Write-Output "  Signer SHA256: $signerSha256"
Write-Output "  APK SHA256:    $apkSha256"
