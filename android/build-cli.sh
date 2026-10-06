#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  bash android/build-cli.sh [debug|release] [options]

Options:
  --build-root <path>          External build directory.
  --signing-properties <path> External keystore.properties file.
  --no-sdk-install            Do not call sdkmanager; only validate the SDK root.
  --require-release-signing   Refuse a release build without external signing.
  -h, --help                  Show this help.

The script keeps Gradle, Kotlin, CMake, DEX, APK and debug-keystore state outside
the repository. Without signing properties it creates an isolated JKS debug
certificate; Gradle embeds that selected certificate SHA-256 into native code.
EOF
}

variant="debug"
build_root=""
signing_properties=""
install_sdk=1
require_release_signing=0

if [[ ${1:-} == "debug" || ${1:-} == "release" ]]; then
    variant="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-root)
            [[ $# -ge 2 ]] || { echo "--build-root requires a value" >&2; exit 2; }
            build_root="$2"
            shift 2
            ;;
        --signing-properties)
            [[ $# -ge 2 ]] || { echo "--signing-properties requires a value" >&2; exit 2; }
            signing_properties="$2"
            shift 2
            ;;
        --no-sdk-install)
            install_sdk=0
            shift
            ;;
        --require-release-signing)
            require_release_signing=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
android_root="$script_dir"
repo_root="$(cd "$android_root/.." && pwd -P)"

if [[ -z "$build_root" ]]; then
    build_root="$(cd "$repo_root/.." && pwd -P)/$(basename "$repo_root")-build"
fi
build_root="$(python3 - "$build_root" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)"

python3 - "$repo_root" "$build_root" <<'PY'
import os
import sys
repo = os.path.realpath(sys.argv[1])
build = os.path.realpath(sys.argv[2])
try:
    inside = os.path.commonpath([repo, build]) == repo
except ValueError:
    inside = False
if inside:
    raise SystemExit(f"Build root must be outside the repository: {build}")
PY

properties_file="$android_root/gradle.properties"
read_property() {
    local key="$1"
    local value
    value="$(awk -F= -v wanted="$key" '
        /^[[:space:]]*#/ { next }
        {
            key=$1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key == wanted) {
                sub(/^[^=]*=/, "")
                gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                print
                exit
            }
        }
    ' "$properties_file")"
    [[ -n "$value" ]] || { echo "Missing Gradle property: $key" >&2; exit 1; }
    printf '%s' "$value"
}

java_required="$(read_property trustattestor.java.version)"
compile_sdk="$(read_property trustattestor.android.compileSdk)"
build_tools="$(read_property trustattestor.android.buildTools)"
d8_build_tools="$(read_property trustattestor.android.d8BuildTools)"
cmake_version="$(read_property trustattestor.android.cmake)"
ndk_version="$(read_property trustattestor.android.ndk)"

java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
if [[ ! -x "$java_bin" ]]; then java_bin="$(command -v java || true)"; fi
[[ -n "$java_bin" && -x "$java_bin" ]] || { echo "JDK $java_required is required; java was not found." >&2; exit 1; }
java_version="$("$java_bin" -version 2>&1 | head -n 1 | sed -E 's/.*version "([^"]+)".*/\1/')"
java_major="${java_version%%.*}"
[[ "$java_major" == "$java_required" ]] || { echo "JDK $java_required is required; found $java_version." >&2; exit 1; }

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
[[ -n "$sdk_root" ]] || { echo "ANDROID_SDK_ROOT or ANDROID_HOME must point to Android SDK command-line tools." >&2; exit 1; }
sdk_root="$(python3 - "$sdk_root" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)"
export ANDROID_SDK_ROOT="$sdk_root"
export ANDROID_HOME="$sdk_root"

find_sdkmanager() {
    if command -v sdkmanager >/dev/null 2>&1; then command -v sdkmanager; return; fi
    for candidate in "$sdk_root/cmdline-tools/latest/bin/sdkmanager" "$sdk_root/cmdline-tools/bin/sdkmanager"; do
        if [[ -x "$candidate" ]]; then printf '%s\n' "$candidate"; return; fi
    done
    find "$sdk_root/cmdline-tools" -type f -path '*/bin/sdkmanager' -perm -u+x 2>/dev/null | sort -V | tail -n 1
}

sdkmanager_bin="$(find_sdkmanager || true)"
if [[ "$install_sdk" -eq 1 ]]; then
    [[ -n "$sdkmanager_bin" ]] || { echo "sdkmanager was not found under $sdk_root." >&2; exit 1; }
    packages=(
        "platform-tools"
        "platforms;android-$compile_sdk"
        "build-tools;$build_tools"
        "build-tools;$d8_build_tools"
        "cmake;$cmake_version"
        "ndk;$ndk_version"
    )
    for attempt in 1 2 3; do
        if "$sdkmanager_bin" --install "${packages[@]}"; then break; fi
        [[ "$attempt" -lt 3 ]] || { echo "Android SDK package installation failed." >&2; exit 1; }
        sleep $((attempt * 5))
    done
fi

required_paths=(
    "$sdk_root/platforms/android-$compile_sdk/android.jar"
    "$sdk_root/build-tools/$build_tools/apksigner"
    "$sdk_root/build-tools/$d8_build_tools/lib/d8.jar"
    "$sdk_root/ndk/$ndk_version"
    "$sdk_root/cmake/$cmake_version"
)
for path in "${required_paths[@]}"; do [[ -e "$path" ]] || { echo "Missing toolchain component: $path" >&2; exit 1; }; done

if [[ ! -f "$android_root/app/src/main/cpp/external/fmt/CMakeLists.txt" ]]; then
    git -C "$repo_root" submodule update --init --recursive
fi

export TRUST_ATTESTOR_BUILD_ROOT="$build_root"
export GRADLE_USER_HOME="$build_root/gradle-user"
export ANDROID_USER_HOME="$build_root/android-user"
export TRUST_ATTESTOR_TEMP="$build_root/temp"
export TEMP="$TRUST_ATTESTOR_TEMP"
export TMP="$TRUST_ATTESTOR_TEMP"
export TMPDIR="$TRUST_ATTESTOR_TEMP"
mkdir -p "$build_root" "$GRADLE_USER_HOME" "$ANDROID_USER_HOME" "$TRUST_ATTESTOR_TEMP" "$build_root/java-user"

if [[ -n "$signing_properties" ]]; then
    signing_properties="$(python3 - "$signing_properties" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)"
    [[ -f "$signing_properties" ]] || { echo "Signing properties do not exist: $signing_properties" >&2; exit 1; }
    python3 - "$repo_root" "$signing_properties" <<'PY'
import os
import sys
repo = os.path.realpath(sys.argv[1])
path = os.path.realpath(sys.argv[2])
if os.path.commonpath([repo, path]) == repo:
    raise SystemExit("Signing properties must be outside the repository.")
PY
else
    debug_keystore="$ANDROID_USER_HOME/debug.keystore"
    if [[ ! -s "$debug_keystore" ]]; then
        keytool_bin="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"
        if [[ ! -x "$keytool_bin" ]]; then keytool_bin="$(command -v keytool || true)"; fi
        [[ -n "$keytool_bin" && -x "$keytool_bin" ]] || { echo "keytool was not found." >&2; exit 1; }
        "$keytool_bin" -genkeypair -keystore "$debug_keystore" -storepass android -keypass android \
            -alias androiddebugkey -dname "CN=Android Debug,O=Android,C=US" -keyalg RSA \
            -keysize 2048 -validity 10000 -storetype JKS >/dev/null 2>&1
        chmod 600 "$debug_keystore"
    fi
fi

if [[ "$variant" == "release" && "$require_release_signing" -eq 1 && -z "$signing_properties" ]]; then
    echo "Release signing is required, but --signing-properties was not supplied." >&2
    exit 1
fi

gradle_args=(--no-daemon --console=plain --stacktrace "-PtrustAttestorBuildRoot=$build_root")
[[ -z "$signing_properties" ]] || gradle_args+=("-PtrustAttestorSigningProperties=$signing_properties")
if [[ "$variant" == "release" && "$require_release_signing" -eq 1 ]]; then gradle_args+=("-PtrustAttestorRequireReleaseSigning=true"); fi
if [[ "$variant" == "debug" ]]; then task=":app:assembleDebug"; else task=":app:assembleRelease"; fi

echo "Building TrustAttestor $variant..."
(cd "$android_root" && ./gradlew "${gradle_args[@]}" "$task")

apk_dir="$build_root/android/app/outputs/apk/$variant"
apk_path="$(find "$apk_dir" -maxdepth 1 -type f -name '*.apk' -print 2>/dev/null | sort | head -n 1)"
[[ -n "$apk_path" && -s "$apk_path" ]] || { echo "APK was not produced under $apk_dir" >&2; exit 1; }
apksigner_bin="$sdk_root/build-tools/$build_tools/apksigner"
apksigner_output="$("$apksigner_bin" verify --print-certs "$apk_path")"
printf '%s\n' "$apksigner_output"
signer_sha256="$(printf '%s\n' "$apksigner_output" | sed -n 's/.*certificate SHA-256 digest:[[:space:]]*//p' | head -n 1 | tr -d '[:space:]:' | tr '[:upper:]' '[:lower:]')"
[[ -n "$signer_sha256" ]] || { echo "Failed to read APK signer SHA-256." >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then apk_sha256="$(sha256sum "$apk_path" | awk '{print $1}')"; else apk_sha256="$(shasum -a 256 "$apk_path" | awk '{print $1}')"; fi

echo "Build complete"
echo "APK: $apk_path"
echo "APK SHA-256: $apk_sha256"
echo "Signer SHA-256: $signer_sha256"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "variant=$variant"
        echo "apk_path=$apk_path"
        echo "apk_sha256=$apk_sha256"
        echo "signer_sha256=$signer_sha256"
    } >> "$GITHUB_OUTPUT"
fi
