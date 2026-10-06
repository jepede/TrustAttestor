#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./build-cli.sh [debug|release] [options]

Options:
  -v, --variant VARIANT       Build variant: debug or release (default: debug).
  -b, --build-root PATH       External build directory.
  -s, --signing-properties PATH
                              External keystore.properties.
      --skip-sdk-install      Do not run sdkmanager --install.
      --clean                 Run Gradle clean before building.
      --offline               Pass --offline to Gradle and skip SDK installation.
      --info                  Pass --info to Gradle.
      --stacktrace            Pass --stacktrace to Gradle.
      --init-submodules       Force git submodule initialization/update.
  -h, --help                  Show this help.
  --                          Pass remaining arguments directly to Gradle.

Debug builds create an external development JKS when --signing-properties is omitted.
Release builds always require --signing-properties.
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

variant="debug"
build_root="${TRUST_ATTESTOR_BUILD_ROOT:-}"
signing_properties="${TRUST_ATTESTOR_SIGNING_PROPERTIES:-}"
skip_sdk_install=false
clean_first=false
offline=false
info=false
stacktrace=true
init_submodules=false
gradle_extra=()

if [[ $# -gt 0 && ( "$1" == "debug" || "$1" == "release" ) ]]; then
    variant="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--variant)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            variant="$2"
            [[ "$variant" == "debug" || "$variant" == "release" ]] ||
                fail "unsupported variant: $variant"
            shift 2
            ;;
        -b|--build-root)
            [[ $# -ge 2 ]] || fail "$1 requires a path"
            build_root="$2"
            shift 2
            ;;
        -s|--signing-properties)
            [[ $# -ge 2 ]] || fail "$1 requires a path"
            signing_properties="$2"
            shift 2
            ;;
        --skip-sdk-install)
            skip_sdk_install=true
            shift
            ;;
        --clean)
            clean_first=true
            shift
            ;;
        --offline)
            offline=true
            skip_sdk_install=true
            shift
            ;;
        --info)
            info=true
            shift
            ;;
        --stacktrace)
            stacktrace=true
            shift
            ;;
        --init-submodules)
            init_submodules=true
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                gradle_extra+=("$1")
                shift
            done
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

if [[ -z "$build_root" ]]; then
    build_root="$(dirname -- "$repo_root")/$(basename -- "$repo_root")-build"
fi
mkdir -p "$build_root"
build_root="$(cd -- "$build_root" && pwd -P)"

case "$build_root" in
    "$repo_root"|"$repo_root"/*)
        fail "build root must be outside the repository: $build_root"
        ;;
esac

properties_file="$script_dir/gradle.properties"
read_property() {
    local key="$1"
    awk -F= -v wanted="$key" '
        {
            key = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key == wanted) {
                sub(/^[^=]*=/, "")
                gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                print
                exit
            }
        }
    ' "$properties_file"
}

java_version="$(read_property trustAttestor.java.version)"
compile_sdk="$(read_property trustAttestor.android.compileSdk)"
build_tools="$(read_property trustAttestor.android.buildTools)"
d8_build_tools="$(read_property trustAttestor.android.d8BuildTools)"
ndk_version="$(read_property trustAttestor.android.ndk)"
cmake_version="$(read_property trustAttestor.android.cmake)"

for value_name in java_version compile_sdk build_tools d8_build_tools ndk_version cmake_version; do
    [[ -n "${!value_name}" ]] || fail "missing toolchain property: $value_name"
done

command -v git >/dev/null 2>&1 || fail "git is required"
command -v java >/dev/null 2>&1 || fail "Java $java_version is required"
command -v keytool >/dev/null 2>&1 || fail "keytool is required"

java_line="$(java -version 2>&1 | head -n 1)"
java_major="$(printf '%s\n' "$java_line" | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p')"
[[ "$java_major" == "$java_version" ]] || fail "expected Java $java_version, got: $java_line"

fmt_dir="$script_dir/app/src/main/cpp/external/fmt"
if [[ "$init_submodules" == true || ! -f "$fmt_dir/CMakeLists.txt" ]]; then
    git -C "$repo_root" submodule update --init --recursive
fi

find_sdkmanager() {
    if command -v sdkmanager >/dev/null 2>&1; then
        command -v sdkmanager
        return 0
    fi
    local roots=()
    [[ -n "${ANDROID_SDK_ROOT:-}" ]] && roots+=("$ANDROID_SDK_ROOT")
    [[ -n "${ANDROID_HOME:-}" ]] && roots+=("$ANDROID_HOME")
    roots+=("$HOME/Android/Sdk")
    local root candidate
    for root in "${roots[@]}"; do
        for candidate in             "$root/cmdline-tools/latest/bin/sdkmanager"             "$root/cmdline-tools/bin/sdkmanager"             "$root/tools/bin/sdkmanager"; do
            if [[ -x "$candidate" ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
    done
    return 1
}

sdkmanager_path="$(find_sdkmanager)" || fail "sdkmanager not found; install Android SDK command-line tools or use the GitHub Actions workflow"

if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
    sdk_root="$ANDROID_SDK_ROOT"
elif [[ -n "${ANDROID_HOME:-}" ]]; then
    sdk_root="$ANDROID_HOME"
elif [[ "$sdkmanager_path" == */cmdline-tools/*/bin/sdkmanager ]]; then
    sdk_root="${sdkmanager_path%%/cmdline-tools/*}"
elif [[ "$sdkmanager_path" == */tools/bin/sdkmanager ]]; then
    sdk_root="${sdkmanager_path%%/tools/bin/sdkmanager}"
else
    fail "cannot derive Android SDK root from: $sdkmanager_path"
fi
sdk_root="$(cd -- "$sdk_root" && pwd -P)"
export ANDROID_SDK_ROOT="$sdk_root"
export ANDROID_HOME="$sdk_root"

if [[ "$skip_sdk_install" != true ]]; then
    yes | "$sdkmanager_path" --licenses >/dev/null 2>&1 || true
    packages=(
        "platform-tools"
        "platforms;android-$compile_sdk"
        "build-tools;$build_tools"
        "ndk;$ndk_version"
        "cmake;$cmake_version"
    )
    if [[ "$d8_build_tools" != "$build_tools" ]]; then
        packages+=("build-tools;$d8_build_tools")
    fi

    for attempt in 1 2 3; do
        if "$sdkmanager_path" --install "${packages[@]}"; then
            break
        fi
        [[ "$attempt" -lt 3 ]] || fail "Android SDK package installation failed after $attempt attempts"
        sleep $((attempt * 5))
    done
fi

export PATH="$ANDROID_SDK_ROOT/cmake/$cmake_version/bin:$PATH"
export TRUST_ATTESTOR_BUILD_ROOT="$build_root"
export GRADLE_USER_HOME="$build_root/gradle-user"
export ANDROID_USER_HOME="$build_root/android-user"
export TEMP="$build_root/temp"
export TMP="$TEMP"
export TMPDIR="$TEMP"
mkdir -p "$GRADLE_USER_HOME" "$ANDROID_USER_HOME" "$TEMP" "$build_root/java-user"

path_is_within_repo() {
    local path="$1"
    case "$path/" in
        "$repo_root"/|"$repo_root"/*/) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ -n "$signing_properties" ]]; then
    signing_properties="$(cd -- "$(dirname -- "$signing_properties")" && pwd -P)/$(basename -- "$signing_properties")"
    [[ -f "$signing_properties" ]] || fail "signing properties file not found: $signing_properties"
    path_is_within_repo "$signing_properties" &&
        fail "signing properties must be outside the repository: $signing_properties"

    keystore_value="$(sed -n 's/^[[:space:]]*androidStoreFile[[:space:]]*=[[:space:]]*//p' "$signing_properties" | tail -n 1 | tr -d '\r')"
    [[ -n "$keystore_value" ]] || fail "androidStoreFile is missing from $signing_properties"
    if [[ "$keystore_value" = /* ]]; then
        keystore_path="$keystore_value"
    else
        keystore_path="$(dirname -- "$signing_properties")/$keystore_value"
    fi
    keystore_path="$(cd -- "$(dirname -- "$keystore_path")" && pwd -P)/$(basename -- "$keystore_path")"
    [[ -f "$keystore_path" ]] || fail "signing keystore not found: $keystore_path"
    path_is_within_repo "$keystore_path" &&
        fail "signing keystore must be outside the repository: $keystore_path"
else
    [[ "$variant" == "debug" ]] || fail "release builds require --signing-properties"
    signing_dir="$build_root/signing"
    mkdir -p "$signing_dir"
    development_keystore="$signing_dir/cli-debug.jks"
    signing_properties="$signing_dir/cli-debug.properties"

    if [[ ! -s "$development_keystore" ]]; then
        keytool -genkeypair             -storetype JKS             -keystore "$development_keystore"             -storepass android             -keypass android             -alias androiddebugkey             -dname "CN=TrustAttestor CLI Debug,O=TrustAttestor,C=US"             -keyalg RSA             -keysize 2048             -validity 10000             >/dev/null
        chmod 600 "$development_keystore"
    fi

    cat > "$signing_properties" <<EOF
androidStoreFile=$development_keystore
androidStorePassword=android
androidKeyAlias=androiddebugkey
androidKeyPassword=android
EOF
    chmod 600 "$signing_properties"
fi

variant_task="${variant^}"
gradle_args=(
    --no-daemon
    --console=plain
    "-PtrustAttestorBuildRoot=$build_root"
    "-PtrustAttestorSigningProperties=$signing_properties"
)
[[ "$stacktrace" == true ]] && gradle_args+=(--stacktrace)
[[ "$offline" == true ]] && gradle_args+=(--offline)
[[ "$info" == true ]] && gradle_args+=(--info)

pushd "$script_dir" >/dev/null
if [[ "$clean_first" == true ]]; then
    ./gradlew "${gradle_args[@]}" clean "${gradle_extra[@]}"
fi
./gradlew "${gradle_args[@]}" :dex:check ":app:assemble$variant_task" "${gradle_extra[@]}"
popd >/dev/null

output_dir="$build_root/android/app/outputs/apk/$variant"
[[ -d "$output_dir" ]] || fail "APK output directory not found: $output_dir"

apk_count="$(find "$output_dir" -maxdepth 1 -type f -name '*.apk' | wc -l | tr -d '[:space:]')"
[[ "$apk_count" == "1" ]] || fail "expected exactly one APK in $output_dir, found $apk_count"
apk_path="$(find "$output_dir" -maxdepth 1 -type f -name '*.apk' -print -quit)"

apksigner="$ANDROID_SDK_ROOT/build-tools/$build_tools/apksigner"
[[ -x "$apksigner" ]] || fail "apksigner not found: $apksigner"
apksigner_output="$("$apksigner" verify --print-certs "$apk_path")"
printf '%s\n' "$apksigner_output"

signer_sha256="$(printf '%s\n' "$apksigner_output" |
    sed -n 's/^[[:space:]]*Signer #1 certificate SHA-256 digest:[[:space:]]*//p' |
    head -n 1 |
    tr -d '[:space:]:' |
    tr '[:upper:]' '[:lower:]')"
[[ -n "$signer_sha256" ]] || fail "could not extract APK signer SHA-256"

if command -v sha256sum >/dev/null 2>&1; then
    apk_sha256="$(sha256sum "$apk_path" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    apk_sha256="$(shasum -a 256 "$apk_path" | awk '{print $1}')"
else
    fail "sha256sum or shasum is required"
fi

artifact_dir="$build_root/artifacts"
mkdir -p "$artifact_dir"
artifact_apk="$artifact_dir/$(basename -- "$apk_path")"
cp -f "$apk_path" "$artifact_apk"
printf '%s  %s\n' "$apk_sha256" "$(basename -- "$artifact_apk")" > "$artifact_dir/SHA256SUMS.txt"
cat > "$artifact_dir/BUILD-INFO.txt" <<EOF
variant=$variant
abi=arm64-v8a
compileSdk=$compile_sdk
buildTools=$build_tools
d8BuildTools=$d8_build_tools
ndk=$ndk_version
cmake=$cmake_version
signerSha256=$signer_sha256
apkSha256=$apk_sha256
apk=$artifact_apk
EOF

echo
echo "TrustAttestor build completed"
echo "  Variant:       $variant"
echo "  APK:           $artifact_apk"
echo "  Signer SHA256: $signer_sha256"
echo "  APK SHA256:    $apk_sha256"
