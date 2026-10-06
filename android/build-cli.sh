#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"
DEFAULT_BUILD_ROOT="$(cd -- "$REPO_ROOT/.." >/dev/null 2>&1 && pwd -P)/$(basename -- "$REPO_ROOT")-build"

variant="release"
build_root="${TRUST_ATTESTOR_BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
signing_properties="${TRUST_ATTESTOR_SIGNING_PROPERTIES:-}"
clean_first=0
stacktrace=0
offline=0
info=0
init_submodules=0
gradle_extra=()

usage() {
    cat <<'USAGE'
TrustAttestor Android CLI builder

Usage:
  ./build-cli.sh [options] [-- <extra Gradle args>]

Options:
  -v, --variant <debug|release>       Build variant (default: release)
  -s, --signing-properties <file>     External keystore.properties file
  -b, --build-root <dir>              External build root
      --clean                         Run Gradle clean before building
      --stacktrace                    Enable Gradle stack traces
      --offline                       Run Gradle in offline mode
      --info                          Enable Gradle --info logging
      --init-submodules               Run git submodule update --init --recursive
  -h, --help                          Show this help

Environment:
  TRUST_ATTESTOR_BUILD_ROOT
  TRUST_ATTESTOR_SIGNING_PROPERTIES
  ANDROID_SDK_ROOT / ANDROID_HOME
  JAVA_HOME

Examples:
  ./build-cli.sh -v release -s /private/TrustAttestor/keystore.properties
  ./build-cli.sh -v debug -s /private/TrustAttestor/keystore.properties --stacktrace
  ./build-cli.sh -s /private/TrustAttestor/keystore.properties -- -PndkVer=27.2.12479018
USAGE
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '[TrustAttestor] %s\n' "$*"
}

canonical_existing_file() {
    local input="$1"
    local parent base
    [ -f "$input" ] || return 1
    parent="$(cd -- "$(dirname -- "$input")" >/dev/null 2>&1 && pwd -P)" || return 1
    base="$(basename -- "$input")"
    printf '%s/%s\n' "$parent" "$base"
}

canonical_dir_create() {
    local input="$1"
    mkdir -p -- "$input"
    (cd -- "$input" >/dev/null 2>&1 && pwd -P)
}

path_is_within_repo() {
    local path="$1"
    case "$path/" in
        "$REPO_ROOT"/|"$REPO_ROOT"/*/) return 0 ;;
        *) return 1 ;;
    esac
}

while (($#)); do
    case "$1" in
        -v|--variant)
            (($# >= 2)) || die "$1 requires a value"
            variant="$2"
            shift 2
            ;;
        -s|--signing-properties)
            (($# >= 2)) || die "$1 requires a value"
            signing_properties="$2"
            shift 2
            ;;
        -b|--build-root)
            (($# >= 2)) || die "$1 requires a value"
            build_root="$2"
            shift 2
            ;;
        --clean)
            clean_first=1
            shift
            ;;
        --stacktrace)
            stacktrace=1
            shift
            ;;
        --offline)
            offline=1
            shift
            ;;
        --info)
            info=1
            shift
            ;;
        --init-submodules)
            init_submodules=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            while (($#)); do
                gradle_extra+=("$1")
                shift
            done
            ;;
        *)
            die "unknown argument: $1 (use --help)"
            ;;
    esac
done

case "$variant" in
    debug|release) ;;
    *) die "unsupported variant '$variant'; expected debug or release" ;;
esac

command -v git >/dev/null 2>&1 || die "git is required"
command -v java >/dev/null 2>&1 || die "JDK 17 is required; java was not found in PATH"

java_version_output="$(java -version 2>&1 | head -n 1)"
java_major="$(printf '%s\n' "$java_version_output" | sed -nE 's/.*version "([0-9]+)(\.[0-9]+)?.*/\1/p')"
if [ -n "$java_major" ] && [ "$java_major" -lt 17 ]; then
    die "JDK 17 or newer is required; detected: $java_version_output"
fi

build_root="$(canonical_dir_create "$build_root")" || die "cannot create build root: $build_root"
path_is_within_repo "$build_root" && die "build root must be outside the repository: $build_root"

[ -n "$signing_properties" ] || die \
    "$variant builds require --signing-properties or TRUST_ATTESTOR_SIGNING_PROPERTIES"
signing_properties="$(canonical_existing_file "$signing_properties")" || die \
    "signing properties file does not exist: $signing_properties"
path_is_within_repo "$signing_properties" && die \
    "signing properties must be outside the repository: $signing_properties"

keystore_value="$(sed -n 's/^[[:space:]]*androidStoreFile[[:space:]]*=[[:space:]]*//p' "$signing_properties" | tail -n 1 | tr -d '\r')"
[ -n "$keystore_value" ] || die "androidStoreFile is missing from $signing_properties"
case "$keystore_value" in
    /*) keystore_path="$keystore_value" ;;
    *) keystore_path="$(dirname -- "$signing_properties")/$keystore_value" ;;
esac
keystore_path="$(canonical_existing_file "$keystore_path")" || die \
    "signing keystore does not exist: $keystore_path"
path_is_within_repo "$keystore_path" && die \
    "signing keystore must be outside the repository: $keystore_path"

fmt_dir="$SCRIPT_DIR/app/src/main/cpp/external/fmt"
if [ ! -f "$fmt_dir/CMakeLists.txt" ]; then
    if ((init_submodules)); then
        note "Initializing git submodules..."
        git -C "$REPO_ROOT" submodule update --init --recursive
    else
        die "fmt submodule is not initialized; run with --init-submodules or execute: git submodule update --init --recursive"
    fi
fi

export TRUST_ATTESTOR_BUILD_ROOT="$build_root"
export TRUST_ATTESTOR_SIGNING_PROPERTIES="$signing_properties"
export GRADLE_USER_HOME="$build_root/gradle-user"
export ANDROID_USER_HOME="$build_root/android-user"
export TEMP="$build_root/temp"
export TMP="$TEMP"
export TMPDIR="$TEMP"
mkdir -p -- "$GRADLE_USER_HOME" "$ANDROID_USER_HOME" "$TEMP" "$build_root/java-user"

gradle_args=(
    --no-daemon
    --console=plain
    "-PtrustAttestorBuildRoot=$build_root"
    "-PtrustAttestorSigningProperties=$signing_properties"
)
((stacktrace)) && gradle_args+=(--stacktrace)
((offline)) && gradle_args+=(--offline)
((info)) && gradle_args+=(--info)

case "$variant" in
    debug) assemble_task=":app:assembleDebug" ;;
    release) assemble_task=":app:assembleRelease" ;;
esac

note "Variant: $variant"
note "Repository: $REPO_ROOT"
note "Build root: $build_root"
note "Signing properties: $signing_properties"
note "Java: $java_version_output"
if [ -n "${ANDROID_SDK_ROOT:-}" ]; then
    note "Android SDK: $ANDROID_SDK_ROOT"
elif [ -n "${ANDROID_HOME:-}" ]; then
    note "Android SDK: $ANDROID_HOME"
fi

cd -- "$SCRIPT_DIR"

if ((clean_first)); then
    note "Cleaning external Gradle outputs..."
    ./gradlew "${gradle_args[@]}" clean "${gradle_extra[@]}"
fi

note "Running $assemble_task ..."
./gradlew "${gradle_args[@]}" "$assemble_task" "${gradle_extra[@]}"

unexpected_state="$(find "$REPO_ROOT" -type d \( -name build -o -name .gradle -o -name .kotlin -o -name .cxx \) -print -quit 2>/dev/null || true)"
[ -z "$unexpected_state" ] || die "build state was created inside the repository: $unexpected_state"

apk_dir="$build_root/android/app/outputs/apk/$variant"
apk_path=""
if [ -d "$apk_dir" ]; then
    while IFS= read -r candidate; do
        apk_path="$candidate"
    done < <(find "$apk_dir" -maxdepth 1 -type f -name '*.apk' -print | sort)
fi
[ -n "$apk_path" ] && [ -f "$apk_path" ] || die "build succeeded but no APK was found under: $apk_dir"

if command -v sha256sum >/dev/null 2>&1; then
    apk_sha256="$(sha256sum "$apk_path" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    apk_sha256="$(shasum -a 256 "$apk_path" | awk '{print $1}')"
else
    apk_sha256="unavailable"
fi

if command -v stat >/dev/null 2>&1 && stat -c '%s' "$apk_path" >/dev/null 2>&1; then
    apk_size="$(stat -c '%s' "$apk_path")"
elif command -v stat >/dev/null 2>&1; then
    apk_size="$(stat -f '%z' "$apk_path")"
else
    apk_size="unknown"
fi

printf '\nBuild succeeded.\n'
printf 'APK:    %s\n' "$apk_path"
printf 'Size:   %s bytes\n' "$apk_size"
printf 'SHA256: %s\n' "$apk_sha256"
