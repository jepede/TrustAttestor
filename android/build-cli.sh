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

read_property() {
    local key="$1"
    local file="$2"
    sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$file" \
        | tail -n 1 \
        | tr -d '\r'
}

resolve_sdk_root() {
    local candidate=""
    if [ -n "${ANDROID_SDK_ROOT:-}" ]; then
        candidate="$ANDROID_SDK_ROOT"
    elif [ -n "${ANDROID_HOME:-}" ]; then
        candidate="$ANDROID_HOME"
    elif [ -f "$SCRIPT_DIR/local.properties" ]; then
        candidate="$(read_property "sdk.dir" "$SCRIPT_DIR/local.properties")"
        candidate="${candidate//\\:/:}"
        candidate="${candidate//\\\\/\\}"
    fi

    [ -n "$candidate" ] || return 1
    [ -d "$candidate" ] || return 1
    (cd -- "$candidate" >/dev/null 2>&1 && pwd -P)
}

resolve_keytool() {
    if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ]; then
        printf '%s\n' "$JAVA_HOME/bin/keytool"
    else
        command -v keytool
    fi
}

resolve_apksigner() {
    local sdk_root="$1"
    local build_tools="$2"
    local candidate=""

    if [ -n "$sdk_root" ] && [ -n "$build_tools" ]; then
        candidate="$sdk_root/build-tools/$build_tools/apksigner"
        if [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi

    command -v apksigner 2>/dev/null || return 1
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
command -v python3 >/dev/null 2>&1 || die "python3 is required for APK metadata validation"

keytool_path="$(resolve_keytool)" || die "keytool was not found; install/use a complete JDK 17"
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

keystore_value="$(read_property "androidStoreFile" "$signing_properties")"
store_password="$(read_property "androidStorePassword" "$signing_properties")"
key_alias="$(read_property "androidKeyAlias" "$signing_properties")"
key_password="$(read_property "androidKeyPassword" "$signing_properties")"

[ -n "$keystore_value" ] || die "androidStoreFile is missing from $signing_properties"
[ -n "$store_password" ] || die "androidStorePassword is missing from $signing_properties"
[ -n "$key_alias" ] || die "androidKeyAlias is missing from $signing_properties"
[ -n "$key_password" ] || die "androidKeyPassword is missing from $signing_properties"

case "$keystore_value" in
    /*) keystore_path="$keystore_value" ;;
    *) keystore_path="$(dirname -- "$signing_properties")/$keystore_value" ;;
esac
keystore_path="$(canonical_existing_file "$keystore_path")" || die \
    "signing keystore does not exist: $keystore_path"
path_is_within_repo "$keystore_path" && die \
    "signing keystore must be outside the repository: $keystore_path"

expected_signer_sha256="$(
    TRUST_ATTESTOR_STORE_PASSWORD="$store_password" \
    "$keytool_path" \
        -J-Duser.language=en \
        -J-Duser.country=US \
        -list -v \
        -keystore "$keystore_path" \
        -storepass:env TRUST_ATTESTOR_STORE_PASSWORD \
        -alias "$key_alias" 2>/dev/null \
    | sed -n 's/^[[:space:]]*SHA256:[[:space:]]*//p' \
    | head -n 1 \
    | tr -d '[:space:]:' \
    | tr '[:upper:]' '[:lower:]'
)"
[ -n "$expected_signer_sha256" ] || die \
    "could not read SHA-256 fingerprint for alias '$key_alias' from the signing keystore"
[[ "$expected_signer_sha256" =~ ^[0-9a-f]{64}$ ]] || die \
    "unexpected signing certificate SHA-256 format: $expected_signer_sha256"

fmt_dir="$SCRIPT_DIR/app/src/main/cpp/external/fmt"
if [ ! -f "$fmt_dir/CMakeLists.txt" ]; then
    if ((init_submodules)); then
        note "Initializing git submodules..."
        git -C "$REPO_ROOT" submodule update --init --recursive
    else
        die "fmt submodule is not initialized; run with --init-submodules or execute: git submodule update --init --recursive"
    fi
fi

build_tools_version="$(
    sed -nE 's/^[[:space:]]*buildToolsVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
        "$SCRIPT_DIR/app/build.gradle.kts" \
    | head -n 1
)"
[ -n "$build_tools_version" ] || die \
    "could not resolve buildToolsVersion from android/app/build.gradle.kts"

sdk_root="$(resolve_sdk_root 2>/dev/null || true)"
apksigner_path="$(resolve_apksigner "$sdk_root" "$build_tools_version" 2>/dev/null || true)"
[ -n "$apksigner_path" ] || die \
    "apksigner was not found (expected Build Tools $build_tools_version under ANDROID_SDK_ROOT/ANDROID_HOME or in PATH)"

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
note "Expected signer SHA-256: $expected_signer_sha256"
note "Java: $java_version_output"
note "Build Tools: $build_tools_version"
if [ -n "$sdk_root" ]; then
    note "Android SDK: $sdk_root"
fi

cd -- "$SCRIPT_DIR"

if ((clean_first)); then
    note "Cleaning external Gradle outputs..."
    ./gradlew "${gradle_args[@]}" clean "${gradle_extra[@]}"
fi

build_started_at="$(date +%s)"
note "Running $assemble_task ..."
./gradlew "${gradle_args[@]}" "$assemble_task" "${gradle_extra[@]}"
build_finished_at="$(date +%s)"
build_duration="$((build_finished_at - build_started_at))"

unexpected_state="$(find "$REPO_ROOT" -type d \( -name build -o -name .gradle -o -name .kotlin -o -name .cxx \) -print -quit 2>/dev/null || true)"
[ -z "$unexpected_state" ] || die "build state was created inside the repository: $unexpected_state"

apk_dir="$build_root/android/app/outputs/apk/$variant"
metadata_path="$apk_dir/output-metadata.json"
[ -s "$metadata_path" ] || die \
    "build succeeded but output-metadata.json is missing or empty: $metadata_path"

metadata_tmp="$(mktemp -d "$TEMP/trustattestor-metadata.XXXXXX")"
cleanup_metadata() {
    rm -rf -- "$metadata_tmp"
}
trap cleanup_metadata EXIT

python3 - "$metadata_path" "$metadata_tmp" <<'PY'
import json
import sys
from pathlib import Path

metadata_path = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

try:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid output-metadata.json: {exc}")

elements = metadata.get("elements")
if not isinstance(elements, list) or not elements:
    raise SystemExit("output-metadata.json contains no APK elements")

apk_elements = [
    element for element in elements
    if isinstance(element, dict)
    and isinstance(element.get("outputFile"), str)
    and element["outputFile"].lower().endswith(".apk")
]
if not apk_elements:
    raise SystemExit("output-metadata.json contains no APK output")

universal = [
    element for element in apk_elements
    if str(element.get("type", "")).upper() == "UNIVERSAL"
    or element["outputFile"].lower().endswith("-universal.apk")
]
if len(universal) == 1:
    selected = universal[0]
elif len(apk_elements) == 1:
    selected = apk_elements[0]
else:
    listed = ", ".join(sorted(element["outputFile"] for element in apk_elements))
    raise SystemExit(
        f"expected one APK (or one universal APK), found {len(apk_elements)}: {listed}"
    )

output_file = selected["outputFile"]
if Path(output_file).name != output_file:
    raise SystemExit(f"unsafe APK output path in metadata: {output_file!r}")

apk_path = metadata_path.parent / output_file
if not apk_path.is_file() or apk_path.stat().st_size <= 0:
    raise SystemExit(f"APK listed by metadata is missing or empty: {apk_path}")

version_name = selected.get("versionName")
version_code = selected.get("versionCode")
if not isinstance(version_name, str) or not version_name.strip():
    raise SystemExit("APK versionName is missing from output metadata")
if not isinstance(version_code, int) or isinstance(version_code, bool) or version_code <= 0:
    raise SystemExit(f"APK versionCode is invalid: {version_code!r}")

(out_dir / "apk_path").write_text(str(apk_path), encoding="utf-8")
(out_dir / "version_name").write_text(version_name.strip(), encoding="utf-8")
(out_dir / "version_code").write_text(str(version_code), encoding="utf-8")
PY

apk_path="$(cat "$metadata_tmp/apk_path")"
version_name="$(cat "$metadata_tmp/version_name")"
version_code="$(cat "$metadata_tmp/version_code")"

note "Verifying final APK signature..."
apksigner_output="$("$apksigner_path" verify --verbose --print-certs "$apk_path")"
actual_signer_sha256="$(
    printf '%s\n' "$apksigner_output" \
    | sed -n 's/.*certificate SHA-256 digest:[[:space:]]*//p' \
    | head -n 1 \
    | tr -d '[:space:]:' \
    | tr '[:upper:]' '[:lower:]'
)"
[ -n "$actual_signer_sha256" ] || die \
    "apksigner verified the APK but no signer SHA-256 digest could be extracted"
[[ "$actual_signer_sha256" =~ ^[0-9a-f]{64}$ ]] || die \
    "unexpected APK signer SHA-256 format: $actual_signer_sha256"
[ "$actual_signer_sha256" = "$expected_signer_sha256" ] || die \
    "APK signer mismatch: expected $expected_signer_sha256, got $actual_signer_sha256"

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

git_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
duration_minutes="$((build_duration / 60))"
duration_seconds="$((build_duration % 60))"
printf -v duration_human '%dm %02ds' "$duration_minutes" "$duration_seconds"

printf '\nBuild succeeded and artifact verification passed.\n'
printf 'Variant:       %s\n' "$variant"
printf 'Version:       %s (%s)\n' "$version_name" "$version_code"
printf 'Commit:        %s\n' "$git_commit"
printf 'APK:           %s\n' "$apk_path"
printf 'Size:          %s bytes\n' "$apk_size"
printf 'APK SHA256:    %s\n' "$apk_sha256"
printf 'Signer SHA256: %s\n' "$actual_signer_sha256"
printf 'Build time:    %s\n' "$duration_human"
