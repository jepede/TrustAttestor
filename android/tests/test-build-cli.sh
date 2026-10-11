#!/usr/bin/env bash
# Offline behavioral tests: no real Android SDK, network, or production keystore.
set -Eeuo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
TEMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_ROOT"' EXIT

fixture="$TEMP_ROOT/TrustAttestor"
sdk="$TEMP_ROOT/sdk"
fakebin="$TEMP_ROOT/bin"
output="$TEMP_ROOT/outputs"
private="$TEMP_ROOT/private"
mkdir -p "$fixture/android/app/src/main/cpp/external/fmt" \
         "$sdk/platforms/android-35" \
         "$sdk/build-tools/35.0.0" \
         "$sdk/build-tools/35.0.1/lib" \
         "$sdk/ndk/27.2.12479018" \
         "$sdk/cmake/3.22.1/bin" \
         "$fakebin" "$private"
cp "$ROOT/build-cli.sh" "$fixture/android/build-cli.sh"
cp "$ROOT/gradle.properties" "$fixture/android/gradle.properties"
touch "$fixture/android/app/src/main/cpp/external/fmt/CMakeLists.txt"
printf 'fake android.jar\n' > "$sdk/platforms/android-35/android.jar"
printf 'fake d8.jar\n' > "$sdk/build-tools/35.0.1/lib/d8.jar"
printf 'Pkg.Revision = 27.2.12479018\n' > "$sdk/ndk/27.2.12479018/source.properties"
printf 'fake jks\n' > "$private/ci.jks"
cat > "$private/keystore.properties" <<EOF
androidStoreFile=$private/ci.jks
androidStorePassword=test
androidKeyAlias=ci
androidKeyPassword=test
EOF

cat > "$fakebin/java" <<'EOF'
#!/usr/bin/env bash
echo "openjdk version \"${MOCK_JAVA_VERSION:-17}.0.1\"" >&2
EOF

cat > "$fakebin/keytool" <<'EOF'
#!/usr/bin/env bash
printf 'SHA256: %064d\n' 0 | tr '0' 'a'
EOF

cat > "$sdk/build-tools/35.0.0/apksigner" <<'EOF'
#!/usr/bin/env bash
if [[ "${MOCK_SIGNER_MISMATCH:-0}" == "1" ]]; then
    printf 'Signer #1 certificate SHA-256 digest: %064d\n' 0 | tr '0' 'b'
else
    printf 'Signer #1 certificate SHA-256 digest: %064d\n' 0 | tr '0' 'a'
fi
EOF

cat > "$sdk/cmake/3.22.1/bin/cmake" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat > "$fixture/android/gradlew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRUST_ATTESTOR_BUILD_ROOT/gradle-calls"
case " $* " in
    *" :app:assembleDebug "*) variant=debug ;;
    *" :app:assembleRelease "*) variant=release ;;
    *) exit 0 ;;
esac
apk_dir="$TRUST_ATTESTOR_BUILD_ROOT/android/app/outputs/apk/$variant"
mkdir -p "$apk_dir"
printf 'fake apk for %s\n' "$variant" > "$apk_dir/fixture.apk"
if [[ "${MOCK_BAD_METADATA:-0}" == "1" ]]; then
    printf '{"elements":[]}\n' > "$apk_dir/output-metadata.json"
else
    cat > "$apk_dir/output-metadata.json" <<JSON
{"elements":[{"type":"SINGLE","outputFile":"fixture.apk","versionName":"1.2","versionCode":3}]}
JSON
fi
EOF
chmod +x "$fakebin/java" "$fakebin/keytool" "$sdk/build-tools/35.0.0/apksigner" \
    "$sdk/cmake/3.22.1/bin/cmake"
# Verify the CLI invokes Gradle through Bash even when a checkout lacks +x.
chmod 0644 "$fixture/android/gradlew"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

run_cli() (
    unset JAVA_HOME TRUST_ATTESTOR_SIGNING_PROPERTIES
    export ANDROID_SDK_ROOT="$sdk"
    export PATH="$fakebin:$PATH"
    bash "$fixture/android/build-cli.sh" \
        --signing-properties "$private/keystore.properties" --build-root "$output" "$@"
)

expect_failure() {
    local expected="$1"
    shift
    if "$@" > "$TEMP_ROOT/result.log" 2>&1; then
        fail "expected failure containing: $expected"
    fi
    grep -Fq -- "$expected" "$TEMP_ROOT/result.log" ||
        fail "missing expected error '$expected': $(cat "$TEMP_ROOT/result.log")"
}

bash -n "$ROOT/build-cli.sh" || fail "bash -n"
run_cli --help > "$TEMP_ROOT/help"
grep -Fq -- '--doctor' "$TEMP_ROOT/help" || fail "help omits --doctor"

run_cli --doctor > "$TEMP_ROOT/doctor"
grep -Fq 'Preflight passed; Gradle was not started.' "$TEMP_ROOT/doctor" ||
    fail "doctor did not pass"
[[ ! -e "$output/gradle-calls" ]] || fail "doctor unexpectedly ran Gradle"

# Clean must not receive an arbitrary Gradle task override; build does.
run_cli --clean --variant debug -- --info > "$TEMP_ROOT/debug"
grep -Fq 'Build succeeded and artifact verification passed.' "$TEMP_ROOT/debug" ||
    fail "debug verification failed"
[[ "$(wc -l < "$output/gradle-calls")" -eq 2 ]] ||
    fail "expected clean followed by one assemble task"
first_call="$(head -n 1 "$output/gradle-calls")"
[[ "$first_call" == *" clean" && "$first_call" != *"--info"* ]] ||
    fail "clean unexpectedly received extra assemble arguments"
grep -Fq ':app:assembleDebug --info' "$output/gradle-calls" ||
    fail "assemble did not receive extra Gradle args"

run_cli --variant release > "$TEMP_ROOT/release"
grep -Fq 'Variant:       release' "$TEMP_ROOT/release" ||
    fail "release selection failed"

expect_failure 'unsupported variant' run_cli --variant bad
run_cli_old_java() { MOCK_JAVA_VERSION=8 run_cli --doctor; }
run_cli_wrong_signer() { MOCK_SIGNER_MISMATCH=1 run_cli --variant debug; }
run_cli_bad_metadata() { MOCK_BAD_METADATA=1 run_cli --variant debug; }

expect_failure 'JDK 17 or newer' run_cli_old_java

cp "$private/keystore.properties" "$fixture/android/leaked.properties"
expect_failure 'signing properties must be outside the repository' \
    run_cli --signing-properties "$fixture/android/leaked.properties"

rm "$sdk/build-tools/35.0.1/lib/d8.jar"
expect_failure 'D8/R8 Build Tools' run_cli --doctor
printf 'fake d8.jar\n' > "$sdk/build-tools/35.0.1/lib/d8.jar"

expect_failure 'APK signer mismatch' run_cli_wrong_signer
expect_failure 'contains no APK elements' run_cli_bad_metadata

echo 'PASS: help, doctor, debug/release, clean args, JDK, signing, SDK, and metadata checks'
