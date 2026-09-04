#!/usr/bin/env bash
# Rebuild test fixtures (samples.dex, samples.apk) from the Java sources.
# Requires a JDK and Android SDK build-tools. Point ANDROID_HOME at the SDK,
# or leave unset to use ../../sdk relative to this script.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
sdk="${ANDROID_HOME:-$here/../../sdk}"
bt="$sdk/build-tools/34.0.0"
aj="$sdk/platforms/android-34/android.jar"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

mapfile -t sources < <(find "$here/src" -name '*.java')
javac --release 11 -cp "$aj" -d "$build/classes" "${sources[@]}"

mapfile -t classes < <(find "$build/classes" -name '*.class')
"$bt/d8" --min-api 21 --lib "$aj" --output "$build" "${classes[@]}"
cp "$build/classes.dex" "$here/samples.dex"

"$bt/aapt2" link -o "$build/base.apk" -I "$aj" \
    --manifest "$here/AndroidManifest.xml" \
    --min-sdk-version 21 --target-sdk-version 21
(cd "$build" && zip -qj base.apk classes.dex)
cp "$build/base.apk" "$here/samples.apk"

echo "wrote $here/samples.dex and $here/samples.apk"
