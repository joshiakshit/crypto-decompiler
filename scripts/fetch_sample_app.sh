#!/usr/bin/env bash
# Download deliberately-insecure demo apps to scan. These are educational
# targets published by their authors; CryptScan does not redistribute them.
set -euo pipefail

dest="${1:-sample_apks}"
mkdir -p "$dest"

fetch() {
    if curl -fL --retry 3 -o "$dest/$2" "$1"; then
        echo "saved $dest/$2"
    else
        echo "skip $2 (download failed)" >&2
    fi
}

fetch "https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk" "insecurebank.apk"
fetch "https://github.com/satishpatnayak/MyTest/raw/master/AndroGoat.apk" "androgoat.apk"
