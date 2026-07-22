#!/bin/bash
set -eo pipefail
cd "$(dirname "$0")"

APP="lara"
SCHEME="lara"
CONFIG="Release"
ENTITLEMENTS="Config/lara.entitlements"
DERIVED="build/DerivedData"

# دعم --debug
if [[ "$*" == *--debug* ]]; then
    CONFIG="Debug"
fi

echo "[*] lara IPA build — config=$CONFIG"
echo "[*] entitlements: $ENTITLEMENTS"

# تحقق من ldid
if ! command -v ldid >/dev/null 2>&1; then
    echo "[!] ldid not found. Install: brew install ldid" >&2
    exit 1
fi

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "[!] entitlements file not found: $ENTITLEMENTS" >&2
    exit 1
fi

# تنظيف
rm -rf build && mkdir -p build

# Build بدون code signing
set +e
xcodebuild \
    -project "$APP.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration "$CONFIG" \
    -derivedDataPath "$DERIVED" \
    -destination 'generic/platform=iOS' \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_ENTITLEMENTS="" \
    CODE_SIGNING_ALLOWED=NO \
    DEVELOPMENT_TEAM="" \
    PROVISIONING_PROFILE_SPECIFIER="" \
    2>&1 | tee build/xcodebuild.log
BUILD_STATUS=${PIPESTATUS[0]}
set -e

if [ "$BUILD_STATUS" -ne 0 ] || ! grep -q "BUILD SUCCEEDED" build/xcodebuild.log; then
    echo "[!] BUILD FAILED (exit code: $BUILD_STATUS)"
    echo "[*] Last 200 lines of log:"
    tail -200 build/xcodebuild.log
    exit 1
fi
echo "[✓] xcodebuild: BUILD SUCCEEDED"

# تحديد مسار الـ .app
APP_PATH="$DERIVED/Build/Products/$CONFIG-iphoneos/$APP.app"
if [ ! -d "$APP_PATH" ]; then
    echo "[!] .app not found at expected path: $APP_PATH"
    echo "[*] Searching inside DerivedData..."
    FOUND=$(find "$DERIVED" -name "$APP.app" -type d 2>/dev/null | head -1)
    if [ -z "$FOUND" ]; then
        echo "[!] .app not found anywhere in DerivedData — build output:"
        find "$DERIVED/Build/Products" -maxdepth 2 2>/dev/null || true
        exit 1
    fi
    echo "[*] Found at: $FOUND"
    APP_PATH="$FOUND"
fi

TARGET="build/$APP.app"
cp -r "$APP_PATH" "$TARGET"

# التوقيع بـ ldid
echo "[*] Removing old code signature..."
codesign --remove "$TARGET" 2>/dev/null || true
rm -rf "$TARGET/_CodeSignature" "$TARGET/embedded.mobileprovision" 2>/dev/null || true

# توقيع الـ frameworks
FW_DIR="$TARGET/Frameworks"
if [ -d "$FW_DIR" ]; then
    for item in "$FW_DIR"/*; do
        [ -e "$item" ] || continue
        NAME=$(basename "$item")
        if [ -d "$item" ]; then
            BIN="$item/${NAME%.framework}"
            if [ -f "$BIN" ]; then
                echo "[*] Signing .framework binary: $NAME"
                ldid -S "$BIN"
            else
                echo "[!] .framework binary not found: $BIN (skipping)"
            fi
        elif [ -f "$item" ]; then
            echo "[*] Signing dylib: $NAME"
            ldid -S "$item"
        fi
    done
fi

# توقيع الـ binary الرئيسي
echo "[*] Signing main binary with: $ENTITLEMENTS"
ldid -S"$ENTITLEMENTS" "$TARGET/$APP"

# التحقق من الـ entitlements
echo "[*] Verifying critical entitlements:"
EMBEDDED=$(ldid -e "$TARGET/$APP" 2>/dev/null || true)
MISSING_ENTITLEMENTS=0
for key in "no-sandbox" "proc_info-allow" "platform-application"; do
    if echo "$EMBEDDED" | grep -q "$key"; then
        echo "    [✓] $key"
    else
        echo "    [!] MISSING: $key — IPA will not work correctly"
        MISSING_ENTITLEMENTS=1
    fi
done

if [ "$MISSING_ENTITLEMENTS" -ne 0 ]; then
    echo "[!] One or more critical entitlements are missing after signing — aborting."
    exit 1
fi

# تغليف IPA
echo "[*] Packaging IPA..."
cd build
mkdir -p Payload
cp -r "$APP.app" "Payload/$APP.app"
IPA_NAME="$APP.ipa"
if [ "$CONFIG" = "Debug" ]; then
    IPA_NAME="$APP.debug.ipa"
fi
zip -qr "$IPA_NAME" Payload
rm -rf Payload
cd ..

echo ""
echo "[✓] Done"
echo "[✓] IPA: build/$IPA_NAME"
ls -lh "build/$IPA_NAME"
