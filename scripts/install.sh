#!/usr/bin/env sh
set -eu

# Secure-by-default release installer. It downloads the checksum file over
# HTTPS, verifies the selected asset, and installs without sudo unless the
# caller explicitly chooses a system directory.
REPO="${CINDER_REPO:-Karmanya03/Cinder}"
VERSION="${CINDER_VERSION:-latest}"
COMPONENT="${CINDER_COMPONENT:-cli}"
INSTALL_DIR="${CINDER_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) ASSET_SUFFIX="linux-x86_64-musl" ;;
  Darwin:x86_64) ASSET_SUFFIX="macos-x86_64" ;;
  Darwin:arm64) ASSET_SUFFIX="macos-aarch64" ;;
  *) echo "Unsupported platform; set CINDER_INSTALL_DIR and install a release manually." >&2; exit 2 ;;
esac

case "$COMPONENT" in
  cli|gui) ASSET="cinder-$COMPONENT-$ASSET_SUFFIX" ;;
  *) echo "CINDER_COMPONENT must be cli or gui" >&2; exit 2 ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION=$(curl --proto '=https' --tlsv1.3 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/##')
fi
case "$VERSION" in v*) ;; *) echo "Release version must look like vX.Y.Z" >&2; exit 2 ;; esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
BASE="https://github.com/$REPO/releases/download/$VERSION"
curl --proto '=https' --tlsv1.3 -fL --retry 3 -o "$TMP/$ASSET" "$BASE/$ASSET"
curl --proto '=https' --tlsv1.3 -fL --retry 3 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
EXPECTED=$(awk -v file="$ASSET" '$2 == file {print $1}' "$TMP/SHA256SUMS")
[ -n "$EXPECTED" ] || { echo "Asset is missing from SHA256SUMS" >&2; exit 1; }
ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "Checksum verification failed" >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/$ASSET" "$INSTALL_DIR/cinder"
echo "Installed Cinder $VERSION ($COMPONENT) to $INSTALL_DIR/cinder"
