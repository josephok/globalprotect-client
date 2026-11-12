#!/bin/sh
# Build the globalprotect-client .deb for the host architecture
# (amd64 or arm64). Output: dist/deb/
# Requires: meson, ninja, gcc, dpkg-dev (dpkg-deb, dpkg-shlibdeps), fakeroot (optional),
# and the development packages: libgnutls28-dev libxml2-dev libp11-kit-dev zlib1g-dev
# Set DEB_DEPENDS to override the automatically computed Depends field.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=globalprotect-client
VERSION=$(sed -n "s/^[[:space:]]*version *: *'\([^']*\)'.*/\1/p" "$ROOT/meson.build" | head -n1)
[ -n "$VERSION" ] || { echo "cannot determine version from meson.build" >&2; exit 1; }

case $(uname -m) in
x86_64)  ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) echo "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" >&2; exit 1 ;;
esac
for t in meson ninja dpkg-deb dpkg-shlibdeps; do
    command -v "$t" >/dev/null || { echo "$t not found" >&2; exit 1; }
done

OUT="$ROOT/dist/deb"
WORK="$OUT/work"
PKG="$WORK/pkg"
rm -rf "$OUT"
mkdir -p "$PKG"

meson setup "$WORK/build" "$ROOT" --prefix=/usr \
    -Dvpnc_script=/usr/share/vpnc-scripts/vpnc-script \
    -Dpkcs11=enabled -Dstoken=disabled -Dyubikey=disabled -Dvhost=enabled >/dev/null
meson compile -C "$WORK/build"
DESTDIR="$PKG" meson install -C "$WORK/build" --no-rebuild --strip

install -d "$PKG/usr/share/doc/$NAME"
install -m 644 "$ROOT/README.md" "$PKG/usr/share/doc/$NAME/README.md"
{ cat "$ROOT/LICENSE"; printf '\n\n-- Bundled json-parser (src/json), BSD-2-Clause --\n\n'; cat "$ROOT/src/json/LICENSE"; } \
    > "$PKG/usr/share/doc/$NAME/copyright"
chmod 644 "$PKG/usr/share/doc/$NAME/copyright"

if [ -n "${DEB_DEPENDS:-}" ]; then
    DEPENDS=$DEB_DEPENDS
else
    mkdir -p "$WORK/shlibs/debian"
    printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$NAME" "$NAME" > "$WORK/shlibs/debian/control"
    DEPENDS=$(cd "$WORK/shlibs" && dpkg-shlibdeps -O -e"$PKG/usr/bin/gp" 2>/dev/null \
              | sed -n 's/^shlibs:Depends=//p')
    [ -n "$DEPENDS" ] || { echo "dpkg-shlibdeps failed; set DEB_DEPENDS manually" >&2; exit 1; }
    DEPENDS="$DEPENDS, vpnc-scripts"
fi

SIZE=$(du -sk "$PKG/usr" | cut -f1)
mkdir -p "$PKG/DEBIAN"
cat > "$PKG/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION-1
Architecture: $ARCH
Maintainer: Joseph Wu <wuyonggao@gmail.com>
Installed-Size: $SIZE
Depends: $DEPENDS
Section: net
Priority: optional
Homepage: https://github.com/josephok/globalprotect-client
Description: Command-line client for Palo Alto Networks GlobalProtect VPN
 A standalone, GlobalProtect-only VPN client derived from OpenConnect. It is
 built as a single executable, gp, and supports TLS and ESP/UDP transports.
EOF
(cd "$PKG" && find usr -type f -exec md5sum {} + > DEBIAN/md5sums)

DEB="$OUT/${NAME}_${VERSION}-1_${ARCH}.deb"
if command -v fakeroot >/dev/null; then
    fakeroot dpkg-deb --root-owner-group --build "$PKG" "$DEB"
else
    dpkg-deb --root-owner-group --build "$PKG" "$DEB"
fi

rm -rf "$WORK"
echo
echo "$DEB"
