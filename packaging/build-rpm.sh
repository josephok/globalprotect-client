#!/bin/sh
# Build the globalprotect-client RPM for the host architecture
# (x86_64 or aarch64). Output: dist/rpm/
# Requires: rpmbuild, tar, and the BuildRequires from the spec file.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=globalprotect-client
VERSION=$(sed -n "s/^[[:space:]]*version *: *'\([^']*\)'.*/\1/p" "$ROOT/meson.build" | head -n1)
[ -n "$VERSION" ] || { echo "cannot determine version from meson.build" >&2; exit 1; }

case $(uname -m) in
x86_64|aarch64) ;;
*) echo "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" >&2; exit 1 ;;
esac
command -v rpmbuild >/dev/null || { echo "rpmbuild not found" >&2; exit 1; }

TOP="$ROOT/dist/rpm"
rm -rf "$TOP"
mkdir -p "$TOP"/SOURCES "$TOP"/SPECS

tar -C "$ROOT" \
    --exclude=./build --exclude=./dist --exclude=./.git \
    --transform "s,^\./,$NAME-$VERSION/," \
    -czf "$TOP/SOURCES/$NAME-$VERSION.tar.gz" .
sed "s/@VERSION@/$VERSION/g" "$ROOT/packaging/rpm/$NAME.spec" > "$TOP/SPECS/$NAME.spec"

rpmbuild -ba --define "_topdir $TOP" "$TOP/SPECS/$NAME.spec"

echo
find "$TOP/RPMS" "$TOP/SRPMS" -name '*.rpm'
