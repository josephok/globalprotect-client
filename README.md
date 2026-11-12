# GlobalProtect client

A standalone command-line client for Palo Alto Networks **GlobalProtect** VPN.
It is a GlobalProtect-only port of [OpenConnect](https://www.infradead.org/openconnect/),
built as a single executable (`gp`) with no shared library, no gettext and no other VPN protocols.

## Requirements

- C compiler with C17 support (gcc/clang)
- [Meson](https://mesonbuild.com/) and Ninja
- pkg-config
- GnuTLS (>= 3.x), libxml2, zlib

Optional:

| Feature | Library | Meson option |
|---|---|---|
| PKCS#11 | p11-kit | `-Dpkcs11` |
| RSA SecurID soft token | libstoken | `-Dstoken` |
| Yubikey OATH | PC/SC (libpcsclite) | `-Dyubikey` |
| vhost-net accelerated tun (Linux) | – | `-Dvhost` |

TOTP/HOTP tokens are always available. Optional features are `auto` by default
(enabled if found); use `-Dname=enabled` or `-Dname=disabled` to force.

Install the dependencies, e.g.:

```sh
# Fedora
sudo dnf install gcc meson ninja-build pkgconf-pkg-config gnutls-devel libxml2-devel zlib-devel
# Debian/Ubuntu
sudo apt install gcc meson ninja-build pkg-config libgnutls28-dev libxml2-dev zlib1g-dev
```

## Build

```sh
meson setup build
meson compile -C build
```

The binary is `build/gp`. Useful options:

```sh
meson setup build -Dvpnc_script=/usr/share/vpnc-scripts/vpnc-script \
                  -Dexternal_browser=/usr/bin/xdg-open \
                  -Dstoken=disabled
```

Reconfigure an existing build directory with `meson configure build -Dname=value`.

## Install

```sh
sudo meson install -C build            # installs to /usr/local/bin/gp
```

Use a different prefix or a staging directory:

```sh
meson setup build --prefix=/usr
DESTDIR=/tmp/stage meson install -C build
```

Uninstall (from the same build directory):

```sh
sudo ninja -C build uninstall
```

## Runtime requirements

- A **vpnc-compatible routing script** (default `/etc/vpnc/vpnc-script`, set at build time via
  `-Dvpnc_script` or at run time with `--script`). Without it, `gp` cannot configure routes/DNS.
  The script is available from the `vpnc-scripts` package or
  <https://gitlab.com/openconnect/vpnc-scripts>.
- Root privileges (or `CAP_NET_ADMIN`) to create the tunnel device.

## Usage

```sh
sudo gp vpn.example.com
sudo gp -u alice --authgroup=gateway vpn.example.com
sudo gp --token-mode=totp --token-secret=base32:SECRET -u alice vpn.example.com
sudo gp -b --pid-file=/run/gp.pid vpn.example.com     # run in background
gp --help                                             # all options
gp --version                                          # shows built-in features
```

Traffic is carried over the TLS connection, and over ESP/UDP when the gateway supports it.

## License

LGPL-2.1-only, derived from OpenConnect. See `LICENSE`.
The bundled JSON parser in `src/json` is BSD-2-Clause (`src/json/LICENSE`).
