Name:           globalprotect-client
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Command-line client for Palo Alto Networks GlobalProtect VPN
License:        LGPL-2.1-only AND BSD-2-Clause
URL:            https://github.com/josephok/globalprotect-client
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  meson >= 1.1
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(p11-kit-1)
BuildRequires:  pkgconfig(zlib)
Requires:       vpnc-script

%description
A standalone, GlobalProtect-only VPN client derived from OpenConnect. It is
built as a single executable, gp, and supports TLS and ESP/UDP transports.

%prep
%autosetup

%build
%meson -Dvpnc_script=/etc/vpnc/vpnc-script \
       -Dpkcs11=enabled -Dstoken=disabled -Dyubikey=disabled -Dvhost=enabled
%meson_build

%install
%meson_install

%files
%license LICENSE
%license src/json/LICENSE
%doc README.md
%{_bindir}/gp

%changelog
* Thu Nov 12 2026 Joseph Wu <wuyonggao@gmail.com> - @VERSION@-1
- Initial package
