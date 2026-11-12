project('globalprotect-client', 'c',
  version : '0.1.0',
  license : 'LGPL-2.1-only',
  meson_version : '>=1.1',
  default_options : ['c_std=gnu17', 'warning_level=1', 'b_pie=true', 'buildtype=debugoptimized'])

cc = meson.get_compiler('c')
host = host_machine.system()

add_project_arguments('-D_GNU_SOURCE', '-DOPENCONNECT_GNUTLS', language : 'c')
if host == 'darwin'
  add_project_arguments('-D__APPLE_USE_RFC_3542', language : 'c')
endif

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('DEFAULT_VPNCSCRIPT', get_option('vpnc_script'))
conf.set_quoted('DEFAULT_EXTERNAL_BROWSER', get_option('external_browser'))
conf.set('HAVE_ESP', 1)
conf.set('HAVE_JSON', 1)

# Required dependencies
gnutls = dependency('gnutls', version : '>=3.6.0')
libxml2 = dependency('libxml-2.0')
zlib = dependency('zlib')
deps = [gnutls, libxml2, zlib, cc.find_library('m', required : false)]

# Optional dependencies
p11kit = dependency('p11-kit-1', required : get_option('pkcs11'))
if p11kit.found()
  conf.set('HAVE_P11KIT', 1)
  deps += p11kit
endif

stoken = dependency('stoken', required : false)
if not stoken.found()
  stoken = dependency('libstoken', required : get_option('stoken'))
endif
if stoken.found()
  conf.set('HAVE_LIBSTOKEN', 1)
  deps += stoken
endif

pcsc = dependency('libpcsclite', required : get_option('yubikey'))
if pcsc.found()
  conf.set('HAVE_LIBPCSCLITE', 1)
  deps += pcsc
endif

if cc.has_function('gnutls_system_key_add_x509', dependencies : gnutls)
  conf.set('HAVE_GNUTLS_SYSTEM_KEYS', 1)
endif

# Platform specifics
if host == 'linux'
  conf.set('HAVE_EPOLL', 1)
  conf.set_quoted('IF_TUN_HDR', 'linux/if_tun.h')
  conf.set('ENDIAN_HDR', '<endian.h>')
  if not get_option('vhost').disabled() and cc.has_header('linux/vhost.h') and cc.has_header('linux/virtio_net.h')
    conf.set('HAVE_VHOST', 1)
  endif
elif host == 'darwin'
  conf.set('ENDIAN_HDR', '<machine/endian.h>')
  if cc.has_header('net/if_utun.h')
    conf.set('HAVE_NET_UTUN_H', 1)
  endif
else
  conf.set('ENDIAN_HDR', '<sys/endian.h>')
  conf.set_quoted('IF_TUN_HDR', 'net/if_tun.h')
endif

foreach f : [
    ['asprintf', 'HAVE_ASPRINTF', 'stdio.h'],
    ['vasprintf', 'HAVE_VASPRINTF', 'stdio.h'],
    ['getline', 'HAVE_GETLINE', 'stdio.h'],
    ['strcasestr', 'HAVE_STRCASESTR', 'string.h'],
    ['strndup', 'HAVE_STRNDUP', 'string.h'],
    ['strchrnul', 'HAVE_STRCHRNUL', 'string.h'],
    ['inet_aton', 'HAVE_INET_ATON', 'arpa/inet.h'],
    ['localtime_r', 'HAVE_LOCALTIME_R', 'time.h'],
    ['explicit_bzero', 'HAVE_EXPLICIT_BZERO', 'string.h'],
    ['posix_spawn', 'HAVE_POSIX_SPAWN', 'spawn.h'],
    ['nl_langinfo', 'HAVE_NL_LANGINFO', 'langinfo.h'],
    ['fdevname_r', 'HAVE_FDEVNAME_R', 'stdlib.h'],
  ]
  if cc.has_function(f[0], prefix : '#define _GNU_SOURCE\n#include <@0@>'.format(f[2]))
    conf.set(f[1], 1)
  endif
endforeach

if cc.has_function('statfs', prefix : '#include <sys/vfs.h>') or cc.has_function('statfs', prefix : '#include <sys/mount.h>')
  conf.set('HAVE_STATFS', 1)
endif

if cc.compiles('int main(int c, char **v){return __builtin_clz(c);}', name : '__builtin_clz')
  conf.set('HAVE_BUILTIN_CLZ', 1)
endif

if cc.has_header_symbol('netinet/in.h', 'IPV6_PATHMTU', prefix : '#define _GNU_SOURCE\n#include <sys/socket.h>')
  conf.set('HAVE_IPV6_PATHMTU', 1)
endif

if cc.has_header('iconv.h') and cc.has_header('langinfo.h')
  conf.set('HAVE_ICONV', 1)
  conf.set('ICONV_CONST', '')
  iconv = dependency('iconv', required : false)
  if iconv.found()
    deps += iconv
  endif
endif

configure_file(output : 'config.h', configuration : conf)

sources = files(
  'src/auth-common.c',
  'src/auth-globalprotect.c',
  'src/auth-html.c',
  'src/compat.c',
  'src/digest.c',
  'src/esp-seqno.c',
  'src/esp.c',
  'src/gnutls-esp.c',
  'src/gnutls.c',
  'src/gpst.c',
  'src/http-auth.c',
  'src/http.c',
  'src/iconv.c',
  'src/json/json.c',
  'src/jsondump.c',
  'src/library.c',
  'src/main.c',
  'src/mainloop.c',
  'src/mtucalc.c',
  'src/oath.c',
  'src/script.c',
  'src/ssl.c',
  'src/textbuf.c',
  'src/tun.c',
  'src/version.c',
)
if conf.has('HAVE_LIBSTOKEN')
  sources += files('src/stoken.c')
endif
if conf.has('HAVE_LIBPCSCLITE')
  sources += files('src/yubikey.c')
endif
if conf.has('HAVE_VHOST')
  sources += files('src/vhost.c')
endif

executable('gp',
  sources,
  include_directories : include_directories('src', 'src/json'),
  dependencies : deps,
  install : true)
