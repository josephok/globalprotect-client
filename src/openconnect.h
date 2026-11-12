/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef __OPENCONNECT_H__
#define __OPENCONNECT_H__

#include <sys/types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Internal interfaces of the gp client (derived from OpenConnect's API). */

/****************************************************************************/

/****************************************************************************/

/* Authentication form processing */

#define OC_FORM_OPT_TEXT	1
#define OC_FORM_OPT_PASSWORD	2
#define OC_FORM_OPT_SELECT	3
#define OC_FORM_OPT_HIDDEN	4
#define OC_FORM_OPT_TOKEN	5
#define OC_FORM_OPT_SSO_TOKEN	6
#define OC_FORM_OPT_SSO_USER	7

#define OC_FORM_RESULT_ERR		-1
#define OC_FORM_RESULT_OK		0
#define OC_FORM_RESULT_CANCELLED	1
#define OC_FORM_RESULT_NEWGROUP		2

#ifdef __OPENCONNECT_PRIVATE__
#define OC_FORM_RESULT_LOGGEDIN		255

#define OC_FORM_OPT_SECOND_AUTH		0x8000
#endif

#define OC_FORM_OPT_IGNORE		0x0001
#define OC_FORM_OPT_NUMERIC		0x0002

/* char * fields are static (owned by XML parser) and don't need to be
   freed by the form handling code — except for value, which for TEXT
   and PASSWORD options is allocated by openconnect_set_option_value()
   when process_form() interacts with the user and must be freed. */
struct oc_form_opt {
	struct oc_form_opt *next;
	int type;
	char *name;
	char *label;
	char *_value; /* Use openconnect_set_option_value() to set this */
	unsigned int flags;
	void *reserved;
};

/* To set the value to a form use the following function */

/* All fields are static, owned by the XML parser */
struct oc_choice {
	char *name;
	char *label;
	char *auth_type;
	char *override_name;
	char *override_label;
#ifdef __OPENCONNECT_PRIVATE__
	int second_auth;
	char *secondary_username;
	int secondary_username_editable;
	int noaaa;
	int priority;
#endif
};

struct oc_form_opt_select {
	struct oc_form_opt form;
	int nr_choices;
	struct oc_choice **choices;
};

/* All char * fields are static, owned by the XML parser */
struct oc_auth_form {
	char *banner;
	char *message;
	char *error;
	char *auth_id;
	char *method;
	char *action;
	struct oc_form_opt *opts;
	struct oc_form_opt_select *authgroup_opt;
	int authgroup_selection;
};

struct oc_split_include {
	const char *route;
	struct oc_split_include *next;
};

struct oc_ip_info {
	const char *addr;
	const char *netmask; /* Just the netmask, in dotted-quad form. */
	const char *addr6;
	const char *netmask6; /* This is the IPv6 address *and* netmask
			       * e.g. "2001::dead:beef/128". */
	const char *dns[3];
	const char *nbns[3];
	const char *domain;
	const char *proxy_pac;
	int mtu;

	struct oc_split_include *split_dns;
	struct oc_split_include *split_includes;
	struct oc_split_include *split_excludes;

	/* The elements above this line come from server-provided CSTP headers,
	 * so they should be handled with caution.  gateway_addr is generated
	 * locally from getnameinfo(). */
	char *gateway_addr;
};

struct oc_vpn_option {
	char *option;
	char *value;
	struct oc_vpn_option *next;
};

struct oc_stats {
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t rx_pkts;
	uint64_t rx_bytes;
};

struct oc_cert {
	int der_len;
	unsigned char *der_data;
	void *reserved;
};

/* Used by openconnect_webview_load_changed() to return data to OC.
 * The arrays must contain an even number of const strings, with names and
 * values, and a NULL to terminate. E.g.:
 * name0, val0, name1, val1, NULL
 */
struct oc_webview_result {
	const char *uri;
	const char **cookies;
	const char **headers;
};

/****************************************************************************/

#define PRG_ERR		0
#define PRG_INFO	1
#define PRG_DEBUG	2
#define PRG_TRACE	3

/* Byte commands to write into the cmd_fd:
 *
 *  CANCEL closes network connections, logs off the session (cookie)
 *    and shuts down the tun device.
 *  PAUSE closes network connections and returns. The caller is expected
 *    to call openconnect_mainloop() again soon.
 *  DETACH closes network connections and shuts down the tun device.
 *    It is not legal to call openconnect_mainloop() again after this,
 *    but a new instance of openconnect can be started using the same
 *    cookie.
 *  STATS calls the stats_handler.
 */
#define OC_CMD_CANCEL		'x'
#define OC_CMD_PAUSE		'p'
#define OC_CMD_DETACH		'd'
#define OC_CMD_STATS		's'

#define RECONNECT_INTERVAL_MIN	10
#define RECONNECT_INTERVAL_MAX	100

struct openconnect_info;

typedef enum {
	OC_TOKEN_MODE_NONE,
	OC_TOKEN_MODE_STOKEN,
	OC_TOKEN_MODE_TOTP,
	OC_TOKEN_MODE_HOTP,
	OC_TOKEN_MODE_YUBIOATH,
} oc_token_mode_t;

/* All strings are UTF-8. If operating in a legacy environment where
   nl_langinfo(CODESET) returns anything other than UTF-8, or on Windows,
   the library will take appropriate steps to convert back to the legacy
   character set (or UTF-16) for file handling and wherever else it is
   appropriate to do so. Library functions may (but probably don't yet)
   return -EILSEQ if passed invalid UTF-8 strings. */

/* Unlike previous versions of openconnect, no functions will take ownership
   of the provided strings. */


/* This string is static, valid only while the connection lasts. If you
 * are going to cache this to remember which certs the user has accepted,
 * make sure you also store the host/port for which it was accepted and
 * don't just accept this cert from *anywhere*. Also use the check
 * function below instead of manually comparing. When this function
 * returns a string which *doesn't* match the previously-stored hash
 * matched with openconnect_check_peer_cert_hash(), you should store
 * the new result from this function in place of the old. It means
 * we have upgraded to a better hash function. */
const char *openconnect_get_peer_cert_hash(struct openconnect_info *vpninfo);

/* Check if the current peer certificate matches a hash previously
 * obtained from openconect_get_peer_cert_hash(). Clients should not
 * attempt to do this using strcmp() and the *current* result of
 * openconnect_get_peer_cert_hash() because it might use
 * a different hash function today. This function will get it right.
 * Returns 0 on match; 1 on mismatch, -errno on failure. */
int openconnect_check_peer_cert_hash(struct openconnect_info *vpninfo,
				     const char *old_hash);

/* The buffers returned by these two functions must be freed with
   openconnect_free_cert_info(), especially on Windows. */
char *openconnect_get_peer_cert_details(struct openconnect_info *vpninfo);

/* Returns the length of the created DER output, in a newly-allocated buffer
   that will need to be freed by openconnect_free_cert_info(). */
int openconnect_get_peer_cert_DER(struct openconnect_info *vpninfo,
				  unsigned char **buf);
void openconnect_free_cert_info(struct openconnect_info *vpninfo,
				void *buf);

/* Creates a list of all certs in the peer's chain, returning the
   number of certs in the chain (or <0 on error). Only valid inside the
   validate_peer_cert callback. The caller should free the chain,
   but should not modify the contents. */
int openconnect_get_peer_cert_chain(struct openconnect_info *vpninfo,
				    struct oc_cert **chain);
void openconnect_free_peer_cert_chain(struct openconnect_info *vpninfo,
				      struct oc_cert *chain);

/* Contains a comma-separated list of authentication methods to enabled.
   Currently supported: Digest,Basic */
int openconnect_set_http_auth(struct openconnect_info *vpninfo,
			      const char *methods);
int openconnect_set_proxy_auth(struct openconnect_info *vpninfo,
			       const char *methods);
int openconnect_set_http_proxy(struct openconnect_info *vpninfo,
			       const char *proxy);

/* Passing a useragent string to openconnect_vpninfo_new() will still
 * append the OpenConnect version number. This function allows the
 * full string to be set, for those cases where a VPN server might
 * require an *exact* match. */
int openconnect_set_useragent(struct openconnect_info *vpninfo,
			      const char *useragent);

int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo);
int openconnect_obtain_cookie(struct openconnect_info *vpninfo);
int openconnect_init_ssl(void);

/* These are strictly cosmetic. The strings differ depending on
 * whether OpenSSL or GnuTLS is being used. And even depending on the
 * version of GnuTLS. Do *not* attempt to do anything meaningful based
 * on matching these strings; if you want to do something like that then
 * ask for an API that *does* offer you what you need. */
const char *openconnect_get_cstp_cipher(struct openconnect_info *);
const char *openconnect_get_dtls_cipher(struct openconnect_info *);

/* These return a descriptive string of the compression algorithm
 * in use (LZS, LZ4, ...). If no compression then NULL is returned. */


/*
 * Since authentication can run in a separate environment to the connection
 * itself, there is a simple set of information which needs to be passed
 * from one to the other. Basically it's just the server to connect to, and
 * the cookie we need for authentication. And luckily, as we've added more
 * and more protocols over the years, the "cookie" part has remained true
 * and we haven't needed to use client certificates for the *connection*.
 *
 * The *server* part is a little more complex. Firstly, the certificate
 * might not be valid and may have been accepted manually by the user,
 * so we pass the certificate fingerprint separately, as a second piece
 * of information.

 * In the beginning, we passed the server hostname as the third piece of
 * information, and all was well.
 *
 * Then we found servers on a non-standard port, so the authentication
 * dialogs would use openconnect_get_port() and just append it (":%d")
 * to the hostname string they passed on.
 *
 * Then we encountered servers with round-robin or geo-DNS, which gave
 * different IP addresses for a given hostname, and we switched the
 * openconnect_get_hostname() function to return the *IP* address instead,
 * since the actual name didn't matter when it wasn't being used to check
 * the server's certificate anyway.
 *
 * At some point later, openconnect_get_dnsname() was added to return the
 * actual hostname, during the authentication phase where the cert was
 * being presented to the user for manual acceptance. But that wasn't
 * really important for the authentication → connection handoff.
 *
 * Later still, Legacy IP addresses got scarce and SNI was invented, and
 * we started to see servers behind proxies that forward a connection
 * based on the SNI in the incoming ClientHello (TLS layer), or based on
 * the 'Host' header in the initial connection-phase request (HTTP[S]
 * layer). So returning just the IP address from openconnect_get_hostname()
 * now made things break.
 *
 * So... we need to pass *both* the actual hostname *and* the IP address
 * to the connecting openconnect invocation. As well as the port.
 *
 * In addition, the Pulse protocol introduced a new requirement for the
 * connection. Instead of connecting to a fixed endpoint on the server,
 * we must connect to the appropriate *path*, which varies. So in fact
 * it isn't just the "hostname" any more, but the full URL.
 *
 * So, now we have openconnect_get_connect_url() which gets the full URL
 * including the port and path, and the original hostname.
 *
 * Since we're now back to giving openconnect a hostname, we need to add
 * a '--resolve' argument to avoid the round robin DNS problem and ensure
 * that we actually connect to the same server we authenticated to. The
 * arguments for that can be obtained from openconnect_get_dnsname() and
 * openconnect_get_hostname() — the latter of which, as noted, was changed
 * years ago to return a numeric address. We end up invoking openconnect
 * to make the connection as follows:
 *
 * openconnect $CONNECT_URL --servercert $FINGERPRINT --cookie $COOKIE \
 *             --resolve $DNSNAME:$HOSTNAME
 *
 * ... where '$HOSTNAME', as returned by openconnect_get_hostname(),
 * isn't actually a hostname (as noted above). Sorry.
 *
 * In fact, what you get back from openconnect_get_hostname() is the
 * IP literal in the form it would appear in a URL. So IPv6 addresses
 * are wrapped in [], and that needs to be *stripped* in order to pass
 * it to openconnect's --resolve argument. As I realise and type this,
 * it doesn't seem particularly useful to provide yet another function
 * that will return the non-[]-wrapped version, as we'd still need UI
 * tools to do it themselves for backward compatibility. Sorry again :)
 */
const char *openconnect_get_connect_url(struct openconnect_info *);

/* Returns the IP address of the exact host to which the connection
 * was made. In --cookieonly mode or in any other scenario involving
 * a "two stage" connection, it is important to reconnect by IP because
 * the server side may be using DNS trickery for load balancing.
 *
 * If the IP address is unavailable due to the use of a proxy, this will
 * fall back to returning the DNS name. */
const char *openconnect_get_hostname(struct openconnect_info *);

/* Returns the hostname parsed out of the server name URL. This is
 * intended to be used by the validate_peer_cert callback to check that
 * the certificate matches the server name. */
const char *openconnect_get_dnsname(struct openconnect_info *);

int openconnect_set_hostname(struct openconnect_info *, const char *);
char *openconnect_get_urlpath(struct openconnect_info *);
int openconnect_set_urlpath(struct openconnect_info *, const char *);
int openconnect_set_localname(struct openconnect_info *, const char *);
int openconnect_set_sni(struct openconnect_info *, const char *);

/* Some software tokens, such as HOTP tokens, include a counter which
 * needs to be stored in persistent storage.
 *
 * For such tokens, the lock function is first invoked to obtain a lock
 * on the storage because we're about to generate a new code. It is
 * permitted to call openconnect_set_token_mode() from the lock function,
 * if the token storage has been updated since it was first loaded. The
 * token mode must not change; only the token secret.
 *
 * The unlock function is called when a token code has been generated,
 * with a new token secret to be written to the persistent storage. The
 * secret will be in the same format as it was originally received by
 * openconnect_set_token_mode(). The new token may be NULL if an error
 * was encountered generating the code, in which case it is only
 * necessary for the callback function to unlock the storage.
 */
typedef int (*openconnect_lock_token_vfn)(void *tokdata);
typedef int (*openconnect_unlock_token_vfn)(void *tokdata, const char *new_tok);
int openconnect_set_token_callbacks(struct openconnect_info *, void *tokdata,
				    openconnect_lock_token_vfn,
				    openconnect_unlock_token_vfn);

int openconnect_set_token_mode(struct openconnect_info *,
			       oc_token_mode_t, const char *token_str);
/* Legacy stoken-only function; do not use */
int openconnect_set_stoken_mode(struct openconnect_info *, int, const char *);


/* The size must be 41 bytes, since that's the size of a 20-byte SHA1
   represented as hex with a trailing NUL. */

int openconnect_set_cafile(struct openconnect_info *, const char *);

/* call this function to disable the system trust from being used to
 * verify the server certificate. @val is a boolean value.
 *
 * For backwards compatibility reasons this is enabled by default.
 */
void openconnect_set_system_trust(struct openconnect_info *vpninfo, unsigned val);

int openconnect_setup_csd(struct openconnect_info *, uid_t, int silent, const char *wrapper);

/* Valid choices are: "linux", "linux-64", "win", "mac-intel",
   "android", and "apple-ios". This also selects the corresponding CSD
   trojan binary. */
int openconnect_set_reported_os(struct openconnect_info *, const char *os);

int openconnect_set_version_string(struct openconnect_info *vpninfo,
				   const char *version_string);
int openconnect_set_client_cert(struct openconnect_info *, const char *cert,
				const char *sslkey);
int openconnect_set_key_password(struct openconnect_info *vpninfo, const char *pass);
/**
 * Multiple certificate authentication (MCA): the client cert _and_ the
 * mca_cert are used for authentication. The mca_cert is used to sign a
 * challenge sent by the server.
 */
const char *openconnect_get_ifname(struct openconnect_info *);
void openconnect_set_reqmtu(struct openconnect_info *, int reqmtu);
void openconnect_set_dpd(struct openconnect_info *, int min_seconds);
void openconnect_set_trojan_interval(struct openconnect_info *, int seconds);
int openconnect_get_idle_timeout(struct openconnect_info *);
time_t openconnect_get_auth_expiration(struct openconnect_info *);

/* The returned structures are owned by the library and may be freed/replaced
   due to rekey or reconnect. Assume that once the mainloop starts, the
   pointers are no longer valid. For similar reasons, it is unsafe to call
   this function from another thread. */
int openconnect_get_ip_info(struct openconnect_info *,
			    const struct oc_ip_info **info,
			    const struct oc_vpn_option **cstp_options,
			    const struct oc_vpn_option **dtls_options);

int openconnect_get_port(struct openconnect_info *);
const char *openconnect_get_cookie(struct openconnect_info *);
int openconnect_set_cookie(struct openconnect_info *, const char *);
void openconnect_clear_cookie(struct openconnect_info *);

int openconnect_disable_ipv6(struct openconnect_info *vpninfo);
int openconnect_disable_dtls(struct openconnect_info *vpninfo);
void openconnect_reset_ssl(struct openconnect_info *vpninfo);
int openconnect_parse_url(struct openconnect_info *vpninfo, const char *url);
void openconnect_set_cert_expiry_warning(struct openconnect_info *vpninfo,
					 int seconds);
void openconnect_set_pfs(struct openconnect_info *vpninfo, unsigned val);
int openconnect_set_allow_insecure_crypto(struct openconnect_info *vpninfo, unsigned val);

/* If this is set, then openconnect_obtain_cookie() will abort and return
   failure if the file descriptor is readable. Typically a user may create
   a pair of pipes with the pipe(2) system call, hand the readable one to
   this function, and then write a byte to the other end if it ever wants
   to cancel the connection. This way, a multi-threaded UI (which will be
   running openconnect_obtain_cookie() in a separate thread since it blocks)
   has the ability to cancel that call, reap its thread and free the
   vpninfo structure (or retry). An 'fd' argument of -1 will render the
   cancellation mechanism inactive. */
void openconnect_set_cancel_fd(struct openconnect_info *vpninfo, int fd);

/* Create a nonblocking pipe used to send cancellations and other commands
   to the library. This returns a file descriptor to the write side of
   the pipe. Both sides will be closed by openconnect_vpninfo_free().
   This replaces openconnect_set_cancel_fd(). */
int
openconnect_setup_cmd_pipe(struct openconnect_info *vpninfo);

const char *openconnect_get_version(void);

/* Open CSTP connection; on success, IP information will be available. */
int openconnect_make_cstp_connection(struct openconnect_info *vpninfo);

/* Create a tun device through the OS kernel (typical use case). Both
   strings are optional and can be NULL if desired. */
int openconnect_setup_tun_device(struct openconnect_info *vpninfo,
				 const char *vpnc_script, const char *ifname);

/* Pass traffic to a script program (no tun device). */
int openconnect_setup_tun_script(struct openconnect_info *vpninfo,
				 const char *tun_script);

/* Caller will provide a file descriptor for the tunnel traffic. */
int openconnect_setup_tun_fd(struct openconnect_info *vpninfo, int tun_fd);
/* Optional call to enable DTLS on the connection. */
int openconnect_setup_dtls(struct openconnect_info *vpninfo, int dtls_attempt_period);

/* Start the main loop; exits if OC_CMD_CANCEL is received on cmd_fd or
   the remote site aborts. */
int openconnect_mainloop(struct openconnect_info *vpninfo,
			 int reconnect_timeout,
			 int reconnect_interval);

/* The first (privdata) argument to each of these functions is either
   the privdata argument provided to openconnect_vpninfo_new_with_cbdata(),
   or if that argument was NULL then it'll be the vpninfo itself. */

/* When the server's certificate fails validation via the normal means,
   this function is called with the offending certificate along with
   a textual reason for the failure (which may not be translated, if
   it comes directly from OpenSSL, but will be if it is rejected for
   "certificate does not match hostname", because that check is done
   in OpenConnect and *is* translated). The function shall return zero
   if the certificate is (or has in the past been) explicitly accepted
   by the user, and non-zero to abort the connection. */
typedef int (*openconnect_validate_peer_cert_vfn) (void *privdata,
						   const char *reason);
/* On a successful connection, the server may provide us with a new XML
   configuration file. This contains the list of servers that can be
   chosen by the user to connect to, amongst other stuff that we mostly
   ignore. By "new", we mean that the SHA1 indicated by the server does
   not match the SHA1 set with the openconnect_set_xmlsha1() above. If
   they don't match, or openconnect_set_xmlsha1() has not been called,
   then the new XML is downloaded and this function is invoked. */
typedef int (*openconnect_write_new_config_vfn) (void *privdata, const char *buf,
						int buflen);
/* Handle an authentication form, requesting input from the user.
 * Return value:
 *  < 0, on error
 *  = 0, when form was parsed and POST required
 *  = 1, when response was cancelled by user
 */
typedef int (*openconnect_process_auth_form_vfn) (void *privdata,
						 struct oc_auth_form *form);
/* Logging output which the user *may* want to see. */
typedef void __attribute__ ((format(printf, 3, 4)))
		(*openconnect_progress_vfn) (void *privdata, int level,
					    const char *fmt, ...);
struct openconnect_info *openconnect_vpninfo_new(const char *useragent,
						 openconnect_validate_peer_cert_vfn,
						 openconnect_process_auth_form_vfn,
						 openconnect_progress_vfn,
						 void *privdata);
void openconnect_vpninfo_free(struct openconnect_info *vpninfo);

typedef int (*openconnect_open_webview_vfn) (struct openconnect_info *,
					     const char *uri,
					     void *privdata);

void openconnect_set_webview_callback(struct openconnect_info *vpninfo,
				      openconnect_open_webview_vfn);

int openconnect_webview_load_changed(struct openconnect_info *vpninfo,
                                     const struct oc_webview_result *result);

void openconnect_set_external_browser_callback(struct openconnect_info *vpninfo,
					       openconnect_open_webview_vfn);

/* Callback to allow binding a newly created socket's file descriptor to
   a specific interface, e.g. with SO_BINDTODEVICE. This tells the kernel
   not to route the traffic in question over the VPN tunnel. */
typedef void (*openconnect_protect_socket_vfn) (void *privdata, int fd);
void openconnect_set_protect_socket_handler(struct openconnect_info *vpninfo,
					    openconnect_protect_socket_vfn protect_socket);

void openconnect_set_loglevel(struct openconnect_info *vpninfo, int level);

void openconnect_set_pass_tos(struct openconnect_info *vpninfo, int enable);

/* Callback for obtaining traffic stats via OC_CMD_STATS.
 */
typedef void (*openconnect_stats_vfn) (void *privdata, const struct oc_stats *stats);
void openconnect_set_stats_handler(struct openconnect_info *vpninfo,
				   openconnect_stats_vfn stats_handler);

/* SSL certificate capabilities. openconnect_has_pkcs11_support() means that we
   can accept PKCS#11 URLs in place of filenames, for the certificate and key. */
int openconnect_has_pkcs11_support(void);

/* The OpenSSL TPM ENGINE stores keys in a PEM file labelled with the string
   -----BEGIN TSS KEY BLOB-----. */

/* Software token capabilities. */
int openconnect_has_stoken_support(void);
int openconnect_has_oath_support(void);
int openconnect_has_yubioath_support(void);
int openconnect_has_system_key_support(void);

/* Query and select from among supported protocols */

struct addrinfo;
typedef int (*openconnect_getaddrinfo_vfn) (void *privdata, const char *node, const char *service,
					    const struct addrinfo *hints, struct addrinfo **res);
void openconnect_override_getaddrinfo(struct openconnect_info *vpninfo, openconnect_getaddrinfo_vfn gai_fn);

/* Callback for configuring the interface after tunnel is fully up. */
typedef void (*openconnect_setup_tun_vfn) (void *privdata);
void openconnect_set_setup_tun_handler(struct openconnect_info *vpninfo,
				       openconnect_setup_tun_vfn setup_tun);

/* Callback for indicating that a TCP reconnection succeeded. */
typedef void (*openconnect_reconnected_vfn) (void *privdata);
void openconnect_set_reconnected_handler(struct openconnect_info *vpninfo,
				         openconnect_reconnected_vfn reconnected_fn);

#ifdef __cplusplus
}
#endif

#endif /* __OPENCONNECT_H__ */
