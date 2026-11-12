/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
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

#include <config.h>

#include "openconnect-internal.h"

#include "gnutls.h"

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#include <libxml/tree.h>
#include <zlib.h>


#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>


struct openconnect_info *openconnect_vpninfo_new(const char *useragent,
						 openconnect_validate_peer_cert_vfn validate_peer_cert,
						 openconnect_process_auth_form_vfn process_auth_form,
						 openconnect_progress_vfn progress,
						 void *privdata)
{
	struct openconnect_info *vpninfo = calloc(1, sizeof(*vpninfo));
#ifdef HAVE_ICONV
	char *charset = nl_langinfo(CODESET);
#endif
	char hostname[256] = {'\0'};

	if (!vpninfo)
		return NULL;

	/* Simple initialisations of member variables, no resources acquired!
	 * The calloc() call initializes integer variables to 0. */
#ifdef HAVE_ICONV
	vpninfo->ic_utf8_to_legacy = (iconv_t)-1;
	vpninfo->ic_legacy_to_utf8 = (iconv_t)-1;
#endif
	vpninfo->redirect_url = NULL;
	vpninfo->platname = NULL;
	vpninfo->csd_token = NULL;
	vpninfo->csd_scriptname = NULL;
	vpninfo->proxy_type = NULL;
	vpninfo->proxy = NULL;
	vpninfo->proxy_fd = -1;
	vpninfo->proxy_user = NULL;
	vpninfo->proxy_pass = NULL;
	vpninfo->bearer_token = NULL;
	vpninfo->try_http_auth = 1;
	vpninfo->proxy_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
	vpninfo->http_auth[AUTH_TYPE_BASIC].state = AUTH_DEFAULT_DISABLED;
#if defined(DEFAULT_EXTERNAL_BROWSER)
	vpninfo->external_browser = DEFAULT_EXTERNAL_BROWSER;
#else
	vpninfo->external_browser = NULL;
#endif
	vpninfo->localname = NULL;
	vpninfo->unique_hostname = NULL;
	vpninfo->port = 443;
	vpninfo->urlpath = NULL;
	vpninfo->sni = NULL;
	vpninfo->connect_urlbuf = NULL;
	vpninfo->cert_expire_warning = 60 * 86400;
	vpninfo->cafile = NULL;
	vpninfo->authgroup = NULL;
	vpninfo->csd_wrapper = NULL;
#ifdef HAVE_LIBSTOKEN
	vpninfo->stoken_ctx = NULL;
	vpninfo->stoken_pin = NULL;
#endif
	vpninfo->oath_secret = NULL;
#ifdef HAVE_LIBPCSCLITE
	vpninfo->pcsc = NULL;
#endif
	vpninfo->tok_cbdata = NULL;
	vpninfo->peer_cert = NULL;
	vpninfo->peer_cert_hash = NULL;
	vpninfo->cert_list_handle = NULL;
	vpninfo->cookie = NULL;
	vpninfo->cstp_options = NULL;
	vpninfo->dtls_options = NULL;
	vpninfo->script_env = NULL;
	vpninfo->ciphersuite_config = NULL;
	vpninfo->pin_cache = NULL;
	vpninfo->deflate_pkt = NULL;
	vpninfo->current_ssl_pkt = NULL;
	vpninfo->cstp_pkt = NULL;
	vpninfo->dtls_pkt = NULL;
	vpninfo->tun_pkt = NULL;
	vpninfo->cstp_cipher = NULL;
	vpninfo->dtls_cipher_desc = NULL;
	vpninfo->vpnc_script = NULL;
	vpninfo->ifname = NULL;
	vpninfo->cmd_ifname = NULL;
	vpninfo->banner = NULL;
	vpninfo->ip_info.gateway_addr = NULL;
#ifdef HAVE_EPOLL
	vpninfo->epoll_fd = -1;
#endif
#ifdef HAVE_VHOST
	vpninfo->vhost_fd = -1;
	vpninfo->vhost_call_fd = -1;
	vpninfo->vhost_kick_fd = -1;
#endif
	vpninfo->tun_fd = -1;
	vpninfo->ssl_fd = -1;
	vpninfo->dtls_fd = -1;
	vpninfo->need_poll_cmd_fd = -1;
	vpninfo->cmd_fd = -1;
	init_pkt_queue(&vpninfo->free_queue);
	init_pkt_queue(&vpninfo->incoming_queue);
	init_pkt_queue(&vpninfo->outgoing_queue);
	init_pkt_queue(&vpninfo->tcp_control_queue);
	vpninfo->max_qlen = 32;	  /* >=16 will enable vhost-net on Linux */
	vpninfo->peer_addr = NULL;
	vpninfo->dtls_addr = NULL;
	vpninfo->useragent = NULL;
	vpninfo->version_string = NULL;
	vpninfo->quit_reason = NULL;
	vpninfo->delay_tunnel_reason = NULL;
	vpninfo->sso_login = NULL;
	vpninfo->sso_login_final = NULL;
	vpninfo->sso_username = NULL;
	vpninfo->sso_token_cookie = NULL;
	vpninfo->sso_error_cookie = NULL;
	vpninfo->sso_cookie_value = NULL;
	vpninfo->sso_browser_mode = NULL;
	vpninfo->verbose = PRG_TRACE;
	vpninfo->cbdata = privdata ? : vpninfo;

	if (gethostname(hostname, sizeof(hostname)) == 0 && hostname[0]) {
		char *localname;

		localname = openconnect_legacy_to_utf8(vpninfo, hostname);
		if (localname == hostname)
			vpninfo->localname = strdup(hostname);
		else
			vpninfo->localname = localname;
	} else {
		vpninfo->localname = strdup("localhost");
	}

	if (!vpninfo->localname)
		goto err;

	vpninfo->validate_peer_cert = validate_peer_cert;
	vpninfo->process_auth_form = process_auth_form;
	vpninfo->progress = progress;
	vpninfo->ssl_read = NULL;
	vpninfo->ssl_gets = NULL;
	vpninfo->ssl_write = NULL;
#ifdef HAVE_VHOST
	vpninfo->vhost_fd = vpninfo->vhost_call_fd = vpninfo->vhost_kick_fd = -1;
#endif

	/* Initialisations of member variables that acquire resources. */
#ifdef HAVE_ICONV
	if (charset && strcmp(charset, "UTF-8")) {
		if ((vpninfo->ic_utf8_to_legacy = iconv_open(charset, "UTF-8")) == (iconv_t)-1)
			goto err;
		if ((vpninfo->ic_legacy_to_utf8 = iconv_open("UTF-8", charset)) == (iconv_t)-1)
			goto err;
	}
#endif
	if (!(vpninfo->useragent = openconnect_create_useragent(useragent)))
		goto err;
	openconnect_set_reported_os(vpninfo, NULL);
	if (!vpninfo->platname)
		goto err;
#ifdef HAVE_EPOLL
	if ((vpninfo->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1)
		goto err;
#endif

	return vpninfo;

err:
	openconnect_vpninfo_free(vpninfo);
	return NULL;
}

void openconnect_set_pass_tos(struct openconnect_info *vpninfo, int enable)
{
	vpninfo->dtls_pass_tos = enable;
}

void openconnect_set_loglevel(struct openconnect_info *vpninfo, int level)
{
	vpninfo->verbose = level;
}

int openconnect_setup_dtls(struct openconnect_info *vpninfo,
			   int attempt_period)

{
	vpninfo->dtls_attempt_period = attempt_period;
	return esp_setup(vpninfo);
}

int openconnect_obtain_cookie(struct openconnect_info *vpninfo)
{
#ifdef HAVE_LIBSTOKEN
	int ret;
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		ret = prepare_stoken(vpninfo);
		if (ret)
			return ret;
	}
#endif
	return gpst_obtain_cookie(vpninfo);
}

int openconnect_make_cstp_connection(struct openconnect_info *vpninfo)
{
	int result = gpst_setup(vpninfo);

	/* ssl_times.last_tx should be set to show that a connection has been setup */
	if (result == 0 && vpninfo->ssl_times.last_tx == 0)
		vpninfo->ssl_times.last_tx = time(NULL);
	return result;
}

int openconnect_set_reported_os(struct openconnect_info *vpninfo,
				const char *os)
{
	static const char * const allowed[] = {"linux", "linux-64", "win", "mac-intel", "android", "apple-ios"};

	if (!os) {
#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  if TARGET_OS_IOS
		/* We need to use Apple's boolean "target" defines to distinguish iOS from
		 * desktop MacOS. See  https://stackoverflow.com/a/5920028 and
		 * https://github.com/mstg/iOS-full-sdk/blob/master/iPhoneOS9.3.sdk/usr/include/TargetConditionals.h#L64-L71
		 */
		os = "apple-ios";
#  else
		os = "mac-intel";
#  endif
#else
		os = sizeof(long) > 4 ? "linux-64" : "linux";
#endif
	}

	for (int i = 0; i < ARRAY_SIZE(allowed); i++) {
		if (!strcmp(os, allowed[i])) {
			STRDUP(vpninfo->platname, os);
			return 0;
		}
	}
	return -EINVAL;
}

int openconnect_set_version_string(struct openconnect_info *vpninfo,
				   const char *version_string)
{
	STRDUP(vpninfo->version_string, version_string);

	return 0;
}

const char *add_option_dup(struct oc_vpn_option **list,
			   const char *opt,
			   const char *val, int val_len)
{
	const char *ret;
	char *new_val;

	if (val_len >= 0)
		new_val = strndup(val, val_len);
	else
		new_val = strdup(val);

	ret = add_option_steal(list, opt, &new_val);
	free(new_val);
	return ret;
}

const char *add_option_steal(struct oc_vpn_option **list,
			     const char *opt, char **val)
{
	struct oc_vpn_option *new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->option = strdup(opt);
	if (!new->option) {
		free(new);
		return NULL;
	}
	new->value = *val;
	*val = NULL;
	new->next = *list;
	*list = new;

	return new->value;
}

const char *add_option_ipaddr(struct oc_vpn_option **list,
			      const char *opt, int af, void *addr)
{
	char buf[40];

	if (!inet_ntop(af, addr, buf, sizeof(buf)))
		return NULL;

	return add_option_dup(list, opt, buf, -1);
}


void free_optlist(struct oc_vpn_option *opt)
{
	struct oc_vpn_option *next;

	for (; opt; opt = next) {
		next = opt->next;
		free(opt->option);
		free(opt->value);
		free(opt);
	}
}

int install_vpn_opts(struct openconnect_info *vpninfo, struct oc_vpn_option *opt,
		     struct oc_ip_info *ip_info)
{
	if (!ip_info->addr && !ip_info->addr6 && !ip_info->netmask6) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No IP address received. Aborting\n"));
		return -EINVAL;
	}

	if (vpninfo->ip_info.addr) {
		if (!ip_info->addr || strcmp(ip_info->addr, vpninfo->ip_info.addr)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP address (%s != %s)\n"),
				     ip_info->addr, vpninfo->ip_info.addr);
			/* EPERM means that the retry loop will abort and won't keep trying. */
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.netmask) {
		if (!ip_info->netmask || strcmp(ip_info->netmask, vpninfo->ip_info.netmask)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different Legacy IP netmask (%s != %s)\n"),
				     ip_info->netmask, vpninfo->ip_info.netmask);
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.addr6) {
		if (!ip_info->addr6 || strcmp(ip_info->addr6, vpninfo->ip_info.addr6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 address (%s != %s)\n"),
				     ip_info->addr6, vpninfo->ip_info.addr6);
			return -EPERM;
		}
	}
	if (vpninfo->ip_info.netmask6) {
		if (!ip_info->netmask6 || strcmp(ip_info->netmask6, vpninfo->ip_info.netmask6)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Reconnect gave different IPv6 netmask (%s != %s)\n"),
				     ip_info->netmask6, vpninfo->ip_info.netmask6);
			return -EPERM;
		}
	}

	/* Preserve gateway_addr and MTU if they were set */
	ip_info->gateway_addr = vpninfo->ip_info.gateway_addr;
	if (!ip_info->mtu)
		ip_info->mtu = vpninfo->ip_info.mtu;

	if (ip_info->mtu && ip_info->mtu < 1280 &&
	    (ip_info->addr6 || ip_info->netmask6)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("IPv6 configuration received but MTU %d is too small.\n"),
			     ip_info->mtu);
	}

	/* XX: Supported protocols and servers are inconsistent in how they send us
	 * multiple search domains. Some provide domains via repeating fields which we
	 * glom into a single space-separated string, some provide domains in single
	 * fields which contain ',' or ';' as separators.
	 *
	 * Since neither ',' nor ';' is a legal character in a domain name, and since all
	 * known routing configuration scripts support space-separated domains, we can
	 * safely replace these characters with spaces, and thus support all known
	 * combinations.
	 */
	for (char *p = (char *)ip_info->domain; p && *p; p++) {
		if (*p == ';' || *p == ',')
			*p = ' ';
	}

	/* Free the original options */
	free_split_routes(&vpninfo->ip_info);
	free_optlist(vpninfo->cstp_options);

	/* Install the new options */
	vpninfo->cstp_options = opt;
	vpninfo->ip_info = *ip_info;

	return 0;
}

static void free_certinfo(struct cert_info *certinfo)
{
	/**
	 * Ensure resources are released
	 */

	unload_certificate(certinfo, 1);

	/* These are const in openconnect itself, but for consistency of
	   the library API we do take ownership of the strings we're given,
	   and thus we have to free them too. */
	if (certinfo->cert != certinfo->key)
		free((void *)certinfo->key);
	free((void *)certinfo->cert);

	free_pass(&certinfo->password);
}

void openconnect_vpninfo_free(struct openconnect_info *vpninfo)
{
	openconnect_close_https(vpninfo, 1);
	esp_shutdown(vpninfo);
	if (vpninfo->cmd_fd_write >= 0) {
		closesocket(vpninfo->cmd_fd);
		closesocket(vpninfo->cmd_fd_write);
	}


	free(vpninfo->sso_username);
	free(vpninfo->sso_cookie_value);
	free(vpninfo->sso_browser_mode);
	free(vpninfo->sso_login);
	free(vpninfo->sso_login_final);
	free(vpninfo->sso_error_cookie);
	free(vpninfo->sso_token_cookie);

#ifdef HAVE_ICONV
	if (vpninfo->ic_utf8_to_legacy != (iconv_t)-1)
		iconv_close(vpninfo->ic_utf8_to_legacy);

	if (vpninfo->ic_legacy_to_utf8 != (iconv_t)-1)
		iconv_close(vpninfo->ic_legacy_to_utf8);
#endif
	free(vpninfo->peer_addr);
	free(vpninfo->ip_info.gateway_addr);
	free_optlist(vpninfo->script_env);
	free_optlist(vpninfo->cookies);
	free_optlist(vpninfo->cstp_options);
	free_optlist(vpninfo->dtls_options);
	free_split_routes(&vpninfo->ip_info);
	free(vpninfo->hostname);
	free(vpninfo->unique_hostname);
	free(vpninfo->sni);
	buf_free(vpninfo->connect_urlbuf);
	free(vpninfo->urlpath);
	free(vpninfo->redirect_url);
	free_pass(&vpninfo->cookie);
	free(vpninfo->proxy_type);
	free(vpninfo->proxy);
	free(vpninfo->proxy_user);
	free_pass(&vpninfo->proxy_pass);
	free(vpninfo->vpnc_script);
	free(vpninfo->cafile);
	free(vpninfo->ifname);
	free(vpninfo->peer_cert_hash);
	free(vpninfo->ciphersuite_config);
	gnutls_free(vpninfo->cstp_cipher);
	free(vpninfo->dtls_addr);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
	}
	free(vpninfo->csd_token);
	free(vpninfo->csd_ticket);
	free(vpninfo->platname);

	free_certinfo(&vpninfo->certinfo[0]);

	if (vpninfo->peer_cert) {
		gnutls_x509_crt_deinit(vpninfo->peer_cert);
	}
	while (vpninfo->pin_cache) {
		struct pin_cache *cache = vpninfo->pin_cache;

		free(cache->token);
		memset(cache->pin, 0x5a, strlen(cache->pin));
		free(cache->pin);
		vpninfo->pin_cache = cache->next;
		free(cache);
	}

	free(vpninfo->localname);
	free(vpninfo->useragent);
	free(vpninfo->authgroup);
#ifdef HAVE_LIBSTOKEN
	if (vpninfo->stoken_pin)
		free_pass(&vpninfo->stoken_pin);
	if (vpninfo->stoken_ctx)
		stoken_destroy(vpninfo->stoken_ctx);
#endif
	if (vpninfo->oath_secret) {
		free_pass(&vpninfo->oath_secret);
	}
#ifdef HAVE_LIBPCSCLITE
	release_pcsc_ctx(vpninfo);
#endif
#ifdef HAVE_EPOLL
	if (vpninfo->epoll_fd >= 0)
		close(vpninfo->epoll_fd);
#endif

	free_pkt(vpninfo, vpninfo->deflate_pkt);
	free_pkt(vpninfo, vpninfo->tun_pkt);
	free_pkt(vpninfo, vpninfo->dtls_pkt);
	free_pkt(vpninfo, vpninfo->cstp_pkt);
	struct pkt *pkt;
	while ((pkt = dequeue_packet(&vpninfo->free_queue)))
		free(pkt);

	free(vpninfo->bearer_token);
	free(vpninfo);
}


const char *openconnect_get_connect_url(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *urlbuf = vpninfo->connect_urlbuf;

	if (!urlbuf)
		urlbuf = buf_alloc();

	buf_append(urlbuf, "https://%s", vpninfo->hostname);
	if (vpninfo->port != 443)
		buf_append(urlbuf, ":%d", vpninfo->port);
	buf_append(urlbuf, "/");

	if (buf_error(urlbuf)) {
		buf_free(urlbuf);
		vpninfo->connect_urlbuf = NULL;
		return NULL;
	}

	vpninfo->connect_urlbuf = urlbuf;
	return urlbuf->data;
}

const char *openconnect_get_hostname(struct openconnect_info *vpninfo)
{
	return vpninfo->unique_hostname?:vpninfo->hostname;
}

const char *openconnect_get_dnsname(struct openconnect_info *vpninfo)
{
	return vpninfo->hostname;
}

int openconnect_set_hostname(struct openconnect_info *vpninfo,
			     const char *hostname)
{
	UTF8CHECK(hostname);

	STRDUP(vpninfo->hostname, hostname);
	free(vpninfo->unique_hostname);
	vpninfo->unique_hostname = NULL;
	free(vpninfo->peer_addr);
	vpninfo->peer_addr = NULL;
	free(vpninfo->ip_info.gateway_addr);
	vpninfo->ip_info.gateway_addr = NULL;

	return 0;
}

char *openconnect_get_urlpath(struct openconnect_info *vpninfo)
{
	return vpninfo->urlpath;
}

int openconnect_set_useragent(struct openconnect_info *vpninfo,
			      const char *useragent)
{
	UTF8CHECK(useragent);

	STRDUP(vpninfo->useragent, useragent);
	return 0;
}

int openconnect_set_urlpath(struct openconnect_info *vpninfo,
			    const char *urlpath)
{
	UTF8CHECK(urlpath);

	STRDUP(vpninfo->urlpath, urlpath);
	return 0;
}

int openconnect_set_localname(struct openconnect_info *vpninfo,
			      const char *localname)
{
	UTF8CHECK(localname);

	STRDUP(vpninfo->localname, localname);
	return 0;
}

int openconnect_set_sni(struct openconnect_info *vpninfo,
			      const char *sni)
{
	UTF8CHECK(sni);

	STRDUP(vpninfo->sni, sni);
	return 0;
}

int openconnect_disable_ipv6(struct openconnect_info *vpninfo)
{
	/* This prevents disabling IPv6 when the connection is
	 * currently connected or has been connected previously.
	 *
	 * XX: It would be better to allow it when currently
	 * disconnected, but we currently have no way to indicate
	 * a state in which IP and routing configuration are
	 * unconfigured state. (Neither a closed TLS socket
	 * nor tunnel socket is a reliable indicator.)
	 */
	if (!vpninfo->disable_ipv6 &&
	    vpninfo->ssl_times.last_tx != 0)
		return -EINVAL;
	vpninfo->disable_ipv6 = 1;
	return 0;
}

int openconnect_disable_dtls(struct openconnect_info *vpninfo)
{
	/* This disables DTLS or ESP. It is prevented when the
	 * connection is currently connected or has been
	 * connected previously.
	 *
	 * We allow to disable DTLS if not yet connected to
	 * allow clients using the library disable DTLS if it
	 * fails to connect, similarly to what openconnect does.
	 */
	if (vpninfo->dtls_state == DTLS_ESTABLISHED
	    || vpninfo->dtls_state == DTLS_CONNECTED)
		return -EINVAL;
	vpninfo->dtls_state = DTLS_DISABLED;
	return 0;
}

int openconnect_set_cafile(struct openconnect_info *vpninfo, const char *cafile)
{
	UTF8CHECK(cafile);

	STRDUP(vpninfo->cafile, cafile);
	return 0;
}

void openconnect_set_system_trust(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->no_system_trust = !val;
}

const char *openconnect_get_ifname(struct openconnect_info *vpninfo)
{
	return vpninfo->ifname;
}

void openconnect_set_reqmtu(struct openconnect_info *vpninfo, int reqmtu)
{
	vpninfo->reqmtu = reqmtu;
}

void openconnect_set_dpd(struct openconnect_info *vpninfo, int min_seconds)
{
	/* Make sure (ka->dpd / 2), our computed midway point, isn't 0 */
	if (!min_seconds || min_seconds >= 2)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = min_seconds;
	else if (min_seconds == 1)
		vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = 2;
}

void openconnect_set_trojan_interval(struct openconnect_info *vpninfo, int seconds)
{
	vpninfo->trojan_interval = seconds;
}

int openconnect_get_idle_timeout(struct openconnect_info *vpninfo)
{
	return vpninfo->idle_timeout;
}

time_t openconnect_get_auth_expiration(struct openconnect_info *vpninfo)
{
	return vpninfo->auth_expiration;
}

int openconnect_get_ip_info(struct openconnect_info *vpninfo,
			    const struct oc_ip_info **info,
			    const struct oc_vpn_option **cstp_options,
			    const struct oc_vpn_option **dtls_options)
{
	if (info)
		*info = &vpninfo->ip_info;
	if (cstp_options)
		*cstp_options = vpninfo->cstp_options;
	if (dtls_options)
		*dtls_options = vpninfo->dtls_options;
	return 0;
}

int openconnect_setup_csd(struct openconnect_info *vpninfo, uid_t uid,
			  int silent, const char *wrapper)
{
	vpninfo->uid_csd = uid;
	vpninfo->uid_csd_given = silent ? 2 : 1;
	STRDUP(vpninfo->csd_wrapper, wrapper);

	return 0;
}

int openconnect_set_client_cert(struct openconnect_info *vpninfo,
				const char *cert, const char *sslkey)
{
	UTF8CHECK(cert);
	UTF8CHECK(sslkey);

	/* Avoid freeing it twice if it's the same */
	if (vpninfo->certinfo[0].key == vpninfo->certinfo[0].cert)
		vpninfo->certinfo[0].key = NULL;

	STRDUP(vpninfo->certinfo[0].cert, cert);

	if (sslkey) {
		STRDUP(vpninfo->certinfo[0].key, sslkey);
	} else {
		vpninfo->certinfo[0].key = vpninfo->certinfo[0].cert;
	}

	return 0;
}

int openconnect_get_port(struct openconnect_info *vpninfo)
{
	return vpninfo->port;
}

const char *openconnect_get_cookie(struct openconnect_info *vpninfo)
{
	return vpninfo->cookie;
}

void openconnect_clear_cookie(struct openconnect_info *vpninfo)
{
	if (vpninfo->cookie)
		memset(vpninfo->cookie, 0, strlen(vpninfo->cookie));
}

int openconnect_set_cookie(struct openconnect_info *vpninfo,
			    const char *cookie)
{
	UTF8CHECK(cookie);

	STRDUP(vpninfo->cookie, cookie);
	return 0;
}

void openconnect_reset_ssl(struct openconnect_info *vpninfo)
{
	vpninfo->got_cancel_cmd = 0;
	openconnect_close_https(vpninfo, 0);

	free(vpninfo->peer_addr);
	vpninfo->peer_addr = NULL;
	vpninfo->dtls_tos_optname = 0;
	free(vpninfo->ip_info.gateway_addr);
	vpninfo->ip_info.gateway_addr = NULL;

	openconnect_clear_cookies(vpninfo);
}

int openconnect_parse_url(struct openconnect_info *vpninfo, const char *url)
{
	char *scheme = NULL;
	int ret;

	UTF8CHECK(url);

	openconnect_set_hostname(vpninfo, NULL);
	free(vpninfo->urlpath);
	vpninfo->urlpath = NULL;

	ret = internal_parse_url(url, &scheme, &vpninfo->hostname,
				 &vpninfo->port, &vpninfo->urlpath, 443);

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server URL '%s'\n"),
			     url);
		return ret;
	}
	if (scheme && strcmp(scheme, "https")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Only https:// permitted for server URL\n"));
		ret = -EINVAL;
	}
	free(scheme);
	return ret;
}

void openconnect_set_cert_expiry_warning(struct openconnect_info *vpninfo,
					 int seconds)
{
	vpninfo->cert_expire_warning = seconds;
}

int openconnect_set_key_password(struct openconnect_info *vpninfo, const char *pass)
{
	STRDUP(vpninfo->certinfo[0].password, pass);

	return 0;
}

void openconnect_set_pfs(struct openconnect_info *vpninfo, unsigned val)
{
	vpninfo->pfs = val;
}

int openconnect_set_allow_insecure_crypto(struct openconnect_info *vpninfo, unsigned val)
{
	int ret = can_enable_insecure_crypto();
	if (ret)
		return ret;
	vpninfo->allow_insecure_crypto = val;
	return 0;
}

void openconnect_set_cancel_fd(struct openconnect_info *vpninfo, int fd)
{
	vpninfo->cmd_fd = fd;
}

# define CMD_PIPE_ERR -EIO

OPENCONNECT_CMD_SOCKET openconnect_setup_cmd_pipe(struct openconnect_info *vpninfo)
{
	OPENCONNECT_CMD_SOCKET pipefd[2];

	if (pipe(pipefd) < 0)
		return CMD_PIPE_ERR;

	if (set_sock_nonblock(pipefd[0]) || set_sock_nonblock(pipefd[1])) {
		closesocket(pipefd[0]);
		closesocket(pipefd[1]);
		return CMD_PIPE_ERR;
	}
	vpninfo->cmd_fd = pipefd[0];
	vpninfo->cmd_fd_write = pipefd[1];
	vpninfo->need_poll_cmd_fd = 1;
	return vpninfo->cmd_fd_write;
}

const char *openconnect_get_version(void)
{
	return openconnect_version_str;
}

int openconnect_has_pkcs11_support(void)
{
#if defined(OPENCONNECT_GNUTLS) && defined(HAVE_P11KIT)
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_stoken_support(void)
{
#ifdef HAVE_LIBSTOKEN
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_oath_support(void)
{
	return 2;
}

int openconnect_has_yubioath_support(void)
{
#ifdef HAVE_LIBPCSCLITE
	return 1;
#else
	return 0;
#endif
}

int openconnect_has_system_key_support(void)
{
#ifdef HAVE_GNUTLS_SYSTEM_KEYS
	return 1;
#else
	return 0;
#endif
}

int openconnect_set_token_callbacks(struct openconnect_info *vpninfo,
				    void *tokdata,
				    openconnect_lock_token_vfn lock,
				    openconnect_unlock_token_vfn unlock)
{
	vpninfo->lock_token = lock;
	vpninfo->unlock_token = unlock;
	vpninfo->tok_cbdata = tokdata;

	return 0;
}

/*
 * Enable software token generation.
 *
 * If token_mode is OC_TOKEN_MODE_STOKEN and token_str is NULL,
 * read the token data from ~/.stokenrc.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if the underlying library (libstoken, liboath) is not
 *                 available or an invalid token_mode was provided
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if token_mode is OC_TOKEN_MODE_STOKEN and ~/.stokenrc is
 *             missing (token_str was NULL)
 *  = -EIO, for other failures in the underlying library (libstoken, liboath)
 *  = 0, on success
 */
int openconnect_set_token_mode(struct openconnect_info *vpninfo,
			       oc_token_mode_t token_mode,
			       const char *token_str)
{
	vpninfo->token_mode = OC_TOKEN_MODE_NONE;

	UTF8CHECK(token_str);

	switch (token_mode) {
	case OC_TOKEN_MODE_NONE:
		return 0;

	case OC_TOKEN_MODE_TOTP:
	case OC_TOKEN_MODE_HOTP:
		return set_oath_mode(vpninfo, token_str, token_mode);

#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return set_libstoken_mode(vpninfo, token_str);
#endif
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return set_yubikey_mode(vpninfo, token_str);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Enable libstoken token generation if use_stoken == 1.
 *
 * If token_str is not NULL, try to parse the string.  Otherwise, try to read
 * the token data from ~/.stokenrc
 *
 * DEPRECATED: use openconnect_set_stoken_mode() instead.
 *
 * Return value:
 *  = -EILSEQ, if token_str is not valid UTF-8
 *  = -EOPNOTSUPP, if libstoken is not available
 *  = -EINVAL, if the token string is invalid (token_str was provided)
 *  = -ENOENT, if ~/.stokenrc is missing (token_str was NULL)
 *  = -EIO, for other libstoken failures
 *  = 0, on success
 */
int openconnect_set_stoken_mode(struct openconnect_info *vpninfo,
				int use_stoken, const char *token_str)
{
	oc_token_mode_t token_mode = OC_TOKEN_MODE_NONE;

	if (use_stoken)
		token_mode = OC_TOKEN_MODE_STOKEN;

	return openconnect_set_token_mode(vpninfo, token_mode, token_str);
}

void openconnect_set_protect_socket_handler(struct openconnect_info *vpninfo,
					    openconnect_protect_socket_vfn protect_socket)
{
	vpninfo->protect_socket = protect_socket;
}

void openconnect_override_getaddrinfo(struct openconnect_info *vpninfo, openconnect_getaddrinfo_vfn gai_fn)
{
	vpninfo->getaddrinfo_override = gai_fn;
}

void openconnect_set_setup_tun_handler(struct openconnect_info *vpninfo,
				       openconnect_setup_tun_vfn setup_tun)
{
	vpninfo->setup_tun = setup_tun;
}

void openconnect_set_reconnected_handler(struct openconnect_info *vpninfo,
				         openconnect_reconnected_vfn reconnected)
{
	vpninfo->reconnected = reconnected;
}

void openconnect_set_stats_handler(struct openconnect_info *vpninfo,
				   openconnect_stats_vfn stats_handler)
{
	vpninfo->stats_handler = stats_handler;
}

/* Set up a traditional OS-based tunnel device, optionally specified in 'ifname'. */
int openconnect_setup_tun_device(struct openconnect_info *vpninfo,
				 const char *vpnc_script, const char *ifname)
{
	intptr_t tun_fd;
	char *legacy_ifname;

	UTF8CHECK(vpnc_script);
	UTF8CHECK(ifname);

	STRDUP(vpninfo->vpnc_script, vpnc_script);
	STRDUP(vpninfo->ifname, ifname);

	prepare_script_env(vpninfo);

	/* XX: vpninfo->ifname will only be non-NULL here if set by the -i option,
	   which only works on some platforms (see os_setup_tun implementations) */
	legacy_ifname = vpninfo->ifname ? openconnect_utf8_to_legacy(vpninfo, vpninfo->ifname) : NULL;
	script_setenv(vpninfo, "TUNDEV", legacy_ifname, 0, 0);
	if (legacy_ifname != vpninfo->ifname)
		free(legacy_ifname);

	script_config_tun(vpninfo, "pre-init");

	tun_fd = os_setup_tun(vpninfo);
	if (tun_fd < 0)
		return tun_fd;


	/* XX: os_setup_tun has set (or even changed) ifname */
	legacy_ifname = openconnect_utf8_to_legacy(vpninfo, vpninfo->ifname);
	script_setenv(vpninfo, "TUNDEV", legacy_ifname, 0, 0);
	if (legacy_ifname != vpninfo->ifname)
		free(legacy_ifname);

	script_config_tun(vpninfo, "connect");

	return openconnect_setup_tun_fd(vpninfo, tun_fd);
}

const char *openconnect_get_dtls_cipher(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_state < DTLS_CONNECTED || !vpninfo->dtls_ssl) {
		gnutls_free(vpninfo->dtls_cipher_desc);
		vpninfo->dtls_cipher_desc = NULL;
		return NULL;
	}
	/* in DTLS rehandshakes don't switch the ciphersuite as only
	 * one is enabled. */
	if (vpninfo->dtls_cipher_desc == NULL) {
		vpninfo->dtls_cipher_desc = get_gnutls_cipher(vpninfo->dtls_ssl);
	}
	return vpninfo->dtls_cipher_desc;
}

int openconnect_check_peer_cert_hash(struct openconnect_info *vpninfo,
				     const char *old_hash)
{
	char *fingerprint = NULL;
	const unsigned min_match_len = 4;
	unsigned old_len, fingerprint_len;
	int case_sensitive = 0;
	int ret = 0;

	if (strchr(old_hash, ':')) {
		/* These are hashes of the public key not the full cert. */
		if (strncmp(old_hash, "sha1:", 5) == 0) {
			old_hash += 5;
			fingerprint = openconnect_bin2hex(NULL, vpninfo->peer_cert_sha1_raw, sizeof(vpninfo->peer_cert_sha1_raw));
		} else if (strncmp(old_hash, "sha256:", 7) == 0) {
			old_hash += 7;
			fingerprint = openconnect_bin2hex(NULL, vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
		} else if (strncmp(old_hash, "pin-sha256:", 11) == 0) {
			old_hash += 11;
			fingerprint = openconnect_bin2base64(NULL, vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
			case_sensitive = 1;
		} else {
			vpn_progress(vpninfo, PRG_ERR, _("Unknown certificate hash: %s.\n"), old_hash);
			return -EIO;
		}
	} else {
		/* Not the same as the sha1: case above, because this hashes the full cert */
		unsigned char *cert;
		int len;
		unsigned char sha1_bin[SHA1_SIZE];

		len = openconnect_get_peer_cert_DER(vpninfo, &cert);
		if (len < 0)
			return len;

		if (openconnect_sha1(sha1_bin, cert, len)) {
			free(cert);
			return -EIO;
		}

		free(cert);
		fingerprint = openconnect_bin2hex(NULL, sha1_bin, sizeof(sha1_bin));
	}

	if (!fingerprint)
		return -EIO;

	old_len = strlen(old_hash);
	fingerprint_len = strlen(fingerprint);

	if (old_len > fingerprint_len)
		ret = 1;
	else if (case_sensitive ? strncmp(old_hash, fingerprint, old_len) :
		 strncasecmp(old_hash, fingerprint, old_len))
		ret = 1;
	else if (old_len < min_match_len) {
		vpn_progress(vpninfo, PRG_ERR, _("The size of the provided fingerprint is less than the minimum required (%u).\n"), min_match_len);
		ret = 1;
	}

	free(fingerprint);
	return ret;
}

const char *openconnect_get_cstp_cipher(struct openconnect_info *vpninfo)
{
	return vpninfo->cstp_cipher;
}

const char *openconnect_get_peer_cert_hash(struct openconnect_info *vpninfo)
{
	if (vpninfo->peer_cert_hash == NULL)
		vpninfo->peer_cert_hash = openconnect_bin2base64("pin-sha256:", vpninfo->peer_cert_sha256_raw, sizeof(vpninfo->peer_cert_sha256_raw));
	return vpninfo->peer_cert_hash;
}

void nuke_opt_values(struct oc_form_opt *opt)
{
	for (; opt; opt = opt->next) {
		if (opt->type == OC_FORM_OPT_TEXT ||
		    opt->type == OC_FORM_OPT_PASSWORD) {
			free(opt->_value);
			opt->_value = NULL;
		}
	}
}

int process_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form)
{
	int ret, do_sso = 0;
	struct oc_form_opt_select *grp = form->authgroup_opt;
	struct oc_choice *auth_choice;
	struct oc_form_opt *opt;

	if (!vpninfo->process_auth_form) {
		vpn_progress(vpninfo, PRG_ERR, _("No form handler; cannot authenticate.\n"));
		return OC_FORM_RESULT_ERR;
	}
	if (!form->auth_id) {
		vpn_progress(vpninfo, PRG_ERR, _("No form ID. This is a bug in OpenConnect's authentication code.\n"));
		return OC_FORM_RESULT_ERR;
	}

	auth_choice = NULL;
	if (grp && grp->nr_choices) {
		/* Set group selection from authgroup */
		if (vpninfo->authgroup) {
			int i;
			for (i = 0; i < grp->nr_choices; i++)
				if (!strcmp(grp->choices[i]->name, vpninfo->authgroup))
					form->authgroup_selection = i;
		}
		auth_choice = grp->choices[form->authgroup_selection];
	}

	for (opt = form->opts; opt; opt = opt->next) {
		int second_auth = opt->flags & OC_FORM_OPT_SECOND_AUTH;
		opt->flags &= ~OC_FORM_OPT_IGNORE;

		if (opt->type == OC_FORM_OPT_SSO_TOKEN) {
			do_sso = 1;
			continue;
		}

		if (!auth_choice ||
		    (opt->type != OC_FORM_OPT_TEXT && opt->type != OC_FORM_OPT_PASSWORD))
			continue;

		if (auth_choice->noaaa ||
		    (!auth_choice->second_auth && second_auth))
			opt->flags |= OC_FORM_OPT_IGNORE;
		else if (!strcmp(opt->name, "secondary_username") && second_auth) {
			if (auth_choice->secondary_username) {
				free(opt->_value);
				opt->_value = strdup(auth_choice->secondary_username);
			}
			if (!auth_choice->secondary_username_editable)
				opt->flags |= OC_FORM_OPT_IGNORE;
		}
	}

	ret = vpninfo->process_auth_form(vpninfo->cbdata, form);

	if (ret == OC_FORM_RESULT_NEWGROUP &&
	    form->authgroup_opt &&
	    form->authgroup_opt->form._value) {
		free(vpninfo->authgroup);
		vpninfo->authgroup = strdup(form->authgroup_opt->form._value);
	}

	if (ret == OC_FORM_RESULT_CANCELLED || ret < 0)
		nuke_opt_values(form->opts);

	if (do_sso) {
		free(vpninfo->sso_cookie_value);
		free(vpninfo->sso_username);
		vpninfo->sso_cookie_value = NULL;
		vpninfo->sso_username = NULL;

		if (vpninfo->open_webview) {
			ret = vpninfo->open_webview(vpninfo, vpninfo->sso_login, vpninfo->cbdata);
		} else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("No SSO handler\n")); /* XX: print more debugging info */
			ret = -EINVAL;
		}
		if (!ret) {
			for (opt = form->opts; opt; opt = opt->next) {
				if (opt->type == OC_FORM_OPT_SSO_TOKEN) {
					free(opt->_value);
					opt->_value = vpninfo->sso_cookie_value;
					vpninfo->sso_cookie_value = NULL;
				} else if (opt->type == OC_FORM_OPT_SSO_USER) {
					free(opt->_value);
					opt->_value = vpninfo->sso_username;
					vpninfo->sso_username = NULL;
				}
			}
		}
		free(vpninfo->sso_username);
		vpninfo->sso_username = NULL;
		free(vpninfo->sso_cookie_value);
		vpninfo->sso_cookie_value = NULL;
		free(vpninfo->sso_browser_mode);
		vpninfo->sso_browser_mode = NULL;
	}

	return ret;
}

void openconnect_set_webview_callback(struct openconnect_info *vpninfo,
				      openconnect_open_webview_vfn webview_fn)
{
	vpninfo->open_webview = webview_fn;
	vpninfo->try_http_auth = 0;
}

void openconnect_set_external_browser_callback(struct openconnect_info *vpninfo,
					       openconnect_open_webview_vfn browser_fn)
{
	vpninfo->open_ext_browser = browser_fn;
	vpninfo->try_http_auth = 0;
}

int openconnect_webview_load_changed(struct openconnect_info *vpninfo,
				      const struct oc_webview_result *result)
{
	if (!vpninfo || !result)
		return -EINVAL;

	return gpst_sso_detect_done(vpninfo, result);
}

char *openconnect_bin2hex(const char *prefix, const uint8_t *data, unsigned len)
{
	struct oc_text_buf *buf;
	char *p = NULL;

	buf = buf_alloc();
	if (prefix)
		buf_append(buf, "%s", prefix);
	buf_append_hex(buf, data, len);

	if (!buf_error(buf)) {
		p = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);

	return p;
}

char *openconnect_bin2base64(const char *prefix, const uint8_t *data, unsigned len)
{
	struct oc_text_buf *buf;
	char *p = NULL;

	buf = buf_alloc();
	if (prefix)
		buf_append(buf, "%s", prefix);
	buf_append_base64(buf, data, len, 0);

	if (!buf_error(buf)) {
		p = buf->data;
		buf->data = NULL;
	}
	buf_free(buf);

	return p;
}

int check_http_status(const char *buf, int len)
{
	if (len >= 5 && !memcmp(buf, "HTTP/", 5)) {
		const char *eol = memchr(buf, '\r', len) ?: memchr(buf, '\n', len);
		const char *sp1 = memchr(buf, ' ', len);
		const char *sp2 = sp1 ? memchr(sp1+1, ' ', len - (sp1-buf) + 1) : NULL;
		return (sp1 && sp2 && (!eol || sp2<eol)) ? atoi(sp1+1) : 500;
	}
	return -EINVAL;
}

int set_csd_user(struct openconnect_info *vpninfo)
{
	setsid();

	if (vpninfo->uid_csd_given && vpninfo->uid_csd != getuid()) {
		struct passwd pwd, *result;
		char buffer[2049];
		int err;

		if (setgid(vpninfo->gid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set gid %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if (setgroups(1, &vpninfo->gid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set groups to %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if (setuid(vpninfo->uid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set uid %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if ((err = getpwuid_r(vpninfo->uid_csd, &pwd, buffer, sizeof(buffer),
				&result)) || !result) {
			fprintf(stderr, _("Invalid user uid=%ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}
		setenv("HOME", result->pw_dir, 1);
		if (chdir(result->pw_dir)) {
			err = errno;
			fprintf(stderr, _("Failed to change to CSD home directory '%s': %s\n"),
				result->pw_dir, strerror(err));
			return -err;
		}
	}
	return 0;
}
