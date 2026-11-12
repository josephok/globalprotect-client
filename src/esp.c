/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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

#include <config.h>

#include "openconnect-internal.h"

#include <unistd.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int print_esp_keys(struct openconnect_info *vpninfo, const char *name, struct esp *esp)
{
	int i;
	const char *enctype, *mactype;
	char enckey[256], mackey[256];

	switch (vpninfo->esp_enc) {
	case ENC_AES_128_CBC:
		enctype = "AES-128-CBC (RFC3602)";
		break;
	case ENC_AES_256_CBC:
		enctype = "AES-256-CBC (RFC3602)";
		break;
	default:
		return -EINVAL;
	}
	switch (vpninfo->esp_hmac) {
	case HMAC_MD5:
		mactype = "HMAC-MD5-96 (RFC2403)";
		break;
	case HMAC_SHA1:
		mactype = "HMAC-SHA-1-96 (RFC2404)";
		break;
	case HMAC_SHA256:
		mactype = "HMAC-SHA-256-128 (RFC4868)";
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < vpninfo->enc_key_len; i++)
		sprintf(enckey + (2 * i), "%02x", esp->enc_key[i]);
	for (i = 0; i < vpninfo->hmac_key_len; i++)
		sprintf(mackey + (2 * i), "%02x", esp->hmac_key[i]);

	vpn_progress(vpninfo, PRG_TRACE,
		     _("Parameters for %s ESP: SPI 0x%08x\n"),
		     name, (unsigned)ntohl(esp->spi));
	vpn_progress(vpninfo, PRG_TRACE,
		     _("ESP encryption type %s key 0x%s\n"),
		     enctype, enckey);
	vpn_progress(vpninfo, PRG_TRACE,
		     _("ESP authentication type %s key 0x%s\n"),
		     mactype, mackey);
	return 0;
}

int esp_setup(struct openconnect_info *vpninfo)
{
	if (vpninfo->dtls_state == DTLS_DISABLED ||
	    vpninfo->dtls_state == DTLS_NOSECRET)
		return -EINVAL;

	/* XX: set ESP DPD interval if not already set */
	if (!vpninfo->dtls_times.dpd) {
		if (vpninfo->esp_ssl_fallback)
			vpninfo->dtls_times.dpd = vpninfo->esp_ssl_fallback;
		else
			vpninfo->dtls_times.dpd = vpninfo->dtls_attempt_period;
	}
	
	print_esp_keys(vpninfo, _("incoming"), &vpninfo->esp_in[vpninfo->current_esp_in]);
	print_esp_keys(vpninfo, _("outgoing"), &vpninfo->esp_out);

	vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes\n"));
	gpst_esp_send_probes(vpninfo);

	return 0;
}

int construct_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, uint8_t next_hdr)
{
	const int blksize = 16;
	int i, padlen, ret;

	if (!next_hdr) {
		if ((pkt->data[0] & 0xf0) == 0x60) /* iph->ip_v */
			next_hdr = IPPROTO_IPV6;
		else
			next_hdr = IPPROTO_IPIP;
	}

	/* This gets much more fun if the IV is variable-length */
	pkt->esp.spi = vpninfo->esp_out.spi;
	pkt->esp.seq = htonl(vpninfo->esp_out.seq++);

	padlen = blksize - 1 - ((pkt->len + 1) % blksize);
	for (i=0; i<padlen; i++)
		pkt->data[pkt->len + i] = i + 1;
	pkt->data[pkt->len + padlen] = padlen;
	pkt->data[pkt->len + padlen + 1] = next_hdr;

	memcpy(pkt->esp.iv, vpninfo->esp_out.iv, sizeof(pkt->esp.iv));

	ret = encrypt_esp_packet(vpninfo, pkt, pkt->len + padlen + 2);
	if (ret)
		return ret;

	return sizeof(pkt->esp) + pkt->len + padlen + 2 + vpninfo->hmac_out_len;
}

int esp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	if (check_auth_expiration(vpninfo, timeout))
		return -EACCES;

	struct esp *esp = &vpninfo->esp_in[vpninfo->current_esp_in];
	struct esp *old_esp = &vpninfo->esp_in[vpninfo->current_esp_in ^ 1];
	struct pkt *this;
	int work_done = 0;
	int ret;

	/* Some servers send us packets that are larger than negotiated
	   MTU, or lack the ability to negotiate MTU (see gpst.c). We
	   reserve some extra space to handle that */
	int receive_mtu = MAX(2048, vpninfo->ip_info.mtu + 256);

	while (readable && vpninfo->dtls_fd >= 0) {
		int len = receive_mtu + vpninfo->pkt_trailer;
		int i;
		struct pkt *pkt;

		if (!vpninfo->dtls_pkt) {
			vpninfo->dtls_pkt = alloc_pkt(vpninfo, len);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}
		pkt = vpninfo->dtls_pkt;
		len = recv(vpninfo->dtls_fd, (void *)&pkt->esp, len + sizeof(pkt->esp), 0);
		if (!len)
			break;
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			vpn_progress(vpninfo, PRG_ERR,
				     _("ESP receive error: %s\n"),
				     strerror(errno));
			/* On *real* errors, close the UDP socket and try again later. */
			esp_close(vpninfo);
			return 0;
		}

		work_done = 1;

		/* both supported algos (SHA1 and MD5) have 12-byte MAC lengths (RFC2403 and RFC2404) */
		if (len <= sizeof(pkt->esp) + vpninfo->hmac_out_len) {
			vpn_progress(vpninfo, PRG_INFO,
                   _("ESP packet too short: len=%d esp=%zu hmac=%d\n"),
                   len, sizeof(pkt->esp), vpninfo->hmac_out_len);
			continue;
		}

		len -= sizeof(pkt->esp) + vpninfo->hmac_out_len;
		pkt->len = len;

		if (pkt->esp.spi == esp->spi) {
			if (decrypt_esp_packet(vpninfo, esp, pkt)) {
				vpn_progress(vpninfo, PRG_INFO,
							_("ESP decrypt failed: spi=0x%08x\n"),
							(unsigned)ntohl(esp->spi));
				continue;
			}
  		} else if (pkt->esp.spi == old_esp->spi &&
			   ntohl(pkt->esp.seq) + esp->seq < vpninfo->old_esp_maxseq) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received ESP packet from old SPI 0x%x, seq %u\n"),
				     (unsigned)ntohl(old_esp->spi), (unsigned)ntohl(pkt->esp.seq));
			if (decrypt_esp_packet(vpninfo, old_esp, pkt))
				continue;
		} else {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received ESP packet with invalid SPI 0x%08x\n"),
				     (unsigned)ntohl(pkt->esp.spi));
			continue;
		}

		/* Possible values of the Next Header field are:
		   0x04: IP[v4]-in-IP
		   0x29: IPv6 encapsulation */
		if (pkt->data[len - 1] == 0x04)
			vpn_progress(vpninfo, PRG_TRACE, _("Received ESP Legacy IP packet of %d bytes\n"),
				     len);
		else if (pkt->data[len - 1] == 0x29)
			vpn_progress(vpninfo, PRG_TRACE, _("Received ESP IPv6 packet of %d bytes\n"),
				     len);
		else {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Received ESP packet of %d bytes with unrecognised payload type %02x\n"),
				     len, pkt->data[len-1]);
			continue;
		}

		if (len <= 2 + pkt->data[len - 2]) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid padding length %02x in ESP\n"),
				     pkt->data[len - 2]);
			continue;
		}
		pkt->len = len - 2 - pkt->data[len - 2];
		for (i = 0 ; i < pkt->data[len - 2]; i++) {
			if (pkt->data[pkt->len + i] != i + 1)
				break; /* We can't just 'continue' here because it
					* would only break out of this 'for' loop */
		}
		if (i != pkt->data[len - 2]) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Invalid padding bytes in ESP\n"));
			continue; /* We can here, though */
		}
		vpninfo->dtls_times.last_rx = time(NULL);

		if (gpst_esp_catch_probe(vpninfo, pkt)) {
			if (vpninfo->dtls_state == DTLS_SLEEPING) {
				vpn_progress(vpninfo, PRG_INFO,
					     _("ESP session established with server\n"));
				vpninfo->dtls_state = DTLS_CONNECTED;
			}
			continue;
		}
		queue_packet(&vpninfo->incoming_queue, pkt);
		vpninfo->dtls_pkt = NULL;
	}

	if (vpninfo->dtls_need_reconnect) {
	need_reconnect:
		esp_close(vpninfo);
	}

	if (vpninfo->dtls_state == DTLS_SLEEPING) {
		time_t now = time(NULL);

		/* Send 5 probes a second apart, then give up until the next attempt */
		if (vpninfo->udp_probes_sent <= 5 &&
		    ka_check_deadline(timeout, now, vpninfo->dtls_times.last_tx + 1)) {
			/* Send repeat probe */
			vpninfo->udp_probes_sent++;
		} else if (vpninfo->dtls_need_reconnect ||
			   ka_check_deadline(timeout, now, vpninfo->new_dtls_started +
					     vpninfo->dtls_attempt_period)) {
			/* New attempt */
			vpninfo->dtls_need_reconnect = 0;
			vpninfo->udp_probes_sent = 1;
			vpninfo->new_dtls_started = now;
			if (*timeout > 1000)
				*timeout = 1000;
		} else {
			return work_done;
		}

		vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes\n"));
		gpst_esp_send_probes(vpninfo);

		vpninfo->dtls_times.last_tx = now;
	}

	if (vpninfo->dtls_state != DTLS_ESTABLISHED)
		return 0;

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY:
		vpn_progress(vpninfo, PRG_ERR, _("Rekey not implemented for ESP\n"));
		break;

	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("ESP detected dead peer\n"));
		goto need_reconnect;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send ESP probes for DPD\n"));
		vpninfo->udp_probes_sent++;
		gpst_esp_send_probes(vpninfo);
		work_done = 1;
		break;

	case KA_KEEPALIVE:
		vpn_progress(vpninfo, PRG_ERR, _("Keepalive not implemented for ESP\n"));
		break;

	case KA_NONE:
		break;
	}
	while (1) {
		int len;
		int ip_version;

		if (vpninfo->deflate_pkt) {
			this = vpninfo->deflate_pkt;
			len = this->len;
			ip_version = this->data[0] >> 4;
		} else {
			this = dequeue_packet(&vpninfo->outgoing_queue);
			if (!this)
				break;
			ip_version = this->data[0] >> 4;

			/* XX: Must precede in-place encryption of the packet, because
			   IP header fields (version and TOS) are garbled afterward.
			   If TOS optname is set, we want to copy the TOS/TCLASS header
			   to the outer UDP packet */
			if (vpninfo->dtls_tos_optname)
				udp_tos_update(vpninfo, this);

			len = construct_esp_packet(vpninfo, this, 0);
			if (len < 0) {
				/* Should we disable ESP? */
				free_pkt(vpninfo, this);
				work_done = 1;
				continue;
			}
		}

		ret = send(vpninfo->dtls_fd, (void *)&this->esp, len, 0);
		if (ret < 0) {
			/* Not that this is likely to happen with UDP, but... */
			if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
				vpninfo->deflate_pkt = this;
				this->len = len;
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Requeueing failed ESP send: %s\n"),
					     strerror(errno));
				monitor_write_fd(vpninfo, dtls);
				return work_done;
			} else {
				/* A real error in sending. Fall back to TCP? */
				vpn_progress(vpninfo, PRG_ERR,
					_("Failed to send ESP packet: %s\n"),
					strerror(errno));
			}
		} else {
			vpninfo->dtls_times.last_tx = time(NULL);

			vpn_progress(vpninfo, PRG_TRACE, _("Sent ESP IPv%d packet of %d bytes\n"),
				     ip_version, len);
		}
		if (this == vpninfo->deflate_pkt) {
			unmonitor_write_fd(vpninfo, dtls);
			vpninfo->deflate_pkt = NULL;
		}
		free_pkt(vpninfo, this);
		work_done = 1;
	}

	return work_done;
}

void esp_close(struct openconnect_info *vpninfo)
{
	/* We close and reopen the socket in case we roamed and our
	   local IP address has changed. */
	if (vpninfo->dtls_fd >= 0) {
		unmonitor_fd(vpninfo, dtls);
		closesocket(vpninfo->dtls_fd);
		vpninfo->dtls_fd = -1;
	}
	if (vpninfo->dtls_state > DTLS_DISABLED)
		vpninfo->dtls_state = DTLS_SLEEPING;
	if (vpninfo->deflate_pkt) {
		free_pkt(vpninfo, vpninfo->deflate_pkt);
		vpninfo->deflate_pkt = NULL;
	}
}

void esp_shutdown(struct openconnect_info *vpninfo)
{
	destroy_esp_ciphers(&vpninfo->esp_in[0]);
	destroy_esp_ciphers(&vpninfo->esp_in[1]);
	destroy_esp_ciphers(&vpninfo->esp_out);
	esp_close(vpninfo);
	if (vpninfo->dtls_state != DTLS_DISABLED)
		vpninfo->dtls_state = DTLS_NOSECRET;
}

int openconnect_setup_esp_keys(struct openconnect_info *vpninfo, int new_keys)
{
	struct esp *esp_in;
	int ret;

	if (vpninfo->dtls_state == DTLS_DISABLED)
		return -EOPNOTSUPP;
	if (!vpninfo->dtls_addr)
		return -EINVAL;

	if (vpninfo->esp_hmac == HMAC_SHA256)
		vpninfo->hmac_out_len = 16;
	else /* MD5 and SHA1 */
		vpninfo->hmac_out_len = 12;

	if (new_keys) {
		vpninfo->old_esp_maxseq = vpninfo->esp_in[vpninfo->current_esp_in].seq + 32;
		vpninfo->current_esp_in ^= 1;
	}

	esp_in = &vpninfo->esp_in[vpninfo->current_esp_in];

	if (new_keys) {
		if (openconnect_random(&esp_in->spi, sizeof(esp_in->spi)) ||
		    openconnect_random((void *)&esp_in->enc_key, vpninfo->enc_key_len) ||
		    openconnect_random((void *)&esp_in->hmac_key, vpninfo->hmac_key_len)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to generate random keys for ESP\n"));
			return -EIO;
		}
	}

	if (openconnect_random(vpninfo->esp_out.iv, sizeof(vpninfo->esp_out.iv))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to generate initial IV for ESP\n"));
		return -EIO;
	}

	/* This is the minimum; some implementations may increase it */
	vpninfo->pkt_trailer = MAX_ESP_PAD + MAX_IV_SIZE + MAX_HMAC_SIZE;

	vpninfo->esp_out.seq = vpninfo->esp_out.seq_backlog = 0;
	esp_in->seq = esp_in->seq_backlog = 0;

	ret = init_esp_ciphers(vpninfo, &vpninfo->esp_out, esp_in);
	if (ret)
		return ret;

	if (vpninfo->dtls_state == DTLS_NOSECRET)
		vpninfo->dtls_state = DTLS_SECRET;

	return 0;
}

int udp_tos_update(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	int tos;

	switch (pkt->data[0] >> 4) {
	case 4:
		tos = pkt->data[1];
		break;
	case 6:
		tos = (load_be16(pkt->data) >> 4) & 0xff;
		break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet (len %d) received: %02x %02x %02x %02x...\n"),
			     pkt->len, pkt->data[0], pkt->data[1], pkt->data[2], pkt->data[3]);
		return -EINVAL;
	}

	if (tos != vpninfo->dtls_tos_current) {
		vpn_progress(vpninfo, PRG_DEBUG, _("TOS this: %d, TOS last: %d\n"),
			     tos, vpninfo->dtls_tos_current);
		if (setsockopt(vpninfo->dtls_fd, vpninfo->dtls_tos_proto,
			       vpninfo->dtls_tos_optname, (void *)&tos, sizeof(tos)))
			vpn_perror(vpninfo, _("UDP setsockopt"));
		else
			vpninfo->dtls_tos_current = tos;
	}
	return 0;
}
