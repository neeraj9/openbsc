/* Osmocom Authentication Protocol client */

/* (C) 2014,2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Authors: Jakob Erlbeck, Neels Hofmeyr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/ipa_client.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>

extern void *tall_bsc_ctx;

static void start_test_procedure(struct ipa_client *ipac);

static void ipa_client_send_ping(struct ipa_client *ipac)
{
	struct msgb *msg = ipa_client_msgb_alloc();

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;
	ipa_msg_push_header(msg, IPAC_PROTO_IPACCESS);
	ipa_client_conn_send(ipac->link, msg);
}

static int ipa_client_connect(struct ipa_client *ipac)
{
	int rc;

	if (ipac->is_connected)
		return 0;

	if (osmo_timer_pending(&ipac->connect_timer)) {
		LOGP(DLINP, LOGL_DEBUG,
		     "IPA connect: connect timer already running\n");
		osmo_timer_del(&ipac->connect_timer);
	}

	if (osmo_timer_pending(&ipac->ping_timer)) {
		LOGP(DLINP, LOGL_DEBUG,
		     "IPA connect: ping timer already running\n");
		osmo_timer_del(&ipac->ping_timer);
	}

	if (ipa_client_conn_clear_queue(ipac->link) > 0)
		LOGP(DLINP, LOGL_DEBUG, "IPA connect: discarded stored messages\n");

	rc = ipa_client_conn_open(ipac->link);

	if (rc >= 0) {
		LOGP(DGPRS, LOGL_INFO, "IPA connecting to %s:%d\n",
		     ipac->link->addr, ipac->link->port);
		return 0;
	}

	LOGP(DGPRS, LOGL_INFO, "IPA failed to connect to %s:%d: %s\n",
	     ipac->link->addr, ipac->link->port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&ipac->connect_timer, IPA_CLIENT_RECONNECT_INTERVAL, 0);

	LOGP(DGPRS, LOGL_INFO, "Scheduled timer to retry IPA connect to %s:%d\n",
	     ipac->link->addr, ipac->link->port);

	return 0;
}

static void connect_timer_cb(void *ipac_)
{
	struct ipa_client *ipac = ipac_;

	if (ipac->is_connected)
		return;

	ipa_client_connect(ipac);
}

static void ipa_client_updown_cb(struct ipa_client_conn *link, int up)
{
	struct ipa_client *ipac = link->data;

	LOGP(DGPRS, LOGL_INFO, "IPA link to %s:%d %s\n",
	     link->addr, link->port, up ? "UP" : "DOWN");

	ipac->is_connected = up;

	if (up) {
		start_test_procedure(ipac);

		osmo_timer_del(&ipac->connect_timer);
	} else {
		osmo_timer_del(&ipac->ping_timer);

		osmo_timer_schedule(&ipac->connect_timer,
				    IPA_CLIENT_RECONNECT_INTERVAL, 0);
	}

	if (ipac->updown_cb != NULL)
	      ipac->updown_cb(ipac, up);
}

static int ipa_client_read_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct ipa_client *ipac = (struct ipa_client *)link->data;
	int rc;
	static struct ipaccess_unit ipa_dev = {
		.unit_name = "SGSN"
	};

	msg->l2h = &hh->data[0];

	rc = ipaccess_bts_handle_ccm(link, &ipa_dev, msg);

	if (rc < 0) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "received an invalid IPA/CCM message from %s:%d\n",
		     link->addr, link->port);
		/* Link has been closed */
		ipac->is_connected = 0;
		msgb_free(msg);
		return -1;
	}

	if (rc == 1) {
		uint8_t msg_type = *(msg->l2h);
		/* CCM message */
		if (msg_type == IPAC_MSGT_PONG) {
			LOGP(DGPRS, LOGL_DEBUG, "IPA receiving PONG\n");
			ipac->got_ipa_pong = 1;
		}

		msgb_free(msg);
		return 0;
	}

	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;

	msg->l2h = &he->data[0];

	OSMO_ASSERT(ipac->read_cb != NULL);
	ipac->read_cb(ipac, hh->proto, he->proto, msg);

	/* Not freeing msg here, because that must be done by the read_cb. */
	return 0;

invalid:
	LOGP(DGPRS, LOGL_NOTICE,
	     "received an invalid IPA message from %s:%d, size = %d\n",
	     link->addr, link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;
}

static void ping_timer_cb(void *ipac_)
{
	struct ipa_client *ipac = ipac_;

	LOGP(DGPRS, LOGL_INFO, "IPA ping callback (%s, %s PONG)\n",
	     ipac->is_connected ? "connected" : "not connected",
	     ipac->got_ipa_pong ? "got" : "didn't get");

	if (ipac->got_ipa_pong) {
		start_test_procedure(ipac);
		return;
	}

	LOGP(DGPRS, LOGL_NOTICE, "IPA ping timed out, reconnecting\n");
	ipa_client_conn_close(ipac->link);
	ipac->is_connected = 0;

	ipa_client_connect(ipac);
}

static void start_test_procedure(struct ipa_client *ipac)
{
	ipac->ping_timer.data = ipac;
	ipac->ping_timer.cb = &ping_timer_cb;

	ipac->got_ipa_pong = 0;
	osmo_timer_schedule(&ipac->ping_timer, IPA_CLIENT_PING_INTERVAL, 0);
	LOGP(DGPRS, LOGL_DEBUG, "IPA sending PING\n");
	ipa_client_send_ping(ipac);
}

struct ipa_client *ipa_client_create(const char *ip_addr,
				     unsigned int tcp_port,
				     ipa_client_updown_cb_t updown_cb,
				     ipa_client_read_cb_t read_cb,
				     void *data)
{
	struct ipa_client *ipac;
	int rc;

	ipac = talloc_zero(tall_bsc_ctx, struct ipa_client);
	OSMO_ASSERT(ipac);

	ipac->updown_cb = updown_cb;
	ipac->read_cb = read_cb;
	ipac->data = data;

	ipac->link = ipa_client_conn_create(ipac,
					    /* no e1inp */ NULL,
					    0,
					    ip_addr, tcp_port,
					    ipa_client_updown_cb,
					    ipa_client_read_cb,
					    /* default write_cb */ NULL,
					    ipac);
	if (!ipac->link)
		goto failed;

	ipac->connect_timer.data = ipac;
	ipac->connect_timer.cb = &connect_timer_cb;

	rc = ipa_client_connect(ipac);

	if (rc < 0)
		goto failed;

	ipac->read_cb = read_cb;

	return ipac;

failed:
	ipa_client_destroy(ipac);
	return NULL;
}

void ipa_client_destroy(struct ipa_client *ipac)
{
	osmo_timer_del(&ipac->connect_timer);
	osmo_timer_del(&ipac->ping_timer);

	if (ipac->link) {
		ipa_client_conn_close(ipac->link);
		ipa_client_conn_destroy(ipac->link);
		ipac->link = NULL;
	}
	talloc_free(ipac);
}

int ipa_client_send(struct ipa_client *ipac, uint8_t proto, uint8_t proto_ext,
		    struct msgb *msg)
{
	OSMO_ASSERT(msg);

	if (!ipac) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	if (!ipac->is_connected) {
		msgb_free(msg);
		return -EAGAIN;
	}

	// l2h is not sent over the wire, but for the test suite it makes sense
	// to make l2h point at the IPA message payload.
	unsigned char *l2h = msg->data;

	ipa_prepend_header_ext(msg, proto);
	ipa_msg_push_header(msg, proto_ext);

	msg->l2h = l2h;

	ipa_client_conn_send(ipac->link, msg);

	return 0;
}

struct msgb *ipa_client_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}


