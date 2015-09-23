/* Specific IPA client for GPRS: Multiplex for GSUP and OAP */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openbsc/gprs_ipa_client.h>
#include <openbsc/ipa_client.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_oap_messages.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/abis/ipa.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>


int gprs_ipa_client_init(struct sgsn_instance *sgi)
{
	const char *addr_str;

	if (!sgi->cfg.ipa_server_addr.sin_addr.s_addr)
		return 0;

	addr_str = inet_ntoa(sgi->cfg.ipa_server_addr.sin_addr);

	sgi->gprs_ipa_client = gprs_ipa_client_create(
		addr_str, sgi->cfg.ipa_server_port);

	if (!sgi->gprs_ipa_client)
		return -1;

	return 1;
}



static void gprs_ipa_client_updown_cb(struct ipa_client *ipac, int up)
{
	struct gprs_ipa_client *gipac = ipac->data;

	if (up && (gipac->oap.sgsn_id != 0)) {
		if (gprs_oap_register(gipac) < 0) {
			/* TODO: fail fatally */
		}
	}
}

static void gprs_ipa_client_read_cb(struct ipa_client *ipac,
				   uint8_t proto,
				   uint8_t proto_ext,
				   struct msgb *msg)
{
	//int rc = -2;
	struct gprs_ipa_client *gipac = ipac->data;

	if (proto != IPAC_PROTO_OSMO)
	      goto invalid;

	switch (proto_ext) {
	case IPAC_PROTO_EXT_GSUP:
		/*rc =*/ gprs_subscr_rx_gsup_message(msg);
		break;

	case IPAC_PROTO_EXT_OAP:
		/*rc =*/ gprs_oap_rx(gipac, msg);
		break;

	default:
		goto invalid;
	}

	/* TODO: error rc? */

	msgb_free(msg);
	return;

invalid:
	LOGP(DGPRS, LOGL_NOTICE,
	     "received an invalid IPA message from %s:%d: proto=%d proto_ext=%d size=%d\n",
	     ipac->link->addr, (int)ipac->link->port,
	     (int)proto, (int)proto_ext,
	     msgb_length(msg));
	msgb_free(msg);

	/* TODO: error rc? */
}

struct gprs_ipa_client *gprs_ipa_client_create(const char *ip_addr,
					       unsigned int tcp_port)
{
	struct gprs_ipa_client *gipac;

	gipac = talloc_zero(tall_bsc_ctx, struct gprs_ipa_client);
	OSMO_ASSERT(gipac);

	gipac->ipac = ipa_client_create(ip_addr,
					tcp_port,
					gprs_ipa_client_updown_cb,
					gprs_ipa_client_read_cb,
					/* data */ NULL);

	OSMO_ASSERT(gipac->ipac);

	if (!gipac->ipac)
		goto failed;

	return gipac;

failed:
	gprs_ipa_client_destroy(gipac);
	return NULL;
}

void gprs_ipa_client_destroy(struct gprs_ipa_client *gipac)
{
	if (!gipac)
		return;

	if (gipac->ipac)
		ipa_client_destroy(gipac->ipac);
	gipac->ipac = NULL;
}

int gprs_ipa_client_send_gsup(struct gprs_ipa_client *gipac, struct msgb *msg)
{
	return ipa_client_send(gipac->ipac, IPAC_PROTO_OSMO, IPAC_PROTO_EXT_GSUP, msg);
}

int gprs_ipa_client_send_oap(struct gprs_ipa_client *gipac, struct msgb *msg)
{
	return ipa_client_send(gipac->ipac, IPAC_PROTO_OSMO, IPAC_PROTO_EXT_OAP, msg);
}

