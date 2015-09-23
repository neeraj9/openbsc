/* Specific IPA client for GPRS: Multiplex for GSUP and OAP */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck, Neels Hofmeyr
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
#pragma once

#include <stdint.h>

#include <osmocom/core/timer.h>

#include <openbsc/ipa_client.h>
#include <openbsc/gprs_oap.h>

struct sgsn_instance;

int gprs_ipa_client_init(struct sgsn_instance *sgsn_inst);


struct gprs_ipa_client {
	struct ipa_client *ipac;

	// sgsn <-> map proxy registration state
	struct gprs_oap_state oap;

	// TODO registration timeout?
};

struct gprs_ipa_client *gprs_ipa_client_create(const char *ip_addr,
					       unsigned int tcp_port);

int gprs_ipa_client_send_gsup(struct gprs_ipa_client *gipac, struct msgb *msg);
int gprs_ipa_client_send_oap(struct gprs_ipa_client *gipac, struct msgb *msg);

void gprs_ipa_client_destroy(struct gprs_ipa_client *gipac);


