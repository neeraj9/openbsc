/* Osmocom Authentication Protocol API */

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

#pragma once

#include <stdint.h>

struct sgsn_instance;
struct gprs_ipa_client;
struct msgb;

/* This is the config part for vty. It is essentially copied in gprs_oap_state,
 * where values are copied over once the config is considered valid. The shared
 * secret is converted from hex string to octet buffer, the sgsn_id is simply
 * copied. Is this separation really necessary? */
struct gprs_oap_config {
	uint16_t sgsn_id;
	const char *shared_secret;
};

struct gprs_oap_state {
	enum {
		oap_uninitialized = 0,	// just allocated.
		oap_disabled,		// disabled by config.
		oap_config_error, // <-- TODO really?
		oap_initialized,	// shared_secret valid.
		oap_requested_challenge,
		oap_sent_challenge_result,
		oap_registered
	} state;
	uint16_t sgsn_id;
	uint8_t shared_secret[16];
	int challenges_count;
};

int gprs_oap_init(struct gprs_oap_config *config, struct gprs_oap_state *state);

int gprs_oap_evaluate_challenge(struct gprs_oap_state *state,
				const uint8_t *rx_random,
				const uint8_t *rx_autn,
				uint8_t *tx_sres,
				uint8_t *tx_kc);

int gprs_oap_register(struct gprs_ipa_client *gipac);
int gprs_oap_rx(struct gprs_ipa_client *gipac, struct msgb *msg);

