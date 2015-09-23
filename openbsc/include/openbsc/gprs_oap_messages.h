/* Osmocom Authentication Protocol message encoder/decoder */

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
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/gsm_data.h>

/* Some numbers are out of sequence because (so far) they match gprs_gsup_iei.
 */
enum gprs_oap_iei {
	GPRS_OAP_CAUSE_IE			= 0x02,
	GPRS_OAP_RAND_IE			= 0x20,
	GPRS_OAP_SRES_IE			= 0x21,
	GPRS_OAP_KC_IE				= 0x22,
	GPRS_OAP_AUTN_IE			= 0x23,
	GPRS_OAP_SGSN_ID_IE			= 0x30,
};

enum gprs_oap_message_type {
	GPRS_OAP_MSGT_REGISTER_REQUEST	= 0b00000100,
	GPRS_OAP_MSGT_REGISTER_ERROR	= 0b00000101,
	GPRS_OAP_MSGT_REGISTER_RESULT	= 0b00000110,

	GPRS_OAP_MSGT_CHALLENGE_REQUEST	= 0b00001000,
	GPRS_OAP_MSGT_CHALLENGE_ERROR	= 0b00001001,
	GPRS_OAP_MSGT_CHALLENGE_RESULT	= 0b00001010,
};

#define GPRS_OAP_IS_MSGT_REQUEST(msgt) (((msgt) & 0b00000011) == 0b00)
#define GPRS_OAP_IS_MSGT_ERROR(msgt)   (((msgt) & 0b00000011) == 0b01)
#define GPRS_OAP_TO_MSGT_ERROR(msgt)   (((msgt) & 0b11111100) | 0b01)

struct gprs_oap_message {
	enum gprs_oap_message_type	message_type;
	enum gsm48_gmm_cause		cause;
	uint16_t			sgsn_id;
	int				rand_present;
	uint8_t				rand[16];
	int				autn_present;
	uint8_t				autn[16];
	int				sres_present;
	uint8_t				sres[4];
	int				kc_present;
	uint8_t				kc[8];
};

int gprs_oap_decode(const uint8_t *data, size_t data_len,
		     struct gprs_oap_message *oap_msg);
void gprs_oap_encode(struct msgb *msg, const struct gprs_oap_message *oap_msg);

