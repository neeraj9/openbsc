/* GPRS Subscriber Update Protocol message encoder/decoder */

/*
 * (C) 2014 by Sysmocom s.f.m.c. GmbH
 * (C) 2015 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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

#include <openbsc/gprs_oap_messages.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>

#include <stdint.h>


int gprs_oap_decode(const uint8_t *const_data, size_t data_len,
		    struct gprs_oap_message *oap_msg)
{
	int rc;
	uint8_t tag;
	/* the shift/match functions expect non-const pointers, but we'll
	 * either copy the data or cast pointers back to const before returning
	 * them
	 */
	uint8_t *data = (uint8_t *)const_data;
	uint8_t *value;
	size_t value_len;
	static const struct gprs_oap_message empty_oap_message = {0};

	*oap_msg = empty_oap_message;

	/* message type */
	rc = gprs_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	oap_msg->message_type = gprs_decode_big_endian(value, 1);

	/* specific parts */
	while (data_len > 0) {
		enum gprs_oap_iei iei;

		rc = gprs_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case GPRS_OAP_SGSN_ID_IE:
			if (value_len != 2) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type SGSN Id (%d) should be 2 octets, but has %d\n",
				     (int)iei, (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}

			oap_msg->sgsn_id = gprs_decode_big_endian(value, value_len);

			if (oap_msg->sgsn_id == 0) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type SGSN Id (%d): SGSN Id must be nonzero.\n",
				     (int)iei);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			break;

		case GPRS_OAP_AUTN_IE:
			if (value_len != sizeof(oap_msg->autn)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type AUTN (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->autn), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->autn, value, value_len);
			oap_msg->autn_present = value_len;
			break;

		case GPRS_OAP_RAND_IE:
			if (value_len != sizeof(oap_msg->rand)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type RAND (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->rand), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->rand, value, value_len);
			oap_msg->rand_present = value_len;
			break;

		case GPRS_OAP_SRES_IE:
			if (value_len != sizeof(oap_msg->sres)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type SRES (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->sres), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->sres, value, value_len);
			oap_msg->sres_present = value_len;
			break;

		case GPRS_OAP_KC_IE:
			if (value_len != sizeof(oap_msg->kc)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type Kc (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->kc), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->kc, value, value_len);
			oap_msg->kc_present = value_len;
			break;

		case GPRS_OAP_CAUSE_IE:
			if (value_len > 1) {
				LOGP(DGPRS, LOGL_ERROR,
				     "OAP cause may not exceed one octet, is %d", (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			oap_msg->cause = *value;
			break;

		default:
			LOGP(DGPRS, LOGL_NOTICE,
			     "OAP IE type %d unknown\n", iei);
			continue;
		}
	}

	return 0;
}

void gprs_oap_encode(struct msgb *msg, const struct gprs_oap_message *oap_msg)
{
	uint8_t u8;

	/* generic part */
	OSMO_ASSERT(oap_msg->message_type);
	msgb_v_put(msg, oap_msg->message_type);

	/* specific parts */
	if ((u8 = oap_msg->cause))
		msgb_tlv_put(msg, GPRS_OAP_CAUSE_IE, sizeof(u8), &u8);

	if (oap_msg->sgsn_id > 0)
		msgb_tlv_put(msg, GPRS_OAP_SGSN_ID_IE, sizeof(oap_msg->sgsn_id),
			     gprs_encode_big_endian(oap_msg->sgsn_id, sizeof(oap_msg->sgsn_id)));

	if (oap_msg->autn_present)
		msgb_tlv_put(msg, GPRS_OAP_AUTN_IE, sizeof(oap_msg->autn), oap_msg->autn);

	if (oap_msg->rand_present)
		msgb_tlv_put(msg, GPRS_OAP_RAND_IE, sizeof(oap_msg->rand), oap_msg->rand);

	if (oap_msg->sres_present)
		msgb_tlv_put(msg, GPRS_OAP_SRES_IE, sizeof(oap_msg->sres), oap_msg->sres);

	if (oap_msg->kc_present)
		msgb_tlv_put(msg, GPRS_OAP_KC_IE, sizeof(oap_msg->kc), oap_msg->kc);
}


