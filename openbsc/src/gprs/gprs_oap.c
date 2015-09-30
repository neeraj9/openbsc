#include <osmocom/crypt/auth.h>
#include <osmocom/abis/ipa.h>

#include <openbsc/gprs_oap.h>
#include <openbsc/sgsn.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/gprs_ipa_client.h>
#include <openbsc/gprs_oap_messages.h>

#include <openbsc/gprs_oap.h>

int gprs_oap_init(struct gprs_oap_config *config, struct gprs_oap_state *state)
{
	OSMO_ASSERT(state->state == oap_uninitialized);

	if ((config->sgsn_id == 0) || (config->shared_secret_present == 0))
		goto disable;

	state->sgsn_id = config->sgsn_id;
	memcpy(state->shared_secret, config->shared_secret, sizeof(state->shared_secret));
	state->state = oap_initialized;
	return 0;

disable:
	state->state = oap_disabled;
	return 0;
}


int gprs_oap_evaluate_challenge(struct gprs_oap_state *state,
				const uint8_t *rx_random,
				const uint8_t *rx_autn,
				uint8_t *tx_sres,
				uint8_t *tx_kc)
{
	switch(state->state) {
	case oap_uninitialized:
	case oap_disabled:
		return -1;
	default:
		break;
	}

	struct osmo_auth_vector vec;

	struct osmo_sub_auth_data auth = {
		.type		= OSMO_AUTH_TYPE_UMTS,
		.algo		= OSMO_AUTH_ALG_MILENAGE,
	};

	OSMO_ASSERT(sizeof(auth.u.umts.opc) == sizeof(state->shared_secret));
	OSMO_ASSERT(sizeof(auth.u.umts.k) == sizeof(state->shared_secret));

	memcpy(auth.u.umts.opc, state->shared_secret, sizeof(auth.u.umts.opc));
	memcpy(auth.u.umts.k, state->shared_secret, sizeof(auth.u.umts.k));
	memset(auth.u.umts.amf, 0, 2);
	auth.u.umts.sqn = 42; // TODO?

	memset(&vec, 0, sizeof(vec));
	osmo_auth_gen_vec(&vec, &auth, rx_random);

	if (vec.res_len != 8) {
		LOGP(DGPRS, LOGL_ERROR, "OAP: generated res length is wrong: %d\n",
		     vec.res_len);
		return -3;
	}

	if (gprs_constant_time_cmp(vec.autn, rx_autn, sizeof(vec.autn)) != 0) {
		LOGP(DGPRS, LOGL_ERROR, "OAP: AUTN mismatch!\n");
		LOGP(DGPRS, LOGL_INFO, "OAP: AUTN from server: %s\n",
		     osmo_hexdump_nospc(rx_autn, sizeof(vec.autn)));
		LOGP(DGPRS, LOGL_INFO, "OAP: AUTN expected:    %s\n",
		     osmo_hexdump_nospc(vec.autn, sizeof(vec.autn)));
		return -2;
	}

	memcpy(tx_sres, vec.sres, sizeof(vec.sres));
	memcpy(tx_kc, vec.kc, sizeof(vec.kc));
	return 0;
}

int gprs_oap_register(struct gprs_ipa_client *gipac)
{
	struct gprs_oap_state *state = &gipac->oap;

	OSMO_ASSERT(state);
	OSMO_ASSERT(state->sgsn_id);

	struct msgb *msg = ipa_client_msgb_alloc();

	struct gprs_oap_message oap_msg = {0};
	oap_msg.message_type = GPRS_OAP_MSGT_REGISTER_REQUEST;
	oap_msg.sgsn_id = state->sgsn_id;

	gprs_oap_encode(msg, &oap_msg);

	state->state = oap_requested_challenge;
	return gprs_ipa_client_send_oap(gipac, msg);
}

int gprs_oap_rx(struct gprs_ipa_client *gipac, struct msgb *msg)
{
	struct gprs_oap_state *state = &gipac->oap;

	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	int rc = 0;

	struct gprs_oap_message oap_msg = {0};

	rc = gprs_oap_decode(data, data_len, &oap_msg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_ERROR,
		     "Decoding OAP message failed with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	switch (oap_msg.message_type) {
	case GPRS_OAP_MSGT_CHALLENGE_REQUEST:
		// reply with challenge result
		if (!(oap_msg.rand_present && oap_msg.autn_present)) {
			LOGP(DGPRS, LOGL_ERROR,
			     "OAP challenge incomplete (rand_present: %d, autn_present: %d)\n",
			     oap_msg.rand_present, oap_msg.autn_present);
			return -1;
		}

		{
			struct gprs_oap_message oap_reply = {0};
			oap_reply.message_type = GPRS_OAP_MSGT_CHALLENGE_RESULT;

			rc = gprs_oap_evaluate_challenge(state,
							 oap_msg.rand,
							 oap_msg.autn,
							 oap_reply.sres,
							 oap_reply.kc);
			if (rc < 0)
				return rc;

			oap_reply.sres_present = 1;
			oap_reply.kc_present = 1;

			struct msgb *oap_reply_msg = ipa_client_msgb_alloc();
			OSMO_ASSERT(oap_reply_msg);

			gprs_oap_encode(oap_reply_msg, &oap_reply);

			state->state = oap_sent_challenge_result;
			state->challenges_count ++;
			gprs_ipa_client_send_oap(gipac, oap_reply_msg);
		}

		break;

	case GPRS_OAP_MSGT_REGISTER_RESULT:
		// successfully registered!
		state->state = oap_registered;
		break;

	case GPRS_OAP_MSGT_REGISTER_ERROR:
		LOGP(DGPRS, LOGL_ERROR,
		     "OAP registration failed, from %s:%d\n",
		     gipac->ipac->link->addr, (int)gipac->ipac->link->port);
		return -1;
		break;

	case GPRS_OAP_MSGT_REGISTER_REQUEST:
	case GPRS_OAP_MSGT_CHALLENGE_RESULT:
		LOGP(DGPRS, LOGL_ERROR,
		     "Received invalid OAP message type for OAP client side: %d\n",
		     (int)oap_msg.message_type);
		return -1;

	default:
		LOGP(DGPRS, LOGL_ERROR,
		     "Unknown OAP message type: %d\n",
		     (int)oap_msg.message_type);
		return -2;
	}

	return 0;
}
