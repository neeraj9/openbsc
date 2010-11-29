
/* BSC Multiplexer/NAT Utilities */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/vty.h>

#include <osmocore/linuxlist.h>
#include <osmocore/talloc.h>
#include <osmocore/gsm0808.h>

#include <osmocore/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static const struct rate_ctr_desc bsc_cfg_ctr_description[] = {
	[BCFG_CTR_SCCP_CONN]     = { "sccp.conn",      "SCCP Connections         "},
	[BCFG_CTR_SCCP_CALLS]    = { "sccp.calls",     "SCCP Assignment Commands "},
	[BCFG_CTR_NET_RECONN]    = { "net.reconnects", "Network reconnects       "},
	[BCFG_CTR_DROPPED_SCCP]  = { "dropped.sccp",   "Dropped SCCP connections."},
	[BCFG_CTR_DROPPED_CALLS] = { "dropped.calls",  "Dropped active calls.    "},
	[BCFG_CTR_REJECTED_CR]   = { "rejected.cr",    "Rejected CR due filter   "},
	[BCFG_CTR_REJECTED_MSG]  = { "rejected.msg",   "Rejected MSG due filter  "},
	[BCFG_CTR_ILL_PACKET]    = { "rejected.ill",   "Rejected due parse error "},
	[BCFG_CTR_CON_TYPE_LU]   = { "conn.lu",        "Conn Location Update     "},
	[BCFG_CTR_CON_CMSERV_RQ] = { "conn.rq",        "Conn CM Service Req      "},
	[BCFG_CTR_CON_PAG_RESP]  = { "conn.pag",       "Conn Paging Response     "},
	[BCFG_CTR_CON_SSA]       = { "conn.ssa",       "Conn USSD                "},
	[BCFG_CTR_CON_OTHER]     = { "conn.other",     "Conn Other               "},
};

static const struct rate_ctr_group_desc bsc_cfg_ctrg_desc = {
	.group_name_prefix = "nat.bsc",
	.group_description = "NAT BSC Statistics",
	.num_ctr = ARRAY_SIZE(bsc_cfg_ctr_description),
	.ctr_desc = bsc_cfg_ctr_description,
};

static const struct rate_ctr_desc acc_list_ctr_description[] = {
	[ACC_LIST_BSC_FILTER]	= { "access-list.bsc-filter", "Rejected by rule for BSC"},
	[ACC_LIST_NAT_FILTER]	= { "access-list.nat-filter", "Rejected by rule for NAT"},
};

static const struct rate_ctr_group_desc bsc_cfg_acc_list_desc = {
	.group_name_prefix = "nat.filter",
	.group_description = "NAT Access-List Statistics",
	.num_ctr = ARRAY_SIZE(acc_list_ctr_description),
	.ctr_desc = acc_list_ctr_description,
};

struct bsc_nat *bsc_nat_alloc(void)
{
	struct bsc_nat *nat = talloc_zero(tall_bsc_ctx, struct bsc_nat);
	if (!nat)
		return NULL;

	INIT_LLIST_HEAD(&nat->sccp_connections);
	INIT_LLIST_HEAD(&nat->bsc_connections);
	INIT_LLIST_HEAD(&nat->bsc_configs);
	INIT_LLIST_HEAD(&nat->access_lists);

	nat->stats.sccp.conn = counter_alloc("nat.sccp.conn");
	nat->stats.sccp.calls = counter_alloc("nat.sccp.calls");
	nat->stats.bsc.reconn = counter_alloc("nat.bsc.conn");
	nat->stats.bsc.auth_fail = counter_alloc("nat.bsc.auth_fail");
	nat->stats.msc.reconn = counter_alloc("nat.msc.conn");
	nat->stats.ussd.reconn = counter_alloc("nat.ussd.conn");
	nat->msc_ip = talloc_strdup(nat, "127.0.0.1");
	nat->msc_port = 5000;
	nat->auth_timeout = 2;
	nat->ping_timeout = 20;
	nat->pong_timeout = 5;
	return nat;
}

void bsc_nat_set_msc_ip(struct bsc_nat *nat, const char *ip)
{
	bsc_replace_string(nat, &nat->msc_ip, ip);
}

struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	con->nat = nat;
	write_queue_init(&con->write_queue, 100);
	return con;
}

struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token)
{
	struct bsc_config *conf = talloc_zero(nat, struct bsc_config);
	if (!conf)
		return NULL;

	conf->token = talloc_strdup(conf, token);
	conf->nr = nat->num_bsc;
	conf->nat = nat;

	INIT_LLIST_HEAD(&conf->lac_list);

	llist_add_tail(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	conf->stats.ctrg = rate_ctr_group_alloc(conf, &bsc_cfg_ctrg_desc, conf->nr);
	if (!conf->stats.ctrg) {
		talloc_free(conf);
		return NULL;
	}

	return conf;
}

void bsc_config_add_lac(struct bsc_config *cfg, int _lac)
{
	struct bsc_lac_entry *lac;

	llist_for_each_entry(lac, &cfg->lac_list, entry)
		if (lac->lac == _lac)
			return;

	lac = talloc_zero(cfg, struct bsc_lac_entry);
	if (!lac) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return;
	}

	lac->lac = _lac;
	llist_add_tail(&lac->entry, &cfg->lac_list);
}

void bsc_config_del_lac(struct bsc_config *cfg, int _lac)
{
	struct bsc_lac_entry *lac;

	llist_for_each_entry(lac, &cfg->lac_list, entry)
		if (lac->lac == _lac) {
			llist_del(&lac->entry);
			talloc_free(lac);
			return;
		}
}

int bsc_config_handles_lac(struct bsc_config *cfg, int lac_nr)
{
	struct bsc_lac_entry *entry;

	llist_for_each_entry(entry, &cfg->lac_list, entry)
		if (entry->lac == lac_nr)
			return 1;

	return 0;
}

void sccp_connection_destroy(struct sccp_connections *conn)
{
	LOGP(DNAT, LOGL_DEBUG, "Destroy 0x%x <-> 0x%x mapping for con %p\n",
	     sccp_src_ref_to_int(&conn->real_ref),
	     sccp_src_ref_to_int(&conn->patched_ref), conn->bsc);
	bsc_mgcp_dlcx(conn);
	llist_del(&conn->list_entry);
	talloc_free(conn);
}

struct bsc_connection *bsc_nat_find_bsc(struct bsc_nat *nat, struct msgb *msg, int *lac_out)
{
	struct bsc_connection *bsc;
	int data_length;
	const uint8_t *data;
	struct tlv_parsed tp;
	int i = 0;

	*lac_out = -1;

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		LOGP(DNAT, LOGL_ERROR, "Paging message is too short.\n");
		return NULL;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 3, msgb_l3len(msg) - 3, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DNAT, LOGL_ERROR, "No CellIdentifier List inside paging msg.\n");
		return NULL;
	}

	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);

	/* No need to try a different BSS */
	if (data[0] == CELL_IDENT_BSS) {
		return NULL;
	} else if (data[0] != CELL_IDENT_LAC) {
		LOGP(DNAT, LOGL_ERROR, "Unhandled cell ident discrminator: %d\n", data[0]);
		return NULL;
	}

	/* Currently we only handle one BSC */
	for (i = 1; i < data_length - 1; i += 2) {
		unsigned int _lac = ntohs(*(unsigned int *) &data[i]);
		*lac_out = _lac;
		llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
			if (!bsc->cfg)
				continue;
			if (!bsc->authenticated)
				continue;
			if (!bsc_config_handles_lac(bsc->cfg, _lac))
				continue;

			return bsc;
		}
	}

	return NULL;
}

int bsc_write_mgcp(struct bsc_connection *bsc, const uint8_t *data, unsigned int length)
{
	struct msgb *msg;

	if (length > 4096 - 128) {
		LOGP(DINP, LOGL_ERROR, "Can not send message of that size.\n");
		return -1;
	}

	msg = msgb_alloc_headroom(4096, 128, "to-bsc");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate memory for BSC msg.\n");
		return -1;
	}

	/* copy the data */
	msg->l3h = msgb_put(msg, length);
	memcpy(msg->l3h, data, length);

        return bsc_write(bsc, msg, IPAC_PROTO_MGCP);
}

int bsc_write(struct bsc_connection *bsc, struct msgb *msg, int proto)
{
	return bsc_do_write(&bsc->write_queue, msg, proto);
}

int bsc_do_write(struct write_queue *queue, struct msgb *msg, int proto)
{
	/* prepend the header */
	ipaccess_prepend_header(msg, proto);
	return bsc_write_msg(queue, msg);
}

int bsc_write_msg(struct write_queue *queue, struct msgb *msg)
{
	if (write_queue_enqueue(queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue the write.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

int bsc_nat_lst_check_allow(struct bsc_nat_acc_lst *lst, const char *mi_string)
{
	struct bsc_nat_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (!entry->imsi_allow)
			continue;
		if (regexec(&entry->imsi_allow_re, mi_string, 0, NULL, 0) == 0)
			return 0;
	}

	return 1;
}

static int lst_check_deny(struct bsc_nat_acc_lst *lst, const char *mi_string)
{
	struct bsc_nat_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (!entry->imsi_deny)
			continue;
		if (regexec(&entry->imsi_deny_re, mi_string, 0, NULL, 0) == 0)
			return 0;
	}

	return 1;
}

/* apply white/black list */
static int auth_imsi(struct bsc_connection *bsc, const char *mi_string)
{
	/*
	 * Now apply blacklist/whitelist of the BSC and the NAT.
	 * 1.) Allow directly if the IMSI is allowed at the BSC
	 * 2.) Reject if the IMSI is not allowed at the BSC
	 * 3.) Reject if the IMSI not allowed at the global level.
	 * 4.) Allow directly if the IMSI is allowed at the global level
	 */
	struct bsc_nat_acc_lst *nat_lst = NULL;
	struct bsc_nat_acc_lst *bsc_lst = NULL;

	bsc_lst = bsc_nat_acc_lst_find(bsc->nat, bsc->cfg->acc_lst_name);
	nat_lst = bsc_nat_acc_lst_find(bsc->nat, bsc->nat->acc_lst_name);


	if (bsc_lst) {
		/* 1. BSC allow */
		if (bsc_nat_lst_check_allow(bsc_lst, mi_string) == 0)
			return 1;

		/* 2. BSC deny */
		if (lst_check_deny(bsc_lst, mi_string) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by imsi_deny on bsc nr: %d.\n", mi_string, bsc->cfg->nr);
			rate_ctr_inc(&bsc_lst->stats->ctr[ACC_LIST_BSC_FILTER]);
			return -2;
		}

	}

	/* 3. NAT deny */
	if (nat_lst) {
		if (lst_check_deny(nat_lst, mi_string) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by nat imsi_deny on bsc nr: %d.\n", mi_string, bsc->cfg->nr);
			rate_ctr_inc(&nat_lst->stats->ctr[ACC_LIST_NAT_FILTER]);
			return -3;
		}
	}

	return 1;
}

static int _cr_check_loc_upd(struct bsc_connection *bsc,
			     uint8_t *data, unsigned int length,
			     char **imsi)
{
	uint8_t mi_type;
	struct gsm48_loc_upd_req *lu;
	char mi_string[GSM48_MI_SIZE];

	if (length < sizeof(*lu)) {
		LOGP(DNAT, LOGL_ERROR,
		     "LU does not fit. Length is %d \n", length);
		return -1;
	}

	lu = (struct gsm48_loc_upd_req *) data;
	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	/*
	 * We can only deal with the IMSI. This will fail for a phone that
	 * will send the TMSI of a previous network to us.
	 */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);
	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_cm_serv_req(struct bsc_connection *bsc,
				 uint8_t *data, unsigned int length,
				 int *con_type, char **imsi)
{
	static const uint32_t classmark_offset =
				offsetof(struct gsm48_service_request, classmark);

	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;
	int rc;
	struct gsm48_service_request *req;

	/* unfortunately in Phase1 the classmark2 length is variable */

	if (length < sizeof(*req)) {
		LOGP(DNAT, LOGL_ERROR,
		     "CM Serv Req does not fit. Length is %d\n", length);
		return -1;
	}

	req = (struct gsm48_service_request *) data;
	if (req->cm_service_type == 0x8)
		*con_type = NAT_CON_TYPE_SSA;
	rc = gsm48_extract_mi((uint8_t *) &req->classmark,
			      length - classmark_offset, mi_string, &mi_type);
	if (rc < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to parse the classmark2/mi. error: %d\n", rc);
		return -1;
	}

	/* we have to let the TMSI or such pass */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_pag_resp(struct bsc_connection *bsc,
			      uint8_t *data, unsigned int length,
			      char **imsi)
{
	struct gsm48_pag_resp *resp;
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	if (length < sizeof(*resp)) {
		LOGP(DNAT, LOGL_ERROR, "PAG RESP does not fit. Length was %d.\n", length);
		return -1;
	}

	resp = (struct gsm48_pag_resp *) data;
	if (gsm48_paging_extract_mi(resp, length, mi_string, &mi_type) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to extract the MI.\n");
		return -1;
	}

	/* we need to let it pass for now */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _dt_check_id_resp(struct bsc_connection *bsc,
			     uint8_t *data, unsigned int length,
			     struct sccp_connections *con)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;
	int ret;

	if (length < 2) {
		LOGP(DNAT, LOGL_ERROR, "mi does not fit.\n");
		return -1;
	}

	if (data[0] < length - 1) {
		LOGP(DNAT, LOGL_ERROR, "mi length too big.\n");
		return -2;
	}

	mi_type = data[1] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), &data[1], data[0]);

	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	ret = auth_imsi(bsc, mi_string);
	con->imsi_checked = 1;
	con->imsi = talloc_strdup(con, mi_string);
	return ret;
}

/* Filter out CR data... */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			   struct bsc_nat_parsed *parsed, int *con_type,
			   char **imsi)
{
	struct tlv_parsed tp;
	struct gsm48_hdr *hdr48;
	int hdr48_len;
	int len;
	uint8_t msg_type;

	*con_type = NAT_CON_TYPE_NONE;
	*imsi = NULL;

	if (parsed->gsm_type != BSS_MAP_MSG_COMPLETE_LAYER_3) {
		LOGP(DNAT, LOGL_ERROR,
		     "Rejecting CR message due wrong GSM Type %d\n", parsed->gsm_type);
		return -1;
	}

	/* the parsed has had some basic l3 length check */
	len = msg->l3h[1];
	if (msgb_l3len(msg) - 3 < len) {
		LOGP(DNAT, LOGL_ERROR,
		     "The CR Data has not enough space...\n");
		return -1;
	}

	msg->l4h = &msg->l3h[3];
	len -= 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h, len, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DNAT, LOGL_ERROR, "CR Data does not contain layer3 information.\n");
		return -1;
	}

	hdr48_len = TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	if (hdr48_len < sizeof(*hdr48)) {
		LOGP(DNAT, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	hdr48 = (struct gsm48_hdr *) TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	msg_type = hdr48->msg_type & 0xbf;
	if (hdr48->proto_discr == GSM48_PDISC_MM &&
	    msg_type == GSM48_MT_MM_LOC_UPD_REQUEST) {
		*con_type = NAT_CON_TYPE_LU;
		return _cr_check_loc_upd(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48), imsi);
	} else if (hdr48->proto_discr == GSM48_PDISC_MM &&
		  msg_type == GSM48_MT_MM_CM_SERV_REQ) {
		*con_type = NAT_CON_TYPE_CM_SERV_REQ;
		return _cr_check_cm_serv_req(bsc, &hdr48->data[0],
					     hdr48_len - sizeof(*hdr48),
					     con_type, imsi);
	} else if (hdr48->proto_discr == GSM48_PDISC_RR &&
		   msg_type == GSM48_MT_RR_PAG_RESP) {
		*con_type = NAT_CON_TYPE_PAG_RESP;
		return _cr_check_pag_resp(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48), imsi);
	} else {
		/* We only want to filter the above, let other things pass */
		*con_type = NAT_CON_TYPE_OTHER;
		return 0;
	}
}

struct gsm48_hdr *bsc_unpack_dtap(struct bsc_nat_parsed *parsed,
				  struct msgb *msg, uint32_t *len)
{
	/* gsm_type is actually the size of the dtap */
	*len = parsed->gsm_type;
	if (*len < msgb_l3len(msg) - 3) {
		LOGP(DNAT, LOGL_ERROR, "Not enough space for DTAP.\n");
		return NULL;
	}

	if (*len < sizeof(struct gsm48_hdr)) {
		LOGP(DNAT, LOGL_ERROR, "GSM48 header does not fit.\n");
		return NULL;
	}

	msg->l4h = &msg->l3h[3];
	return (struct gsm48_hdr *) msg->l4h;
}

int bsc_nat_filter_dt(struct bsc_connection *bsc, struct msgb *msg,
		      struct sccp_connections *con, struct bsc_nat_parsed *parsed)
{
	uint32_t len;
	uint8_t msg_type;
	struct gsm48_hdr *hdr48;

	if (con->imsi_checked)
		return 0;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return -1;

	msg_type = hdr48->msg_type & 0xbf;
	if (hdr48->proto_discr == GSM48_PDISC_MM &&
	    msg_type == GSM48_MT_MM_ID_RESP) {
		return _dt_check_id_resp(bsc, &hdr48->data[0], len - sizeof(*hdr48), con);
	} else {
		return 0;
	}
}

void bsc_parse_reg(void *ctx, regex_t *reg, char **imsi, int argc, const char **argv)
{
	if (*imsi) {
		talloc_free(*imsi);
		*imsi = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*imsi = talloc_strdup(ctx, argv[0]);
		regcomp(reg, argv[0], 0);
	}
}

static const char *con_types [] = {
	[NAT_CON_TYPE_NONE] = "n/a",
	[NAT_CON_TYPE_LU] = "Location Update",
	[NAT_CON_TYPE_CM_SERV_REQ] = "CM Serv Req",
	[NAT_CON_TYPE_PAG_RESP] = "Paging Response",
	[NAT_CON_TYPE_SSA] = "Supplementar Service Activation",
	[NAT_CON_TYPE_LOCAL_REJECT] = "Local Reject",
	[NAT_CON_TYPE_OTHER] = "Other",
};

const char *bsc_con_type_to_string(int type)
{
	return con_types[type];
}

struct bsc_nat_acc_lst *bsc_nat_acc_lst_find(struct bsc_nat *nat, const char *name)
{
	struct bsc_nat_acc_lst *lst;

	if (!name)
		return NULL;

	llist_for_each_entry(lst, &nat->access_lists, list)
		if (strcmp(lst->name, name) == 0)
			return lst;

	return NULL;
}

struct bsc_nat_acc_lst *bsc_nat_acc_lst_get(struct bsc_nat *nat, const char *name)
{
	struct bsc_nat_acc_lst *lst;

	lst = bsc_nat_acc_lst_find(nat, name);
	if (lst)
		return lst;

	lst = talloc_zero(nat, struct bsc_nat_acc_lst);
	if (!lst) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate access list");
		return NULL;
	}

	/* TODO: get the index right */
	lst->stats = rate_ctr_group_alloc(lst, &bsc_cfg_acc_list_desc, 0);
	if (!lst->stats) {
		talloc_free(lst);
		return NULL;
	}

	INIT_LLIST_HEAD(&lst->fltr_list);
	lst->name = talloc_strdup(lst, name);
	llist_add_tail(&lst->list, &nat->access_lists);
	return lst;
}

void bsc_nat_acc_lst_delete(struct bsc_nat_acc_lst *lst)
{
	llist_del(&lst->list);
	rate_ctr_group_free(lst->stats);
	talloc_free(lst);
}

struct bsc_nat_acc_lst_entry *bsc_nat_acc_lst_entry_create(struct bsc_nat_acc_lst *lst)
{
	struct bsc_nat_acc_lst_entry *entry;

	entry = talloc_zero(lst, struct bsc_nat_acc_lst_entry);
	if (!entry)
		return NULL;

	llist_add_tail(&entry->list, &lst->fltr_list);
	return entry;
}

int bsc_nat_msc_is_connected(struct bsc_nat *nat)
{
	return nat->msc_con->is_connected;
}

static const int con_to_ctr[] = {
	[NAT_CON_TYPE_NONE]		= -1,
	[NAT_CON_TYPE_LU]		= BCFG_CTR_CON_TYPE_LU,
	[NAT_CON_TYPE_CM_SERV_REQ]	= BCFG_CTR_CON_CMSERV_RQ,
	[NAT_CON_TYPE_PAG_RESP]		= BCFG_CTR_CON_PAG_RESP,
	[NAT_CON_TYPE_SSA]		= BCFG_CTR_CON_SSA,
	[NAT_CON_TYPE_LOCAL_REJECT]	= -1,
	[NAT_CON_TYPE_OTHER]		= BCFG_CTR_CON_OTHER,
};

int bsc_conn_type_to_ctr(struct sccp_connections *conn)
{
	return con_to_ctr[conn->con_type];
}

int bsc_write_cb(struct bsc_fd *bfd, struct msgb *msg)
{
	int rc;

	rc = write(bfd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DNAT, LOGL_ERROR, "Failed to write message to the BSC.\n");

	return rc;
}

/**
 * Rewrite non global numbers... according to rules based on the IMSI
 */
struct msgb *bsc_nat_rewrite_setup(struct bsc_nat *nat, struct msgb *msg, struct bsc_nat_parsed *parsed, const char *imsi)
{
	struct tlv_parsed tp;
	struct gsm48_hdr *hdr48;
	uint32_t len;
	uint8_t msg_type;
	unsigned int payload_len;
	struct gsm_mncc_number called;
	struct msg_entry *entry;
	char *new_number = NULL;
	struct msgb *out, *sccp;
	uint8_t *outptr;
	const uint8_t *msgptr;
	int sec_len;

	if (!imsi || strlen(imsi) < 5)
		return msg;

	if (!nat->num_rewr)
		return msg;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return msg;
	if (!parsed->dest_local_ref)
		return msg;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return msg;

	msg_type = hdr48->msg_type & 0xbf;
	if (hdr48->proto_discr != GSM48_PDISC_CC ||
	    msg_type != GSM48_MT_CC_SETUP)
		return msg;

	/* decode and rewrite the message */
	payload_len = len - sizeof(*hdr48);
	tlv_parse(&tp, &gsm48_att_tlvdef, hdr48->data, payload_len, 0, 0);

	/* no number, well let us ignore it */
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD))
		return msg;

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	/* check if it looks international and stop */
	if (called.plan != 1)
		return msg;
	if (called.type == 1)
		return msg;
	if (strncmp(called.number, "00", 2) == 0)
		return msg;

	/* need to find a replacement and then fix it */
	llist_for_each_entry(entry, &nat->num_rewr->entry, list) {
		regex_t reg;
		regmatch_t matches[2];

		if (entry->mcc[0] != '*' && strncmp(entry->mcc, imsi, 3) != 0)
			continue;
		if (entry->mnc[0] != '*' && strncmp(entry->mnc, imsi + 3, 2) != 0)
			continue;

		if (entry->text[0] == '+') {
			LOGP(DNAT, LOGL_ERROR,
				"Plus is not allowed in the number");
			continue;
		}

		/* We have an entry for the IMSI. Need to match now */
		if (regcomp(&reg, entry->option, REG_EXTENDED) != 0) {
			LOGP(DNAT, LOGL_ERROR,
				"Regexp '%s' is not valid.\n", entry->option);
			continue;
		}

		/* this regexp matches... */
		if (regexec(&reg, called.number, 2, matches, 0) == 0 &&
		    matches[1].rm_eo != -1)
			new_number = talloc_asprintf(msg, "%s%s",
					entry->text,
					&called.number[matches[1].rm_so]);
		regfree(&reg);

		if (new_number)
			break;
	}

	if (!new_number) {
		LOGP(DNAT, LOGL_DEBUG, "No IMSI match found, returning message.\n");
		return msg;
	}

	/*
	 * Need to create a new message now based on the old onew
	 * with a new number. We can sadly not patch this in place
	 * so we will need to regenerate it.
	 */

	out = msgb_alloc_headroom(4096, 128, "changed-setup");
	if (!out) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		talloc_free(new_number);
		return msg;
	}

	/* copy the header */
	outptr = msgb_put(out, sizeof(*hdr48));
	memcpy(outptr, hdr48, sizeof(*hdr48));

	/* copy everything up to the number */
	sec_len = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 2 - &hdr48->data[0];
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, &hdr48->data[0], sec_len);

	/* create the new number */
	strncpy(called.number, new_number, sizeof(called.number));
	gsm48_encode_called(out, &called);

	/* copy thre rest */
	msgptr = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) +
		 TLVP_LEN(&tp, GSM48_IE_CALLED_BCD);
	sec_len = payload_len - (msgptr - &hdr48->data[0]);
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, msgptr, sec_len);

	/* wrap with DTAP, SCCP, then IPA. TODO: Stop copying */
	gsm0808_prepend_dtap_header(out, 0);
	sccp = sccp_create_dt1(parsed->dest_local_ref, out->data, out->len);
	if (!sccp) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		talloc_free(new_number);
		talloc_free(out);
		return msg;
	}

	ipaccess_prepend_header(sccp, IPAC_PROTO_SCCP);

	/* give up memory, we are done */
	talloc_free(new_number);
	/* the parsed hangs off from msg but it needs to survive */
	talloc_steal(sccp, parsed);
	msgb_free(msg);
	msgb_free(out);
	out = NULL;
	return sccp;
}
