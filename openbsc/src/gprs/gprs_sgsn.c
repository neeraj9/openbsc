/* GPRS SGSN functionality */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdint.h>

#include <osmocore/linuxlist.h>
#include <osmocore/talloc.h>
#include <osmocore/timer.h>
#include <osmocore/rate_ctr.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/sgsn.h>

extern struct sgsn_instance *sgsn;

LLIST_HEAD(sgsn_mm_ctxts);
LLIST_HEAD(sgsn_ggsn_ctxts);
LLIST_HEAD(sgsn_apn_ctxts);
LLIST_HEAD(sgsn_pdp_ctxts);

static const struct rate_ctr_desc mmctx_ctr_description[] = {
	{ "sign.packets.in",	"Signalling Messages ( In)" },
	{ "sign.packets.out",	"Signalling Messages (Out)" },
	{ "udata.packets.in",	"User Data  Messages ( In)" },
	{ "udata.packets.out",	"User Data  Messages (Out)" },
	{ "udata.bytes.in",	"User Data  Bytes    ( In)" },
	{ "udata.bytes.out",	"User Data  Bytes    (Out)" },
	{ "pdp_ctx_act",	"PDP Context Activations  " },
	{ "suspend",		"SUSPEND Count            " },
	{ "paging.ps",		"Paging Packet Switched   " },
	{ "paging.cs",		"Paging Circuit Switched  " },
	{ "ra_update",		"Routing Area Update      " },
};

static const struct rate_ctr_group_desc mmctx_ctrg_desc = {
	.group_name_prefix = "sgsn.mmctx",
	.group_description = "SGSN MM Context Statistics",
	.num_ctr = ARRAY_SIZE(mmctx_ctr_description),
	.ctr_desc = mmctx_ctr_description,
};

static const struct rate_ctr_desc pdpctx_ctr_description[] = {
	{ "udata.packets.in",	"User Data  Messages ( In)" },
	{ "udata.packets.out",	"User Data  Messages (Out)" },
	{ "udata.bytes.in",	"User Data  Bytes    ( In)" },
	{ "udata.bytes.out",	"User Data  Bytes    (Out)" },
};

static const struct rate_ctr_group_desc pdpctx_ctrg_desc = {
	.group_name_prefix = "sgsn.pdpctx",
	.group_description = "SGSN PDP Context Statistics",
	.num_ctr = ARRAY_SIZE(pdpctx_ctr_description),
	.ctr_desc = pdpctx_ctr_description,
};

static int ra_id_equals(const struct gprs_ra_id *id1,
			const struct gprs_ra_id *id2)
{
	return (id1->mcc == id2->mcc && id1->mnc == id2->mnc &&
		id1->lac == id2->lac && id1->rac == id2->rac);
}

/* See 03.02 Chapter 2.6 */
static inline uint32_t tlli_foreign(uint32_t tlli)
{
	return ((tlli | 0x80000000) & ~0x40000000);	
}

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;
	int tlli_type;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (tlli == ctx->tlli &&
		    ra_id_equals(raid, &ctx->ra))
			return ctx;
	}

	tlli_type = gprs_tlli_type(tlli);
	switch (tlli_type) {
	case TLLI_LOCAL:
		llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
			if ((ctx->p_tmsi | 0xC0000000) == tlli ||
			     (ctx->p_tmsi_old && (ctx->p_tmsi_old | 0xC0000000) == tlli)) {
				ctx->tlli = tlli;
				return ctx;
			}
		}
		break;
	case TLLI_FOREIGN:
		llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
			if (tlli == tlli_foreign(ctx->tlli) &&
			    ra_id_equals(raid, &ctx->ra))
				return ctx;
		}
		break;
	default:
		break;
	}

	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(uint32_t p_tmsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (p_tmsi == ctx->p_tmsi ||
		    (ctx->p_tmsi_old && ctx->p_tmsi_old == p_tmsi))
			return ctx;
	}
	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (!strcmp(imsi, ctx->imsi))
			return ctx;
	}
	return NULL;

}

/* Allocate a new SGSN MM context */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;

	ctx = talloc_zero(tall_bsc_ctx, struct sgsn_mm_ctx);
	if (!ctx)
		return NULL;

	memcpy(&ctx->ra, raid, sizeof(ctx->ra));
	ctx->tlli = tlli;
	ctx->mm_state = GMM_DEREGISTERED;
	ctx->ctrg = rate_ctr_group_alloc(ctx, &mmctx_ctrg_desc, tlli);
	INIT_LLIST_HEAD(&ctx->pdp_list);

	llist_add(&ctx->list, &sgsn_mm_ctxts);

	return ctx;
}


/* look up PDP context by MM context and NSAPI */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_nsapi(const struct sgsn_mm_ctx *mm,
					   uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->nsapi == nsapi)
			return pdp;
	}
	return NULL;
}

/* look up PDP context by MM context and transaction ID */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_tid(const struct sgsn_mm_ctx *mm,
					 uint8_t tid)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->ti == tid)
			return pdp;
	}
	return NULL;
}

struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	pdp = sgsn_pdp_ctx_by_nsapi(mm, nsapi);
	if (pdp)
		return NULL;

	pdp = talloc_zero(tall_bsc_ctx, struct sgsn_pdp_ctx);
	if (!pdp)
		return NULL;

	pdp->mm = mm;
	pdp->nsapi = nsapi;
	pdp->ctrg = rate_ctr_group_alloc(pdp, &pdpctx_ctrg_desc, nsapi);
	llist_add(&pdp->list, &mm->pdp_list);
	llist_add(&pdp->g_list, &sgsn_pdp_ctxts);

	return pdp;
}

void sgsn_pdp_ctx_free(struct sgsn_pdp_ctx *pdp)
{
	rate_ctr_group_free(pdp->ctrg);
	llist_del(&pdp->list);
	llist_del(&pdp->g_list);
	talloc_free(pdp);
}

/* GGSN contexts */

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_alloc(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = talloc_zero(tall_bsc_ctx, struct sgsn_ggsn_ctx);
	if (!ggc)
		return NULL;

	ggc->id = id;
	ggc->gtp_version = 1;
	/* if we are called from config file parse, this gsn doesn't exist yet */
	ggc->gsn = sgsn->gsn;
	llist_add(&ggc->list, &sgsn_ggsn_ctxts);

	return ggc;
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_id(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	llist_for_each_entry(ggc, &sgsn_ggsn_ctxts, list) {
		if (id == ggc->id)
			return ggc;
	}
	return NULL;
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_find_alloc(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = sgsn_ggsn_ctx_by_id(id);
	if (!ggc)
		ggc = sgsn_ggsn_ctx_alloc(id);
	return ggc;
}

/* APN contexts */

#if 0
struct apn_ctx *apn_ctx_alloc(const char *ap_name)
{
	struct apn_ctx *actx;

	actx = talloc_zero(talloc_bsc_ctx, struct apn_ctx);
	if (!actx)
		return NULL;
	actx->name = talloc_strdup(actx, ap_name);

	return actx;
}

struct apn_ctx *apn_ctx_by_name(const char *name)
{
	struct apn_ctx *actx;

	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		if (!strcmp(name, actx->name))
			return actx;
	}
	return NULL;
}

struct apn_ctx *apn_ctx_find_alloc(const char *name)
{
	struct apn_ctx *actx;

	actx = apn_ctx_by_name(name);
	if (!actx)
		actx = apn_ctx_alloc(name);

	return actx;
}
#endif

uint32_t sgsn_alloc_ptmsi(void)
{
	struct sgsn_mm_ctx *mm;
	uint32_t ptmsi;

restart:
	ptmsi = rand();
	llist_for_each_entry(mm, &sgsn_mm_ctxts, list) {
		if (mm->p_tmsi == ptmsi)
			goto restart;
	}

	return ptmsi;
}

int gprs_mmctx_dump(struct osmo_dumper *od)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		struct sgsn_mm_ctx *pdp;

		/* first dump the MM context itself */
		osmo_dump_struct(od, OD_TYPE_GPRS_MM_CTX, ctx, sizeof(*ctx));

		/* dump all pdp contexts for this MM context */
		llist_for_each_entry(pdp, &ctx->pdp_list, list)
			osmo_dump_struct(od, OD_TYPE_GPRS_PDP_CTX, ctx, sizeof(*ctx));
	}
}

/* pointer to the last-restored MM context */
static struct sgsn_mm_ctx *restore_last_mm_ctx;

/* callback to restore one data structure from disk */
static int gprs_mmctx_restore(int type, uint8_t *data, int data_len)
{
	struct sgsn_mm_ctx *ctx;

	if (type != OD_TYPE_GPRS_MM_CTX)
		return -EINVAL;
	if (sizeof(*ctx) != data_len)
		return -EMSGSIZE;

	ctx = talloc_zero(tall_bsc_ctx, struct sgsn_mm_ctx);
	if (!ctx)
		return -ENOMEM;

	memcpy(ctx, data, sizeof(*llme));

	ctx->ctrg = rate_ctr_group_alloc(ctx, &mmctx_ctrg_desc, tlli);
	INIT_LLIST_HEAD(&ctx->pdp_list);

	llist_add(&ctx->list, &sgsn_mm_ctxts);

	restore_last_mm_ctx = ctx;

	return 0;
}

static int gprs_pdpctx_restore(int type, uint8_t *data, int data_len)
{
	struct sgsn_pdp_ctx *pdp;

	if (type != OD_TYPE_GPRS_PDP_CTX)
		return -EINVAL;

	if (sizeof(*pdp) != data_len)
		return -EMSGSIZE;

	pdp = sgsn_pdp_ctx_by_nsapi(mm, nsapi);
	if (pdp)
		return -EEXIST;

	pdp = talloc_zero(tall_bsc_ctx, struct sgsn_pdp_ctx);
	if (!pdp)
		return -ENOMEM;

	/* FIXME: how to restore the reference to the MM context? */
	pdp->mm = restore_last_mm_ctx;
	if (!pdp->mm) {
		talloc_free(pdp);
		return -EIO;
	}

	pdp->ctrg = rate_ctr_group_alloc(pdp, &pdpctx_ctrg_desc, nsapi);

	llist_add(&pdp->list, &mm->pdp_list);
	llist_add(&pdp->g_list, &sgsn_pdp_ctxts);

	return pdp;
}
