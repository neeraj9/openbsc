/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 */

#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <gtp.h>

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>

void *osmo_gtphub_ctx;

#define LOGERR(fmt, args...) \
	LOGP(DGTPHUB, LOGL_ERROR, fmt, ##args)

#define LOG(fmt, args...) \
	LOGP(DGTPHUB, LOGL_NOTICE, fmt, ##args)

#define ZERO_STRUCT(struct_pointer) memset(struct_pointer, '\0', sizeof(*(struct_pointer)))

/* TODO move this to osmocom/core/select.h ? */
typedef int (*osmo_fd_cb_t)(struct osmo_fd *fd, unsigned int what);

/* TODO move this to osmocom/core/linuxlist.h ? */
#define __llist_first(head) (((head)->next == (head)) ? NULL : (head)->next)
#define llist_first(head, type, entry) llist_entry(__llist_first(head), type, entry)

/* TODO duplicated from openggsn/gtp/gtpie.h */
#define ntoh16(x) ntohs(x)
#define ntoh32(x) ntohl(x)

/* TODO move GTP header stuff to openggsn/gtp/ ? See gtp_decaps*() */

enum gtp_rc {
	GTP_RC_UNKNOWN = 0,
	GTP_RC_TINY = 1,    /* no IEs (like ping/pong) */
	GTP_RC_PDU = 2,     /* a real packet with IEs */

	GTP_RC_TOOSHORT = -1,
	GTP_RC_UNSUPPORTED_VERSION = -2,
	GTP_RC_INVALID_IE = -3,
};

struct gtp_packet_desc {
	const union gtp_packet *data;
	int data_len;
	int header_len;
	int version;
	int rc;
};

/* Validate GTP version 0 data; analogous to validate_gtp1_header(), see there.
 */
void validate_gtp0_header(struct gtp_packet_desc *p)
{
	const struct gtp0_header *pheader = &(p->data->gtp0.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 0);

	if (p->data_len < GTP0_HEADER_SIZE) {
		LOGERR("GTP0 packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	if (p->data_len == GTP0_HEADER_SIZE) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP0_HEADER_SIZE;
		return;
	}

	/* Check packet length field versus length of packet */
	if (p->data_len != (ntoh16(pheader->length) + GTP0_HEADER_SIZE)) {
		LOGERR("GTP packet length field (%d + %d) does not match"
		       " actual length (%d)\n",
		       GTP0_HEADER_SIZE, (int)ntoh16(pheader->length),
		       p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	LOG("GTP v0 TID = %" PRIu64 "\n", pheader->tid);
	p->header_len = GTP0_HEADER_SIZE;
	p->rc = GTP_RC_PDU;
}

/* Validate GTP version 1 data, and update p->rc with the result, as well as
 * p->header_len in case of a valid header. */
void validate_gtp1_header(struct gtp_packet_desc *p)
{
	const struct gtp1_header_long *pheader = &(p->data->gtp1l.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 1);

	if ((p->data_len < GTP1_HEADER_SIZE_LONG)
	    && (p->data_len != GTP1_HEADER_SIZE_SHORT)){
		LOGERR("GTP packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	LOG("|GTPv1\n");
	LOG("| type = %" PRIu8 " 0x%02" PRIx8 "\n",
	    pheader->type, pheader->type);
	LOG("| length = %" PRIu16 " 0x%04" PRIx16 "\n",
	    ntoh16(pheader->length), ntoh16(pheader->length));
	LOG("| TEI = %" PRIu32 " 0x%08" PRIx32 "\n",
	    ntoh32(pheader->tei), ntoh32(pheader->tei));
	LOG("| seq = %" PRIu16 " 0x%04" PRIx16 "\n",
	    ntoh16(pheader->seq), ntoh16(pheader->seq));
	LOG("| npdu = %" PRIu8 " 0x%02" PRIx8 "\n",
	    pheader->npdu, pheader->npdu);
	LOG("| next = %" PRIu8 " 0x%02" PRIx8 "\n",
	    pheader->next, pheader->next);

	if (p->data_len <= GTP1_HEADER_SIZE_LONG) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP1_HEADER_SIZE_SHORT;
		return;
	}

	/* Check packet length field versus length of packet */
	if (p->data_len != (ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT)) {
		LOGERR("GTP packet length field (%d + %d) does not match"
		       " actual length (%d)\n",
		       GTP1_HEADER_SIZE_SHORT, (int)ntoh16(pheader->length),
		       p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->rc = GTP_RC_PDU;
	p->header_len = GTP1_HEADER_SIZE_LONG;
}

/* Examine whether p->data of size p->data_len has a valid GTP header. Set
 * p->version, p->rc and p->header_len. On error, p->rc <= 0 (see enum
 * gtp_rc). p->data must point at a buffer with p->data_len set. */
void validate_gtp_header(struct gtp_packet_desc *p)
{
	p->rc = GTP_RC_UNKNOWN;

	/* Need at least 1 byte in order to check version */
	if (p->data_len < (1)) {
		LOGERR("Discarding packet - too small\n");
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->version = p->data->flags >> 5;

	switch (p->version) {
	case 0:
		validate_gtp0_header(p);
		break;
	case 1:
		validate_gtp1_header(p);
		break;
	default:
		LOGERR("Unsupported GTP version: %d\n", p->version);
		p->rc = GTP_RC_UNSUPPORTED_VERSION;
		break;
	}
}

/* Validate header, and index information elements. Write decoded packet
 * information to *res. res->data will point at the given data buffer. On
 * error, p->rc is set <= 0 (see enum gtp_rc). */
static void gtp_decode(const uint8_t *data, int data_len, struct gtp_packet_desc *res)
{
	ZERO_STRUCT(res);
	res->data = (union gtp_packet*)data;
	res->data_len = data_len;

	validate_gtp_header(res);

	if (res->rc == GTP_RC_TINY)
		LOG("tiny: no IEs in this GTP packet\n");
}


/* general */

const char* const gtphub_port_idx_names[GTPH_PORT_N] = {
	"CTRL",
	"USER",
};


/* tei_map, tei_pool */

void tei_pool_init(struct tei_pool *pool)
{
	*pool = (struct tei_pool){};
}

uint32_t tei_pool_next(struct tei_pool *pool)
{
	pool->last_tei ++;

	OSMO_ASSERT(pool->last_tei > 0);
	/* TODO: gracefully handle running out of TEIs. */
	/* TODO: random TEIs. */

	return pool->last_tei;
}

void tei_map_init(struct tei_map *map, struct tei_pool *pool)
{
	ZERO_STRUCT(map);
	map->pool = pool;
	INIT_LLIST_HEAD(&map->mappings);
}

static uint32_t tei_map_new(struct tei_map *map, uint32_t tei_orig)
{
	struct tei_mapping *mapping;
	mapping = talloc_zero(osmo_gtphub_ctx, struct tei_mapping);
	OSMO_ASSERT(mapping);
	mapping->orig = tei_orig;
	mapping->repl = tei_pool_next(map->pool);
	llist_add(&mapping->entry, &map->mappings);
	return mapping->repl;
}

uint32_t tei_map_get(struct tei_map *map, uint32_t tei_orig)
{
	OSMO_ASSERT(tei_orig != 0);

	struct tei_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->orig == tei_orig)
			return mapping->repl;
	}
	/* Not found. */

	return tei_map_new(map, tei_orig);
}

uint32_t tei_map_get_rev(struct tei_map *map, uint32_t tei_repl)
{
	OSMO_ASSERT(tei_repl != 0);

	struct tei_mapping *pos;
	llist_for_each_entry(pos, &map->mappings, entry) {
		if (pos->repl == tei_repl) {
			OSMO_ASSERT(pos->orig);
			return pos->orig;
		}
	}
	return 0;
}

void tei_map_del(struct tei_map *map, uint32_t tei_orig)
{
	struct tei_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->orig == tei_orig) {
			llist_del(&mapping->entry);
			talloc_free(mapping);
			return;
		}
	}
	LOGERR("No mapping exists for TEI %" PRIu32 ".\n", tei_orig);
}


/* gtphub */

void gtphub_zero(struct gtphub *hub)
{
	ZERO_STRUCT(hub);
}

static int gtphub_sock_init(struct osmo_fd *ofd,
			    const struct gtphub_cfg_addr *addr,
			    osmo_fd_cb_t cb,
			    void *data,
			    int ofd_id)
{
	ofd->when = BSC_FD_READ;
	ofd->cb = cb;
	ofd->data = data;
	ofd->priv_nr = ofd_id;

	int rc;
	rc = osmo_sock_init_ofd(ofd,
				AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				addr->addr_str, addr->port,
				OSMO_SOCK_F_BIND);
	if (rc < 1) {
		LOGERR("Cannot bind to %s port %d (rc %d)\n",
		       addr->addr_str, (int)addr->port, rc);
		return -1;
	}

	return 0;
}

static int gtphub_gtp_bind_init(struct gtphub_bind *b,
				const struct gtphub_cfg_bind *cfg,
				osmo_fd_cb_t cb, void *cb_data,
				unsigned int ofd_id)
{
	ZERO_STRUCT(b);

	tei_pool_init(&b->teip);
	INIT_LLIST_HEAD(&b->peers);

	if (gtphub_sock_init(&b->ofd, &cfg->bind, cb, cb_data, ofd_id) != 0)
		return -1;
	return 0;
}

/* Recv datagram from from->fd, optionally write sender's address to *from_addr
 * and *from_addr_len, parse datagram as GTP, and forward on to to->fd using
 * *to_addr. to_addr may be NULL, if an address is set on to->fd. */
static int gtp_relay(struct osmo_fd *from,
		     struct sockaddr_storage *from_addr,
		     socklen_t *from_addr_len,
		     struct osmo_fd *to,
		     struct sockaddr_storage *to_addr,
		     socklen_t to_addr_len)
{
	static uint8_t buf[4096];

	/* recvfrom requires the available length to be set in *from_addr_len. */
	if (from_addr_len && from_addr)
		*from_addr_len = sizeof(*from_addr);

	errno = 0;
	ssize_t received = recvfrom(from->fd, buf, sizeof(buf), 0,
				    (struct sockaddr*)from_addr, from_addr_len);
	/* TODO use recvmsg and get a MSG_TRUNC flag to make sure the message
	 * is not truncated. Then maybe reduce buf's size. */

	if (received <= 0) {
		if (errno != EAGAIN)
			LOGERR("error: %s\n", strerror(errno));
		return -errno;
	}

	if (from_addr) {
		LOG("from %s\n", osmo_hexdump((uint8_t*)from_addr, *from_addr_len));
	}

	if (received <= 0) {
		LOGERR("error: %s\n", strerror(errno));
		return -EINVAL;
	}

	/* insert magic here */
	LOG("Received %d\n%s\n", (int)received, osmo_hexdump(buf, received));

	struct gtp_packet_desc p;
	gtp_decode(buf, received, &p);

	if (p.rc > 0)
		LOG("Valid GTP header (v%d)\n", p.version);
#if 0
	else
		// error has been logged
		return 0;
#endif

	errno = 0;
	ssize_t sent = sendto(to->fd, buf, received, 0,
			      (struct sockaddr*)to_addr, to_addr_len);

	if (to_addr) {
		LOG("to %s\n", osmo_hexdump((uint8_t*)to_addr, to_addr_len));
	}

	if (sent == -1) {
		LOGERR("error: %s\n", strerror(errno));
		return -EINVAL;
	}

	if (sent != received)
		LOGERR("sent(%d) != received(%d)\n", (int)sent, (int)received);
	else
		LOG("%d b ok\n", (int)sent);

	return 0;
}

int from_ggsns_read_cb(struct osmo_fd *from_ggsns_ofd, unsigned int what)
{
	unsigned int port_idx = from_ggsns_ofd->priv_nr;
	OSMO_ASSERT(port_idx < GTPH_PORT_N);
	LOG("\n\n=== reading from GGSN (%s)\n", gtphub_port_idx_names[port_idx]);
	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_ggsns_ofd->data;

	/* TODO this will not be hardcoded. */
	struct gtphub_peer *sgsn = llist_first(&hub->to_sgsns[port_idx].peers,
						 struct gtphub_peer, entry);
	if (!sgsn) {
		LOGERR("no sgsn");
		return 0;
	}

	return gtp_relay(from_ggsns_ofd, NULL, NULL,
			 &hub->to_sgsns[port_idx].ofd,
			 &sgsn->addr.a, sgsn->addr.l);
}

int from_sgsns_read_cb(struct osmo_fd *from_sgsns_ofd, unsigned int what)
{
	unsigned int port_idx = from_sgsns_ofd->priv_nr;
	OSMO_ASSERT(port_idx < GTPH_PORT_N);
	LOG("\n\n=== reading from SGSN (%s)\n", gtphub_port_idx_names[port_idx]);

	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_sgsns_ofd->data;

	/* TODO this will not be hardcoded. */
	struct gtphub_peer *ggsn = llist_first(&hub->to_ggsns[port_idx].peers,
					       struct gtphub_peer, entry);
	if (!ggsn) {
		LOGERR("no ggsn to send to\n");
		return 0;
	}

	/* so far just remembering the last sgsn */
	struct gtphub_peer *sgsn = llist_first(&hub->to_sgsns[port_idx].peers,
						 struct gtphub_peer, entry);
	if (!sgsn)
		sgsn = gtphub_peer_new(&hub->to_sgsns[port_idx]);

	return gtp_relay(from_sgsns_ofd, &sgsn->addr.a, &sgsn->addr.l,
			 &hub->to_ggsns[port_idx].ofd,
			 &ggsn->addr.a, ggsn->addr.l);
}

int gtphub_init(struct gtphub *hub, struct gtphub_cfg *cfg)
{
	gtphub_zero(hub);

	int port_id;
	for (port_id = 0; port_id < GTPH_PORT_N; port_id++) {
		int rc;
		rc = gtphub_gtp_bind_init(&hub->to_ggsns[port_id],
					  &cfg->to_ggsns[port_id],
					  from_ggsns_read_cb, hub, port_id);
		if (rc < 0)
			return rc;

		rc = gtphub_gtp_bind_init(&hub->to_sgsns[port_id],
					  &cfg->to_sgsns[port_id],
					  from_sgsns_read_cb, hub, port_id);
		if (rc < 0)
			return rc;

		/* ... */
	}
	return 0;
}

struct gtphub_peer *gtphub_peer_new(struct gtphub_bind *bind)
{
	struct gtphub_peer *n = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer);

	tei_map_init(&n->teim, &bind->teip);

	llist_add(&n->entry, &bind->peers);
	return n;
}

void gtphub_peer_del(struct gtphub_peer *peer)
{
	llist_del(&peer->entry);
	talloc_free(peer);
}

