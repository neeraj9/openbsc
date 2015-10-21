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
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <gtp.h>

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>

#define GTPHUB_DEBUG 1
#define MAP_SEQ 1

static const int GTPH_GC_TICK = 1;
static const int GTPH_SEQ_MAPPING_EXPIRY_SECS = 30;

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

#define hton16(x) htons(x)

/* cheat to use gtpie.h API.
 * TODO publish gtpie.h upon openggsn installation */
union gtpie_member;
extern int gtpie_decaps(union gtpie_member *ie[], int version,
			void *pack, unsigned len);
extern int gtpie_gettv0(union gtpie_member *ie[], int type, int instance,
			void *dst, unsigned int size);
extern int gtpie_gettv1(union gtpie_member *ie[], int type, int instance,
			uint8_t *dst);
extern int gtpie_gettlv(union gtpie_member *ie[], int type, int instance,
			unsigned int *length, void *dst, unsigned int size);
#define GTPIE_IMSI            2	/* International Mobile Subscriber Identity 8 */
#define GTPIE_NSAPI          20	/* NSAPI 1 */
#define GTPIE_GSN_ADDR      133	/* GSN Address */
#define GTPIE_SIZE 256
/* end of things needed from gtpie.h */

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
	union gtp_packet *data;
	int data_len;
	int header_len;
	int version;
	int rc;
	union gtpie_member *ie[GTPIE_SIZE];
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


/* Return the value of the i'th IMSI IEI by copying to *imsi.
 * The first IEI is reached by passing i = 0.
 * imsi must point at allocated space of (at least) 8 bytes.
 * Return 1 on success, or 0 if not found. */
static int get_ie_imsi(union gtpie_member *ie[], uint8_t *imsi, int i)
{
	return gtpie_gettv0(ie, GTPIE_IMSI, i, imsi, 8) == 0;
}

/* Analogous to get_ie_imsi(). nsapi must point at a single uint8_t. */
static int get_ie_nsapi(union gtpie_member *ie[], uint8_t *nsapi, int i)
{
	return gtpie_gettv1(ie, GTPIE_NSAPI, i, nsapi) == 0;
}

static char imsi_digit_to_char(uint8_t nibble)
{
	nibble &= 0x0f;
	if (nibble > 9)
		return (nibble == 0x0f) ? '\0' : '?';
	return '0' + nibble;
}

/* Return a human readable IMSI string, in a static buffer.
 * imsi must point at 8 octets of IMSI IE encoded IMSI data. */
static const char *imsi_to_str(uint8_t *imsi)
{
	static char str[17];
	int i;

	for (i = 0; i < 8; i++) {
		str[2*i] = imsi_digit_to_char(imsi[i]);
		str[2*i + 1] = imsi_digit_to_char(imsi[i] >> 4);
	}
	str[16] = '\0';
	return str;
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

	if (res->rc > 0)
		LOG("Valid GTP header (v%d)\n", res->version);

	if (res->rc == GTP_RC_TINY)
		LOG("tiny: no IEs in this GTP packet\n");

	if (res->rc != GTP_RC_PDU)
		return;

	if (gtpie_decaps(res->ie, res->version,
			 (void*)(data + res->header_len),
			 res->data_len - res->header_len) != 0) {
		res->rc = GTP_RC_INVALID_IE;
		return;
	}

#if GTPHUB_DEBUG
	int i;

	for (i = 0; i < 10; i++) {
		uint8_t imsi[8];
		if (!get_ie_imsi(res->ie, imsi, i))
			break;
		LOG("- IMSI %s\n", imsi_to_str(imsi));
	}

	for (i = 0; i < 10; i++) {
		uint8_t nsapi;
		if (!get_ie_nsapi(res->ie, &nsapi, i))
			break;
		LOG("- NSAPI %d\n", (int)nsapi);
	}

	for (i = 0; i < 10; i++) {
		unsigned int addr_len;
		struct in_addr addr;
		if (gtpie_gettlv(res->ie, GTPIE_GSN_ADDR, i, &addr_len, &addr,
				 sizeof(addr)) != 0)
			break;
		LOG("- addr %s\n", inet_ntoa(addr));
	}
#endif
}


/* general */

const char* const gtphub_port_idx_names[GTPH_PORT_N] = {
	"CTRL",
	"USER",
};

static time_t gtphub_now(void)
{
	struct timespec now_tp;
	OSMO_ASSERT(clock_gettime(CLOCK_MONOTONIC, &now_tp) >= 0);
	return now_tp.tv_sec;
}

/* obsolete */
#if 0
static time_t gtphub_expiry_in(int seconds)
{
	return gtphub_now() + seconds;
}
#endif


/* nr_map, nr_pool */

void nr_pool_init(struct nr_pool *pool)
{
	*pool = (struct nr_pool){};
}

nr_t nr_pool_next(struct nr_pool *pool)
{
	pool->last_nr ++;

	OSMO_ASSERT(pool->last_nr > 0);
	/* TODO: gracefully handle running out of TEIs. */
	/* TODO: random TEIs. */

	return pool->last_nr;
}

void nr_map_init(struct nr_map *map, struct nr_pool *pool,
		 struct nr_map_expiry *exq)
{
	ZERO_STRUCT(map);
	map->pool = pool;
	map->expiry = exq;
	INIT_LLIST_HEAD(&map->mappings);
}

void nr_mapping_init(struct nr_mapping *m)
{
	ZERO_STRUCT(m);
	INIT_LLIST_HEAD(&m->entry);
	INIT_LLIST_HEAD(&m->expiry_entry);
}

void nr_map_add(struct nr_map *map, struct nr_mapping *mapping, time_t now)
{
	/* Generate a mapped number */
	mapping->repl = nr_pool_next(map->pool);

	/* Add to the tail to always yield a list sorted by expiry, in
	 * ascending order. */
	llist_add_tail(&mapping->entry, &map->mappings);
	if (map->expiry)
		nr_map_expiry_add(map->expiry, mapping, now);
}

void nr_map_del(struct nr_map *map)
{
	struct nr_mapping *m;
	struct nr_mapping *n;
	llist_for_each_entry_safe(m, n, &map->mappings, entry) {
		nr_mapping_del(m);
	}
}

int nr_map_empty(const struct nr_map *map)
{
	return llist_empty(&map->mappings);
}

struct nr_mapping *nr_map_get(const struct nr_map *map, nr_t nr_orig)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->orig == nr_orig)
			return mapping;
	}
	/* Not found. */
	return NULL;
}

struct nr_mapping *nr_map_get_inv(const struct nr_map *map, nr_t nr_repl)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->repl == nr_repl) {
			return mapping;
		}
	}
	/* Not found. */
	return NULL;
}

void nr_mapping_del(struct nr_mapping *mapping)
{
	OSMO_ASSERT(mapping);
	llist_del(&mapping->entry);
	llist_del(&mapping->expiry_entry);
	if (mapping->del_cb)
		(mapping->del_cb)(mapping);
}

void nr_map_expiry_init(struct nr_map_expiry *exq, int expiry_in_seconds)
{
	ZERO_STRUCT(exq);
	exq->expiry_in_seconds = expiry_in_seconds;
	INIT_LLIST_HEAD(&exq->mappings);
}

void nr_map_expiry_add(struct nr_map_expiry *exq, struct nr_mapping *mapping,
		       time_t now)
{
	mapping->expiry = now + exq->expiry_in_seconds;

	/* Add/move to the tail to always sort by expiry, ascending. */
	llist_del(&mapping->expiry_entry);
	llist_add_tail(&mapping->expiry_entry, &exq->mappings);
}

int nr_map_expiry_tick(struct nr_map_expiry *exq, time_t now)
{
	int expired = 0;
	struct nr_mapping *m;
	struct nr_mapping *n;
	llist_for_each_entry_safe(m, n, &exq->mappings, expiry_entry) {
		if (m->expiry <= now) {
			nr_mapping_del(m);
			expired ++;
		}
		else {
			/* The items are added sorted by expiry. So when we hit
			 * an unexpired entry, only more unexpired ones will
			 * follow. */
			break;
		}
	}
	return expired;
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
	if (!addr->addr_str) {
		LOGERR("Cannot bind: empty address.\n");
		return -1;
	}
	if (!addr->port) {
		LOGERR("Cannot bind: zero port not permitted.\n");
		return -1;
	}

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

	nr_pool_init(&b->teip);
	INIT_LLIST_HEAD(&b->peers);

	if (gtphub_sock_init(&b->ofd, &cfg->bind, cb, cb_data, ofd_id) != 0)
		return -1;
	return 0;
}

/* Recv datagram from from->fd, optionally write sender's address to *from_addr.
 * Return the number of bytes read, zero on error. */
static int gtphub_read(const struct osmo_fd *from,
		       struct osmo_sockaddr *from_addr,
		       uint8_t *buf, size_t buf_len)
{
	/* recvfrom requires the available length to be set in *from_addr_len. */
	if (from_addr)
		from_addr->l = sizeof(from_addr->a);

	errno = 0;
	ssize_t received = recvfrom(from->fd, buf, buf_len, 0,
				    (struct sockaddr*)&from_addr->a, &from_addr->l);
	/* TODO use recvmsg and get a MSG_TRUNC flag to make sure the message
	 * is not truncated. Then maybe reduce buf's size. */

	if (received <= 0) {
		if (errno != EAGAIN)
			LOGERR("error: %s\n", strerror(errno));
		return 0;
	}

	if (from_addr) {
		LOG("from %s\n", osmo_sockaddr_to_str(from_addr));
	}

	if (received <= 0) {
		LOGERR("error: %s\n", strerror(errno));
		return 0;
	}

	LOG("Received %d\n%s\n", (int)received, osmo_hexdump(buf, received));
	return received;
}

#if MAP_SEQ

inline void gtphub_peer_ref_count_inc(struct gtphub_peer *p)
{
	OSMO_ASSERT(p->ref_count < UINT_MAX);
	p->ref_count++;
}

inline void gtphub_peer_ref_count_dec(struct gtphub_peer *p)
{
	OSMO_ASSERT(p->ref_count > 0);
	p->ref_count--;
}

inline uint16_t get_seq(struct gtp_packet_desc *p)
{
	OSMO_ASSERT(p->version == 1);
	return ntoh16(p->data->gtp1l.h.seq);
}

inline void set_seq(struct gtp_packet_desc *p, uint16_t seq)
{
	OSMO_ASSERT(p->version == 1);
	p->data->gtp1l.h.seq = hton16(seq);
}

static void gtphub_seqmap_del_cb(struct nr_mapping *nrm);

static struct gtphub_seqmap *gtphub_seqmap_new(uint16_t orig_seq)
{
	struct gtphub_seqmap *n;
	n = talloc_zero(osmo_gtphub_ctx, struct gtphub_seqmap);
	OSMO_ASSERT(n);

	nr_mapping_init(&n->nrm);
	n->nrm.orig = orig_seq;
	n->nrm.del_cb = gtphub_seqmap_del_cb;
	return n;
}

static void gtphub_seqmap_del_cb(struct nr_mapping *nrm)
{
	struct gtphub_seqmap *m = container_of(nrm, struct gtphub_seqmap, nrm);
	LOG("expired: %d: nr mapping from %s: %d->%d\n",
	    (int)nrm->expiry,
	    osmo_sockaddr_to_str(&m->from->addr),
	    (int)nrm->orig, (int)nrm->repl);

	if (m->from)
		gtphub_peer_ref_count_dec(m->from);
	talloc_free(m);
}

/* obsolete */
#if 0
static struct gtphub_seqmap *gtphub_seqmap_get(struct llist_head *map,
					       uint16_t *next_peer_seq,
					       uint16_t orig_seq)
{
	struct gtphub_seqmap *m;

	llist_for_each_entry(m, map, entry) {
		if (m->from_seq == orig_seq)
			break;
	}

	if (&m->entry == map) {
		/* No entry exists yet. */
		m = gtphub_seqmap_new();
		m->peer_seq = (*next_peer_seq)++;
		m->from_seq = orig_seq;
		LOG("  MAP %d --> %d\n", (int)m->from_seq, (int)m->peer_seq);
	}

	m->expiry = gtphub_expiry_in(GTPH_SEQ_MAPPING_EXPIRY_SECS);

	/* Store in to_peer's map, so when we later receive a GTP packet back
	 * from to_peer, the seq nr can be unmapped to its origin. Add/move to
	 * the tail to always sort by expiry, ascending. */
	llist_del(&m->entry);
	llist_add_tail(&m->entry, map);

	return m;
}

/* obsolete */
static struct gtphub_seqmap *gtphub_seqmap_get_rev(const struct llist_head *map,
						   uint16_t mapped_seq)
{
	struct gtphub_seqmap *m;
	llist_for_each_entry(m, map, entry) {
		if (m->peer_seq == mapped_seq)
			break;
	}

	if (&m->entry == map) {
		/* not found. */
		return NULL;
	}

	LOG("UNMAP %d <-- %d\n", (int)(m->from_seq), (int)mapped_seq);
	return m;
}
#endif

struct gtphub_seqmap *gtphub_seqmap_have(struct nr_map *map,
					 uint16_t orig_seq)
{
	struct nr_mapping *nrm;
	struct gtphub_seqmap *m;

	nrm = nr_map_get(map, orig_seq);

	if (!nrm) {
		m = gtphub_seqmap_new(orig_seq);
		nr_map_add(map, &m->nrm, gtphub_now());
		LOG("MAP %d --> %d\n", (int)(m->nrm.orig), (int)(m->nrm.repl));
	}
	else {
		/* restart expiry timeout */
		nr_map_expiry_add(map->expiry, nrm, gtphub_now());
		m = container_of(nrm, struct gtphub_seqmap, nrm);
	}

	OSMO_ASSERT(m);
	return m;
}

struct gtphub_seqmap *gtphub_seqmap_get_inv(const struct nr_map *map,
					    uint16_t mapped_seq)
{
	struct nr_mapping *nrm = nr_map_get_inv(map, mapped_seq);

	if (!nrm)
		return NULL;

	struct gtphub_seqmap *m = container_of(nrm, struct gtphub_seqmap, nrm);
	LOG("UNMAP %d <-- %d\n", (int)(nrm->orig), (int)(nrm->repl));
	return m;
}

static int gtphub_map_seq(struct gtp_packet_desc *p,
			  struct gtphub_peer *from_peer, struct gtphub_peer *to_peer)
{
	/* Store a mapping in to_peer's map, so when we later receive a GTP
	 * packet back from to_peer, the seq nr can be unmapped back to its
	 * origin (from_peer here). */
	struct gtphub_seqmap *m;
	m = gtphub_seqmap_have(&to_peer->seq_map, get_seq(p));

	m->from = from_peer;
	gtphub_peer_ref_count_inc(m->from);

	/* Change the GTP packet to yield the new, mapped seq nr */
	set_seq(p, m->nrm.repl);

	return 0;
}

static struct gtphub_peer *gtphub_unmap_seq(struct gtp_packet_desc *p,
					    struct gtphub_peer *replying_peer)
{
	OSMO_ASSERT(p->version == 1);
	struct gtphub_seqmap *m = gtphub_seqmap_get_inv(&replying_peer->seq_map,
							get_seq(p));
	if (!m)
		return NULL;
	set_seq(p, m->nrm.orig);
	return m->from;
}

#endif

static int gtphub_write(struct osmo_fd *to,
			struct osmo_sockaddr *to_addr,
			uint8_t *buf, size_t buf_len)
{
	errno = 0;
	ssize_t sent = sendto(to->fd, buf, buf_len, 0,
			      (struct sockaddr*)&to_addr->a, to_addr->l);

	if (to_addr) {
		LOG("to %s\n", osmo_sockaddr_to_str(to_addr));
	}

	if (sent == -1) {
		LOGERR("error: %s\n", strerror(errno));
		return -EINVAL;
	}

	if (sent != buf_len)
		LOGERR("sent(%d) != data_len(%d)\n", (int)sent, (int)buf_len);
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

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	size_t received = gtphub_read(from_ggsns_ofd, &from_addr,
				      buf, sizeof(buf));
	if (received < 1)
		return 0;

	static struct gtp_packet_desc p;
	gtp_decode(buf, received, &p);

#if 0
	if (p.rc <= 0)
		return 0;
#endif

	/* If a GGSN proxy is configured, check that it's indeed that proxy
	 * talking to us. */
	struct gtphub_peer *ggsn = hub->ggsn_proxy[port_idx];
	if (ggsn
	    && ((ggsn->addr.l != from_addr.l)
		|| (memcmp(&ggsn->addr.a, &from_addr.a,
			   from_addr.l) != 0)
	       )
	   ){
		LOGERR("Rejecting: GGSN proxy configured, but GTP packet"
		       " received on GGSN bind is from another sender:...\n");
		LOGERR("... proxy: %s\n", osmo_sockaddr_to_str(&ggsn->addr));
		LOGERR("...sender: %s\n", osmo_sockaddr_to_str(&from_addr));
		return 0;
	}

	if (!ggsn) {
		/* TODO this will not be hardcoded. */
		ggsn = llist_first(&hub->to_ggsns[port_idx].peers,
				   struct gtphub_peer, entry);
	}

	if (!ggsn) {
		LOGERR("no ggsn\n");
		return 0;
	}


	struct gtphub_peer *sgsn = hub->sgsn_proxy[port_idx];

#if MAP_SEQ
	/* Always try to unmap the sequence number (replaced in the packet).
	 * But give precedence to the SGSN already pointed at by 'sgsn' (the
	 * SGSN proxy), if set. */
	struct gtphub_peer *unmap_sgsn = gtphub_unmap_seq(&p, ggsn);
	if (!sgsn)
		sgsn = unmap_sgsn;
	else
	if (unmap_sgsn && (sgsn != unmap_sgsn))
		LOGERR("Seq unmap yields an SGSN other than the configured proxy. Using proxy.\n");
#endif

	if (!sgsn) {
		LOGERR("no sgsn to send to\n");
		return 0;
	}

#if MAP_SEQ
	/* If the GGSN is replying to an SGSN request, the sequence nr has
	 * already been unmapped above (unmap_sgsn != NULL), and we need not
	 * create a new outgoing sequence map. */
	if (!unmap_sgsn)
		gtphub_map_seq(&p, ggsn, sgsn);
#endif

	return gtphub_write(&hub->to_sgsns[port_idx].ofd, &sgsn->addr,
			    (uint8_t*)p.data, p.data_len);
}

int from_sgsns_read_cb(struct osmo_fd *from_sgsns_ofd, unsigned int what)
{
	unsigned int port_idx = from_sgsns_ofd->priv_nr;
	OSMO_ASSERT(port_idx < GTPH_PORT_N);
	LOG("\n\n=== reading from SGSN (%s)\n", gtphub_port_idx_names[port_idx]);

	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_sgsns_ofd->data;

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	size_t received = gtphub_read(from_sgsns_ofd, &from_addr,
				      buf, sizeof(buf));
	if (received < 1)
		return 0;

	static struct gtp_packet_desc p;
	gtp_decode(buf, received, &p);

#if 0
	if (p.rc <= 0)
		return 0;
#endif
	/* If an SGSN proxy is configured, check that it's indeed that proxy
	 * talking to us. */
	struct gtphub_peer *sgsn = hub->sgsn_proxy[port_idx];
	if (sgsn
	    && ((sgsn->addr.l != from_addr.l)
		|| (memcmp(&sgsn->addr.a, &from_addr.a,
			   from_addr.l) != 0)
	       )
	   ){
		LOGERR("Rejecting: SGSN proxy configured, but GTP packet"
		       " received on SGSN bind is from another sender:...\n");
		LOGERR("... proxy: %s\n", osmo_sockaddr_to_str(&sgsn->addr));
		LOGERR("...sender: %s\n", osmo_sockaddr_to_str(&from_addr));
		return 0;
	}

	if (!sgsn) {
		/* TODO this will not be hardcoded. */
		/* sgsn = gtphub_sgsn_get(hub, ...); */
		sgsn = llist_first(&hub->to_sgsns[port_idx].peers,
				   struct gtphub_peer, entry);
		if (!sgsn)
			sgsn = gtphub_peer_new(hub, &hub->to_sgsns[port_idx]);
		memcpy(&sgsn->addr, &from_addr, sizeof(sgsn->addr));
	}

	struct gtphub_peer *ggsn = hub->ggsn_proxy[port_idx];

#if MAP_SEQ
	/* Always unmap the sequence number (replaced in the packet). But give
	 * precedence to the GGSN already pointed at by 'ggsn' (the GGSN
	 * proxy), if set. */
	struct gtphub_peer *unmap_ggsn = gtphub_unmap_seq(&p, sgsn);
	if (!ggsn)
		ggsn = unmap_ggsn;
	else
	if (unmap_ggsn && (ggsn != unmap_ggsn))
		LOGERR("Seq unmap yields a GGSN other than the configured proxy. Using proxy.\n");
#endif

	if (!ggsn) {
		/* TODO this will not be hardcoded. */
		/* ggsn = gtphub_ggsn_resolve(hub, ...); */
		ggsn = llist_first(&hub->to_ggsns[port_idx].peers,
				   struct gtphub_peer, entry);
	}

	if (!ggsn) {
		LOGERR("no ggsn to send to\n");
		return 0;
	}

#if MAP_SEQ
	/* If the SGSN is replying to a GGSN request, the sequence nr has
	 * already been unmapped above (unmap_ggsn != NULL), and we need not
	 * create a new outgoing sequence map. */
	if (!unmap_ggsn)
		gtphub_map_seq(&p, sgsn, ggsn);
#endif

	return gtphub_write(&hub->to_ggsns[port_idx].ofd, &ggsn->addr,
			    (uint8_t*)p.data, p.data_len);
}

/* obsolete */
#if 0
static void gtphub_gc_peer(struct gtphub *hub, struct gtphub_peer *peer)
{
	struct gtphub_seqmap *m;
	struct gtphub_seqmap *n;
	llist_for_each_entry_safe(m, n, &peer->seqmap, entry) {
		if (m->expiry <= hub->now) {
			gtphub_seqmap_del(m);
			LOG("expired: %d: seq mapping from %s to %s: %d->%d\n",
			    (int)m->expiry,
			    osmo_sockaddr_to_str(&m->from->addr),
			    osmo_sockaddr_to_str(&peer->addr),
			    (int)m->from_seq, (int)m->peer_seq);
		}
		else {
			/* The seq mappings will always have monotonous expiry
			 * values. When we hit an unexpired entry, only more
			 * unexpired ones will follow. */
			break;
		}
	}
}
#endif

static void gtphub_gc_bind(struct gtphub *hub, struct gtphub_bind *b)
{
	struct gtphub_peer *p, *n;
	llist_for_each_entry_safe(p, n, &b->peers, entry) {

		if ((!p->ref_count)
		    && nr_map_empty(&p->seq_map)) {

			LOG("expired: peer %s\n",
			    osmo_sockaddr_to_str(&p->addr));
			gtphub_peer_del(p);
		}
	}
}

static void gtphub_gc_cb(void *data)
{
	int expired;
	struct gtphub *hub = data;
	time_t now;
	
	now = gtphub_now();

	expired = nr_map_expiry_tick(&hub->expire_seq_maps, now);
	/* ... */

	if (expired) {
		int i;
		for (i = 0; i < GTPH_PORT_N; i++) {
			gtphub_gc_bind(hub, &hub->to_sgsns[i]);
			gtphub_gc_bind(hub, &hub->to_ggsns[i]);
		}
	}

	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK, 0);
}

static void gtphub_gc_start(struct gtphub *hub)
{
	hub->gc_timer.cb = gtphub_gc_cb;
	hub->gc_timer.data = hub;

	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK, 0);
}

int gtphub_init(struct gtphub *hub, struct gtphub_cfg *cfg)
{
	int rc;
	gtphub_zero(hub);

	nr_map_expiry_init(&hub->expire_seq_maps, GTPH_SEQ_MAPPING_EXPIRY_SECS);

	int port_id;
	for (port_id = 0; port_id < GTPH_PORT_N; port_id++) {
		rc = gtphub_gtp_bind_init(&hub->to_ggsns[port_id],
					  &cfg->to_ggsns[port_id],
					  from_ggsns_read_cb, hub, port_id);
		if (rc) {
			LOGERR("Failed to bind for GGSNs (%s)\n",
			       gtphub_port_idx_names[port_id]);
			return rc;
		}

		rc = gtphub_gtp_bind_init(&hub->to_sgsns[port_id],
					  &cfg->to_sgsns[port_id],
					  from_sgsns_read_cb, hub, port_id);
		if (rc) {
			LOGERR("Failed to bind for SGSNs (%s)\n",
			       gtphub_port_idx_names[port_id]);
			return rc;
		}
	}

	/* These are separate loops for grouping of log output. */
	for (port_id = 0; port_id < GTPH_PORT_N; port_id++) {

		/* trigger only on the control port address. */
		if (cfg->sgsn_proxy[GTPH_PORT_CONTROL].addr_str) {
			struct gtphub_peer *sgsn = gtphub_peer_new(hub, &hub->to_sgsns[port_id]);
			struct gtphub_cfg_addr *addr = &cfg->sgsn_proxy[port_id];

			rc = osmo_sockaddr_init(&sgsn->addr,
						AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
						addr->addr_str,
						addr->port);
			if (rc) {
				LOGERR("Cannot resolve '%s port %d'\n",
				       addr->addr_str,
				       (int)addr->port);
				return rc;
			}

			hub->sgsn_proxy[port_id] = sgsn;

			/* This is *the* proxy SGSN. Make sure it is never expired. */
			gtphub_peer_ref_count_inc(sgsn);

			LOG("Using SGSN %s proxy %s port %d\n",
			    gtphub_port_idx_names[port_id],
			    addr->addr_str,
			    (int)addr->port);
		}
	}

	for (port_id = 0; port_id < GTPH_PORT_N; port_id++) {
		/* trigger only on the control port address. */
		if (cfg->ggsn_proxy[GTPH_PORT_CONTROL].addr_str) {
			struct gtphub_peer *ggsn = gtphub_peer_new(hub, &hub->to_ggsns[port_id]);
			struct gtphub_cfg_addr *addr = &cfg->ggsn_proxy[port_id];

			rc = osmo_sockaddr_init(&ggsn->addr,
						AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
						addr->addr_str,
						addr->port);
			if (rc) {
				LOGERR("Cannot resolve '%s port %d'\n",
				       addr->addr_str,
				       (int)addr->port);
				return rc;
			}

			hub->ggsn_proxy[port_id] = ggsn;

			/* This is *the* proxy GGSN. Make sure it is never expired. */
			gtphub_peer_ref_count_inc(ggsn);

			LOG("Using GGSN %s proxy %s port %d\n",
			    gtphub_port_idx_names[port_id],
			    addr->addr_str,
			    (int)addr->port);
		}
	}

	gtphub_gc_start(hub);
	return 0;
}

struct gtphub_peer *gtphub_peer_new(struct gtphub *hub, struct gtphub_bind *bind)
{
	struct gtphub_peer *n = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer);

	nr_map_init(&n->tei_map, &bind->teip, NULL);

	nr_pool_init(&n->seq_pool);
	nr_map_init(&n->seq_map, &n->seq_pool, &hub->expire_seq_maps);

	/* TODO use something random to pick the initial sequence nr.
	   0x6d31 produces the ASCII character sequence 'm1', currently used in
	   gtphub_nc_test.sh. */
	n->seq_pool.last_nr = 0x6d31 - 1;

	llist_add(&n->entry, &bind->peers);
	return n;
}

void gtphub_peer_del(struct gtphub_peer *peer)
{
	nr_map_del(&peer->seq_map);
	llist_del(&peer->entry);
	talloc_free(peer);
}


/* TODO move to osmocom/core/socket.c ? */
/* The caller is required to call freeaddrinfo(*result), iff zero is returned. */
/* use this in osmo_sock_init() to remove dup. */
static int _osmo_getaddrinfo(struct addrinfo **result,
			     uint16_t family, uint16_t type, uint8_t proto,
			     const char *host, uint16_t port)
{
	struct addrinfo hints;
	char portbuf[16];

	sprintf(portbuf, "%u", port);
	memset(&hints, '\0', sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 */
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = type;
		hints.ai_protocol = proto;
	}

	return getaddrinfo(host, portbuf, &hints, result);
}

/* TODO move to osmocom/core/socket.c ? */
int osmo_sockaddr_init(struct osmo_sockaddr *addr,
		       uint16_t family, uint16_t type, uint8_t proto,
		       const char *host, uint16_t port)
{
	struct addrinfo *res;
	int rc;
	rc = _osmo_getaddrinfo(&res, family, type, proto, host, port);

	if (rc != 0) {
		LOGERR("getaddrinfo returned error %d\n", (int)rc);
		return -EINVAL;
	}

	OSMO_ASSERT(res->ai_addrlen <= sizeof(addr->a));
	memcpy(&addr->a, res->ai_addr, res->ai_addrlen);
	addr->l = res->ai_addrlen;
	freeaddrinfo(res);

	return 0;
}

int osmo_sockaddr_to_strb(char *addr_str, size_t addr_str_len,
			  char *port_str, size_t port_str_len,
			  const struct osmo_sockaddr *addr,
			  int flags)
{
       int rc;

       rc = getnameinfo((struct sockaddr*)&addr->a, addr->l,
			addr_str, addr_str_len,
			port_str, port_str_len,
			flags);

       if (rc)
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address: %s: %s\n", gai_strerror(rc),
		    osmo_hexdump((uint8_t*)&addr->a, addr->l));

       return rc;
}

const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *addr)
{
	static char buf[256];
	char portbuf[6];
	if (osmo_sockaddr_to_strb(buf, sizeof(buf),
				  portbuf, sizeof(portbuf),
				  addr,
				  NI_NUMERICHOST | NI_NUMERICSERV))
		return NULL;

	char *pos = buf + strnlen(buf, sizeof(buf)-1);
	size_t len = sizeof(buf) - (pos - buf);

	snprintf(pos, len, " port %s", portbuf);
	buf[sizeof(buf)-1] = '\0';

	return buf;
}
