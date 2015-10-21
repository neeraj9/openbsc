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

#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>


/* support */

/* TODO move to osmocom/core/socket.c ? */
#include <netdb.h> /* for IPPROTO_* etc */
struct osmo_sockaddr {
	struct sockaddr_storage a;
	socklen_t l;
};

/* TODO move to osmocom/core/socket.c ? */
/*! \brief Initialize a sockaddr
 * \param[out] addr  Valid osmo_sockaddr pointer to write result to
 * \param[in] family  Address Family like AF_INET, AF_INET6, AF_UNSPEC
 * \param[in] type  Socket type like SOCK_DGRAM, SOCK_STREAM
 * \param[in] proto  Protocol like IPPROTO_TCP, IPPROTO_UDP
 * \param[in] host Remote host name or IP address in string form
 * \param[in] port Remote port number in host byte order
 * \returns 0 on success, otherwise an error code (from getaddrinfo()).
 *
 * Copy the first result from a getaddrinfo() call with the given parameters to
 * *addr and *addr_len. On error, do not change *addr and return nonzero.
 */
int osmo_sockaddr_init(struct osmo_sockaddr *addr,
		       uint16_t family, uint16_t type, uint8_t proto,
		       const char *host, uint16_t port);

/*! \brief convert sockaddr to human readable string.
 * \param[out] addr_str  Valid pointer to a buffer of length addr_str_len.
 * \param[in] addr_str_len  Size of buffer addr_str points at.
 * \param[out] port_str  Valid pointer to a buffer of length port_str_len.
 * \param[in] port_str_len  Size of buffer port_str points at.
 * \param[in] addr  Binary representation as returned by osmo_sockaddr_init().
 * \param[in] flags  flags as passed to getnameinfo().
 * \returns  0 on success, an error code on error.
 *
 * Return the IPv4 or IPv6 address string and the port (a.k.a. service) string
 * representations of the given struct osmo_sockaddr in two caller provided
 * char buffers. Flags of (NI_NUMERICHOST | NI_NUMERICSERV) return numeric
 * address and port. Either one of addr_str or port_str may be NULL, in which
 * case nothing is returned there.
 *
 * See also osmo_sockaddr_to_str() (less flexible, but much more convenient). */
int osmo_sockaddr_to_strb(char *addr_str, size_t addr_str_len,
			  char *port_str, size_t port_str_len,
			  const struct osmo_sockaddr *addr,
			  int flags);

/*! \brief conveniently return osmo_sockaddr_to_strb() in a static buffer.
 * \param[in] addr  Binary representation as returned by osmo_sockaddr_init().
 * \returns  Address string in static buffer.
 *
 * Compose a string of the numeric IP-address and port represented by *addr of
 * the form "<ip-addr> port <port>". The returned string is valid until the
 * next invocation of this function.
 */
const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *addr);


/* general */

enum gtphub_port_idx {
	GTPH_PORT_CONTROL = 0,
	GTPH_PORT_USER = 1,
	GTPH_PORT_N
};

extern const char* const gtphub_port_idx_names[GTPH_PORT_N];


typedef int nr_t;

/* Generator for unused numbers. So far this counts upwards from zero, but the
 * implementation may change in the future. Treat this like an opaque struct. */
struct nr_pool {
	nr_t last_nr;
};

void nr_pool_init(struct nr_pool *pool);

/* Return the next unused number from the nr_pool. */
nr_t nr_pool_next(struct nr_pool *pool);


struct nr_mapping {
	struct llist_head entry;

	nr_t orig;
	nr_t repl;
};

struct nr_map {
	struct nr_pool *pool; /* multiple nr_maps can share a nr_pool. */
	struct llist_head mappings;
};

/* Initialize an (already allocated) nr_map, and set the map's number pool.
 * Multiple nr_map instances may use the same nr_pool. */
void nr_map_init(struct nr_map *map, struct nr_pool *pool);

/* Return a known mapping from nr_orig. If nr_orig is unknown, return NULL. */
struct nr_mapping *nr_map_get(const struct nr_map *map, nr_t nr_orig);

/* Return a known mapping to nr_repl. If nr_repl is unknown, return NULL. */
struct nr_mapping *nr_map_get_inv(const struct nr_map *map, nr_t nr_repl);

/* Remove the given mapping from its parent map. */
void nr_mapping_del(struct nr_mapping *mapping);

/* Initialize the nr_mapping to zero/empty values. */
void nr_mapping_init(struct nr_mapping *mapping);

/* Add a new entry to the map. mapping->orig and mapping->del_cb must be set
 * before calling this function. The remaining fields of *mapping will be
 * overwritten. */
void nr_map_add(struct nr_map *map, struct nr_mapping *mapping);


/* config */

struct gtphub_cfg_addr {
	const char *addr_str;
	uint16_t port;
};

struct gtphub_cfg_bind {
	struct gtphub_cfg_addr bind;
};

struct gtphub_cfg {
	struct gtphub_cfg_bind to_sgsns[GTPH_PORT_N];
	struct gtphub_cfg_bind to_ggsns[GTPH_PORT_N];
	struct gtphub_cfg_addr sgsn_proxy[GTPH_PORT_N];
	struct gtphub_cfg_addr ggsn_proxy[GTPH_PORT_N];
};


/* state */

struct gtphub_peer {
	struct llist_head entry;

	struct osmo_sockaddr addr;
	struct nr_map teim;
	uint16_t next_peer_seq; /* the latest used sequence nr + 1 */
	struct llist_head seqmap; /* of struct gtphub_seqmap */
	unsigned int ref_count; /* references from other peers' seq_maps */
};

struct gtphub_seqmap {
	struct llist_head entry;

	uint16_t peer_seq; /* the new seq nr going out to the peer */
	struct gtphub_peer *from;
	uint16_t from_seq;
	time_t expiry;
};

struct gtphub_bind {
	struct osmo_fd ofd;
	struct nr_pool teip;

	/* list of struct gtphub_peer */
	struct llist_head peers;
};

struct gtphub {
	struct gtphub_bind to_sgsns[GTPH_PORT_N];
	struct gtphub_bind to_ggsns[GTPH_PORT_N];

	/* pointers to an entry of to_sgsns[x].peers */
	struct gtphub_peer *sgsn_proxy[GTPH_PORT_N];

	/* pointers to an entry of to_ggsns[x].peers */
	struct gtphub_peer *ggsn_proxy[GTPH_PORT_N];

	struct osmo_timer_list gc_timer;

	time_t now;
};


/* api */

int gtphub_vty_init(void);
int gtphub_cfg_read(struct gtphub_cfg *cfg, const char *config_file);

void gtphub_zero(struct gtphub *hub);
int gtphub_init(struct gtphub *hub, struct gtphub_cfg *cfg);

/* Create a new gtphub_peer instance added to peers_list.
 * Initialize to all-zero. Return a pointer to the new instance, or NULL on
 * error. */
struct gtphub_peer *gtphub_peer_new(struct gtphub_bind *bind);

/* Remove a gtphub_peer from its list and free it. */
void gtphub_peer_del(struct gtphub_peer *peer);

