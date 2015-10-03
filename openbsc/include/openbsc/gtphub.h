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


/* general */

enum gtphub_port_idx {
	GTPH_PORT_CONTROL = 0,
	GTPH_PORT_USER = 1,
	GTPH_PORT_N
};

extern const char* const gtphub_port_idx_names[GTPH_PORT_N];


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
};


/* state */

struct gtphub_addr {
	struct sockaddr_storage a;
	socklen_t l;
};

struct gtphub_peer {
	struct llist_head entry;

	struct gtphub_addr addr;
};

struct gtphub_bind {
	struct osmo_fd ofd;

	/* list of struct gtphub_peer */
	struct llist_head peers;
};

struct gtphub {
	struct gtphub_bind to_sgsns[GTPH_PORT_N];
	struct gtphub_bind to_ggsns[GTPH_PORT_N];
};


/* api */

void gtphub_zero(struct gtphub *hub);
int gtphub_init(struct gtphub *hub, struct gtphub_cfg *cfg);

/* Create a new gtphub_peer instance added to peers_list.
 * Initialize to all-zero. Return a pointer to the new instance, or NULL on
 * error. */
struct gtphub_peer *gtphub_peer_new(struct gtphub_bind *bind);

/* Remove a gtphub_peer from its list and free it. */
void gtphub_peer_del(struct gtphub_peer *peer);

