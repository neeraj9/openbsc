/* General IPA client.
 * ipa_client is ping/pong connection checking on an ipa_client_conn. */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Authors: Jacob Erlbeck, Neels Hofmeyr
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
#include <osmocom/core/timer.h>

#define IPA_CLIENT_RECONNECT_INTERVAL 10
#define IPA_CLIENT_PING_INTERVAL 20

struct msgb;
struct ipa_client_conn;
struct ipa_client;

typedef void (*ipa_client_updown_cb_t)(struct ipa_client *ipac, int up);

/* Expects message in msg->l2h */
typedef void (*ipa_client_read_cb_t)(struct ipa_client *ipac,
				     uint8_t proto,
				     uint8_t proto_ext,
				     struct msgb *msg);

struct ipa_client {
	ipa_client_updown_cb_t	updown_cb;
	ipa_client_read_cb_t	read_cb;
	void			*data;

	struct ipa_client_conn	*link;

	struct osmo_timer_list	ping_timer;
	struct osmo_timer_list	connect_timer;
	int			is_connected;
	int			got_ipa_pong;
};

struct ipa_client *ipa_client_create(const char *ip_addr,
				     unsigned int tcp_port,
				     ipa_client_updown_cb_t updown_cb,
				     ipa_client_read_cb_t read_cb,
				     void *data);

void ipa_client_destroy(struct ipa_client *ipac);
int ipa_client_send(struct ipa_client *ipac, uint8_t proto, uint8_t proto_ext, struct msgb *msg);
struct msgb *ipa_client_msgb_alloc(void);

