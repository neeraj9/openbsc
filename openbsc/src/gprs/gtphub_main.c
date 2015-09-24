/* GTP Hub main program */

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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>

#include <gtp.h>

#include <unistd.h>

#define LOGERR(fmt, args...) \
	LOGP(DGTPHUB, LOGL_ERROR, fmt, ##args)

#define LOG(fmt, args...) \
	LOGP(DGTPHUB, LOGL_NOTICE, fmt, ##args)

extern void *osmo_gtphub_ctx;

/* TODO move to osmocom/core/socket.c ? */
#include <netdb.h>
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

/* TODO move to osmocom/core/socket.c ?
 * -- will actually disappear when the GGSNs are resolved by DNS. */
/*! \brief Initialize a sockaddr \param[out] addr valid sockaddr pointer to
 * write result to \param[out] addr_len valid pointer to write addr length to
 * \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 * \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM \param[in] proto
 * Protocol like IPPROTO_TCP, IPPROTO_UDP \param[in] host remote host name or
 * IP address in string form \param[in] port remote port number in host byte
 * order \returns 0 on success, otherwise an error code (from getaddrinfo()).
 *
 * Copy the first result from a getaddrinfo() call with the given parameters to
 * *addr and *addr_len. On error, do not change *addr and return nonzero.
 */
int osmo_sockaddr_init(struct sockaddr_storage *addr, socklen_t *addr_len,
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

	OSMO_ASSERT(res->ai_addrlen <= sizeof(*addr));
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	*addr_len = res->ai_addrlen;
	freeaddrinfo(res);

	return 0;
}


void *tall_bsc_ctx;

const char *gtphub_copyright =
	"Copyright (C) 2015 sysmocom s.m.f.c GmbH <info@sysmocom.de>\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

int gtphub_log_filter_fn(const struct log_context *ctx,
			 struct log_target *tar)
{
	return 0;
}

static const struct log_info gtphub_log_info = {
	.filter_fn = gtphub_log_filter_fn,
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

/* Recv datagram from from->fd, optionally write sender's address to *from_addr
 * and *from_addr_len, parse datagram as GTP, and forward on to to->fd using
 * *to_addr. to_addr may be NULL, if an address is set on to->fd. */
int gtp_relay(struct osmo_fd *from, struct sockaddr_storage *from_addr, socklen_t *from_addr_len,
	      struct osmo_fd *to, struct sockaddr_storage *to_addr, socklen_t to_addr_len)
{
	static uint8_t buf[4096];

	errno = 0;
	ssize_t received = recvfrom(from->fd, buf, sizeof(buf), 0,
				    (struct sockaddr*)from_addr, from_addr_len);

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

struct sockaddr_storage last_client_addr;
socklen_t last_client_addr_len;
struct sockaddr_storage server_addr;
socklen_t server_addr_len;

int clients_read_cb(struct osmo_fd *clients_ofd, unsigned int what)
{
	LOG("reading from clients socket\n");
	struct osmo_fd *server_ofd = clients_ofd->data;

	if (!(what & BSC_FD_READ))
		return 0;

	last_client_addr_len = sizeof(last_client_addr);
	return gtp_relay(clients_ofd, &last_client_addr, &last_client_addr_len,
			 server_ofd, &server_addr, server_addr_len);
}

int server_read_cb(struct osmo_fd *server_ofd, unsigned int what)
{
	LOG("reading from server socket\n");
	struct osmo_fd *clients_ofd = server_ofd->data;

	if (!(what & BSC_FD_READ))
		return 0;

	return gtp_relay(server_ofd, NULL, NULL,
			 clients_ofd, &last_client_addr, last_client_addr_len);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&gtphub_log_info);

	int rc;

	const char* clients_addr_str = "localhost";
	uint16_t clients_port = 3386;

	const char* server_addr_str = "localhost";
	uint16_t server_port = 1234;

	/* Which local interface to use to listen for the GTP server's
	 * responses */
	const char* server_rx_addr_str = "localhost";
	uint16_t server_rx_port = 4321;

	rc = osmo_sockaddr_init(&server_addr, &server_addr_len,
				AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, server_addr_str, server_port);
	if (rc != 0) {
		LOGERR("Cannot resolve '%s port %d'\n", server_addr_str, server_port);
		exit(-1);
	}

	struct osmo_fd clients_ofd;
	struct osmo_fd server_ofd;

	memset(&clients_ofd, 0, sizeof(clients_ofd));
	clients_ofd.when = BSC_FD_READ;
	clients_ofd.cb = clients_read_cb;
	clients_ofd.data = &server_ofd;

	rc = osmo_sock_init_ofd(&clients_ofd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, clients_addr_str, clients_port, OSMO_SOCK_F_BIND);
	if (rc < 1) {
		LOGERR("Cannot bind to %s port %d\n", clients_addr_str, clients_port);
		exit(-1);
	}

	memset(&server_ofd, 0, sizeof(server_ofd));
	server_ofd.when = BSC_FD_READ;
	server_ofd.cb = server_read_cb;
	server_ofd.data = &clients_ofd;

	rc = osmo_sock_init_ofd(&server_ofd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, server_rx_addr_str, server_rx_port, OSMO_SOCK_F_BIND);
	if (rc < 1) {
		LOGERR("Cannot bind to %s port %d\n", server_rx_addr_str, server_rx_port);
		exit(-1);
	}

	LOG("GTP server connection: %s port %d <--> %s port %d\n",
	    server_rx_addr_str, (int)server_rx_port,
	    server_addr_str, (int)server_port);
	LOG("Listening for clients on %s port %d.\n", clients_addr_str, clients_port);

	int daemonize = 0;

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			LOGERR("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
