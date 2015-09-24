/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
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
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>

#include <unistd.h>

void *tall_bsc_ctx;

const char *gtphub_copyright =
	"Copyright (C) 2015 sysmocom s.m.f.c GmbH <info@sysmocom.de>\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

#define GTP_PORT 3386

// TODO decide whether to move to libosmocore, and use in osmo_sock_init() to
// remove dup.
/*! \brief Initialize an addrinfo
 *  \param[out] addr pointer to an addrinfo pointer to set to the result.
 *  \param[in] family Address Family like AF_INET, AF_INET6, AF_UNSPEC
 *  \param[in] type Socket type like SOCK_DGRAM, SOCK_STREAM
 *  \param[in] proto Protocol like IPPROTO_TCP, IPPROTO_UDP
 *  \param[in] host remote host name or IP address in string form
 *  \param[in] port remote port number in host byte order
 *  \returns 0 on success, otherwise an error code (from getaddrinfo()).
 *
 * Fill a struct addrinfo according to the given parameters. The user must call
 * freeaddrinfo(addr) when done with addr.
 */
int osmo_addr_init(struct addrinfo **addr,
		   uint16_t family, uint16_t type, uint8_t proto,
		   const char *host, uint16_t port)
{
	struct addrinfo hints;
	int rc;
	char portbuf[16];

	sprintf(portbuf, "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
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

	rc = getaddrinfo(host, portbuf, &hints, addr);
	if (rc != 0) {
		perror("getaddrinfo returned NULL");
		return -EINVAL;
	}
}

int main(int argc, char **argv)
{
	int rc;
	uint16_t in_port = GTP_PORT;

	const char* to_addr_str = "localhost";
	uint16_t to_port = 1234;


	struct osmo_fd ofd = {0};
	rc = osmo_sock_init_ofd(&ofd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "localhost", in_port, OSMO_SOCK_F_BIND);
	if (rc < 1) {
		fprintf(stderr, "Cannot bind to port %d\n", in_port);
		exit(-1);
	}

	struct addrinfo *addr;

	rc = osmo_addr_init(&addr, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, to_addr_str, to_port);
	if (rc != 0) {
		fprintf(stderr, "Cannot resolve '%s:%d'\n", to_addr_str, to_port);
		exit(-1);
	}


	uint8_t buf[4096];

	printf("receiving on port %d ...\n", in_port);
	while (1) {

		errno = 0;
		ssize_t received = recv(ofd.fd, buf, sizeof(buf), 0);

		if (received <= 0) {
			if (errno == EAGAIN) {
				usleep(1000);
				continue;
			}
			fprintf(stderr, "error %s\n", strerror(errno));
			exit(-1);
		}

		printf("sending %d bytes to %s port %d ...\n", received, to_addr_str, to_port);
		ssize_t sent = sendto(ofd.fd, buf, received, 0, addr->ai_addr, addr->ai_addrlen);

		if (sent == -1) {
			fprintf(stderr, "error %s\n", strerror(errno));
			exit(-1);
		}

		if (sent != received)
			fprintf(stderr, "sent(%d) != received(%d)\n", (int)sent, (int)received);
		else
			printf("ok\n");
	}

	freeaddrinfo(addr);

	/* not reached */
	exit(0);
}
