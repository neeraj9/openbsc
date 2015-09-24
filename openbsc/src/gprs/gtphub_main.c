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

#define _GNU_SOURCE
#include <getopt.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

void *tall_bsc_ctx;

const char *gtphub_copyright =
	"Copyright (C) 2015 sysmocom s.m.f.c GmbH <info@sysmocom.de>\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

#define GTP_PORT 3386

/* Bind to UDP port <port> on interface <ifname>. Return the open file
 * descriptor. */
static int udp_sock(const char *ifname, uint16_t port)
{
	int fd, rc, bc = 1;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return fd;

	if (ifname) {
#ifdef __FreeBSD__
		rc = setsockopt(fd, SOL_SOCKET, IP_RECVIF, ifname,
				strlen(ifname));
#else
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen(ifname));
#endif
		if (rc < 0)
			goto err;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = INADDR_ANY;

	rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0)
		goto err;

	return fd;

err:
	close(fd);
	return rc;
}

int main(int argc, char **argv)
{
	int rc;
	uint16_t in_port = GTP_PORT;

	const char* to_addr_str = "127.0.0.1";
	uint16_t to_port = 1234;

	struct sockaddr_in to_sa;
	to_sa.sin_family = AF_INET;
	to_sa.sin_port = htons(to_port);
	rc = inet_pton(AF_INET, to_addr_str, &to_sa.sin_addr);
	if (rc != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", to_addr_str);
		exit(-1);
	}

	int udp_fd = udp_sock(NULL, in_port);

	uint8_t buf[4096];

	while (1) {
		printf("receiving on port %d ...\n", in_port);
		ssize_t received = recv(udp_fd, buf, sizeof(buf), 0);

		if (! received)
			continue;

		printf("sending %d bytes to %s:%d ...\n", received, to_addr_str, to_port);
		ssize_t sent = sendto(udp_fd, buf, received, 0, (struct sockaddr*)&to_sa, sizeof(to_sa));

		if (sent == -1)
			fprintf(stderr, "error %s\n", strerror(errno));

		if (sent != received)
			fprintf(stderr, "sent(%d) != received(%d)\n", (int)sent, (int)received);
		else
			printf("ok\n");
	}

	/* not reached */
	exit(0);
}
