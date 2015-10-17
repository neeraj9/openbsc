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

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/signal.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

#include <openbsc/debug.h>
#include <openbsc/gtphub.h>
#include <openbsc/vty.h>

#include "../../bscconfig.h"

#define LOGERR(fmt, args...) \
	LOGP(DGTPHUB, LOGL_ERROR, fmt, ##args)

#define LOG(fmt, args...) \
	LOGP(DGTPHUB, LOGL_NOTICE, fmt, ##args)

#ifndef OSMO_VTY_PORT_GTPHUB
/* should come from libosmocore */
#define OSMO_VTY_PORT_GTPHUB	4253
#endif

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

void log_cfg(struct gtphub_cfg *cfg)
{
	struct gtphub_cfg_addr *a;
	a = &cfg->to_sgsns[GTPH_PORT_CONTROL].bind;
	LOG("to-SGSNs bind, Control: %s port %d\n",
	    a->addr_str, a->port);
	a = &cfg->to_sgsns[GTPH_PORT_USER].bind;
	LOG("to-SGSNs bind, User:    %s port %d\n",
	    a->addr_str, a->port);
	a = &cfg->to_ggsns[GTPH_PORT_CONTROL].bind;
	LOG("to-GGSNs bind, Control: %s port %d\n",
	    a->addr_str, a->port);
	a = &cfg->to_ggsns[GTPH_PORT_USER].bind;
	LOG("to-GGSNs bind, User:    %s port %d\n",
	    a->addr_str, a->port);
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(osmo_gtphub_ctx, stderr);
		break;
	default:
		break;
	}
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoGTPhub",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

struct cmdline_cfg {
	const char *config_file;
	int daemonize;
};

static void print_help(struct cmdline_cfg *ccfg)
{
	printf("gtphub commandline options\n");
	printf("  -h --help            This text.\n");
	printf("  -D --daemonize       Fork the process into a background daemon.\n");
	printf("  -d,--debug <cat>     Enable Debugging for this category.\n");
	printf("                       Pass '-d list' to get a category listing.\n");
	printf("  -s --disable-color");
	printf("  -c --config-file     The config file to use [%s].\n", ccfg->config_file);
	printf("  -e,--log-level <nr>  Set a global log level.\n");
}

static void list_categories(void)
{
	printf("Avaliable debug categories:\n");
	int i;
	for (i = 0; i < gtphub_log_info.num_cat; ++i) {
		if (!gtphub_log_info.cat[i].name)
			continue;

		printf("%s\n", gtphub_log_info.cat[i].name);
	}
}

static void handle_options(struct cmdline_cfg *ccfg, int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"log-level", 1, 0, 'e'},
			{NULL, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dc:sTe:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			//print_usage();
			print_help(ccfg);
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			if (strcmp("list", optarg) == 0) {
				list_categories();
				exit(0);
			}
			else
				log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			ccfg->daemonize = 1;
			break;
		case 'c':
			ccfg->config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		default:
			/* ignore */
			break;
		}
	}
}

int main(int argc, char **argv)
{
	int rc;

	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	osmo_init_logging(&gtphub_log_info);

	vty_info.copyright = gtphub_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(&gtphub_log_info);
        gtphub_vty_init();

	rate_ctr_init(osmo_gtphub_ctx);
	rc = telnet_init(osmo_gtphub_ctx, 0, OSMO_VTY_PORT_GTPHUB);
	if (rc < 0)
		exit(1);


	struct cmdline_cfg _ccfg = {
		.config_file = "./gtphub.conf"
	};
	struct cmdline_cfg *ccfg = &_ccfg;

	struct gtphub_cfg _cfg = {
	.to_sgsns = {
		{ .bind = {
				.addr_str = "127.0.0.3",
				.port = 2123,
			  } },
		{ .bind = {
				.addr_str = "127.0.0.3",
				.port = 2152,
			  } },
	},
	.to_ggsns = {
		{ .bind = {
				.addr_str = "127.0.0.4",
				.port = 2123,
			  } },
		{ .bind = {
				.addr_str = "127.0.0.4",
				.port = 2152,
			  } },
	},
	};
	struct gtphub_cfg *cfg = &_cfg;

	struct gtphub _hub;
	struct gtphub *hub = &_hub;

	handle_options(ccfg, argc, argv);

	rc = gtphub_cfg_read(cfg, ccfg->config_file);
	if (rc < 0) {
		LOGP(DGTPHUB, LOGL_FATAL, "Cannot parse config file '%s'\n", ccfg->config_file);
		exit(2);
	}

	if (gtphub_init(hub, cfg) != 0)
		return -1;

	/* TODO this will not be configured, gtphub will have to find the
	 * ggsns from incoming GTP PDUs. */
	/* Where the GTP ggsn sits that we're relaying for */
	const char* ggsn_addr_str = "127.0.0.2";
	uint16_t ggsn_port = 2123;
	struct gtphub_peer *test_ggsn = gtphub_peer_new(&hub->to_ggsns[GTPH_PORT_CONTROL]);
	rc = osmo_sockaddr_init(&test_ggsn->addr.a, &test_ggsn->addr.l,
				AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				ggsn_addr_str, ggsn_port);
	if (rc != 0) {
		LOGERR("Cannot resolve '%s port %d'\n", ggsn_addr_str, ggsn_port);
		exit(-1);
	}
	LOG("DEBUG: using GGSN %s port %d\n", ggsn_addr_str, ggsn_port);

	log_cfg(cfg);

	if (ccfg->daemonize) {
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
