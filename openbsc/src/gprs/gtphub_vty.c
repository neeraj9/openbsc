/* (C) 2015 by sysmocom s.f.m.c. GmbH
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
 *
 */

#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/vty/command.h>

#include <openbsc/vty.h>
#include <openbsc/gtphub.h>

static struct gtphub_cfg *g_cfg = 0;

static struct cmd_node gtphub_node = {
	GTPHUB_NODE,
	"%s(config-gtphub)# ",
	1,
};

#define GTPH_DEFAULT_CONTROL_PORT 2123
#define GTPH_DEFAULT_USER_PORT 2152

static void write_addrs(struct vty *vty, const char *name,
			struct gtphub_cfg_addr *c, struct gtphub_cfg_addr *u)
{
	if ((c->port == GTPH_DEFAULT_CONTROL_PORT)
	    && (u->port == GTPH_DEFAULT_USER_PORT)
	    && (strcmp(c->addr_str, u->addr_str) == 0)) {
		/* Default port numbers and same IP address: write "short"
		 * variant. */
		vty_out(vty, " %s %s%s",
			name,
			c->addr_str,
			VTY_NEWLINE);
		return;
	}

	vty_out(vty, " %s ctrl %s %d user %s %d%s",
		name,
		c->addr_str, (int)c->port,
		u->addr_str, (int)u->port,
		VTY_NEWLINE);
}

static int config_write_gtphub(struct vty *vty)
{
	vty_out(vty, "gtphub%s", VTY_NEWLINE);

	write_addrs(vty, "bind-to-sgsns",
		    &g_cfg->to_sgsns[GTPH_PORT_CONTROL].bind,
		    &g_cfg->to_sgsns[GTPH_PORT_USER].bind);

	write_addrs(vty, "bind-to-ggsns",
		    &g_cfg->to_ggsns[GTPH_PORT_CONTROL].bind,
		    &g_cfg->to_ggsns[GTPH_PORT_USER].bind);

	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub, cfg_gtphub_cmd,
      "gtphub",
      "Configure the GTP hub")
{
	vty->node = GTPHUB_NODE;
	return CMD_SUCCESS;
}

#define BIND_ARGS  "ctrl ADDR <0-65535> user ADDR <0-65535>"
#define BIND_DOCS  \
	"Set GTP-C bind\n" \
	"GTP-C local IP address (v4 or v6)\n" \
	"GTP-C local port\n" \
	"Set GTP-U bind\n" \
	"GTP-U local IP address (v4 or v6)\n" \
	"GTP-U local port\n"


DEFUN(cfg_gtphub_bind_to_sgsns_short, cfg_gtphub_bind_to_sgsns_short_cmd,
	"bind-to-sgsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for SGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for (i = 0; i < GTPH_PORT_N; i++)
		g_cfg->to_sgsns[i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_sgsns[GTPH_PORT_CONTROL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_sgsns[GTPH_PORT_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_ggsns_short, cfg_gtphub_bind_to_ggsns_short_cmd,
	"bind-to-ggsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for GGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for (i = 0; i < GTPH_PORT_N; i++)
		g_cfg->to_ggsns[i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_ggsns[GTPH_PORT_CONTROL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_ggsns[GTPH_PORT_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}


static int handle_binds(struct gtphub_cfg_bind *b, const char **argv)
{
	b[GTPH_PORT_CONTROL].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	b[GTPH_PORT_CONTROL].bind.port = atoi(argv[1]);
	b[GTPH_PORT_USER].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	b[GTPH_PORT_USER].bind.port = atoi(argv[3]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_sgsns, cfg_gtphub_bind_to_sgsns_cmd,
	"bind-to-sgsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for SGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_sgsns, argv);
}

DEFUN(cfg_gtphub_bind_to_ggsns, cfg_gtphub_bind_to_ggsns_cmd,
	"bind-to-ggsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for GGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_ggsns, argv);
}

DEFUN(show_gtphub, show_gtphub_cmd, "show gtphub",
      SHOW_STR "Display information about the GTP hub")
{
	vty_out(vty, "gtphub has nothing to say yet%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


int gtphub_vty_init(void)
{
	install_element_ve(&show_gtphub_cmd);

	install_element(CONFIG_NODE, &cfg_gtphub_cmd);
	install_node(&gtphub_node, config_write_gtphub);
	vty_install_default(GTPHUB_NODE);

	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_cmd);

	return 0;
}

int gtphub_cfg_read(struct gtphub_cfg *cfg, const char *config_file)
{
	int rc;

	g_cfg = cfg;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
