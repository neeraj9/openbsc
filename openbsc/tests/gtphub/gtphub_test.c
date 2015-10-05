/* Test the GTP hub */

/* (C) 2015 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmcom.de>
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

#include <stdio.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>

void *osmo_gtphub_ctx;

static void test_gtphub_api(void)
{
	OSMO_ASSERT(1);
}

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

static struct log_info info = {
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");

	test_gtphub_api();
	printf("Done\n");

	talloc_report_full(osmo_gtphub_ctx, stderr);
	return 0;
}

