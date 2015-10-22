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
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>

#include <openbsc/gtphub.h>

void *osmo_gtphub_ctx;

/* TODO copied from libosmo-abis/src/subchan_demux.c, remove dup */
static int llist_len(struct llist_head *head)
{
	struct llist_head *entry;
	int i = 0;

	llist_for_each(entry, head)
		i++;

	return i;
}

static void nr_mapping_free(struct nr_mapping *m)
{
	talloc_free(m);
}

static struct nr_mapping *nr_mapping_alloc(void)
{
	struct nr_mapping *m;
	m = talloc(osmo_gtphub_ctx, struct nr_mapping);
	nr_mapping_init(m);
	m->del_cb = nr_mapping_free;
	return m;
}

static struct nr_mapping *nr_map_have(struct nr_map *map, nr_t orig, time_t now)
{
	struct nr_mapping *mapping;

	mapping = nr_map_get(map, orig);
	if (!mapping) {
		mapping = nr_mapping_alloc();
		mapping->orig = orig;
		nr_map_add(map, mapping, now);
	}

	return mapping;
}

static nr_t nr_map_get_repl(const struct nr_map *map, nr_t orig)
{
	struct nr_mapping *m;
	m = nr_map_get(map, orig);
	OSMO_ASSERT(m);
	return m->repl;
}

static nr_t nr_map_get_orig(const struct nr_map *map, nr_t repl)
{
	struct nr_mapping *m;
	m = nr_map_get_inv(map, repl);
	OSMO_ASSERT(m);
	return m->orig;
}


static void test_nr_map_basic(void)
{
	struct nr_pool _pool;
	struct nr_pool *pool = &_pool;
	struct nr_map _map;
	struct nr_map *map = &_map;

	nr_pool_init(pool);
	nr_map_init(map, pool, NULL);

	OSMO_ASSERT(llist_empty(&map->mappings));

#define TEST_N 100
#define TEST_I 123
	uint32_t i, check_i;
	uint32_t m[TEST_N];
	struct nr_mapping *mapping;

	/* create TEST_N mappings */
	for (i = 0; i < TEST_N; i++) {
		nr_t orig = TEST_I + i;
		mapping = nr_map_have(map, orig, 0);
		m[i] = mapping->repl;
		OSMO_ASSERT(m[i] != 0);
		OSMO_ASSERT(llist_len(&map->mappings) == (i+1));
		for (check_i = 0; check_i < i; check_i++)
			OSMO_ASSERT(m[check_i] != m[i]);
	}
	OSMO_ASSERT(llist_len(&map->mappings) == TEST_N);

	/* verify mappings */
	for (i = 0; i < TEST_N; i++) {
		nr_t orig = TEST_I + i;
		OSMO_ASSERT(nr_map_get_repl(map, orig) == m[i]);
		OSMO_ASSERT(nr_map_get_orig(map, m[i]) == orig);
	}

	/* remove all mappings */
	for (i = 0; i < TEST_N; i++) {
		OSMO_ASSERT(llist_len(&map->mappings) == (TEST_N - i));
		nr_t orig = TEST_I + i;
		nr_mapping_del(nr_map_get(map, orig));
	}
	OSMO_ASSERT(llist_empty(&map->mappings));
#undef TEST_N
#undef TEST_I
}

static int seqmap_is(struct nr_map *map, const char *str)
{
	static char buf[4096];
	char *pos = buf;
	size_t len = sizeof(buf);
	struct nr_mapping *m;
	llist_for_each_entry(m, &map->mappings, entry) {
		size_t wrote = snprintf(pos, len, "(%d->%d@%d), ",
					(int)m->orig,
					(int)m->repl,
					(int)m->expiry);
		OSMO_ASSERT(wrote < len);
		pos += wrote;
		len -= wrote;
	}
	*pos = '\0';

	if (strncmp(buf, str, sizeof(buf)) != 0) {
		printf("FAILURE: seqmap_is() mismatches expected value:\n"
		       "expected: %s\n"
		       "is:       %s\n",
		       str, buf);
		return 0;
	}
	return 1;
}

static void test_nr_map_expiry(void)
{
	struct nr_map_expiry expiry;
	struct nr_pool pool;
	struct nr_map map;
	int i;

	nr_map_expiry_init(&expiry, 30);
	nr_pool_init(&pool);
	nr_map_init(&map, &pool, &expiry);
	OSMO_ASSERT(seqmap_is(&map, ""));

	/* tick on empty map */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10000) == 0);
	OSMO_ASSERT(seqmap_is(&map, ""));

#define MAP1 \
	"(10->1@10040), " \
	""

#define MAP2 \
	"(20->2@10050), " \
	"(21->3@10051), " \
	"(22->4@10052), " \
	"(23->5@10053), " \
	"(24->6@10054), " \
	"(25->7@10055), " \
	"(26->8@10056), " \
	"(27->9@10057), " \
	""

#define MAP3 \
	"(420->10@10072), " \
	"(421->11@10072), " \
	"(422->12@10072), " \
	"(423->13@10072), " \
	"(424->14@10072), " \
	"(425->15@10072), " \
	"(426->16@10072), " \
	"(427->17@10072), " \
	""

	/* add mapping at time 10010. */
	nr_map_have(&map, 10, 10010);
	OSMO_ASSERT(seqmap_is(&map, MAP1));

	/* tick on unexpired item. */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10010) == 0);
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10011) == 0);
	OSMO_ASSERT(seqmap_is(&map, MAP1));

	/* Spread mappings at 10020, 10021, ... 10027. */
	for (i = 0; i < 8; i++)
		nr_map_have(&map, 20 + i, 10020 + i);
	OSMO_ASSERT(seqmap_is(&map, MAP1 MAP2));

	/* tick on unexpired items. */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10030) == 0);
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10039) == 0);
	OSMO_ASSERT(seqmap_is(&map, MAP1 MAP2));

	/* expire the first item (from 10010). */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10010 + 30) == 1);
	OSMO_ASSERT(seqmap_is(&map, MAP2));

	/* again nothing to expire */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10041) == 0);
	OSMO_ASSERT(seqmap_is(&map, MAP2));

	/* Mappings all at the same time. */
	for (i = 0; i < 8; i++)
		nr_map_have(&map, 420 + i, 10042);
	OSMO_ASSERT(seqmap_is(&map, MAP2 MAP3));

	/* Eight to expire, were added further above to be chronologically
	 * correct, at 10020..10027. */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10027 + 30) == 8);
	OSMO_ASSERT(seqmap_is(&map, MAP3));

	/* again nothing to expire */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10027 + 30) == 0);
	OSMO_ASSERT(seqmap_is(&map, MAP3));

	/* Eight to expire, from 10042. Now at 10042 + 30: */
	OSMO_ASSERT(nr_map_expiry_tick(&expiry, 10042 + 30) == 8);
	OSMO_ASSERT(seqmap_is(&map, ""));

#undef MAP1
#undef MAP2
#undef MAP3
}

static void test_seq_map(void)
{
	struct nr_pool _pool;
	struct nr_pool *pool = &_pool;

	struct nr_map _map;
	struct nr_map *map = &_map;

	nr_map_init(map, pool, NULL);

//	struct gtphub_seqmap *m = gtphub_seqmap_have(map, 123);

//	OSMO_ASSERT(m);
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

	test_nr_map_basic();
	test_nr_map_expiry();
	test_seq_map();
	printf("Done\n");

	talloc_report_full(osmo_gtphub_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(osmo_gtphub_ctx) == 1);
	return 0;
}

