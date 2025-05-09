/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <inttypes.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>

#include "contrib/files.h"
#include "knot/common/stats.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"

#define ARRAY_SIZE(array)       (sizeof(array) / sizeof((array)[0]))

struct {
	bool active_dumper;
	pthread_t dumper;
	uint32_t timer;
	server_t *server;
} stats = { 0 };

typedef struct {
	FILE *fd;
	const list_t *query_modules;
	const knot_dname_t *zone;
	bool zone_emitted;
} dump_ctx_t;

#define DUMP_STR(fd, level, name, ...) do { \
	fprintf(fd, "%-.*s"name": %s\n", level, "    ", ##__VA_ARGS__); \
	} while (0)
#define DUMP_CTR(fd, level, name, ...) do { \
	fprintf(fd, "%-.*s"name": %"PRIu64"\n", level, "    ", ##__VA_ARGS__); \
	} while (0)

uint64_t server_zone_count(server_t *server)
{
	return knot_zonedb_size(server->zone_db);
}

const char *server_stat_names[] = {
	"udp_received",
    "udp_async_done",
    "udp_no_req_obj",
	"udp_req_batch_limited",
	"tcp_accept",
    "tcp_received",
    "tcp_async_done",
    "tcp_no_req_obj",
	"tcp_multiple_req",
};

static uint64_t server_stat_counters[ARRAY_SIZE(server_stat_names)];

void server_stats_increment_counter(server_stats_counter_t counter, uint64_t value)
{
	assert(counter < server_stats_max);
	ATOMIC_ADD(server_stat_counters[counter], value);
}

const stats_item_t server_stats[] = {
	{ "zone-count", server_zone_count },
	{ 0 }
};

uint64_t stats_get_counter(uint64_t **stats_vals, uint32_t offset, unsigned threads)
{
	uint64_t res = 0;
	for (unsigned i = 0; i < threads; i++) {
		res += ATOMIC_GET(stats_vals[i][offset]);
	}
	return res;
}

static void dump_counters(FILE *fd, int level, mod_ctr_t *ctr, uint64_t **stats_vals, unsigned threads)
{
	for (uint32_t j = 0; j < ctr->count; j++) {
		uint64_t counter = stats_get_counter(stats_vals, ctr->offset + j, threads);

		// Skip empty counters.
		if (counter == 0) {
			continue;
		}

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(j, ctr->count);
			if (str != NULL) {
				DUMP_CTR(fd, level, "%s", str, counter);
				free(str);
			}
		} else {
			DUMP_CTR(fd, level, "%u", j, counter);
		}
	}
}

static void dump_modules(dump_ctx_t *ctx)
{
	int level = 0;
	knotd_mod_t *mod;
	WALK_LIST(mod, *ctx->query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		// Dump zone name.
		if (ctx->zone != NULL) {
			// Prevent from zone section override.
			if (!ctx->zone_emitted) {
				DUMP_STR(ctx->fd, 0, "zone", "");
				ctx->zone_emitted = true;
			}
			level = 1;

			knot_dname_txt_storage_t name;
			if (knot_dname_to_str(name, ctx->zone, sizeof(name)) == NULL) {
				return;
			}
			DUMP_STR(ctx->fd, level++, "\"%s\"", name, "");
		} else {
			level = 0;
		}

		unsigned threads = knotd_mod_threads(mod);

		// Dump module counters.
		DUMP_STR(ctx->fd, level, "%s", mod->id->name + 1, "");
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats_info + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			if (ctr->count == 1) {
				// Simple counter.
				uint64_t counter = stats_get_counter(mod->stats_vals,
				                                     ctr->offset, threads);
				DUMP_CTR(ctx->fd, level + 1, "%s", ctr->name, counter);
			} else {
				// Array of counters.
				DUMP_STR(ctx->fd, level + 1, "%s", ctr->name, "");
				dump_counters(ctx->fd, level + 2, ctr, mod->stats_vals, threads);
			}
		}
	}
}

static void zone_stats_dump(zone_t *zone, dump_ctx_t *ctx)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	ctx->query_modules = &zone->query_modules;
	ctx->zone = zone->name;

	dump_modules(ctx);
}

static void dump_to_file(FILE *fd, server_t *server)
{
	char date[64] = "";

	// Get formatted current time string.
	struct tm tm;
	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), KNOT_LOG_TIME_FORMAT, &tm);

	// Get the server identity.
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	const char *ident = conf_str(&val);
	if (ident == NULL || ident[0] == '\0') {
		ident = conf()->hostname;
	}

	// Dump record header.
	fprintf(fd,
	        "---\n"
	        "time: %s\n"
	        "identity: %s\n",
	        date, ident);

	// Dump server statistics.
	DUMP_STR(fd, 0, "server", "");
	for (const stats_item_t *item = server_stats; item->name != NULL; item++) {
		DUMP_CTR(fd, 1, "%s", item->name, item->val(server));
	}

	for(int i = 0; i < ARRAY_SIZE(server_stat_names); i++) {
		DUMP_CTR(fd, 1, "%s", server_stat_names[i], ATOMIC_GET(server_stat_counters[i]));
	}

	dump_ctx_t ctx = {
		.fd = fd,
		.query_modules = conf()->query_modules,
	};

	// Dump global statistics.
	dump_modules(&ctx);

	// Dump zone statistics.
	knot_zonedb_foreach(server->zone_db, zone_stats_dump, &ctx);
}

static void dump_stats(server_t *server)
{
	conf_t *pconf = conf();
	conf_val_t val = conf_get(pconf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	val = conf_get(pconf, C_STATS, C_FILE);
	char *file_name = conf_abs_path(&val, rundir);
	free(rundir);

	val = conf_get(pconf, C_STATS, C_APPEND);
	bool append = conf_bool(&val);

	// Open or create output file.
	FILE *fd = NULL;
	char *tmp_name = NULL;
	if (append) {
		fd = fopen(file_name, "a");
		if (fd == NULL) {
			log_error("stats, failed to append file '%s' (%s)",
			          file_name, knot_strerror(knot_map_errno()));
			free(file_name);
			return;
		}
	} else {
		int ret = open_tmp_file(file_name, &tmp_name, &fd,
		                        S_IRUSR | S_IWUSR | S_IRGRP);
		if (ret != KNOT_EOK) {
			log_error("stats, failed to open file '%s' (%s)",
			          file_name, knot_strerror(ret));
			free(file_name);
			return;
		}
	}
	assert(fd);

	// Dump stats into the file.
	dump_to_file(fd, server);

	fflush(fd);
	fclose(fd);

	// Switch the file contents.
	if (!append) {
		int ret = rename(tmp_name, file_name);
		if (ret != 0) {
			log_error("stats, failed to access file '%s' (%s)",
			          file_name, knot_strerror(knot_map_errno()));
			unlink(tmp_name);
		}
		free(tmp_name);
	}

	log_debug("stats, dumped into file '%s'", file_name);
	free(file_name);
}

static void *dumper(void *data)
{
	while (true) {
		assert(stats.timer > 0);
		sleep(stats.timer);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		rcu_read_lock();
		dump_stats(stats.server);
		rcu_read_unlock();
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}

	return NULL;
}

void stats_reconfigure(conf_t *conf, server_t *server)
{
	assert(server_stats_max == ARRAY_SIZE(server_stat_names)); // Ensure enum and names are setup consistently.
	if (conf == NULL || server == NULL) {
		return;
	}

	// Update server context.
	stats.server = server;

	conf_val_t val = conf_get(conf, C_STATS, C_TIMER);
	stats.timer = conf_int(&val);
	if (stats.timer > 0) {
		// Check if dumping is already running.
		if (stats.active_dumper) {
			return;
		}

		int ret = pthread_create(&stats.dumper, NULL, dumper, NULL);
		if (ret != 0) {
			log_error("stats, failed to launch periodic dumping (%s)",
			          knot_strerror(knot_map_errno_code(ret)));
		} else {
			stats.active_dumper = true;
		}
	// Stop current dumping.
	} else if (stats.active_dumper) {
		pthread_cancel(stats.dumper);
		pthread_join(stats.dumper, NULL);
		stats.active_dumper = false;
	}
}

void stats_deinit(void)
{
	if (stats.active_dumper) {
		pthread_cancel(stats.dumper);
		pthread_join(stats.dumper, NULL);
	}

	memset(&stats, 0, sizeof(stats));
}
