/*
 * utils_pbkdf - PBKDF ssettings for libcryptsetup
 *
 * Copyright (C) 2009-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2017, Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <errno.h>

#include "internal.h"

const struct crypt_pbkdf_type default_luks2 = {
	.type = DEFAULT_LUKS2_PBKDF,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS2_ITER_TIME,
	.max_memory_kb = DEFAULT_LUKS2_MEMORY_KB,
	.parallel_threads = DEFAULT_LUKS2_PARALLEL_THREADS
};

const struct crypt_pbkdf_type default_luks1 = {
	.type = CRYPT_KDF_PBKDF2,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS1_ITER_TIME
};

/*
 * PBKDF configuration interface
 */
int verify_pbkdf_params(struct crypt_device *cd,
			const struct crypt_pbkdf_type *pbkdf)
{
	const char *pbkdf_type;
	int r = 0;

	if (!pbkdf->type || !pbkdf->hash || !pbkdf->time_ms)
		return -EINVAL;

	/* TODO: initialise crypto and check the hash and pbkdf are both available */
	r = crypt_parse_pbkdf(pbkdf->type, &pbkdf_type);
	if (r < 0) {
		log_err(cd, _("Unknown PBKDF type %s.\n"), pbkdf->type);
		return r;
	}

	if (crypt_get_type(cd) &&
	    !strcmp(crypt_get_type(cd), CRYPT_LUKS1) &&
	    strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
		log_err(cd, _("Requested PBKDF type is not supported for LUKS1.\n"));
		return -EINVAL;
	}

	if (!strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
		if (pbkdf->max_memory_kb || pbkdf->parallel_threads) {
			log_err(cd, _("PBKDF max memory or parallel threads must not be set with pbkdf2.\n"));
			return -EINVAL;
		}
		return 0;
	}

	if (pbkdf->max_memory_kb > MAX_PBKDF_MEMORY) {
		log_err(cd, _("Requested maximum PBKDF memory cost is too high (maximum is %d kilobytes).\n"),
			MAX_PBKDF_MEMORY);
		r = -EINVAL;
	}
	if (!pbkdf->max_memory_kb) {
		log_err(cd, _("Requested maximum PBKDF memory can not be zero.\n"));
		r = -EINVAL;
	}
	if (!pbkdf->parallel_threads) {
		log_err(cd, _("Requested PBKDF parallel threads can not be zero.\n"));
		r = -EINVAL;
	}
	if (!pbkdf->time_ms) {
		log_err(cd, _("Requested PBKDF target time can not be zero.\n"));
		r = -EINVAL;
	}

	return r;
}

int init_pbkdf_type(struct crypt_device *cd,
		    const struct crypt_pbkdf_type *pbkdf,
		    const char *dev_type)
{
	struct crypt_pbkdf_type *cd_pbkdf = crypt_get_pbkdf(cd);
	const char *hash, *type;
	unsigned cpus;
	uint32_t old_flags;
	int r;

	if (!pbkdf && dev_type && !strcmp(dev_type, CRYPT_LUKS2))
		pbkdf = &default_luks2;
	else if (!pbkdf)
		pbkdf = &default_luks1;

	r = verify_pbkdf_params(cd, pbkdf);
	if (r)
		return r;

	/*
	 * Crypto backend may be not initialized here,
	 * cannot check if algorithms are really available.
	 * It will fail later anyway :-)
	 */
	type = strdup(pbkdf->type);
	hash = strdup(pbkdf->hash);

	if (!type || !hash) {
		free(CONST_CAST(void*)type);
		free(CONST_CAST(void*)hash);
		return -ENOMEM;
	}

	free(CONST_CAST(void*)cd_pbkdf->type);
	free(CONST_CAST(void*)cd_pbkdf->hash);
	cd_pbkdf->type = type;
	cd_pbkdf->hash = hash;

	old_flags = cd_pbkdf->flags;
	cd_pbkdf->flags = pbkdf->flags;

	/* Reset iteration count so benchmark must run again. */
	if (cd_pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK)
		cd_pbkdf->iterations = pbkdf->iterations;
	else
		cd_pbkdf->iterations = 0;

	if (old_flags & CRYPT_PBKDF_ITER_TIME_SET)
		cd_pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;
	else
		cd_pbkdf->time_ms = pbkdf->time_ms;

	cd_pbkdf->max_memory_kb = pbkdf->max_memory_kb;
	cd_pbkdf->parallel_threads = pbkdf->parallel_threads;

	if (cd_pbkdf->parallel_threads > MAX_PBKDF_THREADS) {
		log_dbg("Maximum PBKDF threads is %d (requested %d).",
			MAX_PBKDF_THREADS, cd_pbkdf->parallel_threads);
		cd_pbkdf->parallel_threads = MAX_PBKDF_THREADS;
	}

	if (cd_pbkdf->parallel_threads) {
		cpus = crypt_cpusonline();
		if (cd_pbkdf->parallel_threads > cpus) {
			log_dbg("Only %u active CPUs detected, "
				"PBKDF threads decreased from %d to %d.",
				cpus, cd_pbkdf->parallel_threads, cpus);
			cd_pbkdf->parallel_threads = cpus;
		}
	}

	log_dbg("PBKDF %s, hash %s, time_ms %u (iterations %u), max_memory_kb %u, parallel_threads %u.",
		cd_pbkdf->type ?: "(none)", cd_pbkdf->hash ?: "(none)", cd_pbkdf->time_ms,
		cd_pbkdf->iterations, cd_pbkdf->max_memory_kb, cd_pbkdf->parallel_threads);

	return 0;
}

/* Libcryptsetup API */

int crypt_set_pbkdf_type(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf)
{
	if (!cd)
		return -EINVAL;

	if (!pbkdf)
		log_dbg("Resetting pbkdf type to default");

	crypt_get_pbkdf(cd)->flags = 0;

	return init_pbkdf_type(cd, pbkdf, crypt_get_type(cd));
}

const struct crypt_pbkdf_type *crypt_get_pbkdf_type(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	return crypt_get_pbkdf(cd)->type ? crypt_get_pbkdf(cd) : NULL;
}

void crypt_set_iteration_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	struct crypt_pbkdf_type *pbkdf;
	uint32_t old_time_ms;

	if (!cd || iteration_time_ms > UINT32_MAX)
		return;

	pbkdf = crypt_get_pbkdf(cd);
	old_time_ms = pbkdf->time_ms;
	pbkdf->time_ms = (uint32_t)iteration_time_ms;

	if (pbkdf->type && verify_pbkdf_params(cd, pbkdf)) {
		pbkdf->time_ms = old_time_ms;
		log_dbg("Invalid iteration time.");
		return;
	}

	pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;

	/* iterations must be benchmarked now */
	pbkdf->flags &= ~(CRYPT_PBKDF_NO_BENCHMARK);
	pbkdf->iterations = 0;

	log_dbg("Iteration time set to %" PRIu64 " miliseconds.", iteration_time_ms);
}
