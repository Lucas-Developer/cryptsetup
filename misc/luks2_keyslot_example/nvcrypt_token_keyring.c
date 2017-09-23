/*
 * Token example for storing secondary passphrase in TPM using libnvcrypt
 * (lightweight example using builtin luks2 keyring token)
 *
 * Copyright (C) 2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2017, Ondrej Kozina <okozina@redhat.com>
 *
 * NV_password_appended() and NV_append_new_password() were adopted
 * from libnvcrypt project (contrib directory in source tree)
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "libcryptsetup.h"
#include "libnvcrypt.h"

typedef int32_t key_serial_t;

__attribute__((format(printf, 3, 4)))
static void logger(struct crypt_device *cd, int level, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0 ) {
		if (level >= 0)
			crypt_log(cd, level, target);
		else
			printf("# %s\n", target);
	}

	va_end(argp);
	free(target);
}

#define log_dbg(x...) logger(NULL, CRYPT_LOG_DEBUG, x)
#define log_std(x...) logger(NULL, CRYPT_LOG_NORMAL, x)
#define log_verbose(x...) logger(NULL, CRYPT_LOG_VERBOSE, x)
#define log_err(x...) logger(NULL, CRYPT_LOG_ERROR, x)
void tool_log(int level, const char *msg, void *usrptr);

void *crypt_safe_alloc(size_t size);
void crypt_safe_free(void *data);

int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  size_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd);

#define DEFAULT_PASSPHRASE_SIZE_MAX 512
#define LUKS2_TOKEN_MAX 32

static key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
        return syscall(__NR_add_key, type, description, payload, plen, keyring);
}

/*
 * slightly modified version of function originaly provided in
 * libnvcrypt project
 */
static int NV_append_new_password(struct crypt_device *ctx,
				  int keyIndex,
				  const char *password,
				  size_t password_len,
				  char **password2,
				  size_t *password2_len,
				  struct nv_keyslot **nvks)
{
	char *pw = NULL;
	size_t pw_len = 0;

	log_dbg("Initializing TPM NVRAM storage for saving a new second password");
	if (nv_initialize() < 0) {
		log_dbg("nvram initializiation failed");
		return -EINVAL;
	}

	if (password_len+NV_KEY_SIZE >= DEFAULT_PASSPHRASE_SIZE_MAX) {
		log_err("passphrase is too large for adding second passphrase from NVRAM\n");
		return -EINVAL;
	}

	struct nv_keyslot *ks = nv_keyslot_new(crypt_get_uuid(ctx), keyIndex);
	if (ks == NULL) {
		log_err("TPM NVRAM keyslot allocation failed\n");
		return -EINVAL;
	}

	pw = crypt_safe_alloc(DEFAULT_PASSPHRASE_SIZE_MAX);
	if (!pw) {
		nv_keyslot_free(ks);
		return -EINVAL;
	}

	strncpy(pw, password, DEFAULT_PASSPHRASE_SIZE_MAX);

	nv_keyslot_get_key(ks, (char *)&pw[password_len]);
	pw_len = password_len+NV_KEY_SIZE;

	*password2 = pw;
	*password2_len = pw_len;
	*nvks = ks;

	return 0;
}

static int NV_password_appended(struct crypt_device *ctx,
				int keyIndex,
				const char *password,
				size_t password_len,
				char **password2,
				size_t *password2_len)
{
	char *pw = NULL;
	size_t pw_len = 0;

	log_dbg("Initializing TPM NVRAM storage for reading a new second password");
	if (nv_initialize() < 0) {
		log_dbg("nvram initializiation failed");
		return -EINVAL;
	}

	if (password_len+NV_KEY_SIZE >= DEFAULT_PASSPHRASE_SIZE_MAX) {
		log_err("passphrase is too large for adding second passphrase from NVRAM\n");
		return -EINVAL;
	}

	struct nv_keyslot *ks = nv_keyslot_by_uuid(crypt_get_uuid(ctx), keyIndex);
	if (ks == NULL) {
		log_dbg("TPM NVRAM keyslot for uuid %s (index %d) not found",
			crypt_get_uuid(ctx), keyIndex);

		*password2 = NULL;
		*password2_len = 0;
		return -EINVAL;
	}

	pw = crypt_safe_alloc(DEFAULT_PASSPHRASE_SIZE_MAX);
	if (!pw) {
		return -EINVAL;
	}

	strncpy(pw, password, DEFAULT_PASSPHRASE_SIZE_MAX);
	pw_len = password_len;

	nv_keyslot_get_key(ks, (char *)&pw[password_len]);
	pw_len = password_len+NV_KEY_SIZE;

	nv_keyslot_free(ks);

	*password2 = pw;
	*password2_len = pw_len;

	return 0;
}

static int find_free_keyslot(struct crypt_device *cd)
{
	int i;

	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++)
		if (crypt_keyslot_status(cd, i) == CRYPT_SLOT_INACTIVE) {
			log_dbg("Found free slot %d", i);
			return i;
		}

	return -1;
}

int action_nvkeyslot_add(struct crypt_device *cd,
			 const char *device,
			 int token,
			 int keyslot)
{
	char *existing_pass, *user_pass, *complete_pass;
	int r;
	size_t existing_pass_len, user_pass_len, complete_pass_len;
	struct nv_keyslot *nvks, *oldnvks;

	/* find free slot (we need to know keyslot number) */
	if (keyslot == CRYPT_ANY_SLOT)
		keyslot = find_free_keyslot(cd);
	if (keyslot < 0)
		return -1;
	else if (crypt_keyslot_status(cd, keyslot) != CRYPT_SLOT_INACTIVE) {
		log_err("Keyslot %d is not free.\n", keyslot);
		return -1;
	}

	if (token < 0) {
		log_err("Invalid token value.\n");
		return -1;
	}

	/* ask for existing keyslot passhrase */
	r = tools_get_key("Enter existing LUKS2 pasphrase:", &existing_pass, &existing_pass_len, 0, 0, NULL, 0, 0, 0, cd);
	if (r)
		return r;

	/* ask for new passphrase (first half) */
	r = tools_get_key("Enter new passphrase for TPM enabled keyslot:", &user_pass, &user_pass_len, 0, 0, NULL, 0, 0, 0, cd);
	if (r)
		goto err_existing_pass;

	/* append passphrase with random data to be stored in TPM (second half of new passphrase) */
	r = NV_append_new_password(cd, keyslot, user_pass, user_pass_len, &complete_pass, &complete_pass_len, &nvks);
	crypt_safe_free(user_pass);
	if (r)
		goto err_existing_pass;

	/* remove (if exists) orphan nv keyslot clashing with current keyslot */
	oldnvks = nv_keyslot_by_uuid(crypt_get_uuid(cd), keyslot);
	if (oldnvks) {
		log_dbg("Old data found in TPM");
		nv_keyslot_remove(oldnvks);
		nv_keyslot_free(oldnvks);
	}

	r = crypt_keyslot_add_by_passphrase(cd, keyslot, existing_pass, existing_pass_len, complete_pass, complete_pass_len);
	if (r < 0)
		goto err_nvks;

	/*
	 * Assign the new keyslot to designated token. Later, cryptsetup open
	 * (before asking for passphrase) first tries to unlock keyslot
	 * (CRYPT_SLOT_ANY or specific one) iterating over all active tokens.
	 * This is how autoactivation works using cryptsetup utility. (Or see
	 * crypt_activate_by_token() API). Token is expected to exist.
	 */
	r = crypt_token_assign_keyslot(cd, token, keyslot);
	if (r < 0) {
		log_err("Failed to assign keyslot %d to token %d.\n", keyslot, token);
		goto err_keyslot;
	}

	r = nv_keyslot_save(nvks);
	if (r < 0) {
		log_err("saving keyslot in TPM NVRAM failed\n");
		goto err_keyslot;
	}
	log_dbg("new second password for device with uuid %s (index %d) saved",
		crypt_get_uuid(cd), keyslot);

	crypt_safe_free(existing_pass);
	crypt_safe_free(complete_pass);
	nv_keyslot_free(nvks);

	/*
	 * Lower TPM enabled keyslot priority. It's optional step but it makes the keyslot
	 * ignored by library when crypt_keyslot_activate_by_passphrase() & co is called with
	 * CRYPT_ANY_SLOT set in 'keyslot' parameter.
	 */
	if (crypt_keyslot_set_priority(cd, keyslot, CRYPT_SLOT_PRIORITY_IGNORE) < 0)
		log_std("Warning: Failed to lower keyslot %d priority.\n", keyslot);

	return 0;

err_keyslot:
	crypt_keyslot_destroy(cd, keyslot);
err_nvks:
	crypt_safe_free(complete_pass);
	nv_keyslot_free(nvks);
err_existing_pass:
	crypt_safe_free(existing_pass);

	return r;
}

static int action_nvkeyslot_load_passphrase(struct crypt_device *cd, int keyslot, int token)
{
	char *user_pass, *complete_pass, query[128];
	int r;
	size_t user_pass_len, complete_pass_len;
	key_serial_t kid;
	struct crypt_token_params_luks2_keyring params;

	if (keyslot < 0)
		return -EINVAL;

	/*
	 * Read builtin luks2 keyring token parameters
	 * (currently only key_description is stored).
	 */
	if (crypt_token_luks2_keyring_get(cd, token, &params) < 0)
		return -EINVAL;

	snprintf(query, sizeof(query), "Enter user passphrase part for nvkeyslot %d:", keyslot);
	r = tools_get_key(query, &user_pass, &user_pass_len, 0, 0, NULL, 0, 0, 0, cd);
	if (r < 0)
		return r;

	r = NV_password_appended(cd, keyslot, user_pass, user_pass_len, &complete_pass, &complete_pass_len);
	crypt_safe_free(user_pass);
	if (r)
		return r;

	kid = add_key("user", params.key_description, complete_pass, complete_pass_len, KEY_SPEC_SESSION_KEYRING);
	crypt_safe_free(complete_pass);

	return kid < 0 ? -EINVAL : 0;
}

static int action_nvkeyslot_kill(struct crypt_device *cd, int nvkeyslot)
{
	struct nv_keyslot *nvks;
	int r = 0;

	if (nv_initialize())
		return -1;

	/* try to remove nvkeyslot from NVRAM in TPM */
	nvks = nv_keyslot_by_uuid(crypt_get_uuid(cd), nvkeyslot);
	if (!nvks)
		log_std("No nvkeyslot in TPM with id %d and uuid: %s. Already removed?\n", nvkeyslot, crypt_get_uuid(cd));
	else {
		if (nv_keyslot_remove(nvks)) {
			log_err("Failed to remove nvkeyslot id %d (uuid: %s) from TPM.\n", nvkeyslot, crypt_get_uuid(cd));
			r = -1;
		}
		nv_keyslot_free(nvks);
	}

	return crypt_keyslot_destroy(cd, nvkeyslot) ?: r;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage:\n"
                "%s <path> <action> [parameters]\n\n<action> descriptions:\n"
                "   add token [keyslot] : Add new TPM enabled keyslot, store additional data in TPM and assign the keyslot\n"
                "                         to builtin luks2 keyring token\n"
                "   load keyslot token  : Load TPM enabled keyslot passphrase (both parts) in kernel keyring (key description is extracted from token)\n"
		"   kill keyslot        : erase data from TPM and kill keyslot\n",
		prog);
}

int main(int argc, char **argv)
{
	int r = -1;
	struct crypt_device *cd;

	if (argc < 4) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	crypt_set_debug_level(CRYPT_DEBUG_ALL);

	if (crypt_init(&cd, argv[1])) {
		log_err("Failed to init device %s.\n", argv[1]);
		return EXIT_FAILURE;
	}

	if (crypt_load(cd, CRYPT_LUKS2, NULL)) {
		log_err("Failed to load luks2 device %s.\n", argv[1]);
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[2], "add") && argc > 3)
		r = action_nvkeyslot_add(cd, argv[1], atoi(argv[3]), argc > 4 ? atoi(argv[4]) : CRYPT_ANY_SLOT);
	else if (!strcmp(argv[2], "load") && argc > 4)
		r = action_nvkeyslot_load_passphrase(cd, atoi(argv[3]), atoi(argv[4]));
	else if (!strcmp(argv[2], "kill") && argc > 3)
		r = action_nvkeyslot_kill(cd, atoi(argv[3]));
	else
		usage(argv[0]);

	crypt_free(cd);
	return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
