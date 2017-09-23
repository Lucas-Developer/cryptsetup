/*
 * Token example for storing secondary passphrase in TPM using libnvcrypt
 * (custom nvcrypt token handler example)
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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <json-c/json.h>

#include "libcryptsetup.h"

/* missing include in libnvcrypt.h for NVRAM_INDEX */
#include <tss/tss_defines.h>
#include "libnvcrypt.h"

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

/*
 * user defined nvcrypt token open implementation
 *
 * It'll ask user for first part of passphrase and
 * append it with TPM secondary part. If the open
 * succeeds (returns 0) library will try to open
 * any keyslot assigned to this token with the passphrase
 * stored in buffer. The library will free the buffer
 * when no longer needed.
 */
static int nvcrypt_open(struct crypt_device *cd,
	int token, /* library fills with existing (active) token id it's about to use */
	char **buffer,
	size_t *buffer_len,
	void *usrptr) /* user pointer from crypt_activate_by_token(). NULL in case token id was set to CRYPT_ANY_TOKEN */
{
	enum json_tokener_error jerr;
	int r;
	json_object *jobj_token, *jobj;
	char *user_pass, query[128];
	const char *json;
	size_t user_pass_len;
	uint32_t nvkeyslot;

	/* get json string for token libcryptsetup is about to open */
	r = crypt_token_json_get(cd, token, &json);

	/* this assert is needless. it must be true and user should not need to check this */
	assert(r == token);

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token) {
		log_err("Failed to create json object from string");
		return -1;
	}

	/*
	 * I don't perform any checks for json fields on purpose.
	 * Since I registered token handler before any crypt_activate_by_token() calls
	 * The library would perform validation for me. See validate implementation below.
	 */
	json_object_object_get_ex(jobj_token, "nvindex", &jobj);
	if (NVRAM_INDEX != (uint32_t) json_object_get_int64(jobj)) {
		log_err("NVRAM index mismatch, aborting nvcrypt open");
		json_object_put(jobj_token);
		return -1;
	}

	/* same as above */
	json_object_object_get_ex(jobj_token, "nvkeyslot", &jobj);
	nvkeyslot = json_object_get_int64(jobj); /* validate will ensure it fits in uint32_t */
	json_object_put(jobj_token);

	snprintf(query, sizeof(query), "Enter user passphrase part for nvkeyslot %d:", nvkeyslot);
	r = tools_get_key(query, &user_pass, &user_pass_len, 0, 0, NULL, 0, 0, 0, cd);
	if (r) {
		return -1;
	}

	r = NV_password_appended(cd, nvkeyslot, user_pass, user_pass_len, buffer, buffer_len);
	crypt_safe_free(user_pass);

	return r;
}

/*
 * user defined nvcrypt token validate implementation
 *
 * Each token has two mandatory fileds, "type" field with string
 * and "keyslots" field with array of assigned keyslots to the token
 * (may be empty). The user defined validate function doesn't have
 * to check those two fields, library does it automatically for every
 * token in luks2 header (on crypt_load()).
 *
 * nvcrypt token has additional mandatory fields. The user defined
 * validate function needs to check those fields presence together
 * with type and value.
 *
 * If we register the user defined token handler for nvcrypt before
 * we call crypt_load(), library will validate all nvcrypt tokens
 * in metadata for correctness.
 *
 * The validation (if handler is registered) function is called also before
 * crypt_token_json_set() or before any other function that would trigger luks2
 * header write to disk.
 */
static int nvcrypt_validate(struct crypt_device *cd,
		const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj;
	int r = -1;
	int64_t tmp;

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token)
		return r;

	/* in this example nvcrypt token has to include "nvindex" field with uint32_t number */
	if (!json_object_object_get_ex(jobj_token, "nvindex", &jobj) || !json_object_is_type(jobj, json_type_int))
		goto out;

	/* json-c can't properly handle uint32 type. this is workaround */
	tmp = json_object_get_int64(jobj);
	if (tmp < 0 || tmp > UINT32_MAX)
		goto out;

	/* nvcrypt token has to include "nvkeyslot" field... */
	if (!json_object_object_get_ex(jobj_token, "nvkeyslot", &jobj) || !json_object_is_type(jobj, json_type_int))
		goto out;

	/*...check nvkeyslot is valid luks2 keyslot id */
	tmp = json_object_get_int(jobj);
	if (tmp >= 0 && tmp < crypt_keyslot_max(CRYPT_LUKS2))
		r = 0;

out:
	json_object_put(jobj_token);
	return r;
}

/*
 * User defined nvcrypt token buffer_free function.
 *
 * The library will call it to free buffer allocated in
 * nvcrypt open function when passphrase is no longer needed.
 */
static void nvcrypt_buffer_free(void *buffer, size_t buffer_len __attribute__((unused)))
{
	crypt_safe_free(buffer);
}

const crypt_token_handler nvcrypt_token = {
	.name  = "nvcrypt", /* mandatory */
	.open  = nvcrypt_open, /* mandatory */
	.buffer_free = nvcrypt_buffer_free, /* optional */
	.validate = nvcrypt_validate /* optional but recommended (see above) */
};


/* construct new nvcrypt token json */
static json_object *create_nvkeyslot_token(uint32_t nvindex, uint32_t nvkeyslot)
{
	json_object *jobj, *jobj_token = json_object_new_object();
	if (!jobj_token)
		return NULL;

	/* type is mandatory field in all tokens and must match handler name member */
	jobj = json_object_new_string("nvcrypt");
	if (!jobj) {
		json_object_put(jobj_token);
		return NULL;
	}
	json_object_object_add(jobj_token, "type", jobj);

	/* keyslots array is mandatory field in any token (may be empty aka no keyslot assigned to token) */
	jobj = json_object_new_array();
	if (!jobj) {
		json_object_put(jobj_token);
		return NULL;
	}
	json_object_object_add(jobj_token, "keyslots", jobj);

	/*
	 * following fields are optional (from luks2 POV)
	 * but mandatory for nvcrypt token validate function
	 */

	/* no uint32 support in json-c */
	jobj = json_object_new_int64(nvindex);
	if (!jobj) {
		json_object_put(jobj_token);
		return NULL;
	}
	json_object_object_add(jobj_token, "nvindex", jobj);

	jobj = json_object_new_int(nvkeyslot);
	if (!jobj) {
		json_object_put(jobj_token);
		return NULL;
	}
	json_object_object_add(jobj_token, "nvkeyslot", jobj);

	return jobj_token;
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
			 int keyslot)
{
	char *existing_pass, *user_pass, *complete_pass;
	json_object *jobj_token;
	int token, r;
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

	/* ask for existing keyslot passhrase */
	r = tools_get_key("Enter existing LUKS2 pasphrase:", &existing_pass, &existing_pass_len, 0, 0, NULL, 0, 0, 0, cd);
	if (r)
		return r;

	/* ask for new user passphrase (first half) */
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

	/*
	 * create nvcrypt token json object (may be string since crypt_token_json_set()
	 * requires string so that we don't enforce json library
	 */
	jobj_token = create_nvkeyslot_token(NVRAM_INDEX, keyslot);
	if (!jobj_token) {
		log_err("Failed to allocate nvkeyslot token with index %d.\n", keyslot);
		r = -1;
		goto err_nvks;
	}

	/* try to store nvcrypt token */
	token = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, json_object_to_json_string_ext(jobj_token, JSON_C_TO_STRING_PLAIN));
	json_object_put(jobj_token);
	if (r < 0)
		goto err_nvks;

	/* now store new nvcrypt enabled keyslot */
	r = crypt_keyslot_add_by_passphrase(cd, keyslot, existing_pass, existing_pass_len, complete_pass, complete_pass_len);
	if (r < 0)
		goto err_token;

	/* assing new keyslot to the nvcrypt token */
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
	 * CRYPT_ANY_SLOT set in 'keyslot' parameter. After all keyslot is supposed to be
	 * activated by nvcrypt token in this example.
	 */
	if (crypt_keyslot_set_priority(cd, keyslot, CRYPT_SLOT_PRIORITY_IGNORE) < 0)
		log_std("Warning: Failed to lower keyslot %d priority.\n", keyslot);

	return 0;

err_keyslot:
	crypt_keyslot_destroy(cd, keyslot);
err_token:
	crypt_token_json_set(cd, token, NULL);
err_nvks:
	crypt_safe_free(complete_pass);
	nv_keyslot_free(nvks);
err_existing_pass:
	crypt_safe_free(existing_pass);

	return r;
}

/* activation by token is trivial with nvcrypt token registered */
static int action_nvkeyslot_open(struct crypt_device *cd, const char *name)
{
	int r = crypt_activate_by_token(cd, name, CRYPT_ANY_TOKEN, NULL, 0);
	return r < 0 ? r : 0;
}

static int find_token_by_nvkeyslot(struct crypt_device *cd, uint32_t nvkeyslot)
{
	crypt_token_info token_info;
	enum json_tokener_error jerr;
	const char *json, *type;
	int i, r;
	json_object *jobj_token, *jobj;
	uint32_t tmp;

	for (i = 0; i < LUKS2_TOKEN_MAX; i++) {
		token_info = crypt_token_status(cd, i, &type);
		if (token_info != CRYPT_TOKEN_EXTERNAL || strcmp(type, "nvcrypt"))
			continue;

		r = crypt_token_json_get(cd, i, &json);
		assert(r == i);

		jobj_token = json_tokener_parse_verbose(json, &jerr);
		if (!jobj_token)
			return -1;

		/* with nvcrypt token handler registered we don't have to validate token json */
		json_object_object_get_ex(jobj_token, "nvkeyslot", &jobj);
		tmp = json_object_get_int64(jobj);

		json_object_put(jobj_token);

		if (tmp == nvkeyslot)
			break;
	}

	return i < LUKS2_TOKEN_MAX ? i : -1;
}

static int action_nvkeyslot_kill(struct crypt_device *cd, int nvkeyslot)
{
	struct nv_keyslot *nvks;
	int r = 0, token = find_token_by_nvkeyslot(cd, nvkeyslot);

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

	/* try to remove nvcrypt token from LUKS2 header */
	if (token < 0)
		log_std("No nvcrypt token for keyslot %d. Already removed?\n", nvkeyslot);
	else if (crypt_token_json_set(cd, token, NULL) != token) {
		log_err("Failed to erase nvcrypt token (id %d).\n", token);
		r = -1;
	}

	return crypt_keyslot_destroy(cd, nvkeyslot) ?: r;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage:\n"
                "%s <path> <action> [parameters]\n\n<action> descriptions:\n"
                "   add  [keyslot]: Add new TPM enabled keyslot, nvcrypt token and store additional data in TPM\n"
                "   open [name]   : Unlock (or test if no 'name' passed) TPM enabled keyslot and create dm-crypt mapping\n"
		"   kill keyslot  : erase data from TPM, kill keyslot and erase nvcrypt token associated with TPM enabled keyslot\n",
		prog);
}

int main(int argc, char **argv)
{
	int r = -1;
	struct crypt_device *cd;

	if (argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	crypt_set_debug_level(CRYPT_DEBUG_ALL);

	if (crypt_token_register(&nvcrypt_token)) {
		log_err("Failed to register nvcrypt token handler.\n");
		return EXIT_FAILURE;
	}

	if (crypt_init(&cd, argv[1])) {
		log_err("Failed to init device %s.\n", argv[1]);
		return EXIT_FAILURE;
	}

	if (crypt_load(cd, CRYPT_LUKS2, NULL)) {
		log_err("Failed to load luks2 device %s.\n", argv[1]);
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[2], "add"))
		r = action_nvkeyslot_add(cd, argv[1], argc > 3 ? atoi(argv[3]) : CRYPT_ANY_SLOT);
	else if (!strcmp(argv[2], "open"))
		r = action_nvkeyslot_open(cd, argc > 3 ? argv[3] : NULL);
	else if (!strcmp(argv[2], "kill") && argc > 3)
		r = action_nvkeyslot_kill(cd, atoi(argv[3]));
	else
		usage(argv[0]);

	crypt_free(cd);
	return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
