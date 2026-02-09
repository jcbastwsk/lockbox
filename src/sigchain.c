/* https://www.youtube.com/watch?v=KDuJYFOi_3c */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Canonical JSON for signing ───────────────────────────────────── */
/*
 * Canonical form = JSON with sorted keys, no whitespace, "signature" field
 * stripped out. This is what gets signed. Important that we use JSON_SORT_KEYS
 * everywhere or verification breaks (learned this the hard way).
 */

static char *
link_canonical(json_t *link)
{
	/* Build a copy without "signature" */
	json_t *copy = json_deep_copy(link);
	json_object_del(copy, "signature");
	char *s = json_dumps(copy, JSON_SORT_KEYS | JSON_COMPACT);
	json_decref(copy);
	return s;
}

/* ── Init sigchain ────────────────────────────────────────────────── */

int
lb_sigchain_init(const uint8_t pk[LB_ED25519_PK_LEN],
                 const uint8_t sk[LB_ED25519_SK_LEN])
{
	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	char *b64_pk = lb_base64_encode(pk, LB_ED25519_PK_LEN);

	/* Build payload */
	json_t *payload = json_object();
	json_object_set_new(payload, "public_key", json_string(b64_pk));

	/* Build link (without signature) */
	json_t *link = json_object();
	json_object_set_new(link, "seqno", json_integer(1));
	json_object_set_new(link, "type", json_string(LB_LINK_KEY_CREATE));
	json_object_set_new(link, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(link, "payload", payload);
	json_object_set_new(link, "prev", json_null());

	/* Sign canonical form */
	char *canon = link_canonical(link);
	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)canon, strlen(canon), sk);
	free(canon);

	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);
	json_object_set_new(link, "signature", json_string(sig_b64));
	free(sig_b64);

	/* Wrap in array */
	json_t *chain = json_array();
	json_array_append_new(chain, link);

	char *s = json_dumps(chain, JSON_INDENT(2));
	lb_file_write(sc_path, (uint8_t *)s, strlen(s), 0644);
	free(s);
	json_decref(chain);
	free(b64_pk);
	free(sc_path);
	return 0;
}

/* ── Append to sigchain ───────────────────────────────────────────── */

int
lb_sigchain_append(const char *type, json_t *payload,
                   const uint8_t sk[LB_ED25519_SK_LEN])
{
	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	size_t sc_len;
	uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
	if (!sc_data)
		lb_die("sigchain not found (run 'lockbox init' first)");

	json_error_t err;
	json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
	free(sc_data);
	if (!chain || !json_is_array(chain))
		lb_die("corrupt sigchain");

	size_t last_idx = json_array_size(chain) - 1;
	json_t *last_link = json_array_get(chain, last_idx);

	/* Compute hash of previous link for prev pointer */
	char *prev_str = json_dumps(last_link, JSON_SORT_KEYS | JSON_COMPACT);
	uint8_t prev_hash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(prev_hash, (uint8_t *)prev_str, strlen(prev_str));
	free(prev_str);
	char *prev_b64 = lb_base64_encode(prev_hash, crypto_hash_sha256_BYTES);

	json_int_t seqno = json_integer_value(json_object_get(last_link, "seqno")) + 1;

	/* Build new link */
	json_t *link = json_object();
	json_object_set_new(link, "seqno", json_integer(seqno));
	json_object_set_new(link, "type", json_string(type));
	json_object_set_new(link, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(link, "payload", json_incref(payload));
	json_object_set_new(link, "prev", json_string(prev_b64));
	free(prev_b64);

	/* Sign */
	char *canon = link_canonical(link);
	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)canon, strlen(canon), sk);
	free(canon);

	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);
	json_object_set_new(link, "signature", json_string(sig_b64));
	free(sig_b64);

	json_array_append_new(chain, link);

	char *s = json_dumps(chain, JSON_INDENT(2));
	lb_file_write(sc_path, (uint8_t *)s, strlen(s), 0644);
	free(s);
	json_decref(chain);
	free(sc_path);
	return 0;
}

/* ── Show sigchain ────────────────────────────────────────────────── */

int
lb_sigchain_show(void)
{
	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	size_t sc_len;
	uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
	free(sc_path);

	if (!sc_data)
		lb_die("sigchain not found (run 'lockbox init' first)");

	json_error_t err;
	json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
	free(sc_data);

	if (!chain || !json_is_array(chain))
		lb_die("corrupt sigchain");

	size_t i;
	json_t *link;
	json_array_foreach(chain, i, link) {
		json_int_t seqno = json_integer_value(json_object_get(link, "seqno"));
		const char *type = json_string_value(json_object_get(link, "type"));
		json_int_t ts = json_integer_value(json_object_get(link, "timestamp"));

		char timebuf[64];
		time_t t = (time_t)ts;
		struct tm *tm = localtime(&t);
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

		printf("#%lld  %s  %s\n", (long long)seqno, type, timebuf);
	}

	json_decref(chain);
	return 0;
}

/* ── Verify sigchain ──────────────────────────────────────────────── */

int
lb_sigchain_verify(void)
{
	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	size_t sc_len;
	uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
	free(sc_path);

	if (!sc_data)
		lb_die("sigchain not found (run 'lockbox init' first)");

	json_error_t err;
	json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
	free(sc_data);

	if (!chain || !json_is_array(chain))
		lb_die("corrupt sigchain");

	size_t count = json_array_size(chain);
	if (count == 0)
		lb_die("empty sigchain");

	/* Extract public key from first link */
	json_t *first = json_array_get(chain, 0);
	const char *first_type = json_string_value(json_object_get(first, "type"));
	if (!first_type || strcmp(first_type, LB_LINK_KEY_CREATE) != 0)
		lb_die("first link must be key.create");

	json_t *first_payload = json_object_get(first, "payload");
	const char *pk_b64 = json_string_value(json_object_get(first_payload, "public_key"));
	if (!pk_b64)
		lb_die("first link missing public_key");

	uint8_t *pk;
	size_t pk_len;
	if (lb_base64_decode(pk_b64, &pk, &pk_len) != 0 || pk_len != LB_ED25519_PK_LEN)
		lb_die("invalid public key in sigchain");

	/* Verify each link */
	size_t i;
	json_t *link;
	json_t *prev_link = NULL;

	json_array_foreach(chain, i, link) {
		json_int_t seqno = json_integer_value(json_object_get(link, "seqno"));
		if (seqno != (json_int_t)(i + 1)) {
			fprintf(stderr, "lockbox: seqno mismatch at link %zu (expected %zu, got %lld)\n",
			        i, i + 1, (long long)seqno);
			free(pk);
			json_decref(chain);
			return 1;
		}

		/* Verify prev hash */
		if (i == 0) {
			json_t *prev = json_object_get(link, "prev");
			if (!json_is_null(prev)) {
				fprintf(stderr, "lockbox: first link prev must be null\n");
				free(pk);
				json_decref(chain);
				return 1;
			}
		} else {
			const char *prev_b64 = json_string_value(json_object_get(link, "prev"));
			if (!prev_b64) {
				fprintf(stderr, "lockbox: link %zu missing prev hash\n", i);
				free(pk);
				json_decref(chain);
				return 1;
			}

			/* Compute expected prev hash */
			char *prev_str = json_dumps(prev_link, JSON_SORT_KEYS | JSON_COMPACT);
			uint8_t expected_hash[crypto_hash_sha256_BYTES];
			crypto_hash_sha256(expected_hash, (uint8_t *)prev_str, strlen(prev_str));
			free(prev_str);

			char *expected_b64 = lb_base64_encode(expected_hash, crypto_hash_sha256_BYTES);
			if (strcmp(prev_b64, expected_b64) != 0) {
				fprintf(stderr, "lockbox: prev hash mismatch at link %zu\n", i);
				free(expected_b64);
				free(pk);
				json_decref(chain);
				return 1;
			}
			free(expected_b64);
		}

		/* Verify signature */
		const char *sig_b64 = json_string_value(json_object_get(link, "signature"));
		if (!sig_b64) {
			fprintf(stderr, "lockbox: link %zu missing signature\n", i);
			free(pk);
			json_decref(chain);
			return 1;
		}

		uint8_t *sig;
		size_t sig_len;
		if (lb_base64_decode(sig_b64, &sig, &sig_len) != 0 ||
		    sig_len != LB_ED25519_SIG_LEN) {
			fprintf(stderr, "lockbox: invalid signature at link %zu\n", i);
			free(pk);
			json_decref(chain);
			return 1;
		}

		char *canon = link_canonical(link);
		if (crypto_sign_verify_detached(sig, (uint8_t *)canon, strlen(canon), pk) != 0) {
			fprintf(stderr, "lockbox: signature verification FAILED at link %zu\n", i);
			free(canon);
			free(sig);
			free(pk);
			json_decref(chain);
			return 1;
		}
		free(canon);
		free(sig);

		prev_link = link;
	}

	printf("Sigchain OK (%zu links verified)\n", count);
	free(pk);
	json_decref(chain);
	return 0;
}
