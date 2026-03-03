/* Encrypted keystore for managing external service keys */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Internal helpers ─────────────────────────────────────────────── */

static int
derive_store_key(uint8_t key_out[LB_KEY_LEN])
{
	lb_keypair_t kp;
	if (lb_keypair_load(&kp) != 0)
		return -1;

	/* Derive keystore encryption key from Ed25519 secret key via BLAKE2b */
	crypto_generichash(key_out, LB_KEY_LEN,
	                   kp.sk, LB_ED25519_SK_LEN,
	                   (const uint8_t *)"lockbox-keystore", 16);

	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

static json_t *
keystore_open(void)
{
	char *path = lb_data_path(LB_KEYSTORE_FILE);
	size_t flen;
	uint8_t *data = lb_file_read(path, &flen);
	free(path);

	if (!data) {
		/* No keystore yet — return empty structure */
		json_t *ks = json_object();
		json_object_set_new(ks, "version", json_integer(1));
		json_object_set_new(ks, "entries", json_array());
		return ks;
	}

	/* File format: nonce(24) || ciphertext(len - 24) */
	if (flen < LB_NONCE_LEN + LB_AEAD_TAG_LEN) {
		free(data);
		lb_warn("keystore file too small");
		return NULL;
	}

	uint8_t key[LB_KEY_LEN];
	if (derive_store_key(key) != 0) {
		free(data);
		return NULL;
	}

	uint8_t *nonce = data;
	uint8_t *ciphertext = data + LB_NONCE_LEN;
	size_t ct_len = flen - LB_NONCE_LEN;
	size_t pt_len = ct_len - LB_AEAD_TAG_LEN;

	uint8_t *plaintext = malloc(pt_len + 1);
	if (!plaintext) {
		sodium_memzero(key, sizeof(key));
		free(data);
		return NULL;
	}

	unsigned long long actual_pt_len;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
		plaintext, &actual_pt_len,
		NULL,
		ciphertext, ct_len,
		NULL, 0,
		nonce, key) != 0) {
		sodium_memzero(key, sizeof(key));
		free(plaintext);
		free(data);
		lb_warn("failed to decrypt keystore (wrong key?)");
		return NULL;
	}

	sodium_memzero(key, sizeof(key));
	free(data);

	plaintext[actual_pt_len] = '\0';

	json_error_t err;
	json_t *ks = json_loads((char *)plaintext, 0, &err);
	sodium_memzero(plaintext, actual_pt_len);
	free(plaintext);

	if (!ks) {
		lb_warn("corrupt keystore JSON");
		return NULL;
	}

	return ks;
}

static int
keystore_save(json_t *ks)
{
	char *json_str = json_dumps(ks, JSON_INDENT(2));
	if (!json_str) return -1;

	size_t pt_len = strlen(json_str);

	uint8_t key[LB_KEY_LEN];
	if (derive_store_key(key) != 0) {
		free(json_str);
		return -1;
	}

	/* nonce(24) || ciphertext(pt_len + 16) */
	size_t out_len = LB_NONCE_LEN + pt_len + LB_AEAD_TAG_LEN;
	uint8_t *out = malloc(out_len);
	if (!out) {
		sodium_memzero(key, sizeof(key));
		free(json_str);
		return -1;
	}

	uint8_t *nonce = out;
	uint8_t *ciphertext = out + LB_NONCE_LEN;

	randombytes_buf(nonce, LB_NONCE_LEN);

	unsigned long long ct_len;
	crypto_aead_xchacha20poly1305_ietf_encrypt(
		ciphertext, &ct_len,
		(uint8_t *)json_str, pt_len,
		NULL, 0,
		NULL,
		nonce, key);

	sodium_memzero(key, sizeof(key));
	sodium_memzero(json_str, pt_len);
	free(json_str);

	char *path = lb_data_path(LB_KEYSTORE_FILE);
	int rc = lb_file_write(path, out, LB_NONCE_LEN + (size_t)ct_len, 0600);
	free(path);
	free(out);

	return rc;
}

/* ── Public API ───────────────────────────────────────────────────── */

int
lb_keystore_add(const char *service, const char *label)
{
	json_t *ks = keystore_open();
	if (!ks)
		lb_die("failed to open keystore");

	json_t *entries = json_object_get(ks, "entries");
	if (!entries) {
		entries = json_array();
		json_object_set_new(ks, "entries", entries);
	}

	/* Generate an ID: service-<random> */
	uint8_t rand_bytes[4];
	randombytes_buf(rand_bytes, sizeof(rand_bytes));
	char id[64];
	char rand_hex[9];
	lb_hex_encode(rand_bytes, 4, rand_hex);
	snprintf(id, sizeof(id), "%s-%s", service, rand_hex);

	/* Read key material from stdin */
	printf("Enter private key (or press Enter to skip): ");
	fflush(stdout);
	char privkey[512] = {0};
	if (fgets(privkey, sizeof(privkey), stdin)) {
		size_t len = strlen(privkey);
		while (len > 0 && (privkey[len-1] == '\n' || privkey[len-1] == '\r'))
			privkey[--len] = '\0';
	}

	printf("Enter public key/address (or press Enter to skip): ");
	fflush(stdout);
	char pubkey[512] = {0};
	if (fgets(pubkey, sizeof(pubkey), stdin)) {
		size_t len = strlen(pubkey);
		while (len > 0 && (pubkey[len-1] == '\n' || pubkey[len-1] == '\r'))
			pubkey[--len] = '\0';
	}

	json_t *entry = json_object();
	json_object_set_new(entry, "id", json_string(id));
	json_object_set_new(entry, "service", json_string(service));
	if (label)
		json_object_set_new(entry, "label", json_string(label));
	if (pubkey[0])
		json_object_set_new(entry, "public_key", json_string(pubkey));
	if (privkey[0])
		json_object_set_new(entry, "private_key", json_string(privkey));
	json_object_set_new(entry, "created", json_integer((json_int_t)time(NULL)));
	json_object_set_new(entry, "metadata", json_object());

	json_array_append_new(entries, entry);

	if (keystore_save(ks) != 0) {
		json_decref(ks);
		lb_die("failed to save keystore");
	}

	printf("Added keystore entry: %s\n", id);
	if (label)
		printf("  Label: %s\n", label);
	printf("  Service: %s\n", service);

	sodium_memzero(privkey, sizeof(privkey));
	json_decref(ks);
	return 0;
}

int
lb_keystore_list(void)
{
	json_t *ks = keystore_open();
	if (!ks)
		lb_die("failed to open keystore");

	json_t *entries = json_object_get(ks, "entries");
	size_t count = json_is_array(entries) ? json_array_size(entries) : 0;

	if (count == 0) {
		printf("Keystore is empty.\n");
		json_decref(ks);
		return 0;
	}

	printf("%-20s %-12s %-24s %s\n", "ID", "Service", "Label", "Created");
	printf("%-20s %-12s %-24s %s\n", "----", "-------", "-----", "-------");

	size_t i;
	json_t *entry;
	json_array_foreach(entries, i, entry) {
		const char *id = json_string_value(json_object_get(entry, "id"));
		const char *svc = json_string_value(json_object_get(entry, "service"));
		const char *lbl = json_string_value(json_object_get(entry, "label"));
		json_int_t created = json_integer_value(json_object_get(entry, "created"));

		char timebuf[32] = "?";
		if (created > 0) {
			time_t t = (time_t)created;
			struct tm *tm = localtime(&t);
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%d", tm);
		}

		printf("%-20s %-12s %-24s %s\n",
		       id ? id : "?",
		       svc ? svc : "?",
		       lbl ? lbl : "(none)",
		       timebuf);
	}

	printf("\n%zu entries total.\n", count);

	json_decref(ks);
	return 0;
}

int
lb_keystore_show(const char *id, bool show_secret)
{
	json_t *ks = keystore_open();
	if (!ks)
		lb_die("failed to open keystore");

	json_t *entries = json_object_get(ks, "entries");
	if (!entries) {
		printf("Keystore is empty.\n");
		json_decref(ks);
		return 1;
	}

	size_t i;
	json_t *entry;
	bool found = false;
	json_array_foreach(entries, i, entry) {
		const char *eid = json_string_value(json_object_get(entry, "id"));
		if (eid && strcmp(eid, id) == 0) {
			found = true;

			printf("ID:          %s\n", eid);

			const char *svc = json_string_value(json_object_get(entry, "service"));
			if (svc) printf("Service:     %s\n", svc);

			const char *lbl = json_string_value(json_object_get(entry, "label"));
			if (lbl) printf("Label:       %s\n", lbl);

			const char *pubkey = json_string_value(json_object_get(entry, "public_key"));
			if (pubkey) printf("Public key:  %s\n", pubkey);

			const char *privkey = json_string_value(json_object_get(entry, "private_key"));
			if (privkey) {
				if (show_secret)
					printf("Private key: %s\n", privkey);
				else
					printf("Private key: [redacted] (use --secret to reveal)\n");
			}

			json_int_t created = json_integer_value(json_object_get(entry, "created"));
			if (created > 0) {
				char timebuf[32];
				time_t t = (time_t)created;
				struct tm *tm = localtime(&t);
				strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
				printf("Created:     %s\n", timebuf);
			}

			break;
		}
	}

	if (!found)
		printf("Entry not found: %s\n", id);

	json_decref(ks);
	return found ? 0 : 1;
}

int
lb_keystore_remove(const char *id)
{
	json_t *ks = keystore_open();
	if (!ks)
		lb_die("failed to open keystore");

	json_t *entries = json_object_get(ks, "entries");
	if (!entries) {
		printf("Keystore is empty.\n");
		json_decref(ks);
		return 1;
	}

	size_t i;
	json_t *entry;
	bool found = false;
	json_array_foreach(entries, i, entry) {
		const char *eid = json_string_value(json_object_get(entry, "id"));
		if (eid && strcmp(eid, id) == 0) {
			json_array_remove(entries, i);
			found = true;
			break;
		}
	}

	if (!found) {
		printf("Entry not found: %s\n", id);
		json_decref(ks);
		return 1;
	}

	if (keystore_save(ks) != 0) {
		json_decref(ks);
		lb_die("failed to save keystore");
	}

	printf("Removed keystore entry: %s\n", id);

	json_decref(ks);
	return 0;
}

int
lb_keystore_export_pubkey(const char *id)
{
	json_t *ks = keystore_open();
	if (!ks)
		lb_die("failed to open keystore");

	json_t *entries = json_object_get(ks, "entries");
	if (!entries) {
		printf("Keystore is empty.\n");
		json_decref(ks);
		return 1;
	}

	size_t i;
	json_t *entry;
	bool found = false;
	json_array_foreach(entries, i, entry) {
		const char *eid = json_string_value(json_object_get(entry, "id"));
		if (eid && strcmp(eid, id) == 0) {
			found = true;
			const char *pubkey = json_string_value(json_object_get(entry, "public_key"));
			if (pubkey)
				printf("%s\n", pubkey);
			else
				printf("No public key stored for %s\n", id);
			break;
		}
	}

	if (!found)
		printf("Entry not found: %s\n", id);

	json_decref(ks);
	return found ? 0 : 1;
}
