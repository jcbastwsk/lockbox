/* https://www.youtube.com/watch?v=dDpGBM5IXEU */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

/*
 * helper to truncate a fingerprint hex for display. ended up just using
 * printf format widths everywhere instead but might still use this.
 */
__attribute__((unused))
static const char *
fp_short(const char *hex)
{
	static char buf[20];
	snprintf(buf, sizeof(buf), "%.16s...", hex);
	return buf;
}

/* ── Fingerprint ──────────────────────────────────────────────────── */

void
lb_fingerprint(const uint8_t pk[LB_ED25519_PK_LEN], lb_fingerprint_t *fp)
{
	crypto_hash_sha256(fp->fp, pk, LB_ED25519_PK_LEN);
	lb_hex_encode(fp->fp, LB_FINGERPRINT_LEN, fp->hex);
}

/* ── Init ─────────────────────────────────────────────────────────── */

static int
ensure_dir(const char *path, int mode)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		lb_die("%s exists but is not a directory", path);
	}
	if (mkdir(path, mode) != 0) {
		lb_die("mkdir %s: %s", path, strerror(errno));
	}
	return 0;
}

int
lb_init(void)
{
	char *dir = lb_data_path("");
	size_t dlen = strlen(dir);
	if (dlen > 0 && dir[dlen - 1] == '/')
		dir[dlen - 1] = '\0';

	ensure_dir(dir, 0700);
	free(dir);

	char *keyring_dir = lb_data_path(LB_KEYRING_DIR);
	ensure_dir(keyring_dir, 0700);
	free(keyring_dir);

	char *sk_path = lb_data_path(LB_SECRET_KEY_FILE);
	char *pk_path = lb_data_path(LB_PUBLIC_KEY_FILE);

	struct stat st;
	if (stat(sk_path, &st) == 0) {
		fprintf(stderr, "lockbox: keypair already exists\n");
		free(sk_path);
		free(pk_path);
		return 0;
	}

	lb_keypair_t kp;
	crypto_sign_keypair(kp.pk, kp.sk);

	if (lb_file_write(sk_path, kp.sk, LB_ED25519_SK_LEN, 0600) != 0)
		lb_die("failed to write secret key");
	if (lb_file_write(pk_path, kp.pk, LB_ED25519_PK_LEN, 0644) != 0)
		lb_die("failed to write public key");

	lb_sigchain_init(kp.pk, kp.sk);

	char *cfg_path = lb_data_path(LB_CONFIG_FILE);
	json_t *cfg = json_object();
	json_object_set_new(cfg, "version", json_integer(1));
	/* XXX: add more config options here eventually (default key algo, etc) */
	char *cfg_str = json_dumps(cfg, JSON_INDENT(2));
	lb_file_write(cfg_path, (uint8_t *)cfg_str, strlen(cfg_str), 0644);
	free(cfg_str);
	json_decref(cfg);
	free(cfg_path);

	lb_fingerprint_t fp;
	lb_fingerprint(kp.pk, &fp);
	printf("Keypair generated.\n");
	printf("Fingerprint: %s\n", fp.hex);

	sodium_memzero(&kp, sizeof(kp));
	free(sk_path);
	free(pk_path);
	return 0;
}

/* ── Load keys ────────────────────────────────────────────────────── */

int
lb_keypair_load(lb_keypair_t *kp)
{
	char *sk_path = lb_data_path(LB_SECRET_KEY_FILE);
	char *pk_path = lb_data_path(LB_PUBLIC_KEY_FILE);
	size_t sk_len, pk_len;

	uint8_t *sk = lb_file_read(sk_path, &sk_len);
	if (!sk || sk_len != LB_ED25519_SK_LEN) {
		free(sk_path);
		free(pk_path);
		free(sk);
		lb_die("failed to load secret key (run 'lockbox init' first)");
	}

	uint8_t *pk = lb_file_read(pk_path, &pk_len);
	if (!pk || pk_len != LB_ED25519_PK_LEN) {
		free(sk_path);
		free(pk_path);
		sodium_memzero(sk, sk_len);
		free(sk);
		free(pk);
		lb_die("failed to load public key");
	}

	memcpy(kp->sk, sk, LB_ED25519_SK_LEN);
	memcpy(kp->pk, pk, LB_ED25519_PK_LEN);

	sodium_memzero(sk, sk_len);
	free(sk);
	free(pk);
	free(sk_path);
	free(pk_path);
	return 0;
}

int
lb_pubkey_load(uint8_t pk[LB_ED25519_PK_LEN])
{
	char *pk_path = lb_data_path(LB_PUBLIC_KEY_FILE);
	size_t pk_len;
	uint8_t *data = lb_file_read(pk_path, &pk_len);
	free(pk_path);

	if (!data || pk_len != LB_ED25519_PK_LEN) {
		free(data);
		return -1;
	}
	memcpy(pk, data, LB_ED25519_PK_LEN);
	free(data);
	return 0;
}

/* ── Key export ───────────────────────────────────────────────────── */

int
lb_key_export(bool json_format)
{
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		lb_die("failed to load public key (run 'lockbox init' first)");

	lb_fingerprint_t fp;
	lb_fingerprint(pk, &fp);

	if (json_format) {
		char *b64 = lb_base64_encode(pk, LB_ED25519_PK_LEN);
		json_t *obj = json_object();
		json_object_set_new(obj, "fingerprint", json_string(fp.hex));
		json_object_set_new(obj, "public_key", json_string(b64));
		char *s = json_dumps(obj, JSON_INDENT(2));
		printf("%s\n", s);
		free(s);
		json_decref(obj);
		free(b64);
	} else {
		char *b64 = lb_base64_encode(pk, LB_ED25519_PK_LEN);
		printf("%s\n", b64);
		free(b64);
	}
	return 0;
}

/* ── Keyring ──────────────────────────────────────────────────────── */

int
lb_keyring_save(const uint8_t pk[LB_ED25519_PK_LEN], const char *label)
{
	lb_fingerprint_t fp;
	lb_fingerprint(pk, &fp);

	/* Try to load existing entry to preserve certifications */
	json_t *existing = lb_keyring_load_entry(fp.hex);
	json_t *certs = NULL;
	if (existing) {
		certs = json_object_get(existing, "certifications");
		if (certs)
			json_incref(certs);
		json_decref(existing);
	}

	char fname[128];
	snprintf(fname, sizeof(fname), "%s/%s.json", LB_KEYRING_DIR, fp.hex);
	char *path = lb_data_path(fname);

	char *b64 = lb_base64_encode(pk, LB_ED25519_PK_LEN);
	json_t *obj = json_object();
	json_object_set_new(obj, "fingerprint", json_string(fp.hex));
	json_object_set_new(obj, "public_key", json_string(b64));
	if (label)
		json_object_set_new(obj, "label", json_string(label));
	if (certs)
		json_object_set_new(obj, "certifications", certs);

	char *s = json_dumps(obj, JSON_INDENT(2));
	int rc = lb_file_write(path, (uint8_t *)s, strlen(s), 0644);

	free(s);
	json_decref(obj);
	free(b64);
	free(path);
	return rc;
}

json_t *
lb_keyring_load_entry(const char *hex_prefix)
{
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	if (!d) {
		free(kr_dir);
		return NULL;
	}

	size_t prefix_len = strlen(hex_prefix);
	struct dirent *ent;
	json_t *result = NULL;

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;
		if (strncmp(ent->d_name, hex_prefix, prefix_len) == 0) {
			char fpath[512];
			snprintf(fpath, sizeof(fpath), "%s/%s", kr_dir, ent->d_name);
			size_t flen;
			uint8_t *data = lb_file_read(fpath, &flen);
			if (!data)
				continue;

			json_error_t err;
			result = json_loadb((char *)data, flen, 0, &err);
			free(data);
			break;
		}
	}

	closedir(d);
	free(kr_dir);
	return result;
}

int
lb_keyring_save_json(const char *fp_hex, json_t *obj)
{
	char fname[128];
	snprintf(fname, sizeof(fname), "%s/%s.json", LB_KEYRING_DIR, fp_hex);
	char *path = lb_data_path(fname);
	char *s = json_dumps(obj, JSON_INDENT(2));
	int rc = lb_file_write(path, (uint8_t *)s, strlen(s), 0644);
	free(s);
	free(path);
	return rc;
}

int
lb_keyring_lookup_hex(const char *hex_prefix, uint8_t pk_out[LB_ED25519_PK_LEN])
{
	json_t *obj = lb_keyring_load_entry(hex_prefix);
	if (!obj)
		return -1;

	const char *b64 = json_string_value(json_object_get(obj, "public_key"));
	if (!b64) {
		json_decref(obj);
		return -1;
	}

	uint8_t *dec;
	size_t dec_len;
	int rc = -1;
	if (lb_base64_decode(b64, &dec, &dec_len) == 0 && dec_len == LB_ED25519_PK_LEN) {
		memcpy(pk_out, dec, LB_ED25519_PK_LEN);
		rc = 0;
		free(dec);
	}

	json_decref(obj);
	return rc;
}

/* ── Key import ───────────────────────────────────────────────────── */

int
lb_key_import(const char *path)
{
	size_t flen;
	uint8_t *data = lb_file_read(path, &flen);
	if (!data)
		lb_die("cannot read %s", path);

	uint8_t pk[LB_ED25519_PK_LEN];
	const char *label = NULL;
	bool loaded = false;

	json_error_t err;
	json_t *obj = json_loadb((char *)data, flen, 0, &err);
	if (obj) {
		const char *b64 = json_string_value(json_object_get(obj, "public_key"));
		label = json_string_value(json_object_get(obj, "label"));
		if (b64) {
			uint8_t *dec;
			size_t dec_len;
			if (lb_base64_decode(b64, &dec, &dec_len) == 0 &&
			    dec_len == LB_ED25519_PK_LEN) {
				memcpy(pk, dec, LB_ED25519_PK_LEN);
				loaded = true;
				free(dec);
			}
		}
		json_decref(obj);
	}

	if (!loaded) {
		char *str = malloc(flen + 1);
		memcpy(str, data, flen);
		str[flen] = '\0';
		while (flen > 0 && (str[flen-1] == '\n' || str[flen-1] == '\r' || str[flen-1] == ' '))
			str[--flen] = '\0';

		uint8_t *dec;
		size_t dec_len;
		if (lb_base64_decode(str, &dec, &dec_len) == 0 &&
		    dec_len == LB_ED25519_PK_LEN) {
			memcpy(pk, dec, LB_ED25519_PK_LEN);
			loaded = true;
			free(dec);
		}
		free(str);
	}

	/* last resort: raw 32-byte key file (who does this? but just in case) */
	if (!loaded && flen == LB_ED25519_PK_LEN) {
		memcpy(pk, data, LB_ED25519_PK_LEN);
		loaded = true;
	}

	free(data);

	if (!loaded)
		lb_die("could not parse public key from %s", path);

	lb_keyring_save(pk, label);

	lb_fingerprint_t fp;
	lb_fingerprint(pk, &fp);
	printf("Imported key: %s\n", fp.hex);
	return 0;
}

/* ── Key list ─────────────────────────────────────────────────────── */

int
lb_key_list(void)
{
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	if (!d) {
		printf("No keyring found.\n");
		free(kr_dir);
		return 0;
	}

	struct dirent *ent;
	int count = 0;
	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;
		char *dot = strrchr(ent->d_name, '.');
		if (!dot || strcmp(dot, ".json") != 0)
			continue;

		char fpath[512];
		snprintf(fpath, sizeof(fpath), "%s/%s", kr_dir, ent->d_name);
		size_t flen;
		uint8_t *data = lb_file_read(fpath, &flen);
		if (!data)
			continue;

		json_error_t err;
		json_t *obj = json_loadb((char *)data, flen, 0, &err);
		free(data);
		if (!obj)
			continue;

		const char *fp_hex = json_string_value(json_object_get(obj, "fingerprint"));
		const char *lbl = json_string_value(json_object_get(obj, "label"));
		json_t *certs = json_object_get(obj, "certifications");
		size_t ncerts = json_is_array(certs) ? json_array_size(certs) : 0;

		if (fp_hex) {
			printf("%.16s...  %-20s", fp_hex, lbl ? lbl : "(no label)");
			if (ncerts > 0)
				printf("  [%zu cert%s]", ncerts, ncerts > 1 ? "s" : "");
			printf("\n");
			count++;
		}
		json_decref(obj);
	}

	closedir(d);
	free(kr_dir);

	if (count == 0)
		printf("Keyring is empty.\n");
	return 0;
}

/* ── Fingerprint display ──────────────────────────────────────────── */

int
lb_key_show_fingerprint(void)
{
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		lb_die("failed to load public key (run 'lockbox init' first)");

	lb_fingerprint_t fp;
	lb_fingerprint(pk, &fp);
	printf("%s\n", fp.hex);
	return 0;
}

/* ── Show identity ────────────────────────────────────────────────── */

int
lb_show_id(void)
{
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		lb_die("failed to load public key (run 'lockbox init' first)");

	lb_fingerprint_t fp;
	lb_fingerprint(pk, &fp);
	char *b64 = lb_base64_encode(pk, LB_ED25519_PK_LEN);

	printf("Fingerprint: %s\n", fp.hex);
	printf("Public key:  %s\n", b64);

	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	size_t sc_len;
	uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
	free(sc_path);

	if (sc_data) {
		json_error_t err;
		json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
		free(sc_data);

		if (chain && json_is_array(chain)) {
			size_t i;
			json_t *link;
			printf("\nProven identities:\n");
			bool any = false;
			json_array_foreach(chain, i, link) {
				const char *type = json_string_value(json_object_get(link, "type"));
				if (!type)
					continue;
				if (strcmp(type, LB_LINK_IDENTITY_DNS) == 0 ||
				    strcmp(type, LB_LINK_IDENTITY_HTTPS) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *domain = json_string_value(
						json_object_get(payload, "domain"));
					if (domain) {
						printf("  %s (%s)\n", domain,
						       strcmp(type, LB_LINK_IDENTITY_DNS) == 0
						       ? "DNS" : "HTTPS");
						any = true;
					}
				}
				if (strcmp(type, LB_LINK_IDENTITY_GITHUB) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *user = json_string_value(
						json_object_get(payload, "github"));
					if (user) {
						printf("  github.com/%s (GitHub)\n", user);
						any = true;
					}
				}
			}
			if (!any)
				printf("  (none)\n");
			json_decref(chain);
		}
	}

	free(b64);
	return 0;
}

/* ── Web of Trust: Certify ────────────────────────────────────────── */

int
lb_certify(const char *fingerprint)
{
	/* Load our keypair */
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t our_fp;
	lb_fingerprint(kp.pk, &our_fp);

	/* Look up the subject key in keyring */
	json_t *entry = lb_keyring_load_entry(fingerprint);
	if (!entry)
		lb_die("key not found in keyring: %s\n"
		       "Import it first with 'lockbox key import'", fingerprint);

	const char *subject_fp = json_string_value(json_object_get(entry, "fingerprint"));
	const char *subject_pk_b64 = json_string_value(json_object_get(entry, "public_key"));
	const char *subject_label = json_string_value(json_object_get(entry, "label"));

	if (!subject_fp || !subject_pk_b64) {
		json_decref(entry);
		lb_die("corrupt keyring entry");
	}

	if (strncmp(subject_fp, our_fp.hex, strlen(subject_fp)) == 0) {
		json_decref(entry);
		lb_die("cannot certify your own key");
	}

	/* Build certification statement */
	json_t *stmt = json_object();
	json_object_set_new(stmt, "certifier", json_string(our_fp.hex));
	json_object_set_new(stmt, "subject", json_string(subject_fp));
	json_object_set_new(stmt, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(stmt, "type", json_string("key.certify"));

	char *stmt_str = json_dumps(stmt, JSON_SORT_KEYS | JSON_COMPACT);

	/* Sign */
	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)stmt_str, strlen(stmt_str), kp.sk);
	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);

	/* Add certification to the subject's keyring entry */
	json_t *certs = json_object_get(entry, "certifications");
	if (!certs || !json_is_array(certs)) {
		certs = json_array();
		json_object_set_new(entry, "certifications", certs);
	}

	/* Check for existing certification from us */
	size_t ci;
	json_t *cval;
	bool already = false;
	json_array_foreach(certs, ci, cval) {
		const char *by = json_string_value(json_object_get(cval, "by"));
		if (by && strcmp(by, our_fp.hex) == 0) {
			already = true;
			break;
		}
	}

	if (already) {
		printf("Already certified this key.\n");
	} else {
		json_t *cert = json_object();
		json_object_set_new(cert, "by", json_string(our_fp.hex));
		json_object_set_new(cert, "sig", json_string(sig_b64));
		json_object_set_new(cert, "timestamp", json_integer((json_int_t)time(NULL)));
		json_array_append_new(certs, cert);

		lb_keyring_save_json(subject_fp, entry);

		/* Add to our sigchain */
		json_t *payload = json_object();
		json_object_set_new(payload, "subject", json_string(subject_fp));
		json_object_set_new(payload, "subject_key", json_string(subject_pk_b64));
		lb_sigchain_append(LB_LINK_KEY_CERTIFY, payload, kp.sk);
		json_decref(payload);

		printf("Certified key: %.16s...", subject_fp);
		if (subject_label)
			printf(" (%s)", subject_label);
		printf("\nCertification added to sigchain.\n");
	}

	free(sig_b64);
	free(stmt_str);
	json_decref(stmt);
	json_decref(entry);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

/* ── Web of Trust: Trust path ─────────────────────────────────────── */

/*
 * BFS through keyring certifications to find shortest trust path
 * from our key to the target fingerprint.
 */
int
lb_trust_show(const char *fingerprint)
{
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		lb_die("failed to load public key");

	lb_fingerprint_t our_fp;
	lb_fingerprint(pk, &our_fp);

	/* Check if it's our own key */
	if (strncmp(our_fp.hex, fingerprint, strlen(fingerprint)) == 0) {
		printf("That's your own key (trust level 0: ultimate)\n");
		return 0;
	}

	/* Load all keyring entries */
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	if (!d) {
		free(kr_dir);
		lb_die("empty keyring");
	}

	/* Collect all entries */
	typedef struct {
		char fp[LB_FINGERPRINT_HEX];
		char label[64];
		char certifiers[LB_MAX_KEYRING][LB_FINGERPRINT_HEX];
		int  ncerts;
	} kr_node_t;

	kr_node_t *nodes = calloc(LB_MAX_KEYRING, sizeof(kr_node_t));
	int nnodes = 0;

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && nnodes < LB_MAX_KEYRING) {
		if (ent->d_name[0] == '.')
			continue;
		char *dot = strrchr(ent->d_name, '.');
		if (!dot || strcmp(dot, ".json") != 0)
			continue;

		char fpath[512];
		snprintf(fpath, sizeof(fpath), "%s/%s", kr_dir, ent->d_name);
		size_t flen;
		uint8_t *data = lb_file_read(fpath, &flen);
		if (!data) continue;

		json_error_t err;
		json_t *obj = json_loadb((char *)data, flen, 0, &err);
		free(data);
		if (!obj) continue;

		const char *fp_hex = json_string_value(json_object_get(obj, "fingerprint"));
		const char *lbl = json_string_value(json_object_get(obj, "label"));
		json_t *certs = json_object_get(obj, "certifications");

		if (fp_hex) {
			kr_node_t *n = &nodes[nnodes];
			snprintf(n->fp, sizeof(n->fp), "%s", fp_hex);
			if (lbl)
				snprintf(n->label, sizeof(n->label), "%s", lbl);
			n->ncerts = 0;

			if (json_is_array(certs)) {
				size_t ci;
				json_t *cv;
				json_array_foreach(certs, ci, cv) {
					const char *by = json_string_value(json_object_get(cv, "by"));
					if (by && n->ncerts < LB_MAX_KEYRING) {
						snprintf(n->certifiers[n->ncerts], LB_FINGERPRINT_HEX,
						         "%s", by);
						n->ncerts++;
					}
				}
			}
			nnodes++;
		}
		json_decref(obj);
	}

	closedir(d);
	free(kr_dir);

	/* BFS: start from our fingerprint, follow certification edges */
	/* An edge from A -> B means A has certified B */
	/* (B's certifications list contains A) */

	int *dist = calloc(nnodes, sizeof(int));
	int *prev = calloc(nnodes, sizeof(int));
	bool *visited = calloc(nnodes, sizeof(bool));
	int *queue = calloc(nnodes, sizeof(int));

	for (int i = 0; i < nnodes; i++) {
		dist[i] = -1;
		prev[i] = -1;
	}

	/* Find target index */
	int target_idx = -1;
	size_t fp_prefix_len = strlen(fingerprint);
	for (int i = 0; i < nnodes; i++) {
		if (strncmp(nodes[i].fp, fingerprint, fp_prefix_len) == 0) {
			target_idx = i;
			break;
		}
	}

	if (target_idx < 0) {
		printf("Key not found in keyring.\n");
		free(nodes); free(dist); free(prev); free(visited); free(queue);
		return 1;
	}

	/* Seed: find all keys directly certified by us (our_fp.hex is in their certifiers) */
	int qhead = 0, qtail = 0;
	for (int i = 0; i < nnodes; i++) {
		for (int c = 0; c < nodes[i].ncerts; c++) {
			if (strcmp(nodes[i].certifiers[c], our_fp.hex) == 0) {
				dist[i] = 1;
				prev[i] = -1; /* directly from us */
				visited[i] = true;
				queue[qtail++] = i;
				break;
			}
		}
	}

	/* BFS: from certified nodes, find who they certified */
	while (qhead < qtail && dist[target_idx] < 0) {
		int cur = queue[qhead++];
		if (dist[cur] >= LB_TRUST_MAX_DEPTH)
			continue;

		/* Find all keys certified by nodes[cur] */
		for (int i = 0; i < nnodes; i++) {
			if (visited[i])
				continue;
			for (int c = 0; c < nodes[i].ncerts; c++) {
				if (strcmp(nodes[i].certifiers[c], nodes[cur].fp) == 0) {
					dist[i] = dist[cur] + 1;
					prev[i] = cur;
					visited[i] = true;
					queue[qtail++] = i;
					break;
				}
			}
		}
	}

	/* Display result */
	if (dist[target_idx] < 0) {
		printf("No trust path found to %.16s...", nodes[target_idx].fp);
		if (nodes[target_idx].label[0])
			printf(" (%s)", nodes[target_idx].label);
		printf("\n");
		printf("Trust level: UNKNOWN (no chain of certifications)\n");
	} else {
		printf("Trust path to %.16s...", nodes[target_idx].fp);
		if (nodes[target_idx].label[0])
			printf(" (%s)", nodes[target_idx].label);
		printf(":\n\n");

		/* Reconstruct path */
		int path[LB_TRUST_MAX_DEPTH + 1];
		int pathlen = 0;
		int cur = target_idx;
		while (cur >= 0 && pathlen <= LB_TRUST_MAX_DEPTH) {
			path[pathlen++] = cur;
			cur = prev[cur];
		}

		printf("  You (%.16s...)\n", our_fp.hex);
		for (int i = pathlen - 1; i >= 0; i--) {
			int idx = path[i];
			printf("    -> %.16s...", nodes[idx].fp);
			if (nodes[idx].label[0])
				printf(" (%s)", nodes[idx].label);
			printf("\n");
		}

		printf("\nTrust level: %d", dist[target_idx]);
		if (dist[target_idx] == 1)
			printf(" (directly certified by you)");
		else
			printf(" (indirect, %d hops)", dist[target_idx]);
		printf("\n");
	}

	free(nodes);
	free(dist);
	free(prev);
	free(visited);
	free(queue);
	return 0;
}
