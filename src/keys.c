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
			int score = lb_trust_score(fp_hex);
			printf("%.16s...  %-20s  score:%-3d", fp_hex, lbl ? lbl : "(no label)", score);
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
				if (strcmp(type, LB_LINK_IDENTITY_REDDIT) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *user = json_string_value(
						json_object_get(payload, "reddit"));
					if (user) {
						printf("  reddit.com/u/%s (Reddit)\n", user);
						any = true;
					}
				}
				if (strcmp(type, LB_LINK_IDENTITY_TWITTER) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *user = json_string_value(
						json_object_get(payload, "twitter"));
					if (user) {
						printf("  x.com/%s (Twitter/X)\n", user);
						any = true;
					}
				}
				if (strcmp(type, LB_LINK_IDENTITY_BTC) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *addr = json_string_value(
						json_object_get(payload, "btc"));
					if (addr) {
						printf("  btc:%s (BTC)\n", addr);
						any = true;
					}
				}
				if (strcmp(type, LB_LINK_IDENTITY_ETH) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *addr = json_string_value(
						json_object_get(payload, "eth"));
					if (addr) {
						printf("  eth:%s (ETH)\n", addr);
						any = true;
					}
				}
				if (strcmp(type, LB_LINK_IDENTITY_HN) == 0) {
					json_t *payload = json_object_get(link, "payload");
					const char *user = json_string_value(
						json_object_get(payload, "hn"));
					if (user) {
						printf("  news.ycombinator.com/user?id=%s (HackerNews)\n", user);
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

/* ── Key search ───────────────────────────────────────────────────── */

int
lb_key_search(const char *query)
{
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	if (!d) {
		printf("No keyring found.\n");
		free(kr_dir);
		return 0;
	}

	/* Collect matching entries */
	typedef struct {
		char fp[LB_FINGERPRINT_HEX];
		char label[64];
		int  ncerts;
		int  score;
	} search_result_t;

	search_result_t results[LB_MAX_KEYRING];
	int nresults = 0;

	size_t qlen = strlen(query);
	char query_lower[256];
	size_t ql = qlen < 255 ? qlen : 255;
	for (size_t i = 0; i < ql; i++)
		query_lower[i] = (query[i] >= 'A' && query[i] <= 'Z') ? query[i] + 32 : query[i];
	query_lower[ql] = '\0';

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && nresults < LB_MAX_KEYRING) {
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

		bool match = false;

		/* Match against fingerprint prefix */
		if (fp_hex && strncmp(fp_hex, query, qlen) == 0)
			match = true;

		/* Match against label (case-insensitive) */
		if (!match && lbl) {
			char lbl_lower[64];
			size_t ll = strlen(lbl);
			if (ll > 63) ll = 63;
			for (size_t i = 0; i < ll; i++)
				lbl_lower[i] = (lbl[i] >= 'A' && lbl[i] <= 'Z') ? lbl[i] + 32 : lbl[i];
			lbl_lower[ll] = '\0';
			if (strstr(lbl_lower, query_lower))
				match = true;
		}

		if (match && fp_hex) {
			search_result_t *r = &results[nresults];
			snprintf(r->fp, sizeof(r->fp), "%s", fp_hex);
			if (lbl)
				snprintf(r->label, sizeof(r->label), "%s", lbl);
			else
				r->label[0] = '\0';
			r->ncerts = json_is_array(certs) ? (int)json_array_size(certs) : 0;
			r->score = lb_trust_score(fp_hex);
			nresults++;
		}

		json_decref(obj);
	}

	closedir(d);
	free(kr_dir);

	if (nresults == 0) {
		printf("No keys matching '%s'\n", query);
		return 0;
	}

	/* Sort by trust score descending */
	for (int i = 0; i < nresults - 1; i++) {
		for (int j = i + 1; j < nresults; j++) {
			if (results[j].score > results[i].score) {
				search_result_t tmp = results[i];
				results[i] = results[j];
				results[j] = tmp;
			}
		}
	}

	printf("Found %d key%s matching '%s':\n\n", nresults, nresults > 1 ? "s" : "", query);
	for (int i = 0; i < nresults; i++) {
		printf("  %.16s...  %-20s  score:%d  [%d cert%s]\n",
		       results[i].fp,
		       results[i].label[0] ? results[i].label : "(no label)",
		       results[i].score,
		       results[i].ncerts,
		       results[i].ncerts != 1 ? "s" : "");
	}

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

	/* Also show trust score */
	int score = lb_trust_score(nodes[target_idx].fp);
	const char *level;
	if (score >= 80) level = "HIGH";
	else if (score >= 50) level = "MODERATE";
	else if (score >= 20) level = "LOW";
	else if (score >= 1) level = "MINIMAL";
	else level = "UNKNOWN";

	printf("\nTrust score: %d/100 (%s)\n", score, level);

	free(nodes);
	free(dist);
	free(prev);
	free(visited);
	free(queue);
	return 0;
}

/* ── Trust score computation ──────────────────────────────────────── */

/*
 * Compute a trust score (0-100) for a key based on:
 * - Direct certification by us: +40
 * - Each additional certifier in keyring: +10 (max 20)
 * - 2-hop trust path: +15
 * - 3-hop trust path: +5
 * - Each identity proof on sigchain: +5 (max 25)
 * - Key age per month: +1 (max 10)
 * - Attestations from keyring keys: +5 each (max 15)
 * - Attestations confirming identity proofs: +3 each (max 12)
 */
int
lb_trust_score(const char *fingerprint)
{
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		return 0;

	lb_fingerprint_t our_fp;
	lb_fingerprint(pk, &our_fp);

	/* Own key: maximum */
	if (strncmp(our_fp.hex, fingerprint, strlen(fingerprint)) == 0)
		return 100;

	json_t *entry = lb_keyring_load_entry(fingerprint);
	if (!entry)
		return 0;

	int score = 0;

	/* Count certifications */
	json_t *certs = json_object_get(entry, "certifications");
	bool direct = false;
	int other_certs = 0;

	if (json_is_array(certs)) {
		size_t ci;
		json_t *cv;
		json_array_foreach(certs, ci, cv) {
			const char *by = json_string_value(json_object_get(cv, "by"));
			if (!by) continue;
			if (strcmp(by, our_fp.hex) == 0)
				direct = true;
			else {
				/* Check if certifier is in our keyring */
				json_t *certifier = lb_keyring_load_entry(by);
				if (certifier) {
					other_certs++;
					json_decref(certifier);
				}
			}
		}
	}

	if (direct)
		score += 40;

	/* Additional certifiers in keyring: +10 each, max 20 */
	int cert_bonus = other_certs * 10;
	if (cert_bonus > 20) cert_bonus = 20;
	score += cert_bonus;

	/* Multi-hop trust path — do a lightweight BFS */
	if (!direct) {
		/* Load all keyring entries for BFS */
		char *kr_dir = lb_data_path(LB_KEYRING_DIR);
		DIR *d = opendir(kr_dir);
		if (d) {
			/* Simple structure for BFS */
			char fps[LB_MAX_KEYRING][LB_FINGERPRINT_HEX];
			char cert_by[LB_MAX_KEYRING][LB_MAX_KEYRING][LB_FINGERPRINT_HEX];
			int ncerts_arr[LB_MAX_KEYRING];
			int nn = 0;

			struct dirent *ent;
			while ((ent = readdir(d)) != NULL && nn < LB_MAX_KEYRING) {
				if (ent->d_name[0] == '.') continue;
				char *dot = strrchr(ent->d_name, '.');
				if (!dot || strcmp(dot, ".json") != 0) continue;

				char fpath[512];
				snprintf(fpath, sizeof(fpath), "%s/%s", kr_dir, ent->d_name);
				size_t flen;
				uint8_t *data = lb_file_read(fpath, &flen);
				if (!data) continue;

				json_error_t jerr;
				json_t *obj = json_loadb((char *)data, flen, 0, &jerr);
				free(data);
				if (!obj) continue;

				const char *fp_hex = json_string_value(json_object_get(obj, "fingerprint"));
				json_t *certs2 = json_object_get(obj, "certifications");

				if (fp_hex) {
					snprintf(fps[nn], LB_FINGERPRINT_HEX, "%s", fp_hex);
					ncerts_arr[nn] = 0;
					if (json_is_array(certs2)) {
						size_t ci2;
						json_t *cv2;
						json_array_foreach(certs2, ci2, cv2) {
							const char *by2 = json_string_value(json_object_get(cv2, "by"));
							if (by2 && ncerts_arr[nn] < LB_MAX_KEYRING) {
								snprintf(cert_by[nn][ncerts_arr[nn]], LB_FINGERPRINT_HEX,
								         "%s", by2);
								ncerts_arr[nn]++;
							}
						}
					}
					nn++;
				}
				json_decref(obj);
			}
			closedir(d);
			free(kr_dir);

			/* BFS from our key */
			int dist_arr[LB_MAX_KEYRING];
			bool visited_arr[LB_MAX_KEYRING];
			int queue_arr[LB_MAX_KEYRING];
			for (int i = 0; i < nn; i++) { dist_arr[i] = -1; visited_arr[i] = false; }

			int qh = 0, qt = 0;
			size_t fp_plen = strlen(fingerprint);
			int target_i = -1;

			for (int i = 0; i < nn; i++) {
				if (strncmp(fps[i], fingerprint, fp_plen) == 0)
					target_i = i;
				for (int c = 0; c < ncerts_arr[i]; c++) {
					if (strcmp(cert_by[i][c], our_fp.hex) == 0) {
						dist_arr[i] = 1;
						visited_arr[i] = true;
						queue_arr[qt++] = i;
						break;
					}
				}
			}

			while (qh < qt && target_i >= 0 && dist_arr[target_i] < 0) {
				int cur = queue_arr[qh++];
				if (dist_arr[cur] >= LB_TRUST_MAX_DEPTH) continue;
				for (int i = 0; i < nn; i++) {
					if (visited_arr[i]) continue;
					for (int c = 0; c < ncerts_arr[i]; c++) {
						if (strcmp(cert_by[i][c], fps[cur]) == 0) {
							dist_arr[i] = dist_arr[cur] + 1;
							visited_arr[i] = true;
							queue_arr[qt++] = i;
							break;
						}
					}
				}
			}

			if (target_i >= 0 && dist_arr[target_i] == 2)
				score += 15;
			else if (target_i >= 0 && dist_arr[target_i] == 3)
				score += 5;
		} else {
			free(kr_dir);
		}
	}

	/* Identity proofs: check sigchain data stored in entry */
	/* We look at the subject's keyring entry for stored proofs, or count
	   proof-type links if the subject's sigchain data is mirrored */
	const char *subject_fp = json_string_value(json_object_get(entry, "fingerprint"));
	int proof_count = 0;

	/* Check for identity data stored in the keyring entry */
	json_t *identities = json_object_get(entry, "identities");
	if (json_is_array(identities)) {
		proof_count = (int)json_array_size(identities);
	}

	/* Also check our own sigchain for proofs if this is about our key */
	if (subject_fp && strncmp(subject_fp, our_fp.hex, strlen(subject_fp)) == 0) {
		char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
		size_t sc_len;
		uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
		free(sc_path);

		if (sc_data) {
			json_error_t serr;
			json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &serr);
			free(sc_data);
			if (chain && json_is_array(chain)) {
				size_t si;
				json_t *slink;
				json_array_foreach(chain, si, slink) {
					const char *type = json_string_value(json_object_get(slink, "type"));
					if (type && strncmp(type, "identity.prove.", 15) == 0)
						proof_count++;
				}
				json_decref(chain);
			}
		}
	}

	int proof_bonus = proof_count * 5;
	if (proof_bonus > 25) proof_bonus = 25;
	score += proof_bonus;

	/* Key age: +1 per month, max 10 */
	json_int_t created = json_integer_value(json_object_get(entry, "created"));
	if (created > 0) {
		time_t now = time(NULL);
		int months = (int)((now - (time_t)created) / (30 * 86400));
		if (months > 10) months = 10;
		if (months < 0) months = 0;
		score += months;
	}

	/* Attestations */
	json_t *attestations = json_object_get(entry, "attestations");
	if (json_is_array(attestations)) {
		int attest_count = 0;
		int identity_attests = 0;
		size_t ai;
		json_t *av;
		json_array_foreach(attestations, ai, av) {
			const char *attester = json_string_value(json_object_get(av, "attester"));
			const char *claim = json_string_value(json_object_get(av, "claim"));
			if (!attester) continue;

			/* Check if attester is in our keyring */
			json_t *att_entry = lb_keyring_load_entry(attester);
			if (att_entry) {
				attest_count++;
				if (claim && strncmp(claim, "identity:", 9) == 0)
					identity_attests++;
				json_decref(att_entry);
			}
		}
		int attest_bonus = attest_count * 5;
		if (attest_bonus > 15) attest_bonus = 15;
		score += attest_bonus;

		int id_attest_bonus = identity_attests * 3;
		if (id_attest_bonus > 12) id_attest_bonus = 12;
		score += id_attest_bonus;
	}

	json_decref(entry);

	if (score > 100) score = 100;
	return score;
}

/* ── Trust rank ───────────────────────────────────────────────────── */

int
lb_trust_rank(void)
{
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	if (!d) {
		printf("No keyring found.\n");
		free(kr_dir);
		return 0;
	}

	typedef struct {
		char fp[LB_FINGERPRINT_HEX];
		char label[64];
		int  score;
	} rank_entry_t;

	rank_entry_t entries[LB_MAX_KEYRING];
	int count = 0;

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && count < LB_MAX_KEYRING) {
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

		if (fp_hex) {
			snprintf(entries[count].fp, LB_FINGERPRINT_HEX, "%s", fp_hex);
			if (lbl)
				snprintf(entries[count].label, 64, "%s", lbl);
			else
				entries[count].label[0] = '\0';
			entries[count].score = lb_trust_score(fp_hex);
			count++;
		}
		json_decref(obj);
	}

	closedir(d);
	free(kr_dir);

	if (count == 0) {
		printf("Keyring is empty.\n");
		return 0;
	}

	/* Sort by score descending */
	for (int i = 0; i < count - 1; i++) {
		for (int j = i + 1; j < count; j++) {
			if (entries[j].score > entries[i].score) {
				rank_entry_t tmp = entries[i];
				entries[i] = entries[j];
				entries[j] = tmp;
			}
		}
	}

	printf("%-4s %-18s %-20s %-6s %s\n", "Rank", "Fingerprint", "Label", "Score", "Level");
	printf("%-4s %-18s %-20s %-6s %s\n", "----", "-----------", "-----", "-----", "-----");

	for (int i = 0; i < count; i++) {
		const char *level;
		if (entries[i].score >= 80) level = "HIGH";
		else if (entries[i].score >= 50) level = "MODERATE";
		else if (entries[i].score >= 20) level = "LOW";
		else if (entries[i].score >= 1) level = "MINIMAL";
		else level = "UNKNOWN";

		printf("%-4d %.16s  %-20s %-6d %s\n",
		       i + 1,
		       entries[i].fp,
		       entries[i].label[0] ? entries[i].label : "(no label)",
		       entries[i].score,
		       level);
	}

	return 0;
}

/* ── Attestations ─────────────────────────────────────────────────── */

int
lb_attest(const char *fingerprint, const char *claim)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t our_fp;
	lb_fingerprint(kp.pk, &our_fp);

	json_t *entry = lb_keyring_load_entry(fingerprint);
	if (!entry)
		lb_die("key not found in keyring: %s\n"
		       "Import it first with 'lockbox key import'", fingerprint);

	const char *subject_fp = json_string_value(json_object_get(entry, "fingerprint"));
	if (!subject_fp) {
		json_decref(entry);
		lb_die("corrupt keyring entry");
	}

	if (strncmp(subject_fp, our_fp.hex, strlen(subject_fp)) == 0) {
		json_decref(entry);
		lb_die("cannot attest your own key");
	}

	/* Build attestation statement */
	json_t *stmt = json_object();
	json_object_set_new(stmt, "attester", json_string(our_fp.hex));
	json_object_set_new(stmt, "subject", json_string(subject_fp));
	json_object_set_new(stmt, "claim", json_string(claim));
	json_object_set_new(stmt, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(stmt, "type", json_string("key.attest"));

	char *stmt_str = json_dumps(stmt, JSON_SORT_KEYS | JSON_COMPACT);

	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)stmt_str, strlen(stmt_str), kp.sk);
	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);

	/* Add attestation to subject's keyring entry */
	json_t *attestations = json_object_get(entry, "attestations");
	if (!attestations || !json_is_array(attestations)) {
		attestations = json_array();
		json_object_set_new(entry, "attestations", attestations);
	}

	json_t *attest = json_object();
	json_object_set_new(attest, "attester", json_string(our_fp.hex));
	json_object_set_new(attest, "claim", json_string(claim));
	json_object_set_new(attest, "sig", json_string(sig_b64));
	json_object_set_new(attest, "timestamp", json_integer((json_int_t)time(NULL)));
	json_array_append_new(attestations, attest);

	lb_keyring_save_json(subject_fp, entry);

	/* Add to our sigchain */
	json_t *payload = json_object();
	json_object_set_new(payload, "subject", json_string(subject_fp));
	json_object_set_new(payload, "claim", json_string(claim));
	lb_sigchain_append(LB_LINK_KEY_ATTEST, payload, kp.sk);
	json_decref(payload);

	printf("Attested: %.16s... claim=%s\n", subject_fp, claim);
	printf("Attestation added to sigchain.\n");

	free(sig_b64);
	free(stmt_str);
	json_decref(stmt);
	json_decref(entry);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

int
lb_attestations_show(const char *fingerprint)
{
	json_t *entry = lb_keyring_load_entry(fingerprint);
	if (!entry)
		lb_die("key not found in keyring: %s", fingerprint);

	const char *subject_fp = json_string_value(json_object_get(entry, "fingerprint"));
	const char *label = json_string_value(json_object_get(entry, "label"));

	printf("Attestations for %.16s...", subject_fp ? subject_fp : fingerprint);
	if (label) printf(" (%s)", label);
	printf(":\n\n");

	json_t *attestations = json_object_get(entry, "attestations");
	if (!attestations || !json_is_array(attestations) || json_array_size(attestations) == 0) {
		printf("  (none)\n");
		json_decref(entry);
		return 0;
	}

	size_t i;
	json_t *attest;
	json_array_foreach(attestations, i, attest) {
		const char *attester = json_string_value(json_object_get(attest, "attester"));
		const char *claim = json_string_value(json_object_get(attest, "claim"));
		json_int_t ts = json_integer_value(json_object_get(attest, "timestamp"));

		char timebuf[32] = "?";
		if (ts > 0) {
			time_t t = (time_t)ts;
			struct tm *tm = localtime(&t);
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm);
		}

		printf("  [%zu] by %.16s...  claim=%s  %s\n",
		       i + 1,
		       attester ? attester : "?",
		       claim ? claim : "?",
		       timebuf);
	}

	json_decref(entry);
	return 0;
}
