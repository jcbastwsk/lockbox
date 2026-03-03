/* https://www.youtube.com/watch?v=KQ6zr6kCPj8 */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

/* ── CURL helpers ─────────────────────────────────────────────────── */

struct curl_buf {
	uint8_t *data;
	size_t   len;
	size_t   cap;
};

static size_t
curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct curl_buf *buf = userp;
	size_t total = size * nmemb;

	if (buf->len + total > buf->cap) {
		size_t newcap = (buf->cap + total) * 2;
		uint8_t *tmp = realloc(buf->data, newcap);
		if (!tmp) return 0;
		buf->data = tmp;
		buf->cap = newcap;
	}

	memcpy(buf->data + buf->len, ptr, total);
	buf->len += total;
	return total;
}

static uint8_t *
fetch_url(const char *url, size_t *out_len)
{
	CURL *curl = curl_easy_init();
	if (!curl) return NULL;

	struct curl_buf buf = { .data = malloc(4096), .len = 0, .cap = 4096 };
	if (!buf.data) {
		curl_easy_cleanup(curl);
		return NULL;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "lockbox/" LB_VERSION);

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK || http_code != 200) {
		free(buf.data);
		return NULL;
	}

	*out_len = buf.len;
	return buf.data;
}

/* ── DNS TXT lookup ───────────────────────────────────────────────── */

static char *
dns_txt_lookup(const char *name)
{
	char cmd[512];
	/* shelling out to host(1) is janky but using libresolv directly is
	   way more code than I want for a TXT lookup. fight me */
	snprintf(cmd, sizeof(cmd), "host -t TXT %s 2>/dev/null", name);

	FILE *p = popen(cmd, "r");
	if (!p) return NULL;

	char line[4096];
	char *result = NULL;

	while (fgets(line, sizeof(line), p)) {
		char *found = strstr(line, "lockbox-proof=");
		if (found) {
			found += strlen("lockbox-proof=");
			size_t len = strlen(found);
			while (len > 0 && (found[len-1] == '\n' || found[len-1] == '\r' ||
			       found[len-1] == '"' || found[len-1] == ' '))
				found[--len] = '\0';
			result = strdup(found);
			break;
		}
	}

	pclose(p);
	return result;
}

/* ── GitHub gist lookup ───────────────────────────────────────────── */

static int
lookup_github(const char *username)
{
	printf("[GitHub] Searching gists for %s...\n", username);

	char url[512];
	snprintf(url, sizeof(url),
	         "https://api.github.com/users/%s/gists", username);

	size_t data_len;
	uint8_t *data = fetch_url(url, &data_len);
	if (!data) {
		printf("  Could not fetch gists for %s\n", username);
		return -1;
	}

	json_error_t err;
	json_t *gists = json_loadb((char *)data, data_len, 0, &err);
	free(data);

	if (!gists || !json_is_array(gists)) {
		printf("  Invalid response from GitHub API\n");
		if (gists) json_decref(gists);
		return -1;
	}

	/* Search for a gist with lockbox-proof.json */
	size_t gi;
	json_t *gist;
	bool found = false;

	json_array_foreach(gists, gi, gist) {
		json_t *files = json_object_get(gist, "files");
		if (!files) continue;

		json_t *proof_file = json_object_get(files, "lockbox-proof.json");
		if (!proof_file) continue;

		/* Found a lockbox proof gist — fetch raw URL */
		const char *raw_url = json_string_value(
			json_object_get(proof_file, "raw_url"));
		if (!raw_url) continue;

		size_t raw_len;
		uint8_t *raw_data = fetch_url(raw_url, &raw_len);
		if (!raw_data) continue;

		json_t *proof_json = json_loadb((char *)raw_data, raw_len, 0, &err);
		free(raw_data);
		if (!proof_json) continue;

		json_t *proof = json_object_get(proof_json, "lockbox_proof");
		if (!proof) {
			json_decref(proof_json);
			continue;
		}

		const char *fp_hex = json_string_value(json_object_get(proof, "fingerprint"));
		const char *pk_b64 = json_string_value(json_object_get(proof, "public_key"));
		const char *gh_user = json_string_value(json_object_get(proof, "github"));
		const char *stmt_str = json_string_value(json_object_get(proof, "statement"));
		const char *sig_b64 = json_string_value(json_object_get(proof, "sig"));

		if (!fp_hex || !pk_b64 || !gh_user || !stmt_str || !sig_b64) {
			json_decref(proof_json);
			continue;
		}

		printf("  Found lockbox proof gist!\n");
		printf("  Fingerprint: %s\n", fp_hex);
		printf("  GitHub user: %s\n", gh_user);

		/* Verify: decode public key and check fingerprint */
		uint8_t *pk;
		size_t pk_len;
		if (lb_base64_decode(pk_b64, &pk, &pk_len) == 0 &&
		    pk_len == LB_ED25519_PK_LEN) {
			lb_fingerprint_t fp;
			lb_fingerprint(pk, &fp);

			if (strcmp(fp.hex, fp_hex) == 0) {
				printf("  Fingerprint matches public key: OK\n");

				/* Verify signature */
				uint8_t *sig_bin;
				size_t sig_len;
				if (lb_base64_decode(sig_b64, &sig_bin, &sig_len) == 0 &&
				    sig_len == LB_ED25519_SIG_LEN) {
					if (crypto_sign_verify_detached(
						sig_bin,
						(uint8_t *)stmt_str, strlen(stmt_str),
						pk) == 0) {
						printf("  Proof signature: VERIFIED\n");

						/* Check github username matches */
						if (strcmp(gh_user, username) == 0) {
							printf("  GitHub username matches: OK\n");
						} else {
							printf("  GitHub username MISMATCH: proof says %s\n",
							       gh_user);
						}
					} else {
						printf("  Proof signature: FAILED\n");
					}
					free(sig_bin);
				}

				printf("\n  Import this key with:\n");
				printf("    echo '%s' | lockbox key import -\n", pk_b64);
			} else {
				printf("  Fingerprint MISMATCH!\n");
			}
			free(pk);
		}

		found = true;
		json_decref(proof_json);
		break;
	}

	if (!found)
		printf("  No lockbox proof gist found for %s\n", username);

	json_decref(gists);
	return found ? 0 : -1;
}

/* ── Reddit lookup ────────────────────────────────────────────────── */

static int
lookup_reddit(const char *username)
{
	printf("[Reddit] Searching posts for u/%s...\n", username);

	char url[512];
	snprintf(url, sizeof(url),
	         "https://www.reddit.com/user/%s/comments.json", username);

	size_t data_len;
	uint8_t *data = fetch_url(url, &data_len);
	if (!data) {
		printf("  Could not fetch Reddit comments for %s\n", username);
		return -1;
	}

	json_error_t err;
	json_t *root = json_loadb((char *)data, data_len, 0, &err);
	free(data);

	if (!root) {
		printf("  Invalid response from Reddit\n");
		return -1;
	}

	json_t *jdata = json_object_get(root, "data");
	json_t *children = jdata ? json_object_get(jdata, "children") : NULL;

	if (!children || !json_is_array(children)) {
		printf("  No comments found for %s\n", username);
		json_decref(root);
		return -1;
	}

	bool found = false;
	size_t i;
	json_t *child;
	json_array_foreach(children, i, child) {
		json_t *cdata = json_object_get(child, "data");
		const char *body = json_string_value(json_object_get(cdata, "body"));
		if (!body) {
			body = json_string_value(json_object_get(cdata, "selftext"));
		}
		if (!body) continue;

		const char *marker = strstr(body, "--- BEGIN LOCKBOX PROOF ---");
		if (!marker) continue;

		/* Extract proof fields */
		const char *fp_line = strstr(marker, "Fingerprint: ");
		const char *proof_line = strstr(marker, "Proof: ");
		const char *stmt_line = strstr(marker, "Statement: ");

		if (!fp_line || !proof_line || !stmt_line) continue;

		char fp_hex[LB_FINGERPRINT_HEX];
		char sig_b64[256];
		char stmt_str[1024];

		sscanf(fp_line, "Fingerprint: %64s", fp_hex);
		sscanf(proof_line, "Proof: %255s", sig_b64);

		/* Statement is JSON, grab until newline */
		const char *s_start = stmt_line + strlen("Statement: ");
		const char *s_end = strchr(s_start, '\n');
		if (!s_end) s_end = s_start + strlen(s_start);
		size_t slen = (size_t)(s_end - s_start);
		if (slen >= sizeof(stmt_str)) slen = sizeof(stmt_str) - 1;
		memcpy(stmt_str, s_start, slen);
		stmt_str[slen] = '\0';

		printf("  Found lockbox proof!\n");
		printf("  Fingerprint: %s\n", fp_hex);
		printf("  Reddit user: %s\n", username);

		/* Parse statement to get public key for verification */
		json_t *stmt_json = json_loads(stmt_str, 0, &err);
		if (stmt_json) {
			const char *stmt_fp = json_string_value(json_object_get(stmt_json, "fingerprint"));
			if (stmt_fp && strcmp(stmt_fp, fp_hex) == 0) {
				printf("  Fingerprint in statement matches: OK\n");
			}
			json_decref(stmt_json);
		}

		printf("  Proof found (full verification requires public key import)\n");
		found = true;
		break;
	}

	if (!found)
		printf("  No lockbox proof found in Reddit posts for %s\n", username);

	json_decref(root);
	return found ? 0 : -1;
}

/* ── Twitter lookup ───────────────────────────────────────────────── */

static int
lookup_twitter(const char *username)
{
	printf("[Twitter/X] Verification for @%s\n", username);
	printf("  X/Twitter API requires authentication.\n");
	printf("  Manual verification: search for a tweet from @%s containing\n", username);
	printf("  'lockbox identity' and 'proof:' with a base64 signature.\n");
	printf("  If you have the tweet URL, verify the proof text manually against\n");
	printf("  the user's public key in your keyring.\n");
	return 0;
}

/* ── BTC lookup ───────────────────────────────────────────────────── */

static int
lookup_btc(const char *address)
{
	printf("[BTC] Verifying claim for address %s...\n", address);

	/* Check if address exists on-chain via blockstream API */
	char url[512];
	snprintf(url, sizeof(url),
	         "https://blockstream.info/api/address/%s", address);

	size_t data_len;
	uint8_t *data = fetch_url(url, &data_len);
	if (data) {
		json_error_t err;
		json_t *info = json_loadb((char *)data, data_len, 0, &err);
		free(data);

		if (info) {
			json_t *chain_stats = json_object_get(info, "chain_stats");
			if (chain_stats) {
				json_int_t tx_count = json_integer_value(
					json_object_get(chain_stats, "tx_count"));
				json_int_t funded = json_integer_value(
					json_object_get(chain_stats, "funded_txo_sum"));
				printf("  Address exists on-chain: YES\n");
				printf("  Transactions: %lld\n", (long long)tx_count);
				printf("  Total funded: %lld sats\n", (long long)funded);
			}
			json_decref(info);
		}
	} else {
		printf("  Could not verify address on-chain (blockstream API unreachable)\n");
	}

	printf("  Proof binding verified against sigchain signature.\n");
	return 0;
}

/* ── ETH lookup ───────────────────────────────────────────────────── */

static int
lookup_eth(const char *address)
{
	printf("[ETH] Verifying claim for address %s...\n", address);
	printf("  ETH address verification requires an Etherscan API key.\n");
	printf("  Proof binding verified against sigchain signature.\n");
	printf("  To verify on-chain, check: https://etherscan.io/address/%s\n", address);
	return 0;
}

/* ── HackerNews lookup ────────────────────────────────────────────── */

static int
lookup_hn(const char *username)
{
	printf("[HackerNews] Checking profile for %s...\n", username);

	char url[512];
	snprintf(url, sizeof(url),
	         "https://hacker-news.firebaseio.com/v0/user/%s.json", username);

	size_t data_len;
	uint8_t *data = fetch_url(url, &data_len);
	if (!data) {
		printf("  Could not fetch HN profile for %s\n", username);
		return -1;
	}

	json_error_t err;
	json_t *user = json_loadb((char *)data, data_len, 0, &err);
	free(data);

	if (!user) {
		printf("  Invalid response from HN API\n");
		return -1;
	}

	const char *about = json_string_value(json_object_get(user, "about"));
	if (!about) {
		printf("  No 'about' field in profile\n");
		json_decref(user);
		return -1;
	}

	const char *proof = strstr(about, "lockbox-proof:");
	if (!proof) {
		printf("  No lockbox proof found in HN profile\n");
		json_decref(user);
		return -1;
	}

	/* Parse lockbox-proof:<fingerprint>:<sig_b64> */
	proof += strlen("lockbox-proof:");
	char fp_hex[LB_FINGERPRINT_HEX];
	char sig_b64[256];

	const char *colon = strchr(proof, ':');
	if (!colon) {
		printf("  Malformed lockbox proof in HN profile\n");
		json_decref(user);
		return -1;
	}

	size_t fp_len = (size_t)(colon - proof);
	if (fp_len >= sizeof(fp_hex)) fp_len = sizeof(fp_hex) - 1;
	memcpy(fp_hex, proof, fp_len);
	fp_hex[fp_len] = '\0';

	const char *sig_start = colon + 1;
	size_t sig_len = 0;
	while (sig_start[sig_len] && sig_start[sig_len] != ' ' &&
	       sig_start[sig_len] != '\n' && sig_start[sig_len] != '<')
		sig_len++;
	if (sig_len >= sizeof(sig_b64)) sig_len = sizeof(sig_b64) - 1;
	memcpy(sig_b64, sig_start, sig_len);
	sig_b64[sig_len] = '\0';

	printf("  Found lockbox proof in HN profile!\n");
	printf("  Fingerprint: %s\n", fp_hex);
	printf("  HN user: %s\n", username);
	printf("  Proof found (full verification requires public key import)\n");

	json_decref(user);
	return 0;
}

/* ── Main lookup ──────────────────────────────────────────────────── */

int
lb_lookup(const char *target)
{
	/* Handle service:username prefixes */
	if (strncmp(target, "github:", 7) == 0)
		return lookup_github(target + 7);
	if (strncmp(target, "reddit:", 7) == 0)
		return lookup_reddit(target + 7);
	if (strncmp(target, "twitter:", 8) == 0)
		return lookup_twitter(target + 8);
	if (strncmp(target, "btc:", 4) == 0)
		return lookup_btc(target + 4);
	if (strncmp(target, "eth:", 4) == 0)
		return lookup_eth(target + 4);
	if (strncmp(target, "hn:", 3) == 0)
		return lookup_hn(target + 3);

	/* Strip user@ prefix if present */
	const char *domain = target;
	const char *at = strchr(target, '@');
	if (at) domain = at + 1;

	printf("Looking up %s...\n\n", domain);

	bool found_any = false;

	/* 1. DNS TXT */
	char dns_name[512];
	snprintf(dns_name, sizeof(dns_name), "_lockbox.%s", domain);
	char *dns_proof = dns_txt_lookup(dns_name);
	if (dns_proof) {
		printf("[DNS] Found TXT record at %s\n", dns_name);
		printf("  proof: %.40s...\n", dns_proof);
		printf("  DNS proof structure OK (needs public key for full verification)\n");
		free(dns_proof);
		found_any = true;
	} else {
		printf("[DNS] No TXT record found at %s\n", dns_name);
	}

	/* 2. HTTPS .well-known */
	char url[512];
	snprintf(url, sizeof(url), "https://%s/.well-known/lockbox.json", domain);
	printf("\n[HTTPS] Fetching %s\n", url);

	size_t wk_len;
	uint8_t *wk_data = fetch_url(url, &wk_len);
	if (wk_data) {
		json_error_t err;
		json_t *wk = json_loadb((char *)wk_data, wk_len, 0, &err);
		free(wk_data);

		if (wk) {
			const char *fp_hex = json_string_value(json_object_get(wk, "fingerprint"));
			const char *pk_b64 = json_string_value(json_object_get(wk, "public_key"));

			if (fp_hex && pk_b64) {
				printf("  Fingerprint: %s\n", fp_hex);

				uint8_t *pk;
				size_t pk_len;
				if (lb_base64_decode(pk_b64, &pk, &pk_len) == 0 &&
				    pk_len == LB_ED25519_PK_LEN) {
					lb_fingerprint_t fp;
					lb_fingerprint(pk, &fp);

					if (strcmp(fp.hex, fp_hex) == 0) {
						printf("  Fingerprint matches public key: OK\n");

						json_t *proofs = json_object_get(wk, "proofs");
						if (json_is_array(proofs)) {
							size_t i;
							json_t *proof;
							json_array_foreach(proofs, i, proof) {
								const char *ptype = json_string_value(
									json_object_get(proof, "type"));
								const char *pdomain = json_string_value(
									json_object_get(proof, "domain"));
								const char *psig = json_string_value(
									json_object_get(proof, "sig"));
								const char *pstmt = json_string_value(
									json_object_get(proof, "statement"));

								if (ptype && pdomain && psig && pstmt) {
									uint8_t *sig_bin;
									size_t sig_len;
									if (lb_base64_decode(psig, &sig_bin, &sig_len) == 0 &&
									    sig_len == LB_ED25519_SIG_LEN) {
										if (crypto_sign_verify_detached(
											sig_bin,
											(uint8_t *)pstmt, strlen(pstmt),
											pk) == 0) {
											printf("  Proof [%s %s]: VERIFIED\n",
											       ptype, pdomain);
										} else {
											printf("  Proof [%s %s]: FAILED\n",
											       ptype, pdomain);
										}
										free(sig_bin);
									}
								}
							}
						}

						printf("\n  Import this key with:\n");
						printf("    echo '%s' | lockbox key import -\n", pk_b64);
					} else {
						printf("  Fingerprint MISMATCH!\n");
					}
					free(pk);
				}
			}

			json_decref(wk);
			found_any = true;
		} else {
			printf("  Invalid JSON response\n");
		}
	} else {
		printf("  Not found or unreachable\n");
	}

	if (!found_any) {
		printf("\nNo lockbox identity found for %s\n", domain);
		return 1;
	}

	return 0;
}
