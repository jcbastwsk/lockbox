/* https://www.youtube.com/watch?v=KLNFPCd80OQ */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* all three proof types are basically the same pattern — sign a
   statement, format it for wherever it needs to go. could probably
   refactor but they're different enough that it'd be more confusing */

/* ── DNS proof ────────────────────────────────────────────────────── */

int
lb_prove_dns(const char *domain)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t fp;
	lb_fingerprint(kp.pk, &fp);

	json_t *stmt = json_object();
	json_object_set_new(stmt, "fingerprint", json_string(fp.hex));
	json_object_set_new(stmt, "domain", json_string(domain));
	json_object_set_new(stmt, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(stmt, "type", json_string("dns"));

	char *stmt_str = json_dumps(stmt, JSON_SORT_KEYS | JSON_COMPACT);

	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)stmt_str, strlen(stmt_str), kp.sk);

	size_t combined_len = strlen(stmt_str) + 1 + LB_ED25519_SIG_LEN;
	uint8_t *combined = malloc(combined_len);
	memcpy(combined, stmt_str, strlen(stmt_str));
	combined[strlen(stmt_str)] = '.';
	memcpy(combined + strlen(stmt_str) + 1, sig, LB_ED25519_SIG_LEN);

	char *proof_b64 = lb_base64_encode(combined, combined_len);

	printf("Add this DNS TXT record to _lockbox.%s:\n\n", domain);
	printf("  lockbox-proof=%s\n\n", proof_b64);

	json_t *payload = json_object();
	json_object_set_new(payload, "domain", json_string(domain));
	json_object_set_new(payload, "proof", json_string(proof_b64));

	lb_sigchain_append(LB_LINK_IDENTITY_DNS, payload, kp.sk);
	json_decref(payload);

	printf("Proof added to sigchain.\n");

	free(proof_b64);
	free(combined);
	free(stmt_str);
	json_decref(stmt);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

/* ── HTTPS proof ──────────────────────────────────────────────────── */

int
lb_prove_https(const char *domain)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t fp;
	lb_fingerprint(kp.pk, &fp);
	char *pk_b64 = lb_base64_encode(kp.pk, LB_ED25519_PK_LEN);

	json_t *stmt = json_object();
	json_object_set_new(stmt, "fingerprint", json_string(fp.hex));
	json_object_set_new(stmt, "domain", json_string(domain));
	json_object_set_new(stmt, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(stmt, "type", json_string("https"));

	char *stmt_str = json_dumps(stmt, JSON_SORT_KEYS | JSON_COMPACT);

	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)stmt_str, strlen(stmt_str), kp.sk);
	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);

	json_t *proof_entry = json_object();
	json_object_set_new(proof_entry, "type", json_string("https"));
	json_object_set_new(proof_entry, "domain", json_string(domain));
	json_object_set_new(proof_entry, "statement", json_string(stmt_str));
	json_object_set_new(proof_entry, "sig", json_string(sig_b64));

	json_t *proofs = json_array();
	json_array_append_new(proofs, proof_entry);

	json_t *wellknown = json_object();
	json_object_set_new(wellknown, "fingerprint", json_string(fp.hex));
	json_object_set_new(wellknown, "public_key", json_string(pk_b64));
	json_object_set_new(wellknown, "proofs", proofs);

	char *wk_str = json_dumps(wellknown, JSON_INDENT(2));

	printf("Place this file at https://%s/.well-known/lockbox.json:\n\n", domain);
	printf("%s\n\n", wk_str);

	json_t *payload = json_object();
	json_object_set_new(payload, "domain", json_string(domain));
	json_object_set_new(payload, "statement", json_string(stmt_str));
	json_object_set_new(payload, "sig", json_string(sig_b64));

	lb_sigchain_append(LB_LINK_IDENTITY_HTTPS, payload, kp.sk);
	json_decref(payload);

	printf("Proof added to sigchain.\n");

	free(wk_str);
	json_decref(wellknown);
	free(sig_b64);
	free(stmt_str);
	json_decref(stmt);
	free(pk_b64);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

/* ── GitHub gist proof ────────────────────────────────────────────── */

int
lb_prove_github(const char *username)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t fp;
	lb_fingerprint(kp.pk, &fp);
	char *pk_b64 = lb_base64_encode(kp.pk, LB_ED25519_PK_LEN);

	/* Build proof statement */
	json_t *stmt = json_object();
	json_object_set_new(stmt, "fingerprint", json_string(fp.hex));
	json_object_set_new(stmt, "github", json_string(username));
	json_object_set_new(stmt, "timestamp", json_integer((json_int_t)time(NULL)));
	json_object_set_new(stmt, "type", json_string("github"));

	char *stmt_str = json_dumps(stmt, JSON_SORT_KEYS | JSON_COMPACT);

	/* Sign the statement */
	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, (uint8_t *)stmt_str, strlen(stmt_str), kp.sk);
	char *sig_b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);

	/* Build gist content */
	printf("Create a public GitHub gist named 'lockbox-proof.json' with this content:\n\n");
	printf("{\n");
	printf("  \"lockbox_proof\": {\n");
	printf("    \"fingerprint\": \"%s\",\n", fp.hex);
	printf("    \"public_key\": \"%s\",\n", pk_b64);
	printf("    \"github\": \"%s\",\n", username);
	printf("    \"statement\": \"%s\",\n", stmt_str);
	printf("    \"sig\": \"%s\"\n", sig_b64);
	printf("  }\n");
	printf("}\n\n");
	printf("Then run: lockbox lookup github:%s\n\n", username);

	/* Add to sigchain */
	json_t *payload = json_object();
	json_object_set_new(payload, "github", json_string(username));
	json_object_set_new(payload, "statement", json_string(stmt_str));
	json_object_set_new(payload, "sig", json_string(sig_b64));

	lb_sigchain_append(LB_LINK_IDENTITY_GITHUB, payload, kp.sk);
	json_decref(payload);

	printf("Proof added to sigchain.\n");

	free(sig_b64);
	free(stmt_str);
	json_decref(stmt);
	free(pk_b64);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}
