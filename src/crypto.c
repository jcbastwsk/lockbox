/* https://www.youtube.com/watch?v=KqYMZMBqxXc */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Resolve recipient to public key ──────────────────────────────── */

static int
resolve_recipient(const char *recipient, uint8_t pk_out[LB_ED25519_PK_LEN])
{
	/* Try as hex fingerprint (prefix match in keyring) */
	if (lb_keyring_lookup_hex(recipient, pk_out) == 0)
		return 0;

	/* Try as full hex fingerprint that matches our own key */
	uint8_t own_pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(own_pk) == 0) {
		lb_fingerprint_t own_fp;
		lb_fingerprint(own_pk, &own_fp);
		if (strncmp(own_fp.hex, recipient, strlen(recipient)) == 0) {
			memcpy(pk_out, own_pk, LB_ED25519_PK_LEN);
			return 0;
		}
	}

	/* TODO: try domain-based discovery here — need to think about
	   whether we want to auto-fetch keys or if thats a privacy issue */
	return -1;
}

/* ── Encrypt ──────────────────────────────────────────────────────── */

int
lb_encrypt(const char *recipient, const char *infile, const char *outfile)
{
	/* Resolve recipient public key */
	uint8_t recip_pk[LB_ED25519_PK_LEN];
	if (resolve_recipient(recipient, recip_pk) != 0)
		lb_die("cannot resolve recipient: %s", recipient);

	/*
	 * Convert Ed25519 -> X25519 (see RFC 7748 section 6.1).
	 * This can technically fail if the key is on a small subgroup
	 * but libsodium already rejects those.
	 */
	uint8_t recip_x25519[LB_X25519_PK_LEN];
	if (crypto_sign_ed25519_pk_to_curve25519(recip_x25519, recip_pk) != 0)
		lb_die("failed to convert recipient key to X25519");

	/* Read input */
	size_t in_len;
	uint8_t *in_data = lb_file_read(infile ? infile : "-", &in_len);
	if (!in_data)
		lb_die("cannot read input");

	/* Load our keypair for the sender fingerprint */
	lb_keypair_t kp;
	bool have_sender = (lb_keypair_load(&kp) == 0);

	/* Generate ephemeral X25519 keypair */
	uint8_t eph_pk[LB_X25519_PK_LEN], eph_sk[LB_X25519_SK_LEN];
	crypto_box_keypair(eph_pk, eph_sk);

	/* Compute shared key via X25519 */
	uint8_t shared[crypto_box_BEFORENMBYTES];
	if (crypto_box_beforenm(shared, recip_x25519, eph_sk) != 0)
		lb_die("key agreement failed");

	/* Nonce */
	uint8_t nonce[LB_NONCE_LEN];
	randombytes_buf(nonce, LB_NONCE_LEN);

	/* Encrypt with XChaCha20-Poly1305 */
	size_t ct_len = in_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	uint8_t *ciphertext = malloc(ct_len);
	if (!ciphertext)
		lb_die("out of memory");

	unsigned long long actual_ct_len;
	crypto_aead_xchacha20poly1305_ietf_encrypt(
		ciphertext, &actual_ct_len,
		in_data, in_len,
		NULL, 0,        /* no additional data */
		NULL,           /* nsec (unused) */
		nonce, shared);

	/* Build output: header + ciphertext */
	size_t out_len = LB_FILE_HEADER_LEN + actual_ct_len;
	uint8_t *out_data = malloc(out_len);
	if (!out_data)
		lb_die("out of memory");

	uint8_t *p = out_data;

	/* Magic */
	memcpy(p, LB_MAGIC, LB_MAGIC_LEN);
	p += LB_MAGIC_LEN;

	/* Version */
	*p++ = LB_FILE_VERSION;

	/* Type */
	*p++ = LB_TYPE_AUTH_BOX;

	/* Sender fingerprint */
	if (have_sender) {
		lb_fingerprint_t fp;
		lb_fingerprint(kp.pk, &fp);
		memcpy(p, fp.fp, LB_FINGERPRINT_LEN);
	} else {
		memset(p, 0, LB_FINGERPRINT_LEN);
	}
	p += LB_FINGERPRINT_LEN;

	/* Ephemeral public key */
	memcpy(p, eph_pk, LB_X25519_PK_LEN);
	p += LB_X25519_PK_LEN;

	/* Nonce */
	memcpy(p, nonce, LB_NONCE_LEN);
	p += LB_NONCE_LEN;

	/* Ciphertext */
	memcpy(p, ciphertext, actual_ct_len);

	/* Write output */
	if (lb_file_write(outfile ? outfile : "-", out_data, out_len, 0) != 0)
		lb_die("failed to write output");

	sodium_memzero(shared, sizeof(shared));
	sodium_memzero(eph_sk, sizeof(eph_sk));
	sodium_memzero(&kp, sizeof(kp));
	free(in_data);
	free(ciphertext);
	free(out_data);
	return 0;
}

/* ── Decrypt ──────────────────────────────────────────────────────── */

int
lb_decrypt(const char *infile, const char *outfile)
{
	/* Read input */
	size_t in_len;
	uint8_t *in_data = lb_file_read(infile ? infile : "-", &in_len);
	if (!in_data)
		lb_die("cannot read input");

	if (in_len < LB_FILE_HEADER_LEN)
		lb_die("input too short to be a lockbox file");

	/* Parse header */
	uint8_t *p = in_data;

	if (memcmp(p, LB_MAGIC, LB_MAGIC_LEN) != 0)
		lb_die("not a lockbox encrypted file (bad magic)");
	p += LB_MAGIC_LEN;

	uint8_t version = *p++;
	if (version != LB_FILE_VERSION)
		lb_die("unsupported file version: %d", version);

	uint8_t type = *p++;
	if (type != LB_TYPE_AUTH_BOX && type != LB_TYPE_SEALED && type != LB_TYPE_SIGN_ENCRYPT)
		lb_die("unsupported encryption type: 0x%02x", type);

	/* Skip sender fingerprint for now */
	p += LB_FINGERPRINT_LEN;

	uint8_t eph_pk[LB_X25519_PK_LEN];
	memcpy(eph_pk, p, LB_X25519_PK_LEN);
	p += LB_X25519_PK_LEN;

	uint8_t nonce[LB_NONCE_LEN];
	memcpy(nonce, p, LB_NONCE_LEN);
	p += LB_NONCE_LEN;

	size_t ct_len = in_len - LB_FILE_HEADER_LEN;
	uint8_t *ciphertext = p;

	/* Load our keypair */
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	/* Convert our Ed25519 secret key to X25519 */
	uint8_t our_x25519_sk[LB_X25519_SK_LEN];
	if (crypto_sign_ed25519_sk_to_curve25519(our_x25519_sk, kp.sk) != 0)
		lb_die("failed to convert secret key to X25519");

	/* Compute shared key */
	uint8_t shared[crypto_box_BEFORENMBYTES];
	if (crypto_box_beforenm(shared, eph_pk, our_x25519_sk) != 0)
		lb_die("key agreement failed");

	/* Decrypt */
	if (ct_len < crypto_aead_xchacha20poly1305_ietf_ABYTES)
		lb_die("ciphertext too short");

	size_t pt_len = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
	uint8_t *plaintext = malloc(pt_len);
	if (!plaintext)
		lb_die("out of memory");

	unsigned long long actual_pt_len;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(
		plaintext, &actual_pt_len,
		NULL,           /* nsec (unused) */
		ciphertext, ct_len,
		NULL, 0,        /* no additional data */
		nonce, shared) != 0)
		lb_die("decryption failed (wrong key or corrupted data)");

	/* Write output */
	if (lb_file_write(outfile ? outfile : "-", plaintext, actual_pt_len, 0) != 0)
		lb_die("failed to write output");

	sodium_memzero(shared, sizeof(shared));
	sodium_memzero(our_x25519_sk, sizeof(our_x25519_sk));
	sodium_memzero(&kp, sizeof(kp));
	free(plaintext);
	free(in_data);
	return 0;
}

/* ── Sign ─────────────────────────────────────────────────────────── */

int
lb_sign(const char *infile)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	size_t in_len;
	uint8_t *in_data = lb_file_read(infile ? infile : "-", &in_len);
	if (!in_data)
		lb_die("cannot read input");

	uint8_t sig[LB_ED25519_SIG_LEN];
	crypto_sign_detached(sig, NULL, in_data, in_len, kp.sk);

	/* Output base64 signature */
	char *b64 = lb_base64_encode(sig, LB_ED25519_SIG_LEN);
	printf("%s\n", b64);

	free(b64);
	free(in_data);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

/* ── Verify ───────────────────────────────────────────────────────── */
/* NOTE: this only checks against our own key right now. should probably
   take a --signer flag or something. filed it in my head. */

int
lb_verify(const char *sigfile, const char *infile)
{
	/* Read signature */
	size_t sig_flen;
	uint8_t *sig_data = lb_file_read(sigfile, &sig_flen);
	if (!sig_data)
		lb_die("cannot read signature file: %s", sigfile);

	/* Parse base64 signature, stripping whitespace */
	char *sig_str = malloc(sig_flen + 1);
	memcpy(sig_str, sig_data, sig_flen);
	sig_str[sig_flen] = '\0';
	/* Strip trailing whitespace */
	while (sig_flen > 0 && (sig_str[sig_flen-1] == '\n' ||
	       sig_str[sig_flen-1] == '\r' || sig_str[sig_flen-1] == ' '))
		sig_str[--sig_flen] = '\0';

	uint8_t *sig_bin;
	size_t sig_len;
	if (lb_base64_decode(sig_str, &sig_bin, &sig_len) != 0 ||
	    sig_len != LB_ED25519_SIG_LEN)
		lb_die("invalid signature format");
	free(sig_str);
	free(sig_data);

	/* Read input */
	size_t in_len;
	uint8_t *in_data = lb_file_read(infile ? infile : "-", &in_len);
	if (!in_data)
		lb_die("cannot read input");

	/* Load public key */
	uint8_t pk[LB_ED25519_PK_LEN];
	if (lb_pubkey_load(pk) != 0)
		lb_die("failed to load public key");

	if (crypto_sign_verify_detached(sig_bin, in_data, in_len, pk) != 0) {
		fprintf(stderr, "lockbox: signature verification FAILED\n");
		free(sig_bin);
		free(in_data);
		return 1;
	}

	printf("Signature OK\n");
	free(sig_bin);
	free(in_data);
	return 0;
}
