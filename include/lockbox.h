#ifndef LOCKBOX_H
#define LOCKBOX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>
#include <jansson.h>

/* ── Constants ────────────────────────────────────────────────────── */

#define LB_VERSION           "0.2.0"
#define LB_MAGIC             "LOCKBOX\x00"
#define LB_MAGIC_LEN         8
#define LB_FILE_VERSION      1

#define LB_ED25519_PK_LEN    crypto_sign_PUBLICKEYBYTES   /* 32 */
#define LB_ED25519_SK_LEN    crypto_sign_SECRETKEYBYTES   /* 64 */
#define LB_ED25519_SIG_LEN   crypto_sign_BYTES            /* 64 */
#define LB_X25519_PK_LEN     crypto_scalarmult_curve25519_BYTES /* 32 */
#define LB_X25519_SK_LEN     crypto_scalarmult_curve25519_BYTES /* 32 */
#define LB_FINGERPRINT_LEN   crypto_hash_sha256_BYTES     /* 32 */
#define LB_FINGERPRINT_HEX   (LB_FINGERPRINT_LEN * 2 + 1)
#define LB_NONCE_LEN         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES /* 24 */
#define LB_KEY_LEN           crypto_aead_xchacha20poly1305_ietf_KEYBYTES  /* 32 */
#define LB_AEAD_TAG_LEN      crypto_aead_xchacha20poly1305_ietf_ABYTES    /* 16 */

#define LB_SEALED_OVERHEAD   (crypto_box_SEALBYTES)       /* 48 */
#define LB_BOX_OVERHEAD      (crypto_box_MACBYTES)        /* 16 */

/* File format type bytes */
#define LB_TYPE_SEALED       0x01
#define LB_TYPE_AUTH_BOX     0x02
#define LB_TYPE_SIGN_ENCRYPT 0x03

/* Header size: magic(8) + version(1) + type(1) + sender_fp(32) + ephemeral(32) + nonce(24) */
#define LB_FILE_HEADER_LEN   (LB_MAGIC_LEN + 1 + 1 + LB_FINGERPRINT_LEN + LB_X25519_PK_LEN + LB_NONCE_LEN)

/* Sigchain link types */
#define LB_LINK_KEY_CREATE        "key.create"
#define LB_LINK_KEY_REVOKE        "key.revoke"
#define LB_LINK_KEY_CERTIFY       "key.certify"
#define LB_LINK_IDENTITY_DNS      "identity.prove.dns"
#define LB_LINK_IDENTITY_HTTPS    "identity.prove.https"
#define LB_LINK_IDENTITY_GITHUB   "identity.prove.github"
#define LB_LINK_IDENTITY_REVOKE   "identity.revoke"

/* Trust limits */
#define LB_TRUST_MAX_DEPTH        4
#define LB_MAX_KEYRING            256

/* was going to use this for the multiparty stuff, keeping it around */
#define LB_MAX_RECIPIENTS         16

/* DHT */
#define LB_DHT_NODE_ID_LEN        20
#define LB_DHT_COMPACT_NODE_LEN   26  /* 20 id + 4 ip + 2 port */
#define LB_DHT_MAX_NODES          64
#define LB_DHT_BOOTSTRAP_HOST     "router.bittorrent.com"
#define LB_DHT_BOOTSTRAP_PORT     6881
#define LB_DHT_TIMEOUT_MS         3000

/* ── Data directory paths ─────────────────────────────────────────── */

#define LB_DIR_NAME          ".lockbox"
#define LB_CONFIG_FILE       "config.json"
#define LB_SECRET_KEY_FILE   "secret.key"
#define LB_PUBLIC_KEY_FILE   "public.key"
#define LB_SIGCHAIN_FILE     "sigchain.json"
#define LB_KEYRING_DIR       "keyring"

/* ── Types ────────────────────────────────────────────────────────── */

typedef struct {
	uint8_t pk[LB_ED25519_PK_LEN];
	uint8_t sk[LB_ED25519_SK_LEN];
} lb_keypair_t;

typedef struct {
	uint8_t fp[LB_FINGERPRINT_LEN];
	char    hex[LB_FINGERPRINT_HEX];
} lb_fingerprint_t;

typedef struct {
	uint8_t pk[LB_ED25519_PK_LEN];
	lb_fingerprint_t fp;
	char   *label;              /* optional human label */
} lb_keyring_entry_t;

typedef struct {
	uint8_t  magic[LB_MAGIC_LEN];
	uint8_t  version;
	uint8_t  type;
	uint8_t  sender_fp[LB_FINGERPRINT_LEN];
	uint8_t  ephemeral_pk[LB_X25519_PK_LEN];
	uint8_t  nonce[LB_NONCE_LEN];
} lb_file_header_t;

/* ── util.c ───────────────────────────────────────────────────────── */

char   *lb_base64_encode(const uint8_t *data, size_t len);
int     lb_base64_decode(const char *b64, uint8_t **out, size_t *out_len);

void    lb_hex_encode(const uint8_t *data, size_t len, char *out);
int     lb_hex_decode(const char *hex, uint8_t *out, size_t max_len);

uint8_t *lb_file_read(const char *path, size_t *len);
int      lb_file_write(const char *path, const uint8_t *data, size_t len, int mode);
int      lb_file_exists(const char *path);

char   *lb_data_path(const char *name);

void    lb_hexdump(const uint8_t *data, size_t len);  /* debug */

void    lb_die(const char *fmt, ...);
void    lb_warn(const char *fmt, ...);

/* ── keys.c ───────────────────────────────────────────────────────── */

int     lb_init(void);
int     lb_keypair_load(lb_keypair_t *kp);
int     lb_pubkey_load(uint8_t pk[LB_ED25519_PK_LEN]);
void    lb_fingerprint(const uint8_t pk[LB_ED25519_PK_LEN], lb_fingerprint_t *fp);
int     lb_key_export(bool json_format);
int     lb_key_import(const char *path);
int     lb_key_list(void);
int     lb_key_show_fingerprint(void);
int     lb_show_id(void);

/* Keyring helpers */
int     lb_keyring_save(const uint8_t pk[LB_ED25519_PK_LEN], const char *label);
int     lb_keyring_lookup_hex(const char *hex_prefix, uint8_t pk_out[LB_ED25519_PK_LEN]);
json_t *lb_keyring_load_entry(const char *hex_prefix);
int     lb_keyring_save_json(const char *fp_hex, json_t *obj);

/* Web of trust */
int     lb_certify(const char *fingerprint);
int     lb_trust_show(const char *fingerprint);

/* ── crypto.c ─────────────────────────────────────────────────────── */

int     lb_encrypt(const char *recipient, const char *infile, const char *outfile);
int     lb_decrypt(const char *infile, const char *outfile);
int     lb_sign(const char *infile);
int     lb_verify(const char *sigfile, const char *infile);

/* ── sigchain.c ───────────────────────────────────────────────────── */

int     lb_sigchain_init(const uint8_t pk[LB_ED25519_PK_LEN],
                         const uint8_t sk[LB_ED25519_SK_LEN]);
int     lb_sigchain_append(const char *type, json_t *payload,
                           const uint8_t sk[LB_ED25519_SK_LEN]);
int     lb_sigchain_show(void);
int     lb_sigchain_verify(void);

/* ── identity.c ───────────────────────────────────────────────────── */

int     lb_prove_dns(const char *domain);
int     lb_prove_https(const char *domain);
int     lb_prove_github(const char *username);

/* ── discover.c ───────────────────────────────────────────────────── */

int     lb_lookup(const char *target);

/* ── share.c ──────────────────────────────────────────────────────── */

int     lb_share_encrypt(const char *file, const char *recipient);
int     lb_share_decrypt(const char *file, const char *outfile);

/* ── dht.c ────────────────────────────────────────────────────────── */

int     lb_dht_publish(void);
int     lb_dht_lookup(const char *target);

/* ── tui.c ────────────────────────────────────────────────────────── */

int     lb_tui(void);

#endif /* LOCKBOX_H */
