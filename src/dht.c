/* https://www.youtube.com/watch?v=Kei97bMGsnM */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

/*
 * Minimal BEP 5 / BEP 44 DHT client.
 * Speaks just enough Kademlia to bootstrap, find nodes, and get/put
 * mutable items keyed by Ed25519 public keys.
 *
 * This is not a "proper" DHT node — it doesn't respond to queries from
 * other nodes or maintain a routing table across runs. Good enough for
 * publishing and looking up identity records though.
 *
 * The bencode parser is ugly. I know. It works.
 */

/* ── Bencode ──────────────────────────────────────────────────────── */

/* Simple bencode buffer */
typedef struct {
	uint8_t *data;
	size_t   len;
	size_t   cap;
} benc_buf_t;

static void
bb_init(benc_buf_t *b)
{
	b->cap = 512;
	b->len = 0;
	b->data = malloc(b->cap);
}

static void
bb_append(benc_buf_t *b, const void *p, size_t n)
{
	while (b->len + n > b->cap) {
		b->cap *= 2;
		b->data = realloc(b->data, b->cap);
	}
	memcpy(b->data + b->len, p, n);
	b->len += n;
}

static void
bb_printf(benc_buf_t *b, const char *fmt, ...)
{
	char tmp[128];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	bb_append(b, tmp, n);
}

/* Encode a bencode string */
static void
benc_str(benc_buf_t *b, const void *s, size_t len)
{
	bb_printf(b, "%zu:", len);
	bb_append(b, s, len);
}

static void
benc_int(benc_buf_t *b, int64_t v)
{
	bb_printf(b, "i%llde", (long long)v);
}

/* Decode helpers — minimal recursive-descent parser */

typedef struct {
	const uint8_t *data;
	size_t         pos;
	size_t         len;
} benc_dec_t;

/* Forward declarations */
static int bd_parse(benc_dec_t *d, json_t **out);

static int
bd_string(benc_dec_t *d, const uint8_t **out, size_t *out_len)
{
	size_t slen = 0;
	while (d->pos < d->len && d->data[d->pos] >= '0' && d->data[d->pos] <= '9') {
		slen = slen * 10 + (d->data[d->pos] - '0');
		d->pos++;
	}
	if (d->pos >= d->len || d->data[d->pos] != ':')
		return -1;
	d->pos++;
	if (d->pos + slen > d->len)
		return -1;
	*out = d->data + d->pos;
	*out_len = slen;
	d->pos += slen;
	return 0;
}

static int
bd_parse(benc_dec_t *d, json_t **out)
{
	if (d->pos >= d->len)
		return -1;

	uint8_t c = d->data[d->pos];

	/* Integer */
	if (c == 'i') {
		d->pos++;
		int64_t val = 0;
		int neg = 0;
		if (d->pos < d->len && d->data[d->pos] == '-') {
			neg = 1;
			d->pos++;
		}
		while (d->pos < d->len && d->data[d->pos] != 'e') {
			val = val * 10 + (d->data[d->pos] - '0');
			d->pos++;
		}
		if (d->pos >= d->len) return -1;
		d->pos++; /* skip 'e' */
		*out = json_integer(neg ? -val : val);
		return 0;
	}

	/* List */
	if (c == 'l') {
		d->pos++;
		*out = json_array();
		while (d->pos < d->len && d->data[d->pos] != 'e') {
			json_t *elem;
			if (bd_parse(d, &elem) != 0) return -1;
			json_array_append_new(*out, elem);
		}
		if (d->pos >= d->len) return -1;
		d->pos++; /* skip 'e' */
		return 0;
	}

	/* Dict */
	if (c == 'd') {
		d->pos++;
		*out = json_object();
		while (d->pos < d->len && d->data[d->pos] != 'e') {
			const uint8_t *key;
			size_t key_len;
			if (bd_string(d, &key, &key_len) != 0) return -1;

			/* Make null-terminated key */
			char *kstr = malloc(key_len + 1);
			memcpy(kstr, key, key_len);
			kstr[key_len] = '\0';

			json_t *val;
			if (bd_parse(d, &val) != 0) {
				free(kstr);
				return -1;
			}

			/* For binary strings (like node IDs), store as base64 in JSON */
			json_object_set_new(*out, kstr, val);
			free(kstr);
		}
		if (d->pos >= d->len) return -1;
		d->pos++; /* skip 'e' */
		return 0;
	}

	/* String */
	if (c >= '0' && c <= '9') {
		const uint8_t *s;
		size_t slen;
		if (bd_string(d, &s, &slen) != 0) return -1;
		/* Store as base64 if binary, otherwise as string */
		bool is_binary = false;
		for (size_t i = 0; i < slen; i++) {
			if (s[i] < 0x20 && s[i] != '\t' && s[i] != '\n' && s[i] != '\r') {
				is_binary = true;
				break;
			}
		}
		if (is_binary) {
			char *b64 = lb_base64_encode(s, slen);
			*out = json_string(b64);
			free(b64);
		} else {
			char *tmp = malloc(slen + 1);
			memcpy(tmp, s, slen);
			tmp[slen] = '\0';
			*out = json_string(tmp);
			free(tmp);
		}
		return 0;
	}

	return -1;
}

/* ── DHT node tracking ────────────────────────────────────────────── */

typedef struct {
	uint8_t  id[LB_DHT_NODE_ID_LEN];
	uint32_t ip;
	uint16_t port;
	bool     responded;
	uint8_t  token[64];
	size_t   token_len;
} dht_node_t;

static uint8_t our_node_id[LB_DHT_NODE_ID_LEN];
static dht_node_t nodes[LB_DHT_MAX_NODES];
static int num_nodes = 0;

/* XOR distance — standard kademlia metric, nothing fancy */
static int
xor_cmp(const uint8_t *target, const uint8_t *a, const uint8_t *b)
{
	for (int i = 0; i < LB_DHT_NODE_ID_LEN; i++) {
		uint8_t da = a[i] ^ target[i];
		uint8_t db = b[i] ^ target[i];
		if (da < db) return -1;
		if (da > db) return 1;
	}
	return 0;
}

static void
add_node(const uint8_t *id, uint32_t ip, uint16_t port)
{
	/* Check for duplicate */
	for (int i = 0; i < num_nodes; i++) {
		if (memcmp(nodes[i].id, id, LB_DHT_NODE_ID_LEN) == 0)
			return;
	}
	if (num_nodes >= LB_DHT_MAX_NODES)
		return;
	memcpy(nodes[num_nodes].id, id, LB_DHT_NODE_ID_LEN);
	nodes[num_nodes].ip = ip;
	nodes[num_nodes].port = port;
	nodes[num_nodes].responded = false;
	nodes[num_nodes].token_len = 0;
	num_nodes++;
}

/* Parse compact node info (26 bytes per node) */
static void
parse_compact_nodes(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i + LB_DHT_COMPACT_NODE_LEN <= len; i += LB_DHT_COMPACT_NODE_LEN) {
		const uint8_t *id = data + i;
		uint32_t ip;
		memcpy(&ip, data + i + 20, 4);
		uint16_t port;
		memcpy(&port, data + i + 24, 2);
		port = ntohs(port);
		add_node(id, ip, port);
	}
}

/* ── UDP helpers ──────────────────────────────────────────────────── */

static int
dht_send(int sock, const uint8_t *data, size_t len, uint32_t ip, uint16_t port)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = htons(port);
	return sendto(sock, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
}

static int
dht_recv(int sock, uint8_t *buf, size_t buflen, int timeout_ms)
{
	struct timeval tv;
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	int ret = select(sock + 1, &fds, NULL, NULL, &tv);
	if (ret <= 0)
		return -1;

	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	return recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&from, &fromlen);
}

/* ── DHT queries ──────────────────────────────────────────────────── */

static uint16_t txn_id = 1;

static void
build_find_node(benc_buf_t *b, const uint8_t *target)
{
	char tid[3];
	snprintf(tid, sizeof(tid), "%02x", txn_id++);

	bb_append(b, "d", 1);
	  benc_str(b, "a", 1);
	  bb_append(b, "d", 1);
	    benc_str(b, "id", 2);
	    benc_str(b, our_node_id, LB_DHT_NODE_ID_LEN);
	    benc_str(b, "target", 6);
	    benc_str(b, target, LB_DHT_NODE_ID_LEN);
	  bb_append(b, "e", 1);
	  benc_str(b, "q", 1);
	  benc_str(b, "find_node", 9);
	  benc_str(b, "t", 1);
	  benc_str(b, tid, 2);
	  benc_str(b, "y", 1);
	  benc_str(b, "q", 1);
	bb_append(b, "e", 1);
}

static void
build_get(benc_buf_t *b, const uint8_t target[LB_DHT_NODE_ID_LEN])
{
	char tid[3];
	snprintf(tid, sizeof(tid), "%02x", txn_id++);

	bb_append(b, "d", 1);
	  benc_str(b, "a", 1);
	  bb_append(b, "d", 1);
	    benc_str(b, "id", 2);
	    benc_str(b, our_node_id, LB_DHT_NODE_ID_LEN);
	    benc_str(b, "target", 6);
	    benc_str(b, target, LB_DHT_NODE_ID_LEN);
	  bb_append(b, "e", 1);
	  benc_str(b, "q", 1);
	  benc_str(b, "get", 3);
	  benc_str(b, "t", 1);
	  benc_str(b, tid, 2);
	  benc_str(b, "y", 1);
	  benc_str(b, "q", 1);
	bb_append(b, "e", 1);
}

static void
build_put(benc_buf_t *b, const uint8_t pk[LB_ED25519_PK_LEN],
          const uint8_t sig[LB_ED25519_SIG_LEN], int64_t seq,
          const uint8_t *val, size_t val_len,
          const uint8_t *token, size_t token_len)
{
	char tid[3];
	snprintf(tid, sizeof(tid), "%02x", txn_id++);

	bb_append(b, "d", 1);
	  benc_str(b, "a", 1);
	  bb_append(b, "d", 1);
	    benc_str(b, "id", 2);
	    benc_str(b, our_node_id, LB_DHT_NODE_ID_LEN);
	    benc_str(b, "k", 1);
	    benc_str(b, pk, LB_ED25519_PK_LEN);
	    benc_str(b, "seq", 3);
	    benc_int(b, seq);
	    benc_str(b, "sig", 3);
	    benc_str(b, sig, LB_ED25519_SIG_LEN);
	    benc_str(b, "token", 5);
	    benc_str(b, token, token_len);
	    benc_str(b, "v", 1);
	    benc_str(b, val, val_len);
	  bb_append(b, "e", 1);
	  benc_str(b, "q", 1);
	  benc_str(b, "put", 3);
	  benc_str(b, "t", 1);
	  benc_str(b, tid, 2);
	  benc_str(b, "y", 1);
	  benc_str(b, "q", 1);
	bb_append(b, "e", 1);
}

/* ── Bootstrap ────────────────────────────────────────────────────── */

static int
bootstrap(int sock, const uint8_t *target)
{
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res;

	const char *hosts[] = {
		"router.bittorrent.com",
		"dht.transmissionbt.com",
		"router.utorrent.com",
	};

	for (int h = 0; h < 3; h++) {
		if (getaddrinfo(hosts[h], "6881", &hints, &res) != 0)
			continue;

		struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;

		benc_buf_t b;
		bb_init(&b);
		build_find_node(&b, target);
		dht_send(sock, b.data, b.len, sin->sin_addr.s_addr, 6881);
		free(b.data);
		freeaddrinfo(res);
	}

	/* Collect responses */
	for (int i = 0; i < 10; i++) {
		uint8_t buf[4096];
		int n = dht_recv(sock, buf, sizeof(buf), 500);
		if (n <= 0) continue;

		benc_dec_t d = { .data = buf, .pos = 0, .len = n };
		json_t *resp;
		if (bd_parse(&d, &resp) != 0) continue;

		json_t *r = json_object_get(resp, "r");
		if (r) {
			const char *nodes_b64 = json_string_value(json_object_get(r, "nodes"));
			if (nodes_b64) {
				uint8_t *nodes_bin;
				size_t nodes_len;
				if (lb_base64_decode(nodes_b64, &nodes_bin, &nodes_len) == 0) {
					parse_compact_nodes(nodes_bin, nodes_len);
					free(nodes_bin);
				}
			}
		}
		json_decref(resp);
	}

	return num_nodes > 0 ? 0 : -1;
}

/* ── Iterative find_node ──────────────────────────────────────────── */

static void
iterative_find(int sock, const uint8_t *target, int rounds)
{
	for (int round = 0; round < rounds; round++) {
		int queried = 0;
		for (int i = 0; i < num_nodes && queried < 3; i++) {
			if (nodes[i].responded)
				continue;

			benc_buf_t b;
			bb_init(&b);
			build_find_node(&b, target);
			dht_send(sock, b.data, b.len, nodes[i].ip, nodes[i].port);
			free(b.data);
			nodes[i].responded = true;
			queried++;
		}

		/* Collect responses */
		for (int i = 0; i < 5; i++) {
			uint8_t buf[4096];
			int n = dht_recv(sock, buf, sizeof(buf), 500);
			if (n <= 0) continue;

			benc_dec_t d = { .data = buf, .pos = 0, .len = n };
			json_t *resp;
			if (bd_parse(&d, &resp) != 0) continue;

			json_t *r = json_object_get(resp, "r");
			if (r) {
				const char *nodes_b64 = json_string_value(json_object_get(r, "nodes"));
				if (nodes_b64) {
					uint8_t *nodes_bin;
					size_t nodes_len;
					if (lb_base64_decode(nodes_b64, &nodes_bin, &nodes_len) == 0) {
						parse_compact_nodes(nodes_bin, nodes_len);
						free(nodes_bin);
					}
				}
			}
			json_decref(resp);
		}

		/* Sort by distance to target (yeah its bubble sort, sue me) */
		for (int i = 0; i < num_nodes - 1; i++) {
			for (int j = i + 1; j < num_nodes; j++) {
				if (xor_cmp(target, nodes[j].id, nodes[i].id) < 0) {
					dht_node_t tmp = nodes[i];
					nodes[i] = nodes[j];
					nodes[j] = tmp;
				}
			}
		}
	}
}

/* ── Compute BEP 44 target (SHA-1 of public key) ─────────────────── */

static void
bep44_target(const uint8_t pk[LB_ED25519_PK_LEN], uint8_t target[LB_DHT_NODE_ID_LEN])
{
	/* HACK: BEP 44 specifies SHA-1 but libsodium doesn't have it and
	 * I really don't want to pull in OpenSSL just for this. Using first
	 * 20 bytes of SHA-256 instead — means we can't interop with
	 * mainline DHT clients but that's fine for now. If someone
	 * actually needs that they can swap in a real SHA-1 here. */
	uint8_t hash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(hash, pk, LB_ED25519_PK_LEN);
	memcpy(target, hash, LB_DHT_NODE_ID_LEN);
}

/* ── BEP 44 sign value ───────────────────────────────────────────── */

static void
bep44_sign(const uint8_t sk[LB_ED25519_SK_LEN], int64_t seq,
           const uint8_t *val, size_t val_len,
           uint8_t sig[LB_ED25519_SIG_LEN])
{
	/* Sign over: 3:seqi<seq>e1:v<bencoded_value> */
	benc_buf_t b;
	bb_init(&b);
	bb_printf(&b, "3:seq");
	benc_int(&b, seq);
	bb_printf(&b, "1:v");
	benc_str(&b, val, val_len);

	crypto_sign_detached(sig, NULL, b.data, b.len, sk);
	free(b.data);
}

/* ── Publish ──────────────────────────────────────────────────────── */

int
lb_dht_publish(void)
{
	lb_keypair_t kp;
	lb_keypair_load(&kp);

	lb_fingerprint_t fp;
	lb_fingerprint(kp.pk, &fp);

	printf("Publishing identity to DHT...\n");
	printf("Fingerprint: %.16s...\n", fp.hex);

	/* Generate random node ID */
	randombytes_buf(our_node_id, LB_DHT_NODE_ID_LEN);

	/* Build the value to store (must be < 1000 bytes) */
	char *pk_b64 = lb_base64_encode(kp.pk, LB_ED25519_PK_LEN);
	json_t *val_obj = json_object();
	json_object_set_new(val_obj, "fp", json_string(fp.hex));
	json_object_set_new(val_obj, "pk", json_string(pk_b64));
	json_object_set_new(val_obj, "v", json_integer(1));
	char *val_str = json_dumps(val_obj, JSON_COMPACT | JSON_SORT_KEYS);
	json_decref(val_obj);
	free(pk_b64);

	/* Sign the value for BEP 44 */
	int64_t seq = (int64_t)time(NULL);
	uint8_t sig[LB_ED25519_SIG_LEN];
	bep44_sign(kp.sk, seq, (uint8_t *)val_str, strlen(val_str), sig);

	/* Compute target */
	uint8_t target[LB_DHT_NODE_ID_LEN];
	bep44_target(kp.pk, target);

	/* Create UDP socket */
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		lb_die("failed to create UDP socket");

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = 0,
	};
	bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

	num_nodes = 0;
	printf("Bootstrapping...\n");
	if (bootstrap(sock, target) != 0) {
		printf("Failed to bootstrap DHT (no nodes responded)\n");
		close(sock);
		free(val_str);
		sodium_memzero(&kp, sizeof(kp));
		return 1;
	}
	printf("Found %d DHT nodes\n", num_nodes);

	/* Iterative find to get close to target */
	printf("Finding closest nodes...\n");
	iterative_find(sock, target, 3);

	/* Send get requests to closest nodes to obtain tokens */
	int tokens_got = 0;
	for (int i = 0; i < num_nodes && i < 8; i++) {
		benc_buf_t b;
		bb_init(&b);
		build_get(&b, target);
		dht_send(sock, b.data, b.len, nodes[i].ip, nodes[i].port);
		free(b.data);
	}

	/* Collect tokens from get responses */
	for (int i = 0; i < 15; i++) {
		uint8_t buf[4096];
		int n = dht_recv(sock, buf, sizeof(buf), 500);
		if (n <= 0) continue;

		benc_dec_t d = { .data = buf, .pos = 0, .len = n };
		json_t *resp;
		if (bd_parse(&d, &resp) != 0) continue;

		json_t *r = json_object_get(resp, "r");
		if (r) {
			const char *token_b64 = json_string_value(json_object_get(r, "token"));
			const char *node_id_b64 = json_string_value(json_object_get(r, "id"));

			if (token_b64 && node_id_b64) {
				uint8_t *token_bin;
				size_t token_len;
				uint8_t *nid_bin;
				size_t nid_len;

				if (lb_base64_decode(token_b64, &token_bin, &token_len) == 0 &&
				    lb_base64_decode(node_id_b64, &nid_bin, &nid_len) == 0) {
					/* Find matching node and store token */
					for (int j = 0; j < num_nodes; j++) {
						if (nid_len >= LB_DHT_NODE_ID_LEN &&
						    memcmp(nodes[j].id, nid_bin, LB_DHT_NODE_ID_LEN) == 0) {
							memcpy(nodes[j].token, token_bin,
							       token_len < 64 ? token_len : 64);
							nodes[j].token_len = token_len < 64 ? token_len : 64;
							tokens_got++;
							break;
						}
					}
					free(nid_bin);
				}
				free(token_bin);
			}
		}
		json_decref(resp);
	}

	printf("Got tokens from %d nodes\n", tokens_got);

	/* Put to nodes that gave us tokens */
	int puts_sent = 0;
	for (int i = 0; i < num_nodes && puts_sent < 8; i++) {
		if (nodes[i].token_len == 0)
			continue;

		benc_buf_t b;
		bb_init(&b);
		build_put(&b, kp.pk, sig, seq,
		          (uint8_t *)val_str, strlen(val_str),
		          nodes[i].token, nodes[i].token_len);
		dht_send(sock, b.data, b.len, nodes[i].ip, nodes[i].port);
		free(b.data);
		puts_sent++;
	}

	/* Wait for put acknowledgments */
	int acks = 0;
	for (int i = 0; i < 10; i++) {
		uint8_t buf[4096];
		int n = dht_recv(sock, buf, sizeof(buf), 500);
		if (n <= 0) continue;
		/* Any response to our put is an ack */
		acks++;
	}

	printf("Published to %d nodes (%d acknowledged)\n", puts_sent, acks);

	close(sock);
	free(val_str);
	sodium_memzero(&kp, sizeof(kp));
	return 0;
}

/* ── Lookup via DHT ───────────────────────────────────────────────── */

int
lb_dht_lookup(const char *target_str)
{
	printf("Searching DHT for %s...\n", target_str);

	/* Decode the target — could be a fingerprint hex or base64 public key */
	uint8_t target_pk[LB_ED25519_PK_LEN];
	bool have_pk = false;

	/* Try as base64 public key */
	uint8_t *dec;
	size_t dec_len;
	if (lb_base64_decode(target_str, &dec, &dec_len) == 0 &&
	    dec_len == LB_ED25519_PK_LEN) {
		memcpy(target_pk, dec, LB_ED25519_PK_LEN);
		have_pk = true;
		free(dec);
	}

	/* Try loading from keyring by fingerprint prefix */
	if (!have_pk) {
		if (lb_keyring_lookup_hex(target_str, target_pk) == 0)
			have_pk = true;
	}

	/* Try own key */
	if (!have_pk) {
		uint8_t own_pk[LB_ED25519_PK_LEN];
		if (lb_pubkey_load(own_pk) == 0) {
			lb_fingerprint_t own_fp;
			lb_fingerprint(own_pk, &own_fp);
			if (strncmp(own_fp.hex, target_str, strlen(target_str)) == 0) {
				memcpy(target_pk, own_pk, LB_ED25519_PK_LEN);
				have_pk = true;
			}
		}
	}

	if (!have_pk)
		lb_die("cannot resolve target to a public key for DHT lookup: %s\n"
		       "DHT lookup requires the public key (import it first, or use base64)", target_str);

	uint8_t target[LB_DHT_NODE_ID_LEN];
	bep44_target(target_pk, target);

	randombytes_buf(our_node_id, LB_DHT_NODE_ID_LEN);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		lb_die("failed to create UDP socket");

	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = 0,
	};
	bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

	num_nodes = 0;
	printf("Bootstrapping...\n");
	if (bootstrap(sock, target) != 0) {
		printf("Failed to bootstrap DHT\n");
		close(sock);
		return 1;
	}
	printf("Found %d DHT nodes\n", num_nodes);

	iterative_find(sock, target, 3);

	/* Send get requests to closest nodes */
	printf("Querying closest nodes...\n");
	for (int i = 0; i < num_nodes && i < 8; i++) {
		benc_buf_t b;
		bb_init(&b);
		build_get(&b, target);
		dht_send(sock, b.data, b.len, nodes[i].ip, nodes[i].port);
		free(b.data);
	}

	/* Check responses for value */
	bool found = false;
	for (int i = 0; i < 20; i++) {
		uint8_t buf[4096];
		int n = dht_recv(sock, buf, sizeof(buf), 500);
		if (n <= 0) continue;

		benc_dec_t d = { .data = buf, .pos = 0, .len = n };
		json_t *resp;
		if (bd_parse(&d, &resp) != 0) continue;

		json_t *r = json_object_get(resp, "r");
		if (r) {
			const char *v = json_string_value(json_object_get(r, "v"));
			if (v) {
				printf("\nFound DHT record!\n");

				/* Try to parse as JSON */
				json_error_t err;
				json_t *val = json_loads(v, 0, &err);
				if (val) {
					const char *fp = json_string_value(json_object_get(val, "fp"));
					const char *pk = json_string_value(json_object_get(val, "pk"));
					if (fp) printf("  Fingerprint: %s\n", fp);
					if (pk) printf("  Public key:  %s\n", pk);
					json_decref(val);
				} else {
					printf("  Value: %s\n", v);
				}
				found = true;
				json_decref(resp);
				break;
			}

			/* Might have more nodes to query */
			const char *nodes_b64 = json_string_value(json_object_get(r, "nodes"));
			if (nodes_b64) {
				uint8_t *nodes_bin;
				size_t nodes_len;
				if (lb_base64_decode(nodes_b64, &nodes_bin, &nodes_len) == 0) {
					parse_compact_nodes(nodes_bin, nodes_len);
					free(nodes_bin);
				}
			}
		}
		json_decref(resp);
	}

	if (!found)
		printf("No DHT record found for this key.\n");

	close(sock);
	return found ? 0 : 1;
}
