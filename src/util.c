/* https://www.youtube.com/watch?v=kON_KRmFRKk */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>

/* ── Error reporting ──────────────────────────────────────────────── */

/* TODO: make these thread-safe if we ever do multithreading (probably won't) */

void
lb_die(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "lockbox: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

void
lb_warn(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "lockbox: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/* ── Base64 (using libsodium) ─────────────────────────────────────── */

char *
lb_base64_encode(const uint8_t *data, size_t len)
{
	size_t b64_maxlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
	char *out = malloc(b64_maxlen);
	if (!out)
		return NULL;
	sodium_bin2base64(out, b64_maxlen, data, len, sodium_base64_VARIANT_ORIGINAL);
	return out;
}

int
lb_base64_decode(const char *b64, uint8_t **out, size_t *out_len)
{
	size_t b64_len = strlen(b64);
	size_t max_bin = b64_len;   /* always enough */
	*out = malloc(max_bin);
	if (!*out)
		return -1;
	if (sodium_base642bin(*out, max_bin, b64, b64_len,
	                      " \t\r\n", out_len, NULL,
	                      sodium_base64_VARIANT_ORIGINAL) != 0) {
		free(*out);
		*out = NULL;
		return -1;
	}
	return 0;
}

/* ── Hex encoding ─────────────────────────────────────────────────── */

void
lb_hex_encode(const uint8_t *data, size_t len, char *out)
{
	sodium_bin2hex(out, len * 2 + 1, data, len);
}

int
lb_hex_decode(const char *hex, uint8_t *out, size_t max_len)
{
	size_t hex_len = strlen(hex);
	size_t bin_len;
	if (sodium_hex2bin(out, max_len, hex, hex_len,
	                   NULL, &bin_len, NULL) != 0)
		return -1;
	return (int)bin_len;
}

/* ── File I/O ─────────────────────────────────────────────────────── */

uint8_t *
lb_file_read(const char *path, size_t *len)
{
	FILE *f;
	bool use_stdin = (strcmp(path, "-") == 0);

	if (use_stdin) {
		f = stdin;
	} else {
		f = fopen(path, "rb");
		if (!f)
			return NULL;
	}

	/* 4k initial seems fine, reallocs if needed */
	size_t cap = 4096, sz = 0;
	uint8_t *buf = malloc(cap);
	if (!buf) {
		if (!use_stdin) fclose(f);
		return NULL;
	}

	size_t n;
	while ((n = fread(buf + sz, 1, cap - sz, f)) > 0) {
		sz += n;
		if (sz == cap) {
			cap *= 2;
			uint8_t *tmp = realloc(buf, cap);
			if (!tmp) {
				free(buf);
				if (!use_stdin) fclose(f);
				return NULL;
			}
			buf = tmp;
		}
	}

	if (!use_stdin)
		fclose(f);

	*len = sz;
	return buf;
}

int
lb_file_write(const char *path, const uint8_t *data, size_t len, int mode)
{
	bool use_stdout = (strcmp(path, "-") == 0);

	if (use_stdout) {
		if (fwrite(data, 1, len, stdout) != len)
			return -1;
		fflush(stdout);
		return 0;
	}

	FILE *f = fopen(path, "wb");
	if (!f)
		return -1;

	if (mode > 0) {
		if (fchmod(fileno(f), mode) != 0) {
			fclose(f);
			return -1;
		}
	}

	if (fwrite(data, 1, len, f) != len) {
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}

/* ── Hexdump (for debugging, too useful to delete) ────────────────── */

void
lb_hexdump(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (i > 0 && i % 16 == 0)
			fprintf(stderr, "\n");
		fprintf(stderr, "%02x ", data[i]);
	}
	fprintf(stderr, "\n");
}

/* check if a file exists, returns 1 if it does */
int
lb_file_exists(const char *path)
{
	struct stat st;
	return (stat(path, &st) == 0);
}

/* ── Data directory ───────────────────────────────────────────────── */

char *
lb_data_path(const char *name)
{
	const char *home = getenv("HOME");
	if (!home)
		lb_die("HOME not set");

	size_t len = strlen(home) + 1 + strlen(LB_DIR_NAME) + 1 + strlen(name) + 1;
	char *path = malloc(len);
	if (!path)
		return NULL;
	snprintf(path, len, "%s/%s/%s", home, LB_DIR_NAME, name);
	return path;
}
