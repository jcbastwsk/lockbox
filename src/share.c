/* https://www.youtube.com/watch?v=KV-m2MjnMFU */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Share encrypt ────────────────────────────────────────────────── */

int
lb_share_encrypt(const char *file, const char *recipient)
{
	/* Generate output filename: <file>.lockbox */
	size_t outname_len = strlen(file) + strlen(".lockbox") + 1;
	char *outname = malloc(outname_len);
	snprintf(outname, outname_len, "%s.lockbox", file);

	int rc = lb_encrypt(recipient, file, outname);

	if (rc == 0)
		printf("Encrypted: %s -> %s\n", file, outname);

	free(outname);
	return rc;
}

/* ── Share decrypt ────────────────────────────────────────────────── */

int
lb_share_decrypt(const char *file, const char *outfile)
{
	const char *out = outfile;
	char *generated = NULL;

	if (!out) {
		/* Strip .lockbox extension if present */
		size_t flen = strlen(file);
		if (flen > 8 && strcmp(file + flen - 8, ".lockbox") == 0) {
			generated = strndup(file, flen - 8);
			out = generated;
		} else {
			size_t oname_len = flen + strlen(".dec") + 1;
			generated = malloc(oname_len);
			snprintf(generated, oname_len, "%s.dec", file);
			out = generated;
		}
	}

	int rc = lb_decrypt(file, out);

	if (rc == 0)
		printf("Decrypted: %s -> %s\n", file, out);

	free(generated);
	return rc;
}
