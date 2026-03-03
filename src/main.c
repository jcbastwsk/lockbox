/* https://www.youtube.com/watch?v=KRFx4jCmKks */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
usage(void)
{
	fprintf(stderr,
		"lockbox %s - cryptographic identity tool\n"
		"\n"
		"Usage:\n"
		"  lockbox                                     Launch TUI\n"
		"  lockbox init                                Generate keypair, create ~/.lockbox/\n"
		"  lockbox id                                  Show fingerprint, public key, proofs\n"
		"  lockbox encrypt -r <fpr|domain> [-o out] [file]\n"
		"                                              Encrypt to recipient\n"
		"  lockbox decrypt [-o out] [file]             Decrypt\n"
		"  lockbox sign [file]                         Create detached signature\n"
		"  lockbox verify <sigfile> [file]             Verify detached signature\n"
		"  lockbox key export [--json]                 Export public key\n"
		"  lockbox key import <file|->                 Import public key into keyring\n"
		"  lockbox key list                            List keys in keyring\n"
		"  lockbox key fingerprint                     Show your fingerprint\n"
		"  lockbox key search <query>                  Search keyring by name/fingerprint\n"
		"  lockbox certify <fingerprint>               Certify a key (web of trust)\n"
		"  lockbox trust <fingerprint>                 Show trust path + score\n"
		"  lockbox trust rank                          Rank all keys by trust score\n"
		"  lockbox attest <fpr> <claim>                Attest identity/vouch for a key\n"
		"  lockbox attestations <fpr>                  Show attestations for a key\n"
		"  lockbox prove dns <domain>                  Generate DNS TXT proof\n"
		"  lockbox prove https <domain>                Generate .well-known proof\n"
		"  lockbox prove github <username>             Generate GitHub gist proof\n"
		"  lockbox prove reddit <username>             Generate Reddit proof\n"
		"  lockbox prove twitter <username>            Generate Twitter/X proof\n"
		"  lockbox prove btc <address>                 Generate BTC address proof\n"
		"  lockbox prove eth <address>                 Generate ETH address proof\n"
		"  lockbox prove hn <username>                 Generate HackerNews proof\n"
		"  lockbox lookup <domain|service:user>        Discover keys via DNS/HTTPS/services\n"
		"  lockbox sigchain [show|verify]              Show or verify sigchain\n"
		"  lockbox share <file> -r <fpr|domain>        Encrypt file for recipient\n"
		"  lockbox keystore add <service> [--label <name>]\n"
		"                                              Add key to encrypted keystore\n"
		"  lockbox keystore list                       List keystore entries\n"
		"  lockbox keystore show <id> [--secret]       Show keystore entry\n"
		"  lockbox keystore remove <id>                Remove keystore entry\n"
		"  lockbox keystore export <id>                Export public key from keystore\n"
		"  lockbox dht publish                         Publish identity to DHT\n"
		"  lockbox dht lookup <fingerprint>            Lookup key in DHT\n"
		"\n", LB_VERSION);
	exit(1);
}

static const char *
opt_arg(int argc, char **argv, int *i, const char *flag)
{
	if (strcmp(argv[*i], flag) == 0) {
		if (*i + 1 >= argc)
			lb_die("option %s requires an argument", flag);
		(*i)++;
		return argv[*i];
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	if (sodium_init() < 0)
		lb_die("failed to initialize libsodium");  /* shouldn't happen */

	/* No arguments: launch TUI */
	if (argc < 2)
		return lb_tui();

	const char *cmd = argv[1];

	if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0)
		usage();

	if (strcmp(cmd, "init") == 0)
		return lb_init();

	if (strcmp(cmd, "id") == 0)
		return lb_show_id();

	if (strcmp(cmd, "encrypt") == 0) {
		const char *recipient = NULL;
		const char *outfile = NULL;
		const char *infile = NULL;

		for (int i = 2; i < argc; i++) {
			const char *v;
			if ((v = opt_arg(argc, argv, &i, "-r")) != NULL)
				recipient = v;
			else if ((v = opt_arg(argc, argv, &i, "-o")) != NULL)
				outfile = v;
			else
				infile = argv[i];
		}
		if (!recipient)
			lb_die("encrypt requires -r <recipient>");
		return lb_encrypt(recipient, infile, outfile);
	}

	if (strcmp(cmd, "decrypt") == 0) {
		const char *outfile = NULL;
		const char *infile = NULL;

		for (int i = 2; i < argc; i++) {
			const char *v;
			if ((v = opt_arg(argc, argv, &i, "-o")) != NULL)
				outfile = v;
			else
				infile = argv[i];
		}
		return lb_decrypt(infile, outfile);
	}

	if (strcmp(cmd, "sign") == 0) {
		const char *infile = (argc > 2) ? argv[2] : NULL;
		return lb_sign(infile);
	}

	if (strcmp(cmd, "verify") == 0) {
		if (argc < 3)
			lb_die("verify requires a signature file argument");
		const char *sigfile = argv[2];
		const char *infile = (argc > 3) ? argv[3] : NULL;
		return lb_verify(sigfile, infile);
	}

	if (strcmp(cmd, "key") == 0) {
		if (argc < 3)
			lb_die("key requires a subcommand: export, import, list, fingerprint");
		const char *sub = argv[2];

		if (strcmp(sub, "export") == 0) {
			bool json_fmt = false;
			if (argc > 3 && strcmp(argv[3], "--json") == 0)
				json_fmt = true;
			return lb_key_export(json_fmt);
		}
		if (strcmp(sub, "import") == 0) {
			if (argc < 4)
				lb_die("key import requires a file argument");
			return lb_key_import(argv[3]);
		}
		if (strcmp(sub, "list") == 0)
			return lb_key_list();
		if (strcmp(sub, "fingerprint") == 0)
			return lb_key_show_fingerprint();
		if (strcmp(sub, "search") == 0) {
			if (argc < 4)
				lb_die("key search requires a query argument");
			return lb_key_search(argv[3]);
		}

		lb_die("unknown key subcommand: %s", sub);
	}

	/* lockbox certify <fingerprint> */
	if (strcmp(cmd, "certify") == 0) {
		if (argc < 3)
			lb_die("certify requires a fingerprint argument");
		return lb_certify(argv[2]);
	}

	/* lockbox trust <fingerprint|rank> */
	if (strcmp(cmd, "trust") == 0) {
		if (argc < 3)
			lb_die("trust requires a fingerprint or 'rank'");
		if (strcmp(argv[2], "rank") == 0)
			return lb_trust_rank();
		return lb_trust_show(argv[2]);
	}

	if (strcmp(cmd, "prove") == 0) {
		if (argc < 4)
			lb_die("prove requires: prove <type> <target>");
		if (strcmp(argv[2], "dns") == 0)
			return lb_prove_dns(argv[3]);
		if (strcmp(argv[2], "https") == 0)
			return lb_prove_https(argv[3]);
		if (strcmp(argv[2], "github") == 0)
			return lb_prove_github(argv[3]);
		if (strcmp(argv[2], "reddit") == 0)
			return lb_prove_reddit(argv[3]);
		if (strcmp(argv[2], "twitter") == 0)
			return lb_prove_twitter(argv[3]);
		if (strcmp(argv[2], "btc") == 0)
			return lb_prove_btc(argv[3]);
		if (strcmp(argv[2], "eth") == 0)
			return lb_prove_eth(argv[3]);
		if (strcmp(argv[2], "hn") == 0)
			return lb_prove_hn(argv[3]);
		lb_die("unknown prove type: %s", argv[2]);
	}

	if (strcmp(cmd, "lookup") == 0) {
		if (argc < 3)
			lb_die("lookup requires a target argument");
		return lb_lookup(argv[2]);
	}

	if (strcmp(cmd, "sigchain") == 0) {
		if (argc < 3 || strcmp(argv[2], "show") == 0)
			return lb_sigchain_show();
		if (strcmp(argv[2], "verify") == 0)
			return lb_sigchain_verify();
		lb_die("unknown sigchain subcommand: %s", argv[2]);
	}

	if (strcmp(cmd, "share") == 0) {
		const char *file = NULL;
		const char *recipient = NULL;

		for (int i = 2; i < argc; i++) {
			const char *v;
			if ((v = opt_arg(argc, argv, &i, "-r")) != NULL)
				recipient = v;
			else
				file = argv[i];
		}
		if (!file || !recipient)
			lb_die("share requires: share <file> -r <recipient>");
		return lb_share_encrypt(file, recipient);
	}

	/* lockbox attest <fingerprint> <claim> */
	if (strcmp(cmd, "attest") == 0) {
		if (argc < 4)
			lb_die("attest requires: attest <fingerprint> <claim>");
		return lb_attest(argv[2], argv[3]);
	}

	/* lockbox attestations <fingerprint> */
	if (strcmp(cmd, "attestations") == 0) {
		if (argc < 3)
			lb_die("attestations requires a fingerprint argument");
		return lb_attestations_show(argv[2]);
	}

	/* lockbox keystore <subcommand> */
	if (strcmp(cmd, "keystore") == 0) {
		if (argc < 3)
			lb_die("keystore requires a subcommand: add, list, show, remove, export");
		const char *sub = argv[2];

		if (strcmp(sub, "add") == 0) {
			if (argc < 4)
				lb_die("keystore add requires a service argument");
			const char *label = NULL;
			for (int i = 4; i < argc; i++) {
				const char *v;
				if ((v = opt_arg(argc, argv, &i, "--label")) != NULL)
					label = v;
			}
			return lb_keystore_add(argv[3], label);
		}
		if (strcmp(sub, "list") == 0)
			return lb_keystore_list();
		if (strcmp(sub, "show") == 0) {
			if (argc < 4)
				lb_die("keystore show requires an id argument");
			bool secret = false;
			if (argc > 4 && strcmp(argv[4], "--secret") == 0)
				secret = true;
			return lb_keystore_show(argv[3], secret);
		}
		if (strcmp(sub, "remove") == 0) {
			if (argc < 4)
				lb_die("keystore remove requires an id argument");
			return lb_keystore_remove(argv[3]);
		}
		if (strcmp(sub, "export") == 0) {
			if (argc < 4)
				lb_die("keystore export requires an id argument");
			return lb_keystore_export_pubkey(argv[3]);
		}

		lb_die("unknown keystore subcommand: %s", sub);
	}

	/* lockbox dht <publish|lookup> */
	if (strcmp(cmd, "dht") == 0) {
		if (argc < 3)
			lb_die("dht requires a subcommand: publish, lookup");
		if (strcmp(argv[2], "publish") == 0)
			return lb_dht_publish();
		if (strcmp(argv[2], "lookup") == 0) {
			if (argc < 4)
				lb_die("dht lookup requires a target argument");
			return lb_dht_lookup(argv[3]);
		}
		lb_die("unknown dht subcommand: %s", argv[2]);
	}

	lb_die("unknown command: %s (try --help)", cmd);
	return 1;  /* unreachable but clang complains without it */
}
