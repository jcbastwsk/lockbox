/* https://www.youtube.com/watch?v=K1VLaXoRRdk */
#include "lockbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <dirent.h>
#include <time.h>

/* ── Color pairs ──────────────────────────────────────────────────── */

#define C_NORMAL    0
#define C_TITLE     1
#define C_KEY       2
#define C_GOOD      3
#define C_WARN      4
#define C_ACCENT    5
#define C_DIM       6
#define C_SELECTED  7

/* ── TUI state ────────────────────────────────────────────────────── */

enum tui_view {
	VIEW_DASHBOARD,
	VIEW_KEYRING,
	VIEW_SIGCHAIN,
	VIEW_KEY_DETAIL,
};

static struct {
	enum tui_view view;
	int           cursor;
	int           scroll;
	int           last_rows;   /* for resize detection (unused rn) */
	bool          has_keys;
	lb_fingerprint_t our_fp;
	uint8_t       our_pk[LB_ED25519_PK_LEN];
	char          status[128];
} tui;

/* ── ASCII art logo ───────────────────────────────────────────────── */

static const char *logo[] = {
	"  _            _    _",
	" | | ___   ___| | _| |__   _____  __",
	" | |/ _ \\ / __| |/ / '_ \\ / _ \\ \\/ /",
	" | | (_) | (__|   <| |_) | (_) >  < ",
	" |_|\\___/ \\___|_|\\_\\_.__/ \\___/_/\\_\\",
	NULL
};

static const char *lock_art[] = {
	"    .-------.",
	"   / .-----. \\",
	"  / /       \\ \\",
	"  | |       | |",
	"  \\ \\       / /",
	"   \\ `-----' /",
	" .--`-------'--.  ",
	" |  LOCKED  \\o/ |",
	" |   .-\"\"\"-. | |",
	" |  / .---. \\| |",
	" |  | |   | || |",
	" |  \\ '---' /| |",
	" |   '-----' | |",
	" '-----------'--'",
	NULL
};

/* ── Drawing helpers ──────────────────────────────────────────────── */

static void
draw_box(int y, int x, int h, int w, const char *title)
{
	/* Top */
	mvaddch(y, x, ACS_ULCORNER);
	for (int i = 1; i < w - 1; i++)
		mvaddch(y, x + i, ACS_HLINE);
	mvaddch(y, x + w - 1, ACS_URCORNER);

	/* Sides */
	for (int i = 1; i < h - 1; i++) {
		mvaddch(y + i, x, ACS_VLINE);
		mvaddch(y + i, x + w - 1, ACS_VLINE);
	}

	/* Bottom */
	mvaddch(y + h - 1, x, ACS_LLCORNER);
	for (int i = 1; i < w - 1; i++)
		mvaddch(y + h - 1, x + i, ACS_HLINE);
	mvaddch(y + h - 1, x + w - 1, ACS_LRCORNER);

	/* Title */
	if (title) {
		attron(COLOR_PAIR(C_TITLE) | A_BOLD);
		mvprintw(y, x + 2, " %s ", title);
		attroff(COLOR_PAIR(C_TITLE) | A_BOLD);
	}
}

static void
draw_hline(int y, int x, int w)
{
	for (int i = 0; i < w; i++)
		mvaddch(y, x + i, ACS_HLINE);
}

/* ── Dashboard view ───────────────────────────────────────────────── */

static void
draw_dashboard(void)
{
	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	/* Logo */
	attron(COLOR_PAIR(C_ACCENT) | A_BOLD);
	for (int i = 0; logo[i]; i++)
		mvprintw(1 + i, 2, "%s", logo[i]);
	attroff(COLOR_PAIR(C_ACCENT) | A_BOLD);

	attron(COLOR_PAIR(C_DIM));
	mvprintw(6, 2, "  v%s - cryptographic identity tool", LB_VERSION);
	attroff(COLOR_PAIR(C_DIM));

	/* Lock art on the right */
	if (cols > 60) {
		attron(COLOR_PAIR(C_KEY));
		for (int i = 0; lock_art[i]; i++)
			mvprintw(1 + i, cols - 22, "%s", lock_art[i]);
		attroff(COLOR_PAIR(C_KEY));
	}

	/* Identity box */
	int boxy = 8;
	int boxw = cols - 4;
	draw_box(boxy, 2, 7, boxw, "Identity");

	if (tui.has_keys) {
		char *b64 = lb_base64_encode(tui.our_pk, LB_ED25519_PK_LEN);

		attron(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 1, 4, "Fingerprint:");
		attroff(COLOR_PAIR(C_KEY));
		attron(A_BOLD);
		mvprintw(boxy + 1, 17, "%.32s", tui.our_fp.hex);
		attroff(A_BOLD);
		attron(COLOR_PAIR(C_DIM));
		mvprintw(boxy + 2, 17, "%.32s", tui.our_fp.hex + 32);
		attroff(COLOR_PAIR(C_DIM));

		attron(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 3, 4, "Public key:");
		attroff(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 3, 17, "%s", b64);

		/* Count sigchain links */
		char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
		size_t sc_len;
		uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
		int nlinks = 0;
		if (sc_data) {
			json_error_t err;
			json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
			if (chain) {
				nlinks = json_array_size(chain);
				json_decref(chain);
			}
			free(sc_data);
		}
		free(sc_path);

		/* Count keyring */
		char *kr_dir = lb_data_path(LB_KEYRING_DIR);
		int nkeys = 0;
		DIR *d = opendir(kr_dir);
		if (d) {
			struct dirent *ent;
			while ((ent = readdir(d)) != NULL) {
				if (ent->d_name[0] != '.')
					nkeys++;
			}
			closedir(d);
		}
		free(kr_dir);

		attron(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 5, 4, "Sigchain:");
		attroff(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 5, 17, "%d links", nlinks);

		attron(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 5, 30, "Keyring:");
		attroff(COLOR_PAIR(C_KEY));
		mvprintw(boxy + 5, 40, "%d keys", nkeys);

		free(b64);
	} else {
		attron(COLOR_PAIR(C_WARN));
		mvprintw(boxy + 2, 4, "No keypair found. Run 'lockbox init' to get started.");
		attroff(COLOR_PAIR(C_WARN));
	}

	/* Proven identities */
	int idbox_y = boxy + 8;
	if (tui.has_keys) {
		draw_box(idbox_y, 2, 10, boxw, "Proven Identities");

		char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
		size_t sc_len;
		uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
		free(sc_path);

		int line = 0;
		if (sc_data) {
			json_error_t err;
			json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
			free(sc_data);

			if (chain) {
				size_t i;
				json_t *link;
				json_array_foreach(chain, i, link) {
					const char *type = json_string_value(json_object_get(link, "type"));
					if (!type) continue;

					json_t *payload = json_object_get(link, "payload");
					const char *domain = NULL;
					const char *tag = NULL;

					if (strcmp(type, LB_LINK_IDENTITY_DNS) == 0) {
						domain = json_string_value(json_object_get(payload, "domain"));
						tag = "DNS";
					} else if (strcmp(type, LB_LINK_IDENTITY_HTTPS) == 0) {
						domain = json_string_value(json_object_get(payload, "domain"));
						tag = "HTTPS";
					} else if (strcmp(type, LB_LINK_IDENTITY_GITHUB) == 0) {
						domain = json_string_value(json_object_get(payload, "github"));
						tag = "GitHub";
					} else if (strcmp(type, LB_LINK_IDENTITY_REDDIT) == 0) {
						domain = json_string_value(json_object_get(payload, "reddit"));
						tag = "Reddit";
					} else if (strcmp(type, LB_LINK_IDENTITY_TWITTER) == 0) {
						domain = json_string_value(json_object_get(payload, "twitter"));
						tag = "Twitter";
					} else if (strcmp(type, LB_LINK_IDENTITY_BTC) == 0) {
						domain = json_string_value(json_object_get(payload, "btc"));
						tag = "BTC";
					} else if (strcmp(type, LB_LINK_IDENTITY_ETH) == 0) {
						domain = json_string_value(json_object_get(payload, "eth"));
						tag = "ETH";
					} else if (strcmp(type, LB_LINK_IDENTITY_HN) == 0) {
						domain = json_string_value(json_object_get(payload, "hn"));
						tag = "HN";
					}

					if (domain && line < 8) {
						attron(COLOR_PAIR(C_GOOD));
						mvprintw(idbox_y + 1 + line, 4, "[%s]", tag);
						attroff(COLOR_PAIR(C_GOOD));
						mvprintw(idbox_y + 1 + line, 14, "%s", domain);
						line++;
					}
				}
				json_decref(chain);
			}
		}
		if (line == 0) {
			attron(COLOR_PAIR(C_DIM));
			mvprintw(idbox_y + 2, 4, "(none - use 'lockbox prove' to add identities)");
			attroff(COLOR_PAIR(C_DIM));
		}
	}

	/* Navigation help */
	attron(COLOR_PAIR(C_DIM));
	mvprintw(rows - 2, 2,
		"[k] Keyring  [s] Sigchain  [i] Init  [q] Quit");
	attroff(COLOR_PAIR(C_DIM));

	/* Status line */
	if (tui.status[0]) {
		attron(COLOR_PAIR(C_ACCENT));
		mvprintw(rows - 1, 2, "%s", tui.status);
		attroff(COLOR_PAIR(C_ACCENT));
	}
}

/* ── Keyring view ─────────────────────────────────────────────────── */

typedef struct {
	char fp[LB_FINGERPRINT_HEX];
	char label[64];
	int  ncerts;
	int  trust_score;
} kr_display_t;

static kr_display_t kr_entries[LB_MAX_KEYRING];
static int kr_count = 0;

static void
load_keyring(void)
{
	char *kr_dir = lb_data_path(LB_KEYRING_DIR);
	DIR *d = opendir(kr_dir);
	kr_count = 0;

	if (!d) {
		free(kr_dir);
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && kr_count < LB_MAX_KEYRING) {
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

		const char *fp = json_string_value(json_object_get(obj, "fingerprint"));
		const char *lbl = json_string_value(json_object_get(obj, "label"));
		json_t *certs = json_object_get(obj, "certifications");

		if (fp) {
			snprintf(kr_entries[kr_count].fp, LB_FINGERPRINT_HEX, "%s", fp);
			if (lbl)
				snprintf(kr_entries[kr_count].label, 64, "%s", lbl);
			else
				kr_entries[kr_count].label[0] = '\0';
			kr_entries[kr_count].ncerts = json_is_array(certs) ?
				(int)json_array_size(certs) : 0;
			kr_entries[kr_count].trust_score = lb_trust_score(fp);
			kr_count++;
		}
		json_decref(obj);
	}

	closedir(d);
	free(kr_dir);
}

static void
draw_keyring(void)
{
	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	int boxw = cols - 4;
	draw_box(0, 2, rows - 2, boxw, "Keyring");

	/* Header */
	attron(COLOR_PAIR(C_TITLE) | A_BOLD);
	mvprintw(1, 4, "%-20s %-24s %-6s %s", "Fingerprint", "Label", "Score", "Certs");
	attroff(COLOR_PAIR(C_TITLE) | A_BOLD);
	draw_hline(2, 4, boxw - 4);

	int visible = rows - 6;
	for (int i = 0; i < kr_count && i < visible; i++) {
		int idx = i + tui.scroll;
		if (idx >= kr_count) break;

		if (idx == tui.cursor) {
			attron(COLOR_PAIR(C_SELECTED) | A_REVERSE);
		}

		mvprintw(3 + i, 4, "%.16s...  %-24s  %-3d",
		         kr_entries[idx].fp,
		         kr_entries[idx].label[0] ? kr_entries[idx].label : "(no label)",
		         kr_entries[idx].trust_score);

		if (kr_entries[idx].ncerts > 0) {
			attron(COLOR_PAIR(C_GOOD));
			printw("   [%d]", kr_entries[idx].ncerts);
			attroff(COLOR_PAIR(C_GOOD));
		}

		if (idx == tui.cursor) {
			attroff(COLOR_PAIR(C_SELECTED) | A_REVERSE);
		}
	}

	if (kr_count == 0) {
		attron(COLOR_PAIR(C_DIM));
		mvprintw(4, 4, "(empty - import keys with 'lockbox key import')");
		attroff(COLOR_PAIR(C_DIM));
	}

	/* Footer */
	attron(COLOR_PAIR(C_DIM));
	mvprintw(rows - 2, 2,
		"[j/k] Navigate  [c] Certify  [t] Trust  [d] Dashboard  [q] Quit");
	attroff(COLOR_PAIR(C_DIM));
}

/* ── Sigchain view ────────────────────────────────────────────────── */

static void
draw_sigchain(void)
{
	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	int boxw = cols - 4;
	draw_box(0, 2, rows - 2, boxw, "Sigchain");

	char *sc_path = lb_data_path(LB_SIGCHAIN_FILE);
	size_t sc_len;
	uint8_t *sc_data = lb_file_read(sc_path, &sc_len);
	free(sc_path);

	if (!sc_data) {
		attron(COLOR_PAIR(C_DIM));
		mvprintw(2, 4, "(no sigchain - run 'lockbox init')");
		attroff(COLOR_PAIR(C_DIM));
		return;
	}

	json_error_t err;
	json_t *chain = json_loadb((char *)sc_data, sc_len, 0, &err);
	free(sc_data);

	if (!chain) {
		mvprintw(2, 4, "(corrupt sigchain)");
		return;
	}

	/* Header */
	attron(COLOR_PAIR(C_TITLE) | A_BOLD);
	mvprintw(1, 4, "%-5s %-24s %-20s", "#", "Type", "Time");
	attroff(COLOR_PAIR(C_TITLE) | A_BOLD);
	draw_hline(2, 4, boxw - 4);

	int visible = rows - 6;
	size_t count = json_array_size(chain);

	for (int i = 0; i < visible && (size_t)(i + tui.scroll) < count; i++) {
		size_t idx = (size_t)(i + tui.scroll);
		json_t *link = json_array_get(chain, idx);

		json_int_t seqno = json_integer_value(json_object_get(link, "seqno"));
		const char *type = json_string_value(json_object_get(link, "type"));
		json_int_t ts = json_integer_value(json_object_get(link, "timestamp"));

		char timebuf[32];
		time_t t = (time_t)ts;
		struct tm *tm = localtime(&t);
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm);

		/* Color by type */
		int color = C_NORMAL;
		const char *icon = " ";
		if (type) {
			if (strstr(type, "key.create")) { color = C_GOOD; icon = "+"; }
			else if (strstr(type, "key.attest")) { color = C_ACCENT; icon = "!"; }
			else if (strstr(type, "certify")) { color = C_ACCENT; icon = "*"; }
			else if (strstr(type, "prove")) { color = C_KEY; icon = "~"; }
			else if (strstr(type, "revoke")) { color = C_WARN; icon = "x"; }
		}

		if ((int)idx == tui.cursor)
			attron(A_REVERSE);

		attron(COLOR_PAIR(color));
		mvprintw(3 + i, 4, "%s #%-3lld %-24s %s",
		         icon, (long long)seqno, type ? type : "?", timebuf);
		attroff(COLOR_PAIR(color));

		if ((int)idx == tui.cursor)
			attroff(A_REVERSE);
	}

	json_decref(chain);

	attron(COLOR_PAIR(C_DIM));
	mvprintw(rows - 2, 2,
		"[j/k] Navigate  [d] Dashboard  [q] Quit");
	attroff(COLOR_PAIR(C_DIM));
}

/* TODO: key detail view — show full fingerprint, certs, trust path.
   maybe someday. the keyring list view is good enough for now */

/* ── Main TUI loop ────────────────────────────────────────────────── */

int
lb_tui(void)
{
	/* Init ncurses */
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	curs_set(0);

	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(C_TITLE,    COLOR_CYAN,    -1);
		init_pair(C_KEY,      COLOR_BLUE,    -1);
		init_pair(C_GOOD,     COLOR_GREEN,   -1);
		init_pair(C_WARN,     COLOR_RED,     -1);
		init_pair(C_ACCENT,   COLOR_YELLOW,  -1);
		init_pair(C_DIM,      COLOR_WHITE,   -1);
		init_pair(C_SELECTED, COLOR_BLACK,   COLOR_CYAN);
	}

	/* Load identity */
	tui.view = VIEW_DASHBOARD;
	tui.cursor = 0;
	tui.scroll = 0;
	tui.status[0] = '\0';

	if (lb_pubkey_load(tui.our_pk) == 0) {
		lb_fingerprint(tui.our_pk, &tui.our_fp);
		tui.has_keys = true;
	} else {
		tui.has_keys = false;
	}

	bool running = true;
	while (running) {
		erase();

		switch (tui.view) {
		case VIEW_DASHBOARD:
			draw_dashboard();
			break;
		case VIEW_KEYRING:
			draw_keyring();
			break;
		case VIEW_SIGCHAIN:
			draw_sigchain();
			break;
		default:
			draw_dashboard();
			break;
		}

		refresh();

		int ch = getch();
		switch (ch) {
		case 'q':
		case 'Q':
			running = false;
			break;

		case 'd':
		case 'D':
			tui.view = VIEW_DASHBOARD;
			tui.cursor = 0;
			tui.scroll = 0;
			break;

		case 'k':
		case 'K':
			if (tui.view == VIEW_DASHBOARD) {
				tui.view = VIEW_KEYRING;
				tui.cursor = 0;
				tui.scroll = 0;
				load_keyring();
			} else if (tui.view == VIEW_KEYRING || tui.view == VIEW_SIGCHAIN) {
				/* Navigate up */
				if (tui.cursor > 0)
					tui.cursor--;
			}
			break;

		case 'j':
		case 'J':
			if (tui.view == VIEW_KEYRING) {
				if (tui.cursor < kr_count - 1)
					tui.cursor++;
			} else if (tui.view == VIEW_SIGCHAIN) {
				tui.cursor++;
			}
			break;

		case KEY_UP:
			if (tui.cursor > 0) tui.cursor--;
			break;

		case KEY_DOWN:
			if (tui.view == VIEW_KEYRING && tui.cursor < kr_count - 1)
				tui.cursor++;
			else if (tui.view == VIEW_SIGCHAIN)
				tui.cursor++;
			break;

		case 's':
		case 'S':
			tui.view = VIEW_SIGCHAIN;
			tui.cursor = 0;
			tui.scroll = 0;
			break;

		case 'c':
			/* Certify selected key in keyring view */
			if (tui.view == VIEW_KEYRING && kr_count > 0 &&
			    tui.cursor < kr_count) {
				/* Run certify in the background */
				endwin();
				lb_certify(kr_entries[tui.cursor].fp);
				printf("\nPress Enter to return to TUI...");
				getchar();
				refresh();
				load_keyring();
				snprintf(tui.status, sizeof(tui.status),
				         "Certified: %.16s...", kr_entries[tui.cursor].fp);
			}
			break;

		case 't':
			/* Show trust path for selected key */
			if (tui.view == VIEW_KEYRING && kr_count > 0 &&
			    tui.cursor < kr_count) {
				endwin();
				lb_trust_show(kr_entries[tui.cursor].fp);
				printf("\nPress Enter to return to TUI...");
				getchar();
				refresh();
			}
			break;

		case 'i':
			if (!tui.has_keys) {
				endwin();
				lb_init();
				if (lb_pubkey_load(tui.our_pk) == 0) {
					lb_fingerprint(tui.our_pk, &tui.our_fp);
					tui.has_keys = true;
				}
				printf("\nPress Enter to return to TUI...");
				getchar();
				refresh();
			}
			break;
		}

		/* Scroll adjustment */
		{
			int rows, cols;
			getmaxyx(stdscr, rows, cols);
			(void)cols;
			int visible = rows - 6;
			if (tui.cursor < tui.scroll)
				tui.scroll = tui.cursor;
			if (tui.cursor >= tui.scroll + visible)
				tui.scroll = tui.cursor - visible + 1;
		}
	}

	endwin();
	return 0;
}
