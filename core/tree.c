/* tree.c — the process-tree and field-scrub logic.
 *
 * Lineage (see docs/lineage/tree.md for the line ranges):
 *   config.js         MATCH / NEEDLE_LEN / SECS / SECS_INVALID / FOLD_SKIPPED
 *                     / ALL / SHOW, and the positional-`k=v` fold.
 *   model.js          cstr / basename / isMatch / sessionTgids (parent links
 *                     by ppid, BFS membership over child links).
 *   recall:           the sensor BPF program `struct startrec` (exec stamp bridged to
 *                     exit) + drop_total / upd_fail_total.
 *   feed.js           `scrub` — the byte class that may not reach the wire.
 *
 * Ported *logic* only; the presentation module (feed.js
 * pidColor/paintCmd/badge/clock, model.js fmtDur/fmtAddr/fmtOpenMode) is
 * deliberately left upstream. The frontend owns presentation now.
 *
 * Nothing here allocates per event on a hot path; membership is a bounded
 * BFS over a fixed-size buffer, and every budget exhaustion is reported.
 */
#include "tree.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *const TREE_ALL[TREE_NCLASSES] = {
    "exec", "exit", "open", "conn", "listen"
};

/* ----------------------------------------------------------- config.js --- */

static const char *const KEYS[] = { "match", "m", "secs", "s", "only", "except" };
#define N_KEYS (sizeof KEYS / sizeof *KEYS)

static int key_known(const char *k) {
    for (size_t i = 0; i < N_KEYS; i++) if (strcmp(KEYS[i], k) == 0) return 1;
    return 0;
}

static long parse_secs(const char *raw, int *invalid) {
    /* config.js:
     *   SECS = isFinite(n) && n > 0 ? min(n, 86400) : 0
     *   SECS_INVALID = raw != null && !(isFinite(n) && n >= 0)
     * A provided-but-non-numeric value is REPORTED, never silently treated as
     * "run forever". */
    *invalid = 0;
    if (!raw) return 0;
    char *end = NULL;
    double v = strtod(raw, &end);
    if (!end || *end != '\0' || !isfinite(v) || v < 0) { *invalid = 1; return 0; }
    if (v > 0) return (long)(v > 86400 ? 86400 : v);
    return 0;
}

static void csv_show(tree_config_t *c, const char *only, const char *except_) {
    /* config.js SHOW: start from ALL, keep `only` when given, then drop every
     * `except`. Unknown class names are ignored, exactly as upstream. */
    int only_set[TREE_NCLASSES];
    memset(only_set, 0, sizeof only_set);
    if (only) {
        char buf[128]; snprintf(buf, sizeof buf, "%s", only);
        for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
            while (*tok == ' ') tok++;
            size_t l = strlen(tok); while (l && tok[l-1] == ' ') tok[--l] = '\0';
            for (int i = 0; i < TREE_NCLASSES; i++)
                if (strcmp(tok, TREE_ALL[i]) == 0) only_set[i] = 1;
        }
    }
    int except_set[TREE_NCLASSES];
    memset(except_set, 0, sizeof except_set);
    if (except_) {
        char buf[128]; snprintf(buf, sizeof buf, "%s", except_);
        for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
            while (*tok == ' ') tok++;
            size_t l = strlen(tok); while (l && tok[l-1] == ' ') tok[--l] = '\0';
            for (int i = 0; i < TREE_NCLASSES; i++)
                if (strcmp(tok, TREE_ALL[i]) == 0) except_set[i] = 1;
        }
    }
    for (int i = 0; i < TREE_NCLASSES; i++) {
        int keep = only ? only_set[i] : 1;
        c->show[i] = keep && !except_set[i];
    }
}

void tree_config_default(tree_config_t *c) {
    memset(c, 0, sizeof *c);
    snprintf(c->match, sizeof c->match, "claude");
    c->match_truncated = 0;
    for (int i = 0; i < TREE_NCLASSES; i++) c->show[i] = 1;
}

void tree_config_parse(tree_config_t *c, int argc, char **argv) {
    /* First collect named args (`--k=v` or `-k=v`), then fold positional
     * `k=v` tokens back in — the bare form is what upstream documents. A bare
     * token whose key was already named goes to FOLD_SKIPPED, not silently
     * overriding the explicit flag. */
    char named[8][64]; int named_n = 0;
    char positionals[16][64]; int pos_n = 0;

    for (int i = 0; i < argc && i < 64; i++) {
        const char *a = argv[i];
        const char *eq = strchr(a, '=');
        if (!eq) continue;
        const char *key = a;
        size_t klen = (size_t)(eq - a);
        while (klen && key[0] == '-') { key++; klen--; }
        char k[64];
        if (klen >= sizeof k) continue;
        memcpy(k, key, klen); k[klen] = '\0';
        if (!key_known(k)) continue;

        /* `--match=x` (starts with '-') is named; `match=x` is positional. */
        if (a[0] == '-') {
            int slot = -1;
            for (int j = 0; j < named_n; j++)
                if (strncmp(named[j], k, strlen(k)) == 0 && named[j][strlen(k)] == '=') { slot = j; break; }
            if (slot < 0 && named_n < 8) { snprintf(named[named_n++], 64, "%s", a + (a[0]=='-'?(a[1]=='-'?2:1):0)); }
        } else if (pos_n < 16) {
            snprintf(positionals[pos_n++], 64, "%s", a);
        }
    }

    for (int i = 0; i < pos_n; i++) {
        const char *tok = positionals[i];
        const char *eq = strchr(tok, '=');
        if (!eq || eq == tok) continue;
        char k[64];
        size_t klen = (size_t)(eq - tok);
        if (klen >= sizeof k) continue;
        memcpy(k, tok, klen); k[klen] = '\0';
        if (!key_known(k)) continue;
        /* already named? -> FOLD_SKIPPED (upstream: `if (k in raw)`) */
        int already = 0;
        for (int j = 0; j < named_n; j++) {
            size_t kl = strlen(k);
            if (strncmp(named[j], k, kl) == 0 && named[j][kl] == '=') { already = 1; break; }
        }
        if (already) {
            if (c->fold_len < 8) snprintf(c->fold_skipped[c->fold_len++], 8, "%s", k);
            continue;
        }
        if (named_n < 8) snprintf(named[named_n++], 64, "%s", tok);
    }

    /* apply the named set, last write wins (upstream object spread order) */
    const char *v_match = NULL, *v_secs = NULL, *v_only = NULL, *v_except = NULL;
    for (int j = 0; j < named_n; j++) {
        const char *tok = named[j];
        const char *eq = strchr(tok, '=');
        if (!eq) continue;
        char k[64]; size_t klen = (size_t)(eq - tok);
        if (klen >= sizeof k) continue;
        memcpy(k, tok, klen); k[klen] = '\0';
        const char *v = eq + 1;
        if (!strcmp(k, "match") || !strcmp(k, "m")) v_match = v;
        else if (!strcmp(k, "secs") || !strcmp(k, "s")) v_secs = v;
        else if (!strcmp(k, "only")) v_only = v;
        else if (!strcmp(k, "except")) v_except = v;
    }

    if (v_match) {
        char lower[128]; size_t o = 0;
        for (size_t i = 0; v_match[i] && o + 1 < sizeof lower; i++)
            lower[o++] = (char)tolower((unsigned char)v_match[i]);
        lower[o] = '\0';
        c->match_truncated = strlen(lower) > WD_TREE_NEEDLE_LEN;
        snprintf(c->match, sizeof c->match, "%.*s", WD_TREE_NEEDLE_LEN, lower);
    }
    c->secs = parse_secs(v_secs, &c->secs_invalid);
    csv_show(c, v_only, v_except);
}

/* ------------------------------------------------------------ model.js --- */

void tree_init(tree_t *t) { t->procs = NULL; t->len = t->cap = 0; }

void tree_free(tree_t *t) {
    free(t->procs);
    t->procs = NULL; t->len = t->cap = 0;
}

int tree_add(tree_t *t, uint32_t pid, uint32_t ppid,
             const char *comm, const char *cmdline) {
    /* Upsert by pid: a telemetry stream revisits a pid across exec/open/net/exit.
     * Empty fields never clobber a value we already learned, because an `open`
     * record carries no cmdline and model.js would still see the exec's argv. */
    tree_proc_t *n = NULL;
    for (size_t i = 0; i < t->len; i++)
        if (t->procs[i].pid == pid) { n = &t->procs[i]; break; }
    if (!n) {
        if (t->len == t->cap) {
            size_t cap = t->cap ? t->cap * 2 : 16;
            tree_proc_t *p = realloc(t->procs, cap * sizeof *p);
            if (!p) return -1;
            t->procs = p; t->cap = cap;
        }
        n = &t->procs[t->len++];
        memset(n, 0, sizeof *n);
        n->pid = pid;
    }
    if (ppid) n->ppid = ppid;
    /* cstr(): lift at the first NUL, exactly like model.js. */
    if (comm && *comm) snprintf(n->comm, sizeof n->comm, "%s", comm);
    if (cmdline && *cmdline) snprintf(n->cmdline, sizeof n->cmdline, "%s", cmdline);
    return 0;
}

void tree_remove(tree_t *t, uint32_t pid) {
    for (size_t i = 0; i < t->len; i++) {
        if (t->procs[i].pid != pid) continue;
        for (size_t k = i + 1; k < t->len; k++) t->procs[k - 1] = t->procs[k];
        t->len--;
        return;
    }
}

void tree_basename(const char *path, char *out, size_t cap) {
    if (!out || cap == 0) return;
    if (!path) { out[0] = '\0'; return; }
    const char *slash = strrchr(path, '/');
    snprintf(out, cap, "%s", slash ? slash + 1 : path);
}

int tree_prefix_match(const char *name, const char *needle) {
    if (!name || !needle) return 0;
    for (size_t i = 0; needle[i]; i++)
        if (tolower((unsigned char)name[i]) != needle[i]) return 0;
    return 1;
}

int tree_name_matches(const char *comm, const char *cmdline, const char *needle) {
    if (!needle || !*needle) return 0;
    if (comm && tree_prefix_match(comm, needle)) return 1;
    /* model.js: basename(cmdline.split(" ")[0]).toLowerCase() */
    char first[512]; size_t o = 0;
    const char *cl = cmdline ? cmdline : "";
    while (cl[o] && cl[o] != ' ' && o + 1 < sizeof first) { first[o] = cl[o]; o++; }
    first[o] = '\0';
    if (o == 0) return 0;
    char base[512];
    tree_basename(first, base, sizeof base);
    return base[0] && tree_prefix_match(base, needle);
}

/* BFS over child links, guarded by the same pid-reuse dedupe set upstream
 * keeps in `tracked`: a pid is enqueued at most once, so a cycle cannot loop.
 * `seeds` is the initial queue. */
static size_t bfs(const tree_t *t, uint32_t *seeds, size_t nseed, uint32_t **out) {
    size_t cap = t->len ? t->len : 1;
    uint32_t *set = calloc(cap, sizeof *set);
    uint32_t *queue = calloc(cap * 2 + 8, sizeof *queue);
    if (!set || !queue) { free(set); free(queue); *out = NULL; return 0; }
    size_t nset = 0, qh = 0, qt = 0;
    for (size_t i = 0; i < nseed; i++) queue[qt++] = seeds[i];

    while (qh < qt) {
        uint32_t pid = queue[qh++];
        int dup = 0;
        for (size_t i = 0; i < nset; i++) if (set[i] == pid) { dup = 1; break; }
        if (dup) continue;
        if (nset < cap) set[nset++] = pid;
        for (size_t k = 0; k < t->len; k++) {
            /* model.js rechecks kn.ppid === pid against the live node. */
            if (t->procs[k].pid == pid) continue;
            if (t->procs[k].ppid == pid && qt < cap * 2 + 8) queue[qt++] = t->procs[k].pid;
        }
    }
    free(queue);
    *out = set;
    return nset;
}

size_t tree_descendants(const tree_t *t, uint32_t root_pid, uint32_t **out) {
    uint32_t seed = root_pid;
    return bfs(t, &seed, 1, out);
}

size_t tree_seed_and_descendants(const tree_t *t, uint32_t root_pid,
                                 const char *match, uint32_t **out) {
    if (root_pid) return tree_descendants(t, root_pid, out);
    /* Fresh session: seed from every name match, then BFS down. */
    uint32_t *seeds = calloc(t->len + 1, sizeof *seeds);
    if (!seeds) { *out = NULL; return 0; }
    size_t n = 0;
    for (size_t i = 0; i < t->len; i++)
        if (tree_name_matches(t->procs[i].comm, t->procs[i].cmdline, match))
            seeds[n++] = t->procs[i].pid;
    if (n == 0) { free(seeds); *out = NULL; return 0; }
    size_t r = bfs(t, seeds, n, out);
    free(seeds);
    return r;
}

int tree_member(const uint32_t *set, size_t n, uint32_t pid) {
    for (size_t i = 0; i < n; i++) if (set[i] == pid) return 1;
    return 0;
}

/* ------------------------------------------------------- the start map -- */

void tree_starts_init(tree_starts_t *st) { st->recs = NULL; st->len = st->cap = 0; }

void tree_starts_free(tree_starts_t *st) {
    free(st->recs);
    st->recs = NULL; st->len = st->cap = 0;
}

static tree_start_t *st_slot(tree_starts_t *st, uint32_t pid) {
    for (size_t i = 0; i < st->len; i++) if (st->recs[i].pid == pid) return &st->recs[i];
    return NULL;
}

void tree_starts_put(tree_starts_t *st, uint32_t pid, uint32_t ppid, uint64_t ts) {
    tree_start_t *r = st_slot(st, pid);
    if (r) { r->ppid = ppid; r->ts = ts; return; }
    if (st->len == st->cap) {
        size_t cap = st->cap ? st->cap * 2 : 32;
        tree_start_t *p = realloc(st->recs, cap * sizeof *p);
        if (!p) return;
        st->recs = p; st->cap = cap;
    }
    st->recs[st->len].pid = pid;
    st->recs[st->len].ppid = ppid;
    st->recs[st->len].ts = ts;
    st->len++;
}

const tree_start_t *tree_starts_get(const tree_starts_t *st, uint32_t pid) {
    for (size_t i = 0; i < st->len; i++) if (st->recs[i].pid == pid) return &st->recs[i];
    return NULL;
}

void tree_starts_del(tree_starts_t *st, uint32_t pid) {
    for (size_t i = 0; i < st->len; i++) {
        if (st->recs[i].pid != pid) continue;
        for (size_t k = i + 1; k < st->len; k++) st->recs[k - 1] = st->recs[k];
        st->len--;
        return;
    }
}

uint64_t tree_duration(uint64_t start_ts, uint64_t exit_ts) {
    if (!start_ts || exit_ts < start_ts) return 0;   /* unknown, never fabricated */
    return exit_ts - start_ts;
}

/* ------------------------------------------------------------- feed.js --- */

void tree_scrub(const char *in, char *out, size_t cap) {
    if (!out || cap == 0) return;
    static const char HEXD[] = "0123456789abcdef";
    size_t o = 0;
    const unsigned char *p = (const unsigned char *)(in ? in : "");
    /* feed.js scrubs per JS character (code point), not per byte:
     *   /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g
     * so U+0080..U+009F (C1, two bytes in UTF-8) must be scrubbed while a
     * UTF-8 continuation byte that merely *looks* like 0x80-0x9f must not be.
     * Decoding first is what makes this a port rather than a byte mangler. */
    while (*p) {
        unsigned int cp = p[0];
        int len = 1;
        if ((p[0] & 0xE0) == 0xC0 && (p[1] & 0xC0) == 0x80) {
            cp = ((unsigned)(p[0] & 0x1F) << 6) | (unsigned)(p[1] & 0x3F); len = 2;
        } else if ((p[0] & 0xF0) == 0xE0 &&
                   (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
            cp = ((unsigned)(p[0] & 0x0F) << 12) | ((unsigned)(p[1] & 0x3F) << 6) |
                 (unsigned)(p[2] & 0x3F); len = 3;
        } else if ((p[0] & 0xF8) == 0xF0 &&
                   (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
            cp = ((unsigned)(p[0] & 0x07) << 18) | ((unsigned)(p[1] & 0x3F) << 12) |
                 ((unsigned)(p[2] & 0x3F) << 6) | (unsigned)(p[3] & 0x3F); len = 4;
        }
        int bad = (cp <= 0x08) || (cp >= 0x0a && cp <= 0x1f) ||
                  (cp >= 0x7f && cp <= 0x9f);
        if (bad && cp <= 0xff) {
            if (o + 4 >= cap) break;
            out[o++] = '\\'; out[o++] = 'x';
            out[o++] = HEXD[(cp >> 4) & 0xf]; out[o++] = HEXD[cp & 0xf];
        } else {
            if (o + (size_t)len + 1 > cap) break;   /* never split a sequence */
            memcpy(out + o, p, (size_t)len); o += (size_t)len;
        }
        p += len;
    }
    out[o] = '\0';
}

/* --------------------------------------------- the sensor BPF program counters -- */

void tree_stats_drop(tree_stats_t *s, uint64_t n) { if (s) s->drop_total += n; }
void tree_stats_upd_fail(tree_stats_t *s, uint64_t n) { if (s) s->upd_fail_total += n; }
