/* tree.h — the process-tree and field-scrub logic.
 *
 * Lineage:
 *   config.js  -> the selection contract: MATCH (lowercased, NEEDLE_LEN=16
 *                 prefix), SECS / SECS_INVALID, FOLD_SKIPPED, ALL / SHOW.
 *   model.js   -> process-tree reconstruction (parent links by ppid, BFS
 *                 membership from matched roots) + the exec->exit `start`
 *                 bridge that yields a duration.
 *   feed.js    -> `scrub`: C0/C1 control bytes become `\xHH` before anything
 *                 reaches the wire.
 *   the sensor BPF program -> drop_total / upd_fail_total, counted and never hidden.
 *
 * This is the *logic* only. the audit sensor's presentation (colours, badges, the
 * human clock, fmtDur/fmtAddr/fmtOpenMode) is deliberately NOT ported: the
 * frontend owns presentation now (see docs/lineage/tree.md).
 */
#ifndef LAMASSU_TREE_H
#define LAMASSU_TREE_H

#include "lamassu.h"

/* ----------------------------------------------------------- config.js --- */
/* NEEDLE_LEN. The needle is a program-name prefix
 * matches a fresh session on; the kernel side agrees byte-for-byte. */
#define WD_TREE_NEEDLE_LEN 16

/* config.js ALL — the event classes the feed can show. */
enum {
    TREE_CLASS_EXEC = 0, TREE_CLASS_EXIT, TREE_CLASS_OPEN,
    TREE_CLASS_CONN, TREE_CLASS_LISTEN, TREE_NCLASSES
};
extern const char *const TREE_ALL[TREE_NCLASSES];

typedef struct {
    char   match[WD_TREE_NEEDLE_LEN + 1]; /* lowercased, truncated */
    int    match_truncated;
    long   secs;                          /* 0 = run until Ctrl-C */
    int    secs_invalid;
    char   fold_skipped[8][8];            /* config.js FOLD_SKIPPED */
    size_t fold_len;
    int    show[TREE_NCLASSES];           /* config.js SHOW membership */
} tree_config_t;

void tree_config_default(tree_config_t *c);
/* Parses an argv-style token list exactly as config.js folds `yeet.args`:
 * `--k=v` is a named arg, a bare `k=v` is positional and is folded back into
 * the named set — unless the key was already named, in which case it lands in
 * FOLD_SKIPPED rather than silently overriding. */
void tree_config_parse(tree_config_t *c, int argc, char **argv);

/* ------------------------------------------------------------ model.js --- */
typedef struct {
    uint32_t pid, ppid;
    char     comm[64];
    char     cmdline[512];
} tree_proc_t;

typedef struct {
    tree_proc_t *procs;
    size_t       len, cap;
} tree_t;

void tree_init(tree_t *t);
void tree_free(tree_t *t);
int  tree_add(tree_t *t, uint32_t pid, uint32_t ppid,
              const char *comm, const char *cmdline);
/* the exit handler deletes an exited pid from `tracked` when its
 * last thread leaves, so a later event from that pid is no longer a member.
 * Replay mirrors that: an event from an exited pid is not owned by the session
 * and is counted as a drop rather than mis-attributed. */
void tree_remove(tree_t *t, uint32_t pid);

/* Membership: the set of tgids that belong to a session. With a known
 * root_pid it is that pid plus every descendant; with root_pid == 0 (a fresh
 * session) it is every process whose name matches the needle, plus their
 * descendants — exactly model.js sessionTgids(). The root is always a member.
 * *out is malloc'd; the caller frees it. Returns the member count. */
size_t tree_descendants(const tree_t *t, uint32_t root_pid, uint32_t **out);
size_t tree_seed_and_descendants(const tree_t *t, uint32_t root_pid,
                                 const char *match, uint32_t **out);
int    tree_member(const uint32_t *set, size_t n, uint32_t pid);

/* model.js isMatch: comm prefix, or the basename of argv[0] prefix, compared
 * case-insensitively against the (pre-lowercased) needle. Mirrors the
 * kernel-side name_matches() test so the JS seed and the kernel agree. */
int  tree_name_matches(const char *comm, const char *cmdline, const char *needle);
int  tree_prefix_match(const char *name, const char *needle);
void tree_basename(const char *path, char *out, size_t cap);

/* The `start` map: exec stamps a (ts, ppid) keyed by tgid so EXIT can report
 * how long the process lived. A pid with no stamp reports an unknown (0)
 * lifetime — never a fabricated one. */
typedef struct { uint32_t pid, ppid; uint64_t ts; } tree_start_t;
typedef struct { tree_start_t *recs; size_t len, cap; } tree_starts_t;

void   tree_starts_init(tree_starts_t *st);
void   tree_starts_free(tree_starts_t *st);
void   tree_starts_put(tree_starts_t *st, uint32_t pid, uint32_t ppid, uint64_t ts);
const tree_start_t *tree_starts_get(const tree_starts_t *st, uint32_t pid);
void   tree_starts_del(tree_starts_t *st, uint32_t pid);
uint64_t tree_duration(uint64_t start_ts, uint64_t exit_ts); /* 0 when unknown */

/* ------------------------------------------------------------- feed.js --- */
/* scrub: C0 (0x00-0x08, 0x0a-0x1f), DEL and C1 (0x7f-0x9f) become `\xHH`
 * (lowercase, two digits). TAB (0x09) is deliberately left alone, matching
 * feed.js's character class exactly. */
void tree_scrub(const char *in, char *out, size_t cap);

/* --------------------------------------------- the sensor BPF program counters -- */
typedef struct {
    uint64_t events;        /* captured */
    uint64_t printed;       /* shown */
    uint64_t errors;
    uint64_t drop_total;    /* ring full: reported, never hidden */
    uint64_t upd_fail_total;
} tree_stats_t;

void tree_stats_drop(tree_stats_t *s, uint64_t n);
void tree_stats_upd_fail(tree_stats_t *s, uint64_t n);

#endif /* LAMASSU_TREE_H */
