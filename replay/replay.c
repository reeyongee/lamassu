/* replay.c — drive the whole lamassu core end-to-end from fixture files.
 *
 * This host is macOS: eBPF cannot run here at all. Replay is therefore the
 * only path on which the sensor event model, the session correlation, the
 * process-tree logic (core/tree.c) and the firewall can be
 * exercised together — a first-class deliverable, not a test afterthought.
 *
 * Input: two JSONL fixture files (format documented in replay/README.md).
 * Output: the CONTRACTS.md §9 stream, one JSON object per line, on stdout,
 * with a monotonically increasing `seq`; a count table on stderr; exit 0.
 *
 * Malformed input is a hard, reported failure — never a crash. The fixtures
 * and this parser are the attack surface, so every field is type-checked and
 * parsing is delegated to the depth-limited json_parse().
 *
 * Lineage: the process-tree, membership, scrub and counter logic comes from
 * the audit sensor (core/tree.c, replay/replay.c) via
 * core/tree.c; the inspection logic is the lamassu core itself.
 */
#include "tree.h"

#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static tree_starts_t g_starts;

/* ------------------------------------------------------------------ util -- */

static void die(const char *file, int lineno, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 3, 4)));

static void die(const char *file, int lineno, const char *fmt, ...) {
    fflush(stdout);                      /* never lose already-emitted lines */
    fprintf(stderr, "replay: %s:%d: ", file, lineno);
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* A JSON string field, or NULL when absent. Wrong type is a fixture error. */
static const char *req_str(const jval_t *o, const char *key,
                           const char *file, int ln) {
    const jval_t *v = json_get(o, key);
    if (!v) die(file, ln, "missing required field \"%s\"", key);
    if (v->t != JSTR) die(file, ln, "field \"%s\" must be a string", key);
    return v->str ? v->str : "";
}

static const char *opt_str(const jval_t *o, const char *key,
                           const char *dflt, const char *file, int ln) {
    const jval_t *v = json_get(o, key);
    if (!v) return dflt;
    if (v->t != JSTR) die(file, ln, "field \"%s\" must be a string", key);
    return v->str ? v->str : "";
}

static double req_num(const jval_t *o, const char *key,
                      const char *file, int ln) {
    const jval_t *v = json_get(o, key);
    if (!v) die(file, ln, "missing required field \"%s\"", key);
    if (v->t != JNUM) die(file, ln, "field \"%s\" must be a number", key);
    return v->num;
}

static double opt_num(const jval_t *o, const char *key, double dflt,
                      const char *file, int ln) {
    const jval_t *v = json_get(o, key);
    if (!v) return dflt;
    if (v->t != JNUM) die(file, ln, "field \"%s\" must be a number", key);
    return v->num;
}

/* ----------------------------------------------------------- json escape -- */

/* Escape `in` and append it into a growing line buffer. json_escape emits the
 * body only; this adds the surrounding quotes. */
static void put_escaped(char *dst, size_t cap, size_t *o, const char *in) {
    if (*o + 1 >= cap) return;
    dst[(*o)++] = '"';
    char tmp[8192];
    json_escape(in ? in : "", tmp, sizeof tmp);
    size_t l = strlen(tmp);
    if (*o + l + 2 >= cap) l = cap > *o + 2 ? cap - *o - 2 : 0;
    memcpy(dst + *o, tmp, l); *o += l;
    if (*o + 1 < cap) dst[(*o)++] = '"';
    dst[*o] = '\0';
}

/* --------------------------------------------------------- the emitter ---- */

#define LINE_CAP 65536

static long g_seq = 0;
static uint64_t g_drops_emitted = 0;

static void emit_line(char *buf) {
    fputs(buf, stdout);
    fputc('\n', stdout);
}

/* --------------------------------------------------- per-session tallies -- */

typedef struct {
    char     sid[64];
    uint64_t events;
    uint64_t findings;
    uint64_t tainted_counted;
} tally_t;

static tally_t  g_tally[WD_MAX_SESSIONS];
static size_t   g_tally_len = 0;

static tally_t *tally_get(const char *sid) {
    for (size_t i = 0; i < g_tally_len; i++)
        if (strcmp(g_tally[i].sid, sid) == 0) return &g_tally[i];
    if (g_tally_len >= WD_MAX_SESSIONS) return NULL;
    tally_t *t = &g_tally[g_tally_len++];
    memset(t, 0, sizeof *t);
    snprintf(t->sid, sizeof t->sid, "%s", sid);
    return t;
}

/* -------------------------------------------------------- global counters -- */

typedef struct {
    uint64_t events;
    uint64_t tainted_sessions;
    uint64_t invariant_findings;
    uint64_t scored_findings;
    uint64_t decisions_block;
    uint64_t drop_total;
} counts_t;

static counts_t g_counts;

/* ----------------------------------------------------------- emit stream -- */

static void emit_session_open(const session_t *s) {
    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o, "{\"seq\":%ld,\"t\":\"session_open\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"harness\":");
    put_escaped(buf, sizeof buf, &o, s->harness);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"root_pid\":%u}", s->root_pid);
    emit_line(buf);
}

static void emit_span_line(const session_t *s, const span_t *sp) {
    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        "{\"seq\":%ld,\"t\":\"span\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"trust\":");
    put_escaped(buf, sizeof buf, &o, sp->trust == TRUST_DATA ? "data" :
                                     sp->trust == TRUST_USER ? "user" : "system");
    if (sp->trust == TRUST_DATA && sp->has_origin) {
        o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"origin\":{\"channel\":");
        put_escaped(buf, sizeof buf, &o, sp->origin.channel);
        o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"ref\":");
        put_escaped(buf, sizeof buf, &o, sp->origin.ref);
        o += (size_t)snprintf(buf + o, sizeof buf - o, "}");
    }
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"role\":");
    put_escaped(buf, sizeof buf, &o, sp->role);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"text_len\":%zu}",
                          sp->text ? strlen(sp->text) : 0);
    emit_line(buf);
}

static void emit_event_line(const session_t *s, const event_t *e) {
    /* Fields are scrubbed exactly as the field-scrub logic does, and
     * only at emission time, before json_escape — a control byte or newline
     * must not reach the stream raw. */
    char comm[256], cmdline[2048], filename[1024];
    tree_scrub(e->comm, comm, sizeof comm);
    tree_scrub(e->cmdline, cmdline, sizeof cmdline);
    tree_scrub(e->filename, filename, sizeof filename);

    static const char *KN[] = { "exec", "exit", "open", "net" };

    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        "{\"seq\":%ld,\"t\":\"event\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"kind\":");
    put_escaped(buf, sizeof buf, &o, KN[e->kind]);
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        ",\"ts\":%llu,\"pid\":%u,\"ppid\":%u,\"comm\":",
        (unsigned long long)e->ts, e->pid, e->ppid);
    put_escaped(buf, sizeof buf, &o, comm);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"cmdline\":");
    put_escaped(buf, sizeof buf, &o, cmdline);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"filename\":");
    put_escaped(buf, sizeof buf, &o, filename);
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        ",\"flags\":%u,\"dirfd\":%d,\"port\":%u,\"addr\":",
        e->flags, e->dirfd, (unsigned)e->port);
    char addr[128];
    /* addr is carried as a string in the fixture; it survives verbatim and is
     * scrubbed like every other string field. */
    snprintf(addr, sizeof addr, "%s", e->addr_len ? (const char *)e->addr : "");
    put_escaped(buf, sizeof buf, &o, addr);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"tainted\":%s}",
                          e->tainted ? "true" : "false");
    emit_line(buf);

    g_counts.events++;
    tally_t *t = tally_get(s->sid);
    if (t) t->events++;
}

static void emit_finding_line(const session_t *s, const finding_t *f) {
    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        "{\"seq\":%ld,\"t\":\"finding\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"layer\":");
    put_escaped(buf, sizeof buf, &o, f->layer);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"rule\":");
    put_escaped(buf, sizeof buf, &o, f->rule);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"severity\":");
    put_escaped(buf, sizeof buf, &o, severity_name(f->severity));
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"invariant\":%s,\"provenance\":",
                          f->invariant ? "true" : "false");
    put_escaped(buf, sizeof buf, &o, provenance_name(f->provenance));
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"evidence_digest\":");
    put_escaped(buf, sizeof buf, &o, f->evidence_digest);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"span_index\":%d,\"tainted\":%s}",
                          f->span_index, f->tainted ? "true" : "false");
    emit_line(buf);

    if (f->invariant) g_counts.invariant_findings++;
    else              g_counts.scored_findings++;
    tally_t *t = tally_get(s->sid);
    if (t) t->findings++;
}

static void emit_decision_line(const session_t *s, decision_t d) {
    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        "{\"seq\":%ld,\"t\":\"decision\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"decision\":");
    put_escaped(buf, sizeof buf, &o, decision_name(d));
    o += (size_t)snprintf(buf + o, sizeof buf - o, "}");
    emit_line(buf);
    if (d == DEC_BLOCK) g_counts.decisions_block++;
}

/* A dropped event must reach the STREAM, not only the exit summary. The whole
 * point of the project's honesty rule is that a consumer can see the feed was
 * lossy; a count on stderr that the frontend never receives would leave the UI
 * showing an intact record for an incomplete run. */
static void emit_drop_line(void) {
    char buf[256];
    snprintf(buf, sizeof buf,
        "{\"seq\":%llu,\"t\":\"warning\",\"code\":\"events-dropped\","
        "\"drop_total\":%llu}",
        (unsigned long long)++g_seq, (unsigned long long)g_counts.drop_total);
    g_drops_emitted++;
    emit_line(buf);
}

static void emit_session_close(const session_t *s, uint64_t findings) {
    char buf[LINE_CAP];
    size_t o = 0;
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        "{\"seq\":%ld,\"t\":\"session_close\",\"session\":", ++g_seq);
    put_escaped(buf, sizeof buf, &o, s->sid);
    o += (size_t)snprintf(buf + o, sizeof buf - o,
        ",\"counts\":{\"events\":%llu,\"findings\":%llu,\"drop_total\":%llu,"
        "\"upd_fail_total\":%llu}}",
        (unsigned long long)s->event_len, (unsigned long long)findings,
        (unsigned long long)s->drop_total, (unsigned long long)s->upd_fail_total);
    emit_line(buf);
}

/* Emit every finding of an inspection, then the decision. */
static void emit_inspection(const session_t *s, const findings_t *f, decision_t d) {
    for (size_t i = 0; i < f->len; i++) emit_finding_line(s, &f->items[i]);
    emit_decision_line(s, d);
}

/* ---------------------------------------------------- {{nonce}} template -- */

/* A static fixture cannot know a nonce minted at run time, so a span may write
 * the literal token {{nonce}} and it is replaced with the session's real nonce
 * before the span is inspected. That is how a fixture drives the nonce-forgery
 * path honestly: the attacker is modelled as having obtained the fence value.
 * Substitution calls session_nonce(), which mints the nonce if not yet minted. */
static char *subst_nonce(const char *in, session_t *s) {
    const char *needle = "{{nonce}}";
    size_t nlen = strlen(needle);
    const char *n = s ? session_nonce(s) : "";
    size_t nl = strlen(n), cap = strlen(in) + 64;
    /* each placeholder (nlen) becomes at most nl>nlen bytes; grow if needed */
    const char *scan = in;
    size_t hits = 0;
    while ((scan = strstr(scan, needle))) { hits++; scan += nlen; }
    cap += hits * (nl + 1);
    char *out = xcalloc(cap, 1);
    size_t o = 0;
    for (const char *p = in; *p; ) {
        if (strncmp(p, needle, nlen) == 0) {
            memcpy(out + o, n, nl); o += nl; p += nlen;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    return out;
}

/* --------------------------------------------------------- fixture lines -- */

typedef struct {
    jval_t *val;
    int     file;      /* 0 = events, 1 = spans */
    int     lineno;
    long    ord;
} fline_t;

static const char *FNAME[2];

static int cmp_fline(const void *a, const void *b) {
    const fline_t *x = a, *y = b;
    if (x->ord != y->ord) return x->ord < y->ord ? -1 : 1;
    if (x->file != y->file) return x->file < y->file ? -1 : 1;
    return x->lineno < y->lineno ? -1 : (x->lineno > y->lineno ? 1 : 0);
}

/* Parse one file into `out`, returning the new length. Every line must be a
 * JSON object with a string "t". Nothing here may crash on hostile input. */
static size_t load_file(const char *path, int fidx, fline_t *out, size_t cap,
                        tree_t *tree) {
    FILE *f = fopen(path, "rb");
    if (!f) { fflush(stdout); fprintf(stderr, "replay: cannot open %s\n", path); exit(1); }

    char  *line = NULL;
    size_t linecap = 0;
    ssize_t n;
    int lineno = 0;
    size_t nout = 0;

    while ((n = getline(&line, &linecap, f)) != -1) {
        lineno++;
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;                         /* blank line */

        char err[256];
        jval_t *v = json_parse(line, err, sizeof err);
        if (!v) { free(line); fclose(f); die(path, lineno, "%s", err); }
        if (v->t != JOBJ) { json_free(v); free(line); fclose(f);
                            die(path, lineno, "top-level value must be an object"); }
        const jval_t *tv = json_get(v, "t");
        if (!tv || tv->t != JSTR) { json_free(v); free(line); fclose(f);
                            die(path, lineno, "missing string field \"t\""); }

        if (nout >= cap) { json_free(v); free(line); fclose(f);
                           die(path, lineno, "too many lines (cap %zu)", cap); }

        long ord;
        const jval_t *ov = json_get(v, "ord");
        if (ov && ov->t == JNUM) ord = (long)ov->num;
        else                     ord = (long)lineno;

        /* Pass A also reconstructs the process tree from exec events, exactly
         * as membership is seeded from a sysgraph snapshot before it
         * streams the ring. */
        if (strcmp(tv->str, "event") == 0) {
            const jval_t *kv = json_get(v, "kind");
            if (kv && kv->t == JSTR && strcmp(kv->str, "exec") == 0) {
                const jval_t *pv = json_get(v, "pid");
                if (pv && pv->t == JNUM) {
                    uint32_t pid = (uint32_t)pv->num;
                    const jval_t *pp = json_get(v, "ppid");
                    uint32_t ppid = (pp && pp->t == JNUM) ? (uint32_t)pp->num : 0;
                    tree_add(tree, pid, ppid,
                             opt_str(v, "comm", "", path, lineno),
                             opt_str(v, "cmdline", "", path, lineno));
                }
            }
        }

        out[nout].val = v;
        out[nout].file = fidx;
        out[nout].lineno = lineno;
        out[nout].ord = ord;
        nout++;
    }
    free(line);
    fclose(f);
    return nout;
}

/* ------------------------------------------------------- session helpers -- */

static session_t *get_or_open(const char *sid, uint32_t root_pid,
                              const char *harness) {
    session_t *s = session_find(sid);
    if (s) return s;
    s = session_open(sid, harness ? harness : "replay", root_pid);
    if (!s) { fflush(stdout); fprintf(stderr, "replay: too many sessions\n"); exit(1); }
    emit_session_open(s);
    return s;
}

/* Membership: the set of tgids that belong to a session, recomputed from the
 * fully-reconstructed process tree (model.js sessionTgids: matched roots plus
 * every descendant). A named root_pid seeds the BFS; 0 falls back to the
 * needle match. Cached per call site by the caller. */
static size_t session_members(const session_t *s, const tree_t *tree,
                              const char *match, uint32_t **out) {
    return tree_seed_and_descendants(tree, s->root_pid, match, out);
}

/* --------------------------------------------------------------- policy --- */

static int policy_line(firewall_t *fw, policy_t *pol, const jval_t *v,
                       const char *file, int ln) {
    const jval_t *b = json_get(v, "block_threshold");
    if (b) {
        if (b->t != JSTR) die(file, ln, "\"block_threshold\" must be a string");
        severity_t sev = SEV_HIGH;
        if      (!strcmp(b->str, "INFO"))     sev = SEV_INFO;
        else if (!strcmp(b->str, "LOW"))      sev = SEV_LOW;
        else if (!strcmp(b->str, "MEDIUM"))   sev = SEV_MEDIUM;
        else if (!strcmp(b->str, "HIGH"))     sev = SEV_HIGH;
        else if (!strcmp(b->str, "CRITICAL")) sev = SEV_CRITICAL;
        else die(file, ln, "unknown block_threshold \"%s\"", b->str);
        pol->block_threshold = sev;
    }
    const jval_t *sd = json_get(v, "strict_data");
    if (sd) {
        if (sd->t != JBOOL) die(file, ln, "\"strict_data\" must be a boolean");
        pol->strict_data = sd->boolean ? true : false;
    }

    /* string vectors */
    struct { const char *key; char ***dst; size_t *n; } vecs[3];
    vecs[0].key = "canaries";           vecs[0].dst = &pol->canaries;           vecs[0].n = &pol->canary_len;
    vecs[1].key = "allowed_hosts";      vecs[1].dst = &pol->allowed_hosts;      vecs[1].n = &pol->host_len;
    vecs[2].key = "forbidden_effects";  vecs[2].dst = &pol->forbidden_effects;  vecs[2].n = &pol->eff_len;
    for (size_t i = 0; i < 3; i++) {
        const jval_t *arr = json_get(v, vecs[i].key);
        if (!arr) continue;
        if (arr->t != JARR) die(file, ln, "\"%s\" must be an array", vecs[i].key);
        const char **items = xcalloc(arr->len ? arr->len : 1, sizeof *items);
        char **store = xcalloc(arr->len ? arr->len : 1, sizeof *store);
        for (size_t k = 0; k < arr->len; k++) {
            if (arr->items[k]->t != JSTR) die(file, ln, "\"%s\" entries must be strings", vecs[i].key);
            store[k] = xstrdup(arr->items[k]->str ? arr->items[k]->str : "");
            items[k] = store[k];
        }
        policy_set_vec(vecs[i].dst, vecs[i].n, items, arr->len);
        free(store); free(items);
    }

    char perr[256];
    if (policy_validate_canaries(pol, perr, sizeof perr) != 0) {
        fflush(stdout);
        fprintf(stderr, "replay: %s:%d: %s\n", file, ln, perr);
        exit(1);
    }
    firewall_init(fw, pol);
    return 0;
}

/* ------------------------------------------------------------ tool calls -- */

static void free_tool_call(tool_call_t *tc) {
    for (size_t i = 0; i < tc->arg_len; i++) { free(tc->arg_keys[i]); free(tc->arg_vals[i]); }
    free(tc->arg_keys); free(tc->arg_vals);
    for (size_t i = 0; i < tc->permitted_len; i++) free(tc->permitted[i]);
    free(tc->permitted);
    for (size_t i = 0; i < tc->required_len; i++) free(tc->required[i]);
    free(tc->required);
    for (size_t i = 0; i < tc->allow_len; i++) free(tc->allow_vals[i]);
    free(tc->allow_keys); free(tc->allow_vals);
    for (size_t i = 0; i < tc->effect_len; i++) free(tc->effects[i]);
    free(tc->effects);
    for (size_t i = 0; i < tc->guard_len; i++) free(tc->guards[i]);
    free(tc->guards);
}

static size_t load_strvec(const jval_t *o, const char *key, char ***out,
                          const char *file, int ln) {
    *out = NULL;
    const jval_t *v = json_get(o, key);
    if (!v) return 0;
    if (v->t != JARR) die(file, ln, "\"%s\" must be an array", key);
    char **arr = xcalloc(v->len ? v->len : 1, sizeof *arr);
    for (size_t i = 0; i < v->len; i++) {
        if (v->items[i]->t != JSTR) die(file, ln, "\"%s\" entries must be strings", key);
        arr[i] = xstrdup(v->items[i]->str ? v->items[i]->str : "");
    }
    *out = arr;
    return v->len;
}

/* Parse a tool_call object into a tool_call_t. `ntc`-style; caller frees. */
static void parse_tool_call(const jval_t *o, tool_call_t *tc,
                            const char *file, int ln) {
    memset(tc, 0, sizeof *tc);
    snprintf(tc->name, sizeof tc->name, "%s", req_str(o, "name", file, ln));
    /* An undeclared tool must be refused; the fixture says so explicitly with
     * "known":false. Default is declared. */
    const jval_t *kv = json_get(o, "known");
    if (kv && kv->t != JBOOL) die(file, ln, "\"known\" must be a boolean");
    tc->known = kv ? kv->boolean : 1;
    tc->user_confirmed = json_bool(o, "user_confirmed", 0) ? true : false;

    const jval_t *args = json_get(o, "args");
    if (args) {
        if (args->t != JOBJ) die(file, ln, "\"args\" must be an object");
        size_t n = args->len;
        tc->arg_keys = xcalloc(n ? n : 1, sizeof *tc->arg_keys);
        tc->arg_vals = xcalloc(n ? n : 1, sizeof *tc->arg_vals);
        for (size_t i = 0; i < n; i++) {
            tc->arg_keys[i] = xstrdup(args->keys[i]);
            const jval_t *val = args->items[i];
            if (val->t == JSTR) {
                tc->arg_vals[i] = xstrdup(val->str ? val->str : "");
            } else if (val->t == JNUM) {
                char b[64]; snprintf(b, sizeof b, "%g", val->num);
                tc->arg_vals[i] = xstrdup(b);
            } else {
                /* Nested list/object: flatten every leaf the way PIP render_arg
                 * does, so a secret hidden below the top level is still seen. */
                char b[4096];
                flatten_json_arg(val, b, sizeof b);
                tc->arg_vals[i] = xstrdup(b);
            }
        }
        tc->arg_len = n;
    }
    tc->permitted_len  = load_strvec(o, "permitted", &tc->permitted, file, ln);
    tc->required_len   = load_strvec(o, "required",  &tc->required,  file, ln);
    tc->effect_len     = load_strvec(o, "effects",   &tc->effects,   file, ln);
    tc->guard_len      = load_strvec(o, "guards",    &tc->guards,    file, ln);
    /* ARGS_ALLOWLISTED vector: "key:value" specs. */
    char **allow = NULL;
    size_t alen = load_strvec(o, "allow", &allow, file, ln);
    tc->allow_vals = allow;
    tc->allow_len = alen;
    tc->allow_keys = NULL;   /* unused by layer_toolauth; specs carry the key */
}

/* --------------------------------------------------------------- process -- */

static void process_lines(fline_t *lines, size_t n, tree_t *tree,
                          tree_config_t *cfg, firewall_t *fw, policy_t *pol) {
    for (size_t i = 0; i < n; i++) {
        const jval_t *v = lines[i].val;
        const char *file = FNAME[lines[i].file];
        int ln = lines[i].lineno;
        const char *t = json_str(v, "t", NULL);
        if (!t) die(file, ln, "missing \"t\"");

        if (strcmp(t, "policy") == 0) {
            policy_line(fw, pol, v, file, ln);
            continue;
        }

        if (strcmp(t, "session_open") == 0) {
            const char *sid = req_str(v, "session", file, ln);
            if (session_find(sid)) die(file, ln, "session \"%s\" already open", sid);
            uint32_t root = (uint32_t)opt_num(v, "root_pid", 0, file, ln);
            const char *harness = opt_str(v, "harness", "replay", file, ln);
            session_t *s = session_open(sid, harness, root);
            if (!s) die(file, ln, "too many sessions");
            tally_get(sid);
            emit_session_open(s);
            continue;
        }

        if (strcmp(t, "span") == 0) {
            const char *sid = req_str(v, "session", file, ln);
            const char *trust = req_str(v, "trust", file, ln);
            const char *text = req_str(v, "text", file, ln);
            const char *role = opt_str(v, "role", "", file, ln);
            trust_t tt;
            if      (!strcmp(trust, "data"))   tt = TRUST_DATA;
            else if (!strcmp(trust, "user"))   tt = TRUST_USER;
            else if (!strcmp(trust, "system")) tt = TRUST_SYSTEM;
            else die(file, ln, "unknown trust \"%s\" (system|user|data)", trust);

            session_t *s = get_or_open(sid, 0, NULL);
            origin_t origin; origin.channel[0] = '\0'; origin.ref[0] = '\0';
            const origin_t *op = NULL;
            if (tt == TRUST_DATA) {
                const jval_t *ov = json_get(v, "origin");
                if (!ov) die(file, ln, "a data span must declare \"origin\"");
                if (ov->t != JOBJ) die(file, ln, "\"origin\" must be an object");
                snprintf(origin.channel, sizeof origin.channel, "%s",
                         opt_str(ov, "channel", "unknown", file, ln));
                snprintf(origin.ref, sizeof origin.ref, "%s",
                         opt_str(ov, "ref", "", file, ln));
                op = &origin;
            }
            char *sub = subst_nonce(text, s);
            session_span_add(s, tt, sub, op, role);
            free(sub);
            emit_span_line(s, &s->spans[s->span_len - 1]);
            continue;
        }

        if (strcmp(t, "event") == 0) {
            const char *sid = json_str(v, "session", NULL);
            const char *kind = req_str(v, "kind", file, ln);
            ev_kind_t k;
            if      (!strcmp(kind, "exec")) k = EV_EXEC;
            else if (!strcmp(kind, "exit")) k = EV_EXIT;
            else if (!strcmp(kind, "open")) k = EV_OPEN;
            else if (!strcmp(kind, "net"))  k = EV_NET;
            else die(file, ln, "unknown kind \"%s\" (exec|exit|open|net)", kind);

            uint32_t pid = (uint32_t)req_num(v, "pid", file, ln);
            uint32_t ppid = (uint32_t)opt_num(v, "ppid", 0, file, ln);

            /* Correlation: an event without an explicit session is attributed
             * by process-tree descent from a session root (CONTRACTS §1). An
             * event no session owns is what the kernel would not have emitted,
             * so it is counted and skipped, never silently mis-attributed. */
            session_t *s = NULL;
            if (sid) s = get_or_open(sid, 0, NULL);
            if (!s) {
                for (size_t k2 = 0; k2 < g_tally_len && !s; k2++) {
                    session_t *cand = session_find(g_tally[k2].sid);
                    if (!cand) continue;
                    uint32_t *members = NULL;
                    size_t nm = session_members(cand, tree, cfg->match, &members);
                    if (tree_member(members, nm, pid)) s = cand;
                    free(members);
                }
                if (!s) { g_counts.drop_total++; emit_drop_line(); continue; }
            }

            event_t e; memset(&e, 0, sizeof e);
            e.kind = k;
            e.pid = pid;
            e.ppid = ppid;
            e.ts = (uint64_t)opt_num(v, "ts", 0, file, ln);
            e.flags = (uint32_t)opt_num(v, "flags", 0, file, ln);
            e.dirfd = (int32_t)opt_num(v, "dirfd", -100, file, ln);
            e.port = (uint16_t)opt_num(v, "port", 0, file, ln);
            snprintf(e.comm, sizeof e.comm, "%s", opt_str(v, "comm", "", file, ln));
            snprintf(e.cmdline, sizeof e.cmdline, "%s", opt_str(v, "cmdline", "", file, ln));
            snprintf(e.filename, sizeof e.filename, "%s", opt_str(v, "filename", "", file, ln));
            const char *addr = opt_str(v, "addr", "", file, ln);
            if (addr[0]) {                       /* carry the address verbatim */
                size_t al = strlen(addr);
                if (al >= sizeof e.addr) al = sizeof e.addr - 1;
                memset(e.addr, 0, sizeof e.addr);
                memcpy(e.addr, addr, al);
                e.addr_len = (uint8_t)al;
            }

            /* The start map bridges exec -> exit so an exit reports a real
             * lifetime and a pid with no stamp reports 0, never a fabricated
             * duration (the sensor BPF program startrec). */
            if (k == EV_EXEC) {
                tree_starts_put(&g_starts, pid, ppid, e.ts);
                tree_add(tree, pid, ppid, e.comm, e.cmdline);
            } else if (k == EV_EXIT) {
                const tree_start_t *sr = tree_starts_get(&g_starts, pid);
                if (sr && sr->ts) {
                    uint64_t dur = tree_duration(sr->ts, e.ts);
                    fprintf(stderr, "replay: exit pid=%u lived=%llums\n",
                            pid, (unsigned long long)dur);
                }
                tree_starts_del(&g_starts, pid);
                /* Last thread left: the kernel drops the tgid from `tracked`,
                 * so a later event from this pid is no longer a member. */
                tree_remove(tree, pid);
            }

            /* The ring is bounded; a full ring must be counted, not hidden. */
            if (s->event_len >= WD_MAX_EVENTS) session_event_drop(s, 1);
            session_event_emit(s, &e);
            emit_event_line(s, &s->events[(s->event_head + WD_MAX_EVENTS - 1) % WD_MAX_EVENTS]);
            continue;
        }

        if (strcmp(t, "tool_call") == 0) {
            const char *sid = req_str(v, "session", file, ln);
            session_t *s = get_or_open(sid, 0, NULL);
            tool_call_t tc;
            parse_tool_call(v, &tc, file, ln);

            /* Substitute {{nonce}} in the argument values so the provenance
             * path is reachable from a static fixture. */
            for (size_t k = 0; k < tc.arg_len; k++) {
                if (strstr(tc.arg_vals[k], "{{nonce}}")) {
                    char *sub = subst_nonce(tc.arg_vals[k], s);
                    free(tc.arg_vals[k]);
                    tc.arg_vals[k] = sub;
                }
            }

            findings_t f; findings_init(&f);
            decision_t d = firewall_inspect_egress(fw, s, &tc, 1, NULL, &f);
            emit_inspection(s, &f, d);
            findings_free(&f);
            free_tool_call(&tc);
            continue;
        }

        if (strcmp(t, "reply") == 0) {
            const char *sid = req_str(v, "session", file, ln);
            session_t *s = get_or_open(sid, 0, NULL);
            const char *text = req_str(v, "text", file, ln);
            char *sub = subst_nonce(text, s);

            /* tool_calls: exercised together so toolauth and egress both run. */
            tool_call_t tcs[8]; size_t ntc = 0;
            const jval_t *arr = json_get(v, "tool_calls");
            if (arr) {
                if (arr->t != JARR) die(file, ln, "\"tool_calls\" must be an array");
                for (size_t k = 0; k < arr->len && ntc < 8; k++) {
                    if (arr->items[k]->t != JOBJ)
                        die(file, ln, "\"tool_calls\" entries must be objects");
                    parse_tool_call(arr->items[k], &tcs[ntc], file, ln);
                    for (size_t a = 0; a < tcs[ntc].arg_len; a++) {
                        if (strstr(tcs[ntc].arg_vals[a], "{{nonce}}")) {
                            char *as = subst_nonce(tcs[ntc].arg_vals[a], s);
                            free(tcs[ntc].arg_vals[a]);
                            tcs[ntc].arg_vals[a] = as;
                        }
                    }
                    ntc++;
                }
            }

            findings_t f; findings_init(&f);
            decision_t d = firewall_inspect_egress(fw, s, tcs, ntc, sub, &f);
            emit_inspection(s, &f, d);
            findings_free(&f);
            for (size_t k = 0; k < ntc; k++) free_tool_call(&tcs[k]);
            free(sub);
            continue;
        }

        if (strcmp(t, "session_close") == 0) {
            const char *sid = req_str(v, "session", file, ln);
            session_t *s = session_find(sid);
            if (!s) die(file, ln, "session \"%s\" is not open", sid);

            /* Inbound inspection over the whole declared span set: normalize +
             * ingress + provenance, then the decision (policy.py decide()). */
            findings_t f; findings_init(&f);
            decision_t d = firewall_inspect(fw, s, &f);
            emit_inspection(s, &f, d);
            findings_free(&f);

            tally_t *tal = tally_get(sid);
            uint64_t findings = tal ? tal->findings : 0;
            if (session_tainted(s)) g_counts.tainted_sessions++;
            g_counts.drop_total += s->drop_total;
            emit_session_close(s, findings);
            session_close(sid);
            continue;
        }

        die(file, ln, "unknown line type \"%s\"", t);
    }

    /* Sessions left open at EOF: still inspected, so nothing is silently
     * skipped; then counted. */
    for (size_t i = 0; i < g_tally_len; i++) {
        session_t *s = session_find(g_tally[i].sid);
        if (!s) continue;
        findings_t f; findings_init(&f);
        decision_t d = firewall_inspect(fw, s, &f);
        emit_inspection(s, &f, d);
        findings_free(&f);
        if (session_tainted(s)) g_counts.tainted_sessions++;
        g_counts.drop_total += s->drop_total;
        emit_session_close(s, g_tally[i].findings);
    }
}

/* ------------------------------------------------------------------ main -- */

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <events.jsonl> <spans.jsonl> [--match=..] [--secs=..] [--only=..] [--except=..]\n",
                argv[0]);
        return 2;
    }
    const char *events_path = argv[1];
    const char *spans_path  = argv[2];
    FNAME[0] = events_path;
    FNAME[1] = spans_path;

    /* stdout is piped to the frontend; line-buffer it so a mid-run die() never
     * leaves a half-written line buffered. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    tree_config_t cfg;
    tree_config_default(&cfg);
    tree_config_parse(&cfg, argc - 3, argv + 3);
    if (cfg.match_truncated)
        fprintf(stderr, "replay: match needle truncated to %d bytes\n", WD_TREE_NEEDLE_LEN);
    if (cfg.secs_invalid)
        fprintf(stderr, "replay: SECS_INVALID: secs is not a non-negative number\n");

    tree_t tree;
    tree_init(&tree);
    tree_starts_init(&g_starts);

    /* Two-pass: parse both files and reconstruct the process tree first, then
     * replay the merged line program. the audit sensor likewise seeds membership
     * from a sysgraph snapshot before streaming the ring. */
    size_t cap = 1 << 20;
    fline_t *lines = xcalloc(cap, sizeof *lines);
    size_t n = 0;
    n += load_file(events_path, 0, lines + n, cap - n, &tree);
    n += load_file(spans_path, 1, lines + n, cap - n, &tree);

    qsort(lines, n, sizeof *lines, cmp_fline);

    policy_t pol;
    policy_default(&pol);
    firewall_t fw;
    firewall_init(&fw, &pol);

    process_lines(lines, n, &tree, &cfg, &fw, &pol);

    if (g_counts.drop_total > g_drops_emitted) emit_drop_line();

    fprintf(stderr,
        "events=%llu tainted_sessions=%llu invariant_findings=%llu "
        "scored_findings=%llu decisions_block=%llu drop_total=%llu\n",
        (unsigned long long)g_counts.events,
        (unsigned long long)g_counts.tainted_sessions,
        (unsigned long long)g_counts.invariant_findings,
        (unsigned long long)g_counts.scored_findings,
        (unsigned long long)g_counts.decisions_block,
        (unsigned long long)g_counts.drop_total);

    for (size_t i = 0; i < n; i++) json_free(lines[i].val);
    free(lines);
    tree_free(&tree);
    tree_starts_free(&g_starts);
    policy_free(&pol);
    session_reset();
    return 0;
}
