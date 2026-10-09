/* lamassu-hook.c — Claude Code hook adapter: declared provenance at the model
 * boundary.
 *
 * Lineage:
 *   the guard layer/src/not_sandboxed/firewall.py  (Firewall.inspect,
 *       inspect_egress, render, _fence, the fail-closed _layer_error path)
 *   the guard layer/src/not_sandboxed/proxy/infer.py (the role ->
 *       Trust mapping this adapter deliberately does NOT need)
 *   the guard layer/src/not_sandboxed/config.py  (PROXY_TOOL_CHANNEL,
 *       PROXY_UNKNOWN_TOOL_REF, the FENCE shape)
 *
 * Why this adapter is the strong mode: a Claude Code hook is handed the event
 * JSON, and the event NAME is authoritative metadata supplied by the harness.
 * `prompt` on UserPromptSubmit is user-authored; `tool_response` on PostToolUse
 * is tool output, untrusted by definition; `tool_input` on PreToolUse is a
 * *requested action*, never a decision. So the adapter can DECLARE provenance
 * from the event type instead of guessing it from message roles the way the
 * proxy path must. No content is inspected to decide trust.
 *
 * One binary, four events. Dispatch on hook_event_name; read the event on stdin.
 *
 *   SessionStart      -> declare the session and its root pid
 *   UserPromptSubmit  -> declare `prompt` as a USER span, then firewall_inspect
 *   PostToolUse       -> declare `tool_response` (+ `tool_input`) as DATA spans
 *                        with origin {tool:<tool_name>}, then firewall_inspect
 *   PreToolUse        -> `tool_input` is a REQUESTED ACTION, not a span; run
 *                        firewall_inspect_egress, which honours taint
 *
 * Exit protocol (code.claude.com/docs/en/hooks.md):
 *   exit 2 is the ONLY exit code that blocks on its own; exit 1 does not block.
 *   Structured control is exit 0 + a JSON object on stdout. A hook whose JSON
 *   fails schema validation is a NON-BLOCKING error, so malformed JSON silently
 *   disables the gate. Therefore every terminal path here writes either a
 *   validated object or nothing at all, and the "we cannot even tell what this
 *   is" path uses exit 2, which blocks regardless of what stdout says.
 *
 * Fail closed: unparseable stdin, a missing session id, state I/O failure, or an
 * unrecognised event all REFUSE. An error must never look like an allow.
 *
 * Never leak attacker text: a reason names layer/rule and the evidence DIGEST
 * only. The core digests evidence in findings_push (util.c sha256_hex16); the
 * raw matched content is never carried into a finding, so it cannot reach a
 * reason string or the harness transcript.
 *
 * Per-process state: each hook invocation is a fresh process, so the session
 * (nonce + taint) is persisted under $LAMASSU_STATE (default $TMPDIR/lamassu),
 * keyed by the event's session_id. Taint is restored by ADDING a DATA span, not
 * by poking a flag, so session_tainted() still DERIVES it (context.py: "taint
 * cannot desync from reality"). */
#include "lamassu.h"
#include "toolguard.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ util -- */

static void *hook_realloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("lamassu-hook: out of memory\n", stderr); exit(2); }
    return q;
}

/* Read the whole of stdin. Bounded so a hostile producer cannot make the hook
 * allocate without limit; over budget is a refusal, not a partial read. */
#define HOOK_MAX_INPUT (8u * 1024u * 1024u)

/* Flattened argument/response text cap: matches the core's normalize budget. */
#define HOOK_FLAT_CAP 65536

static int read_all_stdin(char **out, size_t *out_len) {
    size_t cap = 65536, len = 0;
    char *buf = xcalloc(cap, 1);
    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= HOOK_MAX_INPUT) { free(buf); return -1; }
            cap *= 2;
            buf = hook_realloc(buf, cap);
        }
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return -1;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 0;
}

/* ------------------------------------------------------------- refusals --- */

static void write_reason_stderr(const char *reason) {
    fprintf(stderr, "lamassu-hook: REFUSE %s\n", reason);
}

/* The event could not be determined (unparseable stdin, missing event name).
 * No JSON shape is known to be valid, so exit 2 - the one outcome JSON cannot
 * override and the only exit code that blocks on every blockable event. The
 * block object is still printed so a harness that ignores exit codes cannot
 * misread silence as an allow. */
static void refuse_indeterminate(const char *reason) {
    char esc[1024];
    json_escape(reason, esc, sizeof esc);
    printf("{\"decision\":\"block\",\"reason\":\"%s\"}\n", esc);
    fflush(stdout);
    write_reason_stderr(reason);
    exit(2);
}

/* The event IS known but we are refusing. Emit the shape that event validates:
 * top-level decision:block, or hookSpecificOutput.permissionDecision:deny. */
static void emit_block(const char *reason) {
    char esc[1024];
    json_escape(reason, esc, sizeof esc);
    printf("{\"decision\":\"block\",\"reason\":\"%s\"}\n", esc);
    fflush(stdout);
}

static void emit_deny(const char *reason) {
    char esc[1024];
    json_escape(reason, esc, sizeof esc);
    printf("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
           "\"permissionDecision\":\"deny\","
           "\"permissionDecisionReason\":\"%s\"}}\n", esc);
    fflush(stdout);
}

/* An internal failure on a known event. Refuse in that event's shape. */
static int fail_closed(const char *event, const char *detail) {
    char reason[512];
    snprintf(reason, sizeof reason, "lamassu: fail-closed (%s) - refusing: %.200s",
             event, detail ? detail : "internal error");
    if (strcmp(event, "PreToolUse") == 0) emit_deny(reason);
    else emit_block(reason);
    write_reason_stderr(reason);
    return 0;
}

/* --------------------------------------------------------------- reasons -- */

/* Pick the finding that decides the verdict: invariant first (decide() refuses
 * on any invariant), then the highest severity. */
static const finding_t *deciding_finding(const findings_t *f) {
    const finding_t *best = NULL;
    for (size_t i = 0; i < f->len; i++) {
        const finding_t *c = &f->items[i];
        if (!best) { best = c; continue; }
        if (c->invariant != best->invariant) { if (c->invariant) best = c; continue; }
        if (c->severity > best->severity) best = c;
    }
    return best;
}

/* Reason text is layer/rule plus the evidence DIGEST. Never the matched text:
 * a reason reaches the user, the transcript, and Claude itself. */
static void build_reason(const findings_t *f, const char *prefix,
                         char *out, size_t cap) {
    const finding_t *b = deciding_finding(f);
    if (!b) { snprintf(out, cap, "%s: refused", prefix); return; }
    if (b->evidence_digest[0])
        snprintf(out, cap, "%s: %s/%s evidence=%s", prefix, b->layer, b->rule,
                 b->evidence_digest);
    else
        snprintf(out, cap, "%s: %s/%s", prefix, b->layer, b->rule);
}

/* --------------------------------------------------------- session state -- */
/* One small key=value file per session id. No JSON: it is operator-invisible
 * state, not a wire format, and a plain parser cannot fail into a half-load. */

typedef struct {
    char     sid[128];
    char     nonce[64];
    char     origin_channel[32];
    char     origin_ref[64];
    unsigned long root_pid;
    int      tainted;
} hook_state_t;

/* mkdir -p for the state directory: $LAMASSU_STATE may not exist yet, and a
 * missing parent must not silently disable persistence (that would drop taint). */
static int mkdir_p(const char *path) {
    char buf[1024];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof buf) return -1;
    memcpy(buf, path, n + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int state_dir(char *out, size_t cap) {
    /* $LAMASSU_STATE is the state DIRECTORY; default $TMPDIR/lamassu. */
    const char *base = getenv("LAMASSU_STATE");
    int w;
    if (base && *base) {
        w = snprintf(out, cap, "%s", base);
    } else {
        const char *tmp = getenv("TMPDIR");
        if (!tmp || !*tmp) tmp = "/tmp";
        w = snprintf(out, cap, "%s/lamassu", tmp);
    }
    if (w < 0 || (size_t)w >= cap) return -1;
    return mkdir_p(out);
}

/* Session ids are opaque and may contain a path separator. Keep only characters
 * that cannot escape the state directory. */
static void sanitize_sid(const char *sid, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)(sid ? sid : ""); *p && o + 1 < cap; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == '@')
            out[o++] = (char)*p;
        else
            out[o++] = '_';
    }
    if (o == 0) { snprintf(out, cap, "%s", "nosession"); return; }
    out[o] = '\0';
}

static int state_path(const char *sid, char *out, size_t cap) {
    char dir[512], safe[160], w[192];
    if (state_dir(dir, sizeof dir) != 0) return -1;
    sanitize_sid(sid, safe, sizeof safe);
    int n = snprintf(w, sizeof w, "%s.state", safe);
    if (n < 0 || (size_t)n >= sizeof w) return -1;
    n = snprintf(out, cap, "%s/%s", dir, w);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/* 0 = loaded, 1 = absent (fresh session), -1 = error. ENOENT is "absent"; any
 * other failure is an error and the caller refuses rather than guessing. */
static int state_load(const char *sid, hook_state_t *st) {
    char path[1024];
    if (state_path(sid, path, sizeof path) != 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 1 : -1;

    memset(st, 0, sizeof *st);
    snprintf(st->sid, sizeof st->sid, "%s", sid);
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (strcmp(k, "nonce") == 0) snprintf(st->nonce, sizeof st->nonce, "%s", v);
        else if (strcmp(k, "origin_channel") == 0) snprintf(st->origin_channel, sizeof st->origin_channel, "%s", v);
        else if (strcmp(k, "origin_ref") == 0) snprintf(st->origin_ref, sizeof st->origin_ref, "%s", v);
        else if (strcmp(k, "tainted") == 0) st->tainted = atoi(v) ? 1 : 0;
        else if (strcmp(k, "root_pid") == 0) st->root_pid = strtoul(v, NULL, 10);
    }
    fclose(f);
    return 0;
}

/* Written to a temporary file and renamed, so a crash mid-write cannot leave a
 * truncated state that the next invocation would read as "untainted". */
static int state_save(const hook_state_t *st) {
    char path[1024];
    if (state_path(st->sid, path, sizeof path) != 0) return -1;
    char tmp[1088];
    snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid());

    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, "sid=%s\n", st->sid);
    fprintf(f, "nonce=%s\n", st->nonce);
    fprintf(f, "root_pid=%lu\n", st->root_pid);
    fprintf(f, "tainted=%d\n", st->tainted);
    fprintf(f, "origin_channel=%s\n", st->origin_channel);
    fprintf(f, "origin_ref=%s\n", st->origin_ref);
    if (fclose(f) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int nonce_valid(const char *n) {
    if (!n || strlen(n) != WD_NONCE_BYTES * 2) return 0;
    for (const char *p = n; *p; p++)
        if (!isxdigit((unsigned char)*p)) return 0;
    return 1;
}

/* ------------------------------------------------------------- policy ---- */

/* Canary/allowlist are operator configuration, not attacker input. An
 * unusable canary is refused loudly (PIP config.CANARY_REJECTED): egress that
 * protects nothing must not report success. */
static char **split_env_list(const char *v, size_t *n_out) {
    *n_out = 0;
    if (!v || !*v) return NULL;
    size_t cap = 4, n = 0;
    char **arr = xcalloc(cap, sizeof *arr);
    const char *p = v;
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
        size_t len = (size_t)(p - start);
        char *item = xcalloc(len + 1, 1);
        memcpy(item, start, len);
        if (n == cap) { cap *= 2; arr = hook_realloc(arr, cap * sizeof *arr); }
        arr[n++] = item;
    }
    *n_out = n;
    return arr;
}

static void build_policy(policy_t *p) {
    policy_default(p);

    size_t n = 0;
    char **can = split_env_list(getenv("LAMASSU_CANARY"), &n);
    if (n) policy_set_vec(&p->canaries, &p->canary_len, (const char *const *)can, n);
    for (size_t i = 0; i < n; i++) free(can[i]);
    free(can);

    size_t hn = 0;
    char **hosts = split_env_list(getenv("LAMASSU_ALLOWED_HOSTS"), &hn);
    if (hn) policy_set_vec(&p->allowed_hosts, &p->host_len, (const char *const *)hosts, hn);
    for (size_t i = 0; i < hn; i++) free(hosts[i]);
    free(hosts);
}

/* ------------------------------------------------- tool capability table -- */
/* Which requested actions are guarded by NO_UNTRUSTED_INFLUENCE, i.e. refused
 * once the session has ingested untrusted content. The hook payload carries a
 * tool NAME but not the harness's tool registry, so this table is a name-based
 * capability classifier over the egress/effect classes PIP models in tools.py.
 * A tool the table does not know is passed through unguarded - the adapter
 * cannot block a tool it has never heard of, and pretending otherwise would
 * deny every tool call in the harness. Shell/network exfiltration that does not
 * go through a named tool is the sensor's job (observe at the syscall boundary;
 * this adapter enforces at the model boundary). */

/* --------------------------------------------------------------- helpers -- */

/* Flatten a JSON value that may be a string or an object/array. */
static void flatten_to(const jval_t *v, char *out, size_t cap) {
    if (!v) { out[0] = '\0'; return; }
    if (v->t == JSTR) { snprintf(out, cap, "%s", v->str ? v->str : ""); return; }
    flatten_json_arg(v, out, cap);
}

/* ============================================================ event: start */

static int ev_session_start(const jval_t *root, hook_state_t *st) {
    (void)root;
    /* The payload carries no pid. The hook process is spawned by the harness, so
     * the parent pid is the session's root process - the anchor the sensor uses
     * to attribute syscalls to this session by process-tree descent. */
    st->root_pid = (unsigned long)getppid();
    st->tainted = 0;
    st->origin_channel[0] = st->origin_ref[0] = '\0';
    if (state_save(st) != 0) return fail_closed("SessionStart", "cannot persist session state");
    return 0;
}

/* ======================================================= event: user prompt */

static int ev_user_prompt(const jval_t *root, hook_state_t *st, session_t *s,
                          firewall_t *fw) {
    const char *prompt = json_str(root, "prompt", NULL);
    if (!prompt) return fail_closed("UserPromptSubmit", "no prompt field");

    /* The event NAME is the provenance: UserPromptSubmit carries text the human
     * at the keyboard authored, so it is a USER span, not data. */
    session_span_add(s, TRUST_USER, prompt, NULL, "user");

    findings_t f; findings_init(&f);
    decision_t d = firewall_inspect(fw, s, &f);
    if (d == DEC_BLOCK) {
        char reason[512];
        build_reason(&f, "lamassu", reason, sizeof reason);
        findings_free(&f);
        emit_block(reason);
        write_reason_stderr(reason);
        return 0;
    }
    findings_free(&f);
    if (state_save(st) != 0) return fail_closed("UserPromptSubmit", "cannot persist session state");
    return 0;   /* ALLOW: stdout MUST stay empty - anything can be read as control */
}

/* ======================================================== event: post tool */

static int ev_post_tool(const jval_t *root, hook_state_t *st, session_t *s,
                        firewall_t *fw) {
    const char *tool = json_str(root, "tool_name", NULL);
    if (!tool) return fail_closed("PostToolUse", "no tool_name field");

    const jval_t *resp = json_get(root, "tool_response");
    const jval_t *ti   = json_get(root, "tool_input");

    origin_t o;
    memset(&o, 0, sizeof o);
    snprintf(o.channel, sizeof o.channel, "%s", "tool");
    snprintf(o.ref, sizeof o.ref, "%s", tool);

    if (resp) {
        char *flat = xcalloc(HOOK_FLAT_CAP, 1);
        flatten_to(resp, flat, HOOK_FLAT_CAP);
        session_span_add(s, TRUST_DATA, flat, &o, "tool");
        free(flat);
    }
    if (ti) {
        char *flat = xcalloc(HOOK_FLAT_CAP, 1);
        flatten_to(ti, flat, HOOK_FLAT_CAP);
        session_span_add(s, TRUST_DATA, flat, &o, "tool");
        free(flat);
    }

    /* The tool has already run: whatever it returned is in the transcript now.
     * Record the taint regardless of the verdict, and do it before the verdict
     * so a crash cannot leave the session falsely clean. */
    st->tainted = 1;
    snprintf(st->origin_channel, sizeof st->origin_channel, "%s", "tool");
    snprintf(st->origin_ref, sizeof st->origin_ref, "%s", tool);
    if (state_save(st) != 0) return fail_closed("PostToolUse", "cannot persist session state");

    findings_t f; findings_init(&f);
    decision_t d = firewall_inspect(fw, s, &f);
    if (d == DEC_BLOCK) {
        char reason[512];
        build_reason(&f, "lamassu", reason, sizeof reason);
        findings_free(&f);
        emit_block(reason);
        write_reason_stderr(reason);
        return 0;
    }
    findings_free(&f);
    return 0;
}

/* ========================================================= event: pre tool */

static int ev_pre_tool(const jval_t *root, hook_state_t *st, session_t *s,
                       firewall_t *fw) {
    const char *tool = json_str(root, "tool_name", NULL);
    if (!tool) return fail_closed("PreToolUse", "no tool_name field");

    /* tool_input is a REQUESTED ACTION, not a span: it is what the model wants
     * to do, never a statement of fact. It is inspected by egress (a secret in
     * an outbound argument has flattened leaves) and authorised by toolauth. */
    const jval_t *ti = json_get(root, "tool_input");
    size_t an = (ti && ti->t == JOBJ) ? ti->len : 0;
    char **akeys = xcalloc(an ? an : 1, sizeof *akeys);
    char **avals = xcalloc(an ? an : 1, sizeof *avals);
    for (size_t i = 0; i < an; i++) {
        akeys[i] = xstrdup(ti->keys[i]);
        char *flat = xcalloc(HOOK_FLAT_CAP, 1);
        flatten_json_arg(ti->items[i], flat, HOOK_FLAT_CAP);
        avals[i] = flat;
    }

    tool_call_t tc;
    memset(&tc, 0, sizeof tc);
    snprintf(tc.name, sizeof tc.name, "%s", tool);
    /* We cannot see the harness's registry, so we do not claim a tool is
     * unknown (that would deny every call). We do claim its observed args and
     * accept exactly those, so an argument the tool was never called with
     * cannot be smuggled in. */
    tc.known        = 1;
    tc.arg_keys     = akeys;
    tc.arg_vals     = avals;
    tc.arg_len      = an;
    tc.permitted    = akeys;
    tc.permitted_len = an;
    int guarded = lamassu_tool_is_egress(tool);
    char *guards[1];
    if (guarded) { guards[0] = (char *)"NO_UNTRUSTED_INFLUENCE"; tc.guards = guards; tc.guard_len = 1; }

    findings_t f; findings_init(&f);
    decision_t d = firewall_inspect_egress(fw, s, &tc, 1, NULL, &f);
    if (d == DEC_BLOCK) {
        char reason[512];
        build_reason(&f, "lamassu", reason, sizeof reason);
        findings_free(&f);
        for (size_t i = 0; i < an; i++) { free(akeys[i]); free(avals[i]); }
        free(akeys); free(avals);
        emit_deny(reason);
        write_reason_stderr(reason);
        return 0;
    }
    findings_free(&f);
    for (size_t i = 0; i < an; i++) { free(akeys[i]); free(avals[i]); }
    free(akeys); free(avals);
    /* Persist the freshly minted nonce so the fence stays stable across the
     * session's hook invocations. */
    if (state_save(st) != 0) return fail_closed("PreToolUse", "cannot persist session state");
    return 0;   /* ALLOW: silent, the normal permission flow applies */
}

/* =================================================================== main */

int main(void) {
    char *input = NULL;
    size_t len = 0;
    if (read_all_stdin(&input, &len) != 0 || len == 0) {
        free(input);
        refuse_indeterminate("lamassu-hook: unreadable or empty hook input; refusing (fail closed)");
    }

    char err[256];
    jval_t *root = json_parse(input, err, sizeof err);
    if (!root || root->t != JOBJ) {
        /* Malformed JSON is a NON-BLOCKING error for Claude Code, so emitting
         * nothing here would let the action through. Exit 2 blocks instead. */
        json_free(root);
        free(input);
        refuse_indeterminate("lamassu-hook: unparseable hook input; refusing (fail closed)");
    }

    const char *event = json_str(root, "hook_event_name", NULL);
    const char *sid   = json_str(root, "session_id", NULL);
    if (!event || (!*event)) {
        json_free(root); free(input);
        refuse_indeterminate("lamassu-hook: hook_event_name missing; refusing (fail closed)");
    }
    if (!sid || !*sid) {
        if (strcmp(event, "PreToolUse") == 0 || strcmp(event, "PostToolUse") == 0 ||
            strcmp(event, "UserPromptSubmit") == 0 || strcmp(event, "SessionStart") == 0) {
            int rc = fail_closed(event, "session_id missing");
            json_free(root); free(input);
            return rc;
        }
        json_free(root); free(input);
        refuse_indeterminate("lamassu-hook: session_id missing; refusing (fail closed)");
    }

    int known = strcmp(event, "SessionStart") == 0 ||
                strcmp(event, "UserPromptSubmit") == 0 ||
                strcmp(event, "PostToolUse") == 0 ||
                strcmp(event, "PreToolUse") == 0;
    if (!known) {
        /* The hook is wired only to the four events in settings.example.json.
         * Any other event means the configuration is not the one we audited. */
        char reason[256];
        snprintf(reason, sizeof reason,
                 "lamassu-hook: unhandled event '%.120s'; refusing (fail closed)", event);
        json_free(root); free(input);
        refuse_indeterminate(reason);
    }

    /* ---- restore the session across this process boundary ---- */
    hook_state_t st;
    int loaded = state_load(sid, &st);
    if (loaded < 0) {
        int rc = fail_closed(event, "cannot read session state");
        json_free(root); free(input);
        return rc;
    }
    if (loaded == 1) {
        memset(&st, 0, sizeof st);
        snprintf(st.sid, sizeof st.sid, "%s", sid);
    }
    if (!nonce_valid(st.nonce)) {
        /* Mint now; session_nonce() below writes the same value into the
         * in-process session and state_save persists it. */
        st.nonce[0] = '\0';
    }

    policy_t policy;
    build_policy(&policy);
    char cerr[256];
    if (policy_validate_canaries(&policy, cerr, sizeof cerr) != 0) {
        /* egress would protect nothing while reporting success - refuse. */
        char reason[512];
        snprintf(reason, sizeof reason, "lamassu: fail-closed - %.220s", cerr);
        write_reason_stderr(reason);
        if (strcmp(event, "PreToolUse") == 0) emit_deny(reason); else emit_block(reason);
        policy_free(&policy);
        json_free(root); free(input);
        return 0;
    }
    firewall_t fw;
    firewall_init(&fw, &policy);

    session_reset();
    session_t *s = session_open(sid, "claude-code", (uint32_t)st.root_pid);
    if (!s) {
        int rc = fail_closed(event, "cannot open session");
        policy_free(&policy); json_free(root); free(input);
        return rc;
    }

    if (!nonce_valid(st.nonce)) {
        /* session_nonce() lazily mints a CSPRNG nonce; persist it so the fence
         * is stable for the whole session. */
        snprintf(st.nonce, sizeof st.nonce, "%s", session_nonce(s));
    } else {
        snprintf(s->nonce, sizeof s->nonce, "%s", st.nonce);
    }

    /* Taint is restored by ADDING a DATA span (no setter exists), so
     * session_tainted() derives it exactly as it would in one long-lived
     * process. The placeholder is inert: it is not attacker text and matches no
     * rule, so restoring taint cannot itself create a finding. */
    if (st.tainted) {
        origin_t o;
        memset(&o, 0, sizeof o);
        snprintf(o.channel, sizeof o.channel, "%s",
                 st.origin_channel[0] ? st.origin_channel : "tool");
        snprintf(o.ref, sizeof o.ref, "%s",
                 st.origin_ref[0] ? st.origin_ref : "unknown");
        session_span_add(s, TRUST_DATA, "[lamassu] session tainted by prior data span",
                         &o, "tool");
    }

    int rc = 0;
    if (strcmp(event, "SessionStart") == 0)
        rc = ev_session_start(root, &st);
    else if (strcmp(event, "UserPromptSubmit") == 0)
        rc = ev_user_prompt(root, &st, s, &fw);
    else if (strcmp(event, "PostToolUse") == 0)
        rc = ev_post_tool(root, &st, s, &fw);
    else
        rc = ev_pre_tool(root, &st, s, &fw);

    session_reset();
    policy_free(&policy);
    json_free(root);
    free(input);
    return rc;
}
