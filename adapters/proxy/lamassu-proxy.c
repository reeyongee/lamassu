/* lamassu-proxy.c — localhost OpenAI-compatible proxy: inferred provenance at
 * the model boundary.
 *
 * Lineage:
 *   the guard layer/src/not_sandboxed/proxy/app.py   (build_app,
 *       completions, _completion, _verdict_payload, /healthz, the startup
 *       weak-mode warning, the inbound-then-outbound inspection order)
 *   the guard layer/src/not_sandboxed/proxy/infer.py (ChatMessage,
 *       flatten, _ref, infer_context - the role -> Trust guess)
 *   the guard layer/src/not_sandboxed/config.py      (PROXY_* constants,
 *       PROXY_WEAK_MODE_WARNING, CLI_DEFAULT_HOST, CLI_PROXY_PORT)
 *   the guard layer/src/not_sandboxed/firewall.py    (inspect,
 *       inspect_egress)
 *
 * WHY THIS PATH IS WEAKER, IN THE UPSTREAM'S OWN WORDS (config.py:114):
 *   "not-sandboxed proxy: provenance is INFERRED from message roles.
 *    Retrieved content pasted into a user message is NOT seen as
 *    untrusted, which is what most RAG applications do. The library
 *    API is the only mode where provenance is declared and correct."
 * The string is reproduced VERBATIM. It is the honest statement of the
 * limitation: the proxy can only see {role, content} pairs, and a RAG app that
 * pastes a retrieved document into a `user` message hands the proxy text that
 * looks user-authored. Ingress is scoped to DATA spans, so it never fires on
 * that text. Every finding the proxy produces is stamped `provenance: inferred`
 * so a consumer cannot mistake this judgement for a declared one.
 *
 * Transport: one request per connection, HTTP/1.1, Connection: close. Raw
 * sockets, libc only. Inbound messages are inspected BEFORE the upstream is
 * contacted; the upstream reply is inspected BEFORE it is returned.
 *
 * A blocked request is HTTP 200 with an OpenAI-shaped body and
 * finish_reason "content_filter": a drop-in client parses it, shows the refusal,
 * and does not crash. Refusals are never an open stream or a 4xx surprise. */
#include "lamassu.h"
#include "toolguard.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* --------------------------------------------------------- upstream text -- */

/* PIP config.py:114 PROXY_WEAK_MODE_WARNING, verbatim. */
static const char WEAK_MODE_WARNING[] =
    "not-sandboxed proxy: provenance is INFERRED from message roles. "
    "Retrieved content pasted into a user message is NOT seen as "
    "untrusted, which is what most RAG applications do. The library "
    "API is the only mode where provenance is declared and correct.";

/* PIP config.py:121-126, renamed to this product. */
static const char BLOCK_MESSAGE[] = "This request was refused by lamassu.";
static const char MODEL_NAME[]    = "lamassu/guarded";
static const char OBJECT_NAME[]   = "chat.completion";
static const char FINISH_BLOCKED[] = "content_filter";
static const char FINISH_OK[]      = "stop";
static const char TOOL_CHANNEL[]   = "tool";
static const char UNKNOWN_TOOL_REF[] = "unnamed";

#define MAX_HTTP_BYTES (8u * 1024u * 1024u)
#define MAX_FLAT_BYTES 65536

/* ------------------------------------------------------------- buffers ---- */

typedef struct { char *p; size_t len, cap; } buf_t;

static void buf_init(buf_t *b, size_t cap) {
    b->cap = cap ? cap : 256;
    b->p = xcalloc(b->cap, 1);
    b->len = 0;
}

static void buf_free(buf_t *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

static void buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    while (b->len + extra + 1 > b->cap) b->cap *= 2;
    char *q = realloc(b->p, b->cap);
    if (!q) { fputs("lamassu-proxy: out of memory\n", stderr); exit(1); }
    b->p = q;
}

static void buf_add(buf_t *b, const char *data, size_t n) {
    buf_reserve(b, n);
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void buf_addz(buf_t *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_printf(buf_t *b, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof tmp) { buf_add(b, tmp, (size_t)n); return; }
    char *big = xcalloc((size_t)n + 1, 1);
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    buf_add(b, big, (size_t)n);
    free(big);
}

/* -------------------------------------------------- provenance: inferred -- */

/* The layers push PROV_DECLARED. On this path every finding is upgraded to
 * PROV_INFERRED so no consumer can read a guessed judgement as a declared one
 * (CONTRACTS.md §2: "provenance is declared on the socket path and inferred on
 * the proxy path"). */
static void stamp_inferred(findings_t *f) {
    for (size_t i = 0; i < f->len; i++) f->items[i].provenance = PROV_INFERRED;
}

/* ------------------------------------------------------------- sockets ---- */

static int send_all(int fd, const char *data, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, data + off, n - off, 0);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_all_fd(int fd, buf_t *out) {
    char tmp[16384];
    for (;;) {
        ssize_t n = recv(fd, tmp, sizeof tmp, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;
        if (out->len + (size_t)n > MAX_HTTP_BYTES) return -1;
        buf_add(out, tmp, (size_t)n);
    }
    return 0;
}

/* Read one HTTP request without waiting for the client to close: stop as soon
 * as the header block is complete, then read exactly Content-Length bytes of
 * body. A keep-alive client never half-closes, so reading to EOF would
 * deadlock (the client waits for the response we have not sent yet). */
static const char *find_header_end(const char *s, size_t n);

static size_t header_content_length(const char *h, size_t hlen) {
    const char *line = memchr(h, '\n', hlen);
    if (!line) return 0;
    line++;
    const char *end = h + hlen;
    while (line < end) {
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        if (!nl) break;
        if ((size_t)(nl - line) > 15 &&
            strncasecmp(line, "content-length:", 15) == 0) {
            return (size_t)strtoul(line + 15, NULL, 10);
        }
        line = nl + 1;
    }
    return 0;
}

static int read_request(int fd, buf_t *out) {
    char tmp[16384];
    size_t body_start = 0, body_need = 0;
    for (;;) {
        if (body_start) {
            if (out->len - body_start >= body_need) return 0;
        } else {
            const char *he = find_header_end(out->p, out->len);
            if (he) {
                size_t hlen = (size_t)(he - out->p) + 4;
                if (hlen > MAX_HTTP_BYTES) return -1;
                body_start = hlen;
                body_need = header_content_length(out->p, hlen);
                if (body_need > MAX_HTTP_BYTES) return -1;
                continue;   /* re-check with body accounting */
            }
        }
        ssize_t n = recv(fd, tmp, sizeof tmp, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return out->len > 0 ? 0 : -1;
        if (out->len + (size_t)n > MAX_HTTP_BYTES) return -1;
        buf_add(out, tmp, (size_t)n);
    }
}

/* HTTP request: request line + headers + optional body. */
typedef struct { char method[16]; char path[512]; buf_t body; } req_t;

static const char *find_header_end(const char *s, size_t n) {
    for (size_t i = 0; i + 3 < n; i++)
        if (s[i] == '\r' && s[i+1] == '\n' && s[i+2] == '\r' && s[i+3] == '\n')
            return s + i;
    return NULL;
}

static int parse_request(buf_t *raw, req_t *r) {
    memset(r, 0, sizeof *r);
    buf_init(&r->body, 256);

    const char *hend = find_header_end(raw->p, raw->len);
    if (!hend) return -1;
    size_t hlen = (size_t)(hend - raw->p) + 4;

    /* request line */
    const char *sp1 = memchr(raw->p, ' ', hlen);
    if (!sp1) return -1;
    size_t mlen = (size_t)(sp1 - raw->p);
    if (mlen == 0 || mlen >= sizeof r->method) return -1;
    memcpy(r->method, raw->p, mlen);
    r->method[mlen] = '\0';
    const char *p = sp1 + 1;
    const char *sp2 = memchr(p, ' ', hlen - (size_t)(p - raw->p));
    if (!sp2) return -1;
    size_t plen = (size_t)(sp2 - p);
    if (plen >= sizeof r->path) return -1;
    memcpy(r->path, p, plen);
    r->path[plen] = '\0';

    /* Content-Length, case-insensitive over the header block */
    long clen = -1;
    const char *line = memchr(raw->p, '\n', hlen) + 1;
    const char *hdr_end = raw->p + hlen;
    while (line < hdr_end) {
        const char *nl = memchr(line, '\n', (size_t)(hdr_end - line));
        if (!nl) break;
        if ((size_t)(nl - line) > 15 &&
            strncasecmp(line, "content-length:", 15) == 0) {
            clen = strtol(line + 15, NULL, 10);
        }
        line = nl + 1;
    }
    if (clen < 0) clen = 0;
    if ((size_t)clen > MAX_HTTP_BYTES) return -1;
    if (raw->len < hlen + (size_t)clen) return -1;

    buf_add(&r->body, raw->p + hlen, (size_t)clen);
    return 0;
}

/* ------------------------------------------------------------- helpers ---- */

static void rand_hex(char *out, size_t bytes) {
    unsigned char raw[32];
    if (bytes > sizeof raw / 2) bytes = sizeof raw / 2;
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = f ? fread(raw, 1, bytes, f) : 0;
    if (f) fclose(f);
    if (got != bytes) {
        unsigned long long seed = (unsigned long long)time(NULL) ^ (unsigned long long)getpid();
        for (size_t i = 0; i < bytes; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            raw[i] = (unsigned char)(seed >> 33);
        }
    }
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes; i++) {
        out[i*2]   = hx[raw[i] >> 4];
        out[i*2+1] = hx[raw[i] & 0xf];
    }
    out[bytes*2] = '\0';
}

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
        if (n == cap) { cap *= 2; char **q = realloc(arr, cap * sizeof *arr);
            if (!q) { fputs("lamassu-proxy: oom\n", stderr); exit(1); } arr = q; }
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

/* Is a named tool egress-capable, i.e. guarded by NO_UNTRUSTED_INFLUENCE once
 * the context is tainted? Mirrors the hook adapter's capability classifier and
 * PIP's tools.py Effect/GUARD modelling. */

/* ---------------------------------------------------- infer_context (PIP) -- */

/* Flatten an OpenAI content field: a string, or a list of parts of which the
 * "text" parts are the language a model reads (infer.py flatten). */
static void flatten_content(const jval_t *content, buf_t *out) {
    if (!content) return;
    if (content->t == JSTR) { buf_addz(out, content->str ? content->str : ""); return; }
    if (content->t == JARR) {
        for (size_t i = 0; i < content->len; i++) {
            const jval_t *part = content->items[i];
            if (!part || part->t != JOBJ) continue;
            const char *type = json_str(part, "type", "");
            if (strcmp(type, "text") != 0) continue;
            const char *text = json_str(part, "text", NULL);
            if (!text) continue;
            if (out->len) buf_addz(out, "\n");
            buf_addz(out, text);
        }
    }
}

/* Any role outside the two known sets is DATA, so an unrecognised role fails
 * closed rather than being promoted (infer.py infer_context, verbatim rule). */
static void infer_context(const jval_t *messages, session_t *s, findings_t *f) {
    if (!messages || messages->t != JARR) return;
    for (size_t i = 0; i < messages->len; i++) {
        const jval_t *m = messages->items[i];
        if (!m || m->t != JOBJ) continue;
        const char *role = json_str(m, "role", "");
        buf_t text; buf_init(&text, 256);
        flatten_content(json_get(m, "content"), &text);

        if (strcmp(role, "system") == 0 || strcmp(role, "developer") == 0) {
            session_span_add(s, TRUST_SYSTEM, text.p, NULL, "system");
        } else if (strcmp(role, "user") == 0 || strcmp(role, "assistant") == 0) {
            session_span_add(s, TRUST_USER, text.p, NULL, role);
        } else {
            /* tool / function / anything unknown */
            const char *ref = json_str(m, "tool_call_id", NULL);
            if (!ref) ref = json_str(m, "name", NULL);
            origin_t o;
            memset(&o, 0, sizeof o);
            snprintf(o.channel, sizeof o.channel, "%s", TOOL_CHANNEL);
            snprintf(o.ref, sizeof o.ref, "%s", ref ? ref : UNKNOWN_TOOL_REF);
            session_span_add(s, TRUST_DATA, text.p, &o, role);
        }
        buf_free(&text);
    }
    (void)f;
}

/* ---------------------------------------------------- reply → tool calls -- */

static size_t build_tool_calls(const jval_t *message, tool_call_t **out,
                               char ***name_store) {
    *out = NULL;
    *name_store = NULL;
    const jval_t *tcs = message ? json_get(message, "tool_calls") : NULL;
    if (!tcs || tcs->t != JARR || tcs->len == 0) return 0;

    size_t n = tcs->len;
    tool_call_t *arr = xcalloc(n, sizeof *arr);
    char **names = xcalloc(n, 1 ? n : 1); (void)names;
    *name_store = names;
    for (size_t i = 0; i < n; i++) {
        const jval_t *tc = tcs->items[i];
        const jval_t *fn = tc && tc->t == JOBJ ? json_get(tc, "function") : NULL;
        const char *name = fn && fn->t == JOBJ ? json_str(fn, "name", NULL) : NULL;
        const char *args = fn && fn->t == JOBJ ? json_str(fn, "arguments", NULL) : NULL;

        tool_call_t *t = &arr[i];
        memset(t, 0, sizeof *t);
        snprintf(t->name, sizeof t->name, "%s", name ? name : UNKNOWN_TOOL_REF);
        t->known = 1;

        /* arguments is a JSON-encoded string; every leaf must be scanned */
        jval_t *av = NULL;
        if (args) {
            char err[128];
            av = json_parse(args, err, sizeof err);
        }
        size_t an = (av && av->t == JOBJ) ? av->len : 0;
        char **keys = xcalloc(an ? an : 1, sizeof *keys);
        char **vals = xcalloc(an ? an : 1, sizeof *vals);
        for (size_t k = 0; k < an; k++) {
            keys[k] = xstrdup(av->keys[k]);
            char *flat = xcalloc(MAX_FLAT_BYTES, 1);
            flatten_json_arg(av->items[k], flat, MAX_FLAT_BYTES);
            vals[k] = flat;
        }
        json_free(av);
        t->arg_keys = keys; t->arg_vals = vals; t->arg_len = an;
        t->permitted = keys; t->permitted_len = an;

        if (lamassu_tool_is_egress(t->name)) {
            char **g = xcalloc(1, sizeof *g);
            g[0] = xstrdup("NO_UNTRUSTED_INFLUENCE");
            t->guards = g; t->guard_len = 1;
        }
    }
    *out = arr;
    return n;
}

static void free_tool_calls(tool_call_t *tcs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        for (size_t k = 0; k < tcs[i].arg_len; k++) { free(tcs[i].arg_keys[k]); free(tcs[i].arg_vals[k]); }
        free(tcs[i].arg_keys); free(tcs[i].arg_vals);
        for (size_t g = 0; g < tcs[i].guard_len; g++) free(tcs[i].guards[g]);
        free(tcs[i].guards);
    }
    free(tcs);
}

/* ------------------------------------------------------------ responses --- */

static void verdict_payload(buf_t *out, const findings_t *f, const char *decision) {
    buf_addz(out, "{\"decision\":\"");
    buf_addz(out, decision);
    buf_addz(out, "\",\"policy_id\":\"default\",\"provenance\":\"inferred\",\"findings\":[");
    for (size_t i = 0; i < f->len; i++) {
        if (i) buf_addz(out, ",");
        buf_printf(out,
            "{\"layer\":\"%s\",\"rule\":\"%s\",\"severity\":\"%s\","
            "\"invariant\":%s,\"evidence_digest\":\"%s\"}",
            f->items[i].layer, f->items[i].rule,
            severity_name(f->items[i].severity),
            f->items[i].invariant ? "true" : "false",
            f->items[i].evidence_digest);
    }
    buf_addz(out, "]}");
}

/* OpenAI-shaped completion. finish_reason is the mechanism a drop-in client
 * already understands for a refused generation. */
static void completion_body(buf_t *out, const char *text, const char *finish,
                            const findings_t *f, const char *decision) {
    char id[32];
    char hex[25];
    rand_hex(hex, 12);
    snprintf(id, sizeof id, "chatcmpl-%s", hex);
    char esc[8192];
    json_escape(text, esc, sizeof esc);
    buf_printf(out,
        "{\"id\":\"%s\",\"object\":\"%s\",\"created\":%ld,\"model\":\"%s\","
        "\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"%s\"},"
        "\"finish_reason\":\"%s\",\"logprobs\":null}],"
        "\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0},"
        "\"lamassu\":",
        id, OBJECT_NAME, (long)time(NULL), MODEL_NAME, esc, finish);
    verdict_payload(out, f, decision);
    buf_addz(out, "}");
}

static void http_respond(int fd, int status, const char *status_text,
                         const char *ctype, const char *body, size_t blen) {
    buf_t h; buf_init(&h, 256);
    buf_printf(&h, "HTTP/1.1 %d %s\r\n", status, status_text);
    buf_printf(&h, "Content-Type: %s\r\n", ctype);
    buf_printf(&h, "Content-Length: %zu\r\n", blen);
    buf_addz(&h, "Connection: close\r\n\r\n");
    send_all(fd, h.p, h.len);
    if (body && blen) send_all(fd, body, blen);
    buf_free(&h);
}

static void http_json(int fd, int status, const char *status_text, const char *body) {
    http_respond(fd, status, status_text, "application/json", body, strlen(body));
}

/* ------------------------------------------------------------- upstream --- */

/* Split "http://host:port[/path]" into host, port, and path prefix. */
static int parse_upstream(const char *url, char *host, size_t hcap,
                          char *port, size_t pcap, char *prefix, size_t prcap) {
    if (!url || !*url) return -1;
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;
    const char *slash = strchr(p, '/');
    size_t hostlen = slash ? (size_t)(slash - p) : strlen(p);
    if (hostlen == 0 || hostlen >= hcap) return -1;
    memcpy(host, p, hostlen);
    host[hostlen] = '\0';

    char *colon = strrchr(host, ':');
    if (colon) { snprintf(port, pcap, "%s", colon + 1); *colon = '\0'; }
    else        { snprintf(port, pcap, "%s", "80"); }
    if (!host[0]) return -1;

    if (slash) snprintf(prefix, prcap, "%s", slash);
    else       prefix[0] = '\0';
    /* strip a trailing slash on the prefix */
    size_t pl = strlen(prefix);
    while (pl > 0 && prefix[pl-1] == '/') prefix[--pl] = '\0';
    return 0;
}

/* Dechunk a Transfer-Encoding: chunked body. Returns 0 on success. */
static int dechunk(const char *in, size_t n, buf_t *out) {
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && in[j] != '\n') j++;
        if (j >= n) break;
        long len = strtol(in + i, NULL, 16);
        if (len <= 0) break;
        size_t start = j + 1;
        if (start + (size_t)len > n) return -1;
        buf_add(out, in + start, (size_t)len);
        i = start + (size_t)len;
        while (i < n && (in[i] == '\r' || in[i] == '\n')) i++;
    }
    return 0;
}

/* Forward the (already re-serialised) request body to the upstream and return
 * the reply body, dechunked if needed, plus the status. */
static int upstream_post(const char *upstream_url, const char *body, size_t blen,
                         buf_t *resp_body, int *status_out) {
    char host[256], port[16], prefix[256];
    if (parse_upstream(upstream_url, host, sizeof host, port, sizeof port,
                       prefix, sizeof prefix) != 0) return -1;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    buf_t req; buf_init(&req, 1024);
    buf_printf(&req, "POST %s/v1/chat/completions HTTP/1.1\r\n", prefix);
    buf_printf(&req, "Host: %s\r\n", host);
    buf_addz(&req, "Content-Type: application/json\r\n");
    buf_addz(&req, "Connection: close\r\n");
    buf_printf(&req, "Content-Length: %zu\r\n\r\n", blen);
    buf_add(&req, body, blen);
    int rc = send_all(fd, req.p, req.len);
    buf_free(&req);
    if (rc != 0) { close(fd); return -1; }

    buf_t raw; buf_init(&raw, 4096);
    if (read_all_fd(fd, &raw) != 0) { close(fd); buf_free(&raw); return -1; }
    close(fd);

    const char *hend = find_header_end(raw.p, raw.len);
    if (!hend) { buf_free(&raw); return -1; }
    size_t hlen = (size_t)(hend - raw.p) + 4;

    int status = 0;
    if (sscanf(raw.p, "HTTP/%*d.%*d %d", &status) != 1) { buf_free(&raw); return -1; }
    *status_out = status;

    /* chunked? */
    int chunked = 0;
    for (const char *l = raw.p; l < raw.p + hlen; ) {
        const char *nl = memchr(l, '\n', (size_t)(raw.p + hlen - l));
        if (!nl) break;
        if ((size_t)(nl - l) > 18 && strncasecmp(l, "transfer-encoding:", 18) == 0) {
            for (const char *q = l; q < nl; q++)
                if (strncasecmp(q, "chunked", 7) == 0) { chunked = 1; break; }
        }
        l = nl + 1;
    }

    const char *bstart = raw.p + hlen;
    size_t blen2 = raw.len - hlen;
    if (chunked) {
        if (dechunk(bstart, blen2, resp_body) != 0) { buf_free(&raw); return -1; }
    } else {
        buf_add(resp_body, bstart, blen2);
    }
    buf_free(&raw);
    return 0;
}

/* ---------------------------------------------------------- one request --- */

typedef struct {
    policy_t   policy;
    firewall_t fw;
    char       upstream[512];
    int        have_upstream;
} server_t;

static void handle_connection(server_t *sv, int fd) {
    buf_t raw; buf_init(&raw, 4096);
    if (read_request(fd, &raw) != 0) {
        buf_free(&raw);
        http_json(fd, 400, "Bad Request",
                  "{\"error\":{\"message\":\"request too large or unreadable\","
                  "\"type\":\"invalid_request_error\"}}");
        return;
    }

    req_t r;
    if (parse_request(&raw, &r) != 0) {
        buf_free(&raw);
        http_json(fd, 400, "Bad Request",
                  "{\"error\":{\"message\":\"malformed HTTP request\","
                  "\"type\":\"invalid_request_error\"}}");
        return;
    }
    buf_free(&raw);

    if (strcmp(r.method, "GET") == 0 && strcmp(r.path, "/healthz") == 0) {
        buf_t b; buf_init(&b, 256);
        buf_printf(&b, "{\"policy_id\":\"%s\",\"mode\":\"inferred-provenance\","
                       "\"upstream\":%s}", sv->policy.policy_id,
                   sv->have_upstream ? "true" : "false");
        http_json(fd, 200, "OK", b.p);
        buf_free(&b);
        buf_free(&r.body);
        return;
    }

    if (strcmp(r.method, "POST") != 0 ||
        (strcmp(r.path, "/v1/chat/completions") != 0 &&
         strcmp(r.path, "/chat/completions") != 0)) {
        http_json(fd, 404, "Not Found",
                  "{\"error\":{\"message\":\"only POST /v1/chat/completions is served\","
                  "\"type\":\"invalid_request_error\"}}");
        buf_free(&r.body);
        return;
    }

    char jerr[256];
    jval_t *reqj = json_parse(r.body.p, jerr, sizeof jerr);
    if (!reqj || reqj->t != JOBJ) {
        buf_free(&r.body);
        json_free(reqj);
        http_json(fd, 400, "Bad Request",
                  "{\"error\":{\"message\":\"request body is not a JSON object\","
                  "\"type\":\"invalid_request_error\"}}");
        return;
    }
    /* The upstream must receive the request as the client wrote it, so keep a
     * copy of the raw body intact before anything is inspected. */
    char *forward_body = xstrdup(r.body.p ? r.body.p : "{}");
    buf_free(&r.body);

    /* ---- inbound: inferred provenance from message roles ---- */
    session_reset();
    session_t *s = session_open("proxy", "proxy", 0);
    findings_t in; findings_init(&in);
    if (!s) {
        free(forward_body);
        json_free(reqj);
        http_json(fd, 500, "Internal Server Error",
                  "{\"error\":{\"message\":\"cannot open session\",\"type\":\"server_error\"}}");
        return;
    }
    infer_context(json_get(reqj, "messages"), s, &in);
    decision_t din = firewall_inspect(&sv->fw, s, &in);
    stamp_inferred(&in);

    if (din == DEC_BLOCK) {
        buf_t b; buf_init(&b, 1024);
        completion_body(&b, BLOCK_MESSAGE, FINISH_BLOCKED, &in, "block");
        http_respond(fd, 200, "OK", "application/json", b.p, b.len);
        buf_free(&b);
        findings_free(&in);
        session_reset();
        json_free(reqj);
        free(forward_body);
        return;
    }

    /* ---- forward to the real model endpoint ---- */
    if (!sv->have_upstream) {
        findings_free(&in);
        session_reset();
        json_free(reqj);
        free(forward_body);
        http_json(fd, 503, "Service Unavailable",
                  "{\"error\":{\"message\":\"no upstream model endpoint configured "
                  "(set LAMASSU_UPSTREAM); lamassu will not fabricate a model reply\","
                  "\"type\":\"server_error\"}}");
        return;
    }

    buf_t upbody; buf_init(&upbody, 4096);
    int status = 0;
    int urc = upstream_post(sv->upstream, forward_body, strlen(forward_body),
                            &upbody, &status);
    free(forward_body);
    if (urc != 0) {
        buf_free(&upbody);
        findings_free(&in);
        session_reset();
        json_free(reqj);
        http_json(fd, 502, "Bad Gateway",
                  "{\"error\":{\"message\":\"upstream unreachable\",\"type\":\"server_error\"}}");
        return;
    }
    if (status != 200) {
        /* Upstream refused: pass its body through unchanged with its status. */
        http_respond(fd, status, status == 502 ? "Bad Gateway" : "Upstream Error",
                     "application/json", upbody.p, upbody.len);
        buf_free(&upbody);
        findings_free(&in);
        session_reset();
        json_free(reqj);
        return;
    }

    /* ---- outbound: toolauth + egress over prose and flattened args ---- */
    jval_t *reply = json_parse(upbody.p, jerr, sizeof jerr);
    buf_free(&upbody);

    const char *reply_text = "";
    tool_call_t *tcs = NULL;
    size_t tcn = 0;
    char **name_store = NULL;
    if (reply && reply->t == JOBJ) {
        const jval_t *choices = json_get(reply, "choices");
        const jval_t *ch0 = (choices && choices->t == JARR && choices->len) ? choices->items[0] : NULL;
        const jval_t *msg = ch0 && ch0->t == JOBJ ? json_get(ch0, "message") : NULL;
        if (msg && msg->t == JOBJ) {
            const jval_t *content = json_get(msg, "content");
            if (content && content->t == JSTR && content->str) reply_text = content->str;
            tcn = build_tool_calls(msg, &tcs, &name_store);
        }
    } else {
        /* An upstream reply we cannot parse must not be handed to the client
         * unscanned: we cannot prove it is clean, so refuse rather than pass
         * bytes through an uninspected path (fail closed). */
        json_free(reply);
        findings_free(&in);
        session_reset();
        json_free(reqj);
        http_json(fd, 502, "Bad Gateway",
                  "{\"error\":{\"message\":\"upstream reply was not parseable JSON; "
                  "refusing to pass an uninspected reply\",\"type\":\"server_error\"}}");
        return;
    }

    findings_t out; findings_init(&out);
    decision_t dout = firewall_inspect_egress(&sv->fw, s, tcs, tcn, reply_text, &out);
    stamp_inferred(&out);

    if (dout == DEC_BLOCK) {
        buf_t b; buf_init(&b, 1024);
        completion_body(&b, BLOCK_MESSAGE, FINISH_BLOCKED, &out, "block");
        http_respond(fd, 200, "OK", "application/json", b.p, b.len);
        buf_free(&b);
    } else {
        buf_t b; buf_init(&b, 1024);
        completion_body(&b, reply_text, FINISH_OK, &out, "allow");
        http_respond(fd, 200, "OK", "application/json", b.p, b.len);
        buf_free(&b);
    }

    findings_free(&out);
    free_tool_calls(tcs, tcn);
    free(name_store);
    json_free(reply);
    findings_free(&in);
    session_reset();
    json_free(reqj);
}

/* ================================================================== main == */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    signal(SIGPIPE, SIG_IGN);

    long port = 39441;   /* PIP config.py:213 CLI_PROXY_PORT */
    const char *pstr = getenv("LAMASSU_PROXY_PORT");
    if (pstr && *pstr) {
        char *end = NULL;
        long v = strtol(pstr, &end, 10);
        if (end && *end == '\0' && v > 0 && v < 65536) port = v;
    }

    server_t sv;
    memset(&sv, 0, sizeof sv);
    build_policy(&sv.policy);
    firewall_init(&sv.fw, &sv.policy);

    char cerr[256];
    if (policy_validate_canaries(&sv.policy, cerr, sizeof cerr) != 0) {
        fprintf(stderr, "lamassu-proxy: refusing to start: %s\n", cerr);
        return 1;
    }

    const char *up = getenv("LAMASSU_UPSTREAM");
    if (up && *up) {
        snprintf(sv.upstream, sizeof sv.upstream, "%s", up);
        sv.have_upstream = 1;
    }

    /* The weak-mode warning is printed VERBATIM at startup, unconditionally:
     * a proxy that silently looks like the strong mode is the failure mode this
     * line exists to prevent. */
    fprintf(stderr, "%s\n", WEAK_MODE_WARNING);
    fprintf(stderr, "lamassu-proxy: binding 127.0.0.1:%ld (provenance=inferred)\n", port);
    if (!sv.have_upstream)
        fprintf(stderr, "lamassu-proxy: LAMASSU_UPSTREAM unset: inbound inspection only; "
                        "pass-through requests get 503, no reply is fabricated\n");

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* localhost only */

    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); return 1; }
    if (listen(lfd, 16) != 0) { perror("listen"); return 1; }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        handle_connection(&sv, cfd);
        close(cfd);
    }
    close(lfd);
    policy_free(&sv.policy);
    return 0;
}
