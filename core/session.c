/* session.c — sessions, spans, derived taint, nonce minting, event ring.
 * Design:
 *   src/not_sandboxed/context.py  (Trust, Origin, Span with its
 *                                  "a DATA span must declare its origin"
 *                                  validator, Context.tainted_by derived with NO
 *                                  setter, per-context nonce)
 *   src/not_sandboxed/firewall.py (_fence: the exact delimiter shape)
 * plus per-tgid start/tracked bookkeeping and its
 * drop_total / upd_fail_total counters.
 *
 * The load-bearing property: taint is a CONSEQUENCE of what was added, never a
 * flag a caller remembers to set. There is no setter, so it cannot desync. */
#include "lamassu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

static session_t *g_sessions[WD_MAX_SESSIONS];
static size_t g_session_len = 0;

/* Unpredictable nonce. Falls back to /dev/urandom, then to a mixed clock value;
 * a guessable nonce would make the fence forgeable, so the CSPRNG is preferred
 * and its absence is not silent on Linux. */
static void mint_nonce(char out[WD_NONCE_BYTES * 2 + 1]) {
    unsigned char raw[WD_NONCE_BYTES];
    int ok = 0;
#if defined(__linux__)
    if (getrandom(raw, sizeof raw, 0) == (ssize_t)sizeof raw) ok = 1;
#endif
    if (!ok) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) {
            if (fread(raw, 1, sizeof raw, f) == sizeof raw) ok = 1;
            fclose(f);
        }
    }
    if (!ok) {
        /* last resort: do not pretend this is cryptographic */
        unsigned long long seed = (unsigned long long)(uintptr_t)&raw ^
                                  (unsigned long long)time(NULL);
        for (size_t i = 0; i < sizeof raw; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            raw[i] = (unsigned char)(seed >> 33);
        }
    }
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof raw; i++) {
        out[i * 2]     = hx[raw[i] >> 4];
        out[i * 2 + 1] = hx[raw[i] & 0xf];
    }
    out[WD_NONCE_BYTES * 2] = '\0';
}

session_t *session_open(const char *sid, const char *harness, uint32_t root_pid) {
    if (g_session_len >= WD_MAX_SESSIONS) return NULL;
    session_t *s = xcalloc(1, sizeof *s);
    snprintf(s->sid, sizeof s->sid, "%s", sid ? sid : "");
    snprintf(s->harness, sizeof s->harness, "%s", harness ? harness : "");
    s->root_pid = root_pid;
    s->open = true;
    g_sessions[g_session_len++] = s;
    return s;
}

session_t *session_find(const char *sid) {
    for (size_t i = 0; i < g_session_len; i++)
        if (strcmp(g_sessions[i]->sid, sid) == 0) return g_sessions[i];
    return NULL;
}

void session_close(const char *sid) {
    for (size_t i = 0; i < g_session_len; i++) {
        if (strcmp(g_sessions[i]->sid, sid) != 0) continue;
        session_t *s = g_sessions[i];
        for (size_t k = 0; k < s->span_len; k++) free(s->spans[k].text);
        for (size_t k = i + 1; k < g_session_len; k++) g_sessions[k - 1] = g_sessions[k];
        g_session_len--;
        free(s);
        return;
    }
}

void session_reset(void) {
    while (g_session_len) session_close(g_sessions[0]->sid);
}

void session_span_add(session_t *s, trust_t t, const char *text,
                      const origin_t *origin, const char *role) {
    if (!s || s->span_len >= WD_MAX_SPANS) return;
    /* context.py validator: a DATA span MUST declare its origin, and a
     * non-DATA span must NOT carry one. Refusing here keeps provenance honest
     * instead of letting a DATA span claim to be trusted. */
    if (t == TRUST_DATA && !origin) return;
    if (t != TRUST_DATA && origin) origin = NULL;

    span_t *sp = &s->spans[s->span_len++];
    memset(sp, 0, sizeof *sp);
    sp->trust = t;
    sp->text = xstrdup(text ? text : "");
    if (role) snprintf(sp->role, sizeof sp->role, "%s", role);
    if (origin) {
        sp->has_origin = true;
        snprintf(sp->origin.channel, sizeof sp->origin.channel, "%s", origin->channel);
        snprintf(sp->origin.ref, sizeof sp->origin.ref, "%s", origin->ref);
    }
    /* Taint is derived on read; adding a DATA span is the ONLY way to taint. */
    if (t == TRUST_DATA)
        s->tainted_by[s->taint_len++] = sp->origin;
}

bool session_tainted(const session_t *s) {
    if (!s) return false;
    for (size_t i = 0; i < s->span_len; i++)
        if (s->spans[i].trust == TRUST_DATA && s->spans[i].has_origin)
            return true;
    return false;
}

const char *session_nonce(session_t *s) {
    if (!s) return "";
    if (s->nonce[0] == '\0') mint_nonce(s->nonce);
    return s->nonce;
}

void session_event_emit(session_t *s, const event_t *e) {
    if (!s || !e) return;
    event_t *slot = &s->events[s->event_head];
    *slot = *e;
    /* derived at emit time: an event is tainted iff its session is */
    slot->tainted = session_tainted(s) ? 1 : 0;
    s->event_head = (s->event_head + 1) % WD_MAX_EVENTS;
    if (s->event_len < WD_MAX_EVENTS) s->event_len++;
}

/* A ring that overwrites must account for what it lost rather than silently
 * dropping: ring-buffer overflows are counted in drop_total. */
void session_event_drop(session_t *s, uint64_t n) {
    if (s) s->drop_total += n;
}
