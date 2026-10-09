/* layers.c — the five inspection layers and their orchestration.
 * Design:
 *   src/not_sandboxed/layers/normalize.py   -> layer parts (reports, never decides)
 *   src/not_sandboxed/layers/ingress.py     -> chat-template markers +
 *                                              instruction-shaped text, DATA only
 *   src/not_sandboxed/layers/provenance.py  -> per-request nonce fence
 *   src/not_sandboxed/layers/toolauth.py    -> effects, args, guards
 *   src/not_sandboxed/layers/egress.py      -> canary under closure, URL hosts
 *   src/not_sandboxed/firewall.py           -> render(), _run(), fail-closed
 *                                              _layer_error, _disabled
 *   src/not_sandboxed/config.py             -> rules, patterns, budgets
 *
 * The four invariant layers never read payload CONTENT to reach their decision:
 * provenance refuses because the nonce is present, toolauth refuses because the
 * context is tainted, egress refuses because the host is not allowlisted. Only
 * ingress is scored, and it is labelled as such. That split is the whole point
 * of the design and is preserved here. */
#include "lamassu.h"
#include "fold.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------- helpers -- */

static char *lower_dup(const char *s) {
    char *o = xstrdup(s);
    for (char *p = o; *p; p++) *p = (char)tolower((unsigned char)*p);
    return o;
}

static int contains_ci(const char *hay, const char *needle) {
    if (!*needle) return 0;
    char *h = lower_dup(hay), *n = lower_dup(needle);
    int r = strstr(h, n) != NULL;
    free(h); free(n);
    return r;
}

/* Read the closure into a flat search helper: does any reading contain the
 * needle after aggressive normalisation? This is how a secret survives
 * separators, reversal, rot13, or transport encoding. */
static int closure_contains(const char *text, const char *needle, size_t maxv) {
    char **reads = NULL;
    size_t n = closure_readings(text, maxv, &reads);

    /* The needle must be normalised by exactly the same transforms the readings
     * receive. It was previously only strip_noise'd, while every reading had
     * also passed through the confusable fold. That asymmetry is a real bypass:
     * a canary stored with a compatibility character (say a fullwidth form) never
     * matched its own ASCII rendering, so canary-leak could not fire. Fold then
     * strip, mirroring the reading path. */
    char *folded_n = fold_confusables_dup(needle, WD_MAX_NORMALIZE_BYTES);
    const char *nbase = folded_n ? folded_n : needle;
    char *ns = xcalloc(strlen(nbase) + 1, 1);
    strip_noise(nbase, ns, strlen(nbase) + 1);

    int hit = 0;
    for (size_t i = 0; i < n && !hit; i++) {
        char *rs = xcalloc(strlen(reads[i]) + 1, 1);
        strip_noise(reads[i], rs, strlen(reads[i]) + 1);
        char *l = lower_dup(rs), *nl = lower_dup(ns);
        if (*nl && strstr(l, nl)) hit = 1;
        free(l); free(nl); free(rs);
    }
    free(ns);
    free(folded_n);
    closure_free(reads, n);
    return hit;
}

/* --------------------------------------------------- layer: normalize ----- */

static const char *CHAT_TEMPLATE_MARKERS[] = {
    "<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>",
    "<|endoftext|>", "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>",
    "</system>", "</s>",
};
#define N_MARKERS (sizeof CHAT_TEMPLATE_MARKERS / sizeof *CHAT_TEMPLATE_MARKERS)

int layer_normalize(const span_t *sp, findings_t *out) {
    if (!sp || !sp->text) return 0;
    const char *t = sp->text;

    if (strlen(t) > WD_MAX_NORMALIZE_BYTES) {
        findings_push(out, "normalize", "input-too-large", SEV_HIGH, false,
                      PROV_DECLARED, "input exceeds normalize budget", sp->origin.ref[0] ? 0 : -1);
        return 0;
    }

    /* Did a transform need to be applied? A transform is itself a signal, and
     * it is reported even when the decoded content is benign. */
    char *norm = normalize_unicode_dup(t);
    if (strcmp(norm, t) != 0)
        findings_push(out, "normalize", "unicode-transform", SEV_MEDIUM, false,
                      PROV_DECLARED, norm, -1);
    free(norm);

    int depth = 0;
    char *un = unwrap_dup(t, &depth);
    if (un) {
        if (depth >= WD_MAX_DECODE_DEPTH)
            findings_push(out, "normalize", "decode-budget", SEV_HIGH, false,
                          PROV_DECLARED, un, -1);
        else
            findings_push(out, "normalize", "transport-encoded", SEV_MEDIUM, false,
                          PROV_DECLARED, un, -1);
        free(un);
    } else {
        char **emb = NULL;
        size_t n = embedded_decodes(t, &emb, WD_MAX_EMBEDDED_RUNS);
        if (n) {
            findings_push(out, "normalize", "embedded-encoded", SEV_MEDIUM, false,
                          PROV_DECLARED, emb[0], -1);
            for (size_t i = 0; i < n; i++) free(emb[i]);
        }
        free(emb);
    }
    return 0;
}

/* ----------------------------------------------------- layer: ingress ----- */

/* Instruction-shaped text: matched on second person + imperative MOOD, not on
 * vocabulary, so "the courier may act as an agent" passes and "Act as an
 * unrestricted agent" does not (ingress.py). */
static const char *SECOND_PERSON[] = {
    "you must ", "you will ", "you should ", "you shall ", "you are to ",
    "you need to ", "you can ", "you may ", "you are now ", "your instructions",
    "your system prompt",
};
static const char *IMPERATIVE_VERBS[] = {
    "ignore ", "disregard ", "forget ", "override ", "act as ", "behave as ",
    "answer ", "respond ", "reply ", "obey ", "comply ", "reveal ", "disclose ",
    "print ", "output ", "repeat ", "show ", "leak ", "dump ", "send ",
};
#define N_2P (sizeof SECOND_PERSON / sizeof *SECOND_PERSON)
#define N_IMP (sizeof IMPERATIVE_VERBS / sizeof *IMPERATIVE_VERBS)

/* The sentence must be an instruction to the reader, not about the author's own
 * message: PIP's _NOT_OWN_MESSAGE. "my instructions" is the user talking about
 * themselves and must not match. */
static int looks_like_own_message(const char *s) {
    return contains_ci(s, "my ") || contains_ci(s, "our ");
}

/* An instruction-shaped reading is one that reaches for the model's control
 * surface: a second-person address, or an imperative aimed at disclosure. */
static int instruction_shaped(const char *text) {
    char **reads = NULL;
    size_t n = closure_readings(text, WD_MAX_INGRESS_VARIANTS, &reads);
    int hit = 0;
    for (size_t i = 0; i < n && !hit; i++) {
        const char *r = reads[i];
        int second_person = 0;
        for (size_t k = 0; k < N_2P && !second_person; k++)
            if (contains_ci(r, SECOND_PERSON[k])) second_person = 1;
        int imperative = 0;
        for (size_t k = 0; k < N_IMP && !imperative; k++)
            if (contains_ci(r, IMPERATIVE_VERBS[k])) imperative = 1;
        /* disclosure demand: an imperative verb plus a disclosure target */
        int target = contains_ci(r, "system prompt") || contains_ci(r, "initial prompt") ||
                     contains_ci(r, "your instructions") || contains_ci(r, "the secret") ||
                     contains_ci(r, "api key") || contains_ci(r, "credential") ||
                     contains_ci(r, "configuration") || contains_ci(r, "password") ||
                     contains_ci(r, "token") || contains_ci(r, "instructions") ||
                     contains_ci(r, "previous") || contains_ci(r, "prior");
        if (second_person || (imperative && target)) hit = 1;
    }
    if (hit && looks_like_own_message(text)) {
        /* "disregard my previous instructions" is a user speaking about their own
         * note, not an instruction to the model. */
        int real_second_person = 0;
        for (size_t i = 0; i < n; i++)
            for (size_t k = 0; k < N_2P; k++)
                if (contains_ci(reads[i], SECOND_PERSON[k])) real_second_person = 1;
        if (!real_second_person) hit = 0;
    }
    closure_free(reads, n);
    return hit;
}

int layer_ingress(const span_t *sp, const policy_t *p, findings_t *out) {
    (void)p;
    if (!sp || !sp->text) return 0;

    /* Scoped to DATA only. The identical sentence from a user is an ordinary
     * English sentence about their own message; inside a retrieved document it
     * is an attempt to command the model. Same bytes, opposite verdicts. */
    if (sp->trust != TRUST_DATA) return 0;

    char **reads = NULL;
    size_t n = closure_readings(sp->text, WD_MAX_INGRESS_VARIANTS, &reads);
    for (size_t i = 0; i < n; i++) {
        for (size_t m = 0; m < N_MARKERS; m++) {
            if (contains_ci(reads[i], CHAT_TEMPLATE_MARKERS[m])) {
                findings_push(out, "ingress", "chat-template-marker", SEV_HIGH, false,
                              PROV_DECLARED, CHAT_TEMPLATE_MARKERS[m], -1);
            }
        }
    }
    closure_free(reads, n);

    if (instruction_shaped(sp->text))
        findings_push(out, "ingress", "data-imperative", SEV_MEDIUM, false,
                      PROV_DECLARED, sp->text, -1);

    return 0;
}

/* -------------------------------------------------- layer: provenance ----- */

int layer_provenance(const session_t *s, const span_t *sp, const policy_t *p,
                     findings_t *out) {
    (void)p;
    if (!s || !sp || !sp->text) return 0;
    if (sp->trust != TRUST_DATA) return 0;

    /* If the nonce appears in DATA at all it is a CRITICAL invariant violation:
     * attacker content has no legitimate way to know a value minted for this
     * request (provenance.py, firewall.py render()). A static delimiter is
     * forgeable by anyone who has read the source; this one is not. */
    if (closure_contains(sp->text, s->nonce, WD_MAX_VARIANTS))
        findings_push(out, "provenance", "nonce-forgery", SEV_CRITICAL, true,
                      PROV_DECLARED, "fence nonce present in DATA", -1);
    return 0;
}

/* ---------------------------------------------------- layer: toolauth ----- */

int layer_toolauth(const tool_call_t *tc, const session_t *s, const policy_t *p,
                   findings_t *out) {
    if (!tc) return 0;

    if (!tc->known) {
        findings_push(out, "toolauth", "tool-unknown", SEV_CRITICAL, true,
                      PROV_DECLARED, tc->name, -1);
        return 0;
    }

    /* forbidden effects: refuse a whole class of capability */
    for (size_t i = 0; i < tc->effect_len; i++)
        for (size_t k = 0; k < p->eff_len; k++)
            if (strcmp(tc->effects[i], p->forbidden_effects[k]) == 0)
                findings_push(out, "toolauth", "tool-effect-forbidden", SEV_CRITICAL, true,
                              PROV_DECLARED, tc->effects[i], -1);

    /* required arguments present */
    for (size_t i = 0; i < tc->required_len; i++) {
        int found = 0;
        for (size_t k = 0; k < tc->arg_len; k++)
            if (strcmp(tc->required[i], tc->arg_keys[k]) == 0) { found = 1; break; }
        if (!found)
            findings_push(out, "toolauth", "tool-args-invalid", SEV_CRITICAL, true,
                          PROV_DECLARED, tc->required[i], -1);
    }

    /* unexpected arguments: a tool never declared them, so refuse rather than
     * forward something the tool cannot validate */
    for (size_t k = 0; k < tc->arg_len; k++) {
        int permitted = 0;
        for (size_t i = 0; i < tc->permitted_len; i++)
            if (strcmp(tc->arg_keys[k], tc->permitted[i]) == 0) { permitted = 1; break; }
        if (!permitted)
            findings_push(out, "toolauth", "tool-args-unexpected", SEV_CRITICAL, true,
                          PROV_DECLARED, tc->arg_keys[k], -1);
    }

    /* guards */
    for (size_t i = 0; i < tc->guard_len; i++) {
        if (strcmp(tc->guards[i], "NO_UNTRUSTED_INFLUENCE") == 0 ||
            strcmp(tc->guards[i], "no_untrusted_influence") == 0) {
            if (session_tainted(s))
                findings_push(out, "toolauth", "tainted-action", SEV_CRITICAL, true,
                              PROV_DECLARED, tc->name, -1);
        }
        if (strcmp(tc->guards[i], "USER_CONFIRMED") == 0 ||
            strcmp(tc->guards[i], "user_confirmed") == 0) {
            if (!tc->user_confirmed)
                findings_push(out, "toolauth", "tool-unconfirmed", SEV_CRITICAL, true,
                              PROV_DECLARED, tc->name, -1);
        }
        if (strcmp(tc->guards[i], "ARGS_ALLOWLISTED") == 0 ||
            strcmp(tc->guards[i], "args_allowlisted") == 0) {
            /* key/value pairs appended as "key:value" */
            for (size_t k = 0; k < tc->allow_len; k++) {
                const char *spec = tc->allow_vals[k];
                const char *colon = strchr(spec, ':');
                if (!colon) continue;
                char key[64]; size_t kl = (size_t)(colon - spec);
                if (kl >= sizeof key) continue;
                memcpy(key, spec, kl); key[kl] = '\0';
                const char *allowed = colon + 1;
                const char *val = NULL;
                for (size_t a = 0; a < tc->arg_len; a++)
                    if (strcmp(tc->arg_keys[a], key) == 0) val = tc->arg_vals[a];
                if (!val || strcmp(val, allowed) != 0)
                    findings_push(out, "toolauth", "tool-args-not-allowlisted",
                                  SEV_CRITICAL, true, PROV_DECLARED, key, -1);
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------- layer: egress ---- */

static int host_allowed(const char *host, const egress_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->host_len; i++) {
        const char *a = ctx->allowed_hosts[i];
        if (a[0] == '.') {                      /* suffix allowlist */
            const char *suf = a + 1;
            if (strcmp(host, suf) == 0) return 1;
            size_t hl = strlen(host), sl = strlen(suf);
            if (hl > sl && strcmp(host + hl - sl, suf) == 0 &&
                host[hl - sl - 1] == '.') return 1;
        } else if (strcmp(host, a) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Extract the host from a URL-ish token. Handles scheme-relative "//host" and
 * strips userinfo/port/path. */
static void url_host(const char *url, char *out, size_t cap) {
    const char *p = url;
    if (p[0] == '/' && p[1] == '/') p += 2;
    else {
        const char *sl = strstr(p, "://");
        if (sl) p = sl + 3;
    }
    const char *end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#' &&
           *end != ' ' && *end != ')' && *end != ']' && *end != '>' &&
           *end != '"' && *end != '\'') end++;
    size_t n = (size_t)(end - p);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n); out[n] = '\0';
    /* drop userinfo */
    char *at = strchr(out, '@');
    if (at) memmove(out, at + 1, strlen(at));

    /* Strip the port WITHOUT destroying an IPv6 literal. A bracketed literal is
     * `[::1]:8080`; the colons inside the brackets are part of the address, and a
     * naive "cut at the first colon" turned `[2001:db8::1]` into `[2001`. The
     * caller's allowlist then never saw a host with a dot, so the check was
     * skipped entirely and any IPv6 egress passed. */
    char *colon;
    if (out[0] == '[') {
        char *close = strchr(out, ']');
        colon = close ? strchr(close, ':') : NULL;
    } else {
        colon = strchr(out, ':');
    }
    if (colon) *colon = '\0';
}

int layer_egress(const char *text, const egress_ctx_t *ctx, findings_t *out) {
    if (!text || !ctx) return 0;

    if (strlen(text) > WD_MAX_EGRESS_BYTES) {
        findings_push(out, "egress", "output-too-large", SEV_CRITICAL, true,
                      PROV_DECLARED, "output exceeds egress budget", -1);
        return 0;
    }

    /* One mechanism, not one rule per variant: match the canary in ANY reading
     * the closure can reach (egress.py _canary_findings). */
    for (size_t i = 0; i < ctx->canary_len; i++) {
        char *cn = xcalloc(strlen(ctx->canaries[i]) + 1, 1);
        strip_noise(ctx->canaries[i], cn, strlen(ctx->canaries[i]) + 1);
        size_t need = strlen(cn);
        free(cn);
        if (need < WD_MIN_CANARY_LENGTH) continue;   /* refused at construction */
        if (closure_contains(text, ctx->canaries[i], WD_MAX_VARIANTS))
            findings_push(out, "egress", "canary-leak", SEV_CRITICAL, true,
                          PROV_DECLARED, ctx->canaries[i], -1);
    }

    /* URLs: any host not allowlisted is a hard stop, including protocol-relative
     * and mixed-case schemes. Markdown images are treated as links because
     * ![x](https://attacker/?d=DATA) is the actual exfiltration primitive. */
    const char *p = text;
    while ((p = strstr(p, "//")) != NULL) {
        char raw[512];
        const char *start = p;
        /* walk back over an optional scheme */
        if (p - text >= 6 && strncmp(p - 6, "https:", 6) == 0) start = p - 6;
        else if (p - text >= 5 && strncmp(p - 5, "http:", 5) == 0) start = p - 5;
        const char *end = p + 2;
        while (*end && !isspace((unsigned char)*end) && *end != ')' && *end != '"' &&
               *end != '\'' && *end != '>' && *end != ']' && *end != '`') end++;
        size_t n = (size_t)(end - start);
        if (n >= sizeof raw) n = sizeof raw - 1;
        memcpy(raw, start, n); raw[n] = '\0';

        char host[256];
        url_host(raw, host, sizeof host);
        char *lh = lower_dup(host);
        /* A host is checked whenever one was parsed. The previous form required a
         * '.' before consulting the allowlist, so any dotless host — an IPv6
         * literal, a single-label internal name — bypassed it outright. */
        if (*lh && !host_allowed(lh, ctx))
            findings_push(out, "egress", "url-egress", SEV_CRITICAL, true,
                          PROV_DECLARED, lh, -1);
        free(lh);
        p = end;
    }
    return 0;
}

/* ------------------------------------------------------------ firewall ---- */

static const char *LAYER_ORDER[] = { "normalize", "ingress", "provenance" };
#define N_LAYER_ORDER (sizeof LAYER_ORDER / sizeof *LAYER_ORDER)

static int enabled(const policy_t *p, const char *name) {
    if (strcmp(name, "normalize")  == 0) return p->normalize_enabled;
    if (strcmp(name, "ingress")    == 0) return p->ingress_enabled;
    if (strcmp(name, "provenance") == 0) return p->provenance_enabled;
    if (strcmp(name, "toolauth")   == 0) return p->toolauth_enabled;
    if (strcmp(name, "egress")     == 0) return p->egress_enabled;
    return 1;
}

void firewall_init(firewall_t *fw, const policy_t *p) {
    fw->policy = *p;
    fw->egress.canaries = p->canaries;  fw->egress.canary_len = p->canary_len;
    fw->egress.allowed_hosts = p->allowed_hosts; fw->egress.host_len = p->host_len;
}

/* firewalls that DO silently truncate. Without a signal, a caller cannot tell
 * "rendered" from "rendered only the first N bytes", and an unterminated fence
 * is worse than a refusal: the DATA span that got cut has no closing delimiter,
 * so everything printed after it reads as though it were inside the fence.
 * Returns the same value as firewall_render; *truncated is set to 1 when the
 * output could not hold every span. */
char *firewall_render_checked(session_t *s, char *out, size_t cap, int *truncated) {
    if (truncated) *truncated = 0;
    if (!s) return NULL;
    const char *nonce = session_nonce(s);
    size_t o = 0;
    for (size_t i = 0; i < s->span_len; i++) {
        span_t *sp = &s->spans[i];
        int w;
        if (sp->trust == TRUST_DATA) {
            w = snprintf(out + o, cap - o, "<<<UNTRUSTED-%s origin=%s:%s>>>\n%s\n<<<END-%s>>>\n",
                         nonce,
                         sp->has_origin ? sp->origin.channel : "unknown",
                         sp->has_origin ? sp->origin.ref : "unknown",
                         sp->text, nonce);
        } else {
            w = snprintf(out + o, cap - o, "%s\n", sp->text);
        }
        if (w < 0 || (size_t)w >= cap - o) {
            if (truncated) *truncated = 1;
            break;
        }
        o += (size_t)w;
    }
    return out;
}

/* The firewall renders the prompt itself. That is what makes provenance
 * DECLARED rather than inferred: nobody else is trusted to fence the DATA. */
char *firewall_render(session_t *s, char *out, size_t cap) {
    int ignored = 0;
    return firewall_render_checked(s, out, cap, &ignored);
}

static void add_layer_error(findings_t *out, const char *layer, const char *what) {
    /* Fail closed: a layer that raised is an invariant violation, never a pass.
     * "A firewall that fails open on an unhandled exception is worse than none,
     * because it reports success while doing nothing" (firewall.py). */
    findings_push(out, layer, "layer-error", SEV_CRITICAL, true, PROV_DECLARED, what, -1);
}

static void add_layer_disabled(findings_t *out, const char *layer) {
    /* Silence must be visible: a consumer can always tell "nothing fired" from
     * "nothing ran". */
    findings_push(out, layer, "layer-disabled", SEV_INFO, false, PROV_DECLARED,
                  "layer disabled by policy", -1);
}

decision_t firewall_inspect(firewall_t *fw, session_t *s, findings_t *out) {
    for (size_t i = 0; i < N_LAYER_ORDER; i++) {
        const char *name = LAYER_ORDER[i];
        if (!enabled(&fw->policy, name)) { add_layer_disabled(out, name); continue; }
        for (size_t k = 0; k < s->span_len; k++) {
            int rc = 0;
            if (strcmp(name, "normalize") == 0)       rc = layer_normalize(&s->spans[k], out);
            else if (strcmp(name, "ingress") == 0)    rc = layer_ingress(&s->spans[k], &fw->policy, out);
            else if (strcmp(name, "provenance") == 0) rc = layer_provenance(s, &s->spans[k], &fw->policy, out);
            if (rc != 0) add_layer_error(out, name, "layer returned non-zero");
        }
    }
    escalate(out, &fw->policy);
    for (size_t i = 0; i < out->len; i++) out->items[i].tainted = session_tainted(s) ? 1 : 0;
    return decide(out, &fw->policy);
}

/* Flatten one argument value the way PIP render_arg does: a secret nested in a
 * list or object still leaves, so every leaf must be scanned. */
static void flatten_into(const jval_t *v, char *out, size_t cap, size_t *o) {
    if (!v) return;
    switch (v->t) {
    case JSTR:
        if (v->str) {
            size_t l = strlen(v->str);
            if (*o + l + 2 < cap) { memcpy(out + *o, v->str, l); *o += l; out[(*o)++] = ' '; out[*o] = '\0'; }
        }
        break;
    case JNUM: {
        char b[64]; snprintf(b, sizeof b, "%g ", v->num);
        size_t l = strlen(b);
        if (*o + l + 1 < cap) { memcpy(out + *o, b, l); *o += l; out[*o] = '\0'; }
        break;
    }
    case JARR:
        for (size_t i = 0; i < v->len; i++) flatten_into(v->items[i], out, cap, o);
        break;
    case JOBJ:
        for (size_t i = 0; i < v->len; i++) {
            const char *k = v->keys ? v->keys[i] : "";
            size_t l = strlen(k);
            if (*o + l + 2 < cap) { memcpy(out + *o, k, l); *o += l; out[(*o)++] = ' '; out[*o] = '\0'; }
            flatten_into(v->items[i], out, cap, o);
        }
        break;
    default: break;
    }
}

const jval_t *json_get(const jval_t *obj, const char *key);

decision_t firewall_inspect_egress(firewall_t *fw, session_t *s,
                                   const tool_call_t *tcs, size_t tc_len,
                                   const char *reply_text, findings_t *out) {
    (void)s;

    /* toolauth */
    if (!enabled(&fw->policy, "toolauth")) add_layer_disabled(out, "toolauth");
    else {
        for (size_t i = 0; i < tc_len; i++) {
            if (layer_toolauth(&tcs[i], s, &fw->policy, out) != 0)
                add_layer_error(out, "toolauth", "layer returned non-zero");
        }
    }

    /* egress over the prose AND every flattened tool argument */
    if (!enabled(&fw->policy, "egress")) add_layer_disabled(out, "egress");
    else {
        if (reply_text && layer_egress(reply_text, &fw->egress, out) != 0)
            add_layer_error(out, "egress", "layer returned non-zero");
        for (size_t i = 0; i < tc_len; i++) {
            for (size_t k = 0; k < tcs[i].arg_len; k++) {
                if (tcs[i].arg_vals[k] &&
                    layer_egress(tcs[i].arg_vals[k], &fw->egress, out) != 0)
                    add_layer_error(out, "egress", "layer returned non-zero");
            }
        }
    }

    escalate(out, &fw->policy);
    if (s) for (size_t i = 0; i < out->len; i++) out->items[i].tainted = session_tainted(s) ? 1 : 0;
    return decide(out, &fw->policy);
}

/* Public entry point for the adapters: turn a tool_input value into scannable
 * text. A secret nested in a list or an object still leaves, so every leaf is
 * flattened (PIP tools.py render_arg). */
void flatten_json_arg(const jval_t *v, char *out, size_t cap) {
    size_t o = 0;
    out[0] = '\0';
    flatten_into(v, out, cap, &o);
}
