/* closure.c — the encoding closure.
 * Design:
 *   src/not_sandboxed/normalize/views.py  (strip_noise, strip_separators,
 *                                          _rot13, _normalized, _unwrapped,
 *                                          _embedded, _reversed, _VIEWS,
 *                                          readings)
 *   src/not_sandboxed/normalize/unwrap.py (transport decoders, _peel, _runs,
 *                                          embedded_decodes, unwrap)
 *   src/not_sandboxed/normalize/unicode.py (tag block, zero-width, bidi,
 *                                           confusables, NFKC)
 *   src/not_sandboxed/config.py           (budgets)
 *
 * Why a closure and not a fixed pipeline (views.py, verbatim rationale):
 *   base64 of a dashed secret needs decode-before-strip, and a dashed base64
 *   secret needs strip-before-decode. The order depends on the order the
 *   attacker applied them, so the search has to close over every ordering.
 *
 * Bounds are mandatory: the adversary gets unlimited attempts, so every loop
 * here terminates on a budget, and every budget exhaustion is REPORTED by the
 * caller as a `decode-budget` finding rather than silently truncating. */
#include "lamassu.h"
#include "fold.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------- aggressive views -- */

/* Keep only alphanumerics: the reading a separated secret survives. */
void strip_noise(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; p && *p; p++)
        if (isalnum(*p) && o + 1 < cap) out[o++] = (char)*p;
    out[o] = '\0';
}

static int is_separator(unsigned char c) {
    /* config.py SEPARATOR_CODEPOINTS (all < 0x80 here) plus zero-width chars
     * (which are multi-byte and handled separately). */
    switch (c) {
    case ' ': case '\t': case '\n': case '\r': case '-': case '.':
    case '_': case '|': case ',': case ':': case ';': case '*':
    case '~': case '\'': case '"': case '`':
        return 1;
    default: return 0;
    }
}

/* Drop separators but keep the structural characters a decoder still needs. */
void strip_separators(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; p && *p; p++)
        if (!is_separator(*p) && o + 1 < cap) out[o++] = (char)*p;
    out[o] = '\0';
}

char *rot13_dup(const char *in) {
    size_t n = strlen(in);
    char *o = xcalloc(n + 1, 1);
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'a' && c <= 'z')      c = (char)('a' + (c - 'a' + 13) % 26);
        else if (c >= 'A' && c <= 'Z') c = (char)('A' + (c - 'A' + 13) % 26);
        o[i] = c;
    }
    return o;
}

char *reverse_dup(const char *in) {
    size_t n = strlen(in);
    char *o = xcalloc(n + 1, 1);
    for (size_t i = 0; i < n; i++) o[i] = in[n - 1 - i];
    return o;
}

/* --------------------------------------------------- transport decoding --- */

static int printable_ratio_ok(const char *s) {
    size_t total = 0, good = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        total++;
        if (isprint(*p) || *p == '\n' || *p == '\r' || *p == '\t') good++;
    }
    if (total == 0) return 0;
    return ((double)good / (double)total) >= WD_MIN_PRINTABLE_RATIO;
}

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static char *try_base64(const char *t) {
    size_t n = strlen(t);
    if (n < WD_MIN_ENCODED_LENGTH || n % 4 != 0) return NULL;
    for (size_t i = 0; i < n; i++)
        if (t[i] != '=' && b64val((unsigned char)t[i]) < 0) return NULL;
    char *o = xcalloc(n / 4 * 3 + 1, 1);
    size_t oi = 0;
    for (size_t i = 0; i + 3 < n; i += 4) {
        int v0 = b64val((unsigned char)t[i]),   v1 = b64val((unsigned char)t[i+1]);
        int v2 = t[i+2] == '=' ? -2 : b64val((unsigned char)t[i+2]);
        int v3 = t[i+3] == '=' ? -2 : b64val((unsigned char)t[i+3]);
        if (v0 < 0 || v1 < 0) { free(o); return NULL; }
        o[oi++] = (char)((v0 << 2) | (v1 >> 4));
        if (v2 >= 0) o[oi++] = (char)(((v1 & 0xf) << 4) | (v2 >> 2));
        if (v3 >= 0 && v2 >= 0) o[oi++] = (char)(((v2 & 0x3) << 6) | v3);
    }
    o[oi] = '\0';
    if (oi == 0 || !printable_ratio_ok(o)) { free(o); return NULL; }
    return o;
}

static char *try_hex(const char *t) {
    size_t n = strlen(t);
    if (n < WD_MIN_ENCODED_LENGTH || n % 2 != 0) return NULL;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)t[i])) return NULL;
    char *o = xcalloc(n / 2 + 1, 1);
    for (size_t i = 0; i < n; i += 2) {
        char h[3] = { t[i], t[i+1], 0 };
        o[i/2] = (char)strtol(h, NULL, 16);
    }
    if (!printable_ratio_ok(o)) { free(o); return NULL; }
    return o;
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *try_percent(const char *t) {
    if (!strchr(t, '%')) return NULL;
    size_t n = strlen(t), oi = 0;
    char *o = xcalloc(n + 1, 1);
    for (size_t i = 0; i < n; i++) {
        if (t[i] == '%' && i + 2 < n) {
            int h = hexv((unsigned char)t[i+1]), l = hexv((unsigned char)t[i+2]);
            if (h >= 0 && l >= 0) { o[oi++] = (char)((h << 4) | l); i += 2; continue; }
        }
        o[oi++] = t[i];
    }
    o[oi] = '\0';
    if (strcmp(o, t) == 0) { free(o); return NULL; }
    return o;
}

static char *try_quoted_printable(const char *t) {
    if (!strchr(t, '=')) return NULL;
    size_t n = strlen(t), oi = 0;
    char *o = xcalloc(n + 1, 1);
    for (size_t i = 0; i < n; i++) {
        if (t[i] == '=' && i + 2 < n && t[i+1] != '\n') {
            int h = hexv((unsigned char)t[i+1]), l = hexv((unsigned char)t[i+2]);
            if (h >= 0 && l >= 0) { o[oi++] = (char)((h << 4) | l); i += 2; continue; }
        }
        if (t[i] == '=' && i + 1 < n && t[i+1] == '\n') { i++; continue; }
        o[oi++] = t[i];
    }
    o[oi] = '\0';
    if (strcmp(o, t) == 0) { free(o); return NULL; }
    return o;
}

/* One peel attempt across all codecs, first success wins (unwrap.py _peel). */
static char *peel_once(const char *in) {
    char *c;
    if ((c = try_base64(in))) return c;
    if ((c = try_hex(in)))    return c;
    if ((c = try_percent(in))) return c;
    if ((c = try_quoted_printable(in))) return c;
    return NULL;
}

char *unwrap_dup(const char *in, int *depth_out) {
    if (depth_out) *depth_out = 0;
    if (strlen(in) > WD_MAX_NORMALIZE_BYTES) return NULL;

    char *cur = xstrdup(in);
    int depth = 0;
    while (depth < WD_MAX_DECODE_DEPTH) {
        char *next = peel_once(cur);
        if (!next) break;
        free(cur);
        cur = next;
        depth++;
    }
    if (depth_out) *depth_out = depth;
    if (depth == 0) { free(cur); return NULL; }
    return cur;
}

/* Decode every transport-encoded RUN sitting inside a larger text, because the
 * realistic injection is a blob pasted into prose and a whole-span decoder
 * never sees it (unwrap.py embedded_decodes). */
size_t embedded_decodes(const char *text, char ***out, size_t cap) {
    size_t found = 0;
    if (strlen(text) > WD_MAX_NORMALIZE_BYTES) { *out = NULL; return 0; }
    char **arr = xcalloc(cap, sizeof *arr);

    /* runs of base64-ish and hex-ish characters */
    for (size_t i = 0; text[i] && found < cap; ) {
        size_t j = i;
        while (text[j] && (isalnum((unsigned char)text[j]) ||
                           text[j] == '+' || text[j] == '/' || text[j] == '=' ||
                           text[j] == '%')) j++;
        size_t runlen = j - i;
        if (runlen >= WD_MIN_ENCODED_LENGTH) {
            char *run = xcalloc(runlen + 1, 1);
            memcpy(run, text + i, runlen);
            char *dec = peel_once(run);
            free(run);
            if (dec && found < cap) {
                int dup = 0;
                for (size_t k = 0; k < found; k++)
                    if (strcmp(arr[k], dec) == 0) { dup = 1; break; }
                if (!dup) arr[found++] = dec; else free(dec);
            } else free(dec);
        }
        i = (j == i) ? i + 1 : j;
    }
    *out = arr;
    return found;
}

/* --------------------------------------------------------- unicode layer -- */

static int is_zwnbsp_char(unsigned char c) { return c == 0xEF; } /* lead of U+FEFF */

/* Strip the invisible/droppable characters (tag block, zero-width, BOM, bidi,
 * word joiner) — the transforms upstream's unicode.py performs before folding. */
static char *strip_invisibles_dup(const char *in) {
    /* Strip zero-width and BOM-before-tag characters, drop bidi controls, and
     * DROP the Unicode tag block U+E0000..U+E007F, which renders as nothing but
     * survives tokenization (unicode.py). */
    size_t n = strlen(in);
    char *o = xcalloc(n + 1, 1);
    size_t oi = 0;
    for (size_t i = 0; i < n; ) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x80) {
            /* C0/C1 controls that are not whitespace */
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') { i++; continue; }
            o[oi++] = (char)c; i++; continue;
        }
        /* multi-byte: decode enough to identify the block */
        unsigned int cp = 0; int len = 1;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else { o[oi++] = (char)c; i++; continue; }
        if (i + (size_t)len > n) { o[oi++] = (char)c; i++; continue; }
        int ok = 1;
        for (int k = 1; k < len; k++) {
            unsigned char cc = (unsigned char)in[i + k];
            if ((cc & 0xC0) != 0x80) { ok = 0; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (!ok) { o[oi++] = (char)c; i++; continue; }
        int drop = 0;
        if (cp >= 0xE0000 && cp <= 0xE007F) drop = 1;   /* tag block */
        if (cp == 0x200B || cp == 0x200C || cp == 0x200D) drop = 1;  /* zero-width */
        if (cp == 0xFEFF) drop = 1;                      /* BOM / ZWNBSP */
        if (cp >= 0x202A && cp <= 0x202E) drop = 1;      /* bidi embedding */
        if (cp >= 0x2066 && cp <= 0x2069) drop = 1;      /* bidi isolates */
        if (cp == 0x2060) drop = 1;                      /* word joiner */
        if (!drop) { memcpy(o + oi, in + i, (size_t)len); oi += (size_t)len; }
        i += (size_t)len;
    }
    o[oi] = '\0';
    (void)is_zwnbsp_char;
    return o;
}

/* The full normalize step, in upstream order (unicode.py normalize_unicode):
 * drop invisibles first, then fold homoglyphs / NFKC-compatible forms. A
 * homoglyph that renders as a nonce or a canary therefore reaches the layers as
 * the Latin it looks like, instead of as bytes that match nothing. */
char *normalize_unicode_dup(const char *in) {
    char *stripped = strip_invisibles_dup(in);
    char *folded = fold_confusables_dup(stripped, WD_MAX_NORMALIZE_BYTES);
    if (!folded) return stripped; /* over budget: keep the stripped form */
    free(stripped);
    return folded;
}

/* ------------------------------------------------------------- closure ---- */

typedef char *(*view_fn)(const char *);

static char *v_normalized(const char *s) { return normalize_unicode_dup(s); }
static char *v_unwrapped(const char *s)  { int d; return unwrap_dup(s, &d); }
static char *v_strip_sep(const char *s) {
    char *o = xcalloc(strlen(s) + 1, 1); strip_separators(s, o, strlen(s) + 1); return o;
}
static char *v_strip_noise(const char *s) {
    char *o = xcalloc(strlen(s) + 1, 1); strip_noise(s, o, strlen(s) + 1); return o;
}
static char *v_rot13(const char *s)   { return rot13_dup(s); }
static char *v_reversed(const char *s){ return reverse_dup(s); }
static char *v_embedded(const char *s) {
    char **arr = NULL;
    size_t n = embedded_decodes(s, &arr, WD_MAX_EMBEDDED_RUNS);
    size_t total = 1;
    for (size_t i = 0; i < n; i++) total += strlen(arr[i]) + 1;
    char *o = xcalloc(total, 1);
    size_t oi = 0;
    for (size_t i = 0; i < n; i++) {
        if (i) o[oi++] = ' ';
        size_t l = strlen(arr[i]);
        memcpy(o + oi, arr[i], l); oi += l;
        free(arr[i]);
    }
    free(arr);
    o[oi] = '\0';
    return o;
}

static const view_fn VIEWS[] = {
    v_normalized, v_unwrapped, v_embedded,
    v_strip_sep, v_strip_noise, v_rot13, v_reversed,
};
#define N_VIEWS (sizeof VIEWS / sizeof *VIEWS)

static int seen_contains(char **seen, size_t n, const char *s) {
    for (size_t i = 0; i < n; i++) if (strcmp(seen[i], s) == 0) return 1;
    return 0;
}

size_t closure_readings(const char *text, size_t max_variants, char ***out) {
    if (max_variants == 0 || max_variants > WD_MAX_VARIANTS) max_variants = WD_MAX_VARIANTS;
    char **seen = xcalloc(max_variants, sizeof *seen);
    char **frontier = xcalloc(max_variants, sizeof *frontier);
    size_t nseen = 0, nfront = 0;

    seen[nseen++] = xstrdup(text);
    frontier[nfront++] = xstrdup(text);

    for (int round = 0; round < WD_MAX_VARIANT_ROUNDS; round++) {
        if (nseen >= max_variants) break;
        char **produced = xcalloc(max_variants, sizeof *produced);
        size_t nprod = 0;
        for (size_t f = 0; f < nfront; f++) {
            for (size_t v = 0; v < N_VIEWS; v++) {
                char *d = VIEWS[v](frontier[f]);
                if (!d) continue;
                if (*d == '\0' || seen_contains(seen, nseen, d)) { free(d); continue; }
                if (nseen < max_variants) seen[nseen++] = xstrdup(d);
                if (nprod < max_variants) produced[nprod++] = d; else free(d);
                if (nseen >= max_variants) break;
            }
            if (nseen >= max_variants) break;
        }
        for (size_t i = 0; i < nfront; i++) free(frontier[i]);
        memcpy(frontier, produced, nprod * sizeof *produced);
        nfront = nprod;
        free(produced);
        if (nfront == 0) break;
    }
    for (size_t i = 0; i < nfront; i++) free(frontier[i]);
    free(frontier);
    *out = seen;
    return nseen;
}

void closure_free(char **readings, size_t n) {
    for (size_t i = 0; i < n; i++) free(readings[i]);
    free(readings);
}
