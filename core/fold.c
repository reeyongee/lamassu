/* fold.c — bounded homoglyph / NFKC-compatibility folding.
 *
 * Design:
 *   src/not_sandboxed/normalize/unicode.py  (_fold_confusables, normalize_unicode)
 *   src/not_sandboxed/config.py             (CONFUSABLE_CODEPOINTS, CONFUSABLES)
 *
 * Upstream folded a hand-curated 35-entry confusable table and ran the host
 * standard library's NFKC first. C has neither, so the same normalisation is
 * taken to the authoritative Unicode source instead of a hand-typed list: the
 * committed core/fold_table.h is generated from confusables.txt (UTS #39) and
 * the UCD by tools/gen_fold_table.mjs, and is restricted to the ASCII-foldable
 * subset — every codepoint that NFKC and/or the confusables map send to pure
 * [A-Za-z0-9]. That is precisely the set a homoglyph bypass uses, and it is
 * small enough to commit (2089 entries, ~2.4 KB pool). See docs/lineage/fold.c.md.
 *
 * The fold is the fixpoint: the table already stores the fully-folded target, so
 * one pass over the input suffices. Every allocation and every loop is bounded. */
/* Instantiate the generated table arrays in this translation unit. Must be set
 * before fold.h (which includes fold_table.h) so the arrays are emitted here and
 * nowhere else. */
#define LAMASSU_FOLD_TABLE_DEFINE
#include "fold.h"

#include <stdlib.h>
#include <string.h>

/* Decode one UTF-8 sequence at `p` (length `n`). Returns the codepoint and sets
 * *len to the sequence length, or returns < 0 for an invalid/truncated sequence
 * (*len = 1) so the caller copies the offending byte through untouched. */
static long utf8_decode(const unsigned char *p, size_t n, size_t *len) {
    unsigned char c = p[0];
    if (c < 0x80) { *len = 1; return (long)c; }
    if ((c & 0xE0) == 0xC0) {
        if (n < 2 || (p[1] & 0xC0) != 0x80) goto bad;
        *len = 2;
        return ((long)(c & 0x1F) << 6) | (p[1] & 0x3F);
    }
    if ((c & 0xF0) == 0xE0) {
        if (n < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) goto bad;
        *len = 3;
        return ((long)(c & 0x0F) << 12) | ((long)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
    }
    if ((c & 0xF8) == 0xF0) {
        if (n < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 ||
            (p[3] & 0xC0) != 0x80) goto bad;
        *len = 4;
        return ((long)(c & 0x07) << 18) | ((long)(p[1] & 0x3F) << 12) |
               ((long)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
    }
bad:
    *len = 1;
    return -1;
}

/* Binary search the generated, sorted table. Returns the entry or NULL. */
static const fold_entry_t *fold_lookup(unsigned long cp) {
    size_t lo = 0, hi = WD_FOLD_TABLE_LEN;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (FOLD_TABLE[mid].cp == cp) return &FOLD_TABLE[mid];
        if (FOLD_TABLE[mid].cp < cp) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

int fold_confusables(const char *in, char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    out[0] = '\0';
    if (!in) return 0;

    size_t n = strlen(in);
    size_t i = 0, o = 0;
    int changed = 0;

    while (i < n) {
        size_t len = 1;
        long cp = utf8_decode((const unsigned char *)in + i, n - i, &len);
        const fold_entry_t *e = (cp >= 0x80) ? fold_lookup((unsigned long)cp) : NULL;

        if (e) {
            /* Folding expands a single codepoint into an ASCII run. */
            if (o + e->len + 1 > cap) return -1;
            memcpy(out + o, FOLD_POOL + e->off, e->len);
            o += e->len;
            changed = 1;
        } else {
            if (o + len + 1 > cap) return -1;
            memcpy(out + o, in + i, len);
            o += len;
        }
        i += len;
    }
    out[o] = '\0';
    return changed ? 1 : 0;
}

char *fold_confusables_dup(const char *in, size_t max_out) {
    if (!in) return NULL;
    size_t n = strlen(in);
    if (n > max_out) return NULL;
    /* Each codepoint expands to at most WD_FOLD_MAX_TARGET ASCII bytes and the
     * input is at least one byte per codepoint, so n * WD_FOLD_MAX_TARGET + 1 is
     * a safe, bounded capacity. */
    size_t cap = n * (size_t)WD_FOLD_MAX_TARGET + 1;
    if (cap < n + 1) cap = n + 1; /* overflow guard */
    char *o = malloc(cap);
    if (!o) return NULL;
    if (fold_confusables(in, o, cap) < 0) { free(o); return NULL; }
    return o;
}
