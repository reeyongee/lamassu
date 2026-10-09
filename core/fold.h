/* fold.h — bounded homoglyph / NFKC-compatibility folding.
 *
 * The `normalize` layer must see what the model would see. A Cyrillic 'а', a
 * Greek 'ο', a fullwidth 'ａ' or a mathematical-bold '𝐚' renders as its Latin
 * look-alike but is a different codepoint, so a nonce or a canary written in
 * homoglyphs slips past a byte comparison. This unit folds exactly those
 * codepoints that Unicode says are homoglyphs or NFKC-compatible with pure
 * ASCII [A-Za-z0-9] — the set a bypass actually uses — before any layer judges
 * a span.
 *
 * Distinct unit (own header, not lamassu.h): the table is generated from
 * authoritative Unicode data by tools/gen_fold_table.mjs; see
 * docs/lineage/fold.c.md for the derivation and the residual gap.
 */
#ifndef LAMASSU_FOLD_H
#define LAMASSU_FOLD_H

#include <stddef.h>

/* Generated from authoritative Unicode data; supplies WD_FOLD_TABLE_LEN and
 * WD_FOLD_MAX_TARGET (the widest fold target). The table arrays themselves are
 * instantiated only in fold.c. */
#include "fold_table.h"

/* Fold `in` into `out` (capacity `cap`, always NUL-terminated on success).
 *
 * Returns  1 if any codepoint was folded (a transform happened),
 *          0 if the text was already fold-free,
 *         -1 if the folded form does not fit in `cap` (caller reports a budget
 *            exhaustion rather than emitting a truncated reading).
 *
 * ASCII bytes are never rewritten, so a fold can only touch non-ASCII input.
 * Invalid UTF-8 bytes are passed through unchanged. */
int fold_confusables(const char *in, char *out, size_t cap);

/* malloc'd folded copy. Returns NULL when strlen(in) > max_out, so the caller
 * can report `input-too-large` instead of allocating an unbounded buffer.
 * Caller frees. */
char *fold_confusables_dup(const char *in, size_t max_out);

#endif /* LAMASSU_FOLD_H */
