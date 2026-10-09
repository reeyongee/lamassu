/* verdict.c — severity, findings, and the decision algebra.
 * Design:
 * (Severity, Decision, Finding, Verdict.blocked_by) and
 * src/not_sandboxed/policy.py (decide, escalate, STRICT_DATA_RULES).
 *
 * Two properties are load-bearing and preserved exactly:
 *   1. invariant findings force BLOCK regardless of policy thresholds; they are
 *      never mixed into the scored comparison.
 *   2. a layer error produces an invariant finding (fail closed), and a disabled
 *      layer produces a visible layer-disabled finding (silence is visible). */
#include "lamassu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void findings_init(findings_t *f) { f->items = NULL; f->len = f->cap = 0; }

void findings_free(findings_t *f) {
    free(f->items);
    f->items = NULL; f->len = f->cap = 0;
}

int findings_push(findings_t *f, const char *layer, const char *rule,
                  severity_t sev, bool invariant, provenance_t prov,
                  const char *evidence, int span_index) {
    if (f->len == f->cap) {
        size_t cap = f->cap ? f->cap * 2 : 8;
        finding_t *p = realloc(f->items, cap * sizeof *p);
        if (!p) return -1;
        f->items = p; f->cap = cap;
    }
    finding_t *t = &f->items[f->len++];
    memset(t, 0, sizeof *t);
    snprintf(t->layer, sizeof t->layer, "%s", layer ? layer : "");
    snprintf(t->rule,  sizeof t->rule,  "%s", rule  ? rule  : "");
    t->severity  = sev;
    t->invariant = invariant;
    t->provenance = prov;
    t->span_index = span_index;
    sha256_hex16(evidence ? evidence : "", t->evidence_digest);
    return 0;
}

const char *severity_name(severity_t s) {
    switch (s) {
    case SEV_INFO: return "INFO";   case SEV_LOW: return "LOW";
    case SEV_MEDIUM: return "MEDIUM"; case SEV_HIGH: return "HIGH";
    case SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *decision_name(decision_t d) { return d == DEC_BLOCK ? "block" : "allow"; }

const char *provenance_name(provenance_t p) {
    return p == PROV_INFERRED ? "inferred" : "declared";
}

/* decay() mirrors PIP: taint does NOT decay. Present for symmetry with the
 * upstream API; it deliberately does nothing. */
static const char *STRICT_DATA_RULES[] = { "data-imperative", "chat-template-marker" };
#define N_STRICT (sizeof STRICT_DATA_RULES / sizeof *STRICT_DATA_RULES)

void escalate(findings_t *f, const policy_t *p) {
    if (!p->strict_data) return;
    for (size_t i = 0; i < f->len; i++) {
        for (size_t r = 0; r < N_STRICT; r++) {
            if (strcmp(f->items[i].rule, STRICT_DATA_RULES[r]) == 0) {
                f->items[i].invariant = true;
                break;
            }
        }
    }
}

decision_t decide(const findings_t *f, const policy_t *p) {
    /* 1. invariant violations are never thresholded */
    for (size_t i = 0; i < f->len; i++)
        if (f->items[i].invariant) return DEC_BLOCK;

    /* 2. scored findings compared against the policy threshold */
    severity_t worst = SEV_INFO; int any = 0;
    for (size_t i = 0; i < f->len; i++) {
        if (f->items[i].invariant) continue;
        if (f->items[i].severity > SEV_INFO) {
            any = 1;
            if (f->items[i].severity > worst) worst = f->items[i].severity;
        }
    }
    if (any && worst >= p->block_threshold) return DEC_BLOCK;

    return DEC_ALLOW;
}
