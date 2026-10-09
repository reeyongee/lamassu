/* policy.c — layer switches, thresholds, canaries, allowlists.
 * Design:
 *   src/not_sandboxed/policy.py (Policy defaults, PolicyError on an unmatchable
 *   canary), and config.py (CANARY_REJECTED / MIN_CANARY_LENGTH).
 *
 * The rejected-canary rule is preserved because it is an honesty rule: a canary
 * too short to match must ABORT construction, not silently protect nothing.
 * "egress would protect nothing while reporting success." */
#include "lamassu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void policy_default(policy_t *p) {
    memset(p, 0, sizeof *p);
    snprintf(p->policy_id, sizeof p->policy_id, "default");
    p->block_threshold     = SEV_HIGH;   /* policy.py block_threshold */
    p->strict_data         = true;
    p->normalize_enabled   = true;
    p->ingress_enabled     = true;
    p->provenance_enabled  = true;
    p->toolauth_enabled    = true;
    p->egress_enabled      = true;
    p->canaries = NULL;      p->canary_len = 0;
    p->allowed_hosts = NULL; p->host_len = 0;
    p->forbidden_effects = NULL; p->eff_len = 0;
}

static void free_vec(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

void policy_free(policy_t *p) {
    free_vec(p->canaries, p->canary_len);
    free_vec(p->allowed_hosts, p->host_len);
    free_vec(p->forbidden_effects, p->eff_len);
    p->canaries = p->allowed_hosts = p->forbidden_effects = NULL;
    p->canary_len = p->host_len = p->eff_len = 0;
}

void policy_set_vec(char ***dst, size_t *dstlen, const char *const *items, size_t n) {
    free_vec(*dst, *dstlen);
    *dst = n ? xcalloc(n, sizeof **dst) : NULL;
    for (size_t i = 0; i < n; i++) (*dst)[i] = xstrdup(items[i]);
    *dstlen = n;
}

/* A canary carrying fewer than MIN_CANARY_LENGTH alphanumerics cannot be
 * matched under the closure, so egress would report success while protecting
 * nothing. Refuse it loudly rather than degrade silently. */
int policy_validate_canaries(const policy_t *p, char *err, size_t errcap) {
    for (size_t i = 0; i < p->canary_len; i++) {
        char buf[512];
        strip_noise(p->canaries[i], buf, sizeof buf);
        if (strlen(buf) < WD_MIN_CANARY_LENGTH) {
            snprintf(err, errcap,
                     "%zu registered canary value(s) carry fewer than %d "
                     "alphanumeric characters and cannot be matched; egress "
                     "would protect nothing while reporting success",
                     (size_t)1, WD_MIN_CANARY_LENGTH);
            return -1;
        }
    }
    return 0;
}
