/* lamassu.h — umbrella interface for the fused core.
 *
 * Lineage:
 *   core/verdict.h    <- not_sandboxed/verdict.py (Finding/Severity/Decision/Verdict)
 *   core/session.h    <- not_sandboxed/context.py (Trust/Span/Origin/Context)
 *                        + struct event
 *   core/closure.h    <- not_sandboxed/normalize/views.py
 *   core/layers.h     <- not_sandboxed/layers/ (all five) + firewall.py
 *   core/policy.h     <- not_sandboxed/policy.py
 *   protocol.h        <- not_sandboxed/firewall.py render() + the local socket protocol
 *
 * Enforce at the model boundary, observe at the syscall boundary.
 * See CONTRACTS.md for the frozen specification of every type below.
 */
#ifndef LAMASSU_H
#define LAMASSU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct jval jval_t;   /* defined at the bottom of this header */

/* ---------------------------------------------------------------- budget ---
 * Bounds ported from PIP config.py. Every loop in the codebase is bounded by
 * one of these, and every exhaustion is REPORTED, never hidden. */
#define WD_MAX_VARIANT_ROUNDS   4
#define WD_MAX_VARIANTS         96
#define WD_MAX_INGRESS_VARIANTS 24
#define WD_MIN_CANARY_LENGTH    8
#define WD_MAX_DECODE_DEPTH     8
#define WD_MAX_EMBEDDED_RUNS    16
#define WD_MIN_ENCODED_LENGTH   8
#define WD_MIN_PRINTABLE_RATIO  0.85
#define WD_MAX_NORMALIZE_BYTES  65536
#define WD_MAX_EGRESS_BYTES     65536
#define WD_NONCE_BYTES          8
#define WD_AUDIT_DIGEST_CHARS   16

/* ------------------------------------------------------------- verdict ---- */
typedef enum {
    SEV_INFO = 0, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL
} severity_t;

typedef enum { DEC_ALLOW = 0, DEC_BLOCK } decision_t;

/* Declared = the harness told us. Inferred = we guessed from message roles.
 * The proxy path is ALWAYS inferred and says so (PIP weak-mode warning). */
typedef enum { PROV_DECLARED = 0, PROV_INFERRED } provenance_t;

/* Session-relative storage: findings reference session-owned strings. */
typedef struct {
    char        layer[16];
    char        rule[32];
    severity_t  severity;
    bool        invariant;      /* structural guarantee: never thresholded */
    provenance_t provenance;
    char        evidence_digest[WD_AUDIT_DIGEST_CHARS + 1];
    int         span_index;     /* -1 when not span-scoped */
    int         tainted;        /* 1 when emitted while session was tainted */
} finding_t;

typedef struct {
    finding_t *items;
    size_t     len;
    size_t     cap;
} findings_t;

void findings_init(findings_t *f);
void findings_free(findings_t *f);
int  findings_push(findings_t *f, const char *layer, const char *rule,
                   severity_t sev, bool invariant, provenance_t prov,
                   const char *evidence, int span_index);

const char *severity_name(severity_t s);
const char *decision_name(decision_t d);
const char *provenance_name(provenance_t p);

/* ------------------------------------------------------------- policy ----- */
typedef struct {
    char       policy_id[32];
    severity_t block_threshold;
    bool       strict_data;
    bool       normalize_enabled;
    bool       ingress_enabled;
    bool       provenance_enabled;
    bool       toolauth_enabled;
    bool       egress_enabled;
    char     **canaries;      size_t canary_len;
    char     **allowed_hosts; size_t host_len;
    char     **forbidden_effects; size_t eff_len;
} policy_t;

void policy_default(policy_t *p);                 /* PIP Policy() defaults */
void policy_free(policy_t *p);
void policy_set_vec(char ***dst, size_t *dstlen, const char *const *items, size_t n);
/* Refuses a canary too short to match under the closure. Returns -1 and fills
 * err; egress must not report success while protecting nothing. */
int  policy_validate_canaries(const policy_t *p, char *err, size_t errcap);
void closure_free(char **readings, size_t n);

/* decide(): any invariant => BLOCK; else max scored severity >= threshold =>
 * BLOCK; else ALLOW. Ported verbatim from policy.py decide(). */
decision_t decide(const findings_t *f, const policy_t *p);
/* escalate(): strict_data promotes STRICT_DATA_RULES to invariant=true. */
void escalate(findings_t *f, const policy_t *p);

/* ------------------------------------------------------------ sessions ---- */
typedef enum { TRUST_SYSTEM = 0, TRUST_USER, TRUST_DATA } trust_t;

typedef struct {
    char channel[32];
    char ref[64];
} origin_t;

typedef struct {
    trust_t  trust;
    origin_t origin;          /* only meaningful when trust == TRUST_DATA */
    bool     has_origin;
    char    *text;
    char     role[24];        /* harness message role, when known */
} span_t;

/* Sensor event, layout matching the sensor's struct event. */
typedef enum { EV_EXEC = 0, EV_EXIT, EV_OPEN, EV_NET } ev_kind_t;

typedef struct {
    uint64_t  ts;
    uint32_t  pid;
    uint32_t  ppid;
    ev_kind_t kind;
    char      comm[64];
    char      cmdline[512];
    char      filename[256];
    uint32_t  flags;
    int32_t   dirfd;
    uint16_t  port;
    uint8_t   addr[16];
    uint8_t   addr_len;
    int       tainted;        /* derived at emit time, never stored upstream */
} event_t;

#define WD_MAX_EVENTS   4096
#define WD_MAX_SPANS    256
#define WD_MAX_SESSIONS 64

typedef struct session {
    char      sid[64];
    char      harness[32];
    uint32_t  root_pid;
    bool      open;

    span_t    spans[WD_MAX_SPANS];
    size_t    span_len;

    origin_t  tainted_by[WD_MAX_SPANS];
    size_t    taint_len;

    finding_t findings[WD_MAX_SPANS * 4];
    size_t    finding_len;

    event_t   events[WD_MAX_EVENTS];   /* bounded ring */
    size_t    event_head;
    size_t    event_len;

    char      nonce[WD_NONCE_BYTES * 2 + 1];
    uint64_t  drop_total;
    uint64_t  upd_fail_total;
} session_t;

session_t *session_open(const char *sid, const char *harness, uint32_t root_pid);
session_t *session_find(const char *sid);
void       session_close(const char *sid);
void       session_reset(void);
void       session_event_drop(session_t *s, uint64_t n);
void       session_span_add(session_t *s, trust_t t, const char *text,
                            const origin_t *origin, const char *role);
/* Taint is DERIVED from the spans. There is no setter (context.py). */
bool       session_tainted(const session_t *s);
void       session_event_emit(session_t *s, const event_t *e);
const char *session_nonce(session_t *s);   /* lazily minted, unforgeable */

/* ------------------------------------------------------------- closure ---- */
/* Every reading of text reachable by applying all views in any order, to a
 * fixpoint, bounded by max_variants. Caller frees *out and each element. */
size_t closure_readings(const char *text, size_t max_variants, char ***out);
/* Aggressive reading: alphanumerics only (survives inserted separators). */
void   strip_noise(const char *in, char *out, size_t cap);
void   strip_separators(const char *in, char *out, size_t cap);
char  *rot13_dup(const char *in);
char  *reverse_dup(const char *in);
/* Transport decode chain: returns malloc'd peeled text or NULL if nothing
 * peeled; *depth_out receives how many layers came off. */
char  *unwrap_dup(const char *in, int *depth_out);
char  *normalize_unicode_dup(const char *in);
/* Decode encoded runs embedded inside prose (PIP embedded_decodes). */
size_t embedded_decodes(const char *text, char ***out, size_t cap);

/* -------------------------------------------------------------- layers ---- */
int layer_normalize (const span_t *sp, findings_t *out);
int layer_ingress   (const span_t *sp, const policy_t *p, findings_t *out);
int layer_provenance(const session_t *s, const span_t *sp, const policy_t *p,
                     findings_t *out);
typedef struct {
    char  name[64];
    char **arg_keys; char **arg_vals; size_t arg_len;
    char **permitted; size_t permitted_len;
    char **required;  size_t required_len;
    char **allow_keys; char **allow_vals; size_t allow_len; /* ARGS_ALLOWLISTED */
    char **effects; size_t effect_len;
    char **guards;  size_t guard_len;
    int    known;
    bool   user_confirmed;
} tool_call_t;
int layer_toolauth  (const tool_call_t *tc, const session_t *s,
                     const policy_t *p, findings_t *out);
typedef struct {
    char **canaries; size_t canary_len;
    char **allowed_hosts; size_t host_len;
} egress_ctx_t;

/* Scans prose AND every flattened tool argument (search.py render_arg). */
int layer_egress    (const char *text, const egress_ctx_t *ctx, findings_t *out);

/* Flatten a JSON argument value to text the way PIP render_arg does: a secret
 * nested inside a list or an object still leaves, so every leaf must be
 * scanned. Used by the adapters to turn tool_input into scannable text. */
void flatten_json_arg(const jval_t *v, char *out, size_t cap);

/* ------------------------------------------------------------- firewall ---- */
typedef struct {
    policy_t policy;
    egress_ctx_t egress;
} firewall_t;

void firewall_init(firewall_t *fw, const policy_t *p);
/* render(): fence every DATA span with the per-request nonce. The firewall
 * builds the prompt itself, which is what makes provenance declared. */
char *firewall_render(session_t *s, char *out, size_t cap);
/* Render, and report whether the output was truncated. A silent truncation can
 * leave an unterminated fence, so a caller that can act on it should use this. */
char *firewall_render_checked(session_t *s, char *out, size_t cap, int *truncated);
/* Full inbound inspection: normalize + ingress + provenance. */
decision_t firewall_inspect(firewall_t *fw, session_t *s, findings_t *out);
/* Outbound: toolauth + egress over prose and flattened args. */
decision_t firewall_inspect_egress(firewall_t *fw, session_t *s,
                                   const tool_call_t *tcs, size_t tc_len,
                                   const char *reply_text, findings_t *out);

/* ----------------------------------------------------------------- json ---- */
/* First-party minimal JSON. No cJSON. */
typedef enum { JNULL, JBOOL, JNUM, JSTR, JARR, JOBJ } jtype_t;
struct jval {
    jtype_t t;
    double  num;
    int     boolean;
    char   *str;                 /* JSTR */
    struct jval **items; size_t len;   /* JARR/JOBJ values */
    char  **keys;                      /* JOBJ keys */
};

jval_t *json_parse(const char *s, char *err, size_t errcap);
void    json_free(jval_t *v);
const jval_t *json_get(const jval_t *obj, const char *key);
const char   *json_str(const jval_t *obj, const char *key, const char *dflt);
int           json_bool(const jval_t *obj, const char *key, int dflt);
double        json_num(const jval_t *obj, const char *key, double dflt);
/* Append a JSON-escaped string. */
void json_escape(const char *in, char *out, size_t cap);

/* -------------------------------------------------------------- util ------ */
char  *xstrdup(const char *s);
void  *xcalloc(size_t n, size_t sz);
void   sha256_hex16(const char *in, char *out /* 17 bytes */);

#endif /* LAMASSU_H */
