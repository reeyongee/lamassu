/* toolguard.h — the single definition of "this tool can push data outward".
 *
 * Design:
 *   src/not_sandboxed/tools.py (Effect, Guard) and layers/toolauth.py
 *   (_guard_findings, the NO_UNTRUSTED_INFLUENCE branch).
 *
 * Why this lives in core/ rather than being duplicated per adapter: it WAS
 * duplicated, and the two copies drifted. The hook adapter carried five exact
 * names (fetch_url, webfetch, websearch, web_fetch, web_search, email, mail,
 * smtp, telegram_send, slack_send) that the proxy's copy lacked, so on the
 * inferred-provenance proxy path a tainted session could call fetch_url with no
 * taint guard at all. Two lists that must agree are one list. Reported as H5 in
 * docs/hardening.md.
 *
 * The classifier is name-based because a hook payload carries a tool NAME and
 * not the harness's tool registry. A tool it does not know is passed through
 * unguarded, deliberately: the adapter cannot sensibly block a tool it has never
 * heard of, and shell exfiltration through no named tool is the sensor's job.
 */
#ifndef LAMASSU_TOOLGUARD_H
#define LAMASSU_TOOLGUARD_H

#include <stddef.h>

/* Returns 1 when the named tool can move data outward and must therefore be
 * refused once the session has ingested untrusted content. */
int lamassu_tool_is_egress(const char *name);

/* The names the classifier recognises, for tests and for docs. NULL-terminated. */
extern const char *const lamassu_egress_tools[];
extern const char *const lamassu_egress_prefixes[];

#endif /* LAMASSU_TOOLGUARD_H */
