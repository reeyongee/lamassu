/* toolguard.c — the one guarded-tool classifier. See core/toolguard.h for why. */
#include "toolguard.h"

#include <ctype.h>
#include <string.h>

/* Exact names. Kept in one place so a second adapter cannot fall behind. */
const char *const lamassu_egress_tools[] = {
    "send_email", "send_mail", "send_message", "send_sms", "send_dm",
    "post_message", "post_comment", "slack_post", "create_issue",
    "create_pr", "upload_file", "publish", "webhook", "http_request",
    "fetch_url", "webfetch", "websearch", "web_fetch", "web_search",
    "email", "mail", "smtp", "telegram_send", "slack_send",
    NULL
};

/* Prefixes: any verb that pushes data outward. */
const char *const lamassu_egress_prefixes[] = {
    "send_", "post_", "publish_", "upload_", "webhook_",
    NULL
};

int lamassu_tool_is_egress(const char *name) {
    if (!name || !*name) return 0;

    char low[128];
    size_t o = 0;
    for (const char *p = name; *p && o + 1 < sizeof low; p++)
        low[o++] = (char)tolower((unsigned char)*p);
    low[o] = '\0';

    for (size_t i = 0; lamassu_egress_tools[i]; i++)
        if (strcmp(low, lamassu_egress_tools[i]) == 0) return 1;

    for (size_t i = 0; lamassu_egress_prefixes[i]; i++) {
        size_t n = strlen(lamassu_egress_prefixes[i]);
        if (strncmp(low, lamassu_egress_prefixes[i], n) == 0) return 1;
    }

    /* substring: an email or webhook sender by another name */
    if (strstr(low, "email") || strstr(low, "webhook")) return 1;

    return 0;
}
