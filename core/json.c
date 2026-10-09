/* json.c — first-party minimal JSON reader/writer.
 * Lineage: new code for lamassu; JSON is first-party, no upstream port.
 *
 * The input to this module is attacker-influenced: a tool argument, a reply,
 * a socket frame. Two properties are load-bearing and preserved exactly:
 *   1. recursion is bounded (JSON_MAX_DEPTH), so hostile deep nesting is a
 *      clean parse error and never a stack overflow;
 *   2. no input, however malformed, can make the parser dereference past a
 *      NUL or return anything other than a valid tree or NULL.
 * Allocation failure is fatal everywhere else in lamassu (util.c), so the same
 * policy is used here: xcalloc/xrealloc abort rather than return NULL. */
#include "lamassu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Hostile nesting is a parse error, not a crash. 64 is far below any stack. */
#define JSON_MAX_DEPTH 64

typedef struct {
    const char *s;      /* NUL-terminated source */
    size_t      pos;
    char       *err;    /* optional caller buffer */
    size_t      errcap;
    int         depth;
} jctx_t;

/* util.c aborts on OOM; json.c keeps that deal for its own growth. */
static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("lamassu: out of memory\n", stderr); abort(); }
    return q;
}

/* First error wins: the innermost message is the most specific. */
static void set_err(jctx_t *c, const char *msg) {
    if (!c->err || c->errcap == 0) return;
    if (c->err[0] != '\0') return;
    snprintf(c->err, c->errcap, "%s", msg);
}

static void skip_ws(jctx_t *c) {
    for (;;) {
        char ch = c->s[c->pos];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') c->pos++;
        else break;
    }
}

/* ------------------------------------------------------------- builder ---- */
typedef struct { char *p; size_t len, cap; } sbuf_t;

static void sbuf_init(sbuf_t *b) {
    b->cap = 16;
    b->p = xcalloc(b->cap, 1);
    b->len = 0;
}

static void sbuf_put(sbuf_t *b, char ch) {
    if (b->len + 2 > b->cap) {
        b->cap *= 2;
        b->p = xrealloc(b->p, b->cap);
    }
    b->p[b->len++] = ch;
    b->p[b->len] = '\0';
}

static void sbuf_putn(sbuf_t *b, const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) sbuf_put(b, p[i]);
}

static void utf8_put(sbuf_t *b, uint32_t cp) {
    char out[4];
    size_t n;
    if (cp <= 0x7F) {
        out[0] = (char)cp; n = 1;
    } else if (cp <= 0x7FF) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F)); n = 2;
    } else if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F)); n = 3;
    } else {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F)); n = 4;
    }
    sbuf_putn(b, out, n);
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Consume exactly four hex digits. On failure pos is left untouched. */
static int u4(jctx_t *c, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int ch = (unsigned char)c->s[c->pos + i];
        if (ch == '\0') return -1;      /* never read past the terminator */
        int h = hexval(ch);
        if (h < 0) return -1;
        v = (v << 4) | (uint32_t)h;
    }
    c->pos += 4;
    *out = v;
    return 0;
}

/* --------------------------------------------------------------- parse ---- */
static jval_t *parse_value(jctx_t *c);

static jval_t *new_val(jtype_t t) {
    jval_t *v = xcalloc(1, sizeof *v);
    v->t = t;
    return v;
}

static int match_lit(jctx_t *c, const char *lit) {
    size_t n = strlen(lit);
    if (strncmp(c->s + c->pos, lit, n) != 0) return 0;
    c->pos += n;
    return 1;
}

static int parse_string(jctx_t *c, char **out) {
    sbuf_t b;
    c->pos++;                            /* opening quote */
    sbuf_init(&b);
    for (;;) {
        unsigned char ch = (unsigned char)c->s[c->pos];
        if (ch == '\0') {
            free(b.p);
            set_err(c, "unterminated string");
            return -1;
        }
        if (ch == '"') { c->pos++; break; }
        if (ch == '\\') {
            c->pos++;
            char e = c->s[c->pos];
            switch (e) {
            case '"':  sbuf_put(&b, '"');  c->pos++; break;
            case '\\': sbuf_put(&b, '\\'); c->pos++; break;
            case '/':  sbuf_put(&b, '/');  c->pos++; break;
            case 'b':  sbuf_put(&b, '\b'); c->pos++; break;
            case 'f':  sbuf_put(&b, '\f'); c->pos++; break;
            case 'n':  sbuf_put(&b, '\n'); c->pos++; break;
            case 'r':  sbuf_put(&b, '\r'); c->pos++; break;
            case 't':  sbuf_put(&b, '\t'); c->pos++; break;
            case 'u': {
                uint32_t cp;
                c->pos++;
                if (u4(c, &cp) != 0) {
                    free(b.p);
                    set_err(c, "invalid \\u escape");
                    return -1;
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    /* high surrogate: a low surrogate must follow, else U+FFFD */
                    if (c->s[c->pos] == '\\' && c->s[c->pos + 1] == 'u') {
                        size_t save = c->pos;
                        uint32_t lo;
                        c->pos += 2;
                        if (u4(c, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else {
                            c->pos = save;
                            cp = 0xFFFD;
                        }
                    } else {
                        cp = 0xFFFD;
                    }
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = 0xFFFD;         /* lone low surrogate */
                }
                utf8_put(&b, cp);
                break;
            }
            case '\0':
                free(b.p);
                set_err(c, "unterminated escape");
                return -1;
            default:
                free(b.p);
                set_err(c, "invalid escape");
                return -1;
            }
            continue;
        }
        if (ch < 0x20) {                 /* raw control chars must be escaped */
            free(b.p);
            set_err(c, "control character in string");
            return -1;
        }
        sbuf_put(&b, (char)ch);          /* UTF-8 passes through byte-for-byte */
        c->pos++;
    }
    *out = b.p;
    return 0;
}

static jval_t *parse_number(jctx_t *c) {
    size_t start = c->pos;
    size_t p = start;
    const char *s = c->s;
    if (s[p] == '-') p++;
    if (s[p] == '0') {
        p++;
    } else if (s[p] >= '1' && s[p] <= '9') {
        while (s[p] >= '0' && s[p] <= '9') p++;
    } else {
        set_err(c, "invalid number");
        return NULL;
    }
    if (s[p] == '.') {
        p++;
        if (!(s[p] >= '0' && s[p] <= '9')) { set_err(c, "invalid number"); return NULL; }
        while (s[p] >= '0' && s[p] <= '9') p++;
    }
    if (s[p] == 'e' || s[p] == 'E') {
        p++;
        if (s[p] == '+' || s[p] == '-') p++;
        if (!(s[p] >= '0' && s[p] <= '9')) { set_err(c, "invalid number"); return NULL; }
        while (s[p] >= '0' && s[p] <= '9') p++;
    }
    jval_t *v = new_val(JNUM);
    v->num = strtod(s + start, NULL);    /* grammar already fixed the token */
    c->pos = p;
    return v;
}

static jval_t *parse_array(jctx_t *c) {
    if (c->depth >= JSON_MAX_DEPTH) {
        set_err(c, "maximum nesting depth exceeded");
        return NULL;
    }
    jval_t *v = new_val(JARR);
    size_t cap = 0;
    c->pos++;                            /* '[' */
    c->depth++;
    skip_ws(c);
    if (c->s[c->pos] == ']') {
        c->pos++;
        c->depth--;
        return v;
    }
    for (;;) {
        jval_t *item = parse_value(c);
        if (!item) goto fail;
        if (v->len == cap) {
            cap = cap ? cap * 2 : 8;
            v->items = xrealloc(v->items, cap * sizeof *v->items);
        }
        v->items[v->len++] = item;
        skip_ws(c);
        char ch = c->s[c->pos];
        if (ch == ',') { c->pos++; skip_ws(c); continue; }
        if (ch == ']') { c->pos++; c->depth--; return v; }
        set_err(c, "expected ',' or ']'");
        goto fail;
    }
fail:
    c->depth--;
    json_free(v);
    return NULL;
}

static jval_t *parse_object(jctx_t *c) {
    if (c->depth >= JSON_MAX_DEPTH) {
        set_err(c, "maximum nesting depth exceeded");
        return NULL;
    }
    jval_t *v = new_val(JOBJ);
    size_t cap = 0;
    c->pos++;                            /* '{' */
    c->depth++;
    skip_ws(c);
    if (c->s[c->pos] == '}') {
        c->pos++;
        c->depth--;
        return v;
    }
    for (;;) {
        skip_ws(c);
        if (c->s[c->pos] != '"') { set_err(c, "expected string key"); goto fail; }
        char *key;
        if (parse_string(c, &key) != 0) goto fail;
        skip_ws(c);
        if (c->s[c->pos] != ':') {
            free(key);
            set_err(c, "expected ':'");
            goto fail;
        }
        c->pos++;
        jval_t *item = parse_value(c);
        if (!item) { free(key); goto fail; }
        if (v->len == cap) {
            cap = cap ? cap * 2 : 8;
            v->keys  = xrealloc(v->keys,  cap * sizeof *v->keys);
            v->items = xrealloc(v->items, cap * sizeof *v->items);
        }
        v->keys[v->len] = key;
        v->items[v->len] = item;
        v->len++;
        skip_ws(c);
        char ch = c->s[c->pos];
        if (ch == ',') { c->pos++; continue; }
        if (ch == '}') { c->pos++; c->depth--; return v; }
        set_err(c, "expected ',' or '}'");
        goto fail;
    }
fail:
    c->depth--;
    json_free(v);
    return NULL;
}

static jval_t *parse_value(jctx_t *c) {
    skip_ws(c);
    char ch = c->s[c->pos];
    switch (ch) {
    case '{': return parse_object(c);
    case '[': return parse_array(c);
    case '"': {
        jval_t *v = new_val(JSTR);
        if (parse_string(c, &v->str) != 0) { free(v); return NULL; }
        return v;
    }
    case 't':
        if (match_lit(c, "true")) { jval_t *v = new_val(JBOOL); v->boolean = 1; return v; }
        break;
    case 'f':
        if (match_lit(c, "false")) { jval_t *v = new_val(JBOOL); v->boolean = 0; return v; }
        break;
    case 'n':
        if (match_lit(c, "null")) return new_val(JNULL);
        break;
    default:
        if (ch == '-' || (ch >= '0' && ch <= '9')) return parse_number(c);
        break;
    }
    set_err(c, "unexpected character");
    return NULL;
}

/* ------------------------------------------------------------- public ----- */
jval_t *json_parse(const char *s, char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    if (!s) {
        if (err && errcap) snprintf(err, errcap, "%s", "null input");
        return NULL;
    }

    jctx_t c;
    c.s = s;
    c.pos = 0;
    c.err = err;
    c.errcap = errcap;
    c.depth = 0;

    skip_ws(&c);
    if (c.s[c.pos] == '\0') { set_err(&c, "empty input"); return NULL; }

    jval_t *v = parse_value(&c);
    if (!v) return NULL;

    skip_ws(&c);
    if (c.s[c.pos] != '\0') {
        set_err(&c, "trailing garbage after value");
        json_free(v);
        return NULL;
    }
    return v;
}

void json_free(jval_t *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; i++) {
        if (v->keys) free(v->keys[i]);
        json_free(v->items[i]);
    }
    free(v->keys);
    free(v->items);
    free(v->str);
    free(v);
}

const jval_t *json_get(const jval_t *obj, const char *key) {
    if (!obj || obj->t != JOBJ || !key) return NULL;
    for (size_t i = 0; i < obj->len; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->items[i];
    return NULL;
}

const char *json_str(const jval_t *obj, const char *key, const char *dflt) {
    const jval_t *v = json_get(obj, key);
    return (v && v->t == JSTR) ? v->str : dflt;
}

int json_bool(const jval_t *obj, const char *key, int dflt) {
    const jval_t *v = json_get(obj, key);
    return (v && v->t == JBOOL) ? v->boolean : dflt;
}

double json_num(const jval_t *obj, const char *key, double dflt) {
    const jval_t *v = json_get(obj, key);
    return (v && v->t == JNUM) ? v->num : dflt;
}

/* Append one char if room remains for it plus the trailing NUL. '/' is NOT
 * escaped; UTF-8 bytes pass through. */
#define JOUT(ch) do { if (i + 1 < cap) out[i++] = (char)(ch); } while (0)

void json_escape(const char *in, char *out, size_t cap) {
    if (!out || cap == 0) return;
    static const char HEXD[] = "0123456789abcdef";
    size_t i = 0;
    const unsigned char *p = (const unsigned char *)(in ? in : "");
    for (; *p; p++) {
        unsigned char ch = *p;
        switch (ch) {
        case '"':  JOUT('\\'); JOUT('"');  break;
        case '\\': JOUT('\\'); JOUT('\\'); break;
        case '\n': JOUT('\\'); JOUT('n');  break;
        case '\r': JOUT('\\'); JOUT('r');  break;
        case '\t': JOUT('\\'); JOUT('t');  break;
        case '\b': JOUT('\\'); JOUT('b');  break;
        case '\f': JOUT('\\'); JOUT('f');  break;
        default:
            if (ch < 0x20) {
                JOUT('\\'); JOUT('u'); JOUT('0'); JOUT('0');
                JOUT(HEXD[ch >> 4]); JOUT(HEXD[ch & 0xF]);
            } else {
                JOUT(ch);
            }
            break;
        }
    }
    out[i] = '\0';
}
