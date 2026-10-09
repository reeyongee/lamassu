/* lamassu-load — put the sensor object through the REAL kernel BPF verifier and
 * capture the verifier's own output, per program.
 *
 * New development.
 * finding in docs/lineage/lamassu.bpf.c.md — for the project's whole life the
 * verifier was reported as NEVER RUN (macOS has no eBPF). This is the tool that
 * ran it, and verify-linux.sh re-runs it so the claim stays true rather than
 * becoming a stale assertion.
 *
 *   lamassu-load <obj> [each] [log_level]
 *
 * "each" isolates one program at a time. That is necessary, not stylistic:
 * libbpf reuses a single kernel-log buffer, so a whole-object load leaves you
 * only the LAST program's log. Isolation is the only way to get a per-program
 * verdict, and the verifier's own "processed N insns" summary is the artifact
 * worth keeping.
 *
 * On ENOSPC: BPF_PROG_LOAD returns -ENOSPC both when the verifier exhausts its
 * complexity budget AND when the log buffer is too small for the requested
 * verbosity. Those are opposite conclusions — "rejected" vs "cannot even print
 * the log" — so this tool re-asks with logging off before it accuses the
 * verifier of anything.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/utsname.h>

#define BUFSZ (64u << 20)                  /* 64 MiB: level-2 logs are enormous */
static char *g_buf;
static FILE *g_log;

/* libbpf_print_fn_t is (level, fmt, va_list) — three args. A four-arg callback
 * cast into it writes through a garbage FILE* and segfaults. */
static int log_to(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    (void)lvl;
    va_list cp;
    if (g_log) { va_copy(cp, ap); vfprintf(g_log, fmt, cp); va_end(cp); }
    return vfprintf(stdout, fmt, ap);
}

/* The verifier's own complexity summary — the strongest single artifact, because
 * it is the kernel's number, not ours. */
static const char *summary(const char *log) {
    static char line[512];
    const char *best = NULL, *p = log;
    while ((p = strstr(p, "processed ")) != NULL) { best = p; p++; }
    if (!best) return NULL;
    const char *nl = strchr(best, '\n');
    size_t n = nl ? (size_t)(nl - best) : strlen(best);
    if (n >= sizeof line) n = sizeof line - 1;
    memcpy(line, best, n); line[n] = '\0';
    return line;
}

static struct bpf_object *open_with_log(const char *path, int level) {
    struct bpf_object_open_opts o;
    memset(&o, 0, sizeof o);
    o.sz = sizeof o;
    o.kernel_log_buf = g_buf;
    o.kernel_log_size = BUFSZ;
    o.kernel_log_level = level;
    return bpf_object__open_file(path, &o);
}

static int load_whole(const char *path, int level) {
    memset(g_buf, 0, BUFSZ);
    struct bpf_object *obj = open_with_log(path, level);
    long e = libbpf_get_error(obj);
    if (e) { printf("open failed: %s\n", strerror(-e)); return 1; }

    e = bpf_object__load(obj);
    if (e == -ENOSPC && level > 0) {
        printf("[inconclusive] -ENOSPC with logging on. That can mean the verifier\n"
               "rejected it, OR that the log buffer was too small. Re-asking with\n"
               "logging OFF to tell the two apart.\n");
        bpf_object__close(obj);
        return load_whole(path, 0);
    }
    if (e) { printf("LOAD FAILED: %s (errno %ld)\n", strerror(-e), -e); return 1; }

    printf("LOAD OK — the kernel verifier accepted every program\n");
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj)
        printf("  loaded %-24s fd=%d\n", bpf_program__name(p), bpf_program__fd(p));
    const char *s = summary(g_buf);
    if (s) printf("verifier: %s\n", s);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <obj> [each] [log_level]\n", argv[0]); return 2; }

    int each = 0, level = 1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "each") == 0) each = 1;
        else level = atoi(argv[i]);
    }

    struct utsname u;
    if (uname(&u) == 0) printf("kernel: %s %s %s\n", u.sysname, u.release, u.machine);
    printf("btf: %s\n", access("/sys/kernel/btf/vmlinux", R_OK) == 0 ? "present" : "MISSING");

    g_buf = calloc(1, BUFSZ);
    if (!g_buf) { fputs("oom\n", stderr); return 2; }
    g_log = fopen("/tmp/verifier.log", "w");
    libbpf_set_print(log_to);

    if (!each) {
        printf("\n--- whole-object load, log level %d ---\n", level);
        int rc = load_whole(argv[1], level);
        if (g_buf[0]) fputs(g_buf, g_log);
        return rc;
    }

    struct bpf_object *probe = bpf_object__open_file(argv[1], NULL);
    long e = libbpf_get_error(probe);
    if (e) { fprintf(stderr, "open failed: %s\n", strerror(-e)); return 1; }
    char names[32][64];
    int n = 0;
    struct bpf_program *p;
    bpf_object__for_each_program(p, probe)
        if (n < 32) snprintf(names[n++], sizeof names[0], "%s", bpf_program__name(p));
    bpf_object__close(probe);
    printf("programs: %d\n\n", n);

    int failures = 0;
    for (int i = 0; i < n; i++) {
        memset(g_buf, 0, BUFSZ);
        struct bpf_object *obj = open_with_log(argv[1], level);
        if (libbpf_get_error(obj)) { printf("%-24s OPEN FAILED\n", names[i]); failures++; continue; }
        bpf_object__for_each_program(p, obj)
            bpf_program__set_autoload(p, strcmp(bpf_program__name(p), names[i]) == 0);

        long err = bpf_object__load(obj);
        const char *s = summary(g_buf);

        if (err == -ENOSPC && level > 0) {
            bpf_object__close(obj);
            struct bpf_object_open_opts o2;
            memset(&o2, 0, sizeof o2);
            o2.sz = sizeof o2;
            o2.kernel_log_level = 0;
            obj = bpf_object__open_file(argv[1], &o2);
            bpf_object__for_each_program(p, obj)
                bpf_program__set_autoload(p, strcmp(bpf_program__name(p), names[i]) == 0);
            long e2 = bpf_object__load(obj);
            if (e2 == 0)
                printf("%-24s ACCEPTED   (level-%d log exceeded %u MiB; confirmed with logging off)\n",
                       names[i], level, BUFSZ >> 20);
            else { printf("%-24s REJECTED: %s\n", names[i], strerror(-e2)); failures++; }
        } else if (err) {
            printf("%-24s REJECTED: %s\n", names[i], strerror(-err));
            failures++;
        } else {
            printf("%-24s ACCEPTED   %s\n", names[i], s ? s : "(no complexity summary)");
        }

        char fn[160];
        snprintf(fn, sizeof fn, "/tmp/verifier-%.48s.log", names[i]);
        FILE *f = fopen(fn, "w");
        if (f) { if (g_buf[0]) fputs(g_buf, f); fclose(f); }
        bpf_object__close(obj);
    }
    printf("\n%d programs, %d rejected\n", n, failures);
    return failures ? 1 : 0;
}
