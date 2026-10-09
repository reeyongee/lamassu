/* lamassu-observe — attach the observer programs and read the ring.
 *
 * New development.
 * the sensor's story. Everything else about lamassu.bpf.c was established —
 * verified by docs/verifier/ — but NOTHING ever attached it and drained its ring,
 * so the project could prove the object loads and could not prove it observes.
 * This is that half.
 *
 *   lamassu-observe <obj> [seconds]
 *
 * Attaches every tracepoint/kprobe program and prints each event as it arrives.
 * Run as root inside a Linux VM; macOS has no eBPF at all.
 *
 * The ring must be attached BEFORE the events are provoked: libbpf's
 * ring_buffer__new begins consumption at the producer's current position, so a
 * reader created afterwards silently misses everything already emitted. Measured
 * while building the veto tool, and it applies equally here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Mirror of `struct event` in sensor/lamassu.bpf.c. The wire layout must match
 * exactly — that is why there is no local state folded into this struct. */
struct event {
    unsigned int kind, pid, ppid, exit_code, sig;
    unsigned long long duration_ns, ts;
    unsigned int flags;         /* OPEN: open(2) flags */
    int dirfd;                  /* OPEN: openat(2) dirfd, before family in the kernel */
    unsigned int family;        /* CONNECT/LISTEN: AF_INET | AF_INET6 */
    unsigned int port;
    unsigned char addr[16];
    char comm[16];
    char filename[256];
    char cmdline[512];
};

static const char *KIND[] = { "EXEC", "EXIT", "OPEN", "NET" };
static unsigned long long g_count;
static int g_drop_total;

static int quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stdout, fmt, ap);
}

/* Copy a file so the probe can carry a needle-matching basename. */
static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
    fclose(in);
    if (fclose(out) != 0) return -1;
    chmod(dst, 0755);
    return 0;
}

static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < sizeof(struct event)) {
        fprintf(stderr, "short event: %zu < %zu\n", len, sizeof(struct event));
        return 0;
    }
    struct event e;
    memcpy(&e, data, sizeof e);
    g_count++;

    const char *k = e.kind < 4 ? KIND[e.kind] : "?";
    /* Every read of a kernel-filled char array is precision-bounded. The BPF side
     * writes into fixed arrays with bpf_probe_read_user_str / bpf_get_current_comm
     * and does not guarantee a terminator when the source fills the buffer; an
     * unbounded %s walks off the struct and the stack protector aborts the process.
     * That failure was observed, not hypothesised. */
    printf("%-5s pid=%-6u ppid=%-6u comm=%.16s", k, e.pid, e.ppid, e.comm);
    if (e.kind == 0)      printf(" exec=%.512s", e.cmdline[0] ? e.cmdline : e.filename);
    else if (e.kind == 1) printf(" code=%u sig=%u dur=%llums", e.exit_code, e.sig,
                                 (unsigned long long)(e.duration_ns / 1000000ULL));
    else if (e.kind == 2) printf(" open=%.256s dirfd=%d", e.filename, e.dirfd);
    else                  printf(" net port=%u family=%u", e.port, e.family);
    printf("\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <obj> [seconds]\n", argv[0]); return 2; }
    int secs = argc > 2 ? atoi(argv[2]) : 3;

    libbpf_set_print(quiet);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    long e = libbpf_get_error(obj);
    if (e) { fprintf(stderr, "open: %s\n", strerror(-e)); return 1; }

    e = bpf_object__load(obj);
    if (e) { fprintf(stderr, "load: %s (errno %ld)\n", strerror(-e), -e); return 1; }
    printf("loaded %s\n", argv[1]);

    struct bpf_map *ring = bpf_object__find_map_by_name(obj, "events");
    if (!ring) { fprintf(stderr, "no 'events' ring map\n"); return 1; }

    /* Attach the ring FIRST, so nothing emitted after this point is missed. */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ring), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }
    printf("ring attached\n");

    int attached = 0;
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        struct bpf_link *l = bpf_program__attach(p);
        long ae = libbpf_get_error(l);
        if (ae) { printf("  attach %-24s FAILED: %s\n", bpf_program__name(p), strerror(-ae)); continue; }
        attached++;
    }
    printf("attached %d programs\n", attached);
    if (!attached) { fprintf(stderr, "nothing attached\n"); return 1; }

    printf("\n--- observing for %ds ---\n", secs);
    for (int i = 0; i < secs * 10; i++) {
        ring_buffer__poll(rb, 100);
        if (i == 2) {          /* provoke activity AFTER we are listening */
            /* The probe must match what the sensor is WATCHING. The shipping
             * object is membership-gated: exec_common emits only when the parent
             * is tracked, this tgid is tracked, or the program name matches the
             * needle (default "claude"). Provoking with /bin/echo therefore
             * produces nothing on a correct object, which is what made this look
             * broken when it was not. Copy the probe to a needle-matching name
             * and exec that, so the test exercises the real path. */
            const char *probe = "/tmp/lamassu-needle-probe/claude-lamassu-probe";
            mkdir("/tmp/lamassu-needle-probe", 0755);
            copy_file("/bin/echo", probe);
            if (fork() == 0) { execl(probe, "claude-lamassu-probe", "lamassu-observe-probe", (char *)NULL); _exit(127); }
            int st; wait(&st);
            FILE *f = fopen("/tmp/lamassu-observe-probe.txt", "w");
            if (f) { fputs("probe\n", f); fclose(f); }
            if (system("true") != 0) { /* probe only; failure is not meaningful */ }
        }
    }

    /* Drop accounting: whatever the ring refused is a number, not a silence.
     * `drop_total` is declared as a plain __u64 global in the BPF source, not as
     * a map, so the loader cannot look it up by that name — libbpf lifts globals
     * into an auto-created .bss/.data map named after the object. Find it by
     * convention and read the first u64, which is where the sole global lands.
     * If the convention ever changes this prints the map list instead of lying. */
    struct bpf_map *bss = NULL;
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        const char *n = bpf_map__name(m);
        if (n && (strstr(n, ".bss") || strstr(n, ".data"))) bss = m;
    }
    if (bss) {
        /* The .bss map holds EVERY global in the program, not just drop_total —
         * including the __used event-type anchor the BPF source keeps for BTF.
         * Reading into an 8-byte buffer overflows the stack (observed: the stack
         * protector aborted the process). Size the destination from the map. */
        unsigned int vsz = bpf_map__value_size(bss);
        unsigned char *buf = calloc(1, vsz ? vsz : 8);
        unsigned int key = 0;
        if (buf && bpf_map_lookup_elem(bpf_map__fd(bss), &key, buf) == 0)
            g_drop_total = *(unsigned long long *)buf;   /* drop_total is the first u64 */
        else
            printf("note: could not read %s for drop_total\n", bpf_map__name(bss));
        free(buf);
    } else {
        printf("note: no .bss/.data map; maps present:\n");
        bpf_object__for_each_map(m, obj) printf("        %s (type %d)\n", bpf_map__name(m), bpf_map__type(m));
    }

    printf("\nevents=%llu drop_total=%d\n", g_count, g_drop_total);
    return g_count > 0 ? 0 : 1;
}
