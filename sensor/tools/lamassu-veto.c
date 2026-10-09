/* lamassu-veto — load the opt-in LSM program and demonstrate a real refusal.
 *
 * New development.
 * hard boundary — "the sensor observes, it does not veto: tracepoints cannot
 * block a syscall" — and a boundary is only meaningful if the other side of it
 * has been tried. This is the other side.
 *
 *   lamassu-veto <obj> <target-file>
 *
 * It proves the veto by attempting the syscall rather than by asserting it:
 *   1. load + attach the LSM program
 *   2. populate the deny map with the target's inode
 *   3. open(target)          -> must fail with EPERM
 *   4. open(/etc/hostname)   -> must still succeed (the veto is targeted, not global)
 *   5. read one record off the veto ring, so the refusal is observable too
 *
 * A demonstration that only checked step 3 would pass against a program that
 * denied everything. The negative control in step 4 is what makes it a proof.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    if (lvl == LIBBPF_DEBUG) return 0;
    return vfprintf(stdout, fmt, ap);
}

/* The veto event, as delivered by the ring. A ringbuf is polled, never looked up.
 * This layout must match `struct veto_event` in sensor/lamassu_lsm.bpf.c exactly.
 * The first version of this file folded a `seen` flag into the struct and guarded
 * with `len >= sizeof(struct) - sizeof(int)`; the struct then padded to 48 while
 * the kernel sends 40, so the guard was always false and every event was silently
 * discarded. Keeping the wire layout and the local state as separate objects
 * removes the trap. */
struct veto_event {
    unsigned long long ts, ino;
    unsigned int pid;
    int ret;
    char comm[16];
};
static struct veto_event g_ev;
static int g_seen;

static int on_veto(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len >= sizeof(struct veto_event)) {
        memcpy(&g_ev, data, sizeof g_ev);
        g_seen = 1;
    }
    return 0;
}

static int try_open(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <obj> <target-file>\n", argv[0]); return 2; }

    libbpf_set_print(quiet);

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    long e = libbpf_get_error(obj);
    if (e) { fprintf(stderr, "open: %s\n", strerror(-e)); return 1; }

    e = bpf_object__load(obj);
    if (e) { fprintf(stderr, "load: %s (errno %ld)\n", strerror(-e), -e); return 1; }
    printf("loaded %s\n", argv[1]);

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lamassu_veto_file_open");
    if (!prog) { fprintf(stderr, "program lamassu_veto_file_open not found\n"); return 1; }

    struct bpf_link *link = bpf_program__attach(prog);
    e = libbpf_get_error(link);
    if (e) { fprintf(stderr, "attach: %s (errno %ld) - is bpf LSM active?\n", strerror(-e), -e); return 1; }
    printf("attached lsm/file_open\n");

    struct bpf_map *dm = bpf_object__find_map_by_name(obj, "deny_inodes");
    struct bpf_map *rm = bpf_object__find_map_by_name(obj, "veto_events");
    if (!dm || !rm) { fprintf(stderr, "maps not found\n"); return 1; }
    int dmfd = bpf_map__fd(dm);

    struct stat st;
    if (stat(argv[2], &st) != 0) { perror("stat target"); return 1; }
    unsigned long long ino = (unsigned long long)st.st_ino;
    printf("target %s inode=%llu\n", argv[2], ino);

    unsigned char one = 1;
    if (bpf_map_update_elem(dmfd, &ino, &one, BPF_ANY) != 0) { perror("map update"); return 1; }
    printf("deny-list populated with 1 inode\n\n");

    /* Attach the ring BEFORE generating any events. libbpf's ring_buffer__new
     * begins consumption at the producer's current position, so a reader created
     * after the fact sees nothing that happened earlier. Measured, not assumed:
     * with the reader created first this reports 1 event; created afterwards it
     * reports 0 against the same refusing syscall. */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rm), on_veto, NULL, NULL);
    if (!rb) fprintf(stderr, "ring_buffer__new failed\n");

    /* 3. the refusal */
    int cr = try_open(argv[2]);
    if (cr == -EPERM) printf("PASS  open(%s) refused with EPERM\n", argv[2]);
    else              printf("FAIL  open(%s) returned %d (%s), expected -EPERM\n",
                            argv[2], cr, cr ? strerror(-cr) : "success");

    /* 4. the negative control - the veto must be targeted, not global */
    int gr = try_open("/etc/hostname");
    if (gr == 0)      printf("PASS  open(/etc/hostname) still succeeds (veto is targeted)\n");
    else              printf("FAIL  open(/etc/hostname) returned %d (%s) - the veto is too broad\n",
                            gr, strerror(-gr));

    /* 5. the veto is observable on the ring, not silent.
     * A ringbuf is NOT a map: bpf_map_lookup_and_delete_elem does nothing useful
     * on one. It is consumed by polling, via libbpf's ring_buffer API. */
    if (rb) {
        for (int i = 0; i < 20 && !g_seen; i++) ring_buffer__poll(rb, 100);
        if (g_seen)
            printf("PASS  veto event on the ring: pid=%u comm=%.16s ret=%d ino=%llu\n",
                   g_ev.pid, g_ev.comm, g_ev.ret, g_ev.ino);
        else
            printf("note  no veto event observed on the ring\n");
        ring_buffer__free(rb);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return (cr == -EPERM && gr == 0) ? 0 : 1;
}
