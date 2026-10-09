/* lamassu_lsm.bpf.c — OPT-IN kernel-side veto.
 *
 * New development.
 * refuse, not merely observe) was named as a gap in CONTRACTS.md and README.md:
 * "The sensor observes, it does not veto: tracepoints cannot block a syscall."
 * This is the other hook family. It is deliberately NOT part of the default
 * sensor: lamassu.bpf.c stays observation-only, and this object is loaded only
 * when someone asks for a veto.
 *
 * Why the design is this small: a kernel program that can refuse a syscall is a
 * kernel program that can break the machine. The policy is therefore an explicit
 * inode allowlist-of-denials held in a map that userspace populates, not a
 * pattern match over paths inside the kernel. There is no string parsing here,
 * no path walking, and nothing that can cost unbounded verifier state. If the
 * inode is not in the map, the program returns 0 and the kernel's normal
 * permission path continues untouched.
 *
 * Return convention: 0 allows, a negative errno denies. -1 is -EPERM.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* LSM programs require a GPL-compatible license. */
char LICENSE[] SEC("license") = "GPL";

/* Inodes userspace has asked us to refuse. Populated by lamassu-veto, never by
 * the kernel program itself. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} deny_inodes SEC(".maps");

/* A refusal is a security event, so it goes on the same kind of ring the sensor
 * uses: the veto is observable, not silent. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} veto_events SEC(".maps");

struct veto_event {
    __u64 ts;
    __u64 ino;
    __u32 pid;
    __s32 ret;
    char comm[16];
};

SEC("lsm/file_open")
int BPF_PROG(lamassu_veto_file_open, struct file *file)
{
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);

    __u8 *deny = bpf_map_lookup_elem(&deny_inodes, &ino);
    if (!deny)
        return 0;                       /* nothing to say about this file */

    struct veto_event *e = bpf_ringbuf_reserve(&veto_events, sizeof(*e), 0);
    if (e) {
        e->ts = bpf_ktime_get_ns();
        e->ino = ino;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->ret = -1;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return -1;                          /* -EPERM: refuse the open */
}
