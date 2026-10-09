/* Minimal vmlinux.h for the BPF SYNTAX GATE only.
   Contains just the kernel types/fields the sensor BPF program references.
   This proves the C parses. It is NOT a real BTF dump and CANNOT prove the
   BPF verifier accepts the bytecode -- impossible on macOS (no BPF, no Linux). */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

/* libbpf normally sources these from BTF; the gate needs them declared. */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_RINGBUF = 27,
};
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

/* arm64: bpf_tracing.h casts to this and indexes ->regs[N] */
/* A kprobe's context IS a struct pt_regs. bpf_tracing.h casts to
   struct user_pt_regs on arm64, but the verifier sizes the program's argument
   from struct pt_regs itself, so it must be a COMPLETE type here — a forward
   declaration gives "arg#0 reference type('FWD pt_regs') size cannot be
   determined" and the load fails with EPERM. Same layout on arm64. */
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};

struct user_pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};

struct __sk_buff { unsigned int len; };

struct in6_addr {
    union {
        __u8 u6_addr8[16];
    } in6_u;
};

struct sock_common {
    __u16 skc_family;
    __be16 skc_dport;
    __be32 skc_daddr;
    __be16 skc_num;
    __be32 skc_rcv_saddr;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
    struct sock_common __sk_common;
};

/* Types referenced by the opt-in LSM veto program (sensor/lamassu_lsm.bpf.c).
   CO-RE resolves the real field offsets from the kernel's BTF at load time; only
   the names have to exist here for the relocations to be generated. */
struct inode {
    unsigned long i_ino;
};

struct file {
    struct inode *f_inode;
};

struct socket {
    struct sock *sk;
};

struct signal_struct {
    unsigned int nr_threads;
};

struct task_struct {
    struct task_struct *real_parent;
    int pid;
    int tgid;
    unsigned int exit_code;
    struct signal_struct *signal;   /* real task_struct holds a POINTER here */
    char comm[16];
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_template {
    __u64 unused;
    char comm[16];
    int pid;
};

#endif /* __VMLINUX_H__ */
