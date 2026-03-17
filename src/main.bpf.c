#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "blackbox.h"

// Define the Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB Buffer
} rb SEC(".maps");

// Helper to fill common fields (PID, UID, Cgroup, Comm)
static __always_inline void fill_base_event(struct event_t *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Hook 1: Process Execution (The "Who")
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event_t *e;

    // Reserve space in Ring Buffer
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_base_event(e);
    e->type = EVENT_EXEC;
    
    // Clear network fields for safety
    e->saddr = 0; 
    e->daddr = 0; 
    e->sport = 0; 
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook 3: OOM Kill Detector (The Autonomous Trigger)
// This fires the exact millisecond the Linux kernel decides to kill a process for memory exhaustion.
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(handle_oom_kill)
{
    struct event_t *e;
    
    // Reserve space in Ring Buffer
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    fill_base_event(e);
    e->type = EVENT_OOM; // Tag it as an OOM event

    // Clear network fields
    e->saddr = 0;
    e->daddr = 0;
    e->sport = 0;
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- CRITICAL LICENSE DECLARATION ---
// This line allows your program to call bpf_get_current_task() and other helpers.
char LICENSE[] SEC("license") = "GPL";