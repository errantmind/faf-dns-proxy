#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define bpf_ntohs(x) __builtin_bswap16(x)
#define MAX_PROCESS_TREE_DEPTH 5  // Reduced for DNS monitoring performance
#define PR_SET_NAME 15

struct process_node {
    __u32 pid;
    __u8 comm[16];
} __attribute__((packed));

struct udp_packet_info {
    __u32 pid;
    __u8 comm[16];
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u64 timestamp_ns;
    __u64 processing_start_ns;  // When eBPF processing started
    __u64 processing_end_ns;    // When eBPF processing completed
    __u32 msg_len;
    __u8 flags;  // bit flags: 1=saddr_valid, 2=sport_valid, 4=daddr_valid, 8=dport_valid, 16=tree_valid
    __u8 tree_depth;
    __u8 padding[2];  // Explicit padding for alignment
    struct process_node tree[MAX_PROCESS_TREE_DEPTH];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  // Reduced for DNS-only monitoring
} rb SEC(".maps");

// Removed port_filter map - we do early DNS filtering instead

struct process_name_cache_entry {
    __u8 friendly_name[16];
    __u64 timestamp;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);  // Reduced for DNS-only monitoring
    __type(key, __u32);
    __type(value, struct process_name_cache_entry);
} process_name_cache SEC(".maps");

static __always_inline int extract_dest_info(struct sock *sk, struct msghdr *msg, 
                                           __be32 *daddr, __be16 *dport)
{
    // Method 1: For unconnected sockets, check msg_name
    if (msg) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        int msg_namelen = BPF_CORE_READ(msg, msg_namelen);
        
        if (msg_name && msg_namelen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in addr;
            if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0) {
                if (addr.sin_family == AF_INET) {
                    *daddr = addr.sin_addr.s_addr;
                    *dport = addr.sin_port;
                    return 1;
                }
            }
        }
    }
    
    // Method 2: For connected sockets, use socket structure
    __be32 sk_daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __be16 sk_dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    
    if (sk_daddr != 0) {
        *daddr = sk_daddr;
        *dport = sk_dport;
        return 2;
    }
    
    return 0;
}

static __always_inline void get_friendly_name(struct task_struct *task, __u8 friendly_name[16])
{
    __u32 pid = BPF_CORE_READ(task, tgid);
    
    // Initialize to prevent garbage data
    __builtin_memset(friendly_name, 0, 16);
    
    // Check cache for friendly name first
    struct process_name_cache_entry *cached = bpf_map_lookup_elem(&process_name_cache, &pid);
    if (cached && cached->friendly_name[0] != '\0') {
        // Use cached friendly name with safe copying
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            friendly_name[i] = cached->friendly_name[i];
            if (cached->friendly_name[i] == '\0') break;
        }
        friendly_name[15] = '\0';  // Ensure null termination
        return;
    }
    
    // Use thread group leader's comm (main process name) instead of thread name
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    if (group_leader) {
        bpf_probe_read_kernel_str(friendly_name, 16, BPF_CORE_READ(group_leader, comm));
    } else {
        // Fallback to current task comm if no group leader
        bpf_probe_read_kernel_str(friendly_name, 16, BPF_CORE_READ(task, comm));
    }
    
    // Ensure null termination
    friendly_name[15] = '\0';
}

static __always_inline int extract_process_tree(struct task_struct *task, 
                                               struct process_node tree[MAX_PROCESS_TREE_DEPTH], 
                                               __u8 *tree_depth)
{
    struct task_struct *current_task = task;
    *tree_depth = 0;
    
    // Walk up the process tree with bounded depth for verifier
    #pragma unroll
    for (int i = 0; i < MAX_PROCESS_TREE_DEPTH; i++) {
        if (!current_task)
            break;
            
        // Read current process info
        tree[i].pid = BPF_CORE_READ(current_task, tgid);
        get_friendly_name(current_task, tree[i].comm);
        (*tree_depth)++;
        
        // Move to parent
        current_task = BPF_CORE_READ(current_task, real_parent);
        
        // Stop at init (PID 1) or if we hit the same task (self-parent)
        if (!current_task || BPF_CORE_READ(current_task, tgid) <= 1)
            break;
            
        // Prevent infinite loops by checking if parent is the same as current
        if (current_task == task)
            break;
    }
    
    return (*tree_depth > 0) ? 1 : 0;
}

static __always_inline int extract_source_info(struct sock *sk, 
                                              __be32 *saddr, __be16 *sport)
{
    struct inet_sock *inet_sk = (struct inet_sock *)sk;
    
    *saddr = BPF_CORE_READ(inet_sk, inet_saddr);
    *sport = BPF_CORE_READ(inet_sk, inet_sport);
    
    return (*saddr != 0 || *sport != 0) ? 1 : 0;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    // Capture processing start time immediately
    __u64 processing_start = bpf_ktime_get_ns();
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    
    // EARLY DNS PORT FILTERING - check destination port first
    __be16 dport = 0;
    int is_dns_traffic = 0;
    
    // Quick check for DNS traffic before expensive operations
    if (msg) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            // For unconnected sockets, check msg_name destination port
            struct sockaddr_in addr;
            if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0) {
                if (addr.sin_family == AF_INET && bpf_ntohs(addr.sin_port) == 53) {
                    is_dns_traffic = 1;
                    dport = 53;
                }
            }
        }
    }
    
    if (!is_dns_traffic) {
        // For connected sockets, check socket structure
        __be16 sk_dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        if (bpf_ntohs(sk_dport) == 53) {
            is_dns_traffic = 1;
            dport = 53;
        }
    }
    
    // Exit early if not DNS traffic
    if (!is_dns_traffic)
        return 0;
    
    struct udp_packet_info *info;
    __be32 saddr = 0, daddr = 0;
    __be16 sport = 0;
    
    info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
    if (!info)
        return 0;
    
    // Initialize all fields to prevent garbage data
    __builtin_memset(info, 0, sizeof(*info));
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->timestamp_ns = bpf_ktime_get_ns();
    info->processing_start_ns = processing_start;
    info->msg_len = len;
    info->flags = 0;
    
    // Get current task for process information
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    
    // Get friendly name for current process
    get_friendly_name(current_task, info->comm);
    
    // Extract process tree information
    if (extract_process_tree(current_task, info->tree, &info->tree_depth)) {
        info->flags |= 16; // tree_valid
    } else {
        info->tree_depth = 0;
        // Tree already zeroed by memset above
    }
    
    // Extract source information
    if (extract_source_info(sk, &saddr, &sport)) {
        info->saddr = saddr;
        info->sport = bpf_ntohs(sport);
        info->flags |= 1 | 2; // saddr_valid | sport_valid
    } else {
        info->saddr = 0;
        info->sport = 0;
    }
    
    // Extract destination information (optimized for DNS)
    info->dport = 53; // We already know this is DNS traffic
    info->flags |= 8; // dport_valid
    
    // Only extract destination IP (we don't need the complex logic for port)
    if (msg) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            struct sockaddr_in addr;
            if (bpf_probe_read_user(&addr, sizeof(addr), msg_name) == 0 && addr.sin_family == AF_INET) {
                info->daddr = addr.sin_addr.s_addr;
                info->flags |= 4; // daddr_valid
            }
        }
    }
    
    if (!(info->flags & 4)) {
        // Fallback to socket structure for connected sockets
        __be32 sk_daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        if (sk_daddr != 0) {
            info->daddr = sk_daddr;
            info->flags |= 4; // daddr_valid
        } else {
            info->daddr = 0;
        }
    }
    
    // Capture processing end time
    info->processing_end_ns = bpf_ktime_get_ns();
    
    // No need for port filtering - we already filtered for DNS at the top
    bpf_ringbuf_submit(info, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl_enter(struct trace_event_raw_sys_enter* ctx) {
    // Check if this is a PR_SET_NAME operation
    int option = (int)ctx->args[0];
    if (option != PR_SET_NAME)
        return 0;
    
    __u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;  // Get TGID (main process PID)
    char *new_name = (char *)ctx->args[1];
    
    if (!new_name)
        return 0;
    
    // Create cache entry with new friendly name
    struct process_name_cache_entry entry;
    __builtin_memset(&entry, 0, sizeof(entry));
    entry.timestamp = bpf_ktime_get_ns();
    
    // Safely read the new name from user memory
    int name_len = bpf_probe_read_user_str(entry.friendly_name, sizeof(entry.friendly_name), new_name);
    if (name_len < 0)
        return 0;
    
    // Ensure null termination
    entry.friendly_name[15] = '\0';
    
    // Update the cache
    bpf_map_update_elem(&process_name_cache, &pid, &entry, BPF_ANY);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";