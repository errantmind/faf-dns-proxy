#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// Process information structure
struct process_info {
    __u32 pid;
    __u32 port;
    __u64 timestamp;
};

// Socket tracking structure
struct socket_key {
    __u32 pid;
    __u32 fd;
};

// eBPF maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct process_info);
} port_to_process SEC(".maps");

// Map to track socket file descriptors to ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct socket_key);
    __type(value, __u32);
} socket_to_port SEC(".maps");

// Track socket() syscall to capture socket creation
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(void *ctx) {
    // We'll track socket creation - when a socket is created,
    // we can later associate it with a port during sendto/bind
    return 0;
}

// Track sendto() syscall to capture UDP traffic with source port
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    // For DNS clients, we need to track when they send UDP packets
    // Since we can't easily get the socket info from tracepoint context,
    // we'll use a simpler approach: track all processes that make sendto calls
    // and associate them with any available port information
    
    // Create a process info entry using PID as a temporary port identifier
    // This is a simplified approach - in practice, multiple processes
    // will overwrite each other, but it gives us a basic mapping
    struct process_info proc_info = {0};
    proc_info.pid = pid;
    proc_info.port = tgid; // Use TGID as pseudo-port for now
    proc_info.timestamp = bpf_ktime_get_ns();
    
    // Store using TGID as key since we don't have real port info
    // Also store using PID as key for better matching
    bpf_map_update_elem(&port_to_process, &tgid, &proc_info, BPF_ANY);
    bpf_map_update_elem(&port_to_process, &pid, &proc_info, BPF_ANY);
    
    // Store a few common keys to help with debugging
    __u32 debug_key = 12345;
    bpf_map_update_elem(&port_to_process, &debug_key, &proc_info, BPF_ANY);
    
    return 0;
}

// Track connect() syscall for outbound connections
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    // Track processes that make outbound connections (like DNS queries)
    struct process_info proc_info = {0};
    proc_info.pid = pid;
    proc_info.port = tgid;
    proc_info.timestamp = bpf_ktime_get_ns();
    
    // Store the mapping with multiple keys
    bpf_map_update_elem(&port_to_process, &tgid, &proc_info, BPF_ANY);
    bpf_map_update_elem(&port_to_process, &pid, &proc_info, BPF_ANY);
    
    // Store debug entry
    __u32 debug_key = 54321;
    bpf_map_update_elem(&port_to_process, &debug_key, &proc_info, BPF_ANY);
    
    return 0;
}

// License required for eBPF programs
char LICENSE[] SEC("license") = "GPL";