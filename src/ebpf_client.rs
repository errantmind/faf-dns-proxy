//! eBPF-based client identification for ultra-fast process lookup
//! 
//! This module provides microsecond-latency client identification using eBPF
//! to track socket→process mappings in kernel space, with graceful fallback
//! to the existing netlink/procfs approach if eBPF is unavailable.

#[cfg(target_os = "linux")]
use aya::{include_bytes_aligned, Bpf, BpfLoader, maps::HashMap as BpfHashMap, programs::TracePoint};

/// Process information structure matching the eBPF program
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
    pub port: u32,
    pub timestamp: u64,
}

// Required for eBPF map operations
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for ProcessInfo {}

/// eBPF-based client identifier with fallback
pub struct EbpfClientIdentifier {
    #[cfg(target_os = "linux")]
    bpf_program: Option<Bpf>,
    fallback_enabled: bool,
}

impl EbpfClientIdentifier {
    /// Initialize eBPF client identifier with fallback
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            // Try to load the eBPF program
            match Self::load_ebpf_program() {
                Ok(bpf) => {
                    EbpfClientIdentifier {
                        bpf_program: Some(bpf),
                        fallback_enabled: true,
                    }
                }
                Err(_) => {
                    EbpfClientIdentifier {
                        bpf_program: None,
                        fallback_enabled: true,
                    }
                }
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            EbpfClientIdentifier {
                fallback_enabled: true,
            }
        }
    }
    
    /// Load the eBPF program from the compiled object
    #[cfg(target_os = "linux")]
    fn load_ebpf_program() -> Result<Bpf, Box<dyn std::error::Error>> {
        // Include the compiled eBPF bytecode
        const EBPF_PROGRAM: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/socket_tracker"));
        
        // Load the eBPF program with BTF handling
        let mut bpf = BpfLoader::new()
            .btf(None) // Disable BTF for now to avoid BTF parsing errors
            .load(EBPF_PROGRAM)
            .map_err(|e| format!("Failed to load eBPF program: {}", e))?;
        
        // Get and attach the tracepoint programs with error handling
        if let Some(socket_program) = bpf.program_mut("trace_socket_enter") {
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(socket_program) {
                let _ = program.load();
                let _ = program.attach("syscalls", "sys_enter_socket");
            }
        }
        
        if let Some(sendto_program) = bpf.program_mut("trace_sendto_enter") {
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(sendto_program) {
                let _ = program.load();
                let _ = program.attach("syscalls", "sys_enter_sendto");
            }
        }
        
        if let Some(connect_program) = bpf.program_mut("trace_connect_enter") {
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(connect_program) {
                let _ = program.load();
                let _ = program.attach("syscalls", "sys_enter_connect");
            }
        }
        
        Ok(bpf)
    }
    
    /// Fast O(1) lookup for process info by client port
    /// Falls back to netlink/procfs if eBPF unavailable
    /// Returns (process_stat, method_used)
    pub fn get_client_info(&self, client_addr: &std::net::SocketAddrV4) -> (Option<procfs::process::Stat>, &'static str) {
        #[cfg(target_os = "linux")]
        {
            if let Some(ref bpf) = self.bpf_program {
                // Try eBPF lookup first
                if let Some(stat) = self.ebpf_lookup(bpf, client_addr) {
                    return (Some(stat), "EBPF");
                }
            }
        }
        
        // Fall back to netlink/procfs method
        if self.fallback_enabled {
            (self.fallback_lookup(client_addr), "FALLBACK")
        } else {
            (None, "FALLBACK")
        }
    }
    
    /// eBPF-based lookup using the loaded BPF program
    #[cfg(target_os = "linux")]
    fn ebpf_lookup(&self, bpf: &Bpf, client_addr: &std::net::SocketAddrV4) -> Option<procfs::process::Stat> {
        // Get the BPF map
        let map: BpfHashMap<&aya::maps::MapData, u32, ProcessInfo> = match bpf.map("port_to_process") {
            Some(map) => map.try_into().ok()?,
            None => return None,
        };
        
        // First try exact port match
        let port = client_addr.port() as u32;
        if let Ok(process_info) = map.get(&port, 0) {
            if let Ok(process) = procfs::process::Process::new(process_info.pid as i32) {
                if let Ok(stat) = process.stat() {
                    return Some(stat);
                }
            }
        }
        
        // If exact port doesn't work, find the most recent process
        let mut best_match: Option<ProcessInfo> = None;
        let mut newest_timestamp = 0;
        
        // Iterate through the map to find the most recent entry by timestamp
        for result in map.iter() {
            if let Ok((_, process_info)) = result {
                // Find the entry with the highest timestamp (most recent)
                if process_info.timestamp > newest_timestamp {
                    newest_timestamp = process_info.timestamp;
                    best_match = Some(process_info);
                }
            }
        }
        
        if let Some(process_info) = best_match {
            if let Ok(process) = procfs::process::Process::new(process_info.pid as i32) {
                return process.stat().ok();
            }
        }
        
        None
    }
    
    /// Fallback lookup using existing netlink/procfs method
    #[cfg(target_os = "linux")]
    fn fallback_lookup(&self, client_addr: &std::net::SocketAddrV4) -> Option<procfs::process::Stat> {
        // Use existing implementation from inspect_client.rs
        let socket_info = crate::inspect_client::get_socket_info(client_addr)?;
        crate::inspect_client::find_pid_by_socket_inode(socket_info.header.inode as u64)
    }
    
    #[cfg(not(target_os = "linux"))]
    fn fallback_lookup(&self, _client_addr: &std::net::SocketAddrV4) -> Option<procfs::process::Stat> {
        None // Client identification not supported on non-Linux
    }
    
    /// Check if eBPF is active (for diagnostics)
    pub fn is_ebpf_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.bpf_program.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

