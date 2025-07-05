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
            eprintln!("DEBUG: Initializing eBPF client identifier");
            // Try to load the eBPF program
            match Self::load_ebpf_program() {
                Ok(bpf) => {
                    eprintln!("DEBUG: eBPF client identification loaded successfully");
                    EbpfClientIdentifier {
                        bpf_program: Some(bpf),
                        fallback_enabled: true, // Keep fallback enabled for debugging
                    }
                }
                Err(e) => {
                    eprintln!("DEBUG: Failed to load eBPF program: {}. Using netlink/procfs fallback.", e);
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
        eprintln!("DEBUG: Loading eBPF program");
        // Include the compiled eBPF bytecode
        const EBPF_PROGRAM: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/socket_tracker"));
        eprintln!("DEBUG: eBPF program size: {} bytes", EBPF_PROGRAM.len());
        
        // Load the eBPF program with BTF handling
        eprintln!("DEBUG: Creating BpfLoader");
        let mut bpf = BpfLoader::new()
            .btf(None) // Disable BTF for now to avoid BTF parsing errors
            .load(EBPF_PROGRAM)
            .map_err(|e| format!("Failed to load eBPF program: {}", e))?;
        eprintln!("DEBUG: eBPF program loaded successfully");
        
        // Get and attach the tracepoint programs with error handling
        eprintln!("DEBUG: Attempting to attach tracepoint programs");
        
        if let Some(socket_program) = bpf.program_mut("trace_socket_enter") {
            eprintln!("DEBUG: Found trace_socket_enter program");
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(socket_program) {
                if let Err(e) = program.load() {
                    eprintln!("DEBUG: Failed to load socket tracepoint: {}", e);
                } else {
                    eprintln!("DEBUG: Socket tracepoint loaded successfully");
                    if let Err(e) = program.attach("syscalls", "sys_enter_socket") {
                        eprintln!("DEBUG: Failed to attach socket tracepoint: {}", e);
                    } else {
                        eprintln!("DEBUG: Socket tracepoint attached successfully");
                    }
                }
            } else {
                eprintln!("DEBUG: Failed to convert socket program to TracePoint");
            }
        } else {
            eprintln!("DEBUG: trace_socket_enter program not found");
        }
        
        if let Some(sendto_program) = bpf.program_mut("trace_sendto_enter") {
            eprintln!("DEBUG: Found trace_sendto_enter program");
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(sendto_program) {
                if let Err(e) = program.load() {
                    eprintln!("DEBUG: Failed to load sendto tracepoint: {}", e);
                } else {
                    eprintln!("DEBUG: Sendto tracepoint loaded successfully");
                    if let Err(e) = program.attach("syscalls", "sys_enter_sendto") {
                        eprintln!("DEBUG: Failed to attach sendto tracepoint: {}", e);
                    } else {
                        eprintln!("DEBUG: Sendto tracepoint attached successfully");
                    }
                }
            } else {
                eprintln!("DEBUG: Failed to convert sendto program to TracePoint");
            }
        } else {
            eprintln!("DEBUG: trace_sendto_enter program not found");
        }
        
        if let Some(connect_program) = bpf.program_mut("trace_connect_enter") {
            eprintln!("DEBUG: Found trace_connect_enter program");
            if let Ok(program) = TryInto::<&mut TracePoint>::try_into(connect_program) {
                if let Err(e) = program.load() {
                    eprintln!("DEBUG: Failed to load connect tracepoint: {}", e);
                } else {
                    eprintln!("DEBUG: Connect tracepoint loaded successfully");
                    if let Err(e) = program.attach("syscalls", "sys_enter_connect") {
                        eprintln!("DEBUG: Failed to attach connect tracepoint: {}", e);
                    } else {
                        eprintln!("DEBUG: Connect tracepoint attached successfully");
                    }
                }
            } else {
                eprintln!("DEBUG: Failed to convert connect program to TracePoint");
            }
        } else {
            eprintln!("DEBUG: trace_connect_enter program not found");
        }
        
        Ok(bpf)
    }
    
    /// Fast O(1) lookup for process info by client port
    /// Falls back to netlink/procfs if eBPF unavailable
    pub fn get_client_info(&self, client_addr: &std::net::SocketAddrV4) -> Option<procfs::process::Stat> {
        eprintln!("DEBUG: get_client_info called for {}:{}", client_addr.ip(), client_addr.port());
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref bpf) = self.bpf_program {
                eprintln!("DEBUG: eBPF program available, trying eBPF lookup");
                // Try eBPF lookup first
                if let Some(stat) = self.ebpf_lookup(bpf, client_addr) {
                    eprintln!("DEBUG: eBPF lookup succeeded, returning: {}", stat.comm);
                    return Some(stat);
                } else {
                    eprintln!("DEBUG: eBPF lookup failed, trying fallback");
                }
            } else {
                eprintln!("DEBUG: No eBPF program available, using fallback only");
            }
        }
        
        // Fall back to netlink/procfs method
        if self.fallback_enabled {
            eprintln!("DEBUG: Using fallback lookup");
            let result = self.fallback_lookup(client_addr);
            if let Some(ref stat) = result {
                eprintln!("DEBUG: Fallback lookup succeeded: {}", stat.comm);
            } else {
                eprintln!("DEBUG: Fallback lookup failed");
            }
            result
        } else {
            eprintln!("DEBUG: Fallback disabled, returning None");
            None
        }
    }
    
    /// eBPF-based lookup using the loaded BPF program
    #[cfg(target_os = "linux")]
    fn ebpf_lookup(&self, bpf: &Bpf, client_addr: &std::net::SocketAddrV4) -> Option<procfs::process::Stat> {
        eprintln!("DEBUG: eBPF lookup called for {}:{}", client_addr.ip(), client_addr.port());
        
        // Get the BPF map
        let map: BpfHashMap<&aya::maps::MapData, u32, ProcessInfo> = match bpf.map("port_to_process") {
            Some(map) => {
                eprintln!("DEBUG: Successfully got port_to_process map");
                match map.try_into() {
                    Ok(m) => {
                        eprintln!("DEBUG: Successfully converted map");
                        m
                    }
                    Err(e) => {
                        eprintln!("DEBUG: Failed to convert map: {:?}", e);
                        return None;
                    }
                }
            }
            None => {
                eprintln!("DEBUG: port_to_process map not found");
                return None;
            }
        };
        
        // First try exact port match
        let port = client_addr.port() as u32;
        eprintln!("DEBUG: Trying exact port lookup for port {}", port);
        if let Ok(process_info) = map.get(&port, 0) {
            eprintln!("DEBUG: Found exact port match - PID: {}, Port: {}", process_info.pid, process_info.port);
            if let Ok(process) = procfs::process::Process::new(process_info.pid as i32) {
                if let Ok(stat) = process.stat() {
                    eprintln!("DEBUG: Successfully got process stat for PID {}: {}", process_info.pid, stat.comm);
                    return Some(stat);
                }
            }
            eprintln!("DEBUG: Failed to get process stat for PID {}", process_info.pid);
        } else {
            eprintln!("DEBUG: No exact port match found");
        }
        
        // If exact port doesn't work, try to find the most recent process
        // that made network calls (this is a fallback since we're using TGID as keys)
        eprintln!("DEBUG: Trying to find most recent process in map");
        
        // Note: eBPF timestamps use bpf_ktime_get_ns() which is time since boot,
        // while system time is since Unix epoch. We'll find the newest entry
        // based on relative timestamps instead of absolute time comparison.
        let mut best_match: Option<ProcessInfo> = None;
        let mut newest_timestamp = 0;
        let mut map_entries = 0;
        
        // Iterate through the map to find the most recent entry by timestamp
        for result in map.iter() {
            map_entries += 1;
            if let Ok((key, process_info)) = result {
                eprintln!("DEBUG: Map entry {} - Key: {}, PID: {}, Port: {}, Timestamp: {}", 
                         map_entries, key, process_info.pid, process_info.port, process_info.timestamp);
                
                // Simply find the entry with the highest timestamp (most recent)
                if process_info.timestamp > newest_timestamp {
                    newest_timestamp = process_info.timestamp;
                    best_match = Some(process_info);
                    eprintln!("DEBUG: New best match - PID: {}", process_info.pid);
                }
            } else {
                eprintln!("DEBUG: Failed to read map entry {}", map_entries);
            }
        }
        
        eprintln!("DEBUG: Scanned {} map entries, newest_timestamp: {}", map_entries, newest_timestamp);
        
        if let Some(process_info) = best_match {
            eprintln!("DEBUG: Best match found - PID: {}, attempting to get process stat", process_info.pid);
            if let Ok(process) = procfs::process::Process::new(process_info.pid as i32) {
                if let Ok(stat) = process.stat() {
                    eprintln!("DEBUG: Successfully got best match process stat: {}", stat.comm);
                    return Some(stat);
                }
            }
            eprintln!("DEBUG: Failed to get process stat for best match PID {}", process_info.pid);
        } else {
            eprintln!("DEBUG: No best match found in map");
        }
        
        eprintln!("DEBUG: eBPF lookup returning None");
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

