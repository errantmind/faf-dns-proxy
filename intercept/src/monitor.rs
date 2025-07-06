//! Main DNS monitoring implementation

use crate::cache::DnsRequestCache;
use crate::ebpf::EbpfManager;
use crate::error::{Error, Result};
use crate::types::{DnsRequestInfo, UdpPacketInfo};
use std::mem;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Main DNS monitor implementation
pub struct DnsMonitor {
    ebpf_manager: EbpfManager,
    cache: DnsRequestCache,
    is_running: Arc<AtomicBool>,
    debug_output: Arc<AtomicBool>,
}

impl DnsMonitor {
    /// Create a new DNS monitor
    pub fn new() -> Result<Self> {
        Ok(Self {
            ebpf_manager: EbpfManager::new(),
            cache: DnsRequestCache::new(10_000, Duration::from_secs(30)),
            is_running: Arc::new(AtomicBool::new(false)),
            debug_output: Arc::new(AtomicBool::new(false)),
        })
    }
    
    /// Start monitoring DNS traffic
    pub fn start_monitoring(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(Error::AlreadyRunning);
        }
        
        // Load and attach eBPF programs
        self.ebpf_manager.load_and_attach()?;
        self.is_running.store(true, Ordering::Relaxed);
        
        if self.debug_output.load(Ordering::Relaxed) {
            println!("Monitoring DNS traffic only (port 53) - optimized for performance");
            println!("On-demand polling enabled for immediate capture");
            println!(
                "{:<8} {:<16} {:<15} {:<8} {:<8} {:<8} {:<8} {:<8} PROCESS_TREE",
                "PID", "COMM", "SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "MSG_LEN", "LAT_μs"
            );
        }
        
        Ok(())
    }
    
    /// Stop monitoring DNS traffic
    pub fn stop_monitoring(&mut self) {
        if !self.is_running.load(Ordering::Relaxed) {
            return;
        }
        
        self.is_running.store(false, Ordering::Relaxed);
    }
    
    /// Look up DNS request details for a given source address
    /// 
    /// This method polls for new eBPF events and then performs an immediate lookup.
    /// The eBPF program captures DNS requests at the kernel level (udp_sendmsg) BEFORE
    /// the packet leaves the system, so even ephemeral processes that exit immediately
    /// after making the DNS call should be captured.
    /// 
    /// Returns None if:
    /// - The monitor is not running  
    /// - No DNS request was captured for this source address
    /// - The cache entry has expired
    pub fn lookup_request_details(&self, addr: SocketAddrV4) -> Option<DnsRequestInfo> {
        if !self.is_running.load(Ordering::Relaxed) {
            return None;
        }
        
        // Create a temporary ringbuffer for immediate polling
        let cache = self.cache.clone();
        let debug_output = self.debug_output.clone();
        
        if let Ok(ringbuf) = self.ebpf_manager.create_ringbuffer(move |data: &[u8]| -> i32 {
            if let Some(info) = Self::handle_event(data) {
                // Store in cache for later lookup
                cache.insert(info.clone());
                
                // Print debug output if enabled
                if debug_output.load(Ordering::Relaxed) {
                    Self::print_debug_event(&info);
                }
            }
            0
        }) {
            // Non-blocking poll to capture any pending events
            let _ = ringbuf.poll(Duration::from_nanos(0));
        }
        
        // Now lookup in cache
        self.cache.lookup(addr)
    }
    
    /// Enable debug output
    pub fn enable_debug_output(&mut self) {
        self.debug_output.store(true, Ordering::Relaxed);
    }
    
    /// Disable debug output
    pub fn disable_debug_output(&mut self) {
        self.debug_output.store(false, Ordering::Relaxed);
    }
    
    /// Check if the monitor is currently running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, bool) {
        (self.cache.len(), self.cache.is_empty())
    }
    
    /// Handle incoming eBPF events
    fn handle_event(data: &[u8]) -> Option<DnsRequestInfo> {
        if data.len() < mem::size_of::<UdpPacketInfo>() {
            return None;
        }
        
        let info = unsafe { *(data.as_ptr() as *const UdpPacketInfo) };
        Some(info.to_dns_request_info())
    }
    
    /// Print debug event (same format as original implementation)
    fn print_debug_event(info: &DnsRequestInfo) {
        let saddr_str = if info.source_addr.is_unspecified() {
            "0.0.0.0".to_string()
        } else {
            info.source_addr.to_string()
        };
        
        let sport_str = if info.source_port == 0 {
            "0".to_string()
        } else {
            info.source_port.to_string()
        };
        
        let daddr_str = if info.destination_addr.is_unspecified() {
            "0.0.0.0".to_string()
        } else {
            info.destination_addr.to_string()
        };
        
        let dport_str = if info.destination_port == 0 {
            "0".to_string()
        } else {
            info.destination_port.to_string()
        };
        
        println!(
            "{:<8} {:<16} {:<15} {:<8} {:<15} {:<8} {:<8} {:<8} {}",
            info.pid,
            info.process_name,
            saddr_str,
            sport_str,
            daddr_str,
            dport_str,
            info.message_length,
            info.latency_us,
            info.process_tree_string()
        );
    }
}

impl Drop for DnsMonitor {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_monitor_creation() {
        // This test will fail without root privileges and proper eBPF setup,
        // but it tests the basic structure
        let monitor = DnsMonitor::new();
        assert!(monitor.is_ok());
    }
    
    #[test]
    fn test_monitor_state() {
        let monitor = DnsMonitor::new().unwrap();
        assert!(!monitor.is_running());
        
        let (cache_len, is_empty) = monitor.cache_stats();
        assert_eq!(cache_len, 0);
        assert!(is_empty);
    }
}