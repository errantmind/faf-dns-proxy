/*
FaF is a high performance DNS over TLS proxy
Copyright (C) 2022  James Bates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//! eBPF-based high-performance client identification
//!
//! This module provides a fast path for DNS client identification using eBPF kernel probes.
//! It intercepts DNS requests at the kernel level before they leave the system, providing
//! microsecond-level latency with complete process information including process trees.

#[cfg(feature = "ebpf-client-ident")]
use faf_dns_intercept::DnsMonitor;
use std::net::SocketAddrV4;
use std::sync::Mutex;

/// High-performance eBPF-based client identification manager
pub struct EbpfClientManager {
   #[cfg(feature = "ebpf-client-ident")]
   monitor: Mutex<Option<DnsMonitor>>,
   #[cfg(not(feature = "ebpf-client-ident"))]
   _phantom: std::marker::PhantomData<()>,
}

/// Result of client identification lookup
#[derive(Debug, Clone)]
pub struct ClientInfo {
   pub pid: u32,
   pub process_name: String,
   pub process_tree: String,
   pub latency_us: u64,
   pub lookup_method: &'static str,
}

impl EbpfClientManager {
   /// Create a new eBPF client manager
   pub fn new() -> Self {
      Self {
         #[cfg(feature = "ebpf-client-ident")]
         monitor: Mutex::new(None),
         #[cfg(not(feature = "ebpf-client-ident"))]
         _phantom: std::marker::PhantomData,
      }
   }

   /// Initialize the eBPF monitoring system
   /// Returns true if eBPF was successfully initialized, false if fallback should be used
   pub fn initialize(&self) -> bool {
      #[cfg(feature = "ebpf-client-ident")]
      {
         match DnsMonitor::new() {
            Ok(mut monitor) => match monitor.start_monitoring() {
               Ok(_) => {
                  if let Ok(mut guard) = self.monitor.lock() {
                     *guard = Some(monitor);
                     eprintln!("eBPF DNS monitoring initialized successfully - using fast path\n");
                     return true;
                  }
               }
               Err(e) => {
                  eprintln!("Failed to start eBPF monitoring: {}. Falling back to netlink.", e);
               }
            },
            Err(e) => {
               eprintln!("Failed to create eBPF monitor: {}. Falling back to netlink.", e);
            }
         }
      }

      #[cfg(not(feature = "ebpf-client-ident"))]
      {
         eprintln!("eBPF support not compiled in. Using netlink fallback.\n");
      }

      false
   }

   /// Look up client information for a given source address using eBPF fast path
   /// Returns None if eBPF is not available or no information was found
   pub fn lookup_client_info(&self, source_addr: SocketAddrV4) -> Option<ClientInfo> {
      #[cfg(feature = "ebpf-client-ident")]
      {
         if let Ok(guard) = self.monitor.lock() {
            if let Some(ref monitor) = *guard {
               if let Some(dns_info) = monitor.lookup_request_details(source_addr) {
                  return Some(ClientInfo {
                     pid: dns_info.pid,
                     process_name: dns_info.process_name.clone(),
                     process_tree: dns_info.process_tree_string(),
                     latency_us: dns_info.latency_us,
                     lookup_method: "EBPF",
                  });
               }
            }
         }
      }

      None
   }

   /// Check if eBPF monitoring is active
   pub fn is_active(&self) -> bool {
      #[cfg(feature = "ebpf-client-ident")]
      {
         if let Ok(guard) = self.monitor.lock() { guard.is_some() } else { false }
      }

      #[cfg(not(feature = "ebpf-client-ident"))]
      false
   }

   /// Get statistics about the eBPF monitoring system
   pub fn get_stats(&self) -> (usize, bool) {
      #[cfg(feature = "ebpf-client-ident")]
      {
         if let Ok(guard) = self.monitor.lock() {
            if let Some(ref monitor) = *guard {
               return monitor.cache_stats();
            }
         }
      }

      (0, true)
   }
}

impl Drop for EbpfClientManager {
   fn drop(&mut self) {
      #[cfg(feature = "ebpf-client-ident")]
      {
         if let Ok(mut guard) = self.monitor.lock() {
            if let Some(mut monitor) = guard.take() {
               monitor.stop_monitoring();
            }
         }
      }
   }
}
