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

#[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
use faf_dns_intercept::DnsMonitor;
use std::net::SocketAddrV4;
#[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
use std::sync::Mutex;

/// High-performance eBPF-based client identification manager
pub struct EbpfClientManager {
   #[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
   monitor: Mutex<Option<DnsMonitor>>,
   #[cfg(not(all(feature = "ebpf-client-ident", target_arch = "x86_64")))]
   _phantom: std::marker::PhantomData<()>,
}

/// Result of client identification lookup
#[derive(Debug, Clone)]
pub struct ClientInfo {
   pub pid: u32,
   pub process_name: String,
   pub lookup_method: &'static str,
}

impl EbpfClientManager {
   /// Create a new eBPF client manager
   pub fn new() -> Self {
      Self {
         #[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
         monitor: Mutex::new(None),
         #[cfg(not(all(feature = "ebpf-client-ident", target_arch = "x86_64")))]
         _phantom: std::marker::PhantomData,
      }
   }

   /// Initialize the eBPF monitoring system
   /// Returns true if eBPF was successfully initialized, false if fallback should be used
   pub fn initialize(&self) -> bool {
      #[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
      {
         match DnsMonitor::new() {
            Ok(mut monitor) => match monitor.start_monitoring() {
               Ok(_) => {
                  if let Ok(mut guard) = self.monitor.lock() {
                     *guard = Some(monitor);
                     return true;
                  }
               }
               Err(e) => {
                  eprintln!("Failed to start eBPF monitoring: {e}. Falling back to netlink.");
               }
            },
            Err(e) => {
               eprintln!("Failed to create eBPF monitor: {e}. Falling back to netlink.");
            }
         }
      }

      #[cfg(not(all(feature = "ebpf-client-ident", target_arch = "x86_64")))]
      {
         eprintln!("eBPF support not compiled in. Using netlink fallback.\n");
      }

      false
   }

   /// Look up client information for a given source address using eBPF fast path
   /// Returns None if eBPF is not available or no information was found
   pub fn lookup_client_info(&self, _source_addr: SocketAddrV4) -> Option<ClientInfo> {
      #[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
      {
         if let Ok(guard) = self.monitor.lock()
            && let Some(ref monitor) = *guard
            && let Some(dns_info) = monitor.lookup_request_details(_source_addr)
         {
            return Some(ClientInfo { pid: dns_info.pid, process_name: dns_info.process_name.clone(), lookup_method: "EBPF" });
         }
      }

      None
   }
}

impl Drop for EbpfClientManager {
   fn drop(&mut self) {
      #[cfg(all(feature = "ebpf-client-ident", target_arch = "x86_64"))]
      {
         if let Ok(mut guard) = self.monitor.lock()
            && let Some(mut monitor) = guard.take()
         {
            monitor.stop_monitoring();
         }
      }
   }
}
