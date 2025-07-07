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

use crate::statics::*;
use std::sync::atomic::{AtomicU64, Ordering};

// Cache-line aligned to prevent false sharing between different server stats
#[repr(align(64))]
pub struct ServerStats {
   pub fastest_count: AtomicU64,
   pub refused_count: AtomicU64,
}

impl ServerStats {
   const fn new() -> Self {
      Self { fastest_count: AtomicU64::new(0), refused_count: AtomicU64::new(0) }
   }
}

// Global atomic statistics array - safe, thread-safe, zero-overhead
static SERVER_STATS: [ServerStats; DNS_SERVERS.len()] = {
   // Create array with const new() to avoid complex initialization
   [const { ServerStats::new() }; DNS_SERVERS.len()]
};

/// Increment fastest response counter for a DNS server
/// Returns (new_fastest_count, current_refused_count)
#[inline]
pub fn increment_fastest(dns_server_index: usize) -> (u64, u64) {
   let fastest = SERVER_STATS[dns_server_index].fastest_count.fetch_add(1, Ordering::Relaxed);
   let refused = SERVER_STATS[dns_server_index].refused_count.load(Ordering::Relaxed);
   (fastest + 1, refused)
}

/// Increment refused response counter for a DNS server  
/// Returns (current_fastest_count, new_refused_count)
#[inline]
pub fn increment_refused(dns_server_index: usize) -> (u64, u64) {
   let refused = SERVER_STATS[dns_server_index].refused_count.fetch_add(1, Ordering::Relaxed);
   let fastest = SERVER_STATS[dns_server_index].fastest_count.load(Ordering::Relaxed);
   (fastest, refused + 1)
}

/// Get current stats for a DNS server
/// Returns (fastest_count, refused_count)
#[inline]
pub fn get_stats(dns_server_index: usize) -> (u64, u64) {
   let fastest = SERVER_STATS[dns_server_index].fastest_count.load(Ordering::Relaxed);
   let refused = SERVER_STATS[dns_server_index].refused_count.load(Ordering::Relaxed);
   (fastest, refused)
}

/// Display statistics for a DNS server
pub fn display_server_stats(dns_server_index: usize) -> String {
   let (fastest, _) = get_stats(dns_server_index);
   format!("{}\n  fastest: {}\n", DNS_SERVERS[dns_server_index].socket_addr.ip(), fastest)
}
