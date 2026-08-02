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

#[repr(align(64))]
struct QueryStats {
   cache_hits: AtomicU64,
   cache_misses: AtomicU64,
}

#[repr(align(64))]
struct RefreshStats {
   started: AtomicU64,
   succeeded: AtomicU64,
   useful: AtomicU64,
   promoted: AtomicU64,
   failed: AtomicU64,
   skipped: AtomicU64,
}

static QUERY_STATS: QueryStats = QueryStats { cache_hits: AtomicU64::new(0), cache_misses: AtomicU64::new(0) };
static REFRESH_STATS: RefreshStats = RefreshStats {
   started: AtomicU64::new(0),
   succeeded: AtomicU64::new(0),
   useful: AtomicU64::new(0),
   promoted: AtomicU64::new(0),
   failed: AtomicU64::new(0),
   skipped: AtomicU64::new(0),
};

#[inline]
pub fn increment_cache_hit() -> u64 {
   QUERY_STATS.cache_hits.fetch_add(1, Ordering::Relaxed) + 1
}

#[inline]
pub fn increment_cache_miss() {
   QUERY_STATS.cache_misses.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_started() {
   REFRESH_STATS.started.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_succeeded() {
   REFRESH_STATS.succeeded.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_useful() {
   REFRESH_STATS.useful.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_promoted() {
   REFRESH_STATS.promoted.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_failed() {
   REFRESH_STATS.failed.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn increment_refresh_skipped() {
   REFRESH_STATS.skipped.fetch_add(1, Ordering::Relaxed);
}

pub fn start_reporter() {
   tokio::task::spawn(async move {
      let started_at = tokio::time::Instant::now();
      let period = std::time::Duration::from_secs(5 * 60);
      let mut interval = tokio::time::interval_at(started_at + period, period);

      loop {
         interval.tick().await;
         print_run_summary(started_at.elapsed());
      }
   });
}

fn print_run_summary(run_time: std::time::Duration) {
   let cache_hits = QUERY_STATS.cache_hits.load(Ordering::Relaxed);
   let cache_misses = QUERY_STATS.cache_misses.load(Ordering::Relaxed);
   let queries = cache_hits.saturating_add(cache_misses);
   let refresh_started = REFRESH_STATS.started.load(Ordering::Relaxed);
   let refresh_succeeded = REFRESH_STATS.succeeded.load(Ordering::Relaxed);
   let refresh_useful = REFRESH_STATS.useful.load(Ordering::Relaxed);
   let refresh_promoted = REFRESH_STATS.promoted.load(Ordering::Relaxed);
   let refresh_failed = REFRESH_STATS.failed.load(Ordering::Relaxed);
   let refresh_skipped = REFRESH_STATS.skipped.load(Ordering::Relaxed);

   let hit_rate = percentage(cache_hits, queries);
   let refresh_efficiency = percentage(refresh_useful, refresh_started);
   let hit_rate_contribution = percentage(refresh_useful, queries);
   let total_seconds = run_time.as_secs();
   let hours = total_seconds / 3600;
   let minutes = total_seconds % 3600 / 60;
   let seconds = total_seconds % 60;

   println!(
      "\n[FaF stats | run {hours:02}:{minutes:02}:{seconds:02}]\n  DNS      {:>10} queries | {:>10} hits ({hit_rate:.2}%) | {} misses\n  Refresh  {:>10} started | {:>10} succeeded | {} useful ({refresh_efficiency:.2}%) | +{hit_rate_contribution:.2} pp hit rate\n           {:>10} promoted | {:>10} failed | {} skipped",
      format_count(queries),
      format_count(cache_hits),
      format_count(cache_misses),
      format_count(refresh_started),
      format_count(refresh_succeeded),
      format_count(refresh_useful),
      format_count(refresh_promoted),
      format_count(refresh_failed),
      format_count(refresh_skipped),
   );
}

#[inline]
fn percentage(numerator: u64, denominator: u64) -> f64 {
   if denominator == 0 { 0.0 } else { numerator as f64 * 100.0 / denominator as f64 }
}

fn format_count(value: u64) -> String {
   let digits = value.to_string();
   let mut output = String::with_capacity(digits.len() + digits.len() / 3);
   for (index, byte) in digits.bytes().enumerate() {
      if index > 0 && (digits.len() - index).is_multiple_of(3) {
         output.push(',');
      }
      output.push(byte as char);
   }
   output
}

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
