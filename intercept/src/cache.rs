//! Caching and lookup functionality for DNS request data

use crate::types::DnsRequestInfo;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cache entry for DNS request information
#[derive(Debug, Clone)]
struct CacheEntry {
    info: DnsRequestInfo,
    inserted_at: Instant,
}

/// Thread-safe cache for DNS request information
///
/// This cache stores DNS request information indexed by source socket address.
/// Entries automatically expire after a configurable timeout to prevent
/// unbounded memory growth.
#[derive(Debug, Clone)]
pub struct DnsRequestCache {
    inner: Arc<Mutex<DnsCacheInner>>,
}

#[derive(Debug)]
struct DnsCacheInner {
    entries: HashMap<SocketAddrV4, CacheEntry>,
    max_entries: usize,
    entry_ttl: Duration,
}

impl DnsRequestCache {
    /// Create a new DNS request cache
    ///
    /// # Arguments
    /// * `max_entries` - Maximum number of entries to keep in cache
    /// * `entry_ttl` - Time-to-live for cache entries
    pub fn new(max_entries: usize, entry_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DnsCacheInner {
                entries: HashMap::with_capacity(max_entries),
                max_entries,
                entry_ttl,
            })),
        }
    }

    /// Insert a DNS request into the cache
    pub fn insert(&self, info: DnsRequestInfo) {
        let source_addr = info.source_socket_addr();
        let entry = CacheEntry {
            info,
            inserted_at: Instant::now(),
        };

        let mut inner = self.inner.lock().unwrap();

        // Clean up expired entries before inserting
        inner.cleanup_expired();

        // If we're at capacity, remove oldest entries
        if inner.entries.len() >= inner.max_entries {
            inner.evict_oldest();
        }

        inner.entries.insert(source_addr, entry);
    }

    /// Look up DNS request information by source address
    pub fn lookup(&self, addr: SocketAddrV4) -> Option<DnsRequestInfo> {
        let mut inner = self.inner.lock().unwrap();

        // Clean up expired entries
        inner.cleanup_expired();

        inner.entries.get(&addr).map(|entry| entry.info.clone())
    }

    /// Get the current number of cached entries
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.entries.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.entries.is_empty()
    }
}

impl DnsCacheInner {
    /// Remove expired entries from the cache
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.inserted_at) < self.entry_ttl);
    }

    /// Evict the oldest entry to make room for new ones
    fn evict_oldest(&mut self) {
        if let Some((oldest_addr, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(addr, entry)| (*addr, entry.inserted_at))
        {
            self.entries.remove(&oldest_addr);
        }
    }
}
