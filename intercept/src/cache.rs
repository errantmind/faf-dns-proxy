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
    
    /// Create a new cache with default settings
    /// 
    /// Default: 10,000 entries, 30 second TTL
    pub fn with_defaults() -> Self {
        Self::new(10_000, Duration::from_secs(30))
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
        
        inner.entries.get(&addr)
            .map(|entry| entry.info.clone())
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
    
    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.entries.clear();
    }
    
    /// Manually trigger cleanup of expired entries
    pub fn cleanup(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cleanup_expired();
    }
}

impl DnsCacheInner {
    /// Remove expired entries from the cache
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.duration_since(entry.inserted_at) < self.entry_ttl
        });
    }
    
    /// Evict the oldest entry to make room for new ones
    fn evict_oldest(&mut self) {
        if let Some((oldest_addr, _)) = self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(addr, entry)| (*addr, entry.inserted_at))
        {
            self.entries.remove(&oldest_addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    
    fn create_test_dns_info(source_port: u16) -> DnsRequestInfo {
        DnsRequestInfo {
            pid: 1234,
            process_name: "test".to_string(),
            source_addr: Ipv4Addr::new(192, 168, 1, 100),
            source_port,
            destination_addr: Ipv4Addr::new(8, 8, 8, 8),
            destination_port: 53,
            message_length: 64,
            latency_us: 100,
            process_tree: vec![],
            timestamp_ns: 1000000000,
        }
    }
    
    #[test]
    fn test_cache_insert_and_lookup() {
        let cache = DnsRequestCache::with_defaults();
        let info = create_test_dns_info(12345);
        let addr = info.source_socket_addr();
        
        cache.insert(info.clone());
        
        let retrieved = cache.lookup(addr).unwrap();
        assert_eq!(retrieved.pid, info.pid);
        assert_eq!(retrieved.source_port, info.source_port);
    }
    
    #[test]
    fn test_cache_expiry() {
        let cache = DnsRequestCache::new(100, Duration::from_millis(50));
        let info = create_test_dns_info(12345);
        let addr = info.source_socket_addr();
        
        cache.insert(info);
        assert!(cache.lookup(addr).is_some());
        
        thread::sleep(Duration::from_millis(100));
        assert!(cache.lookup(addr).is_none());
    }
    
    #[test]
    fn test_cache_capacity() {
        let cache = DnsRequestCache::new(2, Duration::from_secs(60));
        
        // Insert 3 entries, should evict the oldest
        cache.insert(create_test_dns_info(12345));
        cache.insert(create_test_dns_info(12346));
        cache.insert(create_test_dns_info(12347));
        
        assert_eq!(cache.len(), 2);
    }
}