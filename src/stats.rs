use crate::const_config::*;

pub struct Stats {
   pub dns_ip: &'static str,
   pub fastest_count: usize,
   pub reconnect_count: usize,
}

impl Stats {
   const fn increment_fastest(&mut self) {
      self.fastest_count += 1;
   }

   const fn increment_reconnect(&mut self) {
      self.reconnect_count += 1;
   }

   pub fn array_increment_fastest(stat_array: &mut [Self], dns_ip_key: &str) {
      for stats in stat_array {
         if stats.dns_ip == dns_ip_key {
            stats.increment_fastest();
         }
      }
   }

   pub fn array_increment_reconnect(stat_array: &mut [Self], dns_ip_key: &str) {
      for stats in stat_array {
         if stats.dns_ip == dns_ip_key {
            stats.increment_reconnect();
         }
      }
   }
}

impl std::fmt::Display for Stats {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}\n  fastest: {}\n  reconnects: {}", self.dns_ip, self.fastest_count, self.reconnect_count)
   }
}

pub const fn init_stats() -> [Stats; UPSTREAM_DNS_SERVERS.len()] {
   #[allow(invalid_value)]
   let mut arr: [Stats; UPSTREAM_DNS_SERVERS.len()] = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
   let mut index = 0;

   while index < UPSTREAM_DNS_SERVERS.len() {
      arr[index] = Stats { dns_ip: UPSTREAM_DNS_SERVERS[index].1, fastest_count: 0, reconnect_count: 0 };
      index += 1;
   }

   arr
}
