/*
FaF is a cutting edge, high performance dns proxy
Copyright (C) 2021  James Bates

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

pub struct Stats {
   pub dns_ip: &'static str,
   pub fastest_count: usize
}

impl Stats {
   const fn increment_fastest(&mut self) {
      self.fastest_count += 1;
   }   

   pub fn array_increment_fastest(stat_array: &mut [Self], dns_ip_key: &str) -> usize {
      for stats in stat_array {
         if stats.dns_ip == dns_ip_key {
            stats.increment_fastest();
            return stats.fastest_count;
         }
      }

      0
   }   
}

impl std::fmt::Display for Stats {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f, "{}\n  fastest: {}\n", self.dns_ip, self.fastest_count)
   }
}

pub const fn init_stats() -> [Stats; UPSTREAM_DNS_SERVERS.len()] {
   #[allow(invalid_value)]
   let mut arr: [Stats; UPSTREAM_DNS_SERVERS.len()] = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
   let mut index = 0;

   while index < UPSTREAM_DNS_SERVERS.len() {
      arr[index] = Stats { dns_ip: UPSTREAM_DNS_SERVERS[index].ip, fastest_count: 0 };
      index += 1;
   }

   arr
}
