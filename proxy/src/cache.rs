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

#[derive(Clone, Copy)]
pub struct InFlightWaiter {
   pub client_addr: std::net::SocketAddrV4,
   pub client_id: u16,
}

pub struct InFlightEntry {
   pub upstream_id: u16,
   pub asked_at: u128,
   pub deadline: tokio::time::Instant,
   pub waiters: Vec<InFlightWaiter>,
   pub query_template: Vec<u8>,
}

pub enum InFlightRegistration {
   Cached(AnswerCacheRef),
   Joined,
   Leader { upstream_id: u16, deadline: tokio::time::Instant },
   Overflow,
}

pub struct AnswerCacheEntry {
   pub answer: Vec<u8>,
   pub elapsed_ms: u128,
   pub expires_at: u64,
}

lazy_static::lazy_static! {
   // Stores questions currently awaiting an upstream response and every client waiting for each answer.
   static ref DNS_IN_FLIGHT: dashmap::DashMap<Vec<u8>, InFlightEntry, rustc_hash::FxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, rustc_hash::FxBuildHasher::default());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<Vec<u8>, AnswerCacheEntry, rustc_hash::FxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, rustc_hash::FxBuildHasher::default());
}

const MAX_IN_FLIGHT: usize = 4096;
const MAX_WAITERS_PER_FLIGHT: usize = 16_384;
const IN_FLIGHT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(2);

static IN_FLIGHT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static NEXT_UPSTREAM_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub fn in_flight_register(cache_key: &[u8], query: &[u8], waiter: InFlightWaiter, current_time: u64) -> InFlightRegistration {
   use dashmap::mapref::entry::Entry;
   use std::sync::atomic::Ordering;

   if let Some(mut entry) = DNS_IN_FLIGHT.get_mut(cache_key) {
      if entry.waiters.len() >= MAX_WAITERS_PER_FLIGHT {
         return InFlightRegistration::Overflow;
      }
      entry.waiters.push(waiter);
      return InFlightRegistration::Joined;
   }

   match DNS_IN_FLIGHT.entry(cache_key.to_vec()) {
      Entry::Occupied(mut entry) => {
         if entry.get().waiters.len() >= MAX_WAITERS_PER_FLIGHT {
            return InFlightRegistration::Overflow;
         }
         entry.get_mut().waiters.push(waiter);
         InFlightRegistration::Joined
      }
      Entry::Vacant(entry) => {
         // The answer may have arrived after the caller's first cache lookup but before this shard was locked.
         if let Some(cached_response) = answer_cache_get_mut_check_expiry(cache_key, current_time) {
            return InFlightRegistration::Cached(cached_response);
         }

         if IN_FLIGHT_COUNT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < MAX_IN_FLIGHT).then_some(count + 1))
            .is_err()
         {
            return InFlightRegistration::Overflow;
         }

         let upstream_id = NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed);
         let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
         entry.insert(InFlightEntry {
            upstream_id,
            asked_at: crate::util::get_unix_ts_millis(),
            deadline,
            waiters: vec![waiter],
            query_template: query[..12 + cache_key.len()].to_vec(),
         });

         InFlightRegistration::Leader { upstream_id, deadline }
      }
   }
}

pub fn in_flight_complete(cache_key: &[u8], upstream_id: u16, response: &[u8]) -> Option<(InFlightEntry, crate::dns::DnsResponseResult)> {
   use std::sync::atomic::Ordering;

   let mut dns_response = None;
   let (_, in_flight) = DNS_IN_FLIGHT.remove_if(cache_key, |key, entry| {
      if entry.upstream_id != upstream_id {
         return false;
      }

      let response_result = crate::dns::process_dns_response(response, Some(entry.asked_at));
      let cache_entry = crate::dns::create_cache_entry_from_response(&response_result, response);
      DNS_ANSWER_CACHE.insert(key.clone(), cache_entry);
      dns_response = Some(response_result);
      true
   })?;

   IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
   Some((in_flight, dns_response.unwrap()))
}

pub fn in_flight_take_expired(now: tokio::time::Instant) -> Vec<InFlightEntry> {
   use std::sync::atomic::Ordering;

   let expired_keys: Vec<(Vec<u8>, u16)> =
      DNS_IN_FLIGHT.iter().filter(|entry| entry.deadline <= now).map(|entry| (entry.key().clone(), entry.upstream_id)).collect();
   let mut expired_entries = Vec::with_capacity(expired_keys.len());

   for (cache_key, upstream_id) in expired_keys {
      if let Some((_, entry)) = DNS_IN_FLIGHT.remove_if(&cache_key, |_, entry| entry.upstream_id == upstream_id && entry.deadline <= now) {
         IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
         expired_entries.push(entry);
      }
   }

   expired_entries
}

// Answer cache interface functions
pub struct AnswerCacheRef {
   pub answer: Vec<u8>,
}

pub fn answer_cache_get_mut_check_expiry(cache_key: &[u8], current_time: u64) -> Option<AnswerCacheRef> {
   if let Some(cached_response) = DNS_ANSWER_CACHE.get(cache_key) {
      if cached_response.expires_at > current_time { Some(AnswerCacheRef { answer: cached_response.answer.clone() }) } else { None }
   } else {
      None
   }
}

pub fn answer_cache_iter_filtered() -> Vec<u64> {
   DNS_ANSWER_CACHE.iter().filter(|x| x.elapsed_ms <= 8192).map(|x| x.elapsed_ms as u64).collect()
}

#[test]
fn in_flight_fan_out_test() {
   use std::sync::atomic::Ordering;

   DNS_IN_FLIGHT.clear();
   DNS_ANSWER_CACHE.clear();
   IN_FLIGHT_COUNT.store(0, Ordering::Relaxed);

   let mut query = vec![0u8; 24];
   query[2] = 1;
   query[5] = 1;
   query[12..20].copy_from_slice(&[2, b'x', b'x', 3, b'c', b'o', b'm', 0]);
   query[21] = 1;
   query[23] = 1;
   let cache_key = query[12..].to_vec();
   let client_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 12345);

   let upstream_id =
      match in_flight_register(&cache_key, &query, InFlightWaiter { client_addr, client_id: 100 }, crate::util::get_unix_ts_secs()) {
         InFlightRegistration::Leader { upstream_id, .. } => upstream_id,
         _ => panic!("first request must lead the flight"),
      };
   assert!(matches!(
      in_flight_register(&cache_key, &query, InFlightWaiter { client_addr, client_id: 200 }, crate::util::get_unix_ts_secs(),),
      InFlightRegistration::Joined
   ));

   let mut response = query;
   crate::dns::set_id_network_byte_order(upstream_id, &mut response);
   response[2] = 0b1000_0001;
   response[3] = 0b1000_0011;
   let (entry, _) = in_flight_complete(&cache_key, upstream_id, &response).unwrap();

   assert_eq!(entry.waiters.len(), 2);
   assert_eq!(entry.waiters[0].client_id, 100);
   assert_eq!(entry.waiters[1].client_id, 200);
   assert!(in_flight_complete(&cache_key, upstream_id, &response).is_none());
   assert!(answer_cache_get_mut_check_expiry(&cache_key, crate::util::get_unix_ts_secs()).is_none());
   assert_eq!(IN_FLIGHT_COUNT.load(Ordering::Relaxed), 0);
}
