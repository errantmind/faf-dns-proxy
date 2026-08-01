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
   pub background_refresh: bool,
   pub background_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

pub enum InFlightRegistration {
   Cached(AnswerCacheRef),
   Joined,
   PromotedBackground { upstream_id: u16, deadline: tokio::time::Instant },
   Leader { upstream_id: u16, deadline: tokio::time::Instant },
   Overflow,
}

pub enum BackgroundRefreshRegistration {
   Leader { upstream_id: u16, deadline: tokio::time::Instant, query: Vec<u8> },
   Skipped,
   AlreadyInFlight,
}

const REFRESH_ELIGIBLE: u8 = 0;
const REFRESH_ARMED: u8 = 1;
const REFRESH_ATTEMPTED: u8 = 2;

pub struct AnswerCacheEntry {
   pub answer: Vec<u8>,
   pub elapsed_ms: u128,
   pub expires_at: tokio::time::Instant,
   pub refresh_generation: u64,
   pub(crate) refresh_state: std::sync::atomic::AtomicU8,
}

pub struct RefreshEvent {
   pub cache_key: Vec<u8>,
   pub generation: u64,
   pub due_at: tokio::time::Instant,
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
static NEXT_REFRESH_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn join_in_flight(in_flight: &mut InFlightEntry, waiter: InFlightWaiter) -> InFlightRegistration {
   if in_flight.waiters.len() >= MAX_WAITERS_PER_FLIGHT {
      return InFlightRegistration::Overflow;
   }
   in_flight.waiters.push(waiter);
   if in_flight.background_refresh {
      // Mark promotion before releasing the shard lock so a response cannot
      // be rejected at the old expiry while this foreground waiter exists.
      in_flight.background_refresh = false;
      drop(in_flight.background_permit.take());
      InFlightRegistration::PromotedBackground { upstream_id: in_flight.upstream_id, deadline: in_flight.deadline }
   } else {
      InFlightRegistration::Joined
   }
}

pub fn in_flight_register(
   cache_key: &[u8],
   query: &[u8],
   waiter: InFlightWaiter,
   current_time: tokio::time::Instant,
) -> InFlightRegistration {
   use dashmap::mapref::entry::Entry;
   use std::sync::atomic::Ordering;

   if let Some(mut entry) = DNS_IN_FLIGHT.get_mut(cache_key) {
      return join_in_flight(entry.value_mut(), waiter);
   }

   match DNS_IN_FLIGHT.entry(cache_key.to_vec()) {
      Entry::Occupied(mut entry) => join_in_flight(entry.get_mut(), waiter),
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
            background_refresh: false,
            background_permit: None,
         });

         InFlightRegistration::Leader { upstream_id, deadline }
      }
   }
}

pub fn background_refresh_register(
   cache_key: &[u8],
   expected_generation: u64,
   permit: tokio::sync::OwnedSemaphorePermit,
) -> BackgroundRefreshRegistration {
   use dashmap::mapref::entry::Entry;
   use std::sync::atomic::Ordering;

   match DNS_IN_FLIGHT.entry(cache_key.to_vec()) {
      Entry::Occupied(_) => BackgroundRefreshRegistration::AlreadyInFlight,
      Entry::Vacant(entry) => {
         let answer = match DNS_ANSWER_CACHE.get(cache_key) {
            Some(answer)
               if answer.refresh_generation == expected_generation
                  && answer.refresh_state.load(Ordering::Relaxed) == REFRESH_ARMED
                  && answer.expires_at > tokio::time::Instant::now() =>
            {
               answer
            }
            _ => return BackgroundRefreshRegistration::Skipped,
         };

         if IN_FLIGHT_COUNT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < MAX_IN_FLIGHT).then_some(count + 1))
            .is_err()
         {
            answer.refresh_state.store(REFRESH_ATTEMPTED, Ordering::Relaxed);
            return BackgroundRefreshRegistration::Skipped;
         }

         let upstream_id = NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed);
         let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
         let Some(mut query) = crate::dns::create_refresh_query(&answer.answer, cache_key.len()) else {
            IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
            answer.refresh_state.store(REFRESH_ATTEMPTED, Ordering::Relaxed);
            return BackgroundRefreshRegistration::Skipped;
         };
         crate::dns::set_id_network_byte_order(upstream_id, &mut query);
         answer.refresh_state.store(REFRESH_ATTEMPTED, Ordering::Relaxed);
         drop(answer);

         entry.insert(InFlightEntry {
            upstream_id,
            asked_at: crate::util::get_unix_ts_millis(),
            deadline,
            waiters: Vec::new(),
            query_template: query.clone(),
            background_refresh: true,
            background_permit: Some(permit),
         });

         BackgroundRefreshRegistration::Leader { upstream_id, deadline, query }
      }
   }
}

pub fn background_refresh_cancel(cache_key: &[u8], upstream_id: u16) {
   use std::sync::atomic::Ordering;

   if DNS_IN_FLIGHT.remove_if(cache_key, |_, entry| entry.upstream_id == upstream_id && entry.background_refresh).is_some() {
      IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
   }
}

pub fn answer_cache_mark_refresh_attempted(cache_key: &[u8], generation: u64) {
   use std::sync::atomic::Ordering;

   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
   {
      answer.refresh_state.store(REFRESH_ATTEMPTED, Ordering::Relaxed);
   }
}

pub fn in_flight_complete(cache_key: &[u8], upstream_id: u16, response: &[u8]) -> Option<(InFlightEntry, crate::dns::DnsResponseResult)> {
   use std::sync::atomic::Ordering;

   let mut dns_response = None;
   let (_, in_flight) = DNS_IN_FLIGHT.remove_if(cache_key, |key, entry| {
      if entry.upstream_id != upstream_id {
         return false;
      }

      let mut response_result = crate::dns::process_dns_response(response, Some(entry.asked_at));
      if entry.background_refresh
         && let Some(answer) = DNS_ANSWER_CACHE.get(key)
      {
         response_result.elapsed_ms = answer.elapsed_ms;
      }
      let generation = NEXT_REFRESH_GENERATION.fetch_add(1, Ordering::Relaxed);
      let cache_entry = crate::dns::create_cache_entry_from_response(&response_result, response, generation);
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

pub struct AnswerCacheLookup {
   pub answer: Vec<u8>,
   pub refresh_event: Option<RefreshEvent>,
}

pub fn answer_cache_get_mut_check_expiry(cache_key: &[u8], current_time: tokio::time::Instant) -> Option<AnswerCacheRef> {
   let cached_response = DNS_ANSWER_CACHE.get(cache_key)?;
   (cached_response.expires_at > current_time).then(|| AnswerCacheRef { answer: cached_response.answer.clone() })
}

pub fn answer_cache_get_for_client(cache_key: &[u8], current_time: tokio::time::Instant) -> Option<AnswerCacheLookup> {
   use std::sync::atomic::Ordering;

   let cached_response = DNS_ANSWER_CACHE.get(cache_key)?;
   if cached_response.expires_at <= current_time {
      return None;
   }

   let mut refresh_event = None;
   if cached_response.refresh_state.load(Ordering::Relaxed) == REFRESH_ELIGIBLE
      && cached_response.expires_at.saturating_duration_since(current_time) > crate::statics::BACKGROUND_REFRESH_MIN_TTL
      && cached_response.refresh_state.compare_exchange(REFRESH_ELIGIBLE, REFRESH_ARMED, Ordering::Relaxed, Ordering::Relaxed).is_ok()
   {
      let due_at = cached_response.expires_at.checked_sub(crate::statics::BACKGROUND_REFRESH_MARGIN).unwrap_or(current_time);
      refresh_event = Some(RefreshEvent { cache_key: cache_key.to_vec(), generation: cached_response.refresh_generation, due_at });
   }

   Some(AnswerCacheLookup { answer: cached_response.answer.clone(), refresh_event })
}

pub fn answer_cache_iter_filtered() -> Vec<u64> {
   DNS_ANSWER_CACHE.iter().filter(|x| x.elapsed_ms <= 8192).map(|x| x.elapsed_ms as u64).collect()
}
