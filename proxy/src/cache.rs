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
   pub received_at: tokio::time::Instant,
}

pub struct InFlightEntry {
   pub upstream_id: u16,
   pub asked_at: u128,
   pub deadline: tokio::time::Instant,
   pub waiters: Vec<InFlightWaiter>,
   pub query_template: Vec<u8>,
   pub background_refresh: bool,
   pub started_as_background: bool,
   pub background_send_accepted: bool,
   pub refresh_generation: u64,
   pub refresh_lease_until_ms: u64,
   pub background_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

pub enum InFlightRegistration {
   Cached(AnswerCacheLookup),
   Joined,
   PromotedBackground,
   Leader { upstream_id: u16, deadline: tokio::time::Instant },
   Overflow,
}

pub enum BackgroundRefreshRegistration {
   Leader { upstream_id: u16, deadline: tokio::time::Instant, query: Vec<u8> },
   Retry,
   Stale,
}

const REFRESH_ELIGIBLE: u8 = 0;
const REFRESH_ARMED: u8 = 1;
const REFRESH_ATTEMPTED: u8 = 2;
const REFRESH_PHASE_MASK: u8 = 0b0111_1111;
const REFRESH_USEFUL_RECORDED: u8 = 0b1000_0000;

pub struct AnswerCacheEntry {
   pub answer: Vec<u8>,
   pub elapsed_ms: u128,
   pub expires_at: tokio::time::Instant,
   pub previous_expires_at: Option<tokio::time::Instant>,
   pub refresh_generation: u64,
   pub(crate) refresh_state: std::sync::atomic::AtomicU8,
   pub(crate) refresh_lease_until_ms: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct RefreshEvent {
   pub cache_key: Vec<u8>,
   pub generation: u64,
   pub due_at: tokio::time::Instant,
}

impl RefreshEvent {
   pub fn retry_after(mut self, delay: std::time::Duration) -> Self {
      self.due_at = tokio::time::Instant::now() + delay;
      self
   }
}

lazy_static::lazy_static! {
   // Stores questions currently awaiting an upstream response and every client waiting for each answer.
   static ref DNS_IN_FLIGHT: dashmap::DashMap<Vec<u8>, InFlightEntry, rustc_hash::FxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4_096, rustc_hash::FxBuildHasher::default());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<Vec<u8>, AnswerCacheEntry, rustc_hash::FxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4_096, rustc_hash::FxBuildHasher::default());
}

const MAX_IN_FLIGHT: usize = 4_096;
const MAX_WAITERS_PER_FLIGHT: usize = 16_384;
const IN_FLIGHT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(2);

static IN_FLIGHT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static NEXT_UPSTREAM_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
static NEXT_REFRESH_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
fn refresh_due_at(expires_at: tokio::time::Instant, now: tokio::time::Instant) -> tokio::time::Instant {
   expires_at.checked_sub(crate::statics::BACKGROUND_REFRESH_MARGIN).unwrap_or(now).max(now)
}

static LEASE_CLOCK_START: std::sync::OnceLock<tokio::time::Instant> = std::sync::OnceLock::new();

#[inline]
fn lease_now_ms() -> u64 {
   LEASE_CLOCK_START.get_or_init(tokio::time::Instant::now).elapsed().as_millis().min(u64::MAX as u128) as u64
}

#[inline]
fn lease_deadline_ms() -> u64 {
   lease_now_ms().saturating_add(crate::statics::BACKGROUND_REFRESH_LEASE.as_millis().min(u64::MAX as u128) as u64)
}

#[inline]
fn lease_is_active(lease_until_ms: u64) -> bool {
   lease_until_ms > lease_now_ms()
}

#[inline]
fn set_refresh_phase(state: &std::sync::atomic::AtomicU8, phase: u8) {
   use std::sync::atomic::Ordering;

   let _ = state.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| Some((current & REFRESH_USEFUL_RECORDED) | phase));
}

fn join_in_flight(in_flight: &mut InFlightEntry, waiter: InFlightWaiter) -> InFlightRegistration {
   if in_flight.waiters.is_empty() || in_flight.refresh_lease_until_ms != 0 {
      in_flight.refresh_lease_until_ms = lease_deadline_ms();
   }
   if in_flight.waiters.len() >= MAX_WAITERS_PER_FLIGHT {
      return InFlightRegistration::Overflow;
   }
   in_flight.waiters.push(waiter);
   if in_flight.background_refresh {
      in_flight.background_refresh = false;
      drop(in_flight.background_permit.take());
      crate::stats::increment_refresh_promoted();
      InFlightRegistration::PromotedBackground
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
         if let Some(cached_response) = answer_cache_get_for_client(cache_key, current_time) {
            return InFlightRegistration::Cached(cached_response);
         }

         let refresh_lease_until_ms = DNS_ANSWER_CACHE.get(cache_key).map_or(0, |answer| {
            let deadline = lease_deadline_ms();
            answer.refresh_lease_until_ms.store(deadline, Ordering::Relaxed);
            deadline
         });

         if IN_FLIGHT_COUNT.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < MAX_IN_FLIGHT).then_some(count + 1)).is_err()
         {
            return InFlightRegistration::Overflow;
         }

         let upstream_id = NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed);
         let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
         let refresh_generation = DNS_ANSWER_CACHE.get(cache_key).map_or(0, |answer| answer.refresh_generation);
         entry.insert(InFlightEntry {
            upstream_id,
            asked_at: crate::util::get_unix_ts_millis(),
            deadline,
            waiters: vec![waiter],
            query_template: query[..12 + cache_key.len()].to_vec(),
            background_refresh: false,
            started_as_background: false,
            background_send_accepted: false,
            refresh_generation,
            refresh_lease_until_ms,
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
      Entry::Occupied(_) => BackgroundRefreshRegistration::Stale,
      Entry::Vacant(entry) => {
         let answer = match DNS_ANSWER_CACHE.get(cache_key) {
            Some(answer)
               if answer.refresh_generation == expected_generation
                  && answer.refresh_state.load(Ordering::Relaxed) & REFRESH_PHASE_MASK == REFRESH_ARMED
                  && lease_is_active(answer.refresh_lease_until_ms.load(Ordering::Relaxed)) =>
            {
               answer
            }
            _ => return BackgroundRefreshRegistration::Stale,
         };

         if IN_FLIGHT_COUNT.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < MAX_IN_FLIGHT).then_some(count + 1)).is_err()
         {
            return BackgroundRefreshRegistration::Retry;
         }

         let upstream_id = NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed);
         let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
         let Some(mut query) = crate::dns::create_refresh_query(&answer.answer, cache_key.len()) else {
            IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
            set_refresh_phase(&answer.refresh_state, REFRESH_ATTEMPTED);
            return BackgroundRefreshRegistration::Stale;
         };
         crate::dns::set_id_network_byte_order(upstream_id, &mut query);
         let refresh_lease_until_ms = answer.refresh_lease_until_ms.load(Ordering::Relaxed);
         set_refresh_phase(&answer.refresh_state, REFRESH_ATTEMPTED);
         drop(answer);

         entry.insert(InFlightEntry {
            upstream_id,
            asked_at: crate::util::get_unix_ts_millis(),
            deadline,
            waiters: Vec::new(),
            query_template: query.clone(),
            background_refresh: true,
            started_as_background: true,
            background_send_accepted: false,
            refresh_generation: expected_generation,
            refresh_lease_until_ms,
            background_permit: Some(permit),
         });

         BackgroundRefreshRegistration::Leader { upstream_id, deadline, query }
      }
   }
}

pub fn background_refresh_mark_sent(cache_key: &[u8], upstream_id: u16) -> bool {
   if let Some(mut entry) = DNS_IN_FLIGHT.get_mut(cache_key)
      && entry.upstream_id == upstream_id
      && entry.started_as_background
   {
      entry.background_send_accepted = true;
      true
   } else {
      false
   }
}

pub fn background_refresh_cancel(cache_key: &[u8], upstream_id: u16) {
   use std::sync::atomic::Ordering;

   if DNS_IN_FLIGHT.remove_if(cache_key, |_, entry| entry.upstream_id == upstream_id && entry.background_refresh).is_some() {
      IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
   }
}

pub fn answer_cache_mark_refresh_attempted(cache_key: &[u8], generation: u64) {
   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
   {
      set_refresh_phase(&answer.refresh_state, REFRESH_ATTEMPTED);
   }
}

pub fn answer_cache_disarm_refresh(cache_key: &[u8], generation: u64) {
   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
   {
      set_refresh_phase(&answer.refresh_state, REFRESH_ELIGIBLE);
   }
}

pub fn answer_cache_rearm_refresh(cache_key: &[u8], generation: u64) -> bool {
   use std::sync::atomic::Ordering;

   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
      && lease_is_active(answer.refresh_lease_until_ms.load(Ordering::Relaxed))
   {
      set_refresh_phase(&answer.refresh_state, REFRESH_ARMED);
      true
   } else {
      false
   }
}

pub fn refresh_event_is_current(cache_key: &[u8], generation: u64) -> bool {
   use std::sync::atomic::Ordering;

   DNS_ANSWER_CACHE.get(cache_key).is_some_and(|answer| {
      answer.refresh_generation == generation
         && answer.refresh_state.load(Ordering::Relaxed) & REFRESH_PHASE_MASK == REFRESH_ARMED
         && lease_is_active(answer.refresh_lease_until_ms.load(Ordering::Relaxed))
   })
}

pub struct InFlightCompletion {
   pub entry: InFlightEntry,
   pub dns_response: crate::dns::DnsResponseResult,
   pub refresh_event: Option<RefreshEvent>,
}

pub fn in_flight_complete(question: &crate::dns::ParsedQuestion<'_>) -> Option<InFlightCompletion> {
   use std::sync::atomic::Ordering;

   let cache_key = question.cache_key();
   let upstream_id = question.id();
   let response = question.message();
   let mut dns_response = None;
   let mut completed_generation = 0;
   let mut completed_expires_at = None;
   let (_, in_flight) = DNS_IN_FLIGHT.remove_if(cache_key, |key, entry| {
      if entry.upstream_id != upstream_id {
         return false;
      }

      let mut response_result = crate::dns::process_dns_response(question, Some(entry.asked_at));
      let mut previous_expires_at = None;
      if entry.started_as_background
         && let Some(answer) = DNS_ANSWER_CACHE.get(key)
         && entry.background_refresh
      {
         response_result.elapsed_ms = answer.elapsed_ms;
         previous_expires_at = Some(answer.expires_at);
      }
      let generation = NEXT_REFRESH_GENERATION.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
      let refresh_lease_until_ms = DNS_ANSWER_CACHE.get(key).map_or(entry.refresh_lease_until_ms, |answer| {
         entry.refresh_lease_until_ms.max(answer.refresh_lease_until_ms.load(Ordering::Relaxed))
      });
      let cache_entry =
         crate::dns::create_cache_entry_from_response(&response_result, response, generation, previous_expires_at, refresh_lease_until_ms);
      if lease_is_active(refresh_lease_until_ms) {
         set_refresh_phase(&cache_entry.refresh_state, REFRESH_ARMED);
      }
      completed_generation = generation;
      completed_expires_at = Some(cache_entry.expires_at);
      DNS_ANSWER_CACHE.insert(key.clone(), cache_entry);
      if entry.background_send_accepted {
         crate::stats::increment_refresh_succeeded();
      }
      dns_response = Some(response_result);
      true
   })?;

   IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
   let refresh_event =
      (dns_response.as_ref().unwrap().ttl > 0 && lease_is_active(in_flight.refresh_lease_until_ms)).then(|| RefreshEvent {
         cache_key: cache_key.to_vec(),
         generation: completed_generation,
         due_at: refresh_due_at(completed_expires_at.unwrap(), tokio::time::Instant::now()),
      });
   Some(InFlightCompletion { entry: in_flight, dns_response: dns_response.unwrap(), refresh_event })
}

pub struct ExpiredInFlight {
   pub entry: InFlightEntry,
   pub refresh_event: Option<RefreshEvent>,
}

pub fn in_flight_take_expired(now: tokio::time::Instant) -> Vec<ExpiredInFlight> {
   use std::sync::atomic::Ordering;

   let expired_keys: Vec<(Vec<u8>, u16)> =
      DNS_IN_FLIGHT.iter().filter(|entry| entry.deadline <= now).map(|entry| (entry.key().clone(), entry.upstream_id)).collect();
   let mut expired_entries = Vec::with_capacity(expired_keys.len());

   for (cache_key, upstream_id) in expired_keys {
      if let Some((_, entry)) = DNS_IN_FLIGHT.remove_if(&cache_key, |_, entry| entry.upstream_id == upstream_id && entry.deadline <= now) {
         IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
         let started_as_background = entry.started_as_background;
         let refresh_event =
            (started_as_background && answer_cache_rearm_refresh(&cache_key, entry.refresh_generation)).then(|| RefreshEvent {
               cache_key: cache_key.clone(),
               generation: entry.refresh_generation,
               due_at: now + crate::statics::BACKGROUND_REFRESH_RETRY_DELAY,
            });
         if entry.background_send_accepted && entry.background_refresh {
            crate::stats::increment_refresh_failed();
         }
         expired_entries.push(ExpiredInFlight { entry, refresh_event });
      }
   }

   expired_entries
}

// Answer cache interface functions
pub struct AnswerCacheLookup {
   pub answer: Vec<u8>,
   pub refresh_event: Option<RefreshEvent>,
}

pub fn answer_cache_get_for_client(cache_key: &[u8], current_time: tokio::time::Instant) -> Option<AnswerCacheLookup> {
   use std::sync::atomic::Ordering;

   let cached_response = DNS_ANSWER_CACHE.get(cache_key)?;
   let previous_lease_until_ms = cached_response.refresh_lease_until_ms.load(Ordering::Relaxed);
   if !lease_is_active(previous_lease_until_ms) {
      set_refresh_phase(&cached_response.refresh_state, REFRESH_ELIGIBLE);
   }
   cached_response.refresh_lease_until_ms.store(lease_deadline_ms(), Ordering::Relaxed);
   if cached_response.expires_at <= current_time {
      return None;
   }

   if previous_lease_until_ms != 0
      && cached_response.previous_expires_at.is_some_and(|old_expiry| current_time >= old_expiry)
      && cached_response.refresh_state.fetch_or(REFRESH_USEFUL_RECORDED, Ordering::Relaxed) & REFRESH_USEFUL_RECORDED == 0
   {
      crate::stats::increment_refresh_useful();
   }

   let mut refresh_event = None;
   if cached_response.refresh_state.load(Ordering::Relaxed) & REFRESH_PHASE_MASK == REFRESH_ELIGIBLE
      && cached_response
         .refresh_state
         .try_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
            (state & REFRESH_PHASE_MASK == REFRESH_ELIGIBLE).then_some((state & REFRESH_USEFUL_RECORDED) | REFRESH_ARMED)
         })
         .is_ok()
   {
      let due_at = refresh_due_at(cached_response.expires_at, current_time);
      refresh_event = Some(RefreshEvent { cache_key: cache_key.to_vec(), generation: cached_response.refresh_generation, due_at });
   }

   Some(AnswerCacheLookup { answer: cached_response.answer.clone(), refresh_event })
}

pub fn answer_cache_latencies() -> Vec<u64> {
   DNS_ANSWER_CACHE.iter().filter(|entry| entry.elapsed_ms <= 8_192).map(|entry| entry.elapsed_ms as u64).collect()
}
