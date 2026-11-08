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

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheKey {
   question: Vec<u8>,
   settings: crate::dns::QuerySettings,
}

#[derive(Clone, Copy)]
pub struct CacheKeyRef<'a> {
   pub question: &'a [u8],
   pub settings: crate::dns::QuerySettings,
}

trait CacheKeyView {
   fn question(&self) -> &[u8];
   fn settings(&self) -> crate::dns::QuerySettings;
}

impl CacheKeyView for CacheKey {
   #[inline]
   fn question(&self) -> &[u8] {
      &self.question
   }

   #[inline]
   fn settings(&self) -> crate::dns::QuerySettings {
      self.settings
   }
}

impl CacheKeyView for CacheKeyRef<'_> {
   #[inline]
   fn question(&self) -> &[u8] {
      self.question
   }

   #[inline]
   fn settings(&self) -> crate::dns::QuerySettings {
      self.settings
   }
}

impl Hash for dyn CacheKeyView + '_ {
   #[inline]
   fn hash<H: Hasher>(&self, state: &mut H) {
      self.settings().hash(state);
      self.question().hash(state);
   }
}

impl PartialEq for dyn CacheKeyView + '_ {
   #[inline]
   fn eq(&self, other: &Self) -> bool {
      self.settings() == other.settings() && self.question() == other.question()
   }
}

impl Eq for dyn CacheKeyView + '_ {}

impl Hash for CacheKey {
   #[inline]
   fn hash<H: Hasher>(&self, state: &mut H) {
      (self as &dyn CacheKeyView).hash(state);
   }
}

impl<'a> Borrow<dyn CacheKeyView + 'a> for CacheKey {
   #[inline]
   fn borrow(&self) -> &(dyn CacheKeyView + 'a) {
      self
   }
}

impl CacheKeyRef<'_> {
   #[inline]
   fn into_owned(self) -> CacheKey {
      CacheKey { question: self.question.to_vec(), settings: self.settings }
   }
}

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
   pub settings: Option<crate::dns::QuerySettings>,
   pub background_refresh: bool,
   pub started_as_background: bool,
   pub background_send_accepted: bool,
   pub refresh_generation: u64,
   pub refresh_lease_until_ms: u64,
   pub background_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

#[derive(Default)]
struct InFlightBucket {
   first: Option<InFlightEntry>,
   rest: Vec<InFlightEntry>,
}

impl InFlightBucket {
   #[inline]
   fn entries(&self) -> impl Iterator<Item = &InFlightEntry> {
      self.first.iter().chain(self.rest.iter())
   }

   #[inline]
   fn entries_mut(&mut self) -> impl Iterator<Item = &mut InFlightEntry> {
      self.first.iter_mut().chain(self.rest.iter_mut())
   }

   fn push(&mut self, entry: InFlightEntry) {
      if self.first.is_none() {
         self.first = Some(entry);
      } else {
         self.rest.push(entry);
      }
   }

   fn take(&mut self, upstream_id: u16) -> Option<InFlightEntry> {
      if self.first.as_ref().is_some_and(|entry| entry.upstream_id == upstream_id) {
         let entry = self.first.take();
         self.first = self.rest.pop();
         return entry;
      }
      let index = self.rest.iter().position(|entry| entry.upstream_id == upstream_id)?;
      Some(self.rest.swap_remove(index))
   }
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
   pub opt_offset: Option<u16>,
   pub elapsed_ms: u128,
   pub expires_at: tokio::time::Instant,
   pub previous_expires_at: Option<tokio::time::Instant>,
   pub refresh_generation: u64,
   pub(crate) refresh_state: std::sync::atomic::AtomicU8,
   pub(crate) refresh_lease_until_ms: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct RefreshEvent {
   pub cache_key: CacheKey,
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
   static ref DNS_IN_FLIGHT: dashmap::DashMap<Vec<u8>, InFlightBucket, rustc_hash::FxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4_096, rustc_hash::FxBuildHasher::default());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<CacheKey, AnswerCacheEntry, rustc_hash::FxBuildHasher> =
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

fn reserve_upstream_id(bucket: &InFlightBucket) -> Option<u16> {
   use std::sync::atomic::Ordering;

   IN_FLIGHT_COUNT.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < MAX_IN_FLIGHT).then_some(count + 1)).ok()?;
   loop {
      let upstream_id = NEXT_UPSTREAM_ID.fetch_add(1, Ordering::Relaxed);
      if !bucket.entries().any(|entry| entry.upstream_id == upstream_id) {
         return Some(upstream_id);
      }
   }
}

fn query_template(query: &[u8], question_len: usize, settings: Option<crate::dns::QuerySettings>) -> Vec<u8> {
   let end = 12 + question_len;
   let mut template = Vec::with_capacity(end + settings.map_or(0, crate::dns::QuerySettings::opt_len));
   template.extend_from_slice(&query[..end]);
   template
}

fn register_foreground(
   bucket: &mut InFlightBucket,
   question: &[u8],
   settings: Option<crate::dns::QuerySettings>,
   query: &[u8],
   waiter: InFlightWaiter,
   current_time: tokio::time::Instant,
) -> InFlightRegistration {
   use std::sync::atomic::Ordering;

   let mut refresh_generation = 0;
   let mut refresh_lease_until_ms = 0;
   if let Some(settings) = settings {
      if let Some(entry) = bucket.entries_mut().find(|entry| entry.settings == Some(settings)) {
         return join_in_flight(entry, waiter);
      }
      let key = CacheKeyRef { question, settings };
      if let Some(cached_response) = answer_cache_get_for_client(&key, current_time) {
         return InFlightRegistration::Cached(cached_response);
      }
      if let Some(answer) = DNS_ANSWER_CACHE.get(&key as &dyn CacheKeyView) {
         refresh_generation = answer.refresh_generation;
         refresh_lease_until_ms = lease_deadline_ms();
         answer.refresh_lease_until_ms.store(refresh_lease_until_ms, Ordering::Relaxed);
      }
   }

   let Some(upstream_id) = reserve_upstream_id(bucket) else {
      return InFlightRegistration::Overflow;
   };
   let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
   bucket.push(InFlightEntry {
      upstream_id,
      asked_at: crate::util::get_unix_ts_millis(),
      deadline,
      waiters: vec![waiter],
      query_template: query_template(query, question.len(), settings),
      settings,
      background_refresh: false,
      started_as_background: false,
      background_send_accepted: false,
      refresh_generation,
      refresh_lease_until_ms,
      background_permit: None,
   });
   InFlightRegistration::Leader { upstream_id, deadline }
}

pub fn in_flight_register(
   question: &[u8],
   settings: Option<crate::dns::QuerySettings>,
   query: &[u8],
   waiter: InFlightWaiter,
   current_time: tokio::time::Instant,
) -> InFlightRegistration {
   use dashmap::mapref::entry::Entry;

   if let Some(mut bucket) = DNS_IN_FLIGHT.get_mut(question) {
      return register_foreground(&mut bucket, question, settings, query, waiter, current_time);
   }
   match DNS_IN_FLIGHT.entry(question.to_vec()) {
      Entry::Occupied(mut entry) => register_foreground(entry.get_mut(), question, settings, query, waiter, current_time),
      Entry::Vacant(entry) => {
         let mut bucket = InFlightBucket::default();
         let registration = register_foreground(&mut bucket, question, settings, query, waiter, current_time);
         if bucket.first.is_some() {
            entry.insert(bucket);
         }
         registration
      }
   }
}

fn register_background(
   bucket: &mut InFlightBucket,
   cache_key: &CacheKey,
   expected_generation: u64,
   permit: tokio::sync::OwnedSemaphorePermit,
) -> BackgroundRefreshRegistration {
   use std::sync::atomic::Ordering;

   if bucket.entries().any(|entry| entry.settings == Some(cache_key.settings)) {
      return BackgroundRefreshRegistration::Stale;
   }
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
   let Some(upstream_id) = reserve_upstream_id(bucket) else {
      return BackgroundRefreshRegistration::Retry;
   };
   let deadline = tokio::time::Instant::now() + IN_FLIGHT_TIMEOUT;
   let query = crate::dns::create_refresh_query(&cache_key.question, cache_key.settings, upstream_id);
   let refresh_lease_until_ms = answer.refresh_lease_until_ms.load(Ordering::Relaxed);
   set_refresh_phase(&answer.refresh_state, REFRESH_ATTEMPTED);
   drop(answer);

   bucket.push(InFlightEntry {
      upstream_id,
      asked_at: crate::util::get_unix_ts_millis(),
      deadline,
      waiters: Vec::new(),
      query_template: query_template(&query, cache_key.question.len(), Some(cache_key.settings)),
      settings: Some(cache_key.settings),
      background_refresh: true,
      started_as_background: true,
      background_send_accepted: false,
      refresh_generation: expected_generation,
      refresh_lease_until_ms,
      background_permit: Some(permit),
   });
   BackgroundRefreshRegistration::Leader { upstream_id, deadline, query }
}

pub fn background_refresh_register(
   cache_key: &CacheKey,
   expected_generation: u64,
   permit: tokio::sync::OwnedSemaphorePermit,
) -> BackgroundRefreshRegistration {
   use dashmap::mapref::entry::Entry;

   match DNS_IN_FLIGHT.entry(cache_key.question.clone()) {
      Entry::Occupied(mut entry) => register_background(entry.get_mut(), cache_key, expected_generation, permit),
      Entry::Vacant(entry) => {
         let mut bucket = InFlightBucket::default();
         let registration = register_background(&mut bucket, cache_key, expected_generation, permit);
         if bucket.first.is_some() {
            entry.insert(bucket);
         }
         registration
      }
   }
}

fn take_in_flight(question: &[u8], upstream_id: u16, predicate: impl FnOnce(&mut InFlightEntry) -> bool) -> Option<InFlightEntry> {
   use std::sync::atomic::Ordering;

   let mut removed = None;
   DNS_IN_FLIGHT.remove_if_mut(question, |_, bucket| {
      let should_remove = bucket.entries_mut().find(|entry| entry.upstream_id == upstream_id).is_some_and(predicate);
      if should_remove {
         removed = bucket.take(upstream_id);
      }
      bucket.first.is_none()
   });
   if removed.is_some() {
      IN_FLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
   }
   removed
}

pub fn background_refresh_mark_sent(cache_key: &CacheKey, upstream_id: u16) -> bool {
   if let Some(mut bucket) = DNS_IN_FLIGHT.get_mut(&cache_key.question)
      && let Some(entry) = bucket.entries_mut().find(|entry| entry.upstream_id == upstream_id)
      && entry.settings == Some(cache_key.settings)
      && entry.started_as_background
   {
      entry.background_send_accepted = true;
      true
   } else {
      false
   }
}

pub fn background_refresh_cancel(cache_key: &CacheKey, upstream_id: u16) {
   take_in_flight(&cache_key.question, upstream_id, |entry| entry.settings == Some(cache_key.settings) && entry.background_refresh);
}

pub fn answer_cache_mark_refresh_attempted(cache_key: &CacheKey, generation: u64) {
   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
   {
      set_refresh_phase(&answer.refresh_state, REFRESH_ATTEMPTED);
   }
}

pub fn answer_cache_disarm_refresh(cache_key: &CacheKey, generation: u64) {
   if let Some(answer) = DNS_ANSWER_CACHE.get(cache_key)
      && answer.refresh_generation == generation
   {
      set_refresh_phase(&answer.refresh_state, REFRESH_ELIGIBLE);
   }
}

pub fn answer_cache_rearm_refresh(cache_key: &CacheKey, generation: u64) -> bool {
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

pub fn refresh_event_is_current(cache_key: &CacheKey, generation: u64) -> bool {
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

   let mut dns_response = None;
   let mut refresh_event = None;
   let in_flight = take_in_flight(question.cache_key(), question.id(), |entry| {
      let mut response_result = crate::dns::process_dns_response(question, Some(entry.asked_at), entry.settings);
      if let Some(settings) = entry.settings {
         let key = CacheKeyRef { question: question.cache_key(), settings };
         if response_result.cache_layout.is_some() {
            let mut previous_expires_at = None;
            let mut refresh_lease_until_ms = entry.refresh_lease_until_ms;
            if let Some(answer) = DNS_ANSWER_CACHE.get(&key as &dyn CacheKeyView) {
               if entry.started_as_background && entry.background_refresh {
                  response_result.elapsed_ms = answer.elapsed_ms;
                  previous_expires_at = Some(answer.expires_at);
               }
               refresh_lease_until_ms = refresh_lease_until_ms.max(answer.refresh_lease_until_ms.load(Ordering::Relaxed));
            }
            let generation = NEXT_REFRESH_GENERATION.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            let cache_entry = crate::dns::create_cache_entry_from_response(
               &response_result,
               question.message(),
               generation,
               previous_expires_at,
               refresh_lease_until_ms,
            );
            let key = key.into_owned();
            if lease_is_active(refresh_lease_until_ms) {
               set_refresh_phase(&cache_entry.refresh_state, REFRESH_ARMED);
               if response_result.ttl > 0 {
                  refresh_event = Some(RefreshEvent {
                     cache_key: key.clone(),
                     generation,
                     due_at: refresh_due_at(cache_entry.expires_at, tokio::time::Instant::now()),
                  });
               }
            }
            DNS_ANSWER_CACHE.insert(key, cache_entry);
            if entry.background_send_accepted {
               crate::stats::increment_refresh_succeeded();
            }
         } else {
            DNS_ANSWER_CACHE.remove(&key as &dyn CacheKeyView);
            if entry.background_send_accepted {
               crate::stats::increment_refresh_failed();
            }
         }
      }
      dns_response = Some(response_result);
      true
   })?;

   Some(InFlightCompletion { entry: in_flight, dns_response: dns_response.unwrap(), refresh_event })
}

pub struct ExpiredInFlight {
   pub entry: InFlightEntry,
   pub refresh_event: Option<RefreshEvent>,
}

pub fn in_flight_take_expired(now: tokio::time::Instant) -> Vec<ExpiredInFlight> {
   let mut expired_keys = Vec::new();
   for bucket in DNS_IN_FLIGHT.iter() {
      for entry in bucket.entries().filter(|entry| entry.deadline <= now) {
         expired_keys.push((bucket.key().clone(), entry.upstream_id));
      }
   }
   let mut expired_entries = Vec::with_capacity(expired_keys.len());

   for (question, upstream_id) in expired_keys {
      if let Some(entry) = take_in_flight(&question, upstream_id, |entry| entry.deadline <= now) {
         let refresh_event = if entry.started_as_background
            && let Some(settings) = entry.settings
         {
            let cache_key = CacheKey { question, settings };
            answer_cache_rearm_refresh(&cache_key, entry.refresh_generation).then(|| RefreshEvent {
               cache_key,
               generation: entry.refresh_generation,
               due_at: now + crate::statics::BACKGROUND_REFRESH_RETRY_DELAY,
            })
         } else {
            None
         };
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

pub fn answer_cache_get_for_client(cache_key: &CacheKeyRef<'_>, current_time: tokio::time::Instant) -> Option<AnswerCacheLookup> {
   use std::sync::atomic::Ordering;

   let cached_response = DNS_ANSWER_CACHE.get(cache_key as &dyn CacheKeyView)?;
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
      refresh_event = Some(RefreshEvent { cache_key: cache_key.into_owned(), generation: cached_response.refresh_generation, due_at });
   }

   let mut answer = cached_response.answer.clone();
   if let Some(offset) = cached_response.opt_offset {
      cache_key.settings.write_response_opt(&mut answer[usize::from(offset)..usize::from(offset) + 11]);
   }
   Some(AnswerCacheLookup { answer, refresh_event })
}

pub fn answer_cache_latencies() -> Vec<u64> {
   DNS_ANSWER_CACHE.iter().filter(|entry| entry.elapsed_ms <= 8_192).map(|entry| entry.elapsed_ms as u64).collect()
}
