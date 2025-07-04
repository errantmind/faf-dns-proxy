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

pub struct TimingCacheEntry {
   pub asked_at: u128,
}

pub struct AnswerCacheEntry {
   pub answer: Vec<u8>,
   pub elapsed_ms: u128,
   pub expires_at: u64,
}

#[cfg(not(any(
   all(any(target_arch = "arm", target_arch = "aarch64"), target_feature = "aes", target_feature = "neon"),
   all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", target_feature = "sse2")
)))]
lazy_static::lazy_static! {
   // Stores when questions are asked
   static ref DNS_TIMING_CACHE: dashmap::DashMap<Vec<u8>, TimingCacheEntry, ahash::RandomState> =
      dashmap::DashMap::with_capacity_and_hasher(4096, ahash::RandomState::new());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<Vec<u8>, AnswerCacheEntry, ahash::RandomState> =
      dashmap::DashMap::with_capacity_and_hasher(4096, ahash::RandomState::new());
}

#[cfg(any(
   all(any(target_arch = "arm", target_arch = "aarch64"), target_feature = "aes", target_feature = "neon"),
   all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", target_feature = "sse2")
))]
lazy_static::lazy_static! {
   // Stores when questions are asked
   static ref DNS_TIMING_CACHE: dashmap::DashMap<Vec<u8>, TimingCacheEntry, gxhash::GxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, gxhash::GxBuildHasher::default());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<Vec<u8>, AnswerCacheEntry, gxhash::GxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, gxhash::GxBuildHasher::default());
}

// Timing cache interface functions
pub fn timing_cache_contains_key(cache_key: &[u8]) -> bool {
   DNS_TIMING_CACHE.contains_key(cache_key)
}

pub fn timing_cache_get(cache_key: &[u8]) -> bool {
   DNS_TIMING_CACHE.get(cache_key).is_some()
}

pub fn timing_cache_get_asked_at(cache_key: &[u8]) -> Option<u128> {
   DNS_TIMING_CACHE.get(cache_key).map(|entry| entry.asked_at)
}

pub fn timing_cache_insert(cache_key: Vec<u8>, entry: TimingCacheEntry) {
   DNS_TIMING_CACHE.insert(cache_key, entry);
}

pub fn timing_cache_remove(cache_key: &[u8]) -> Option<(Vec<u8>, TimingCacheEntry)> {
   DNS_TIMING_CACHE.remove(cache_key)
}

// Answer cache interface functions
pub fn answer_cache_contains_key(cache_key: &[u8]) -> bool {
   DNS_ANSWER_CACHE.contains_key(cache_key)
}

pub struct AnswerCacheRef {
   pub expires_at: u64,
   pub answer: Vec<u8>,
}

pub fn answer_cache_get_mut_check_expiry(cache_key: &[u8], current_time: u64) -> Option<AnswerCacheRef> {
   if let Some(cached_response) = DNS_ANSWER_CACHE.get(cache_key) {
      if cached_response.expires_at > current_time {
         Some(AnswerCacheRef { expires_at: cached_response.expires_at, answer: cached_response.answer.clone() })
      } else {
         None
      }
   } else {
      None
   }
}

pub fn answer_cache_insert(cache_key: Vec<u8>, entry: AnswerCacheEntry) {
   DNS_ANSWER_CACHE.insert(cache_key, entry);
}

pub fn answer_cache_remove(cache_key: &[u8]) -> Option<(Vec<u8>, AnswerCacheEntry)> {
   DNS_ANSWER_CACHE.remove(cache_key)
}

pub fn answer_cache_iter_filtered() -> Vec<u64> {
   DNS_ANSWER_CACHE.iter().filter(|x| x.elapsed_ms <= 8192).map(|x| x.elapsed_ms as u64).collect()
}
