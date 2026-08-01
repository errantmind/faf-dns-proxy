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

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;

#[derive(Eq)]
struct ScheduledRefresh {
   cache_key: Vec<u8>,
   generation: u64,
   due_at: tokio::time::Instant,
}

impl Ord for ScheduledRefresh {
   fn cmp(&self, other: &Self) -> Ordering {
      other.due_at.cmp(&self.due_at).then_with(|| other.generation.cmp(&self.generation))
   }
}

impl PartialOrd for ScheduledRefresh {
   fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
      Some(self.cmp(other))
   }
}

impl PartialEq for ScheduledRefresh {
   fn eq(&self, other: &Self) -> bool {
      self.due_at == other.due_at && self.generation == other.generation && self.cache_key == other.cache_key
   }
}

struct SendRate {
   tokens: u32,
   last_refill: tokio::time::Instant,
}

impl SendRate {
   fn new(now: tokio::time::Instant) -> Self {
      Self { tokens: crate::statics::BACKGROUND_REFRESH_BURST, last_refill: now }
   }

   fn take(&mut self, now: tokio::time::Instant) -> bool {
      let elapsed_ns = now.duration_since(self.last_refill).as_nanos();
      let added = elapsed_ns * crate::statics::BACKGROUND_REFRESH_RATE_PER_SECOND as u128 / 1_000_000_000;
      if added > 0 {
         self.tokens = self.tokens.saturating_add(added.min(u32::MAX as u128) as u32).min(crate::statics::BACKGROUND_REFRESH_BURST);
         let used_ns = added * 1_000_000_000 / crate::statics::BACKGROUND_REFRESH_RATE_PER_SECOND as u128;
         self.last_refill += std::time::Duration::from_nanos(used_ns.min(u64::MAX as u128) as u64);
      }

      if self.tokens == 0 {
         false
      } else {
         self.tokens -= 1;
         true
      }
   }
}

type ArmedRefreshes = HashSet<Vec<u8>, rustc_hash::FxBuildHasher>;

pub fn start(
   refresh_rx: kanal::AsyncReceiver<crate::cache::RefreshEvent>,
   background_tx: kanal::AsyncSender<crate::network::UpstreamQuery>,
) {
   tokio::task::spawn(run(refresh_rx, background_tx));
}

async fn run(
   refresh_rx: kanal::AsyncReceiver<crate::cache::RefreshEvent>,
   background_tx: kanal::AsyncSender<crate::network::UpstreamQuery>,
) {
   let semaphore = Arc::new(tokio::sync::Semaphore::new(crate::statics::BACKGROUND_REFRESH_CONCURRENCY));
   let mut schedule = BinaryHeap::with_capacity(crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT);
   let mut armed =
      ArmedRefreshes::with_capacity_and_hasher(crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT, rustc_hash::FxBuildHasher::default());
   let mut rate = SendRate::new(tokio::time::Instant::now());

   loop {
      while let Ok(Some(event)) = refresh_rx.try_recv() {
         admit(event, &mut schedule, &mut armed);
      }

      let Some(next_due) = schedule.peek().map(|event| event.due_at) else {
         match refresh_rx.recv().await {
            Ok(event) => admit(event, &mut schedule, &mut armed),
            Err(_) => return,
         }
         continue;
      };

      tokio::select! {
         event = refresh_rx.recv() => match event {
            Ok(event) => admit(event, &mut schedule, &mut armed),
            Err(_) => return,
         },
         _ = tokio::time::sleep_until(next_due) => {
            let now = tokio::time::Instant::now();
            while schedule.peek().is_some_and(|event| event.due_at <= now) {
               let event = schedule.pop().unwrap();
               armed.remove(&event.cache_key);
               dispatch(event, now, &semaphore, &mut rate, &background_tx);
            }
         }
      }
   }
}

fn admit(event: crate::cache::RefreshEvent, schedule: &mut BinaryHeap<ScheduledRefresh>, armed: &mut ArmedRefreshes) {
   if schedule.len() >= crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT {
      crate::cache::answer_cache_mark_refresh_attempted(&event.cache_key, event.generation);
      return;
   }
   if !armed.insert(event.cache_key.clone()) {
      return;
   }

   schedule.push(ScheduledRefresh { cache_key: event.cache_key, generation: event.generation, due_at: event.due_at });
}

fn dispatch(
   event: ScheduledRefresh,
   now: tokio::time::Instant,
   semaphore: &Arc<tokio::sync::Semaphore>,
   rate: &mut SendRate,
   background_tx: &kanal::AsyncSender<crate::network::UpstreamQuery>,
) {
   let Ok(permit) = semaphore.clone().try_acquire_owned() else {
      crate::cache::answer_cache_mark_refresh_attempted(&event.cache_key, event.generation);
      return;
   };
   if !rate.take(now) {
      crate::cache::answer_cache_mark_refresh_attempted(&event.cache_key, event.generation);
      return;
   }

   let registration = crate::cache::background_refresh_register(&event.cache_key, event.generation, permit);
   let crate::cache::BackgroundRefreshRegistration::Leader { upstream_id, deadline, query } = registration else {
      if matches!(registration, crate::cache::BackgroundRefreshRegistration::AlreadyInFlight) {
         crate::cache::answer_cache_mark_refresh_attempted(&event.cache_key, event.generation);
      }
      return;
   };

   let mut data = Vec::with_capacity(query.len() + 2);
   data.extend_from_slice(&(query.len() as u16).to_be_bytes());
   data.extend_from_slice(&query);
   let message = crate::network::UpstreamQuery { data, deadline };

   if background_tx.try_send(message) != Ok(true) {
      crate::cache::background_refresh_cancel(&event.cache_key, upstream_id);
   }
}
