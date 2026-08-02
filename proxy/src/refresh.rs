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
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

#[derive(Eq)]
struct ScheduledRefresh {
   cache_key: Vec<u8>,
   generation: u64,
   due_at: tokio::time::Instant,
}

impl Ord for ScheduledRefresh {
   fn cmp(&self, other: &Self) -> Ordering {
      self.due_at.cmp(&other.due_at).then_with(|| self.generation.cmp(&other.generation)).then_with(|| self.cache_key.cmp(&other.cache_key))
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

type ArmedRefreshes = HashMap<Vec<u8>, (tokio::time::Instant, u64), rustc_hash::FxBuildHasher>;

static REFRESH_TX: once_cell::sync::OnceCell<kanal::AsyncSender<crate::cache::RefreshEvent>> = once_cell::sync::OnceCell::new();

pub fn start(
   refresh_tx: kanal::AsyncSender<crate::cache::RefreshEvent>,
   refresh_rx: kanal::AsyncReceiver<crate::cache::RefreshEvent>,
   background_tx_channels: Vec<kanal::AsyncSender<crate::network::UpstreamQuery>>,
) {
   REFRESH_TX.set(refresh_tx).ok();
   tokio::task::spawn(run(refresh_rx, background_tx_channels));
}

pub fn schedule(event: crate::cache::RefreshEvent) {
   if REFRESH_TX.get().is_none_or(|tx| tx.try_send(event.clone()) != Ok(true)) {
      crate::cache::answer_cache_disarm_refresh(&event.cache_key, event.generation);
      crate::stats::increment_refresh_skipped();
   }
}

async fn run(
   refresh_rx: kanal::AsyncReceiver<crate::cache::RefreshEvent>,
   background_tx_channels: Vec<kanal::AsyncSender<crate::network::UpstreamQuery>>,
) {
   let semaphore = Arc::new(tokio::sync::Semaphore::new(crate::statics::BACKGROUND_REFRESH_CONCURRENCY));
   let mut schedule = BTreeSet::new();
   let mut armed =
      ArmedRefreshes::with_capacity_and_hasher(crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT, rustc_hash::FxBuildHasher::default());
   loop {
      while let Ok(Some(event)) = refresh_rx.try_recv() {
         admit(event, &mut schedule, &mut armed);
      }

      let Some(next_due) = schedule.first().map(|event| event.due_at) else {
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
            while schedule.first().is_some_and(|event| event.due_at <= now) {
               let event = schedule.pop_first().unwrap();
               armed.remove(&event.cache_key);
               dispatch(event, &semaphore, &background_tx_channels, &mut schedule, &mut armed);
            }
         }
      }
   }
}

fn admit(event: crate::cache::RefreshEvent, schedule: &mut BTreeSet<ScheduledRefresh>, armed: &mut ArmedRefreshes) {
   if let Some((old_due_at, old_generation)) = armed.get(&event.cache_key).copied() {
      if old_generation > event.generation {
         return;
      }
      schedule.remove(&ScheduledRefresh { cache_key: event.cache_key.clone(), generation: old_generation, due_at: old_due_at });
   } else if !crate::cache::refresh_event_is_current(&event.cache_key, event.generation) {
      return;
   } else if schedule.len() >= crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT {
      crate::cache::answer_cache_mark_refresh_attempted(&event.cache_key, event.generation);
      crate::stats::increment_refresh_skipped();
      return;
   }

   armed.insert(event.cache_key.clone(), (event.due_at, event.generation));
   schedule.insert(ScheduledRefresh { cache_key: event.cache_key, generation: event.generation, due_at: event.due_at });
}

fn dispatch(
   event: ScheduledRefresh,
   semaphore: &Arc<tokio::sync::Semaphore>,
   background_tx_channels: &[kanal::AsyncSender<crate::network::UpstreamQuery>],
   schedule: &mut BTreeSet<ScheduledRefresh>,
   armed: &mut ArmedRefreshes,
) {
   let Ok(permit) = semaphore.clone().try_acquire_owned() else {
      retry(event, schedule, armed);
      return;
   };

   let registration = crate::cache::background_refresh_register(&event.cache_key, event.generation, permit);
   let (upstream_id, deadline, query) = match registration {
      crate::cache::BackgroundRefreshRegistration::Leader { upstream_id, deadline, query } => (upstream_id, deadline, query),
      crate::cache::BackgroundRefreshRegistration::Retry => {
         retry(event, schedule, armed);
         return;
      }
      crate::cache::BackgroundRefreshRegistration::Stale => return,
   };

   let mut data = Vec::with_capacity(query.len() + 2);
   data.extend_from_slice(&(query.len() as u16).to_be_bytes());
   data.extend_from_slice(&query);
   let message = crate::network::UpstreamQuery { data, deadline };
   let sends = background_tx_channels.iter().filter(|tx| tx.try_send(message.clone()) == Ok(true)).count();

   if sends > 0 {
      if crate::cache::background_refresh_mark_sent(&event.cache_key, upstream_id) {
         crate::stats::increment_refresh_started();
      }
   } else {
      crate::cache::background_refresh_cancel(&event.cache_key, upstream_id);
      if crate::cache::answer_cache_rearm_refresh(&event.cache_key, event.generation) {
         retry(event, schedule, armed);
      } else {
         crate::stats::increment_refresh_skipped();
      }
   }
}

fn retry(event: ScheduledRefresh, schedule: &mut BTreeSet<ScheduledRefresh>, armed: &mut ArmedRefreshes) {
   let event = crate::cache::RefreshEvent { cache_key: event.cache_key, generation: event.generation, due_at: event.due_at }
      .retry_after(crate::statics::BACKGROUND_REFRESH_RETRY_DELAY);
   admit(event, schedule, armed);
}
