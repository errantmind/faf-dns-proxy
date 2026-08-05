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

// STATS removed - now using atomic counters in stats.rs module

pub async fn go(port: u16) {
   let proxy = tokio::task::spawn(async move {
      let listener_socket = {
         let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
         std::sync::Arc::new(tokio::net::UdpSocket::bind(listener_addr).await.unwrap())
      };

      let mut tx_channels: Vec<kanal::AsyncSender<crate::network::UpstreamQuery>> = Vec::with_capacity(crate::statics::DNS_SERVERS.len());
      let mut background_tx_channels = Vec::with_capacity(crate::statics::DNS_SERVERS.len());

      for (dns_server_index, _) in crate::statics::DNS_SERVERS.iter().enumerate() {
         let (tx, rx) = kanal::bounded_async::<crate::network::UpstreamQuery>(8192);
         let (background_tx, background_rx) = kanal::bounded_async::<crate::network::UpstreamQuery>(64);
         tokio::task::spawn(crate::network::upstream_tls_handler(rx, Some(background_rx), dns_server_index, listener_socket.clone()));
         tx_channels.push(tx);
         background_tx_channels.push(background_tx);
      }

      let (refresh_tx, refresh_rx) = kanal::bounded_async::<crate::cache::RefreshEvent>(crate::statics::BACKGROUND_REFRESH_ACTIVE_LIMIT);
      crate::refresh::start(refresh_tx, refresh_rx, background_tx_channels);

      // Initialize eBPF client identification before starting main loop
      #[cfg(target_os = "linux")]
      crate::network::initialize_ebpf_client_manager();

      {
         let listener_socket = listener_socket.clone();
         tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
            loop {
               interval.tick().await;
               for expired in crate::cache::in_flight_take_expired(tokio::time::Instant::now()) {
                  if let Some(refresh_event) = expired.refresh_event {
                     crate::refresh::schedule(refresh_event);
                  }
                  let entry = expired.entry;
                  let mut response = entry.query_template;
                  crate::dns::create_servfail_response(&mut response);
                  let mut waiters = entry.waiters.into_iter();
                  let Some(first_waiter) = waiters.next() else {
                     continue;
                  };
                  crate::dns::set_id_network_byte_order(first_waiter.client_id, &mut response);
                  if let Err(err) = listener_socket.send_to(&response, first_waiter.client_addr).await {
                     eprintln!("Failed to send timed out response to the client with error: {err}");
                  }

                  if waiters.len() > 0 {
                     let listener_socket = listener_socket.clone();
                     tokio::task::spawn(async move {
                        for waiter in waiters {
                           crate::dns::set_id_network_byte_order(waiter.client_id, &mut response);
                           if let Err(err) = listener_socket.send_to(&response, waiter.client_addr).await {
                              eprintln!("Failed to send timed out response to the client with error: {err}");
                           }
                        }
                     });
                  }
               }
            }
         });
      }

      // Reserve 2 bytes for the DNS-over-TCP length prefix.
      let mut query_buf = vec![0; crate::dns::MAX_DNS_MESSAGE_SIZE + 2];

      // Print header for DNS output when not in daemon mode
      if !crate::statics::ARGS.daemon {
         #[cfg(target_os = "linux")]
         let header = if crate::statics::ARGS.client_ident {
            format!(
               "  {:>4} -> {:<50} {:>7} {:>3} {:>7} {:^23} {:>7} - {:^40}",
               "TIME", "DOMAIN", "TYPE", "CLS", "TTL", "UPSTREAM", "REF", "PROCESS (CLIENT) [METHOD]"
            )
         } else {
            format!("  {:>4} -> {:<50} {:>7} {:>3} {:>7} {:^23} {:>7}", "TIME", "DOMAIN", "TYPE", "CLS", "TTL", "UPSTREAM", "REF")
         };

         #[cfg(not(target_os = "linux"))]
         let header =
            format!("  {:>4} -> {:<50} {:>7} {:>3} {:>7} {:^23} {:>7}", "TIME", "DOMAIN", "TYPE", "CLS", "TTL", "UPSTREAM", "REF");

         println!("{}", header);
         println!("{}", "=".repeat(header.len()));
         crate::stats::start_reporter();
      }

      loop {
         // We reserve the first 2 bytes for the message length which is required for DNS over TCP
         let (read_bytes, client_addr) = match listener_socket.recv_from(&mut query_buf[2..]).await {
            Ok(res) => res,
            Err(err) => {
               println!("{err}");
               continue;
            }
         };
         assert!(read_bytes <= crate::dns::MAX_DNS_MESSAGE_SIZE, "Received an oversized datagram on the UDP socket");
         let udp_segment = &mut query_buf[2..read_bytes + 2];

         let id = crate::dns::get_id_network_byte_order(udp_segment.as_ptr(), udp_segment.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());
         let current_time = tokio::time::Instant::now();

         // First check the ANSWER cache and respond immediately if we already have an answer to the query.
         // Scheduling is nonblocking; a full refresh queue never delays the cache-hit path.
         if let Some(cached_response) = crate::cache::answer_cache_get_for_client(cache_key, current_time) {
            if let Some(refresh_event) = cached_response.refresh_event {
               crate::refresh::schedule(refresh_event);
            }
            let cache_hits = crate::stats::increment_cache_hit();
            let mut answer = cached_response.answer;
            crate::dns::set_id_network_byte_order(id, &mut answer);
            let wrote_len_maybe = listener_socket.send_to(&answer, &client_addr).await;

            if let Ok(wrote_len) = wrote_len_maybe {
               // Due to how rust implements IO for send_to, we will never have a len_written less than 0
               if wrote_len == 0 {
                  eprintln!("Failed to write response to the client. 0 bytes written at {}:{}", file!(), line!());
                  continue;
               }
            } else {
               eprintln!(
                  "Failed to write cached response to the client with error: {} at {}:{}",
                  wrote_len_maybe.unwrap_err(),
                  file!(),
                  line!()
               );
               continue;
            }

            if !crate::statics::ARGS.daemon && crate::statics::ARGS.charts && cache_hits >= 16 && crate::util::is_power_of_2(cache_hits) {
               tokio::task::spawn(async move {
                  let mut elapsed_ms_vec = crate::cache::answer_cache_latencies();
                  if elapsed_ms_vec.len() > 25 {
                     elapsed_ms_vec.sort_unstable();
                     if let Err(err) = crate::chart::generate_log_chart(elapsed_ms_vec) {
                        eprintln!("Failed to generate chart with error: {err}");
                     }
                  }
               });
            }
            continue;
         }

         let client_addr_ipv4 = match client_addr {
            std::net::SocketAddr::V4(value) => value,
            _ => std::unreachable!(),
         };
         let registration = crate::cache::in_flight_register(
            cache_key,
            udp_segment,
            crate::cache::InFlightWaiter { client_addr: client_addr_ipv4, client_id: id },
            current_time,
         );

         match registration {
            crate::cache::InFlightRegistration::Cached(cached_response) => {
               crate::stats::increment_cache_hit();
               if let Some(refresh_event) = cached_response.refresh_event {
                  crate::refresh::schedule(refresh_event);
               }
               let mut answer = cached_response.answer;
               crate::dns::set_id_network_byte_order(id, &mut answer);
               if let Err(err) = listener_socket.send_to(&answer, client_addr_ipv4).await {
                  eprintln!("Failed to write cached response to the client with error: {err}");
               }
            }
            crate::cache::InFlightRegistration::Joined => {
               crate::stats::increment_cache_miss();
            }
            crate::cache::InFlightRegistration::PromotedBackground => {
               crate::stats::increment_cache_miss();
            }
            crate::cache::InFlightRegistration::Overflow => {
               crate::stats::increment_cache_miss();
               crate::dns::create_servfail_response(udp_segment);
               if let Err(err) = listener_socket.send_to(udp_segment, client_addr_ipv4).await {
                  eprintln!("Failed to send overloaded response to the client with error: {err}");
               }
            }
            crate::cache::InFlightRegistration::Leader { upstream_id, deadline } => {
               crate::stats::increment_cache_miss();
               crate::dns::set_id_network_byte_order(upstream_id, udp_segment);

               // Write both bytes at once after converting to Big Endian
               unsafe { *(query_buf.as_mut_ptr() as *mut u16) = (read_bytes as u16).to_be() };
               let query = crate::network::UpstreamQuery { data: query_buf[0..read_bytes + 2].to_vec(), deadline };
               for tx in &tx_channels {
                  match tx.send(query.clone()).await {
                     Ok(_) => (),
                     Err(err) => panic!("{}", err),
                  };
               }
            }
         }
      }
   });

   proxy.await.unwrap();
}
