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

      for (dns_server_index, _) in crate::statics::DNS_SERVERS.iter().enumerate() {
         let (tx, rx) = kanal::bounded_async::<crate::network::UpstreamQuery>(8192);
         tokio::task::spawn(crate::network::upstream_tls_handler(rx, dns_server_index, listener_socket.clone()));
         tx_channels.push(tx);
      }

      // Initialize eBPF client identification before starting main loop
      #[cfg(target_os = "linux")]
      crate::network::initialize_ebpf_client_manager();

      {
         let listener_socket = listener_socket.clone();
         tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
            loop {
               interval.tick().await;
               for entry in crate::cache::in_flight_take_expired(tokio::time::Instant::now()) {
                  let mut response = entry.query_template;
                  crate::dns::create_servfail_response(&mut response);
                  let mut waiters = entry.waiters.into_iter();
                  let first_waiter = waiters.next().unwrap();
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

      let mut cache_hits: u64 = 0;

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

         // Process domain filtering
         let filter_result = crate::filter::process_domain_filtering(udp_segment, &listener_socket, &client_addr).await;
         if filter_result.is_blocked {
            continue;
         }

         let id = crate::dns::get_id_network_byte_order(udp_segment.as_ptr(), udp_segment.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());
         let current_time = crate::util::get_unix_ts_secs();

         // First check the ANSWER cache and respond immediately if we already have an answer to the query
         if let Some(cached_response) = crate::cache::answer_cache_get_mut_check_expiry(cache_key, current_time) {
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

            if !crate::statics::ARGS.daemon {
               cache_hits += 1;
               if cache_hits >= 16 && crate::util::is_power_of_2(cache_hits) {
                  tokio::task::spawn(async move {
                     // Filter out values greater than 8192ms as they are likely bogus, possibly caused by a drop in internet
                     // connectivity mid-query, or packet loss.
                     let mut elapsed_ms_vec: Vec<u64> = crate::cache::answer_cache_iter_filtered();
                     if elapsed_ms_vec.len() > 25 {
                        elapsed_ms_vec.sort_unstable();
                        let median = elapsed_ms_vec[elapsed_ms_vec.len() / 2];
                        println!("cache hits: {cache_hits}, median uncached query time: {median}ms, lowest: {}ms", elapsed_ms_vec[0]);
                        if crate::statics::ARGS.charts {
                           match crate::chart::generate_log_chart(elapsed_ms_vec) {
                              Ok(_) => (),
                              Err(err) => eprintln!("Failed to generate chart with error: {}", err),
                           }
                        }
                     }
                  });
               }
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
               let mut answer = cached_response.answer;
               crate::dns::set_id_network_byte_order(id, &mut answer);
               if let Err(err) = listener_socket.send_to(&answer, client_addr_ipv4).await {
                  eprintln!("Failed to write cached response to the client with error: {err}");
               }
            }
            crate::cache::InFlightRegistration::Joined => (),
            crate::cache::InFlightRegistration::Overflow => {
               crate::dns::create_servfail_response(udp_segment);
               if let Err(err) = listener_socket.send_to(udp_segment, client_addr_ipv4).await {
                  eprintln!("Failed to send overloaded response to the client with error: {err}");
               }
            }
            crate::cache::InFlightRegistration::Leader { upstream_id, deadline } => {
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

   // Initialize domain filtering system
   crate::filter::initialize_blocklists().await;

   proxy.await.unwrap();
}
