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

lazy_static::lazy_static! {
   // Stores lists of blocked domains loaded from blocklists
   static ref BLOCKLISTS: tokio::sync::Mutex<Vec<crate::blocklist::BlocklistFile>> = tokio::sync::Mutex::new(Vec::new());
}

pub static mut STATS: once_cell::sync::Lazy<[crate::stats::Stats; crate::statics::DNS_SERVERS.len()]> =
   once_cell::sync::Lazy::new(crate::stats::init_stats);

pub async fn go(port: u16) {
   let proxy = tokio::task::spawn(async move {
      let listener_socket = {
         let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
         std::sync::Arc::new(tokio::net::UdpSocket::bind(listener_addr).await.unwrap())
      };

      let mut tx_channels: Vec<kanal::AsyncSender<Vec<u8>>> = Vec::with_capacity(crate::statics::DNS_SERVERS.len());

      for (dns_server_index, _) in crate::statics::DNS_SERVERS.iter().enumerate() {
         let (tx, rx) = kanal::bounded_async::<Vec<u8>>(8192);
         tokio::task::spawn(crate::network::upstream_tls_handler(rx, dns_server_index, listener_socket.clone()));
         tx_channels.push(tx);
      }

      // 2 bytes reserved for the TCP length + 512 bytes for the DNS query (which is defacto maximum)
      let mut query_buf = vec![0; 514];

      let mut cache_hits: u64 = 0;

      loop {
         // We reserve the first 2 bytes for the message length which is required for DNS over TCP
         let (read_bytes, client_addr) = match listener_socket.recv_from(&mut query_buf[2..]).await {
            Ok(res) => res,
            Err(err) => {
               println!("{err}");
               continue;
            }
         };
         assert!(read_bytes <= 512, "Received a datagram with > 512 bytes on the UDP socket");
         let udp_segment = &mut query_buf[2..read_bytes + 2];

         if crate::statics::ARGS.blocklists {
            let (question, primary_domain) = crate::dns::get_domain_for_filtering(udp_segment);

            let mut domain_is_blocked = false;
            for blocklist_file in BLOCKLISTS.lock().await.iter() {
               if blocklist_file.blocked_domains.contains(&question)
                  || (!primary_domain.is_empty() && blocklist_file.blocked_domains.contains(&primary_domain))
               {
                  crate::dns::mutate_question_into_bogus_response(udp_segment);
                  let wrote_len_maybe = listener_socket.send_to(udp_segment, &client_addr).await;

                  if let Ok(wrote_len) = wrote_len_maybe {
                     // Due to how rust implements IO for send_to, we will never have a len_written less than 0
                     if wrote_len == 0 {
                        eprintln!("Failed to write blocked response to the client. 0 bytes written at {}:{}", file!(), line!());
                     }
                  } else {
                     eprintln!(
                        "Failed to write cached response to the client with error: {} at {}:{}",
                        wrote_len_maybe.unwrap_err(),
                        file!(),
                        line!()
                     );
                  }

                  domain_is_blocked = true;
                  break;
               }
            }

            if domain_is_blocked {
               continue;
            }
         }

         let id = crate::dns::get_id_network_byte_order(udp_segment.as_ptr(), udp_segment.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

         // if the question / query is already in the question cache but not the answer cache, we delay for 50ms.
         // TODO: This is a temporary solution to prevent situation I ran into where I have thousands of simultaneous DNS requests to the same domain.
         if crate::cache::timing_cache_get(cache_key) {
            eprintln!("Query has not been answered yet. Delaying for 100ms");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
         }

         // First check the ANSWER cache and respond immediately if we already have an answer to the query
         if let Some(cached_response) = crate::cache::answer_cache_get_mut_check_expiry(cache_key, crate::util::get_unix_ts_secs()) {
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

         // We don't have it cached. Add to QUESTION cache
         crate::cache::timing_cache_insert(
            cache_key.to_vec(),
            crate::cache::TimingCacheEntry { asked_at: crate::util::get_unix_ts_millis() },
         );

         // Save the client state
         let client_addr_ipv4 = match client_addr {
            std::net::SocketAddr::V4(value) => value,
            _ => std::unreachable!(),
         };
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

         crate::network::router_insert(crate::util::encode_id_and_hash32_to_u64(id, crate::util::hash32(cache_key)), client_addr_ipv4);

         // Write both bytes at once after converting to Big Endian
         unsafe { *(query_buf.as_mut_ptr() as *mut u16) = (read_bytes as u16).to_be() };
         for tx in &tx_channels {
            match tx.send(query_buf[0..read_bytes + 2].to_vec()).await {
               Ok(_) => (),
               Err(err) => panic!("{}", err),
            };
         }
      }
   });

   if crate::statics::ARGS.blocklists {
      let blocklist = crate::blocklist::get_blocklists().await;
      *BLOCKLISTS.lock().await = blocklist;
   }

   proxy.await.unwrap();
}