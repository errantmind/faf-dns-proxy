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

use hashbrown::HashMap;

static mut STATS: once_cell::sync::Lazy<[crate::stats::Stats; crate::statics::UPSTREAM_DNS_SERVERS.len()]> =
   once_cell::sync::Lazy::new(crate::stats::init_stats);

struct QuestionCache {
   asked_at: u128,
}

struct AnswerCache {
   answer: Vec<u8>,
   _elapsed_ms: u128,
   expires_at: u64,
}

const CONN_ERROR_SLEEP_MS: u64 = 1000;

lazy_static::lazy_static! {
   static ref DNS_QUESTION_CACHE: tokio::sync::Mutex<HashMap<Vec<u8>, QuestionCache>> =
   tokio::sync::Mutex::new(HashMap::default());

   static ref DNS_ANSWER_CACHE: tokio::sync::Mutex<HashMap<Vec<u8>, AnswerCache>> =
   tokio::sync::Mutex::new(HashMap::default());

   // We route DNS responses by the id they provided in the initial request. This may occasionally cause
   // timing collisions but they should be very rare. There is a 1 / 2^16 chance of a collision, but even then
   // only if the requests arrive around the exact same time with the same id. Note, cached responses are not
   // affected by this, which makes the odds even lower.
   static ref BUF_ID_ROUTER: tokio::sync::Mutex<HashMap<u16, std::net::SocketAddr>> = tokio::sync::Mutex::new(HashMap::default());

}

pub async fn go(port: u16) {
   tokio::task::spawn(async move {
      let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
      let listener_socket = std::sync::Arc::new(tokio::net::UdpSocket::bind(listener_addr).await.unwrap());

      let mut tx_channels = Vec::with_capacity(crate::statics::UPSTREAM_DNS_SERVERS.len());

      for dns in &crate::statics::UPSTREAM_DNS_SERVERS {
         let (tx, rx) = tokio::sync::mpsc::channel(8192);
         tokio::task::spawn(upstream_tls_handler(rx, dns, listener_socket.clone()));
         tx_channels.push(tx);
      }

      let mut query_buf = vec![0; 514];
      let mut cache_hits: u64 = 0;
      let mut cache_hits_print_threshold = 16;

      loop {
         let (read_bytes, client_addr) = match listener_socket.recv_from(&mut query_buf[2..]).await {
            Ok(res) => res,
            Err(err) => {
               println!("{err}");
               continue;
            }
         };
         assert!(read_bytes <= 512, "Received a datagram with > 512 bytes on the listening socket");
         let udp_segment = &query_buf[2..read_bytes + 2];

         let id = crate::dns::get_id(udp_segment.as_ptr(), udp_segment.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

         {
            // Add to QUESTION cache (only once)

            let mut question_cache_guard = DNS_QUESTION_CACHE.lock().await;
            if !question_cache_guard.contains_key(cache_key) {
               question_cache_guard.insert(cache_key.to_vec(), QuestionCache { asked_at: crate::util::get_unix_ts_millis() });
            }
         }

         {
            // Scope for cache guard.
            // First check the ANSWER cache and respond immediately if we already have an answer to the query

            let mut answer_cache_guard = DNS_ANSWER_CACHE.lock().await;
            let cached_response_maybe = answer_cache_guard.get_mut(cache_key);

            if let Some(cached_response) = cached_response_maybe {
               if cached_response.expires_at > crate::util::get_unix_ts_secs() {
                  crate::dns::set_id_big_endian(id, &mut cached_response.answer);
                  let wrote = listener_socket.send_to(&cached_response.answer, &client_addr).await.unwrap();
                  assert!(wrote != 0, "Wrote nothing to client after fetching data from cache");

                  {
                     // Temp: Track cache hits

                     cache_hits += 1;
                     if cache_hits >= cache_hits_print_threshold {
                        println!("cache hits: {cache_hits_print_threshold}");
                        cache_hits_print_threshold <<= 1;
                     }
                  }

                  continue;
               } else {
                  answer_cache_guard.remove_entry(cache_key);
                  DNS_QUESTION_CACHE.lock().await.insert(cache_key.to_vec(), QuestionCache { asked_at: crate::util::get_unix_ts_millis() });
               }
            }
         }

         {
            // Save the client state
            BUF_ID_ROUTER.lock().await.insert(id, client_addr);
         }

         // Write both bytes at once after converting to Big Endian
         unsafe { *(query_buf.as_mut_ptr() as *mut u16) = (read_bytes as u16).to_be() };
         for tx in &tx_channels {
            match tx.send(query_buf[0..read_bytes + 2].to_vec()).await {
               Ok(_) => (),
               Err(err) => panic!("{}", err),
            };
         }
      }
   })
   .await
   .unwrap();
}

pub async fn upstream_tls_handler(
   mut msg_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
   upstream_dns: &crate::statics::UpstreamDnsServer,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
) {
   let tls_client_config = crate::tls::get_tls_client_config();
   let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config));

   let mut tls_stream = connect(&tls_connector, upstream_dns).await;

   let mut response_buf = vec![0; 2 << 15];

   loop {
      let msg_maybe = match tokio::time::timeout(std::time::Duration::from_nanos(100_000), msg_rx.recv()).await {
         Ok(msg_maybe) => match msg_maybe {
            Some(data) => Some(data),
            None => {
               panic!("Channel has been closed prematurely");
            }
         },
         Err(_) => None,
      };

      if let Some(query_buf) = msg_maybe {
         loop {
            // If we have a query from our local listener, write it to the upstream DNS server.
            //
            // We need the below convoluted logic because there doesn't appear to be any way to detect HUPs (hangups).
            // So, say we get silently disconnected by DNS server (google DNS, cloudflare, etc), a simple `write` call will succeed (!),
            //   which makes us believe the write was successful, even though it was never delivered.
            // We NEED a way to know if we still have a 'valid' connection.
            //
            if let Ok(ready_status) = tls_stream.get_ref().0.ready(tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE).await {
               if !ready_status.is_read_closed() && !ready_status.is_write_closed() {
                  if let Ok(_bytes_written_to_socket) = tokio::io::AsyncWriteExt::write(&mut tls_stream, &query_buf).await {
                     break;
                  }
               }
            }

            tls_stream = connect(&tls_connector, upstream_dns).await
         }
      } else {
         // No request for writes, try reads

         let read_bytes_maybe = match tokio::time::timeout(
            std::time::Duration::from_nanos(100_000),
            tokio::io::AsyncReadExt::read(&mut tls_stream, &mut response_buf),
         )
         .await
         {
            Ok(msg_maybe) => match msg_maybe {
               Ok(0) => None,
               Ok(n) => Some(n),
               Err(_) => None,
            },
            Err(_) => None,
         };

         let read_bytes_tcp = match read_bytes_maybe {
            Some(n) => n,
            None => continue,
         };

         let mut offset = 0;
         loop {
            let udp_segment_len = crate::dns::get_tcp_dns_size_prefix_le(&response_buf[offset..]);
            if !udp_segment_len > 0 && !udp_segment_len <= 512 {
               panic!("Tcp reported len is invalid ({udp_segment_len})");
            };
            assert!(
               udp_segment_len <= (read_bytes_tcp - 2),
               "Udp segment length cannot be larger than the TCP wrapper ({udp_segment_len}/{read_bytes_tcp})"
            );

            let udp_segment_no_tcp_prefix = &response_buf[offset + 2..offset + udp_segment_len + 2];

            // Scope for guards
            {
               {
                  let id = crate::dns::get_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
                  let cache_key = crate::dns::get_query_unique_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
                  let mut cache_guard = DNS_ANSWER_CACHE.lock().await;
                  if !cache_guard.contains_key(cache_key) {
                     let id_router_guard = BUF_ID_ROUTER.lock().await;
                     let saved_addr = id_router_guard.get(&id).unwrap();

                     let wrote = listener_addr.send_to(udp_segment_no_tcp_prefix, &saved_addr).await.unwrap();

                     if wrote == 0 {
                        panic!("Wrote nothing to client after receiving data from upstream")
                     }

                     let (site_name, mut ttl) = crate::dns::get_question_as_string_and_lowest_ttl(
                        udp_segment_no_tcp_prefix.as_ptr(),
                        udp_segment_no_tcp_prefix.len(),
                     );

                     if ttl < crate::statics::MINIMUM_TTL_OVERRIDE {
                        ttl = crate::statics::MINIMUM_TTL_OVERRIDE;
                     }

                     let elapsed_ms = crate::util::get_unix_ts_millis() - DNS_QUESTION_CACHE.lock().await.get(cache_key).unwrap().asked_at;

                     let unix_timestamp_secs = crate::util::get_unix_ts_secs();

                     cache_guard.insert(
                        cache_key.to_vec(),
                        AnswerCache {
                           answer: udp_segment_no_tcp_prefix.to_vec(),
                           _elapsed_ms: elapsed_ms,
                           expires_at: unix_timestamp_secs + ttl,
                        },
                     );

                     unsafe {
                        if !crate::statics::ARGS.daemon {
                           let fastest_count = crate::stats::Stats::array_increment_fastest(
                              STATS.as_mut(),
                              format!("{}", upstream_dns.socket_addr.ip()).as_str(),
                           );
                           println!(
                              "{:>4}ms -> {}. ttl: {} ({} [{}])",
                              elapsed_ms,
                              site_name,
                              ttl,
                              format!("{}", upstream_dns.socket_addr.ip()).as_str(),
                              fastest_count
                           );
                        }
                     }
                  }
               }
            }

            offset += udp_segment_len + 2;

            if offset == read_bytes_tcp {
               break;
            }
         }
      }
   }
}

async fn connect(
   tls_connector: &tokio_rustls::TlsConnector,
   upstream_dns: &crate::statics::UpstreamDnsServer,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
   fn is_power_of_2(num: i32) -> bool {
      num & (num - 1) == 0
   }

   let mut connection_failures = 0;
   let mut tls_failures = 0;

   loop {
      let tcp_stream = match tokio::net::TcpStream::connect(upstream_dns.socket_addr).await {
         Ok(conn) => conn,
         Err(err) => {
            println!("{err}");
            connection_failures += 1;
            if is_power_of_2(connection_failures) {
               println!("failed {}x times connecting to: {}", connection_failures, upstream_dns.socket_addr);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_MS)).await;
            continue;
         }
      };

      let _ = tcp_stream.set_linger(None);
      let _ = tcp_stream.set_nodelay(true);

      let tls_stream =
         match tls_connector.connect(tokio_rustls::rustls::ServerName::try_from(upstream_dns.server_name).unwrap(), tcp_stream).await {
            Ok(stream) => stream,
            Err(err) => {
               println!("{err}");
               tls_failures += 1;
               if is_power_of_2(tls_failures) {
                  println!("failed {}x times establishing tls connection to: {}", tls_failures, upstream_dns.socket_addr);
               }
               tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_MS)).await;
               continue;
            }
         };

      break tls_stream;
   }
}
