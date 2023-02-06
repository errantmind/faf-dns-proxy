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

      for dns in crate::statics::UPSTREAM_DNS_SERVERS {
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
               }
            }
         }

         {
            // Add to QUESTION cache

            DNS_QUESTION_CACHE.lock().await.insert(cache_key.to_vec(), QuestionCache { asked_at: crate::util::get_unix_ts_millis() });
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
   msg_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
   upstream_dns: crate::statics::UpstreamDnsServer,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
) {
   let tls_client_config = crate::tls::get_tls_client_config();
   let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config)).early_data(true);

   let mut tls_stream = connect(&tls_connector, &upstream_dns).await;
   let mut tls_stream_split = tokio::io::split(tls_stream);

   let (mut shutdown_writer_sender_channel, mut shutdown_writer_receiver_channel) = tokio::sync::oneshot::channel();
   let (mut shutdown_reader_sender_channel, mut shutdown_reader_receiver_channel) = tokio::sync::oneshot::channel();

   let mut write_handle = tokio::task::spawn(handle_writes(tls_stream_split.1, msg_rx, None, shutdown_writer_receiver_channel));
   let mut read_handle =
      tokio::task::spawn(handle_reads(tls_stream_split.0, upstream_dns, listener_addr.clone(), shutdown_reader_receiver_channel));

   loop {
      tokio::select! {
         write_result = &mut write_handle => {
            println!("write handle finished");

         if !read_handle.is_finished() {
            shutdown_reader_sender_channel.send(true).unwrap();

            let _ = read_handle.await;
         }

         let (msg_rx, unsent_query) = write_result.unwrap();

         (shutdown_writer_sender_channel, shutdown_writer_receiver_channel) = tokio::sync::oneshot::channel();
         (shutdown_reader_sender_channel, shutdown_reader_receiver_channel) = tokio::sync::oneshot::channel();
         tls_stream = connect(&tls_connector, &upstream_dns).await;
         tls_stream_split = tokio::io::split(tls_stream);
         write_handle = tokio::task::spawn(handle_writes(tls_stream_split.1, msg_rx, unsent_query, shutdown_writer_receiver_channel));
         read_handle =
            tokio::task::spawn(handle_reads(tls_stream_split.0, upstream_dns, listener_addr.clone(), shutdown_reader_receiver_channel));
         },
         _ = &mut read_handle => {
            println!("read handle finished");

         if !write_handle.is_finished() {
            shutdown_writer_sender_channel.send(true).unwrap();
         }

         let (msg_rx, unsent_query) = write_handle.await.unwrap();

         (shutdown_writer_sender_channel, shutdown_writer_receiver_channel) = tokio::sync::oneshot::channel();
         (shutdown_reader_sender_channel, shutdown_reader_receiver_channel) = tokio::sync::oneshot::channel();
         tls_stream = connect(&tls_connector, &upstream_dns).await;
         tls_stream_split = tokio::io::split(tls_stream);
         write_handle = tokio::task::spawn(handle_writes(tls_stream_split.1, msg_rx, unsent_query, shutdown_writer_receiver_channel));
         read_handle =
            tokio::task::spawn(handle_reads(tls_stream_split.0, upstream_dns, listener_addr.clone(), shutdown_reader_receiver_channel));
         }
      }
   }
}

async fn handle_writes(
   mut write_half: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   mut msg_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
   unsent_previous_query_maybe: Option<Vec<u8>>,
   mut shutdown_writer_receiver_channel: tokio::sync::oneshot::Receiver<bool>,
) -> (tokio::sync::mpsc::Receiver<Vec<u8>>, Option<Vec<u8>>) {
   println!("-> handle writes called");

   if let Some(unsent_previous_query) = unsent_previous_query_maybe {
      if let Some(unsent_data) = write(&mut write_half, unsent_previous_query).await {
         return (msg_rx, Some(unsent_data));
      }
   }

   //let mut handle_writes_counter = 0;
   loop {
      // handle_writes_counter += 1;
      // if is_power_of_2(handle_writes_counter) {
      //    println!("handle writes {handle_writes_counter}x times",);
      // }

      tokio::select! {
         shutdown_msg = &mut shutdown_writer_receiver_channel => {
            match shutdown_msg {
               Ok(_) => return (msg_rx, None),
               Err(_) => panic!("Shutdown Channel has been closed prematurely"),
            }
         },
         query_msg = msg_rx.recv() => {
            match query_msg {
               Some(data) => match write(&mut write_half, data).await {
                  Some(unsent_data) => return (msg_rx, Some(unsent_data)),
                  None => {
                     println!("malfunction?");
                     continue;
                  }
               },
               None => ()
            }
         }
      }

      // match msg_rx.recv().await {
      //    Ok(data) => match write(&mut write_half, data).await {
      //       Some(unsent_data) => return (msg_rx, Some(unsent_data)),
      //       None => {
      //          println!("malfunction?");
      //          continue;
      //       }
      //    },
      //    Err(err) if err == tokio::sync::mpsc::error::TryRecvError::Disconnected => {
      //       panic!("Channel has been closed prematurely");
      //    }
      //    Err(err) if err == tokio::sync::mpsc::error::TryRecvError::Empty => {
      //       tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
      //       //tokio::task::yield_now().await;
      //    }
      //    Err(_) => std::unreachable!(),
      // };

      // match shutdown_writer_receiver_channel.try_recv() {
      //    Ok(_) => return (msg_rx, None),
      //    Err(err) if err == tokio::sync::oneshot::error::TryRecvError::Closed => {
      //       panic!("Shutdown Channel has been closed prematurely");
      //    }
      //    Err(err) if err == tokio::sync::oneshot::error::TryRecvError::Empty => {
      //       tokio::task::yield_now().await;
      //    }
      //    Err(_) => panic!("Unknown channel error"),
      // };

      // match msg_rx.try_recv() {
      //    Ok(data) => match write(&mut write_half, data).await {
      //       Some(unsent_data) => return (msg_rx, Some(unsent_data)),
      //       None => {
      //          println!("malfunction?");
      //          continue;
      //       }
      //    },
      //    Err(err) if err == tokio::sync::mpsc::error::TryRecvError::Disconnected => {
      //       panic!("Channel has been closed prematurely");
      //    }
      //    Err(err) if err == tokio::sync::mpsc::error::TryRecvError::Empty => {
      //       tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
      //       //tokio::task::yield_now().await;
      //    }
      //    Err(_) => std::unreachable!(),
      // };

      //tokio::task::yield_now().await;
   }
}

async fn write(
   mut write_half: &mut tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   query_buf: Vec<u8>,
) -> Option<Vec<u8>> {
   match tokio::io::AsyncWriteExt::write(&mut write_half, &query_buf).await {
      Ok(_bytes_written_to_socket) => {
         if tokio::io::AsyncWriteExt::flush(&mut write_half).await.is_err() {
            Some(query_buf)
         } else {
            None
         }
      }
      Err(_) => Some(query_buf),
   }
}

async fn handle_reads(
   mut read_half: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   upstream_dns: crate::statics::UpstreamDnsServer,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
   mut shutdown_reader_receiver_channel: tokio::sync::oneshot::Receiver<bool>,
) {
   println!("-> handle reads called");

   let mut response_buf = vec![0; 2 << 15];

   let mut handle_reads_counter = 0;
   loop {
      handle_reads_counter += 1;
      if is_power_of_2(handle_reads_counter) {
         println!("handle reads {handle_reads_counter}x times",);
      }

      {
         match shutdown_reader_receiver_channel.try_recv() {
            Ok(_) => return,
            Err(err) if err == tokio::sync::oneshot::error::TryRecvError::Closed => {
               panic!("Shutdown Channel has been closed prematurely");
            }
            Err(err) if err == tokio::sync::oneshot::error::TryRecvError::Empty => {
               tokio::task::yield_now().await;
            }
            Err(_) => std::unreachable!(),
         };

         let read_bytes_tcp = match tokio::io::AsyncReadExt::read(&mut read_half, &mut response_buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
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
                              "{:>4}ms -> {} ({} [{}])",
                              elapsed_ms,
                              site_name,
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

fn is_power_of_2(num: i32) -> bool {
   num & (num - 1) == 0
}
