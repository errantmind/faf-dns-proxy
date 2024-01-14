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


static mut STATS: once_cell::sync::Lazy<[crate::stats::Stats; crate::statics::DNS_SERVERS.len()]> =
   once_cell::sync::Lazy::new(crate::stats::init_stats);

struct TimingCacheEntry {
   asked_at: u128,
}

struct AnswerCacheEntry {
   answer: Vec<u8>,
   elapsed_ms: u128,
   expires_at: u64,
}

lazy_static::lazy_static! {

   // Stores when questions are asked
   static ref DNS_TIMING_CACHE: dashmap::DashMap<Vec<u8>, TimingCacheEntry, gxhash::GxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, gxhash::GxBuildHasher::default());

   // Stores when questions are answered, as well as when they expire and how long it took to answer
   static ref DNS_ANSWER_CACHE: dashmap::DashMap<Vec<u8>, AnswerCacheEntry, gxhash::GxBuildHasher> =
      dashmap::DashMap::with_capacity_and_hasher(4096, gxhash::GxBuildHasher::default());

   // Stores lists of blocked domains loaded from blocklists
   static ref BLOCKLISTS: tokio::sync::Mutex<Vec<crate::blocklist::BlocklistFile>> = tokio::sync::Mutex::new(Vec::new());


   // When we receive a request from a client, we may have the answer cached or we will request it from upstream. However,
   // when we receive a response from an upstream server we need to know which client to send it to. So, to route responses
   // to the correct client, we need to identify the correct client with something in the response itself, which knows nothing of
   // the client. We use a combination of the ID and the QNAME, QTYPE, and QCLASS of the Question (all of which are unchanged
   // in the response) to identify the client. The chance of a collision is negligible, even more so since this applies only
   // to uncached requests.
   // We use a DashMap (hashmap) for thread safety with a NoHashHasher for additional performance (which is a
   // no-op hasher) over particular types like u64.
   static ref BUF_ID_ROUTER: dashmap::DashMap<u64, std::net::SocketAddrV4, nohash_hasher::BuildNoHashHasher<u64>> =
      dashmap::DashMap::default();
}

pub async fn go(port: u16) {
   let proxy = tokio::task::spawn(async move {
      let listener_socket = {
         let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
         std::sync::Arc::new(tokio::net::UdpSocket::bind(listener_addr).await.unwrap())
      };

      let mut tx_channels: Vec<kanal::AsyncSender<Vec<u8>>> = Vec::with_capacity(crate::statics::DNS_SERVERS.len());

      for (dns_server_index, _) in crate::statics::DNS_SERVERS.iter().enumerate() {
         let (tx, rx) = kanal::bounded_async::<Vec<u8>>(8192);
         tokio::task::spawn(upstream_tls_handler(rx, dns_server_index, listener_socket.clone()));
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
            let question = crate::dns::get_question_as_string(udp_segment.as_ptr(), udp_segment.len());

            // The blocklists are not accurate because they are derived from the browser regex filters. They exclude most subdomains.
            let mut primary_domain = String::new();
            let parts: Vec<&str> = question.rsplitn(3, '.').collect();
            if parts.len() > 2 {
               primary_domain = format!("{}.{}", parts[1], parts[0]);
            }

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

         // First check the ANSWER cache and respond immediately if we already have an answer to the query
         if let Some(mut cached_response) = DNS_ANSWER_CACHE.get_mut(cache_key) {
            if cached_response.expires_at > crate::util::get_unix_ts_secs() {
               crate::dns::set_id_network_byte_order(id, &mut cached_response.answer);
               let wrote_len_maybe = listener_socket.send_to(&cached_response.answer, &client_addr).await;
               drop(cached_response);

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
                        let mut elapsed_ms_vec: Vec<u64> = DNS_ANSWER_CACHE.iter().map(|x| x.elapsed_ms as u64).collect();
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
            } else {
               drop(cached_response);
               DNS_ANSWER_CACHE.remove(cache_key);
            }
         }

         // We don't have it cached. Add to QUESTION cache
         DNS_TIMING_CACHE.insert(cache_key.to_vec(), TimingCacheEntry { asked_at: crate::util::get_unix_ts_millis() });

         // Save the client state
         let client_addr_ipv4 = match client_addr {
            std::net::SocketAddr::V4(value) => value,
            _ => std::unreachable!(),
         };
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

         BUF_ID_ROUTER.insert(crate::util::encode_id_and_hash32_to_u64(id, crate::util::hash32(cache_key)), client_addr_ipv4);

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

pub async fn upstream_tls_handler(
   client_msg_rx: kanal::AsyncReceiver<Vec<u8>>,
   upstream_dns_index: usize,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
) {
   let tls_client_config = crate::tls::get_tls_client_config();
   let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config)).early_data(true);

   let upstream_dns = crate::statics::DNS_SERVERS[upstream_dns_index];

   let (mut shutdown_writer_tx, mut shutdown_writer_rx) = tokio::sync::oneshot::channel();
   let (mut shutdown_reader_tx, mut shutdown_reader_rx) = tokio::sync::oneshot::channel();
   let mut tls_stream = connect(&tls_connector, &upstream_dns).await;
   let (mut read_half, mut write_half) = tokio::io::split(tls_stream);
   let mut write_handle = tokio::task::spawn(handle_writes(write_half, client_msg_rx, None, shutdown_writer_rx));
   let mut read_handle = tokio::task::spawn(handle_reads(read_half, upstream_dns_index, listener_addr.clone(), shutdown_reader_rx));

   loop {
      let (client_msg_rx, unsent_query) = tokio::select! {
            write_result = &mut write_handle => {
               // If our write handle has returned, we need to ensure the read handle is finished before we re-establish the connection
               if !read_handle.is_finished() {
                  shutdown_reader_tx.send(true).unwrap();
                  let _ = read_handle.await;
               }

               write_result.unwrap()
            },

            _ = &mut read_handle => {
               // If our read handle has returned, we need to ensure the write handle is finished before we re-establish the connection
               if !write_handle.is_finished() {
                  shutdown_writer_tx.send(true).unwrap();
               }

               write_handle.await.unwrap()
         }
      };

      (shutdown_writer_tx, shutdown_writer_rx) = tokio::sync::oneshot::channel();
      (shutdown_reader_tx, shutdown_reader_rx) = tokio::sync::oneshot::channel();
      tls_stream = connect(&tls_connector, &upstream_dns).await;

      (read_half, write_half) = tokio::io::split(tls_stream);
      write_handle = tokio::task::spawn(handle_writes(write_half, client_msg_rx, unsent_query, shutdown_writer_rx));
      read_handle = tokio::task::spawn(handle_reads(read_half, upstream_dns_index, listener_addr.clone(), shutdown_reader_rx));
   }
}

async fn handle_writes(
   mut write_half: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   msg_rx: kanal::AsyncReceiver<Vec<u8>>,
   unsent_previous_query_maybe: Option<Vec<u8>>,
   mut shutdown_writer_rx: tokio::sync::oneshot::Receiver<bool>,
) -> (kanal::AsyncReceiver<Vec<u8>>, Option<Vec<u8>>) {
   // In the event we had an issue previously, we begin by resuming the previous failed request
   if let Some(unsent_previous_query) = unsent_previous_query_maybe {
      if let Some(unsent_data) = write(&mut write_half, unsent_previous_query).await {
         return (msg_rx, Some(unsent_data));
      }
   }

   loop {
      tokio::select! {
         shutdown_msg = &mut shutdown_writer_rx => {
            match shutdown_msg {
               Ok(_) => {
                  // Shutdown requested, return the queue
                  return (msg_rx, None)
               },
               Err(_) => panic!("Shutdown channel has been closed prematurely"),
            }
         },
         query_msg = msg_rx.recv() => {
            match query_msg {
               Ok(data) => match write(&mut write_half, data).await {
                  Some(unsent_data) => {
                     // Qeury failed
                     return (msg_rx, Some(unsent_data))
                  },
                  None => {
                     // Query completed successfully
                     continue;
                  }
               },
               Err(_) => panic!("Query channel has been closed prematurely")
            }
         }
      }
   }
}

async fn write(
   write_half: &mut tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   query_buf: Vec<u8>,
) -> Option<Vec<u8>> {
   use tokio::io::AsyncWriteExt;

   match write_half.write_all(&query_buf).await {
      Ok(_) => match write_half.flush().await {
         Ok(_) => None,
         Err(_) => Some(query_buf),
      },
      Err(_) => Some(query_buf),
   }
}

async fn handle_reads(
   mut read_half: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   upstream_dns_index: usize,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
   mut shutdown_reader_rx: tokio::sync::oneshot::Receiver<bool>,
) {
   let mut response_buf = vec![0; 2 << 15];

   loop {
      let tls_bytes_read;

      tokio::select! {
         shutdown_msg = &mut shutdown_reader_rx => {
            match shutdown_msg {
               Ok(_) => return,
               Err(_) => panic!("Shutdown Channel has been closed prematurely")
            };
         },
         read_result = tokio::io::AsyncReadExt::read(&mut read_half, &mut response_buf) => {
            match read_result {
               Ok(0) => {
                  // The upstream closed the connection.
                  // Many DNS servers, including Cloudflare, will close the connection after a short period of inactivity.
                  return;
               },
               Ok(n) => tls_bytes_read = n,
               Err(_) => {
                  // Google DNS will occasionally close the connection without sending TLS close_notify.
                  // This is against the RFC but we handle it anyway, along with any other errors.
                  return;
               }
            }
         }
      }

      let mut offset = 0;
      loop {
         let udp_segment_len = crate::dns::get_tcp_dns_size_prefix_le(&response_buf[offset..]);
         if !udp_segment_len > 0 && !udp_segment_len <= 512 {
            panic!("Tcp reported len is invalid ({udp_segment_len})");
         };
         assert!(
            udp_segment_len <= (tls_bytes_read - 2),
            "Udp segment length cannot be larger than the TCP wrapper ({udp_segment_len}/{tls_bytes_read})"
         );

         let udp_segment_no_tcp_prefix = &response_buf[offset + 2..offset + udp_segment_len + 2];

         // Scope for guards
         {
            {
               let id = crate::dns::get_id_network_byte_order(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
               let cache_key = crate::dns::get_query_unique_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
               if !DNS_ANSWER_CACHE.contains_key(cache_key) {
                  // copy the address for now to minimize chances of a collision
                  let saved_addr =
                     BUF_ID_ROUTER.get(&crate::util::encode_id_and_hash32_to_u64(id, crate::util::hash32(cache_key))).unwrap();

                  #[cfg(target_os = "linux")]
                  let stat_maybe: Option<procfs::process::Stat> = if crate::statics::ARGS.client_ident {
                     // We have to check here because the clients often close their socket immediately after the write.
                     let socket_info_maybe = crate::inspect_client::get_socket_info(&saved_addr);
                     if let Some(socket_info) = socket_info_maybe {
                        crate::inspect_client::find_pid_by_socket_inode(socket_info.header.inode as u64)
                     } else {
                        None
                     }
                  } else {
                     None
                  };

                  let wrote_len_maybe = listener_addr.send_to(udp_segment_no_tcp_prefix, *saved_addr).await;

                  if let Ok(wrote_len) = wrote_len_maybe {
                     // Due to how rust implements IO for send_to, we will never have a len_written less than 0
                     if wrote_len == 0 {
                        eprintln!("Failed to write response to the client. 0 bytes written at {}:{}", file!(), line!());
                     }
                  } else {
                     eprintln!(
                        "Failed to write cached response to the client with error: {} at {}:{}",
                        wrote_len_maybe.unwrap_err(),
                        file!(),
                        line!()
                     );
                  }

                  let elapsed_ms = { crate::util::get_unix_ts_millis() - DNS_TIMING_CACHE.get(cache_key).unwrap().asked_at };

                  let (site_name, qtype_str, qclass_str, mut ttl) =
                     crate::dns::get_question_as_string_and_lowest_ttl(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());

                  if ttl < crate::statics::MINIMUM_TTL_OVERRIDE {
                     ttl = crate::statics::MINIMUM_TTL_OVERRIDE;
                  }

                  DNS_ANSWER_CACHE.insert(
                     cache_key.to_vec(),
                     AnswerCacheEntry {
                        answer: udp_segment_no_tcp_prefix.to_vec(),
                        elapsed_ms,
                        expires_at: crate::util::get_unix_ts_secs() + ttl,
                     },
                  );

                  unsafe {
                     if !crate::statics::ARGS.daemon {
                        let fastest_count = crate::stats::Stats::array_increment_fastest(STATS.as_mut(), upstream_dns_index);
                        let mut output = format!(
                           "{:>4}ms -> {:<46} {:>7} {:>3} {:>15} {:>7}",
                           elapsed_ms,
                           site_name,
                           qtype_str,
                           qclass_str,
                           format!("{}", crate::statics::DNS_SERVERS[upstream_dns_index].socket_addr.ip()).as_str(),
                           format!("[{}]", fastest_count),
                        );

                        #[cfg(target_os = "linux")]
                        if crate::statics::ARGS.client_ident {
                           output = format!(
                              "{} - {} ({}:{})",
                              output,
                              stat_maybe.map_or("UNKNOWN".to_string(), |x| format!("{}/{}", x.pid, x.comm)),
                              saved_addr.ip(),
                              saved_addr.port(),
                           );
                        }

                        println!("{}", output);
                     }
                  }
               }
            }
         }

         offset += udp_segment_len + 2;

         if offset == tls_bytes_read {
            break;
         }
      }
   }
}

async fn connect(
   tls_connector: &tokio_rustls::TlsConnector,
   upstream_dns: &crate::statics::UpstreamDnsServer,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
   const CONN_ERROR_SLEEP_MS: u64 = 1000;

   let mut connection_failures = 0;
   let mut tls_failures = 0;

   loop {
      let tcp_stream = match tokio::net::TcpStream::connect(upstream_dns.socket_addr).await {
         Ok(conn) => conn,
         Err(err) => {
            connection_failures += 1;
            if connection_failures > 1 && crate::util::is_power_of_2(connection_failures) {
               eprintln!("failed {connection_failures}x times connecting to: {} with error: {}", upstream_dns.socket_addr, err);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_MS)).await;
            continue;
         }
      };

      let _ = tcp_stream.set_linger(None);
      let _ = tcp_stream.set_nodelay(true);

      let tls_stream = match tls_connector
         .connect(tokio_rustls::rustls::pki_types::ServerName::try_from(upstream_dns.server_name).unwrap(), tcp_stream)
         .await
      {
         Ok(stream) => stream,
         Err(err) => {
            tls_failures += 1;
            if tls_failures > 1 && crate::util::is_power_of_2(tls_failures) {
               eprintln!("failed {tls_failures}x times establishing tls connection to: {} with error: {}", upstream_dns.socket_addr, err);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_MS)).await;
            continue;
         }
      };

      break tls_stream;
   }
}
