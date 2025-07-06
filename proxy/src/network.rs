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

#[cfg(target_os = "linux")]
static EBPF_CLIENT_MANAGER: once_cell::sync::OnceCell<crate::ebpf_client::EbpfClientManager> = 
   once_cell::sync::OnceCell::new();

#[cfg(target_os = "linux")]
pub fn initialize_ebpf_client_manager() {
   let manager = crate::ebpf_client::EbpfClientManager::new();
   if crate::statics::ARGS.client_ident && !crate::statics::ARGS.force_netlink {
      manager.initialize();
   }
   EBPF_CLIENT_MANAGER.set(manager).ok();
}

// Router interface functions
pub fn router_insert(key: u64, value: std::net::SocketAddrV4) {
   BUF_ID_ROUTER.insert(key, value);
}

pub fn router_get(
   key: u64,
) -> Option<dashmap::mapref::one::Ref<'static, u64, std::net::SocketAddrV4, nohash_hasher::BuildNoHashHasher<u64>>> {
   BUF_ID_ROUTER.get(&key)
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
   let mut response_buf = vec![0; 2 << 17];

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

         let is_refused_maybe = crate::dns::check_for_rcode_refused(udp_segment_no_tcp_prefix);

         if is_refused_maybe.is_some() && is_refused_maybe.unwrap() || is_refused_maybe.is_none() {
            // The upstream DNS server refused to answer the question. This isn't particularly useful to us so we skip these answers.
            // I added a check for REFUSED because, on one occasion, one of the upstream DNS servers would only return REFUSED to any query.
            eprintln!(
               "Upstream DNS server {} refused to answer the question or the question was malformed",
               crate::statics::DNS_SERVERS[upstream_dns_index].socket_addr
            );
            unsafe { crate::stats::Stats::array_increment_refused(crate::proxy::STATS.as_mut(), upstream_dns_index) };

            // Clean up timing cache entry even for refused responses to prevent permanent delays
            let cache_key = crate::dns::get_query_unique_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
            crate::cache::timing_cache_remove(cache_key);

            offset += udp_segment_len + 2;

            if offset == tls_bytes_read {
               break;
            } else {
               continue;
            }
         }

         // Scope for guards
         {
            let id = crate::dns::get_id_network_byte_order(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
            let cache_key = crate::dns::get_query_unique_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());

            // Atomically remove timing cache entry to ensure only first response is processed
            if let Some((_, timing_entry)) = crate::cache::timing_cache_remove(cache_key) {
               // copy the address for now to minimize chances of a collision
               let saved_addr = router_get(crate::util::encode_id_and_hash32_to_u64(id, crate::util::hash32(cache_key))).unwrap();

               #[cfg(target_os = "linux")]
               let (client_pid_comm, lookup_method) = if crate::statics::ARGS.client_ident {
                  // Try eBPF fast path first
                  if !crate::statics::ARGS.force_netlink {
                     if let Some(manager) = EBPF_CLIENT_MANAGER.get() {
                        if let Some(client_info) = manager.lookup_client_info(*saved_addr) {
                           (Some((client_info.pid as i32, client_info.process_name)), client_info.lookup_method)
                        } else {
                           // Fallback to netlink if eBPF didn't find anything
                           let socket_info = crate::inspect_client::get_socket_info(&saved_addr);
                           if let Some(socket_info) = socket_info {
                              let stat = crate::inspect_client::find_pid_by_socket_inode(socket_info.header.inode as u64);
                              (stat.map(|s| (s.pid, s.comm)), "NETLINK")
                           } else {
                              (None, "NETLINK")
                           }
                        }
                     } else {
                        // eBPF manager not initialized, fallback to netlink
                        let socket_info = crate::inspect_client::get_socket_info(&saved_addr);
                        if let Some(socket_info) = socket_info {
                           let stat = crate::inspect_client::find_pid_by_socket_inode(socket_info.header.inode as u64);
                           (stat.map(|s| (s.pid, s.comm)), "NETLINK")
                        } else {
                           (None, "NETLINK")
                        }
                     }
                  } else {
                     // Force netlink mode
                     let socket_info = crate::inspect_client::get_socket_info(&saved_addr);
                     if let Some(socket_info) = socket_info {
                        let stat = crate::inspect_client::find_pid_by_socket_inode(socket_info.header.inode as u64);
                        (stat.map(|s| (s.pid, s.comm)), "NETLINK")
                     } else {
                        (None, "NETLINK")
                     }
                  }
               } else {
                  (None, "")
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

               let mut dns_response = crate::dns::process_dns_response(udp_segment_no_tcp_prefix, Some(timing_entry.asked_at));
               dns_response.cache_key = cache_key.to_vec(); // Use the original cache key consistently

               let cache_entry = crate::dns::create_cache_entry_from_response(&dns_response, udp_segment_no_tcp_prefix);
               crate::cache::answer_cache_insert(cache_key.to_vec(), cache_entry);

               unsafe {
                  if !crate::statics::ARGS.daemon {
                     let (fastest_count, refused_count) =
                        crate::stats::Stats::array_increment_fastest(crate::proxy::STATS.as_mut(), upstream_dns_index);
                     let mut output = format!(
                        "{:>4}ms -> {:<50} {:>7} {:>3} {:>15} {:>7} {:>7}",
                        dns_response.elapsed_ms,
                        dns_response.site_name,
                        dns_response.qtype_str,
                        dns_response.qclass_str,
                        format!("{}", crate::statics::DNS_SERVERS[upstream_dns_index].socket_addr.ip()).as_str(),
                        format!("[{}]", fastest_count),
                        format!("[{}]", refused_count),
                     );

                     #[cfg(target_os = "linux")]
                     if crate::statics::ARGS.client_ident {
                        output = format!(
                           "{} - {} ({}:{}) [{}]",
                           output,
                           client_pid_comm.map_or("UNKNOWN".to_string(), |(pid, comm)| format!("{}/{}", pid, comm)),
                           saved_addr.ip(),
                           saved_addr.port(),
                           lookup_method,
                        );
                     }

                     println!("{}", output);
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
