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

#[derive(Clone)]
pub struct UpstreamQuery {
   pub data: Vec<u8>,
   pub deadline: tokio::time::Instant,
}

#[cfg(target_os = "linux")]
static EBPF_CLIENT_MANAGER: once_cell::sync::OnceCell<crate::ebpf_client::EbpfClientManager> = once_cell::sync::OnceCell::new();

#[cfg(target_os = "linux")]
pub fn initialize_ebpf_client_manager() {
   let manager = crate::ebpf_client::EbpfClientManager::new();
   if crate::statics::ARGS.client_ident && !crate::statics::ARGS.force_netlink {
      manager.initialize();
   }
   EBPF_CLIENT_MANAGER.set(manager).ok();
}

pub async fn upstream_tls_handler(
   client_msg_rx: kanal::AsyncReceiver<UpstreamQuery>,
   background_msg_rx: Option<kanal::AsyncReceiver<UpstreamQuery>>,
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
   let mut write_handle = tokio::task::spawn(handle_writes(write_half, client_msg_rx, background_msg_rx.clone(), None, shutdown_writer_rx));
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
      write_handle =
         tokio::task::spawn(handle_writes(write_half, client_msg_rx, background_msg_rx.clone(), unsent_query, shutdown_writer_rx));
      read_handle = tokio::task::spawn(handle_reads(read_half, upstream_dns_index, listener_addr.clone(), shutdown_reader_rx));
   }
}

async fn handle_writes(
   mut write_half: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   msg_rx: kanal::AsyncReceiver<UpstreamQuery>,
   background_msg_rx: Option<kanal::AsyncReceiver<UpstreamQuery>>,
   unsent_previous_query_maybe: Option<UpstreamQuery>,
   mut shutdown_writer_rx: tokio::sync::oneshot::Receiver<bool>,
) -> (kanal::AsyncReceiver<UpstreamQuery>, Option<UpstreamQuery>) {
   // In the event we had an issue previously, we begin by resuming the previous failed request
   if let Some(unsent_previous_query) = unsent_previous_query_maybe {
      if let Some(unsent_data) = write(&mut write_half, unsent_previous_query).await {
         return (msg_rx, Some(unsent_data));
      }
   }

   if background_msg_rx.is_none() {
      return handle_foreground_writes(write_half, msg_rx, shutdown_writer_rx).await;
   }
   let background_msg_rx = background_msg_rx.unwrap();

   loop {
      // Drain already-queued foreground work before considering background work.
      if let Ok(Some(data)) = msg_rx.try_recv() {
         if let Some(unsent_data) = write(&mut write_half, data).await {
            return (msg_rx, Some(unsent_data));
         }
         continue;
      }

      tokio::select! {
         biased;
         shutdown_msg = &mut shutdown_writer_rx => {
            match shutdown_msg {
               Ok(_) => return (msg_rx, None),
               Err(_) => panic!("Shutdown channel has been closed prematurely"),
            }
         },
         query_msg = msg_rx.recv() => {
            match query_msg {
               Ok(data) => match write(&mut write_half, data).await {
                  Some(unsent_data) => return (msg_rx, Some(unsent_data)),
                  None => continue,
               },
               Err(_) => panic!("Query channel has been closed prematurely")
            }
         },
         query_msg = background_msg_rx.recv() => {
            match query_msg {
               Ok(data) => {
                  // Background work is speculative and is never retried ahead of foreground work.
                  let _ = write(&mut write_half, data).await;
               },
               Err(_) => continue,
            }
         },
      }
   }
}

async fn handle_foreground_writes(
   mut write_half: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   msg_rx: kanal::AsyncReceiver<UpstreamQuery>,
   mut shutdown_writer_rx: tokio::sync::oneshot::Receiver<bool>,
) -> (kanal::AsyncReceiver<UpstreamQuery>, Option<UpstreamQuery>) {
   loop {
      tokio::select! {
         shutdown_msg = &mut shutdown_writer_rx => {
            match shutdown_msg {
               Ok(_) => return (msg_rx, None),
               Err(_) => panic!("Shutdown channel has been closed prematurely"),
            }
         },
         query_msg = msg_rx.recv() => {
            match query_msg {
               Ok(data) => match write(&mut write_half, data).await {
                  Some(unsent_data) => return (msg_rx, Some(unsent_data)),
                  None => continue,
               },
               Err(_) => panic!("Query channel has been closed prematurely")
            }
         },
      }
   }
}

async fn write(
   write_half: &mut tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   query: UpstreamQuery,
) -> Option<UpstreamQuery> {
   use tokio::io::AsyncWriteExt;

   if query.deadline <= tokio::time::Instant::now() {
      return None;
   }

   match write_half.write_all(&query.data).await {
      Ok(_) => match write_half.flush().await {
         Ok(_) => None,
         Err(_) => Some(query),
      },
      Err(_) => Some(query),
   }
}

async fn handle_reads(
   mut read_half: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   upstream_dns_index: usize,
   listener_addr: std::sync::Arc<tokio::net::UdpSocket>,
   mut shutdown_reader_rx: tokio::sync::oneshot::Receiver<bool>,
) {
   use tokio::io::AsyncReadExt;

   let mut response_buf = [0u8; crate::dns::MAX_DNS_MESSAGE_SIZE];

   loop {
      let mut length_prefix = [0u8; 2];

      let prefix_result = tokio::select! {
         shutdown_msg = &mut shutdown_reader_rx => {
            match shutdown_msg {
               Ok(_) | Err(_) => return,
            }
         },
         result = read_half.read_exact(&mut length_prefix) => result,
      };

      if prefix_result.is_err() {
         // The upstream closed the connection or the read failed before a
         // complete DNS-over-TCP length prefix was received.
         return;
      }

      let udp_segment_len = crate::dns::get_tcp_dns_size_prefix(&length_prefix);

      if udp_segment_len == 0 {
         // A zero-length DNS-over-TCP frame is invalid, but its complete
         // prefix has already been consumed. Ignore it without reconnecting.
         continue;
      }

      if udp_segment_len > crate::dns::MAX_DNS_MESSAGE_SIZE {
         // Skip responses above FaF's supported UDP payload size so we can
         // continue using this connection.
         let mut limited_reader = (&mut read_half).take(udp_segment_len as u64);
         let mut sink = tokio::io::sink();
         let discard_result = tokio::select! {
            shutdown_msg = &mut shutdown_reader_rx => {
               match shutdown_msg {
                  Ok(_) | Err(_) => return,
               }
            },
            result = tokio::io::copy(&mut limited_reader, &mut sink) => result,
         };

         match discard_result {
            Ok(bytes) if bytes == udp_segment_len as u64 => continue,
            _ => return,
         }
      }

      let body_result = tokio::select! {
         shutdown_msg = &mut shutdown_reader_rx => {
            match shutdown_msg {
               Ok(_) | Err(_) => return,
            }
         },
         result = read_half.read_exact(&mut response_buf[..udp_segment_len]) => result,
      };

      if body_result.is_err() {
         // The upstream closed the connection or the read failed before the
         // complete DNS response body was received.
         return;
      }

      let udp_segment_no_tcp_prefix = &response_buf[..udp_segment_len];

      if crate::dns::check_for_usable_response(udp_segment_no_tcp_prefix) != Some(true) {
         // Keep the flight open so another upstream can still return a usable NOERROR or NXDOMAIN response.
         eprintln!(
            "Upstream DNS server {} returned an unusable or malformed response",
            crate::statics::DNS_SERVERS[upstream_dns_index].socket_addr
         );
         crate::stats::increment_refused(upstream_dns_index);
         continue;
      }

      // Scope for guards
      {
         let id = crate::dns::get_id_network_byte_order(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment_no_tcp_prefix.as_ptr(), udp_segment_no_tcp_prefix.len());

         // Atomically remove the in-flight query so only the first usable response is processed.
         if let Some((in_flight, dns_response)) = crate::cache::in_flight_complete(cache_key, id, udp_segment_no_tcp_prefix) {
            let saved_addr = in_flight.waiters.first().map(|waiter| waiter.client_addr);

            #[cfg(target_os = "linux")]
            let (client_pid_comm, lookup_method) = if crate::statics::ARGS.client_ident && saved_addr.is_some() {
               let saved_addr = saved_addr.unwrap();
               // Try eBPF fast path first
               if !crate::statics::ARGS.force_netlink {
                  if let Some(manager) = EBPF_CLIENT_MANAGER.get() {
                     if let Some(client_info) = manager.lookup_client_info(saved_addr) {
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

            let mut waiters = in_flight.waiters.into_iter();
            if let Some(first_waiter) = waiters.next() {
               let mut answer = udp_segment_no_tcp_prefix.to_vec();
               crate::dns::set_id_network_byte_order(first_waiter.client_id, &mut answer);
               let wrote_len_maybe = listener_addr.send_to(&answer, first_waiter.client_addr).await;

               if let Ok(wrote_len) = wrote_len_maybe {
                  // Due to how rust implements IO for send_to, we will never have a len_written less than 0
                  if wrote_len == 0 {
                     eprintln!("Failed to write response to the client. 0 bytes written at {}:{}", file!(), line!());
                  }
               } else {
                  eprintln!(
                     "Failed to write response to the client with error: {} at {}:{}",
                     wrote_len_maybe.unwrap_err(),
                     file!(),
                     line!()
                  );
               }

               if waiters.len() > 0 {
                  let listener_addr = listener_addr.clone();
                  tokio::task::spawn(async move {
                     for waiter in waiters {
                        crate::dns::set_id_network_byte_order(waiter.client_id, &mut answer);
                        if let Err(err) = listener_addr.send_to(&answer, waiter.client_addr).await {
                           eprintln!("Failed to write response to the client with error: {err}");
                        }
                     }
                  });
               }
            }

            if !crate::statics::ARGS.daemon && saved_addr.is_some() {
               let (fastest_count, refused_count) = crate::stats::increment_fastest(upstream_dns_index);
               let mut output = format!(
                  "{:>4}ms -> {:<50} {:>7} {:>3} {:>7} {:>15} {:<7} {:>7}",
                  dns_response.elapsed_ms,
                  dns_response.site_name,
                  dns_response.qtype_str,
                  dns_response.qclass_str,
                  format!("{}s", dns_response.ttl),
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
                     saved_addr.unwrap().ip(),
                     saved_addr.unwrap().port(),
                     lookup_method,
                  );
               }

               println!("{}", output);
            }
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
