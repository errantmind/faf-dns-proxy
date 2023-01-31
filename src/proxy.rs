use hashbrown::HashMap;

pub struct UpstreamDnsServer {
   pub server_name: &'static str,
   pub socket_addr: std::net::SocketAddrV4,
}

pub const UPSTREAM_DNS_SERVERS: [UpstreamDnsServer; 5] = [
   UpstreamDnsServer { server_name: "one.one.one.one", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 853) },
   UpstreamDnsServer { server_name: "one.one.one.one", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 0, 0, 1), 853) },
   UpstreamDnsServer { server_name: "dns.google", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 8, 8), 853) },
   UpstreamDnsServer { server_name: "dns.google", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 4, 4), 853) },
   UpstreamDnsServer { server_name: "dns.quad9.net", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(9, 9, 9, 9), 853) },
];

struct QuestionCache {
   pub asked_timestamp: crate::time::timespec,
}

struct AnswerCache {
   pub answer: Vec<u8>,
   pub elapsed_ms: i64,
   pub ttl: u64,
}

pub const CONN_ERROR_SLEEP_TIME: u64 = 2000;

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

      let mut tx_channels = Vec::with_capacity(UPSTREAM_DNS_SERVERS.len());

      for dns in &UPSTREAM_DNS_SERVERS {
         let (tx, rx) = tokio::sync::mpsc::channel(8192);
         tokio::task::spawn(upstream_tls_handler(rx, dns));
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
         //println!("read_buff len: {}, read: {}", query_buf.len(), read_bytes);

         let id = crate::dns::get_id_big_endian(udp_segment.as_ptr(), udp_segment.len());
         let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

         {
            // Add to QUESTION cache (only once)

            let mut cache_guard = DNS_QUESTION_CACHE.lock().await;
            if !cache_guard.contains_key(cache_key) {
               cache_guard.insert(cache_key.to_vec(), QuestionCache { asked_timestamp: crate::time::get_timespec() });
            }
         }

         {
            // Scope for cache guard.
            // First check the ANSWER cache and respond immediately if we already have an answer to the query

            let mut cache_guard = DNS_ANSWER_CACHE.lock().await;
            let cached_response_maybe = cache_guard.get_mut(cache_key);

            if let Some(cached_response) = cached_response_maybe {
               crate::dns::set_id_big_endian(id, &mut cached_response.answer);
               let wrote = listener_socket.send_to(udp_segment, &client_addr).await.unwrap();

               if wrote == 0 {
                  panic!("Wrote nothing to client after fetching data from cache")
               }

               {
                  // Temp: Track cache hits

                  cache_hits += 1;
                  if cache_hits >= cache_hits_print_threshold {
                     println!("cache hits: {}", cache_hits_print_threshold);
                     cache_hits_print_threshold <<= 1;
                  }
               }

               continue;
            }
         }

         {
            // Save the client state

            let mut id_router_guard = BUF_ID_ROUTER.lock().await;
            id_router_guard.insert(id, client_addr);
         }

         // Write both bytes at once after converting to Big Endian
         unsafe { *(query_buf.as_mut_ptr() as *mut u16) = (read_bytes as u16).to_be() };
         for tx in &tx_channels {
            tx.send((query_buf[0..read_bytes + 2].to_vec(), listener_socket.clone(), client_addr)).await;
         }
      }
   })
   .await
   .unwrap();
}

pub async fn upstream_tls_handler(
   mut msg_rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::sync::Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>,
   upstream_dns: &UpstreamDnsServer,
) {
   let tls_client_config = crate::tls::get_tls_client_config();
   let tls_connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config));

   let (mut stream_read, mut stream_write) = connect(&tls_connector, upstream_dns).await;

   let mut response_buf = vec![0; 514];

   loop {
      let msg_maybe = msg_rx.recv().await;
      let (query_buf, listener_addr, client_addr) = match msg_maybe {
         Some(data) => data,
         None => continue,
      };
      let start_time = crate::time::get_timespec();

      loop {
         let read_bytes_maybe = match tokio::io::AsyncWriteExt::write_all(&mut stream_write, &query_buf).await {
            Ok(_) => match tokio::io::AsyncReadExt::read(&mut stream_read, &mut response_buf).await {
               Ok(0) => None,
               Ok(n) => Some(n),
               Err(_) => None,
            },
            Err(_) => None,
         };

         let read_bytes_tcp = match read_bytes_maybe {
            Some(n) => n,
            None => {
               (stream_read, stream_write) = connect(&tls_connector, upstream_dns).await;
               continue;
            }
         };

         assert!(read_bytes_tcp <= 514, "Received a response with > 512 bytes from upstream socket ({})", read_bytes_tcp);
         assert!(read_bytes_tcp > 2, "Received a response with <= 2 bytes from upstream socket ({})", read_bytes_tcp);

         let udp_segment_len = crate::dns::get_tcp_dns_size_prefix_le(&response_buf);
         assert!(udp_segment_len > 0 && udp_segment_len <= 512, "Tcp reported len is invalid ({})", udp_segment_len);
         assert!(
            udp_segment_len <= (read_bytes_tcp - 2),
            "Udp segment length cannot be larger than the TCP wrapper ({}/{})",
            udp_segment_len,
            read_bytes_tcp
         );

         let udp_segment = &response_buf[2..udp_segment_len + 2];

         // Scope for guards
         {
            let id = crate::dns::get_id_big_endian(udp_segment.as_ptr(), udp_segment.len());
            let id_router_guard = BUF_ID_ROUTER.lock().await;
            let saved_addr = id_router_guard.get(&id).unwrap();
            let cache_key = crate::dns::get_query_unique_id(udp_segment.as_ptr(), udp_segment.len());

            {
               let mut cache_guard = DNS_ANSWER_CACHE.lock().await;
               if !cache_guard.contains_key(cache_key) {
                  let debug_query = crate::dns::get_question_as_string(udp_segment.as_ptr(), udp_segment.len());

                  let wrote = listener_addr.send_to(udp_segment, &saved_addr).await.unwrap();

                  if wrote == 0 {
                     panic!("Wrote nothing to client after receiving data from upstream")
                  }

                  let elapsed_ms = crate::time::get_elapsed_ms(
                     &crate::time::get_timespec(),
                     &DNS_QUESTION_CACHE.lock().await.get(cache_key).unwrap().asked_timestamp,
                  );
                  cache_guard.insert(cache_key.to_vec(), AnswerCache { answer: udp_segment.to_vec(), elapsed_ms, ttl: 0 });

                  // unsafe {
                  //    if !crate::statics::ARGS.daemon {
                  //       let fastest_count = crate::stats::Stats::array_increment_fastest(&mut STATS, upstream_server.ip);
                  //       println!("{:>4}ms -> {} ({} [{}])", elapsed_ms, debug_query, upstream_server.ip, fastest_count);
                  //    }
                  // }
               }
            }
         }

         {
            let elapsed_ms = crate::time::get_elapsed_ms(&crate::time::get_timespec(), &start_time);
            let debug_query = crate::dns::get_question_as_string(udp_segment.as_ptr(), udp_segment_len);
            println!("{:>4}ms -> {} ({})", elapsed_ms, debug_query, upstream_dns.socket_addr.ip());
         }

         break;
      }
   }
}

async fn connect(
   tls_connector: &tokio_rustls::TlsConnector,
   upstream_dns: &UpstreamDnsServer,
) -> (
   tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
   tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
) {
   fn is_power_of_2(num: i32) -> bool {
      num & (num - 1) == 0
   }

   let mut connection_failures = 0;
   let mut tls_failures = 0;

   // let mut tls_conn = {
   //    let upstream_dns_address: rustls::ServerName = upstream_server.server_name.try_into().unwrap();
   //    let arc_config = std::sync::Arc::new(tls_client_config.clone());
   //    rustls::ClientConnection::new(arc_config, upstream_dns_address).unwrap()
   // };

   loop {
      let tcp_stream = match tokio::net::TcpStream::connect(upstream_dns.socket_addr).await {
         Ok(conn) => conn,
         Err(err) => {
            println!("{err}");
            connection_failures += 1;
            if is_power_of_2(connection_failures) {
               println!("failed {}x times connecting to: {}", connection_failures, upstream_dns.socket_addr);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_TIME)).await;
            continue;
         }
      };

      let tls_stream = match tls_connector.connect(rustls::ServerName::try_from(upstream_dns.server_name).unwrap(), tcp_stream).await {
         Ok(stream) => stream,
         Err(err) => {
            println!("{err}");
            tls_failures += 1;
            if is_power_of_2(tls_failures) {
               println!("failed {}x times establishing tls connection to: {}", tls_failures, upstream_dns.socket_addr);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(CONN_ERROR_SLEEP_TIME)).await;
            continue;
         }
      };

      break tokio::io::split(tls_stream);
   }
}
