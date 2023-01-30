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

pub const CONN_ERROR_SLEEP_TIME: u64 = 2000;

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

      loop {
         let (read_bytes, client_addr) = match listener_socket.recv_from(&mut query_buf[2..]).await {
            Ok(res) => res,
            Err(err) => {
               println!("{err}");
               continue;
            }
         };
         assert!(read_bytes <= 512, "Received a datagram with > 512 bytes on the listening socket");
         //println!("read_buff len: {}, read: {}", query_buf.len(), read_bytes);

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

#[must_use]
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

#[must_use]
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

         match listener_addr.send_to(&response_buf[2..read_bytes_tcp], &client_addr).await {
            Ok(_) => (),
            Err(_) => (),
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
