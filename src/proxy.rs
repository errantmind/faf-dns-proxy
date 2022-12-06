pub async fn go(port: u16) {
   tokio::task::spawn(async move {
      let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
      //&format!("127.0.0.1:{}", port)
      let listener_socket = std::sync::Arc::new(tokio::net::UdpSocket::bind(listener_addr).await.unwrap());

      let (tx, rx) = tokio::sync::mpsc::channel(8192);

      tokio::task::spawn(upstream_tls_handler(rx));

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
         println!("read_buff len: {}, read: {}", query_buf.len(), read_bytes);

         // Write both bytes at once after converting to Big Endian
         unsafe { *(query_buf.as_mut_ptr() as *mut u16) = crate::net::htons(read_bytes as u16) };

         tx.send((query_buf[0..read_bytes + 2].to_vec(), listener_socket.clone(), client_addr)).await.unwrap();
      }
   })
   .await
   .unwrap();
}

pub async fn upstream_tls_handler(mut msg_rx: tokio::sync::mpsc::Receiver<(Vec<u8>, std::sync::Arc<tokio::net::UdpSocket>, std::net::SocketAddr)>) {
   let mut response_buf = vec![0; 514];

   let tls_client_config = crate::tls::get_tls_client_config();
   let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config));
   let upstream_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 853);
   let base_stream = tokio::net::TcpStream::connect(&upstream_addr).await.unwrap();
   let domain = rustls::ServerName::try_from("one.one.one.one").unwrap();
   let stream = connector.connect(domain, base_stream).await.unwrap();

   let (mut stream_read, mut stream_write) = tokio::io::split(stream);

   loop {
      let msg_maybe = msg_rx.recv().await;
      let (query_buf, listener_addr, client_addr) = match msg_maybe {
         Some(data) => data,
         None => continue,
      };

      let read_bytes = match tokio::io::AsyncWriteExt::write_all(&mut stream_write, &query_buf).await {
         Ok(_) => match tokio::io::AsyncReadExt::read(&mut stream_read, &mut response_buf).await {
            Ok(0) => {
               println!("received 0 bytes from upstream read");
               break;
            }
            Ok(n) => n,
            Err(err) => {
               println!("{}", err);
               break;
            }
         },
         Err(err) => {
            println!("{}", err);
            break;
         }
      };

      assert!(read_bytes <= 514, "Received a datagram with > 512 bytes from upstream socket");
      println!("read {} bytes from upstream", read_bytes);

      let wrote_bytes = listener_addr.send_to(&response_buf[2..read_bytes - 2], &client_addr).await.unwrap();

      println!("wrote {} bytes to client", wrote_bytes);
   }
}
