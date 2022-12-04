pub async fn go(port: u16) {
   tokio::task::spawn(async move {
      let listener_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
      let listener_socket = tokio::net::UdpSocket::bind(listener_addr).await.unwrap();

      loop {
         let mut query_buf = vec![0; 1024];
         let mut response_buf = vec![0; 1024];

         let (read_bytes, origin_addr) = match listener_socket.recv_from(&mut query_buf[2..]).await {
            Ok(res) => res,
            Err(err) => {
               println!("{}", err);
               continue;
            }
         };

         println!("read_buff len: {}, read: {}", query_buf.len(), read_bytes);

         // Write both bytes at once after converting to Big Endian
         unsafe { *(query_buf.as_mut_ptr() as *mut u16) = crate::net::htons(read_bytes as u16) };

         let tls_client_config = crate::tls::get_tls_client_config();
         let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_client_config));
         let upstream_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 853);
         let base_stream = tokio::net::TcpStream::connect(&upstream_addr).await.unwrap();
         let domain = rustls::ServerName::try_from("one.one.one.one").unwrap();
         let mut stream = connector.connect(domain, base_stream).await.unwrap();

         //let (mut client_stream_read, mut client_stream_write) = stream.into_split();

         let read_bytes = match tokio::io::AsyncWriteExt::write_all(&mut stream, &query_buf[0..read_bytes + 2]).await {
            Ok(_) => match tokio::io::AsyncReadExt::read(&mut stream, &mut response_buf).await {
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

         println!("read {} bytes from upstream", read_bytes);

         let wrote_bytes = listener_socket.send_to(&response_buf[2..read_bytes - 2], &origin_addr).await.unwrap();

         println!("wrote {} bytes to client", wrote_bytes);
      }
   })
   .await
   .unwrap();
}
