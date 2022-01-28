use crate::net;
use std::net::TcpStream;
use std::os::unix::prelude::FromRawFd;

#[inline]
pub fn get_tls_client_config() -> rustls::ClientConfig {
   let mut root_store = rustls::RootCertStore { roots: Vec::new() };
   root_store.roots.extend(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
      rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
   }));
   let mut config = rustls::ClientConfig::builder()
      .with_safe_defaults()
      .with_root_certificates(root_store.clone())
      .with_no_client_auth();
   config.session_storage = std::sync::Arc::new(PersistCache::new());

   config
}

#[inline]
pub fn get_tls_client(server_domain_name: &str, client_config: rustls::ClientConfig) -> rustls::ClientConnection {
   let upstream_dns_address: rustls::ServerName = server_domain_name.try_into().unwrap();
   let arc_config = std::sync::Arc::new(client_config);
   rustls::ClientConnection::new(arc_config, upstream_dns_address).unwrap()
}

pub struct PersistCache {
   pub cache: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl PersistCache {
   fn new() -> Self {
      PersistCache { cache: std::sync::Mutex::new(std::collections::HashMap::new()) }
   }

   fn len(&self) -> Option<usize> {
      match self.cache.lock() {
         Ok(n) => Some(n.len()),
         Err(_) => None,
      }
   }
}

impl rustls::client::StoresClientSessions for PersistCache {
   fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
      self.cache.lock().unwrap().insert(key, value);
      true
   }

   fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
      // {
      //    println!("{} entries in cache", self.len().unwrap());
      // }
      self.cache.lock().unwrap().get(key).cloned()
   }
}

fn complete_handshake(client: &mut rustls::ClientConnection, sock: &mut TcpStream) {
   while client.is_handshaking() {
      let res = client.complete_io(sock);
      if res.is_err() {
         panic!("complete_handshake FAILED: {}", res.err().unwrap());
      }
   }
}

#[inline]
pub fn connect_helper(
   tls_server_domain: &str,
   tls_server_ip: &str,
   tls_server_port: u16,
   tls_client_config: &rustls::ClientConfig,
) -> (rustls::ClientConnection, TcpStream, isize) {
   let mut tls_client_conn = get_tls_client(tls_server_domain, tls_client_config.clone());
   let upstream_fd = net::tcp_connect(tls_server_ip, tls_server_port);
   let mut sock = unsafe { std::net::TcpStream::from_raw_fd(upstream_fd as i32) };
   complete_handshake(&mut tls_client_conn, &mut sock);
   (tls_client_conn, sock, upstream_fd)
}
